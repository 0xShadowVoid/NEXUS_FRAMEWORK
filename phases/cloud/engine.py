"""Pass 6 — cloud posture engine (read-only checks over normalized data).

Providers expose a tiny READ-ONLY client surface; every check here is a
pure function over the collected, normalized data. Fake clients make tests
fully deterministic; real SDKs are optional and lazily imported.

Hard rules (verified by tests):
- read-only: the sources never call resource-mutating API methods
  (``FORBIDDEN_METHOD_RE`` is asserted against this package's own source);
- secrets are redacted before persistence/reporting (keys + sanitizer);
- a failed check, missing permissions, and missing credentials are
  distinct statuses — never conflated.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from core.sanitizer import sanitize_evidence
from lib.logger import get_logger

logger = get_logger("cloud_engine")

# Statuses for a single check (per directive: distinguish failure vs permissions).
CHECK_STATUSES = (
    "ok", "issue", "insufficient_permissions", "insufficient_credentials",
    "not_supported", "error", "skipped",
)

SENSITIVE_KEYS = (
    "secret", "token", "password", "private_key", "credential", "access_key",
    "session", "authorization", "cookie", "client_secret", "connection_string",
)

SENSITIVE_PORTS = frozenset({22, 3389, 3306, 5432, 6379, 9200, 11211, 27017, 1433, 5900})

# Resource-mutating call patterns — asserted to have ZERO matches in this package.
FORBIDDEN_METHOD_RE = re.compile(
    r"\.(?:create|delete|put|update|patch|modify|attach|detach|terminate|reboot|"
    r"revoke|set|add|remove|enable|disable|start|stop|restart)_[a-z0-9_]+\(",
)
READ_METHOD_PREFIXES = ("get", "list", "describe", "head", "read", "query", "search", "validate")


def redact(value: Any, depth: int = 0) -> Any:
    """Recursively redact sensitive keys + sanitize strings (bounded)."""
    if depth > 6:
        return "[depth-limit]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in list(value.items())[:200]:
            key_l = str(key).lower()
            if any(marker in key_l for marker in SENSITIVE_KEYS):
                out[str(key)] = "[REDACTED]"
            else:
                out[str(key)] = redact(item, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(item, depth + 1) for item in list(value)[:200]]
    if isinstance(value, str):
        return sanitize_evidence(value, max_length=600)
    return value


def classify_error(exc: Exception) -> str:
    """Map a provider exception to a check status (never conflated)."""
    blob = f"{type(exc).__name__} {exc}".lower()
    if any(k in blob for k in (
        "nocredential", "credentials", "credential", "token", "unauthorized",
        "authentication", "invalidkey", "signature", "expired",
    )):
        return "insufficient_credentials"
    if any(k in blob for k in (
        "accessdenied", "permission", "forbidden", "notauthorized",
        "authorizationfailed", "denied",
    )):
        return "insufficient_permissions"
    return "error"


@dataclass
class CheckResult:
    """One posture check outcome."""

    check: str
    status: str
    resource: str = ""
    severity: str = ""
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "status": self.status,
            "resource": self.resource,
            "severity": self.severity,
            "detail": self.detail,
            "evidence": redact(self.evidence),
        }


# ---- individual checks (over normalized provider data) -------------------------

def _check_storage(provider: str, buckets: list[dict[str, Any]] | None) -> list[CheckResult]:
    out: list[CheckResult] = []
    for bucket in buckets or []:
        name = str(bucket.get("name", "?"))
        resource = f"{provider}:{name}"
        if bucket.get("public_acl") or bucket.get("public_policy"):
            out.append(CheckResult(
                "storage_public_exposure", "issue", resource, "P1",
                "storage is publicly accessible",
                {"bucket": name, "grants": bucket.get("grants", [])},
            ))
        if bucket.get("public_access_block") is False:
            out.append(CheckResult(
                "storage_public_access_block", "issue", resource, "P2",
                "public access block is disabled or absent", {"bucket": name},
            ))
        if bucket.get("encryption") is False:
            out.append(CheckResult(
                "storage_encryption", "issue", resource, "P2",
                "default encryption is not enabled", {"bucket": name},
            ))
        if bucket.get("versioning") is False:
            out.append(CheckResult(
                "storage_versioning", "issue", resource, "P3",
                "object versioning is disabled", {"bucket": name},
            ))
    if not out:
        out.append(CheckResult("storage_review", "ok", provider, detail="no storage issues detected"))
    return out


def _check_network(provider: str, rules: list[dict[str, Any]] | None) -> list[CheckResult]:
    out: list[CheckResult] = []
    for rule in rules or []:
        name = str(rule.get("name", "?"))
        resource = f"{provider}:{name}"
        for ingress in rule.get("rules") or []:
            ports = ingress.get("ports", "all")
            port_set = set(ports) if isinstance(ports, (list, tuple)) else set()
            sensitive = ports == "all" or bool(port_set & SENSITIVE_PORTS)
            severity = "P1" if sensitive else "P2"
            out.append(CheckResult(
                "network_open_ingress", "issue", resource, severity,
                "ingress open to the internet"
                + (" on sensitive ports" if sensitive else ""),
                {"group": name, "cidrs": ingress.get("cidrs", []), "ports": ports},
            ))
    if not out:
        out.append(CheckResult("network_review", "ok", provider, detail="no open ingress detected"))
    return out


def _check_iam(provider: str, summary: dict[str, Any] | None) -> list[CheckResult]:
    summary = summary or {}
    out: list[CheckResult] = []
    if summary.get("mfa_enabled") is False:
        out.append(CheckResult(
            "iam_account_mfa", "issue", f"{provider}:account", "P2",
            "account-level MFA is not enabled", {"mfa_enabled": False},
        ))
    if summary.get("root_access_keys") is True:
        out.append(CheckResult(
            "iam_root_access_keys", "issue", f"{provider}:root", "P1",
            "root/account access keys exist", {"root_access_keys": True},
        ))
    if not out:
        out.append(CheckResult("iam_review", "ok", provider, detail="no identity issues detected"))
    return out


def _check_logging(provider: str, flags: dict[str, Any] | None) -> list[CheckResult]:
    flags = flags or {}
    out: list[CheckResult] = []
    if flags.get("audit_logging_enabled") is False:
        out.append(CheckResult(
            "logging_audit_disabled", "issue", f"{provider}:audit", "P2",
            "audit logging is not enabled", {"audit_logging_enabled": False},
        ))
    if flags.get("log_validation") is False:
        out.append(CheckResult(
            "logging_validation_disabled", "issue", f"{provider}:audit", "P3",
            "log file validation is disabled", {"log_validation": False},
        ))
    if not out:
        out.append(CheckResult("logging_review", "ok", provider, detail="audit logging configured"))
    return out


_CHECKERS = {
    "storage": _check_storage,
    "network": _check_network,
    "iam": _check_iam,
    "logging": _check_logging,
}


def run_checks(provider: str, sections: dict[str, dict[str, Any]]) -> list[CheckResult]:
    """Run all posture checks over collected sections.

    Sections with non-ok collection status produce a distinct result each —
    a failed check is never reported when data was actually unavailable.
    """
    results: list[CheckResult] = []
    for name in ("storage", "network", "iam", "logging"):
        section = sections.get(name)
        if section is None:
            results.append(CheckResult(f"{name}_review", "not_supported", provider))
            continue
        status = str(section.get("status", "error"))
        if status != "ok":
            results.append(CheckResult(
                f"{name}_review", status, provider,
                detail=f"{name} data unavailable ({status})",
            ))
            continue
        checker = _CHECKERS[name]
        results.extend(checker(provider, section.get("data")))
    return results


def summarize(results: list[CheckResult]) -> dict[str, int]:
    counts = {"ok": 0, "issue": 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts
