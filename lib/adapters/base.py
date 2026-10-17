"""Security-tool adapter framework (Task 14).

A small, ZAP-independent contract for integrating external security tools
(DAST scanners, proxies, fuzzers) into NEXUS **without** letting them bypass
the framework's security controls. The framework defines one adapter
interface:

    connection/health  ->  capability discovery  ->  start a job
      ->  monitor status  ->  cancel (where supported)  ->  collect
      ->  normalized errors / timeouts / status

Adapters translate a tool's native concepts (its REST API, its scan IDs, its
alert schema) into NEXUS concepts: :class:`JobSpec`, :class:`JobHandle`,
:class:`RawFinding` and :class:`AdapterHealth`. Nothing here knows about any
specific product — a ZAP adapter lives in :mod:`lib.adapters.zap`, and future
Burp/Caido adapters plug in through the same interface and registry
(:mod:`lib.adapters.registry`) with no changes to this core.

Every job started through :class:`GuardedAdapter` passes the NEXUS boundaries,
reusing the existing primitives instead of re-implementing them:

    kill switch         -> lib.ops_guard.KillSwitch
    scope (fail closed) -> lib.scope_validator.validate_target_scope
    destination SSRF    -> lib.ssrf_guard.is_safe_url
    request budget      -> lib.ops_guard.spend_requests
    evidence redaction  -> core.sanitizer.sanitize_evidence

Returned tool output (alerts, HTTP content) is ALWAYS untrusted input: it is
never executed, is length-capped, and is sanitized before it is persisted as
evidence.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from core.sanitizer import sanitize_evidence
from lib.exceptions import NexusError, ScopeException
from lib.logger import get_logger
from lib.ops_guard import KillSwitch, spend_requests
from lib.redaction import redact_text
from lib.scope_validator import validate_target_scope
from lib.ssrf_guard import is_safe_url

logger = get_logger("adapters")

# -- job kinds -----------------------------------------------------------------
KIND_PASSIVE = "passive"     # observe/traffic-driven analysis (non-intrusive)
KIND_SPIDER = "spider"       # crawl to discover surface (non-intrusive)
KIND_ACTIVE = "active"       # intrusive/active testing (requires authorization)

# -- normalized job statuses ---------------------------------------------------
STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
STATUS_TIMEOUT = "timeout"

TERMINAL_STATUSES = frozenset(
    {STATUS_COMPLETED, STATUS_FAILED, STATUS_CANCELLED, STATUS_TIMEOUT}
)

# -- normalized severities (NEXUS uses P1..P4; P1 is worst) --------------------
_SEVERITY_BY_RANK = {
    "critical": "P1", "high": "P2", "medium": "P3",
    "low": "P4", "info": "P4", "informational": "P4",
}
_CONFIDENCE_BY_WORD = {"high": 90, "medium": 70, "low": 50}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class AdapterError(NexusError):
    """Base class for all adapter failures (normalized)."""


class AdapterUnavailable(AdapterError):
    """The tool instance is unreachable (connection refused, DNS, timeout)."""


class AdapterAuthError(AdapterError):
    """The tool rejected our credentials/API key."""


class AdapterPolicyError(AdapterError):
    """A NEXUS policy boundary blocked the operation (scope/authz/kill switch)."""


class AdapterTimeout(AdapterError):
    """An operation exceeded its configured timeout."""


class AdapterProtocolError(AdapterError):
    """The tool returned a malformed/unsupported response."""


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sanitize_untrusted(value: Any, limit: int = 2000) -> str:
    """Redact + bound untrusted tool text (central redaction + evidence scrub).

    Applies the framework's central secret redaction (``lib.redaction``) first
    (covers ``token=`` / ``key:`` forms), then the evidence sanitizer's
    credential patterns + length cap. Used for every string an adapter takes
    from a third-party tool before it reaches a finding, log or the database.
    """
    text = value if isinstance(value, str) else str(value if value is not None else "")
    return sanitize_evidence(redact_text(text), max_length=limit)


def severity_from_risk(value: Any) -> str:
    """Map a tool risk word (or P-level) to a NEXUS P-level (P4 default)."""
    text = str(value or "").strip().lower()
    if text in _SEVERITY_BY_RANK:
        return _SEVERITY_BY_RANK[text]
    upper = text.upper()
    if upper in ("P1", "P2", "P3", "P4"):
        return upper
    return "P4"


def confidence_from_word(value: Any, default: int = 50) -> int:
    """Map a tool confidence word (or number) to a 0-100 integer."""
    if isinstance(value, (int, float)):
        return max(0, min(100, int(value)))
    word = str(value or "").strip().lower()
    if word in _CONFIDENCE_BY_WORD:
        return _CONFIDENCE_BY_WORD[word]
    try:
        return max(0, min(100, int(word)))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class AdapterCapability:
    """One capability a tool advertises (for capability discovery)."""

    name: str
    active: bool = False          # True = intrusive/state-changing by nature
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "active": self.active, "description": self.description}


@dataclass
class AdapterHealth:
    """Connection + health status of a tool instance."""

    name: str
    reachable: bool = False
    version: str = ""
    mode: str = ""
    error: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "reachable": self.reachable,
            "version": self.version,
            "mode": self.mode,
            "error": self.error,
            "details": dict(self.details),
        }


@dataclass
class JobSpec:
    """A request to start one analysis job against *target*."""

    target: str
    kind: str = KIND_PASSIVE
    params: dict[str, Any] = field(default_factory=dict)
    authorized: bool = False      # explicit operator authorization for active work
    timeout: float = 0.0          # whole-job wall clock (0 = caller's default)
    poll_interval: float = 0.0    # status-poll spacing (0 = caller's default)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "kind": self.kind,
            "params": dict(self.params),
            "authorized": self.authorized,
            "timeout": self.timeout,
            "poll_interval": self.poll_interval,
        }


@dataclass
class JobHandle:
    """A started job's identity + normalized status."""

    job_id: str
    adapter: str
    target: str = ""
    kind: str = KIND_PASSIVE
    status: str = STATUS_PENDING
    progress: int = 0
    message: str = ""
    started_at: str = ""
    updated_at: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "adapter": self.adapter,
            "target": self.target,
            "kind": self.kind,
            "status": self.status,
            "progress": int(self.progress),
            "message": self.message,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
        }


@dataclass
class RawFinding:
    """One normalized finding produced by a tool (untrusted content)."""

    adapter: str
    source: str
    name: str
    severity: str = "P4"
    confidence: int = 50
    endpoint: str = ""
    method: str = "GET"
    param: str = ""
    description: str = ""
    solution: str = ""
    reference: str = ""
    cwe_id: str = ""
    evidence: str = ""
    other_info: str = ""
    plugin_id: str = ""
    alert_id: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "adapter": self.adapter,
            "source": self.source,
            "name": self.name,
            "severity": self.severity,
            "confidence": int(self.confidence),
            "endpoint": self.endpoint,
            "method": self.method,
            "param": self.param,
            "description": self.description,
            "solution": self.solution,
            "reference": self.reference,
            "cwe_id": self.cwe_id,
            "evidence": self.evidence,
            "other_info": self.other_info,
            "plugin_id": self.plugin_id,
            "alert_id": self.alert_id,
            "extra": dict(self.extra),
        }


@dataclass
class AdapterResult:
    """Collected findings + provenance for one finished job."""

    handle: JobHandle
    findings: list[RawFinding] = field(default_factory=list)
    error: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "handle": self.handle.to_dict(),
            "error": self.error,
            "finding_count": len(self.findings),
            "provenance": dict(self.provenance),
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Adapter contract
# ---------------------------------------------------------------------------


class SecurityToolAdapter(ABC):
    """Contract every external-tool integration implements.

    Concrete adapters own only translation + transport. Policy (scope,
    authorization, budgets, kill switch, redaction) is applied by
    :class:`GuardedAdapter`, so adapters stay product-specific and thin.
    """

    name: str = "adapter"

    # -- discovery ----------------------------------------------------------

    @abstractmethod
    def capabilities(self) -> list[AdapterCapability]:
        """Capabilities this adapter supports (declared, no network I/O)."""

    @abstractmethod
    def health(self) -> AdapterHealth:
        """Connection/health check. Never raises — reports failure in the result."""

    def validate_config(self) -> list[str]:
        """Return configuration problems (already secret-redacted); [] when ok."""
        return []

    # -- job control --------------------------------------------------------

    @abstractmethod
    def start_job(self, job: JobSpec) -> JobHandle:
        """Start *job*. Raises a normalized :class:`AdapterError` on failure."""

    @abstractmethod
    def job_status(self, handle: JobHandle) -> JobHandle:
        """Return *handle* refreshed with the tool's current status."""

    @abstractmethod
    def collect(self, handle: JobHandle) -> list[RawFinding]:
        """Return normalized findings for *handle* (untrusted content)."""

    def cancel_job(self, handle: JobHandle) -> bool:
        """Request cancellation. Returns True when the tool accepted it."""
        return False

    def wait(
        self,
        handle: JobHandle,
        *,
        timeout: float = 0.0,
        poll_interval: float = 1.0,
        should_stop: Callable[[], str] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> JobHandle:
        """Poll until the job is terminal, times out, or ``should_stop`` trips.

        ``should_stop`` returns a non-empty reason to abort (e.g. kill switch);
        ``sleep`` is injectable for deterministic tests.
        """
        import time as _time

        do_sleep = sleep or _time.sleep
        start = _time.monotonic()
        interval = max(0.0, float(poll_interval))
        while True:
            if should_stop is not None:
                reason = should_stop()
                if reason:
                    handle.status = STATUS_CANCELLED
                    handle.message = reason
                    handle.updated_at = _now()
                    return handle
            handle = self.job_status(handle)
            if handle.terminal:
                return handle
            if timeout and (_time.monotonic() - start) >= timeout:
                handle.status = STATUS_TIMEOUT
                handle.message = f"exceeded {timeout:g}s"
                handle.updated_at = _now()
                return handle
            do_sleep(interval)

    def close(self) -> None:
        """Release any adapter-side resources (default: nothing)."""
        return None


# ---------------------------------------------------------------------------
# Policy enforcement wrapper
# ---------------------------------------------------------------------------


@dataclass
class AdapterPolicy:
    """Policy context for guarded adapter jobs (reuses NEXUS primitives).

    - ``target_config``: scope gate via ``validate_target_scope`` (fail closed);
    - ``ssrf_allow``: explicit operator allowlist for the SSRF guard (e.g. a
      local controlled test target or a remote ZAP host);
    - ``allow_active``: master switch for intrusive jobs (must be granted);
    - ``actor``/``db``: audit identity/trail;
    - ``killswitch``: file-backed global stop (defaults to the repo kill switch).
    """

    target_config: Any = None
    ssrf_allow: set[str] = field(default_factory=set)
    allow_active: bool = False
    actor: str = "operator"
    db: Any = None
    killswitch: KillSwitch | None = None

    def check_target(self, target: str) -> tuple[bool, str]:
        """Scope (cheap, first) then SSRF guard. Returns (ok, reason)."""
        if self.target_config is not None:
            try:
                if not validate_target_scope(target, self.target_config):
                    return False, "scope: target not authorized"
            except ScopeException as exc:
                return False, f"scope: {exc}"
        ok, reason = is_safe_url(target, allow=set(self.ssrf_allow), local_ok=True)
        if not ok:
            return False, f"ssrf: {reason}"
        return True, "ok"


class GuardedAdapter:
    """Wraps a :class:`SecurityToolAdapter` with NEXUS policy enforcement.

    Every job start passes: kill switch → SCOPE/AUTHORIZATION → request budget
    → start. Active jobs additionally require ``policy.allow_active`` AND
    per-job ``spec.authorized``. All actions are audited.
    """

    def __init__(self, adapter: SecurityToolAdapter, policy: AdapterPolicy):
        self.adapter = adapter
        self.policy = policy
        self.name = getattr(adapter, "name", "adapter")

    # -- audit --------------------------------------------------------------

    def _audit(self, action: str, detail: str = "") -> None:
        if self.policy.db is None:
            return
        try:
            self.policy.db.insert_audit_event(
                actor=self.policy.actor, action=action,
                category="adapter", detail=str(detail)[:300],
            )
        except Exception:  # audit must never break the run
            pass

    def _killed(self) -> str:
        ks = self.policy.killswitch or KillSwitch()
        return "kill switch engaged" if ks.killed() else ""

    # -- read-only passthroughs --------------------------------------------

    def capabilities(self) -> list[AdapterCapability]:
        return self.adapter.capabilities()

    def health(self) -> AdapterHealth:
        return self.adapter.health()

    def validate_config(self) -> list[str]:
        return self.adapter.validate_config()

    # -- guarded job control ------------------------------------------------

    def _gate(self, spec: JobSpec) -> None:
        reason = self._killed()
        if reason:
            self._audit("adapter.blocked", f"{self.name} {reason}")
            raise AdapterPolicyError(reason)
        if not str(spec.target or "").strip():
            raise AdapterPolicyError("target is required")
        ok, why = self.policy.check_target(spec.target)
        if not ok:
            self._audit("adapter.blocked", f"{self.name} {spec.target} {why}")
            raise AdapterPolicyError(f"blocked: {why} ({spec.target})")
        if spec.kind == KIND_ACTIVE:
            if not self.policy.allow_active:
                self._audit("adapter.blocked", f"{self.name} active scan disabled by policy")
                raise AdapterPolicyError("active scanning is not authorized in policy")
            if not spec.authorized:
                self._audit("adapter.blocked", f"{self.name} active scan not authorized for this run")
                raise AdapterPolicyError("active scanning requires explicit authorization")
        if not spend_requests(1):
            self._audit("adapter.blocked", f"{self.name} request budget exhausted")
            raise AdapterPolicyError("request budget exhausted")

    def start_job(self, spec: JobSpec) -> JobHandle:
        self._gate(spec)
        handle = self.adapter.start_job(spec)
        self._audit(f"adapter.{self.name}.start", f"{spec.kind} {spec.target}")
        return handle

    def job_status(self, handle: JobHandle) -> JobHandle:
        return self.adapter.job_status(handle)

    def cancel_job(self, handle: JobHandle) -> bool:
        cancelled = self.adapter.cancel_job(handle)
        self._audit(f"adapter.{self.name}.cancel", handle.job_id)
        return cancelled

    def wait(self, handle: JobHandle, **kwargs: Any) -> JobHandle:
        def _should_stop() -> str:
            return self._killed()

        kwargs.setdefault("should_stop", _should_stop)
        if "poll_interval" not in kwargs:
            kwargs["poll_interval"] = float(handle.raw.get("poll_interval") or 1.0)
        return self.adapter.wait(handle, **kwargs)

    def collect(self, handle: JobHandle) -> list[RawFinding]:
        findings = self.adapter.collect(handle)
        self._audit(f"adapter.{self.name}.collect", f"{handle.job_id} {len(findings)} finding(s)")
        return findings

    def close(self) -> None:
        self.adapter.close()


# ---------------------------------------------------------------------------
# Evidence / finding ingestion (adapter-agnostic, provenance-preserving)
# ---------------------------------------------------------------------------


def build_adapter_evidence(
    finding: RawFinding,
    *,
    phase: str = "",
    finding_ref: int | None = None,
    scan_id: int | None = None,
) -> dict[str, Any]:
    """NEXUS evidence schema for one tool finding (content is untrusted)."""
    return {
        "scan_id": scan_id,
        "url": finding.endpoint,
        "method": finding.method or "GET",
        "tool": finding.adapter,
        "source": phase or finding.source or finding.adapter,
        "finding_reference": finding_ref,
        "timestamp": _now(),
        "detection": {
            "name": sanitize_untrusted(finding.name, 300),
            "plugin_id": finding.plugin_id,
            "alert_id": finding.alert_id,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "cwe_id": finding.cwe_id,
        },
        "observation": sanitize_untrusted(finding.evidence),
        "other_info": sanitize_untrusted(finding.other_info),
        "trusted": False,
    }


def ingest_findings(
    db: Any,
    scan_id: int,
    findings: list[RawFinding],
    target_config: Any = None,
    *,
    phase: str = "",
) -> dict[str, Any]:
    """Persist normalized findings + linked evidence, preserving provenance.

    - a finding's endpoint is scope-checked (out-of-scope findings are stored
      ``in_scope=False`` and never treated as submittable);
    - the tool, alert id and plugin id are recorded as provenance on both the
      finding (``tools_found``) and the evidence row (via :func:`build_adapter_evidence`);
    - untrusted text is sanitized by the DB choke point before persistence.

    Returns ``{"finding_ids": [...], "evidence_ids": [...], "out_of_scope": n}``.
    """
    from lib.scope_validator import validate_finding_scope

    finding_ids: list[int] = []
    evidence_ids: list[int] = []
    out_of_scope = 0
    source = phase or (findings[0].source if findings else "")
    for finding in findings:
        in_scope = True
        if target_config is not None and finding.endpoint:
            in_scope = bool(validate_finding_scope(finding.endpoint, target_config))
        if not in_scope:
            out_of_scope += 1
        fid = db.insert_finding(
            scan_id=scan_id,
            endpoint=finding.endpoint,
            vuln_type=finding.name or "adapter-finding",
            severity=finding.severity,
            confidence=int(finding.confidence),
            payload=sanitize_untrusted(finding.evidence, 300),
            response_snippet=sanitize_untrusted(finding.other_info or finding.evidence),
            tools_found=[finding.adapter],
            in_scope=in_scope,
        )
        finding_ids.append(fid)
        record = build_adapter_evidence(
            finding, phase=source, finding_ref=fid, scan_id=scan_id
        )
        import json as _json

        eid = db.insert_evidence(
            scan_id,
            url=finding.endpoint or "adapter://finding",
            method=finding.method or "GET",
            tool=finding.adapter,
            source=source or finding.adapter,
            response_body=_json.dumps(record, default=str),
            finding_id=fid,
        )
        evidence_ids.append(eid)
    return {
        "finding_ids": finding_ids,
        "evidence_ids": evidence_ids,
        "out_of_scope": out_of_scope,
    }
