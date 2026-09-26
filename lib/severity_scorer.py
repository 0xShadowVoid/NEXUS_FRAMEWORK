"""Impact-based severity scoring.

RCE > SQLi > XSS > IDOR > Info Disclosure. Confidence thresholds are
applied per finding type from the false-positive filters config.
"""
from __future__ import annotations

from typing import Any

# Base severity ladder (impact-based). P1 worst.
# type → (default severity, confidence adjustment)
_BASE_RULES: dict[str, tuple[str, int]] = {
    "rce": ("P1", 0),
    "sqli": ("P1", 0),
    "auth_bypass": ("P1", 0),
    "ssrf": ("P2", 0),
    "stored_xss": ("P2", 0),
    "idor": ("P2", 0),
    "lfi": ("P2", 0),
    "reflected_xss": ("P3", 0),
    "xss": ("P3", 0),
    "open_redirect": ("P4", 0),
    "info": ("P4", 0),
    "info_disclosure": ("P4", 0),
}

_SEVERITY_ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}

# Contextual upgrades -----------------------------------------------

_AUTH_KEYWORDS = ("admin", "login", "auth", "session", "token", "password", "passwd")
_DB_ACCESS_HINTS = ("auth_bypass", "full database", "all users", "dumped")
_SENSITIVE_DATA_HINTS = ("email", "payment", "invoice", "ssn", "address", "phone")


def _ctx_or_default(finding: dict[str, Any]) -> tuple[str, int]:
    vt = str(finding.get("vuln_type", "")).lower().strip()
    if vt in _BASE_RULES:
        return _BASE_RULES[vt]
    # Loose matching for variants (blind_sqli, union_sqli, dom_xss, ...).
    if "sqli" in vt or "sql_injection" in vt:
        return ("P1", 0)
    if "rce" in vt or "command_injection" in vt or "code_exec" in vt:
        return ("P1", 0)
    if "stored" in vt and "xss" in vt:
        return ("P2", 0)
    if "xss" in vt:
        return ("P3", 0)
    if "idor" in vt or "bola" in vt:
        return ("P2", 0)
    if "ssrf" in vt:
        return ("P2", 0)
    if "lfi" in vt or "file_inclusion" in vt or "traversal" in vt:
        return ("P2", 0)
    if "redirect" in vt:
        return ("P4", 0)
    if "info" in vt or "disclosure" in vt or "leak" in vt:
        return ("P4", 0)
    return ("P3", 0)


def _contextual_adjust(finding: dict[str, Any], severity: str, confidence: int) -> tuple[str, int]:
    """Apply contextual impact adjustments to a base severity."""
    endpoint = str(finding.get("endpoint", "")).lower()
    payload = str(finding.get("payload", "")).lower()
    response = str(finding.get("response_snippet", "")).lower()
    everything = endpoint + " " + payload + " " + response
    vt = str(finding.get("vuln_type", "")).lower()

    # SQLi + auth keywords/context → stays P1 with a confidence bump.
    if "sqli" in vt and any(k in everything for k in _AUTH_KEYWORDS):
        confidence = min(100, confidence + 5)

    # IDOR on sensitive data surface → P2, else P3.
    if "idor" in vt:
        if any(k in everything for k in _SENSITIVE_DATA_HINTS):
            return ("P2", confidence)
        severity = "P3"

    # XSS reflected → P3; if it hits an auth surface, upgrade to P2.
    if "xss" in vt and "stored" not in vt:
        if any(k in endpoint for k in _AUTH_KEYWORDS):
            severity = "P2"

    # Open redirect toward oauth/token flows → P3.
    if "redirect" in vt and any(k in everything for k in ("oauth", "token", "callback")):
        severity = "P3"

    return (severity, confidence)


class SeverityScorer:
    """Scores findings with impact-based severities and confidence."""

    def __init__(self, filters_config: dict[str, Any] | None = None):
        self.thresholds: dict[str, int] = {}
        if filters_config:
            for ftype, rule in (filters_config.get("filters", {}) or {}).items():
                thr = rule.get("confidence_threshold")
                if thr is not None:
                    self.thresholds[ftype] = int(thr)

    def threshold_for(self, finding_type: str) -> int | None:
        """Confidence threshold for a finding type, if configured."""
        vt = str(finding_type).lower().strip()
        if vt in self.thresholds:
            return self.thresholds[vt]
        for key, thr in self.thresholds.items():
            if key in vt or vt in key:
                return thr
        return None

    def score(self, finding: dict[str, Any]) -> tuple[str, int]:
        """Return ``(severity, confidence)`` for a finding."""
        confidence = int(finding.get("confidence", 50))
        severity, adj = _ctx_or_default(finding)
        confidence = max(0, min(100, confidence + adj))
        severity, confidence = _contextual_adjust(finding, severity, confidence)
        return severity, confidence

    def meets_threshold(self, finding_type: str, confidence: int) -> bool:
        """Whether *confidence* meets the configured threshold for the type."""
        thr = self.threshold_for(finding_type)
        if thr is None:
            return True
        return confidence >= thr

    def score_and_flag(self, finding: dict[str, Any]) -> tuple[str, int, bool]:
        """Score + threshold flag in one call."""
        severity, confidence = self.score(finding)
        meets = self.meets_threshold(str(finding.get("vuln_type", "")), confidence)
        return severity, confidence, meets


def severity_rank(severity: str) -> int:
    """P1=1 … P4=4; unknown → 5."""
    return _SEVERITY_ORDER.get(str(severity).upper().strip(), 5)


def severity_order(severity: str) -> int:
    """Back-compat alias for :func:`severity_rank`."""
    return severity_rank(severity)
