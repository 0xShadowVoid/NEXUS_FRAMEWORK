"""Deterministic finding verification (roadmap A1/A2).

Confirms findings from evidence already captured — no new traffic by
default — so false positives are removed *before* submission:

- XSS: payload must appear **unescaped** in the response evidence;
  entity-encoded reflection is actively disproved.
- SQLi: DB error/driver signatures in the evidence.
- RCE: command-output markers (uid=, Windows version banner).
- LFI: file-content markers (root:x:0:0:, [boot loader]).
- Correlation: findings produced by ≥2 independent tools are considered
  corroborated ("corroboration" method) even without inline evidence.

When a live HTTP probe callback is supplied it is used as a fallback
(replay), keeping the default fully offline and deterministic.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Callable

from lib.logger import get_logger

logger = get_logger("verifier")

MIN_CORROBORATING_TOOLS = 2

_ENCODED_RE = re.compile(r"&lt;|&gt;|&#x?3[ce];|&quot;|&#39;|%3C|%3E", re.IGNORECASE)
_DB_ERROR_RE = re.compile(
    r"(?i)(sql syntax|you have an error in your sql|mysql_|mysqli|pg_query|postgresql.*error"
    r"|ora-\d{4,5}|sqlite3\.|unclosed quotation mark|odbc .*driver|syntax error at or near)"
)
_CMD_OUT_RE = re.compile(r"(?i)\buid=\d+|\bgid=\d+|volume serial number|microsoft windows \[version")
_FILE_RE = re.compile(r"(?i)root:x:0:0:|\[boot loader\]|daemon:x:\d+:|/bin/(ba)?sh")
_REDIRECT_RE = re.compile(r"(?i)(^|\n)\s*(location|http/\d\.\d\s+30\d)")

_PAYLOAD_FRAGMENT_RE = re.compile(r"[A-Za-z0-9_./<>=\"'()\[\]{}:;,$!?*+~^%#@|-]{4,}")


@dataclass
class VerificationResult:
    """Outcome of verifying one finding."""

    verified: bool
    method: str = "heuristic"      # reflection | error-signature | command-output | file-content | corroboration | unverified
    confidence: int = 50
    notes: str = ""
    disproved: bool = False        # evidence actively contradicts the finding


def _xss_fragment(payload: str) -> str:
    """Extract a distinctive fragment of an XSS payload to look for."""
    p = (payload or "").strip()
    if not p:
        return ""
    # Prefer the tag/handler core, e.g. <img src=x onerror=alert(1)> → onerror=alert(1)
    m = re.search(r"(on\w+\s*=\s*[a-z]+\([^)]*\))", p, re.IGNORECASE)
    if m:
        return m.group(1)
    candidates = _PAYLOAD_FRAGMENT_RE.findall(p)
    candidates = [c for c in candidates if not c.isdigit()]
    return max(candidates, key=len) if candidates else ""


def corroborated(finding: dict[str, Any], min_tools: int = MIN_CORROBORATING_TOOLS) -> bool:
    """True when ≥*min_tools* independent tools reported the same finding."""
    return len({str(t).lower() for t in (finding.get("tools_found") or [])}) >= min_tools


def verify_finding(
    finding: dict[str, Any],
    http_probe: Callable[[str], str] | None = None,
) -> VerificationResult:
    """Verify a single finding from its captured evidence."""
    vt = str(finding.get("vuln_type", "")).lower()
    payload = str(finding.get("payload", "") or "")
    response = str(finding.get("response_snippet", "") or "")

    # 1. Multi-tool corroboration (independent agreement).
    if corroborated(finding):
        return VerificationResult(
            verified=True,
            method="corroboration",
            confidence=min(95, 70 + 5 * len(finding.get("tools_found") or [])),
            notes="multiple independent tools agree",
        )

    # 2. Inline evidence checks per vulnerability class.
    #    Only DECISIVE outcomes (verified / disproved) return here; otherwise
    #    fall through to the live replay, then the generic unverified result.
    if "xss" in vt:
        frag = _xss_fragment(payload)
        if frag:
            if frag in response:
                if _ENCODED_RE.search(response):
                    return VerificationResult(
                        verified=False, method="reflection", confidence=15,
                        notes="payload reflected but entity/percent-encoded (not executable)",
                        disproved=True,
                    )
                return VerificationResult(
                    verified=True, method="reflection", confidence=90,
                    notes="payload reflected unescaped in evidence",
                )
            # fragment not present in captured evidence → not decisive; try replay

    elif "sqli" in vt or "sql_injection" in vt:
        if _DB_ERROR_RE.search(response):
            return VerificationResult(verified=True, method="error-signature", confidence=88,
                                      notes="database error signature in evidence")

    elif "rce" in vt or "command_injection" in vt:
        if _CMD_OUT_RE.search(response):
            return VerificationResult(verified=True, method="command-output", confidence=92,
                                      notes="command output marker in evidence")

    elif "lfi" in vt or "traversal" in vt or "file_inclusion" in vt:
        if _FILE_RE.search(response):
            return VerificationResult(verified=True, method="file-content", confidence=85,
                                      notes="file-content marker in evidence")

    elif "redirect" in vt:
        if _REDIRECT_RE.search(response):
            return VerificationResult(verified=True, method="error-signature", confidence=70,
                                      notes="redirect/Location evidence present")

    # 3. Live replay fallback (only when a probe is supplied).
    if http_probe is not None:
        try:
            body = http_probe(str(finding.get("endpoint", "")))
            if payload and payload in (body or ""):
                return VerificationResult(verified=True, method="replay", confidence=80,
                                          notes="payload reflected on live replay")
        except Exception as exc:  # probe must never break verification
            logger.debug("live verification probe failed: %s", exc)

    return VerificationResult(verified=False, method="unverified", confidence=50,
                              notes="no deterministic confirmation available")


def verification_dict(result: VerificationResult) -> dict[str, Any]:
    return asdict(result)
