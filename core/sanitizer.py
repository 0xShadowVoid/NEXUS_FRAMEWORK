"""Evidence sanitizer — keeps reports to proof-only content.

SECURITY BOUNDARY output restriction (BUILD_SPEC Part 8 / SECURITY_BOUNDARY
§Output Restrictions): reports must contain proof only — no cookies, no
authorization headers, no tokens, no PII beyond the single proof address
needed for an IDOR proof, and capped snippet lengths.
"""
from __future__ import annotations

import re

MAX_SNIPPET_LENGTH = 500

# Full evidence records keep more context than report snippets, but stay
# bounded so a stored record can never balloon (Pass 3B §4).
EVIDENCE_MAX_LENGTH = 20000

# Headers/values that must never survive into a report.
_SET_COOKIE_RE = re.compile(r"(?im)^set-cookie:.*$")
_AUTH_HEADER_RE = re.compile(r"(?im)^(authorization|proxy-authorization):.*$")
_BEARER_RE = re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]{10,}")
_TOKEN_JSON_RE = re.compile(
    r'"(token|access_token|refresh_token|api_?key|secret|session_?id|password|passwd|pwd)"\s*:\s*"[^"]*"',
    re.IGNORECASE,
)
_API_KEY_LIKE_RE = re.compile(
    r"(?i)\b(?:sk-[a-z0-9]{16,}|ghp_[a-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})\b"
)
# Keep at most one proof email (IDOR proof); mask any others.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def sanitize_evidence(text: str, max_length: int = MAX_SNIPPET_LENGTH) -> str:
    """Sanitize a response snippet for reports (proof-only content)."""
    out = text or ""
    out = _SET_COOKIE_RE.sub("set-cookie: [REDACTED]", out)
    out = _AUTH_HEADER_RE.sub("authorization: [REDACTED]", out)
    out = _BEARER_RE.sub("bearer [REDACTED]", out)
    out = _TOKEN_JSON_RE.sub(r'"\1": "[REDACTED]"', out)
    out = _API_KEY_LIKE_RE.sub("[REDACTED-KEY]", out)

    # Keep one proof email for IDOR evidence; mask all others.
    emails = _EMAIL_RE.findall(out)
    if len(emails) > 1:
        first = emails[0]
        out = _EMAIL_RE.sub(lambda m: m.group(0) if m.group(0) == first else "***@***.***", out)

    if len(out) > max_length:
        out = out[:max_length] + "…[truncated]"
    return out


def sanitize_finding(finding: dict) -> dict:
    """Return a copy of *finding* with sanitized evidence fields."""
    import copy

    out = copy.deepcopy(finding)
    if "response_snippet" in out:
        out["response_snippet"] = sanitize_evidence(str(out.get("response_snippet") or ""))
    if "payload" in out:
        out["payload"] = sanitize_evidence(str(out.get("payload") or ""), max_length=300)
    return out


# Headers whose values must never survive into persisted evidence.
_SENSITIVE_HEADER_NAMES = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token",
    "x-session-token", "x-csrf-token", "private-token", "x-amz-security-token",
})


def sanitize_headers(headers: dict[str, str] | None) -> dict[str, str]:
    """Redact credential-bearing HTTP headers before persistence (Pass 3B §4)."""
    out: dict[str, str] = {}
    for key, value in (headers or {}).items():
        k = str(key)
        if k.strip().lower() in _SENSITIVE_HEADER_NAMES:
            out[k] = "[REDACTED]"
            continue
        v = str(value)
        v = _BEARER_RE.sub("bearer [REDACTED]", v)
        v = _API_KEY_LIKE_RE.sub("[REDACTED-KEY]", v)
        out[k] = v
    return out


def sanitize_evidence_record(
    request_headers: dict[str, str] | None = None,
    request_body: str = "",
    response_headers: dict[str, str] | None = None,
    response_body: str = "",
) -> tuple[dict[str, str], str, dict[str, str], str]:
    """Sanitize a full evidence record for persistence.

    Returns ``(request_headers, request_body, response_headers, response_body)``
    with secrets redacted; keeps enough request/response context for
    reproduction (method/url/status live outside this record).
    """
    return (
        sanitize_headers(request_headers),
        sanitize_evidence(str(request_body or ""), max_length=EVIDENCE_MAX_LENGTH),
        sanitize_headers(response_headers),
        sanitize_evidence(str(response_body or ""), max_length=EVIDENCE_MAX_LENGTH),
    )
