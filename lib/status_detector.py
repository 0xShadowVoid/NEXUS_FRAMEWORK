"""HTTP status + response classification.

Gates which endpoints heavy tools (sqlmap, commix) may touch and feeds
bypass testing. Detection happens on already-collected responses — this
module performs no network requests itself.
"""
from __future__ import annotations

import re
from typing import Any

_AUTH_KEYWORDS = re.compile(
    r"(?i)\b(login|log.?in|sign.?in|auth|session|passwd|password|token|jwt|otp)\b"
)
_ERROR_KEYWORDS = re.compile(
    r"(?i)\b(sql|syntax|exception|traceback|stack\s*trace|warning|fatal|deprecated)\b"
)


def classify_status(status_code: int, body: str = "") -> str:
    """Classify an HTTP response into a gating category.

    Categories:
      - ``auth_candidate_200``: 200 with auth keywords → heavy-tool gate
      - ``bypass_candidate_401_403``: 401/403 → bypass + heavy-tool gate
      - ``not_found_404``: 404
      - ``server_error_5xx``: 5xx
      - ``ok_plain_200``: plain 200
      - ``unknown``: anything else
    """
    code = int(status_code or 0)
    text = body or ""

    if code == 200:
        if _AUTH_KEYWORDS.search(text):
            return "auth_candidate_200"
        return "ok_plain_200"
    if code in (401, 403):
        return "bypass_candidate_401_403"
    if code == 404:
        return "not_found_404"
    if 500 <= code <= 599:
        return "server_error_5xx"
    return "unknown"


def is_heavy_tool_candidate(status_code: int, body: str = "") -> bool:
    """Whether heavy tools (sqlmap/commix) may target this response.

    Per spec: heavy tools run ONLY on 200 auth-keyword endpoints,
    401/403 bypass candidates, or user-chosen endpoints.
    """
    category = classify_status(status_code, body)
    return category in ("auth_candidate_200", "bypass_candidate_401_403")


def has_error_keywords(body: str) -> bool:
    """Whether a response body leaks error/stack information."""
    return bool(_ERROR_KEYWORDS.search(body or ""))


def classify_response(response: dict[str, Any]) -> str:
    """Classify a ``{status_code, body}`` dict (probe result shape)."""
    return classify_status(
        int(response.get("status_code", 0) or 0), str(response.get("body", "") or "")
    )
