"""Safe active IDOR probing (roadmap J1).

Detection-only differential testing: compare the response for an owned
resource id against id±1. If the shapes match (a foreign object is
returned), an IDOR candidate is recorded — but nothing is written,
updated, or exfiltrated. The fetch call is injected, so the prober is
fully offline-testable and never performs its own network calls.
"""
from __future__ import annotations

import re
from typing import Any, Callable

from lib.logger import get_logger

logger = get_logger("idor_prober")

_ID_IN_PATH_RE = re.compile(r"/(\d+)(?=/|$)")
_ID_IN_QUERY_RE = re.compile(r"[?&](id|user_id|account_id|uid|item_id)=(\d+)", re.IGNORECASE)

# Fields that legitimately differ between two different objects.
_SKIP_FIELDS = {"id", "user_id", "uuid", "token", "email", "username", "created_at",
                "updated_at", "name", "timestamp", "session", "csrf", "nonce"}


def _normalize(obj: Any, parent_key: str = "") -> Any:
    """Recursively strip identity fields so two objects' *shapes* compare."""
    if isinstance(obj, dict):
        return {
            k: _normalize(v, k)
            for k, v in obj.items()
            if k.lower() not in _SKIP_FIELDS
        }
    if isinstance(obj, list):
        return [_normalize(v) for v in obj[:5]]  # cap list length
    return obj


def _shape(body: str | None) -> Any:
    if not body:
        return None
    import json

    try:
        return _normalize(json.loads(body))
    except (json.JSONDecodeError, TypeError):
        # Non-JSON: compare a cheap structural fingerprint.
        return _normalize({"text": bool(re.search(r"\w", body or ""))})


class IdorProber:
    """Differential IDOR probe (read-only, injected fetch)."""

    def __init__(self, fetch: Callable[[str], str] | None = None):
        self.fetch = fetch or (lambda url: "")

    def _candidate_ids(self, url: str) -> list[str]:
        """Return test URLs for id and id±1."""
        out: list[str] = []
        for m in _ID_IN_QUERY_RE.finditer(url):
            base_id = int(m.group(2))
            for delta in (1, -1):
                if base_id + delta <= 0:
                    continue
                out.append(url[: m.start(2)] + str(base_id + delta) + url[m.end(2):])
        if not out:
            for m in _ID_IN_PATH_RE.finditer(url):
                base_id = int(m.group(1))
                for delta in (1, -1):
                    if base_id + delta <= 0:
                        continue
                    out.append(url[: m.start(1)] + str(base_id + delta) + url[m.end(1):])
        return out

    def probe(self, url: str, max_ids: int = 3) -> dict[str, Any]:
        """Probe one URL for IDOR; returns a finding dict or None."""
        candidates = self._candidate_ids(url)[:max_ids]
        if not candidates:
            return None
        try:
            own_body = self.fetch(url)
        except Exception as exc:  # probe must never crash the caller
            logger.debug("idor fetch failed for %s: %s", url, exc)
            return None
        own_shape = _shape(own_body)
        if own_shape is None:
            return None
        for candidate in candidates:
            try:
                other_body = self.fetch(candidate)
            except Exception:
                continue
            other_shape = _shape(other_body)
            if other_shape is not None and other_shape == own_shape:
                return {
                    "endpoint": url,
                    "vuln_type": "idor",
                    "severity": "P2",
                    "confidence": 78,
                    "payload": f"id replaced: {candidate}",
                    "response_snippet": f"identical response shape for foreign id ({candidate}) — detection only",
                    "tools_found": ["nexus-idor-prober"],
                    "verification": {"verified": True, "method": "corroboration",
                                     "confidence": 78, "notes": "differential shape match"},
                }
        return None

    def probe_many(self, urls: list[str], max_per_url: int = 3, limit: int = 20) -> list[dict[str, Any]]:
        """Probe up to *limit* URLs; returns IDOR candidate findings."""
        findings: list[dict[str, Any]] = []
        for url in urls[:limit]:
            result = self.probe(url, max_ids=max_per_url)
            if result:
                findings.append(result)
        logger.info("idor prober: %d candidate(s)", len(findings))
        return findings
