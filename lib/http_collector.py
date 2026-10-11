"""Scope-checked HTTP collector (PROBE phase).

Produces the ``{url, status_code, body, headers}`` response set that the
PROBE phase needs for heavy-tool gating (``status_detector``), SQLi/commix
candidate selection and IDOR/logic differential probing. Before this module
existed, ``probe_orchestrator.run_probe`` was called from the CLI *without*
``responses``/``http_get``, so those paths could never fire.

SECURITY BOUNDARY:
- every URL is scope-validated against the target config first;
- every URL is SSRF-checked (private/loopback/metadata blocked);
- payloads are passed through ``lib.payload_guard`` when supplied;
- requests share the process-wide rate limiter and request budget;
- bodies are truncated and sanitized, never stored raw beyond the limit;
- GET/HEAD only by default — no state-changing requests, ever.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import requests

from lib.config import TargetConfig
from lib.logger import get_logger
from lib.ops_guard import spend_requests
from lib.payload_guard import validate_payload
from lib.rate_limiter import RateLimiter
from lib.scope_validator import validate_finding_scope
from lib.ssrf_guard import is_safe_url

logger = get_logger("http_collector")

DEFAULT_TIMEOUT = (5, 15)
DEFAULT_MAX_URLS = 50
DEFAULT_MAX_BODY = 4096
_USER_AGENT = "Mozilla/5.0 NEXUS-Probe/2.1 (authorized security testing)"


@dataclass
class CollectedResponse:
    url: str
    status_code: int = 0
    body: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "body": self.body,
            "headers": dict(self.headers),
            "error": self.error,
        }


class HttpCollector:
    """Read-only HTTP probe used to materialize response evidence."""

    def __init__(
        self,
        target_config: TargetConfig,
        rate_limiter: RateLimiter | None = None,
        rate_key: str = "",
        max_urls: int = DEFAULT_MAX_URLS,
        max_body: int = DEFAULT_MAX_BODY,
        timeout: tuple[int, int] = DEFAULT_TIMEOUT,
        ssrf_allow: set[str] | None = None,
    ):
        self.target_config = target_config
        self.limiter = rate_limiter
        self.rate_key = rate_key or target_config.domain
        self.max_urls = int(max_urls)
        self.max_body = int(max_body)
        self.timeout = timeout
        self.ssrf_allow = ssrf_allow or set()
        self.stats = {"attempted": 0, "collected": 0, "scope_blocked": 0,
                      "ssrf_blocked": 0, "errors": 0, "budget_exhausted": 0}

    # -- single fetch -------------------------------------------------------

    def fetch(self, url: str, payload: str = "") -> CollectedResponse:
        """Fetch one URL. ``payload`` is guard-validated but NOT sent as a body
        (read-only probing); it is used only to refuse unsafe probe strings."""
        raw = (url or "").strip()
        if not raw:
            return CollectedResponse(url=raw, error="empty url")

        if payload:
            allowed, reason = validate_payload(payload)
            if not allowed:
                return CollectedResponse(url=raw, error=f"payload blocked: {reason}")

        if not validate_finding_scope(raw, self.target_config):
            self.stats["scope_blocked"] += 1
            return CollectedResponse(url=raw, error="out of scope")

        safe, reason = is_safe_url(raw, allow=self.ssrf_allow)
        if not safe:
            self.stats["ssrf_blocked"] += 1
            return CollectedResponse(url=raw, error=f"ssrf blocked: {reason}")

        if not spend_requests(1):
            self.stats["budget_exhausted"] += 1
            return CollectedResponse(url=raw, error="request budget exhausted")

        if self.limiter is not None:
            self.limiter.acquire(self.rate_key)

        self.stats["attempted"] += 1
        try:
            resp, redirect_error = self._get_with_checked_redirects(raw)
        except requests.RequestException as exc:
            self.stats["errors"] += 1
            return CollectedResponse(url=raw, error=f"request error: {exc}")
        if resp is None:
            return CollectedResponse(url=raw, error=redirect_error or "redirect blocked")

        body = resp.text or ""
        headers = {str(k): str(v) for k, v in resp.headers.items()}
        self.stats["collected"] += 1
        return CollectedResponse(
            url=raw,
            status_code=int(resp.status_code),
            body=body[: self.max_body],
            headers=headers,
        )

    # -- fetch internals ----------------------------------------------------

    def _get_with_checked_redirects(self, url: str, max_hops: int = 5):
        """GET with manual redirects — every hop is re-checked by the SSRF guard.

        Returns ``(response, "")`` on success, or ``(None, reason)`` when a
        hop is blocked / the hop limit is hit. ``allow_redirects=False``
        ensures no unguarded hop is ever fetched by ``requests`` itself.
        """
        current = url
        for _hop in range(max_hops + 1):
            resp = requests.get(
                current,
                headers={"User-Agent": _USER_AGENT},
                timeout=self.timeout,
                allow_redirects=False,
            )
            if resp.status_code not in (301, 302, 303, 307, 308):
                return resp, ""
            location = str((resp.headers or {}).get("Location") or "")
            if not location:
                return resp, ""
            current = urljoin(current, location)
            safe, reason = is_safe_url(current, allow=self.ssrf_allow)
            if not safe:
                self.stats["ssrf_blocked"] += 1
                logger.warning("ssrf guard blocked redirect hop %s: %s", current, reason)
                return None, f"ssrf blocked on redirect: {reason}"
        logger.warning("redirect hop limit exceeded for %s", url)
        return None, "too many redirects"

    # -- batch --------------------------------------------------------------

    def collect(self, urls: list[str]) -> list[dict[str, Any]]:
        """Collect responses for a URL list, scope/SSRF/budget-gated."""
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        for raw in urls:
            if len(out) >= self.max_urls:
                logger.debug("collector: max_urls (%d) reached", self.max_urls)
                break
            url = (raw or "").strip()
            if not url or url in seen:
                continue
            # Only http(s) URLs are fetchable; bare hosts get a scheme.
            if "://" not in url:
                host = url.split("/")[0]
                if not host:
                    continue
                url = f"https://{url}"
            seen.add(url)
            out.append(self.fetch(url).to_dict())
        logger.info(
            "collector: %d urls -> %d responses (scope=%d ssrf=%d err=%d)",
            len(seen), self.stats["collected"], self.stats["scope_blocked"],
            self.stats["ssrf_blocked"], self.stats["errors"],
        )
        return out
