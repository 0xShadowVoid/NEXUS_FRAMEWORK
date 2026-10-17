"""OWASP ZAP adapter (Task 14).

Integrates a running ZAP instance through its documented JSON REST API:

    GET /JSON/core/view/version/          connection + version
    GET /JSON/core/view/mode/             current mode (safe/protect/standard/attack)
    GET /JSON/spider/action/scan/         start crawl (discovery, non-intrusive)
    GET /JSON/ascan/action/scan/          start ACTIVE scan (intrusive)
    GET /JSON/spider/view/status/         spider status 0..100
    GET /JSON/ascan/view/status/          active-scan status 0..100
    GET /JSON/{spider,ascan}/action/stop/ cancel
    GET /JSON/core/view/alerts/           retrieve alerts (findings)

Design notes:

- The adapter only *translates*; scope, authorization, budgets and the kill
  switch are enforced by :class:`lib.adapters.base.GuardedAdapter`.
- Active scanning is only reachable through :data:`KIND_ACTIVE`, which the
  guard refuses unless policy allows it AND the run is explicitly authorized.
- Alerts and HTTP content are untrusted: every string field is length-capped
  and sanitized before it becomes a :class:`RawFinding`.
- The HTTP transport is injectable, so the whole adapter is exercised offline
  with mocked responses (no live ZAP required).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlencode

from lib.adapters.base import (
    KIND_ACTIVE,
    KIND_PASSIVE,
    KIND_SPIDER,
    STATUS_COMPLETED,
    STATUS_RUNNING,
    AdapterAuthError,
    AdapterCapability,
    AdapterError,
    AdapterHealth,
    AdapterProtocolError,
    AdapterTimeout,
    AdapterUnavailable,
    JobHandle,
    JobSpec,
    RawFinding,
    SecurityToolAdapter,
    confidence_from_word,
    severity_from_risk,
)
from lib.adapters.registry import api_key_for, register
from lib.logger import get_logger
from lib.ssrf_guard import is_safe_url

logger = get_logger("adapters.zap")

DEFAULT_BASE_URL = "http://127.0.0.1:8080"
DEFAULT_TIMEOUT: tuple[int, int] = (3, 30)

#: Supported job kinds → ZAP component that runs them.
_KIND_COMPONENT = {
    KIND_PASSIVE: "spider",   # passive analysis rides along with spider traffic
    KIND_SPIDER: "spider",
    KIND_ACTIVE: "ascan",
}

#: Advertised capabilities (capability discovery).
_CAPABILITIES = (
    AdapterCapability("passive-scan", active=False,
                      description="Passive, traffic-driven analysis (no injection)"),
    AdapterCapability("spider", active=False,
                      description="Crawl a target to discover endpoints"),
    AdapterCapability("active-scan", active=True,
                      description="Intrusive active scanning (requires authorization)"),
    AdapterCapability("alert-retrieval", active=False,
                      description="Retrieve normalized alerts as findings"),
)

#: Fields echoed from a ZAP alert that may carry request/response content.
_UNTRUSTED_FIELDS = ("evidence", "otherinfo", "attack", "param", "description")


def _safe_text(value: Any, limit: int = 2000) -> str:
    from lib.adapters.base import sanitize_untrusted

    return sanitize_untrusted(value, limit)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ZapAdapter(SecurityToolAdapter):
    """Adapter for a running OWASP ZAP instance (JSON REST API)."""

    name = "zap"

    def __init__(
        self,
        base_url: str = "",
        api_key: str = "",
        timeout: tuple[int, int] | None = None,
        transport: Callable[[str], tuple[int, str]] | None = None,
        ssrf_allow: set[str] | None = None,
    ):
        self.base_url = (base_url or DEFAULT_BASE_URL).strip().rstrip("/")
        self.api_key = api_key or ""
        self.timeout = tuple(timeout) if timeout else DEFAULT_TIMEOUT
        self._transport = transport
        self.ssrf_allow = set(ssrf_allow or set())

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"ZapAdapter(base_url={self.base_url!r})"

    # -- config -------------------------------------------------------------

    def validate_config(self) -> list[str]:
        issues: list[str] = []
        if not self.base_url:
            issues.append("zap: base_url is not configured")
        elif not self.base_url.startswith(("http://", "https://")):
            issues.append("zap: base_url must be an http(s) URL")
        return issues

    # -- transport ----------------------------------------------------------

    def _default_transport(self, url: str) -> tuple[int, str]:
        import requests

        try:
            resp = requests.get(url, timeout=self.timeout)
        except requests.Timeout as exc:
            raise AdapterTimeout(f"zap request timed out: {exc}") from exc
        except requests.RequestException as exc:
            raise AdapterUnavailable(f"zap unreachable: {exc.__class__.__name__}") from exc
        return int(resp.status_code), resp.text

    def _http(self, url: str) -> tuple[int, str]:
        transport = self._transport or self._default_transport
        try:
            status, text = transport(url)
        except (AdapterError,):
            raise
        except TimeoutError as exc:
            raise AdapterTimeout(str(exc) or "zap request timed out") from exc
        except Exception as exc:  # connection refused, DNS, injected failures
            raise AdapterUnavailable(
                f"zap unreachable: {exc.__class__.__name__}"
            ) from exc
        return int(status), text or ""

    def _endpoint(self, component: str, view: str, name: str, params: dict[str, Any] | None = None) -> str:
        query = {str(k): str(v) for k, v in (params or {}).items() if v is not None}
        if self.api_key:
            query.setdefault("apikey", self.api_key)
        qs = urlencode(query)
        return f"{self.base_url}/JSON/{component}/{view}/{name}/" + (f"?{qs}" if qs else "")

    def _api(self, component: str, view: str, name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Call one ZAP API method, returning its JSON object (normalized errors)."""
        safe, reason = is_safe_url(self.base_url, allow=self.ssrf_allow, local_ok=True)
        if not safe:
            raise AdapterError(f"zap endpoint blocked by SSRF guard: {reason}")
        url = self._endpoint(component, view, name, params)
        status, text = self._http(url)
        if status in (401, 403):
            raise AdapterAuthError(f"zap authentication failed (HTTP {status})")
        if status >= 500 or (400 <= status < 500):
            raise AdapterProtocolError(f"zap returned HTTP {status} for {name}")
        try:
            payload = json.loads(text) if text.strip() else {}
        except ValueError as exc:
            raise AdapterProtocolError(f"zap returned malformed JSON for {name}") from exc
        if not isinstance(payload, dict):
            raise AdapterProtocolError(f"zap returned unexpected payload for {name}")
        code = payload.get("code")
        if code is not None:
            try:
                int_code = int(code)
            except (TypeError, ValueError):
                int_code = 0
            if int_code in (401, 403):
                raise AdapterAuthError(
                    f"zap authentication failed: {payload.get('message') or int_code}"
                )
            if int_code >= 400:
                raise AdapterProtocolError(str(payload.get("message") or f"zap error {int_code}"))
        return payload

    # -- discovery ----------------------------------------------------------

    def capabilities(self) -> list[AdapterCapability]:
        return list(_CAPABILITIES)

    def health(self) -> AdapterHealth:
        health = AdapterHealth(name=self.name)
        if not self.base_url:
            health.error = "no base_url configured"
            return health
        try:
            version = self._api("core", "view", "version")
        except AdapterError as exc:
            health.error = str(exc)
            logger.debug("zap health check failed: %s", health.error)
            return health
        health.reachable = True
        health.version = str(version.get("version") or "")
        try:
            mode = self._api("core", "view", "mode")
            health.mode = str(mode.get("mode") or "")
        except AdapterError:
            health.mode = ""
        return health

    # -- jobs ---------------------------------------------------------------

    def start_job(self, job: JobSpec) -> JobHandle:
        component = _KIND_COMPONENT.get(job.kind)
        if component is None:
            raise AdapterError(f"unsupported job kind: {job.kind!r}")
        if not str(job.target or "").strip():
            raise AdapterError("job target is required")
        params = {"url": job.target, "recurse": str(bool(job.params.get("recurse", True))).lower()}
        payload = self._api(component, "action", "scan", params)
        scan_id = payload.get("scan")
        if scan_id is None:
            raise AdapterProtocolError("zap did not return a scan id")
        handle = JobHandle(
            job_id=str(scan_id),
            adapter=self.name,
            target=job.target,
            kind=job.kind,
            status=STATUS_RUNNING,
            started_at=_now(),
            updated_at=_now(),
            raw={
                "component": component,
                "scan_id": str(scan_id),
                "poll_interval": float(job.poll_interval or 1.0),
                "timeout": float(job.timeout or 0.0),
                "target": job.target,
            },
        )
        return handle

    def job_status(self, handle: JobHandle) -> JobHandle:
        component = str(handle.raw.get("component") or "spider")
        scan_id = str(handle.raw.get("scan_id") or handle.job_id)
        payload = self._api(component, "view", "status", {"scanId": scan_id})
        raw_status = payload.get("status")
        try:
            progress = int(raw_status)
        except (TypeError, ValueError) as exc:
            raise AdapterProtocolError("zap returned a non-numeric scan status") from exc
        handle.progress = max(0, min(100, progress))
        handle.status = STATUS_COMPLETED if progress >= 100 else STATUS_RUNNING
        handle.updated_at = _now()
        return handle

    def cancel_job(self, handle: JobHandle) -> bool:
        component = str(handle.raw.get("component") or "spider")
        scan_id = str(handle.raw.get("scan_id") or handle.job_id)
        try:
            self._api(component, "action", "stop", {"scanId": scan_id})
        except AdapterError:
            return False
        handle.status = "cancelled"
        return True

    # -- findings -----------------------------------------------------------

    def collect(self, handle: JobHandle) -> list[RawFinding]:
        target = str(handle.raw.get("target") or handle.target or "")
        params = {"baseurl": target} if target else None
        payload = self._api("core", "view", "alerts", params)
        alerts = payload.get("alerts")
        if alerts is None:
            raise AdapterProtocolError("zap returned no alerts collection")
        if not isinstance(alerts, list):
            raise AdapterProtocolError("zap alerts payload is not a list")
        return [self.normalize_alert(a) for a in alerts if isinstance(a, dict)]

    def normalize_alert(self, alert: dict[str, Any]) -> RawFinding:
        """Translate one ZAP alert into a normalized, sanitized finding."""
        extra = {
            "alert_ref": str(alert.get("alertRef") or ""),
            "wasc_id": str(alert.get("wascid") or ""),
            "source_id": str(alert.get("sourceid") or ""),
        }
        return RawFinding(
            adapter=self.name,
            source="zap",
            name=_safe_text(alert.get("alert") or alert.get("name") or "ZAP alert", 300),
            severity=severity_from_risk(alert.get("risk")),
            confidence=confidence_from_word(alert.get("confidence")),
            endpoint=_safe_text(alert.get("url"), 2000),
            method=str(alert.get("method") or "GET").upper(),
            param=_safe_text(alert.get("param"), 300),
            description=_safe_text(alert.get("description"), 3000),
            solution=_safe_text(alert.get("solution"), 2000),
            reference=_safe_text(alert.get("reference"), 1000),
            cwe_id=str(alert.get("cweid") or ""),
            evidence=_safe_text(alert.get("evidence"), 2000),
            other_info=_safe_text(alert.get("otherinfo"), 2000),
            plugin_id=str(alert.get("pluginId") or ""),
            alert_id=str(alert.get("id") or ""),
            extra=extra,
        )


@register("zap")
def build_zap(spec: dict[str, Any]) -> ZapAdapter:
    """Factory registered as ``zap`` (reads ``integrations.zap`` config)."""
    timeout_seconds = int(spec.get("timeout_seconds") or 0)
    timeout = (3, timeout_seconds) if timeout_seconds else None
    ssrf_allow = {str(h).strip().lower() for h in (spec.get("ssrf_allow") or []) if str(h).strip()}
    return ZapAdapter(
        base_url=str(spec.get("base_url") or DEFAULT_BASE_URL),
        api_key=api_key_for(spec),
        timeout=timeout,
        transport=None,
        ssrf_allow=ssrf_allow,
    )


# ---------------------------------------------------------------------------
# Offline mock (tests, dry runs, `nexus zap --mock`)
# ---------------------------------------------------------------------------


class FakeZapBackend:
    """Deterministic in-memory stand-in for a ZAP REST endpoint.

    Configured with canned alerts and an optional failure mode so the adapter's
    parsing/error paths are exercised without a live ZAP.
    """

    def __init__(
        self,
        version: str = "2.15.0",
        mode: str = "standard",
        alerts: list[dict[str, Any]] | None = None,
        fail: str = "",
        status_seq: list[int] | None = None,
    ):
        self.version = version
        self.mode = mode
        self.alerts = alerts if alerts is not None else [default_alert()]
        self.fail = fail                         # "" | "auth" | "unreachable" | "malformed" | "server"
        self.status_seq = list(status_seq or [100])
        self._idx = 0

    def _json(self, obj: Any) -> tuple[int, str]:
        return 200, json.dumps(obj)

    def __call__(self, url: str) -> tuple[int, str]:
        if self.fail == "unreachable":
            raise ConnectionError("connection refused")
        if self.fail == "auth":
            return self._json({"code": "401", "message": "invalid API key"})
        if url.endswith("/JSON/core/view/version/"):
            if self.fail == "malformed":
                return 200, "<html>not json</html>"
            return self._json({"version": self.version})
        if url.endswith("/JSON/core/view/mode/"):
            return self._json({"mode": self.mode})
        if "/action/scan/" in url:
            return self._json({"scan": "0"})
        if "/view/status/" in url:
            if self.fail == "server":
                return 500, "boom"
            value = self.status_seq[min(self._idx, len(self.status_seq) - 1)]
            self._idx += 1
            return self._json({"status": str(value)})
        if "/action/stop/" in url:
            return self._json({"Result": "OK"})
        if "/JSON/core/view/alerts/" in url:
            return self._json({"alerts": list(self.alerts)})
        return 404, "not found"


def default_alert() -> dict[str, Any]:
    """One representative ZAP alert (used by the mock backend)."""
    return {
        "id": "1",
        "pluginId": "10038",
        "alertRef": "10038",
        "alert": "Content Security Policy (CSP) Header Not Set",
        "risk": "Medium",
        "confidence": "High",
        "url": "http://example.com/",
        "method": "GET",
        "param": "",
        "attack": "",
        "evidence": "Missing CSP header",
        "otherinfo": "",
        "description": "CSP is not set.",
        "solution": "Add a Content-Security-Policy header.",
        "reference": "https://owasp.org/www-project-secure-headers/",
        "cweid": "693",
        "wascid": "15",
        "sourceid": "1",
    }


class MockZapAdapter(ZapAdapter):
    """Offline ZAP adapter backed by :class:`FakeZapBackend` (no network)."""

    def __init__(self, backend: FakeZapBackend | None = None, **kwargs: Any):
        backend = backend or FakeZapBackend()
        kwargs.setdefault("base_url", DEFAULT_BASE_URL)
        super().__init__(transport=backend, **kwargs)
        self._backend = backend
