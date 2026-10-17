"""Burp Suite adapter (Task 18).

Integrates a running **Burp Suite Professional** instance through its
documented REST API (``Settings → Suite → REST API``):

    {service_url}/{api_key}/v0.1/knowledge_base/issue_definitions   discovery
    {service_url}/{api_key}/v0.1/scan                               start scan
    {service_url}/{api_key}/v0.1/scan/{id}                          status + issues

Supported interface (verified against PortSwigger's documentation):

* ``GET  .../v0.1/knowledge_base/issue_definitions`` — live capability/issue
  discovery, and the cheapest authenticated liveness probe.
* ``POST .../v0.1/scan`` — start a **crawl + audit** scan (returns a scan id).
* ``GET  .../v0.1/scan/{id}`` — scan status/metrics and the issues found
  (``issue_events`` embedded in the scan resource).

Documented limitations (not implemented here, on purpose):

* Burp **Community Edition has no REST API**; only Professional (and the
  separate DAST/Enterprise product) expose one. A missing service therefore
  surfaces as ``AdapterUnavailable``, not a fabricated result.
* The REST API exposes **no** HTTP-proxy-history or site-map endpoint; that
  data is only reachable through a Montoya/BApp **extension** loaded into Burp
  or the desktop UI. We do not pretend otherwise.
* There is **no documented stop/cancel endpoint**. :meth:`BurpAdapter.cancel_job`
  therefore returns ``False`` rather than sending a destructive delete, and a
  client-side timeout/cancellation is **never** reported as proof that Burp
  stopped working.
* Burp Suite **DAST / Enterprise** uses a different (API-key header, CI-first)
  interface and is out of scope.
* Third-party **MCP** bridges are not relied on: they only wrap the same REST
  API (or a Montoya extension) and do not provide complete Burp control.

The API key is part of the request **path**, so it is treated as a secret:
every diagnostic goes through :func:`lib.redaction.redact_text` and the URL is
logged host-only. Policy (scope, authorization, budgets, kill switch) is
enforced by :class:`lib.adapters.base.GuardedAdapter`; starting a scan is an
intrusive :data:`KIND_ACTIVE` job, while health/discovery/issue retrieval are
read-only.

The HTTP transport is injectable, so the whole adapter is exercised offline
with mocked responses (no live Burp required).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlsplit

from lib.adapters.base import (
    KIND_ACTIVE,
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_RUNNING,
    STATUS_TIMEOUT,
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
    sanitize_untrusted,
    severity_from_risk,
)
from lib.adapters.registry import api_key_for, register
from lib.logger import get_logger
from lib.ssrf_guard import is_safe_url

logger = get_logger("adapters.burp")

DEFAULT_BASE_URL = "http://127.0.0.1:1337"
API_VERSION = "v0.1"
DEFAULT_TIMEOUT: tuple[int, int] = (3, 30)

#: Advertised capabilities (declared; no network I/O).
_CAPABILITIES = (
    AdapterCapability("health", active=False,
                      description="Connection/authentication check against the REST API"),
    AdapterCapability("capability-discovery", active=False,
                      description="List Burp's scanner issue definitions"),
    AdapterCapability("active-scan", active=True,
                      description="Start a crawl + audit scan (intrusive; needs authorization)"),
    AdapterCapability("issue-retrieval", active=False,
                      description="Retrieve and normalize a scan's issues"),
)

#: Burp scan_status → NEXUS normalized status.
_STATUS_MAP = {
    "succeeded": STATUS_COMPLETED,
    "failed": STATUS_FAILED,
    "running": STATUS_RUNNING,
    "paused": STATUS_RUNNING,
    "scheduled": STATUS_PENDING,
}

#: Burp confidence words → 0-100 (falls back to the shared mapper).
_BURP_CONFIDENCE = {"certain": 95, "firm": 75, "tentative": 40}


def _safe_text(value: Any, limit: int = 2000) -> str:
    return sanitize_untrusted(value, limit)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _endpoint_label(url: str) -> str:
    """Host-only label for diagnostics (never the key-bearing path)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return "?"
    return f"{parts.scheme}://{parts.hostname}" if parts.hostname else "?"


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _burp_confidence(value: Any) -> int:
    word = str(value or "").strip().lower()
    if word in _BURP_CONFIDENCE:
        return _BURP_CONFIDENCE[word]
    return confidence_from_word(value)


class BurpAdapter(SecurityToolAdapter):
    """Adapter for a running Burp Suite Professional REST API."""

    name = "burp"

    def __init__(
        self,
        base_url: str = "",
        api_key: str = "",
        timeout: tuple[int, int] | None = None,
        transport: Callable[[str, str, str], tuple[int, str]] | None = None,
        ssrf_allow: set[str] | None = None,
    ):
        self.base_url = (base_url or DEFAULT_BASE_URL).strip().rstrip("/")
        self.api_key = api_key or ""
        self.timeout = tuple(timeout) if timeout else DEFAULT_TIMEOUT
        self._transport = transport
        self.ssrf_allow = set(ssrf_allow or set())

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"BurpAdapter(base_url={self.base_url!r})"

    # -- config -------------------------------------------------------------

    def validate_config(self) -> list[str]:
        issues: list[str] = []
        if not self.base_url:
            issues.append("burp: base_url is not configured")
        elif not self.base_url.startswith(("http://", "https://")):
            issues.append("burp: base_url must be an http(s) URL")
        return issues

    # -- transport ----------------------------------------------------------

    def _default_transport(self, method: str, url: str, body: str) -> tuple[int, str]:
        import requests

        headers = {"Content-Type": "application/json"} if body else {}
        try:
            resp = requests.request(method, url, data=body or None, headers=headers,
                                    timeout=self.timeout)
        except requests.Timeout as exc:
            raise AdapterTimeout("burp request timed out") from exc
        except requests.RequestException as exc:
            raise AdapterUnavailable(f"burp unreachable: {exc.__class__.__name__}") from exc
        return int(resp.status_code), resp.text

    def _http(self, method: str, url: str, body: str = "") -> tuple[int, str]:
        transport = self._transport or self._default_transport
        try:
            status, text = transport(method, url, body)
        except AdapterError:
            raise
        except TimeoutError as exc:
            raise AdapterTimeout(str(exc) or "burp request timed out") from exc
        except Exception as exc:  # connection refused, DNS, injected failures
            raise AdapterUnavailable(
                f"burp unreachable: {exc.__class__.__name__}"
            ) from exc
        return int(status), text or ""

    def _endpoint(self, path: str) -> str:
        """Build an API URL. The API key (a secret) lives in the path."""
        path = path.lstrip("/")
        if self.api_key:
            return f"{self.base_url}/{self.api_key}/{API_VERSION}/{path}"
        return f"{self.base_url}/{API_VERSION}/{path}"

    def _api(self, method: str, path: str, body: dict | None = None) -> dict[str, Any]:
        """Call one REST API method, returning its JSON object (normalized errors)."""
        safe, reason = is_safe_url(self.base_url, allow=self.ssrf_allow, local_ok=True)
        if not safe:
            raise AdapterError(f"burp endpoint blocked by SSRF guard: {reason}")
        url = self._endpoint(path)
        payload_text = json.dumps(body) if body is not None else ""
        status, text = self._http(method, url, payload_text)
        if status in (401, 403):
            raise AdapterAuthError(f"burp authentication failed (HTTP {status})")
        if status >= 400:
            reason_text = self._error_message(text)
            suffix = f": {reason_text}" if reason_text else ""
            raise AdapterProtocolError(f"burp returned HTTP {status} for {path}{suffix}")
        try:
            payload = json.loads(text) if text.strip() else {}
        except ValueError as exc:
            raise AdapterProtocolError(f"burp returned malformed JSON for {path}") from exc
        if not isinstance(payload, dict):
            raise AdapterProtocolError(f"burp returned unexpected payload for {path}")
        return payload

    @staticmethod
    def _error_message(text: str) -> str:
        """Extract a short, redacted error hint from a Burp error body."""
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return ""
        if isinstance(data, dict):
            raw = data.get("message") or data.get("error") or data.get("reason") or ""
            return _safe_text(raw, 300)
        return ""

    # -- discovery ----------------------------------------------------------

    def capabilities(self) -> list[AdapterCapability]:
        return list(_CAPABILITIES)

    def issue_definitions(self) -> list[dict[str, Any]]:
        """Live capability discovery: Burp's scanner issue definitions."""
        payload = self._api("GET", "knowledge_base/issue_definitions")
        defs = payload.get("issue_definitions")
        if defs is None and isinstance(payload.get("issue_types"), list):
            defs = payload.get("issue_types")
        if not isinstance(defs, list):
            raise AdapterProtocolError("burp returned no issue_definitions collection")
        return [d for d in defs if isinstance(d, dict)]

    def health(self) -> AdapterHealth:
        health = AdapterHealth(name=self.name)
        if not self.base_url:
            health.error = "no base_url configured"
            return health
        health.details["api"] = f"Burp Suite Professional REST API {API_VERSION}"
        health.details["auth"] = "api-key" if self.api_key else "none"
        try:
            definitions = self.issue_definitions()
        except AdapterError as exc:
            health.error = str(exc)
            logger.debug("burp health check failed: %s", health.error)
            return health
        health.reachable = True
        health.details["issue_definition_count"] = len(definitions)
        # The REST API does not expose a version string.
        return health

    # -- jobs ---------------------------------------------------------------

    def start_job(self, job: JobSpec) -> JobHandle:
        if job.kind != KIND_ACTIVE:
            raise AdapterError(
                f"unsupported job kind: {job.kind!r} "
                "(Burp's REST API only starts crawl+audit scans)"
            )
        if not str(job.target or "").strip():
            raise AdapterError("job target is required")
        body: dict[str, Any] = {"urls": [job.target]}
        for key in ("scan_configurations", "application_logins", "scope"):
            if job.params.get(key):
                body[key] = job.params[key]
        payload = self._api("POST", "scan", body)
        scan_id = payload.get("scan_id") or payload.get("task_id")
        if scan_id is None:
            raise AdapterProtocolError("burp did not return a scan id")
        return JobHandle(
            job_id=str(scan_id),
            adapter=self.name,
            target=job.target,
            kind=job.kind,
            status=STATUS_RUNNING,
            started_at=_now(),
            updated_at=_now(),
            raw={
                "scan_id": str(scan_id),
                "poll_interval": float(job.poll_interval or 1.0),
                "timeout": float(job.timeout or 0.0),
                "target": job.target,
            },
        )

    def job_status(self, handle: JobHandle) -> JobHandle:
        scan_id = str(handle.raw.get("scan_id") or handle.job_id)
        payload = self._api("GET", f"scan/{scan_id}")
        raw_status = str(payload.get("scan_status") or "").strip().lower()
        handle.status = _STATUS_MAP.get(raw_status, STATUS_RUNNING)
        handle.progress = _progress(payload.get("scan_metrics"))
        if handle.status == STATUS_COMPLETED:
            handle.progress = 100
        handle.message = raw_status or handle.message
        handle.updated_at = _now()
        return handle

    def cancel_job(self, handle: JobHandle) -> bool:
        """Not supported: Burp's REST API has no documented stop endpoint.

        We deliberately do not send a destructive scan-delete. Returning
        ``False`` signals that the request was not accepted, and the caller
        must not assume the scan stopped.
        """
        logger.info("burp: no documented cancel endpoint; not requesting a stop")
        return False

    def wait(self, handle: JobHandle, **kwargs: Any) -> JobHandle:
        """Poll to completion/timeout, flagging that Burp may still be running.

        A client-side timeout or kill-switch stop means *we stopped waiting*,
        not that Burp stopped the scan (no stop endpoint exists).
        """
        handle = super().wait(handle, **kwargs)
        if handle.status in (STATUS_CANCELLED, STATUS_TIMEOUT):
            handle.raw["burp_may_still_be_running"] = True
            note = "note: Burp may still be scanning (no stop endpoint)"
            if note not in handle.message:
                handle.message = f"{handle.message}; {note}" if handle.message else note
        return handle

    # -- findings -----------------------------------------------------------

    def collect(self, handle: JobHandle) -> list[RawFinding]:
        scan_id = str(handle.raw.get("scan_id") or handle.job_id)
        payload = self._api("GET", f"scan/{scan_id}")
        issues = self._issues_from_scan(payload)
        return [self.normalize_issue(issue) for issue in issues]

    @staticmethod
    def _issues_from_scan(payload: dict[str, Any]) -> list[dict[str, Any]]:
        events = payload.get("issue_events")
        if events is not None:
            if not isinstance(events, list):
                raise AdapterProtocolError("burp issue_events payload is not a list")
            items: list[dict[str, Any]] = []
            for event in events:
                if not isinstance(event, dict):
                    continue
                issue = event.get("issue")
                if isinstance(issue, dict):
                    items.append(issue)
                elif event.get("name") or event.get("severity"):
                    items.append(event)
            return items
        issues = payload.get("issues")
        if issues is not None:
            if not isinstance(issues, list):
                raise AdapterProtocolError("burp issues payload is not a list")
            return [i for i in issues if isinstance(i, dict)]
        raise AdapterProtocolError("burp scan response contained no issues collection")

    def normalize_issue(self, issue: dict[str, Any]) -> RawFinding:
        """Translate one Burp issue into a normalized, sanitized finding."""
        extra = {
            "burp_confidence": str(issue.get("confidence") or ""),
            "type_index": str(issue.get("type_index") or issue.get("issue_type_index") or ""),
            "serial_number": str(issue.get("serial_number") or ""),
        }
        return RawFinding(
            adapter=self.name,
            source="burp",
            name=_safe_text(issue.get("name") or issue.get("issue_type") or "Burp issue", 300),
            severity=severity_from_risk(issue.get("severity")),
            confidence=_burp_confidence(issue.get("confidence")),
            endpoint=_safe_text(issue.get("origin") or issue.get("url") or issue.get("path"), 2000),
            method=str(issue.get("method") or "GET").upper(),
            param=_safe_text(issue.get("parameter") or issue.get("param"), 300),
            description=_safe_text(
                issue.get("description") or issue.get("issue_background")
                or issue.get("issue_detail"), 3000,
            ),
            solution=_safe_text(
                issue.get("remediation") or issue.get("remediation_background"), 2000,
            ),
            reference=_safe_text(issue.get("reference") or issue.get("references"), 1000),
            cwe_id=str(issue.get("cwe") or issue.get("cwe_id") or ""),
            evidence=_evidence_text(issue.get("evidence")),
            other_info=_evidence_text(issue.get("issue_detail") or issue.get("request_response"), 2000),
            plugin_id=str(issue.get("type_index") or issue.get("issue_type_index") or ""),
            alert_id=str(issue.get("serial_number") or issue.get("id") or ""),
            extra=extra,
        )


def _progress(metrics: Any) -> int:
    """Best-effort 0..100 progress from a scan's metrics (0 when unknown)."""
    if not isinstance(metrics, dict):
        return 0
    audit_done = _as_int(metrics.get("audit_queue_items_completed"))
    audit_wait = _as_int(metrics.get("audit_queue_items_waiting"))
    if audit_done + audit_wait:
        return max(0, min(100, int(100 * audit_done / (audit_done + audit_wait))))
    crawl_done = _as_int(metrics.get("crawl_requests_completed"))
    crawl_pend = _as_int(metrics.get("crawl_requests_pending"))
    if crawl_done + crawl_pend:
        return max(0, min(100, int(100 * crawl_done / (crawl_done + crawl_pend))))
    return 0


def _evidence_text(value: Any, limit: int = 2000) -> str:
    """Render untrusted evidence (Burp returns lists of request/response blobs)."""
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, dict):
                for key in ("request", "response", "detail", "highlight"):
                    if item.get(key):
                        parts.append(f"{key}: {item[key]}")
            elif item is not None:
                parts.append(str(item))
        return _safe_text("\n".join(parts), limit)
    if isinstance(value, dict):
        return _safe_text(json.dumps(value, default=str), limit)
    return _safe_text(value, limit)


@register("burp")
def build_burp(spec: dict[str, Any]) -> BurpAdapter:
    """Factory registered as ``burp`` (reads ``integrations.burp`` config)."""
    timeout_seconds = int(spec.get("timeout_seconds") or 0)
    timeout = (3, timeout_seconds) if timeout_seconds else None
    ssrf_allow = {str(h).strip().lower() for h in (spec.get("ssrf_allow") or []) if str(h).strip()}
    return BurpAdapter(
        base_url=str(spec.get("base_url") or DEFAULT_BASE_URL),
        api_key=api_key_for(spec),
        timeout=timeout,
        transport=None,
        ssrf_allow=ssrf_allow,
    )


# ---------------------------------------------------------------------------
# Offline mock (tests, dry runs, `nexus burp --mock`)
# ---------------------------------------------------------------------------


class FakeBurpBackend:
    """Deterministic in-memory stand-in for a Burp REST endpoint.

    Configured with canned issues and an optional failure mode so the adapter's
    parsing/error paths are exercised without a live Burp.
    """

    def __init__(
        self,
        scan_status: str = "succeeded",
        issues: list[dict[str, Any]] | None = None,
        issue_definitions: list[dict[str, Any]] | None = None,
        fail: str = "",
        status_seq: list[str] | None = None,
    ):
        self.scan_status = scan_status
        self.issues = issues if issues is not None else [default_issue()]
        self.issue_definitions = (
            issue_definitions if issue_definitions is not None else default_issue_definitions()
        )
        self.fail = fail  # "" | "auth" | "unreachable" | "malformed" | "server"
        self.status_seq = list(status_seq or [])
        self._idx = 0
        self.calls: list[tuple[str, str, str]] = []

    def __call__(self, method: str, url: str, body: str) -> tuple[int, str]:
        self.calls.append((method, url, body))
        if self.fail == "unreachable":
            raise ConnectionError("connection refused")
        if self.fail == "auth":
            return 401, json.dumps({"message": "invalid API key"})
        if "knowledge_base/issue_definitions" in url:
            if self.fail == "malformed":
                return 200, "<html>not json</html>"
            return 200, json.dumps({"issue_definitions": list(self.issue_definitions)})
        if method == "POST" and url.rstrip("/").endswith("/v0.1/scan"):
            return 200, json.dumps({"scan_id": "42"})
        if method == "GET" and "/v0.1/scan/" in url:
            if self.fail == "server":
                return 500, "boom"
            if self.fail == "malformed":
                return 200, "<html>not json</html>"
            status = self.scan_status
            if self.status_seq:
                status = self.status_seq[min(self._idx, len(self.status_seq) - 1)]
                self._idx += 1
            return 200, json.dumps(self._scan_document(status))
        return 404, "not found"

    def _scan_document(self, status: str) -> dict[str, Any]:
        events = [{"type": "issue_found", "issue": issue} for issue in self.issues]
        return {
            "scan_id": "42",
            "scan_status": status,
            "scan_metrics": {
                "crawl_requests_made": 10,
                "crawl_requests_completed": 10,
                "crawl_requests_pending": 0,
                "audit_queue_items_completed": 5,
                "audit_queue_items_waiting": 5,
            },
            "issue_events": events,
        }


def default_issue_definitions() -> list[dict[str, Any]]:
    return [
        {"name": "SQL injection", "type_index": 1049088, "severity": "high"},
        {"name": "Cross-site scripting (reflected)", "type_index": 2097408, "severity": "high"},
        {"name": "TLS cookie without Secure flag set", "type_index": 5243392, "severity": "low"},
    ]


def default_issue() -> dict[str, Any]:
    """One representative Burp issue (used by the mock backend)."""
    return {
        "serial_number": "1",
        "type_index": 1049088,
        "name": "SQL injection",
        "issue_type": "SQL injection",
        "severity": "high",
        "confidence": "certain",
        "origin": "http://example.com/login",
        "path": "/login",
        "method": "POST",
        "parameter": "username",
        "issue_background": "The application appears to be vulnerable to SQL injection.",
        "issue_detail": "The payload ' OR 1=1-- was reflected in a database error.",
        "remediation_background": "Use parameterized queries.",
        "evidence": [{"request": "POST /login HTTP/1.1", "response": "HTTP/1.1 500"}],
    }


class MockBurpAdapter(BurpAdapter):
    """Offline Burp adapter backed by :class:`FakeBurpBackend` (no network)."""

    def __init__(self, backend: FakeBurpBackend | None = None, **kwargs: Any):
        backend = backend or FakeBurpBackend()
        kwargs.setdefault("base_url", DEFAULT_BASE_URL)
        kwargs.setdefault("api_key", "MOCKKEY")
        super().__init__(transport=backend, **kwargs)
        self._backend = backend


# ---------------------------------------------------------------------------
# Read-only retrieval from an existing scan (no scan is started)
# ---------------------------------------------------------------------------


def existing_scan_handle(scan_id: str | int, target: str = "") -> JobHandle:
    """JobHandle for an already-running/finished Burp scan (read-only)."""
    return JobHandle(
        job_id=str(scan_id),
        adapter="burp",
        target=target,
        kind=KIND_ACTIVE,
        status=STATUS_RUNNING,
        raw={"scan_id": str(scan_id), "target": target},
    )
