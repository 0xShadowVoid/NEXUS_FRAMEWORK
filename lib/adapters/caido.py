"""Caido adapter (Task 19).

Integrates a running **Caido** instance through its documented, officially
public **instance GraphQL API** (``POST <base_url>/graphql``). Caido's own
``@caido/sdk-client`` ("Client SDK") is a thin wrapper over exactly this
endpoint, so we speak it directly rather than depending on a Node/TypeScript
SDK or a community bridge.

Verified against Caido's published documentation and schema
(``docs.caido.io``, ``developer.caido.io/client-sdk``, ``caido/schemas``):

    POST <base_url>/graphql   { viewer { __typename id } }        liveness + auth
    POST <base_url>/graphql   { __schema { queryType { … } } }    live introspection
    POST <base_url>/graphql   { findings(…) { edges { node } } }  retrieval
    POST <base_url>/graphql   { requests(…) { edges { node } } }  retrieval

Documented interface facts and limitations (not invented):

* The **instance GraphQL API is intentionally public** "to assist with the
  development of third-party tools", but **stability is not guaranteed** —
  each release may change the schema. Field names here follow the published
  SDK/schema; a schema change surfaces as a normalized ``AdapterProtocolError``,
  never a fabricated result.
* Authentication is an OAuth **access token** sent as ``Authorization: Bearer
  <token>``. For headless use Caido documents **Personal Access Tokens**
  (``caido_…``) that auto-approve the device flow; we accept either the
  resulting token or a PAT via an env var (never inline).
* **Findings and requests are project-scoped**: a project must be open on the
  instance, otherwise the calls fail (surfaced as a GraphQL error).
* There is **no documented active-scan / job API**. Caido is a manual
  intercepting proxy; findings are produced by plugins and scripts, not by a
  remote "start a scan against this URL" endpoint. :meth:`CaidoAdapter.start_job`
  therefore **refuses** to invent one (:class:`AdapterError`), and the adapter
  is strictly **read-only**. Forwarding traffic (Replay/Automate) is an active
  operation we deliberately do **not** drive.
* Because nothing is started, there is nothing to cancel or to leave running;
  :meth:`CaidoAdapter.cancel_job` still returns ``False`` (no cancel endpoint).
* The **Cloud API** (``api.caido.io`` ``/api/v1/…``) is account/team/workspace
  management, not security scanning, and is out of scope.
* Community **MCP servers** and BApps/extensions are **not** required and are
  not assumed to exist; the adapter talks to the documented GraphQL endpoint
  only.

Returned tool output (findings, descriptions, raw request metadata) is ALWAYS
untrusted input: it is never executed, is length-capped and redacted before it
becomes a finding or evidence. Policy (scope, SSRF, authorization, budgets,
kill switch) is enforced by :class:`lib.adapters.base.GuardedAdapter`; the
connection endpoint is an operator-configured local service, while finding
endpoints are scope-checked at ingest time.

The transport is injectable, so the entire adapter is exercised offline with
mocked responses (no live Caido required).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable

from lib.adapters.base import (
    KIND_PASSIVE,
    STATUS_COMPLETED,
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
    sanitize_untrusted,
)
from lib.adapters.registry import api_key_for, register
from lib.logger import get_logger
from lib.ssrf_guard import is_safe_url

logger = get_logger("adapters.caido")

DEFAULT_BASE_URL = "http://127.0.0.1:8080"
GRAPHQL_PATH = "/graphql"
DEFAULT_TIMEOUT: tuple[int, int] = (3, 30)
DEFAULT_PAGE_SIZE = 50

#: Advertised capabilities (declared; no network I/O). Caido integration is
#: READ-ONLY: there is no documented remote scan/job API to expose.
_CAPABILITIES = (
    AdapterCapability("health", active=False,
                      description="Connection/authentication check against the instance GraphQL API"),
    AdapterCapability("capability-discovery", active=False,
                      description="Live schema introspection (GraphQL __schema query fields)"),
    AdapterCapability("finding-retrieval", active=False,
                      description="Retrieve project findings as normalized, scoped findings"),
    AdapterCapability("request-retrieval", active=False,
                      description="Read proxied HTTP history metadata (never sends traffic)"),
)

#: GraphQL operations (field names from the published Caido schema).
_VIEWER_QUERY = "query NexusViewer { viewer { __typename id } }"
_INTROSPECT_QUERY = "query NexusIntrospect { __schema { queryType { fields { name } } } }"


def _safe_text(value: Any, limit: int = 2000) -> str:
    return sanitize_untrusted(value, limit)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _findings_query(first: int, after: str | None, reporter: str) -> str:
    args = [f"first: {int(first)}"]
    if after:
        args.append(f'after: {json.dumps(after)}')
    if reporter:
        args.append(f"filter: {{ reporter: {json.dumps(reporter)} }}")
    return (
        "query NexusFindings { findings(" + ", ".join(args) + ") { "
        "edges { cursor node { id title description reporter dedupeKey host path hidden createdAt "
        "request { id } } } "
        "pageInfo { hasNextPage endCursor } } }"
    )


def _requests_query(first: int, after: str | None, httpql: str) -> str:
    args = [f"first: {int(first)}", "order: { by: CREATED_AT, ordering: DESC }"]
    if after:
        args.append(f'after: {json.dumps(after)}')
    if httpql:
        args.append(f"filter: {{ code: {json.dumps(httpql)} }}")
    return (
        "query NexusRequests { requests(" + ", ".join(args) + ") { "
        "edges { cursor node { id method host path query createdAt "
        "response { statusCode length } } } "
        "pageInfo { hasNextPage endCursor } } }"
    )


class CaidoAdapter(SecurityToolAdapter):
    """Read-only adapter for a running Caido instance (GraphQL API)."""

    name = "caido"

    def __init__(
        self,
        base_url: str = "",
        token: str = "",
        timeout: tuple[int, int] | None = None,
        transport: Callable[[str, str, dict, str], tuple[int, str]] | None = None,
        ssrf_allow: set[str] | None = None,
    ):
        self.base_url = (base_url or DEFAULT_BASE_URL).strip().rstrip("/")
        self.token = token or ""
        self.timeout = tuple(timeout) if timeout else DEFAULT_TIMEOUT
        self._transport = transport
        self.ssrf_allow = set(ssrf_allow or set())

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"CaidoAdapter(base_url={self.base_url!r})"

    # -- config -------------------------------------------------------------

    def validate_config(self) -> list[str]:
        issues: list[str] = []
        if not self.base_url:
            issues.append("caido: base_url is not configured")
        elif not self.base_url.startswith(("http://", "https://")):
            issues.append("caido: base_url must be an http(s) URL")
        return issues

    # -- transport ----------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _default_transport(self, method: str, url: str, headers: dict, body: str) -> tuple[int, str]:
        import requests

        try:
            resp = requests.request(method, url, data=body or None, headers=dict(headers),
                                    timeout=self.timeout)
        except requests.Timeout as exc:
            raise AdapterTimeout("caido request timed out") from exc
        except requests.RequestException as exc:
            raise AdapterUnavailable(f"caido unreachable: {exc.__class__.__name__}") from exc
        return int(resp.status_code), resp.text

    def _http(self, method: str, url: str, headers: dict, body: str = "") -> tuple[int, str]:
        transport = self._transport or self._default_transport
        try:
            status, text = transport(method, url, headers, body)
        except AdapterError:
            raise
        except TimeoutError as exc:
            raise AdapterTimeout(str(exc) or "caido request timed out") from exc
        except Exception as exc:  # connection refused, DNS, injected failures
            raise AdapterUnavailable(f"caido unreachable: {exc.__class__.__name__}") from exc
        return int(status), text or ""

    def _endpoint(self) -> str:
        return f"{self.base_url}{GRAPHQL_PATH}"

    def _graphql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        """POST one GraphQL operation, returning its ``data`` object.

        Normalizes transport/auth/protocol failures. GraphQL-level ``errors``
        (HTTP 200) are surfaced as :class:`AdapterProtocolError` with a redacted
        message so a schema/permission change never looks like real data.
        """
        safe, reason = is_safe_url(self.base_url, allow=self.ssrf_allow, local_ok=True)
        if not safe:
            raise AdapterError(f"caido endpoint blocked by SSRF guard: {reason}")
        body = json.dumps({"query": query, "variables": variables or {}})
        status, text = self._http("POST", self._endpoint(), self._headers(), body)
        if status in (401, 403):
            raise AdapterAuthError(f"caido authentication failed (HTTP {status})")
        if status >= 400:
            raise AdapterProtocolError(f"caido returned HTTP {status}")
        try:
            payload = json.loads(text) if text.strip() else {}
        except ValueError as exc:
            raise AdapterProtocolError("caido returned malformed JSON") from exc
        if not isinstance(payload, dict):
            raise AdapterProtocolError("caido returned an unexpected payload")
        errors = payload.get("errors")
        if errors:
            raise AdapterProtocolError(f"caido GraphQL error: {_graphql_error(errors)}")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise AdapterProtocolError("caido returned no data")
        return data

    # -- discovery ----------------------------------------------------------

    def capabilities(self) -> list[AdapterCapability]:
        return list(_CAPABILITIES)

    def introspect(self) -> list[str]:
        """Live capability discovery via standard GraphQL introspection."""
        data = self._graphql(_INTROSPECT_QUERY)
        schema = data.get("__schema")
        if not isinstance(schema, dict):
            raise AdapterProtocolError("caido introspection returned no schema")
        query_type = schema.get("queryType")
        fields = query_type.get("fields") if isinstance(query_type, dict) else None
        if not isinstance(fields, list):
            raise AdapterProtocolError("caido introspection returned no query fields")
        return sorted(str(f.get("name")) for f in fields if isinstance(f, dict) and f.get("name"))

    def finding_reporters(self) -> list[str]:
        """Distinct reporters present in the current project."""
        data = self._graphql("query NexusFindingReporters { findingReporters }")
        reporters = data.get("findingReporters")
        if not isinstance(reporters, list):
            raise AdapterProtocolError("caido returned no finding reporters")
        return [str(r) for r in reporters]

    def health(self) -> AdapterHealth:
        health = AdapterHealth(name=self.name)
        if not self.base_url:
            health.error = "no base_url configured"
            return health
        health.details["api"] = "Caido instance GraphQL API"
        health.details["auth"] = "bearer" if self.token else "anonymous"
        try:
            data = self._graphql(_VIEWER_QUERY)
        except AdapterError as exc:
            health.error = str(exc)
            logger.debug("caido health check failed: %s", health.error)
            return health
        viewer = data.get("viewer")
        if not isinstance(viewer, dict):
            health.error = "caido returned no viewer"
            return health
        health.reachable = True
        # The schema exposes a viewer identity/type, not an instance version here.
        health.details["viewer"] = _safe_text(viewer.get("__typename") or "", 64)
        return health

    # -- read-only retrieval ------------------------------------------------

    def findings(
        self,
        first: int = DEFAULT_PAGE_SIZE,
        after: str | None = None,
        reporter: str = "",
    ) -> list[RawFinding]:
        """Retrieve the current project's findings as normalized findings."""
        data = self._graphql(_findings_query(first, after, reporter))
        connection = data.get("findings")
        if not isinstance(connection, dict):
            raise AdapterProtocolError("caido returned no findings collection")
        edges = connection.get("edges")
        if not isinstance(edges, list):
            raise AdapterProtocolError("caido findings payload is not a list")
        findings: list[RawFinding] = []
        for edge in edges:
            node = edge.get("node") if isinstance(edge, dict) else None
            if isinstance(node, dict):
                findings.append(self.normalize_finding(node))
        return findings

    def requests(
        self,
        first: int = DEFAULT_PAGE_SIZE,
        after: str | None = None,
        httpql: str = "",
    ) -> list[dict[str, Any]]:
        """Read proxied HTTP-history metadata (never sends traffic)."""
        data = self._graphql(_requests_query(first, after, httpql))
        connection = data.get("requests")
        if not isinstance(connection, dict):
            raise AdapterProtocolError("caido returned no requests collection")
        edges = connection.get("edges")
        if not isinstance(edges, list):
            raise AdapterProtocolError("caido requests payload is not a list")
        rows: list[dict[str, Any]] = []
        for edge in edges:
            node = edge.get("node") if isinstance(edge, dict) else None
            if isinstance(node, dict):
                rows.append(self.normalize_request(node))
        return rows

    def normalize_request(self, node: dict[str, Any]) -> dict[str, Any]:
        """Translate one Caido request edge into safe, untrusted metadata."""
        response = node.get("response") if isinstance(node.get("response"), dict) else {}
        return {
            "id": str(node.get("id") or ""),
            "method": str(node.get("method") or "GET").upper(),
            "host": _safe_text(node.get("host"), 300),
            "path": _safe_text(node.get("path"), 1000),
            "query": _safe_text(node.get("query"), 1000),
            "created_at": _safe_text(node.get("createdAt"), 64),
            "status_code": response.get("statusCode"),
            "length": response.get("length"),
        }

    def normalize_finding(self, node: dict[str, Any]) -> RawFinding:
        """Translate one Caido finding into a normalized, sanitized finding.

        Caido findings carry no severity/confidence fields, so those default to
        the framework's safe values (P4 / 50); the reporter and request id are
        preserved as provenance.
        """
        reporter = str(node.get("reporter") or "")
        request = node.get("request") if isinstance(node.get("request"), dict) else {}
        request_id = str(request.get("id") or node.get("requestId") or "")
        extra = {
            "reporter": reporter,
            "dedupe_key": _safe_text(node.get("dedupeKey"), 300),
            "request_id": request_id,
            "hidden": bool(node.get("hidden")),
        }
        evidence = f"request_id={request_id} reporter={reporter}".strip()
        return RawFinding(
            adapter=self.name,
            source="caido",
            name=_safe_text(node.get("title") or "Caido finding", 300),
            severity="P4",
            confidence=50,
            endpoint=_finding_endpoint(node),
            method="GET",
            param="",
            description=_safe_text(node.get("description"), 3000),
            solution="",
            reference="",
            cwe_id="",
            evidence=evidence,
            other_info=_safe_text(node.get("dedupeKey"), 1000),
            plugin_id=reporter,
            alert_id=str(node.get("id") or ""),
            extra=extra,
        )

    # -- job control (unsupported: Caido has no remote scan API) ------------

    def start_job(self, job: JobSpec) -> JobHandle:
        raise AdapterError(
            "unsupported operation: Caido exposes no documented remote scan/job "
            "API; this adapter is read-only (use findings/requests retrieval)"
        )

    def job_status(self, handle: JobHandle) -> JobHandle:
        """Read handles are already complete; nothing is polled."""
        handle.status = STATUS_COMPLETED
        handle.progress = 100
        handle.updated_at = _now()
        return handle

    def cancel_job(self, handle: JobHandle) -> bool:
        """Not supported: no job is ever started, so there is nothing to cancel."""
        logger.info("caido: no documented cancel endpoint; nothing to cancel")
        return False

    def collect(self, handle: JobHandle) -> list[RawFinding]:
        """Read findings for a read handle (optionally filtered by reporter)."""
        reporter = str(handle.raw.get("reporter") or "")
        return self.findings(first=int(handle.raw.get("limit") or DEFAULT_PAGE_SIZE), reporter=reporter)


def _finding_endpoint(node: dict[str, Any]) -> str:
    """Build a scope-checkable endpoint URL from a finding's host + path."""
    host = str(node.get("host") or "").strip()
    path = str(node.get("path") or "").strip()
    if not host:
        return _safe_text(path, 2000)
    base = host if "://" in host else f"https://{host}"
    if path and not path.startswith("/"):
        path = "/" + path
    return _safe_text(base + path, 2000)


def _graphql_error(errors: Any) -> str:
    """First redacted GraphQL error message (never leaks raw server text)."""
    if isinstance(errors, list) and errors:
        first = errors[0]
        if isinstance(first, dict):
            return _safe_text(first.get("message") or "unknown error", 300)
    return "unknown error"


@register("caido")
def build_caido(spec: dict[str, Any]) -> CaidoAdapter:
    """Factory registered as ``caido`` (reads ``integrations.caido`` config)."""
    timeout_seconds = int(spec.get("timeout_seconds") or 0)
    timeout = (3, timeout_seconds) if timeout_seconds else None
    ssrf_allow = {str(h).strip().lower() for h in (spec.get("ssrf_allow") or []) if str(h).strip()}
    return CaidoAdapter(
        base_url=str(spec.get("base_url") or DEFAULT_BASE_URL),
        token=api_key_for(spec),
        timeout=timeout,
        transport=None,
        ssrf_allow=ssrf_allow,
    )


# ---------------------------------------------------------------------------
# Read handle (no scan is started) + offline mock
# ---------------------------------------------------------------------------


def read_handle(reporter: str = "", target: str = "", limit: int = DEFAULT_PAGE_SIZE) -> JobHandle:
    """JobHandle for a read-only findings retrieval (nothing is started)."""
    return JobHandle(
        job_id="caido-findings",
        adapter="caido",
        target=target,
        kind=KIND_PASSIVE,
        status=STATUS_COMPLETED,
        progress=100,
        raw={"reporter": reporter, "limit": int(limit)},
    )


class FakeCaidoBackend:
    """Deterministic in-memory stand-in for a Caido GraphQL endpoint.

    Configured with canned findings/requests and an optional failure mode so the
    adapter's parsing/error paths are exercised without a live Caido.
    """

    def __init__(
        self,
        findings: list[dict[str, Any]] | None = None,
        requests: list[dict[str, Any]] | None = None,
        reporters: list[str] | None = None,
        query_fields: list[str] | None = None,
        viewer_type: str = "CloudUser",
        fail: str = "",
    ):
        self.findings = findings if findings is not None else [default_finding()]
        self.requests = requests if requests is not None else [default_request()]
        self.reporters = reporters if reporters is not None else ["nexus-plugin"]
        self.query_fields = query_fields if query_fields is not None else [
            "findings", "requests", "request", "viewer", "runtime", "scopes"]
        self.viewer_type = viewer_type
        self.fail = fail  # "" | "auth" | "unreachable" | "malformed" | "server" | "gql" | "no_data"
        self.calls: list[tuple[str, str, dict, str]] = []

    def __call__(self, method: str, url: str, headers: dict, body: str) -> tuple[int, str]:
        self.calls.append((method, url, dict(headers), body))
        if self.fail == "unreachable":
            raise ConnectionError("connection refused")
        if self.fail == "auth":
            return 401, json.dumps({"errors": [{"message": "unauthorized"}]})
        if self.fail == "server":
            return 500, "boom"
        if self.fail == "malformed":
            return 200, "<html>not json</html>"
        if self.fail == "gql":
            return 200, json.dumps({"errors": [{"message": "no project is currently open"}]})
        if self.fail == "no_data":
            return 200, json.dumps({"data": None})

        query = ""
        try:
            query = str(json.loads(body).get("query") or "")
        except (ValueError, TypeError):
            pass
        if "viewer" in query:
            return 200, json.dumps({"data": {"viewer": {"__typename": self.viewer_type, "id": "1"}}})
        if "__schema" in query:
            fields = [{"name": n} for n in self.query_fields]
            return 200, json.dumps(
                {"data": {"__schema": {"queryType": {"fields": fields}}}})
        if "findingReporters" in query:
            return 200, json.dumps({"data": {"findingReporters": list(self.reporters)}})
        if "findings(" in query:
            return 200, json.dumps({"data": {"findings": self._connection(self.findings)}})
        if "requests(" in query:
            return 200, json.dumps({"data": {"requests": self._connection(self.requests)}})
        return 200, json.dumps({"errors": [{"message": "unknown operation"}]})

    @staticmethod
    def _connection(items: list[dict[str, Any]]) -> dict[str, Any]:
        edges = [{"cursor": str(i), "node": item} for i, item in enumerate(items)]
        return {"edges": edges,
                "pageInfo": {"hasNextPage": False, "hasPreviousPage": False,
                             "startCursor": "0" if items else None,
                             "endCursor": str(len(items) - 1) if items else None}}


def default_finding() -> dict[str, Any]:
    """One representative Caido finding (used by the mock backend)."""
    return {
        "id": "1",
        "title": "SQL injection",
        "description": "The id parameter appears to alter the SQL query.",
        "reporter": "nexus-plugin",
        "dedupeKey": "sqli:/item:1",
        "host": "example.com",
        "path": "/item",
        "hidden": False,
        "createdAt": "1700000000",
        "request": {"id": "7"},
    }


def default_request() -> dict[str, Any]:
    """One representative proxied request edge (used by the mock backend)."""
    return {
        "id": "7",
        "method": "POST",
        "host": "example.com",
        "path": "/item",
        "query": "id=1",
        "createdAt": "1700000000",
        "response": {"statusCode": 500, "length": 1234},
    }


class MockCaidoAdapter(CaidoAdapter):
    """Offline Caido adapter backed by :class:`FakeCaidoBackend` (no network)."""

    def __init__(self, backend: FakeCaidoBackend | None = None, **kwargs: Any):
        backend = backend or FakeCaidoBackend()
        kwargs.setdefault("base_url", DEFAULT_BASE_URL)
        kwargs.setdefault("token", "caido_MOCKTOKEN")
        super().__init__(transport=backend, **kwargs)
        self._backend = backend
