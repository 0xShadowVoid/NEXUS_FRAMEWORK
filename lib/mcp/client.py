"""MCP client — protocol lifecycle over an injectable transport.

:class:`McpClient` speaks the handshake-based MCP revisions: it connects
(``initialize`` → ``notifications/initialized``), discovers tools
(``tools/list``, paged), and invokes them (``tools/call``). It applies only
*protocol* hygiene — envelope validation, schema validation, result
normalization, redaction and size bounds. Authorization, scope, SSRF and
approval decisions belong to :mod:`lib.mcp.gateway`; the client never treats a
server as trusted.

The transport is injected, so the whole client is exercised offline with
:class:`lib.mcp.transport.FakeTransport` and :class:`lib.mcp.mock.FakeMcpServer`.
"""
from __future__ import annotations

import json
from typing import Any

from core.sanitizer import sanitize_evidence
from lib.logger import get_logger
from lib.mcp.protocol import (
    CLIENT_NAME,
    DEFAULT_PROTOCOL_VERSION,
    M_INITIALIZE,
    M_INITIALIZED,
    M_PING,
    M_TOOLS_CALL,
    M_TOOLS_LIST,
    SUPPORTED_PROTOCOL_VERSIONS,
    McpCallResult,
    McpProtocolError,
    McpToolSpec,
    encode_notification,
    encode_request,
    extract_content_text,
    next_id,
    rpc_error,
    validate_tool_schema,
)
from lib.mcp.transport import McpTransport
from lib.redaction import redact, redact_text

logger = get_logger("mcp.client")

DEFAULT_RESULT_BYTES = 262_144
_MAX_PAGES = 50

# Cap on retained result text after normalization (additional to the byte
# bound); keeps a hostile server from filling logs/reports.
_MAX_TEXT_CHARS = 100_000


def scrub(value: Any, limit: int = 2000) -> str:
    """Redact + bound untrusted server text (credentials never survive)."""
    text = value if isinstance(value, str) else str(value if value is not None else "")
    return sanitize_evidence(redact_text(text), max_length=limit)


def scrub_structured(value: Any) -> Any:
    """Recursively redact secret-looking keys/values in a structured result."""
    return redact(value)


def _unwrap(response: dict[str, Any], what: str) -> Any:
    """Return ``response['result']`` or raise on a JSON-RPC error envelope."""
    if "error" in response:
        raise rpc_error(response)
    result = response.get("result")
    if not isinstance(result, dict):
        raise McpProtocolError(f"{what} returned no result object")
    return result


class McpClient:
    """A single MCP server connection (transport in, normalized data out)."""

    def __init__(
        self,
        transport: McpTransport,
        name: str = "mcp",
        *,
        timeout: float = 30.0,
        max_result_bytes: int = DEFAULT_RESULT_BYTES,
        protocol_version: str = DEFAULT_PROTOCOL_VERSION,
        client_version: str = "",
    ):
        self.transport = transport
        self.name = name
        self.timeout = float(timeout)
        self.max_result_bytes = int(max_result_bytes)
        self.protocol_version = protocol_version
        self.client_version = client_version or ""
        self.server_info: dict[str, Any] = {}
        self.server_capabilities: dict[str, Any] = {}
        self.negotiated_version = ""
        self.tools: dict[str, McpToolSpec] = {}
        self.schema_errors: dict[str, list[str]] = {}
        self.connected = False

    # -- lifecycle ----------------------------------------------------------

    def connect(self) -> dict[str, Any]:
        """Start the transport and complete the initialize handshake."""
        self.transport.start()
        params = {
            "protocolVersion": self.protocol_version,
            "capabilities": {"tools": {}},
            "clientInfo": {"name": CLIENT_NAME, "version": self.client_version},
        }
        response = self.transport.request(
            encode_request(next_id(), M_INITIALIZE, params), timeout=self.timeout
        )
        result = _unwrap(response, "initialize")

        self.negotiated_version = str(result.get("protocolVersion") or "")
        if self.negotiated_version and self.negotiated_version not in SUPPORTED_PROTOCOL_VERSIONS:
            raise McpProtocolError(
                f"server negotiated an unsupported protocol revision: {self.negotiated_version!r}"
            )
        info = result.get("serverInfo")
        self.server_info = info if isinstance(info, dict) else {}
        caps = result.get("capabilities")
        self.server_capabilities = caps if isinstance(caps, dict) else {}

        self.transport.notify(encode_notification(M_INITIALIZED))
        self.connected = True
        return {
            "protocol_version": self.negotiated_version,
            "server_info": dict(self.server_info),
            "capabilities": dict(self.server_capabilities),
        }

    # -- discovery ----------------------------------------------------------

    def _tool_from_raw(self, raw: Any) -> tuple[McpToolSpec | None, list[str]]:
        if not isinstance(raw, dict):
            return None, ["tool entry is not an object"]
        name = raw.get("name")
        if not isinstance(name, str) or not name.strip():
            return None, ["tool has no usable name"]
        schema = raw.get("inputSchema")
        issues = validate_tool_schema(schema)
        output_schema = raw.get("outputSchema")
        annotations = raw.get("annotations")
        spec = McpToolSpec(
            name=name.strip(),
            description=scrub(raw.get("description"), 1000),
            input_schema=schema if isinstance(schema, dict) else {},
            output_schema=output_schema if isinstance(output_schema, dict) else None,
            annotations=annotations if isinstance(annotations, dict) else {},
        )
        return spec, issues

    def list_tools(self) -> list[McpToolSpec]:
        """Discover every tool, paging until exhausted; drop malformed ones.

        A tool whose ``inputSchema`` is invalid is recorded in
        :attr:`schema_errors` and never returned — it can never be invoked.
        """
        tools: dict[str, McpToolSpec] = {}
        errors: dict[str, list[str]] = {}
        cursor: str | None = None
        for _ in range(_MAX_PAGES):
            params = {"cursor": cursor} if cursor else {}
            response = self.transport.request(
                encode_request(next_id(), M_TOOLS_LIST, params), timeout=self.timeout
            )
            result = _unwrap(response, "tools/list")
            items = result.get("tools")
            if not isinstance(items, list):
                raise McpProtocolError("tools/list 'tools' is not a list")
            for raw in items:
                spec, issues = self._tool_from_raw(raw)
                if spec is None:
                    continue
                if issues:
                    errors[spec.name] = issues
                    logger.debug("mcp tool %r refuses malformed schema: %s", spec.name, "; ".join(issues))
                    continue
                tools[spec.name] = spec
            next_cursor = result.get("nextCursor")
            cursor = next_cursor if isinstance(next_cursor, str) and next_cursor else None
            if not cursor:
                break
        self.tools = tools
        self.schema_errors = errors
        return list(tools.values())

    # -- invocation ---------------------------------------------------------

    def call_tool(
        self, name: str, arguments: dict[str, Any] | None = None, timeout: float | None = None
    ) -> McpCallResult:
        """Invoke *name* and return a normalized, redacted, bounded result."""
        import time as _time

        params = {"name": name, "arguments": dict(arguments or {})}
        start = _time.monotonic()
        response = self.transport.request(
            encode_request(next_id(), M_TOOLS_CALL, params),
            timeout=timeout if timeout and timeout > 0 else self.timeout,
        )
        result = _unwrap(response, "tools/call")

        raw_size = len(json.dumps(result, default=str).encode("utf-8"))
        if raw_size > self.max_result_bytes:
            raise McpProtocolError(
                f"tool result exceeds size limit ({raw_size} > {self.max_result_bytes} bytes)"
            )

        text, truncated = extract_content_text(result.get("content"), limit=_MAX_TEXT_CHARS)
        is_error = bool(result.get("isError"))
        structured = result.get("structuredContent")
        if structured is not None:
            structured = scrub_structured(structured)

        return McpCallResult(
            tool=name,
            ok=not is_error,
            is_error=is_error,
            content_text=scrub(text, _MAX_TEXT_CHARS),
            structured=structured,
            truncated=truncated,
            error=scrub(text, 500) if is_error else "",
            duration_ms=int((_time.monotonic() - start) * 1000),
        )

    def ping(self) -> bool:
        response = self.transport.request(
            encode_request(next_id(), M_PING, {}), timeout=self.timeout
        )
        return "result" in response

    # -- teardown -----------------------------------------------------------

    def close(self) -> None:
        try:
            self.transport.close()
        finally:
            self.connected = False
