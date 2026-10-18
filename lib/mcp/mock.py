"""Deterministic offline MCP server + client for tests and ``nexus mcp --mock``.

:class:`FakeMcpServer` is a canned JSON-RPC responder; :class:`McpClient` (or
:class:`MockMcpClient`) drives it through :class:`FakeTransport`. No sockets,
subprocesses or network are involved, so the test suite stays offline.
"""
from __future__ import annotations

from typing import Any, Callable

from lib.mcp.client import McpClient
from lib.mcp.protocol import (
    M_INITIALIZE,
    M_INITIALIZED,
    M_PING,
    M_TOOLS_CALL,
    M_TOOLS_LIST,
    McpConnectionError,
    McpTimeoutError,
)
from lib.mcp.transport import FakeTransport


def default_tool(name: str = "echo") -> dict[str, Any]:
    """A representative read-only tool descriptor."""
    return {
        "name": name,
        "description": "Echo a message back to the caller.",
        "inputSchema": {
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "required": ["message"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
    }


def default_active_tool(name: str = "scan") -> dict[str, Any]:
    """A representative state-changing (active) tool descriptor."""
    return {
        "name": name,
        "description": "Run a scan against a target URL.",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
    }


class FakeMcpServer:
    """Canned MCP server callable: ``message -> response | None``."""

    def __init__(
        self,
        tools: list[dict[str, Any]] | None = None,
        results: dict[str, Any] | None = None,
        *,
        fail: str = "",
        protocol_version: str = "2025-06-18",
        server_name: str = "fake-mcp",
        call_hook: Callable[[dict[str, Any]], Any] | None = None,
    ):
        self.tools = tools if tools is not None else [default_tool()]
        self.results = dict(results or {})
        # "" | "connect" | "auth" | "malformed" | "error" | "oversized" | "tool_error" | "timeout"
        self.fail = fail
        self.protocol_version = protocol_version
        self.server_name = server_name
        self.call_hook = call_hook
        self.initialized = False
        self.calls: list[tuple[str, Any]] = []

    def _ok(self, msg_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def _err(self, msg_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}

    def __call__(self, message: dict[str, Any]) -> dict[str, Any] | None:
        if self.fail == "connect":
            raise McpConnectionError("fake server unavailable")

        method = message.get("method")
        params = message.get("params") or {}
        msg_id = message.get("id")
        self.calls.append((str(method), params))

        if method == M_INITIALIZE:
            if self.fail == "auth":
                return self._err(msg_id, -32000, "unauthorized")
            if self.fail == "malformed":
                return self._ok(msg_id, "not-an-object")
            return self._ok(msg_id, {
                "protocolVersion": self.protocol_version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": self.server_name, "version": "1.0"},
            })

        if method == M_INITIALIZED:
            self.initialized = True
            return None

        if method == M_TOOLS_LIST:
            return self._ok(msg_id, {"tools": [dict(tool) for tool in self.tools]})

        if method == M_TOOLS_CALL:
            if self.fail == "timeout":
                raise McpTimeoutError("simulated timeout")
            if self.fail == "error":
                return self._err(msg_id, -32603, "internal failure")
            name = str(params.get("name") or "")
            if self.call_hook is not None:
                hooked = self.call_hook(params)
                if hooked is not None:
                    return self._ok(msg_id, hooked)
            payload = self.results.get(name)
            if callable(payload):
                payload = payload(params)
            if payload is None:
                payload = {"content": [{"type": "text", "text": f"ok:{name}"}]}
            if self.fail == "oversized":
                payload = {"content": [{"type": "text", "text": "x" * 300_000}]}
            if self.fail == "tool_error":
                payload = {"content": [{"type": "text", "text": "tool failed"}], "isError": True}
            return self._ok(msg_id, payload)

        if method == M_PING:
            return self._ok(msg_id, {})

        return self._err(msg_id, -32601, f"Method not found: {method}")


class MockMcpClient(McpClient):
    """Offline MCP client backed by a :class:`FakeMcpServer` (no transport I/O)."""

    def __init__(self, server: FakeMcpServer | None = None, **kwargs: Any):
        self.server = server or FakeMcpServer()
        self.transport = FakeTransport(self.server)
        super().__init__(self.transport, **kwargs)
