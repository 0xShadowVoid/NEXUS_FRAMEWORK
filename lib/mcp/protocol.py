"""MCP wire protocol: JSON-RPC 2.0 constants, errors and value objects.

This is the *protocol-only* half of NEXUS's Model Context Protocol client
(Task 21). It knows the message shapes documented by the MCP specification
(initialize handshake, ``tools/list``, ``tools/call``) and nothing about
policy, connections or a specific server — those live in
:mod:`lib.mcp.client` and :mod:`lib.mcp.gateway`.

Reference: the Model Context Protocol specification
(https://modelcontextprotocol.io/specification). NEXUS targets the
handshake-based revisions (2025-06-18 / 2025-03-26 / 2024-11-05). The
2026-07-28 stateless revision (``server/discover``, no handshake, per-request
``_meta``) is NOT implemented — see ``docs/MCP.md`` for the limitation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from lib.exceptions import NexusError

# -- protocol ------------------------------------------------------------------

#: Versions this client can speak (most recent first). The server's chosen
#: version is echoed back by ``initialize`` and recorded on the client.
SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = (
    "2025-06-18", "2025-03-26", "2024-11-05",
)
DEFAULT_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]

CLIENT_NAME = "nexus-mcp-client"

# -- JSON-RPC methods ----------------------------------------------------------

M_INITIALIZE = "initialize"
M_INITIALIZED = "notifications/initialized"
M_TOOLS_LIST = "tools/list"
M_TOOLS_CALL = "tools/call"
M_PING = "ping"
M_CANCELLED = "notifications/cancelled"

# -- JSON-RPC error codes ------------------------------------------------------

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

#: Counter used for request ids (monotonic, never reused within a session).
_ID_COUNTER = {"n": 0}


def next_id() -> int:
    """Return the next JSON-RPC request id (process-local, monotonic)."""
    _ID_COUNTER["n"] += 1
    return _ID_COUNTER["n"]


# ---------------------------------------------------------------------------
# Errors (all normalized under NexusError so the CLI reports them uniformly)
# ---------------------------------------------------------------------------


class McpError(NexusError):
    """Base class for every MCP client failure."""


class McpTransportError(McpError):
    """The transport could not deliver/receive a message."""


class McpConnectionError(McpTransportError):
    """The server could not be reached or the process failed to start."""


class McpTimeoutError(McpTransportError):
    """A request exceeded its configured timeout."""


class McpProtocolError(McpError):
    """The server sent a malformed or unexpected message (or a JSON-RPC error)."""


class McpSchemaError(McpError):
    """A tool descriptor or its input schema is invalid (fail closed)."""


class McpToolError(McpError):
    """A tool call returned an application-level error (``isError`` true)."""


class McpPolicyError(McpError):
    """A NEXUS policy boundary blocked the operation (disabled/allowlist/scope/SSRF)."""


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class McpToolSpec:
    """One tool advertised by an MCP server (untrusted metadata).

    ``annotations`` carries the spec's optional hints (``readOnlyHint``,
    ``destructiveHint``, ``idempotentHint``, ``openWorldHint``). Absent or
    non-boolean hints are treated as *unknown* — and unknown tools are
    classified active (fail closed) by :meth:`is_active`.
    """

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] = field(default_factory=dict)

    def _flag(self, key: str) -> bool | None:
        value = self.annotations.get(key)
        return value if isinstance(value, bool) else None

    @property
    def read_only(self) -> bool | None:
        return self._flag("readOnlyHint")

    @property
    def destructive(self) -> bool | None:
        return self._flag("destructiveHint")

    @property
    def open_world(self) -> bool | None:
        return self._flag("openWorldHint")

    def is_active(self) -> bool:
        """True when invoking this tool may change state / touch a target.

        Read-only is only honored when the server *explicitly* claims it and
        does not also claim destructive behaviour; everything else (including
        missing annotations) is active — the safe default.
        """
        if self.destructive is True:
            return True
        if self.read_only is True and self.destructive is not True:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "annotations": dict(self.annotations),
            "read_only": self.read_only,
            "destructive": self.destructive,
            "active": self.is_active(),
        }


@dataclass
class McpCallResult:
    """Normalized, redacted, size-bounded result of a ``tools/call``."""

    tool: str
    ok: bool = True
    content_text: str = ""
    structured: Any = None
    is_error: bool = False
    truncated: bool = False
    error: str = ""
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "ok": self.ok,
            "is_error": self.is_error,
            "content_text": self.content_text,
            "structured": self.structured,
            "truncated": self.truncated,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


# ---------------------------------------------------------------------------
# Encoding / decoding
# ---------------------------------------------------------------------------


def encode_request(request_id: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 request object."""
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


def encode_notification(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a JSON-RPC 2.0 notification object (no id)."""
    message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        message["params"] = params
    return message


def decode_message(payload: Any) -> dict[str, Any]:
    """Validate the envelope of a server message, returning it unchanged.

    Raises :class:`McpProtocolError` for anything that is not a JSON-RPC 2.0
    object (the server does not get to redefine the envelope).
    """
    if not isinstance(payload, dict):
        raise McpProtocolError("MCP server sent a non-object message")
    if payload.get("jsonrpc") != "2.0":
        raise McpProtocolError("MCP server sent a message without jsonrpc 2.0")
    if "id" in payload:
        if not isinstance(payload.get("id"), (int, str)) or isinstance(payload.get("id"), bool):
            raise McpProtocolError("MCP server sent a message with an invalid id")
    elif payload.get("method") is None:
        raise McpProtocolError("MCP server sent a message with neither id nor method")
    return payload


def rpc_error(payload: dict[str, Any]) -> McpProtocolError:
    """Translate a JSON-RPC ``error`` object into a normalized exception."""
    err = payload.get("error")
    if not isinstance(err, dict):
        return McpProtocolError("MCP server returned an error in an unexpected shape")
    code = err.get("code")
    message = str(err.get("message") or "MCP error")
    return McpProtocolError(f"MCP error {code}: {message}")


# ---------------------------------------------------------------------------
# Minimal JSON-Schema validation (subset) — fail closed on malformed schemas
# ---------------------------------------------------------------------------

_JSON_TYPES = frozenset({"string", "integer", "number", "boolean", "array", "object", "null"})


def validate_tool_schema(schema: Any) -> list[str]:
    """Return schema problems (empty list = a usable object schema).

    Only the subset NEXUS needs is understood (type / properties / required /
    enum). Anything it cannot reason about conservatively — a non-object
    schema, a non-dict property, an unknown type — is reported so the tool is
    refused rather than trusted.
    """
    issues: list[str] = []
    if schema is None:
        return ["inputSchema is missing"]
    if not isinstance(schema, dict):
        return ["inputSchema must be a JSON object"]

    root_type = schema.get("type")
    if root_type is not None and root_type != "object":
        issues.append("inputSchema root type must be 'object'")

    props = schema.get("properties", {})
    if not isinstance(props, dict):
        issues.append("inputSchema 'properties' must be an object")
        props = {}

    required = schema.get("required", [])
    if not isinstance(required, list) or any(not isinstance(item, str) for item in required):
        issues.append("inputSchema 'required' must be a list of strings")
        required = []

    for key, sub in props.items():
        if not isinstance(sub, dict):
            issues.append(f"property {key!r} schema must be a JSON object")
            continue
        sub_type = sub.get("type")
        if isinstance(sub_type, list):
            for candidate in sub_type:
                if candidate not in _JSON_TYPES:
                    issues.append(f"property {key!r} has unsupported type {candidate!r}")
        elif sub_type is not None and sub_type not in _JSON_TYPES:
            issues.append(f"property {key!r} has unsupported type {sub_type!r}")

    for name in required:
        if name not in props:
            issues.append(f"required property {name!r} is not declared")

    return issues


def _value_matches(value: Any, type_name: str) -> bool:
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "array":
        return isinstance(value, list)
    if type_name == "object":
        return isinstance(value, dict)
    if type_name == "null":
        return value is None
    return False


def _check_value(key: str, value: Any, sub: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    declared = sub.get("type")
    if isinstance(declared, list):
        if declared and not any(_value_matches(value, t) for t in declared):
            issues.append(f"argument {key!r} must be one of {declared}")
    elif isinstance(declared, str) and not _value_matches(value, declared):
        issues.append(f"argument {key!r} must be {declared}")
    allowed = sub.get("enum")
    if isinstance(allowed, list) and value not in allowed:
        issues.append(f"argument {key!r} is not an allowed value")
    return issues


def validate_arguments(arguments: Any, schema: dict[str, Any]) -> list[str]:
    """Validate *arguments* against a tool's (already-validated) input schema."""
    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        return ["arguments must be a JSON object"]

    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    required = schema.get("required", []) if isinstance(schema, dict) else []

    issues: list[str] = []
    for name in required if isinstance(required, list) else []:
        if name not in arguments:
            issues.append(f"missing required argument: {name}")

    for key, value in arguments.items():
        sub = props.get(key) if isinstance(props, dict) else None
        if sub is None:
            if isinstance(schema, dict) and schema.get("additionalProperties", True) is False:
                issues.append(f"unexpected argument: {key}")
            continue
        if isinstance(sub, dict):
            issues.extend(_check_value(key, value, sub))
    return issues


def extract_content_text(content: Any, limit: int = 200_000) -> tuple[str, bool]:
    """Flatten MCP content blocks into bounded text; returns (text, truncated)."""
    if content is None:
        return "", False
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                if block.get("type") == "text":
                    parts.append(str(block.get("text") or ""))
                else:
                    kind = str(block.get("type") or "unknown")
                    parts.append(f"[{kind} content]")
        text = "\n".join(parts)
    elif isinstance(content, dict):
        text = str(content.get("text") or "")
    else:
        text = str(content)
    if len(text) > limit:
        return text[:limit], True
    return text, False
