"""Pass 29 — MCP integration hardening (Task 22).

Offline and deterministic: every test drives the client through an injected
:class:`FakeTransport` / :class:`FakeMcpServer`. No MCP server, socket,
subprocess or network is required, and no test touches the real project
configuration.
"""
from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest

from lib.config import TargetConfig
from lib.mcp.client import _MAX_PAGES, McpClient
from lib.mcp.gateway import GuardedMcpServer, McpServerPolicy, load_server_policies
from lib.mcp.mock import FakeMcpServer, MockMcpClient, default_active_tool, default_tool
from lib.mcp.protocol import (
    McpConnectionError,
    McpProtocolError,
    decode_message,
    validate_arguments,
    validate_tool_schema,
)
from lib.mcp.transport import FakeTransport
from lib.nemesis.mcp import McpGateway, McpTool

REDACTED = "***REDACTED***"
SECRET = "SUPERSECRETVALUE123456"


# --- helpers ------------------------------------------------------------------


def _policy(tools=("echo",), **kw) -> McpServerPolicy:
    base: dict = {"name": "t", "enabled": True, "transport": "mock", "tools": list(tools)}
    base.update(kw)
    return McpServerPolicy(**base)


def _guarded(fake=None, tools=("echo",), *, policy=None, target_config=None,
             allow_active=False, client=None, db=None) -> GuardedMcpServer:
    fake = fake or FakeMcpServer()
    client = client or MockMcpClient(fake, name="t")
    pol = policy or McpServerPolicy(
        name="t", enabled=True, transport="mock", tools=list(tools),
        allow_active=allow_active, scope_tools={"scan": "target"},
    )
    return GuardedMcpServer(pol, client=client, target_config=target_config, db=db)


def _tool(name, schema, *, annotations=None):
    default = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}
    return {"name": name, "description": "", "inputSchema": schema,
            "annotations": default if annotations is None else annotations}


def _both_tools() -> FakeMcpServer:
    return FakeMcpServer(tools=[default_tool("echo"), default_active_tool("scan")])


class _AuditDb:
    def __init__(self):
        self.events: list[dict] = []

    def insert_audit_event(self, **kw):
        self.events.append(kw)


# --- 1/2. authorization: disabled by default, allow/deny matrix ---------------


def test_disabled_server_denies_every_tool():
    server = _guarded(policy=_policy(enabled=False))
    server.connect()
    for tool in ("echo", "scan", "evil"):
        assert server.call(tool, {})["status"] == "denied"


def test_allow_deny_matrix_across_servers():
    fake = FakeMcpServer(tools=[default_tool("echo"), default_tool("extra"), default_tool("evil")])
    allowed = _guarded(fake, tools=("echo", "extra"))
    allowed.connect()
    assert allowed.call("echo", {"message": "x"})["status"] == "ok"
    assert allowed.call("extra", {"message": "x"})["status"] == "ok"
    assert allowed.call("evil", {"message": "x"})["status"] == "denied"

    none_allowed = _guarded(fake, tools=())
    none_allowed.connect()
    assert none_allowed.call("echo", {"message": "x"})["status"] == "denied"


# --- 3. authorization enforced on every invocation ---------------------------


def test_authorization_is_enforced_on_every_invocation():
    server = _guarded(FakeMcpServer(fail="error"), tools=("echo",))
    server.connect()
    for _ in range(3):
        result = server.call("echo", {"message": "x"})
        assert result["status"] == "error"  # the handler re-ran every time (no caching)
    # The transport saw one tools/call per invocation.
    calls = [m for m, _ in server.client.transport._server.calls if m == "tools/call"]
    assert len(calls) == 3


def test_active_approval_is_not_sticky():
    target = TargetConfig(domain="93.184.216.34", in_scope=["93.184.216.34"])
    server = _guarded(_both_tools(), tools=("echo", "scan"), allow_active=True,
                      target_config=target)
    server.connect()
    assert server.call("scan", {"target": "https://93.184.216.34/"},
                       authorize_active=True)["status"] == "ok"
    # The very next call without explicit approval is denied again.
    assert server.call("scan", {"target": "https://93.184.216.34/"},
                       authorize_active=False)["status"] == "denied"


def test_calls_denied_after_close():
    server = _guarded(_both_tools(), tools=("echo", "scan"))
    server.connect()
    server.close()
    assert server.call("echo", {"message": "x"})["status"] == "denied"
    assert server.call("scan", {"target": "https://93.184.216.34/"})["status"] == "denied"


# --- 4. invalid / malicious schemas and arguments ----------------------------


def test_malicious_schema_types_rejected():
    assert validate_tool_schema({"type": "object", "properties": {"a": {"type": ["string", "bogus"]}}})
    assert validate_tool_schema({"type": "object", "properties": {"a": {"type": 42}}})
    assert validate_tool_schema({"type": "array"})
    assert validate_tool_schema({"type": "object", "properties": {}, "required": "x"})


def test_enum_argument_enforced():
    tool = _tool("mode", {
        "type": "object",
        "properties": {"mode": {"type": "string", "enum": ["safe", "fast"]}},
        "required": ["mode"], "additionalProperties": False,
    })
    server = _guarded(FakeMcpServer(tools=[tool]), tools=("mode",))
    server.connect()
    assert server.call("mode", {"mode": "safe"})["status"] == "ok"
    bad = server.call("mode", {"mode": "evil"})
    assert bad["status"] == "denied"
    assert "allowed value" in bad["reason"] or "schema" in bad["reason"]


def test_integer_type_enforced():
    tool = _tool("count", {
        "type": "object", "properties": {"n": {"type": "integer"}},
        "required": ["n"], "additionalProperties": False,
    })
    server = _guarded(FakeMcpServer(tools=[tool]), tools=("count",))
    server.connect()
    assert server.call("count", {"n": 2})["status"] == "ok"
    assert server.call("count", {"n": "two"})["status"] == "denied"


def test_boolean_is_not_an_integer():
    assert validate_arguments({"n": True}, {"type": "object", "properties": {"n": {"type": "integer"}}})


def test_oversized_arguments_denied_by_gateway():
    server = _guarded(policy=_policy(["echo"], max_result_bytes=4096))
    server.connect()
    result = server.call("echo", {"message": "x" * 10_000})
    assert result["status"] == "denied"
    assert "size" in result["reason"]


def test_oversized_arguments_raise_at_client():
    client = MockMcpClient(FakeMcpServer(), name="t", max_result_bytes=4096)
    client.connect()
    client.list_tools()
    with pytest.raises(McpProtocolError):
        client.call_tool("echo", {"message": "x" * 10_000})


# --- 5. scope and SSRF --------------------------------------------------------


def test_out_of_scope_denied_in_scope_allowed():
    target = TargetConfig(domain="93.184.216.34", in_scope=["93.184.216.34"])
    server = _guarded(_both_tools(), tools=("echo", "scan"), allow_active=True, target_config=target)
    server.connect()
    assert server.call("scan", {"target": "https://93.184.216.35/"},
                       authorize_active=True)["status"] == "denied"
    assert server.call("scan", {"target": "https://93.184.216.34/"},
                       authorize_active=True)["status"] == "ok"


def test_metadata_url_argument_denied():
    server = _guarded()
    server.connect()
    result = server.call("echo", {"message": "http://169.254.169.254/latest/meta-data/"})
    assert result["status"] == "denied"
    assert "ssrf" in result["reason"].lower()


def test_metadata_path_on_public_host_denied():
    server = _guarded()
    server.connect()
    result = server.call("echo", {"message": "http://93.184.216.34/latest/meta-data/"})
    assert result["status"] == "denied"
    assert "ssrf" in result["reason"].lower()


def test_nested_argument_ssrf_denied():
    tool = _tool("configure", {
        "type": "object", "properties": {"config": {"type": "object"}},
        "required": ["config"],
    })
    server = _guarded(FakeMcpServer(tools=[tool]), tools=("configure",))
    server.connect()
    result = server.call("configure", {"config": {"url": "http://169.254.169.254/x"}})
    assert result["status"] == "denied"
    assert "ssrf" in result["reason"].lower()


def test_nested_list_argument_ssrf_denied():
    tool = _tool("probe", {
        "type": "object", "properties": {"targets": {"type": "array"}},
        "required": ["targets"],
    })
    server = _guarded(FakeMcpServer(tools=[tool]), tools=("probe",))
    server.connect()
    result = server.call("probe", {"targets": ["http://169.254.169.254/x"]})
    assert result["status"] == "denied"
    assert "ssrf" in result["reason"].lower()


# --- 6. read-only vs active ---------------------------------------------------


def test_read_only_runs_active_requires_approval():
    server = _guarded(_both_tools(), tools=("echo", "scan"), allow_active=True)
    server.connect()
    assert server.call("echo", {"message": "x"})["status"] == "ok"
    assert server.call("scan", {"target": "https://93.184.216.34/"})["status"] == "denied"


def test_missing_annotations_default_to_active():
    tool = _tool("mystery", {
        "type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"],
    }, annotations={})
    # No annotations at all → cannot prove read-only → treated as active.
    server = _guarded(FakeMcpServer(tools=[tool]), tools=("mystery",), allow_active=True)
    server.connect()
    assert server.call("mystery", {"target": "https://93.184.216.34/"})["status"] == "denied"
    assert server.call("mystery", {"target": "https://93.184.216.34/"},
                       authorize_active=True)["status"] == "ok"


# --- 7. transport resilience + cleanup ---------------------------------------


def test_discovery_failure_releases_transport():
    client = MockMcpClient(FakeMcpServer(fail="list_error"), name="t")
    server = GuardedMcpServer(_policy(["echo"]), client=client)
    status = server.connect()
    assert status["connected"] is False
    assert client.transport.closed is True


def test_server_shutdown_mid_session_is_error():
    base = FakeMcpServer()

    def srv(msg):
        if msg.get("method") == "tools/call":
            raise McpConnectionError("server closed the pipe")
        return base(msg)

    client = McpClient(FakeTransport(srv), name="t")
    client.connect()
    client.list_tools()
    with pytest.raises(McpConnectionError):
        client.call_tool("echo", {"message": "x"})

    server = _guarded(_both_tools(), tools=("echo",))
    server.client = client
    server.connected = True
    server._register_tools(client.tools.values())
    result = server.call("echo", {"message": "x"})
    assert result["status"] == "error"
    assert "closed" in result["error"].lower()

def test_malformed_jsonrpc_envelope_rejected():
    with pytest.raises(McpProtocolError):
        decode_message("not-an-object")
    with pytest.raises(McpProtocolError):
        decode_message({"id": 1, "result": {}})
    with pytest.raises(McpProtocolError):
        decode_message({"jsonrpc": "2.0", "result": {}})  # neither id nor method


def test_error_envelope_on_call_raises():
    client = MockMcpClient(FakeMcpServer(fail="error"), name="t")
    client.connect()
    client.list_tools()
    with pytest.raises(McpProtocolError):
        client.call_tool("echo", {"message": "x"})


def test_close_is_idempotent():
    client = MockMcpClient(FakeMcpServer(), name="t")
    client.connect()
    client.close()
    client.close()
    assert client.connected is False
    assert client.transport.closed is True


# --- 8. resource limits -------------------------------------------------------


def test_tools_list_paging_is_bounded():
    client = MockMcpClient(FakeMcpServer(fail="cursor_loop"), name="t")
    client.connect()
    client.list_tools()
    list_calls = [m.get("method") for m in client.transport.sent if m.get("method") == "tools/list"]
    assert len(list_calls) == _MAX_PAGES


def test_oversized_result_is_error_not_crash():
    fake = FakeMcpServer(fail="oversized")
    server = _guarded(fake, policy=_policy(["echo"], max_result_bytes=4096))
    server.connect()
    result = server.call("echo", {"message": "x"})
    assert result["status"] == "error"
    assert "size" in result["error"].lower()


def test_invalid_result_structure_is_safe():
    client = MockMcpClient(FakeMcpServer(results={"echo": {"content": 5}}), name="t")
    client.connect()
    client.list_tools()
    result = client.call_tool("echo", {"message": "x"})
    assert result.ok is True
    assert result.content_text == "5"


# --- 9. secret redaction ------------------------------------------------------


def test_nemesis_gateway_audit_and_error_redact_secret():
    db = _AuditDb()
    gateway = McpGateway(db=db)

    def boom(args):
        raise RuntimeError(f"failed token={SECRET}")

    gateway.register(
        McpTool(name="t", handler=boom, enabled=True, allowed_actors=("operator",)),
        enabled=True,
    )
    result = gateway.call("t", {}, actor="operator")
    assert result["status"] == "error"
    assert SECRET not in json.dumps(result)
    assert db.events
    assert all(SECRET not in str(e.get("detail", "")) for e in db.events)


def test_denial_reason_is_redacted(monkeypatch):
    monkeypatch.setattr(
        "lib.mcp.gateway.is_safe_url",
        lambda *a, **k: (False, f"blocked token={SECRET}"),
    )
    server = _guarded()
    server.connect()
    result = server.call("echo", {"message": "https://example.test/x"})
    assert result["status"] == "denied"
    assert SECRET not in json.dumps(result)
    assert REDACTED in result["reason"]


def test_tool_error_result_is_redacted():
    fake = FakeMcpServer(results={
        "echo": {"content": [{"type": "text", "text": f"failed token={SECRET}"}], "isError": True}
    })
    server = _guarded(fake)
    server.connect()
    result = server.call("echo", {"message": "x"})
    assert result["status"] == "error"
    assert SECRET not in json.dumps(result)


def test_audit_events_recorded_without_secret():
    db = _AuditDb()
    server = _guarded(_both_tools(), tools=("echo", "scan"), allow_active=True, db=db)
    server.connect()
    server.call("echo", {"message": "x"})
    server.call("scan", {"target": "https://93.184.216.34/"})  # denied: no approval
    actions = {e["action"] for e in db.events}
    assert any(a.endswith(".connect") for a in actions)
    assert any(a.endswith(".denied") for a in actions)
    assert all(SECRET not in str(e.get("detail", "")) for e in db.events)


# --- 10. configuration boundaries --------------------------------------------


def test_tools_cannot_modify_configuration_or_scope():
    cfg_like = SimpleNamespace(mcp={
        "enabled": True,
        "servers": [{"name": "s", "enabled": True, "transport": "mock", "tools": ["update_scope"]}],
    })
    snapshot = copy.deepcopy(cfg_like.mcp)
    target = TargetConfig(domain="93.184.216.34", in_scope=["93.184.216.34"])
    scope_snapshot = list(target.in_scope)

    admin = _tool("update_scope", {"type": "object", "properties": {}}, annotations={
        "readOnlyHint": False, "destructiveHint": True, "openWorldHint": True,
    })
    server = _guarded(FakeMcpServer(tools=[admin]), tools=("update_scope",),
                      allow_active=True, target_config=target)
    server.connect()
    result = server.call("update_scope", {}, authorize_active=True)
    assert result["status"] == "ok"  # the call ran, but as inert data

    assert cfg_like.mcp == snapshot
    assert list(target.in_scope) == scope_snapshot
    assert load_server_policies(cfg_like)[0].tools == ["update_scope"]


def test_non_allowlisted_admin_tool_denied():
    admin = _tool("set_permissions", {"type": "object", "properties": {}}, annotations={
        "readOnlyHint": False, "destructiveHint": True,
    })
    server = _guarded(FakeMcpServer(tools=[admin]), tools=("echo",))
    server.connect()
    assert server.call("set_permissions", {})["status"] == "denied"


def test_load_server_policies_does_not_mutate_input():
    cfg_like = SimpleNamespace(mcp={
        "enabled": True,
        "servers": [{"name": "s", "enabled": True, "transport": "stdio",
                     "command": ["npx", "-y", "srv"], "tools": ["t"]}],
    })
    snapshot = copy.deepcopy(cfg_like.mcp)
    load_server_policies(cfg_like)
    assert cfg_like.mcp == snapshot


# --- 11. lifecycle + backward compatibility ----------------------------------


def test_repeated_calls_do_not_leak_or_break():
    server = _guarded(_both_tools(), tools=("echo", "scan"), allow_active=True)
    server.connect()
    for i in range(25):
        result = server.call("echo", {"message": f"m{i}"})
        assert result["status"] == "ok"
    call_count = len([m for m in server.client.transport.sent if m.get("method") == "tools/call"])
    assert call_count == 25


def test_reconnect_after_close_works():
    server = _guarded(_both_tools(), tools=("echo",))
    assert server.connect()["connected"] is True
    server.close()
    assert server.call("echo", {"message": "x"})["status"] == "denied"
    assert server.connect()["connected"] is True
    assert server.call("echo", {"message": "x"})["status"] == "ok"


def test_cli_mock_still_works(capsys):
    import nexus

    assert nexus.main(["mcp", "--mock", "--call", "echo", "--arg", "message=hi"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"


def test_adapter_registry_and_nemesis_unchanged():
    from lib.adapters.registry import adapter_names

    assert {"zap", "burp", "caido"} <= set(adapter_names())

    gateway = McpGateway()
    gateway.register(
        McpTool(name="t", handler=lambda a: "ok", enabled=True, allowed_actors=("operator",)),
        enabled=True,
    )
    assert gateway.call("t", {}, actor="operator")["status"] == "ok"
