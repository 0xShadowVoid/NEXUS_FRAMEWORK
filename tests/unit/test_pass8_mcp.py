"""Unit and integration tests for Pass 8 Live MCP Transport and Hardening."""
from __future__ import annotations

import asyncio
import pytest
from lib.nemesis.mcp import McpGateway, McpTool
from lib.nemesis.mcp_transport import McpServerTransport
from lib.config import TargetConfig

def test_mcp_transport_initialization():
    gateway = McpGateway()
    transport = McpServerTransport(gateway)
    
    req = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    res = asyncio.run(transport.handle_json_rpc(req))
    assert res["result"]["serverInfo"]["name"] == "nexus-mcp-server"

def test_mcp_transport_tools_list_and_call():
    gateway = McpGateway()
    tool = McpTool(
        name="echo_test",
        handler=lambda args: {"echo": args.get("msg", "")},
        description="Echo test tool",
        enabled=True,
        requires_auth=True,
        allowed_actors=("operator",)
    )
    gateway.register(tool, enabled=True)
    transport = McpServerTransport(gateway)

    # List tools
    list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    list_res = asyncio.run(transport.handle_json_rpc(list_req, actor="operator"))
    assert len(list_res["result"]["tools"]) == 1
    assert list_res["result"]["tools"][0]["name"] == "echo_test"

    # Call tool successfully
    call_req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "echo_test", "arguments": {"msg": "hello nexus"}}
    }
    call_res = asyncio.run(transport.handle_json_rpc(call_req, actor="operator"))
    assert "content" in call_res["result"]

def test_mcp_transport_unauthorized_actor():
    gateway = McpGateway()
    tool = McpTool(
        name="secure_tool",
        handler=lambda args: "success",
        enabled=True,
        requires_auth=True,
        allowed_actors=("operator",)
    )
    gateway.register(tool, enabled=True)
    transport = McpServerTransport(gateway)

    call_req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "secure_tool", "arguments": {}}
    }
    # Call with unauthorized actor "guest"
    call_res = asyncio.run(transport.handle_json_rpc(call_req, actor="guest"))
    # McpGateway returns denial dict, which transport wraps in result text or json
    content_text = call_res["result"]["content"][0]["text"]
    assert "denied" in content_text or "authorization" in content_text

def test_mcp_transport_timeout():
    gateway = McpGateway()
    def slow_handler(args):
        import time
        time.sleep(0.5)
        return "done"
    tool = McpTool(name="slow_tool", handler=slow_handler, enabled=True, allowed_actors=("operator",))
    gateway.register(tool, enabled=True)
    
    transport = McpServerTransport(gateway, timeout_seconds=0.1)
    call_req = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {"name": "slow_tool", "arguments": {}}
    }
    res = asyncio.run(transport.handle_json_rpc(call_req, actor="operator"))
    assert "error" in res
    assert res["error"]["code"] == -32000
    assert "timed out" in res["error"]["message"]
