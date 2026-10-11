"""NEXUS Live MCP Transport Module (Pass 8).

Implements a standards-compatible Model Context Protocol (MCP) server & transport
layer integrating directly with the NEXUS McpGateway security architecture.
Enforces authentication, role authorization, engagement scope verification,
payload safety, budgets, timeouts, concurrency limits, and audit logging on every tool invocation.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable, Optional
from pydantic import BaseModel, Field

from lib.nemesis.mcp import McpGateway, McpTool
from lib.config import load_config
from core.database import Database

logger = logging.getLogger("nexus.mcp.transport")

class McpRequestMessage(BaseModel):
    jsonrpc: str = "2.0"
    id: int | str = 1
    method: str
    params: dict[str, Any] = Field(default_factory=dict)

class McpServerTransport:
    """Standards-compatible MCP transport wrapping McpGateway with robust limits & error handling."""

    def __init__(self, gateway: McpGateway, max_concurrency: int = 10, timeout_seconds: float = 30.0):
        self.gateway = gateway
        self.max_concurrency = max_concurrency
        self.timeout_seconds = timeout_seconds
        self._semaphore = asyncio.Semaphore(max_concurrency)

    async def handle_json_rpc(self, raw_message: str | dict[str, Any], actor: str = "operator") -> dict[str, Any]:
        """Process an incoming JSON-RPC message for MCP tool discovery or invocation."""
        try:
            msg = raw_message if isinstance(raw_message, dict) else json.loads(raw_message)
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {str(e)}"}
            }

        req = McpRequestMessage(**msg)
        method = req.method
        params = req.params
        msg_id = req.id

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "nexus-mcp-server", "version": "3.8.0"}
                }
            }
        elif method == "tools/list":
            tools_list = []
            for name, tool in self.gateway.tools.items():
                if tool.enabled:
                    tools_list.append({
                        "name": tool.name,
                        "description": tool.description,
                        "inputSchema": {"type": "object", "properties": {}}
                    })
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": tools_list}
            }
        elif method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            if not tool_name:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32602, "message": "Missing tool name"}
                }
            
            # Enforce concurrency limit and timeout
            try:
                async with self._semaphore:
                    result = await asyncio.wait_for(
                        asyncio.to_thread(self.gateway.call, tool_name, tool_args, actor),
                        timeout=self.timeout_seconds
                    )
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"content": [{"type": "text", "text": json.dumps(result)}]}
                }
            except asyncio.TimeoutError:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32000, "message": "Tool execution timed out"}
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32603, "message": f"Internal error: {str(exc)}"}
                }
        else:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"}
            }
