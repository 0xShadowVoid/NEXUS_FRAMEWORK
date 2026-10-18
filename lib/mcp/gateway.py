"""Guarded MCP server — NEXUS stays the policy authority.

:class:`GuardedMcpServer` fuses the existing NEMESIS policy pipeline
(:class:`lib.nemesis.mcp.McpGateway`) with the MCP client
(:mod:`lib.mcp.client`) and the NEXUS boundaries the rest of the framework
already uses:

    kill switch          -> lib.ops_guard.KillSwitch
    target scope         -> lib.scope_validator (via McpGateway / this class)
    destination SSRF     -> lib.ssrf_guard.is_safe_url
    request budget       -> lib.ops_guard.spend_requests
    payload safety       -> lib.payload_guard.validate_payload (via McpGateway)
    secret redaction     -> lib.redaction / core.sanitizer

Additional MCP-specific gates enforced here, all fail-closed:

- the server must be explicitly enabled in configuration;
- only tools on the per-server allowlist are registered (unknown = denied);
- arguments are validated against the discovered ``inputSchema`` first;
- read-only vs active tools stay distinct — an active tool needs both
  ``allow_active`` in policy *and* a per-call ``authorize_active``;
- URL arguments pass the SSRF guard, and remote endpoints are SSRF-checked;
- results are bounded in size and redacted before they reach logs/reports.

An MCP server can never change NEXUS scope, permissions, credentials or
security configuration: tool metadata/results are untrusted data and are never
applied back to configuration.
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from typing import Any

from lib.logger import get_logger
from lib.mcp.client import DEFAULT_RESULT_BYTES, McpClient
from lib.mcp.protocol import (
    McpCallResult,
    McpError,
    McpPolicyError,
    McpToolError,
    McpToolSpec,
    validate_arguments,
)
from lib.mcp.transport import StdioTransport, StreamableHttpTransport
from lib.nemesis.mcp import McpGateway, McpTool
from lib.ops_guard import KillSwitch
from lib.payload_guard import validate_tool_command
from lib.redaction import redact_text
from lib.ssrf_guard import is_safe_url
from lib.version import framework_version

logger = get_logger("mcp.gateway")

SUPPORTED_TRANSPORTS = ("stdio", "streamable-http", "mock")


@dataclass
class McpServerPolicy:
    """Operator configuration for one MCP server (never holds a live secret).

    ``auth_token`` is the *resolved* value loaded from ``auth_token_env`` at
    build time; it is never logged and never written back to configuration.
    """

    name: str
    enabled: bool = False
    transport: str = "stdio"
    command: list[str] = field(default_factory=list)
    url: str = ""
    tools: list[str] = field(default_factory=list)
    allow_active: bool = False
    timeout: float = 30.0
    max_result_bytes: int = DEFAULT_RESULT_BYTES
    max_concurrency: int = 2
    auth_token: str = ""
    ssrf_allow: set[str] = field(default_factory=set)
    scope_tools: dict[str, str] = field(default_factory=dict)

    def validate(self) -> list[str]:
        """Return configuration problems (already secret-free); [] when ok."""
        issues: list[str] = []
        if not str(self.name or "").strip():
            issues.append("server name is required")
        if self.transport not in SUPPORTED_TRANSPORTS:
            issues.append(f"unsupported transport: {self.transport!r}")
        if self.transport == "stdio":
            if not self.command:
                issues.append("stdio server requires a command")
            else:
                allowed, reason = validate_tool_command(self.command)
                if not allowed:
                    issues.append(f"stdio command refused by safety guard: {reason}")
        elif self.transport == "streamable-http":
            if not self.url:
                issues.append("streamable-http server requires a url")
            else:
                safe, reason = is_safe_url(self.url, allow=self.ssrf_allow, local_ok=True)
                if not safe:
                    issues.append(f"endpoint blocked by SSRF guard: {reason}")
        return issues


class GuardedMcpServer:
    """A configured MCP server whose every invocation passes NEXUS policy."""

    def __init__(
        self,
        policy: McpServerPolicy,
        *,
        client: McpClient | None = None,
        db: Any = None,
        target_config: Any = None,
        killswitch: KillSwitch | None = None,
        actor: str = "operator",
    ):
        self.policy = policy
        self.actor = actor
        self.db = db
        self.target_config = target_config
        self.killswitch = killswitch
        self.gateway = McpGateway(db=db, target_config=target_config)
        self.client = client
        self.connected = False
        self.status_error = ""
        self._specs: dict[str, McpToolSpec] = {}
        self._sem = threading.Semaphore(max(1, int(policy.max_concurrency)))

    # -- audit --------------------------------------------------------------

    def _audit(self, action: str, detail: str = "") -> None:
        if self.db is None:
            return
        try:
            self.db.insert_audit_event(
                actor=self.actor,
                action=f"mcp.{self.policy.name}.{action}",
                category="mcp",
                detail=redact_text(str(detail)),
            )
        except Exception:  # audit must never break execution
            pass

    def _deny(self, tool: str, reason: str) -> dict[str, Any]:
        self._audit("denied", f"{tool}: {reason}")
        return {"status": "denied", "tool": tool, "server": self.policy.name, "reason": reason}

    # -- connection / discovery --------------------------------------------

    def _build_client(self) -> McpClient:
        if self.client is not None:
            return self.client
        p = self.policy
        if p.transport == "stdio":
            transport: Any = StdioTransport(
                p.command, timeout=p.timeout, max_message_bytes=p.max_result_bytes
            )
        elif p.transport == "streamable-http":
            transport = StreamableHttpTransport(
                p.url,
                token=p.auth_token,
                timeout=p.timeout,
                ssrf_allow=p.ssrf_allow,
                max_message_bytes=p.max_result_bytes,
            )
        else:  # pragma: no cover - "mock" always supplies a client
            raise McpPolicyError(f"transport {p.transport!r} requires an injected client")
        return McpClient(
            transport,
            p.name,
            timeout=p.timeout,
            max_result_bytes=p.max_result_bytes,
            client_version=framework_version(),
        )

    def connect(self) -> dict[str, Any]:
        """Validate config, connect, discover tools and register the allowlist."""
        if not self.policy.enabled:
            self.status_error = "server disabled"
            return self.status()
        ks = self.killswitch or KillSwitch()
        if ks.killed():
            self.status_error = "kill switch engaged"
            return self.status()

        issues = self.policy.validate()
        if issues:
            self.status_error = "; ".join(issues)
            self._audit("config_rejected", self.status_error)
            return self.status()

        try:
            if self.client is None:
                self.client = self._build_client()
            self.client.connect()
            tools = self.client.list_tools()
        except McpError as exc:
            self.status_error = redact_text(str(exc))
            self.connected = False
            self._audit("connect_error", self.status_error)
            return self.status()

        self.connected = True
        self._register_tools(tools)
        self._audit("connect", f"discovered={len(tools)} allowed={len(self._specs)}")
        return self.status()

    def _register_tools(self, tools: list[McpToolSpec]) -> None:
        allow = {str(name).strip() for name in self.policy.tools if str(name).strip()}
        for spec in tools:
            if spec.name not in allow:
                continue  # deny by default: not on the allowlist → not registered
            self.gateway.register(
                McpTool(
                    name=spec.name,
                    handler=self._make_handler(spec),
                    description=spec.description,
                    requires_auth=True,
                    allowed_actors=("operator",),
                    allow_agent=False,
                    scope_target_key=self.policy.scope_tools.get(spec.name, ""),
                    side_effects=spec.is_active(),
                    enabled=True,
                ),
                enabled=True,
            )
            self._specs[spec.name] = spec

    def _make_handler(self, spec: McpToolSpec):
        def handler(args: dict[str, Any]) -> Any:
            result = self._invoke(spec, args)
            if not result.ok:
                raise McpToolError(result.error or "tool reported an error")
            return result.to_dict()

        return handler

    def _invoke(self, spec: McpToolSpec, args: dict[str, Any]) -> McpCallResult:
        assert self.client is not None
        with self._sem:
            return self.client.call_tool(spec.name, args, timeout=self.policy.timeout)

    # -- inspection ---------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Secret-free server status (no tool is executed)."""
        return {
            "server": self.policy.name,
            "enabled": self.policy.enabled,
            "transport": self.policy.transport,
            "connected": self.connected,
            "protocol_version": self.client.negotiated_version if self.client else "",
            "server_info": dict(self.client.server_info) if self.client else {},
            "capabilities": dict(self.client.server_capabilities) if self.client else {},
            "tools_allowed": sorted(self._specs),
            "tools_discovered": sorted(self.client.tools) if self.client else [],
            "tools_rejected": dict(self.client.schema_errors) if self.client else {},
            "error": redact_text(self.status_error),
        }

    def capabilities(self) -> dict[str, Any]:
        """Discovered tool metadata (schemas included) — never executes a tool."""
        discovered = list(self.client.tools.values()) if self.client else []
        allow = set(self._specs)
        return {
            "server": self.policy.name,
            "tools": [
                {**spec.to_dict(), "allowed": spec.name in allow} for spec in discovered
            ],
            "rejected": dict(self.client.schema_errors) if self.client else {},
        }

    # -- invocation ---------------------------------------------------------

    def call(
        self,
        tool: str,
        args: dict[str, Any] | None = None,
        actor: str | None = None,
        *,
        authorize_active: bool = False,
    ) -> dict[str, Any]:
        """Invoke *tool* through the full NEXUS pipeline (fail closed)."""
        args = dict(args or {})
        actor = actor or self.actor

        spec = self._specs.get(str(tool))
        if spec is None:
            return self._deny(str(tool), "unknown or non-allowlisted tool")
        if not self.connected:
            return self._deny(spec.name, "server not connected")
        ks = self.killswitch or KillSwitch()
        if ks.killed():
            return self._deny(spec.name, "kill switch engaged")

        issues = validate_arguments(args, spec.input_schema)
        if issues:
            return self._deny(spec.name, "schema: " + "; ".join(issues))

        if spec.is_active() and not (self.policy.allow_active and authorize_active):
            return self._deny(
                spec.name,
                "active tool requires allow_active in policy and explicit per-call authorization",
            )

        for key, value in args.items():
            if isinstance(value, str) and value.startswith(("http://", "https://")):
                safe, reason = is_safe_url(value, allow=self.policy.ssrf_allow, local_ok=False)
                if not safe:
                    return self._deny(spec.name, f"ssrf: argument {key!r} blocked: {reason}")

        # Auth/authz/scope/payload/execution/audit are enforced by McpGateway.
        return self.gateway.call(spec.name, args, actor)

    def close(self) -> None:
        if self.client is not None:
            self.client.close()
        self.connected = False


# ---------------------------------------------------------------------------
# Configuration → policies
# ---------------------------------------------------------------------------


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return default


def _resolve_token(section: dict[str, Any]) -> str:
    env_name = str(section.get("auth_token_env") or "").strip()
    if not env_name:
        return ""
    return os.environ.get(env_name, "") or ""


def policy_from_config(name: str, section: dict[str, Any], *, global_enabled: bool) -> McpServerPolicy:
    """Build one :class:`McpServerPolicy` from a ``mcp.servers`` entry."""
    section = section if isinstance(section, dict) else {}
    command = section.get("command") or []
    if isinstance(command, str):
        command = [command]
    scope_tools = section.get("scope_tools") or {}
    return McpServerPolicy(
        name=str(name),
        enabled=bool(global_enabled and _as_bool(section.get("enabled", False))),
        transport=str(section.get("transport") or "stdio"),
        command=[str(part) for part in command] if isinstance(command, list) else [],
        url=str(section.get("url") or ""),
        tools=[str(t) for t in (section.get("tools") or []) if str(t).strip()],
        allow_active=_as_bool(section.get("allow_active", False)),
        timeout=float(section.get("timeout_seconds") or 30.0),
        max_result_bytes=int(section.get("max_result_bytes") or DEFAULT_RESULT_BYTES),
        max_concurrency=max(1, int(section.get("max_concurrency") or 2)),
        auth_token=_resolve_token(section),
        ssrf_allow={
            str(h).strip().lower() for h in (section.get("ssrf_allow") or []) if str(h).strip()
        },
        scope_tools={
            str(k): str(v) for k, v in scope_tools.items()
        } if isinstance(scope_tools, dict) else {},
    )


def load_server_policies(cfg: Any) -> list[McpServerPolicy]:
    """Build every configured server policy (disabled ones included)."""
    config = getattr(cfg, "mcp", {}) or {}
    global_enabled = _as_bool(config.get("enabled", False))
    servers = config.get("servers") or []
    policies: list[McpServerPolicy] = []
    if isinstance(servers, dict):
        servers = [{"name": name, **(spec or {})} for name, spec in servers.items()]
    for entry in servers if isinstance(servers, list) else []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        if not name:
            continue
        policies.append(policy_from_config(name, entry, global_enabled=global_enabled))
    return policies


def find_server_policy(cfg: Any, name: str) -> McpServerPolicy | None:
    for policy in load_server_policies(cfg):
        if policy.name == name:
            return policy
    return None


def mock_server(
    *,
    db: Any = None,
    target_config: Any = None,
    allow_active: bool = False,
    tools: list[str] | None = None,
) -> GuardedMcpServer:
    """Build an offline server (``nexus mcp --mock``) backed by a fake backend."""
    from lib.mcp.mock import FakeMcpServer, MockMcpClient, default_active_tool, default_tool

    allow = tools if tools is not None else ["echo", "scan"]
    policy = McpServerPolicy(
        name="mock",
        enabled=True,
        transport="mock",
        tools=list(allow),
        allow_active=allow_active,
        scope_tools={"scan": "target"},
    )
    fake = FakeMcpServer(tools=[default_tool("echo"), default_active_tool("scan")])
    client = MockMcpClient(fake, name="mock")
    return GuardedMcpServer(policy, client=client, db=db, target_config=target_config)
