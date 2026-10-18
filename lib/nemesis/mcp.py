"""MCP security gateway (Phase F).

External MCP tools cannot bypass NEXUS security controls. Every call
passes through the same pipeline:

    AUTH → AUTHORIZATION → SCOPE → SAFETY → EXECUTION → EVIDENCE → AUDIT

Tools are represented through one policy abstraction, are disabled by
default, and never execute merely because an agent requested them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from lib.logger import get_logger
from lib.payload_guard import validate_payload
from lib.redaction import redact_text
from lib.scope_validator import validate_finding_scope

logger = get_logger("nemesis.mcp")


@dataclass
class McpTool:
    """One registered MCP tool + its security policy."""

    name: str
    handler: Callable[[dict[str, Any]], Any]
    description: str = ""
    requires_auth: bool = True
    allowed_actors: tuple[str, ...] = ("operator",)
    allow_agent: bool = False
    scope_target_key: str = ""        # args key carrying a target to scope-check
    side_effects: bool = False
    enabled: bool = False


class McpGateway:
    """Policy-enforcing gateway for MCP tool calls."""

    def __init__(self, db: Any = None, target_config: Any = None):
        self.db = db
        self.target_config = target_config
        self.tools: dict[str, McpTool] = {}

    def register(self, tool: McpTool, enabled: bool = False) -> None:
        tool.enabled = bool(enabled)
        self.tools[tool.name] = tool

    # -- pipeline pieces ---------------------------------------------------------

    def _audit(self, actor: str, name: str, status: str, detail: str = "") -> None:
        if self.db is None:
            return
        try:
            self.db.insert_audit_event(
                actor=str(actor or ""), action=f"mcp.{name}",
                category="mcp", detail=redact_text(f"{status} {detail}").strip()[:300],
            )
        except Exception:  # audit must never break execution
            pass

    def _deny(self, actor: str, name: str, reason: str) -> dict[str, Any]:
        self._audit(actor, name, "denied", reason)
        return {"status": "denied", "tool": name, "reason": redact_text(reason)}

    # -- entrypoint -----------------------------------------------------------------

    def call(
        self, name: str, args: dict[str, Any] | None = None, actor: str = "operator"
    ) -> dict[str, Any]:
        """Call a registered MCP tool through the full security pipeline."""
        args = dict(args or {})
        tool = self.tools.get(str(name))
        if tool is None:
            return self._deny(actor, str(name), "unknown tool")
        if not tool.enabled:
            return self._deny(actor, tool.name, "tool disabled")

        # AUTH
        if tool.requires_auth and not str(actor or "").strip():
            return self._deny(actor, tool.name, "authentication required")

        # AUTHORIZATION
        if actor == "agent" and not tool.allow_agent:
            return self._deny(actor, tool.name, "authorization: agent actors not permitted")
        if actor != "agent" and actor not in tool.allowed_actors:
            return self._deny(actor, tool.name, f"authorization: actor {actor!r} not allowed")

        # SCOPE
        if tool.scope_target_key:
            target = str(args.get(tool.scope_target_key) or "").strip()
            if not target:
                return self._deny(actor, tool.name, "scope: target missing")
            if self.target_config is None or not validate_finding_scope(target, self.target_config):
                return self._deny(actor, tool.name, "scope: target out of scope")

        # SAFETY (payload guard over string arguments)
        for value in args.values():
            if isinstance(value, str):
                allowed, reason = validate_payload(value)
                if not allowed:
                    return self._deny(actor, tool.name, f"safety: {reason}")

        # EXECUTION
        try:
            result = tool.handler(dict(args))
        except Exception as exc:
            message = redact_text(str(exc))
            self._audit(actor, tool.name, "error", message)
            return {"status": "error", "tool": tool.name, "error": message}

        # EVIDENCE hook: handlers may return {"evidence_id": ...}; we link it
        # to nothing by default (no fabrication) — the caller decides.
        self._audit(actor, tool.name, "ok", "")
        return {"status": "ok", "tool": tool.name, "result": result}
