"""C2 bot command layer (CONTROL phase).

Authorization + routing + audit live here, not in the frontends. Every
command is authorized against the configured owner, executed through a
whitelisted action map, and appended to a JSONL audit log. Destructive
actions require an explicit ``confirm`` token.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from lib.logger import get_logger

logger = get_logger("c2_commands")

COMMANDS = {
    "/nexus hunt": "start a scan: /nexus hunt <target>",
    "/nexus stop": "stop the current scan",
    "/nexus logs": "show the latest log lines",
    "/nexus report": "latest findings report path",
    "/nexus status": "framework status (targets, scans, schedules)",
    "/nexus cve-update": "run a manual CVE update",
    "/nexus add-target": "register a target: /nexus add-target <domain>",
    "/nexus remove-target": "disable a target: /nexus remove-target <domain> confirm",
    "/nexus schedules": "list schedules",
    "/nexus add-schedule": "add schedule: /nexus add-schedule <name> <domain> <cron>",
    "/nexus remove-schedule": "disable schedule: /nexus remove-schedule <name> confirm",
}

# Actions that must carry an explicit `confirm` token.
CONFIRM_REQUIRED = {"remove-target", "remove-schedule", "stop"}


@dataclass
class CommandOutcome:
    """Result of one C2 command execution."""

    command: str
    ok: bool
    output: str

    def to_dict(self) -> dict[str, Any]:
        return {"command": self.command, "ok": self.ok, "output": self.output}


class C2Router:
    """Routes authorized bot commands to whitelisted local actions."""

    def __init__(
        self,
        owner_id: str,
        actions: dict[str, Callable[[list[str]], str]] | None = None,
        audit_path: Path | None = None,
    ):
        self.owner_id = str(owner_id)
        self.actions = actions or {}
        self.audit_path = Path(audit_path) if audit_path else None

    def authorized(self, sender_id: str) -> bool:
        return str(sender_id) == self.owner_id and self.owner_id != ""

    # -- audit -------------------------------------------------------------

    def _audit(self, sender: str, command: str, ok: bool, output: str) -> None:
        if not self.audit_path:
            return
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "sender": str(sender),
                "command": command,
                "ok": ok,
                "output": output[:300],
            }
            with self.audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError as exc:  # audit must never break command handling
            logger.debug("audit write failed: %s", exc)

    # -- routing -----------------------------------------------------------

    def handle(self, sender_id: str, text: str) -> CommandOutcome:
        text = (text or "").strip()
        if not text.startswith("/nexus"):
            return CommandOutcome(command=text, ok=False, output="unknown command")

        if not self.authorized(sender_id):
            logger.warning("C2 command from unauthorized sender rejected")
            outcome = CommandOutcome(command=text.split()[0], ok=False, output="unauthorized")
            self._audit(sender_id, text, False, outcome.output)
            return outcome

        parts = text.split()
        action_name = parts[1] if len(parts) >= 2 else ""
        args = parts[2:]

        # Confirmation gate for destructive actions.
        if action_name in CONFIRM_REQUIRED:
            if "confirm" not in [a.lower() for a in args]:
                outcome = CommandOutcome(
                    command=action_name, ok=False,
                    output=f"{action_name} requires an explicit 'confirm' token",
                )
                self._audit(sender_id, text, False, outcome.output)
                return outcome
            args = [a for a in args if a.lower() != "confirm"]

        handler = self.actions.get(action_name)
        if handler is None:
            outcome = CommandOutcome(command=action_name, ok=False, output=f"no handler for {action_name}")
            self._audit(sender_id, text, False, outcome.output)
            return outcome

        try:
            output = str(handler(args))
            outcome = CommandOutcome(command=action_name, ok=True, output=output)
        except Exception as exc:  # never leak a traceback to chat
            logger.warning("C2 command failed: %s", exc)
            outcome = CommandOutcome(command=action_name, ok=False, output=f"error: {exc}")
        self._audit(sender_id, text, outcome.ok, outcome.output)
        return outcome

    def help_text(self) -> str:
        return "\n".join(f"{cmd} — {desc}" for cmd, desc in COMMANDS.items())
