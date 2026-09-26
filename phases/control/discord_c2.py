"""Discord C2 frontend (CONTROL phase).

Listens for slash commands in a private channel and routes them through
the shared C2Router. Uses the Discord bot gateway when ``discord.py``
is installed; otherwise registers a documented stub so tests can verify
routing/authorization without the dependency.
"""
from __future__ import annotations

from typing import Any, Callable

from lib.logger import get_logger
from phases.control.c2_commands import C2Router, default_logs_handler

logger = get_logger("discord_c2")


class DiscordC2:
    """Discord frontend for the NEXUS C2 bot."""

    def __init__(self, router: C2Router, bot_token: str = "", channel_id: str = ""):
        self.router = router
        self.bot_token = bot_token
        self.channel_id = channel_id

    def start(self) -> dict[str, Any]:
        """Start listening. Requires discord.py + token; else stub mode."""
        if not self.bot_token:
            return {"status": "stub", "reason": "DISCORD_BOT_TOKEN unset; routing tests still available"}
        try:
            import discord  # type: ignore[import-not-found]
        except ImportError:
            return {"status": "stub", "reason": "discord.py not installed (optional dependency)"}

        intents = discord.Intents.default()
        intents.message_content = True
        client = discord.Client(intents=intents)

        @client.event
        async def on_ready() -> None:
            logger.info("discord C2 connected as %s", client.user)

        @client.event
        async def on_message(message: discord.Message) -> None:
            if message.author == client.user:
                return
            outcome = self.router.handle(str(message.author.id), message.content)
            if outcome.command.startswith("/nexus"):
                await message.channel.send(f"```\n{outcome.output[:1900]}\n```")

        import threading

        threading.Thread(
            target=lambda: client.run(self.bot_token), daemon=True
        ).start()
        return {"status": "running", "channel_id": self.channel_id}


def build_default_router(owner_id: str, logs_path=None) -> C2Router:
    """Build a router with the default handler set."""
    from pathlib import Path

    handlers: dict[str, Callable[[str], str]] = {
        "/nexus hunt": lambda target: f"scan started: {target}",
        "/nexus stop": lambda _a: "stop requested",
        "/nexus logs": lambda _a: default_logs_handler(logs_path),
        "/nexus report": lambda _a: "latest report path: results/",
        "/nexus status": lambda _a: "no running scans",
        "/nexus cve-update": lambda _a: "cve update triggered",
    }
    return C2Router(owner_id=owner_id, handlers=handlers, logs_path=logs_path)
