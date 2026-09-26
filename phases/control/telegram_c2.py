"""Telegram C2 frontend (CONTROL phase).

Long-poll based listener that routes messages through the shared
C2Router. Uses only ``requests`` (no heavy SDK). Runs in a daemon
thread; unauthorized senders are rejected by the router.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Callable

import requests

from lib.logger import get_logger
from phases.control.c2_commands import C2Router, default_logs_handler

logger = get_logger("telegram_c2")

_API_BASE = "https://api.telegram.org/bot{token}"
_POLL_TIMEOUT = 25


class TelegramC2:
    """Telegram frontend for the NEXUS C2 bot."""

    def __init__(self, router: C2Router, bot_token: str = "", chat_id: str = ""):
        self.router = router
        self.bot_token = bot_token
        self.chat_id = chat_id
        self._stop = threading.Event()

    def _send(self, text: str) -> bool:
        if not self.bot_token or not self.chat_id:
            return False
        try:
            resp = requests.post(
                _API_BASE.format(token=self.bot_token) + "/sendMessage",
                json={"chat_id": self.chat_id, "text": text[:4000]},
                timeout=(5, 15),
            )
            return resp.status_code == 200
        except requests.RequestException:
            return False

    def start(self) -> dict[str, Any]:
        """Start the long-poll loop in a daemon thread."""
        if not self.bot_token:
            return {"status": "stub", "reason": "TELEGRAM_BOT_TOKEN unset; routing tests still available"}

        def loop() -> None:
            offset = 0
            while not self._stop.is_set():
                try:
                    resp = requests.get(
                        _API_BASE.format(token=self.bot_token) + "/getUpdates",
                        params={"timeout": _POLL_TIMEOUT, "offset": offset},
                        timeout=(5, _POLL_TIMEOUT + 10),
                    )
                    if resp.status_code != 200:
                        time.sleep(5)
                        continue
                    for update in resp.json().get("result", []):
                        offset = update.get("update_id", 0) + 1
                        message = update.get("message") or {}
                        sender = str((message.get("from") or {}).get("id", ""))
                        text = str(message.get("text", ""))
                        outcome = self.router.handle(sender, text)
                        if text.startswith("/nexus"):
                            self._send(f"{outcome.command}: {outcome.output}")
                except (requests.RequestException, ValueError):
                    time.sleep(5)

        threading.Thread(target=loop, daemon=True, name="nexus-telegram-c2").start()
        return {"status": "running", "chat_id": self.chat_id}

    def stop(self) -> None:
        self._stop.set()


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
