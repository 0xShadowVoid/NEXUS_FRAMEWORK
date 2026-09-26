"""Operational safety guards (roadmap H2).

- Global kill-switch: a marker file that stops all new scan work.
- Request budget: a counter that refuses further traffic once a
  configured limit is exhausted (per-process).
"""
from __future__ import annotations

import threading
from pathlib import Path

from lib.logger import get_logger
from lib.paths import REPO_ROOT

logger = get_logger("ops_guard")

KILLSWITCH_NAME = ".nexus_killswitch"

_lock = threading.Lock()
_request_budget: int | None = None          # None = unlimited
_requests_spent: int = 0


def set_request_budget(limit: int | None) -> None:
    """Configure the process-wide request budget (None = unlimited)."""
    global _request_budget, _requests_spent
    with _lock:
        _request_budget = limit
        _requests_spent = 0


def spend_requests(n: int = 1) -> bool:
    """Reserve *n* requests; False when the budget is exhausted."""
    global _requests_spent
    with _lock:
        if _request_budget is None:
            return True
        if _requests_spent + n > _request_budget:
            logger.warning("request budget exhausted (%d/%d)", _requests_spent, _request_budget)
            return False
        _requests_spent += n
        return True


def requests_remaining() -> int | None:
    with _lock:
        return None if _request_budget is None else max(0, _request_budget - _requests_spent)


class KillSwitch:
    """File-backed global stop."""

    def __init__(self, base_dir: Path | None = None):
        self.path = (Path(base_dir) if base_dir else REPO_ROOT) / KILLSWITCH_NAME

    def killed(self) -> bool:
        return self.path.exists()

    def kill(self) -> Path:
        self.path.write_text("killed", encoding="utf-8")
        logger.warning("kill-switch engaged: %s", self.path)
        return self.path

    def resume(self) -> None:
        if self.path.exists():
            self.path.unlink()
        logger.info("kill-switch cleared")
