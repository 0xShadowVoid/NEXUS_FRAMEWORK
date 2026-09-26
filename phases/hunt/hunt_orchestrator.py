"""HUNT phase orchestrator."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from lib.config import Config
from lib.logger import get_logger
from phases.hunt.auto_hunter import run_hunt

logger = get_logger("hunt_orchestrator")


def run_hunt_phase(
    cfg: Config,
    results_base: Path,
    scan_runner: Callable[[dict[str, Any]], Any] | None = None,
) -> dict[str, Any]:
    """Run Phase 4 (auto-hunt). OFF by default."""
    summary = run_hunt(cfg, results_base, scan_runner=scan_runner)
    return summary
