"""TAKEOVER phase orchestrator (thin wrapper over lib.takeover)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from lib.config import Config, TargetConfig
from lib.logger import get_logger

logger = get_logger("takeover_orchestrator")


def run_subdominator(
    target: str,
    runner: Any | None = None,
    results_dir: Path | None = None,
) -> dict[str, Any]:
    """Optional binary entrypoint (kept for the tool registry)."""
    from lib.takeover import run_takeover

    return run_takeover(
        cfg=None,
        target_config=TargetConfig(domain=target),
        results_dir=results_dir or Path("."),
        runner=runner,
    )


def run_takeover(
    cfg: Config,
    target_config: TargetConfig,
    results_dir: Path,
    db: Any | None = None,
    scan_id: int | None = None,
    cnames: dict[str, str] | None = None,
    http_get: Any | None = None,
) -> dict[str, Any]:
    from lib.takeover import run_takeover as _run

    return _run(
        cfg, target_config, results_dir,
        cnames=cnames, db=db, scan_id=scan_id, http_get=http_get,
    )
