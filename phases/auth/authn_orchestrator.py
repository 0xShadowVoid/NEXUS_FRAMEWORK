"""AUTHN phase orchestrator (thin wrapper over lib.authn_engine)."""
from __future__ import annotations

from typing import Any

from lib.config import Config, TargetConfig
from lib.logger import get_logger

logger = get_logger("authn_orchestrator")


def run_authn(
    cfg: Config,
    target_config: TargetConfig,
    results_dir: Any,
    urls: list[str] | None = None,
    responses: list[dict[str, Any]] | None = None,
    db: Any | None = None,
    scan_id: int | None = None,
    notifier: Any | None = None,
) -> dict[str, Any]:
    from lib.authn_engine import run_authn as _run

    return _run(
        cfg, target_config, results_dir,
        urls=urls, responses=responses, db=db, scan_id=scan_id, notifier=notifier,
    )
