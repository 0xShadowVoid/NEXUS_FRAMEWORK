"""AUTHZ phase orchestrator (thin wrapper over lib.authz_engine)."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from lib.config import Config, TargetConfig
from lib.logger import get_logger

logger = get_logger("authz_orchestrator")


def run_authz(
    cfg: Config,
    target_config: TargetConfig,
    results_dir: Path,
    urls: list[str] | None = None,
    identities: list[dict[str, Any]] | None = None,
    http_get: Callable[[str], str] | None = None,
    db: Any | None = None,
    scan_id: int | None = None,
) -> dict[str, Any]:
    from lib.authz_engine import run_authz as _run

    return _run(
        cfg, target_config, results_dir,
        urls=urls, identities=identities, http_get=http_get, db=db, scan_id=scan_id,
    )
