"""ANALYZE phase orchestrator — thin wrapper over core.Analyzer."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core.analyzer import Analyzer
from core.database import Database
from lib.config import Config, TargetConfig
from lib.logger import get_logger

logger = get_logger("analyze_orchestrator")


def run_analyze(
    cfg: Config,
    db: Database,
    target_config: TargetConfig,
    raw_findings: list[dict[str, Any]],
    scan_id: int,
    results_dir: Path,
    urls_discovered: int = 0,
    endpoints_tested: int = 0,
    duration_seconds: int = 0,
    min_severity: str = "",
    exclude: list[str] | None = None,
    exclude_p4: bool = False,
) -> dict[str, Any]:
    """Run Phase 3; returns metrics."""
    analyzer = Analyzer(cfg, db)
    metrics = analyzer.run(
        raw_findings=raw_findings,
        target_config=target_config,
        scan_id=scan_id,
        results_dir=results_dir,
        urls_discovered=urls_discovered,
        endpoints_tested=endpoints_tested,
        duration_seconds=duration_seconds,
        min_severity=min_severity,
        exclude=exclude,
        exclude_p4=exclude_p4,
    )
    return metrics
