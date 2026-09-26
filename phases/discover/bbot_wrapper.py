"""BBot wrapper (DISCOVER, deep scan only).

BBot runs 100+ modules and requires the Pegpon step to have completed
(probe URLs present). This wrapper invokes bbot via the boundary-checked
ToolRunner when available and summarizes its output; when bbot is
absent (common on Windows), the wrapper degrades to a documented
no-op so the phase still completes in light environments.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from phases.probe.tool_runner import ToolRunner
from lib.logger import get_logger

logger = get_logger("bbot_wrapper")


def bbot_prerequisites_met(results_dir: Path) -> bool:
    """True when Pegpon output exists (domains.txt present)."""
    return (results_dir / "recon" / "domains.txt").exists()


def run_bbot(
    domain: str,
    runner: ToolRunner,
    results_dir: Path,
    force: bool = False,
) -> dict[str, Any]:
    """Run bbot (deep scan only). Requires pegpon output first.

    ``force`` lets the orchestrator bypass the prerequisite check only
    when the user explicitly re-runs discover with --full-scan.
    """
    if not force and not bbot_prerequisites_met(results_dir):
        return {
            "status": "skipped",
            "reason": "pegpon output missing (auto-run discover first)",
        }

    if not runner.tool_available("bbot"):
        return {
            "status": "skipped",
            "reason": "bbot not installed (deep-scan tool); phase continues",
        }

    out_dir = results_dir / "recon" / "bbot"
    out_dir.mkdir(parents=True, exist_ok=True)
    result = runner.run(
        "bbot",
        ["-t", domain, "-p", "subdomain-enum", "-f", "json", "-o", str(out_dir)],
    )
    summary: dict[str, Any] = {
        "status": "ok" if result.ok else result.status,
        "returncode": result.returncode,
        "duration_seconds": result.duration_seconds,
    }
    # Best-effort parse of bbot JSON output files.
    events: list[dict[str, Any]] = []
    for file in out_dir.glob("*.json"):
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                events.extend(data)
            elif isinstance(data, dict):
                events.append(data)
        except (OSError, json.JSONDecodeError):
            continue
    summary["events"] = len(events)
    logger.info("bbot: %s (%d events)", summary["status"], len(events))
    return summary
