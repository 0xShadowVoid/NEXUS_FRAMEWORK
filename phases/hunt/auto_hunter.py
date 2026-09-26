"""Auto-hunter (HUNT phase).

Fetches new programs via the platform APIs, filters BB (paid, priority)
vs VDP (light strategy), respects ``max_scans_per_day``, and queues
quick-scans. OFF by default — enabled via config or ``nexus hunt-new
--enable``. Alerts fire on P1/P2 findings.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lib.config import Config
from lib.logger import get_logger
from phases.hunt.api_fetcher import (
    fetch_bugcrowd_programs,
    fetch_hackerone_programs,
    fetch_intigriti_programs,
    fetch_yeswehack_programs,
)

logger = get_logger("auto_hunter")

ALERT_SEVERITIES = ("P1", "P2")


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class AutoHunter:
    """Queue manager + scan trigger for first-blood hunting."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        hunt_cfg = cfg.phases.get("hunt", {}) or {}
        self.enabled = bool(hunt_cfg.get("enabled", False))
        self.intensity = str(hunt_cfg.get("intensity", "quick-scan"))
        self.max_per_day = int(hunt_cfg.get("max_scans_per_day", 5))
        self.alert_on = [str(s).upper() for s in hunt_cfg.get("alert_on", ["P1", "P2"])]
        self.vdp_strategy = str(hunt_cfg.get("vdp_strategy", "light_scan"))
        self.bb_strategy = str(hunt_cfg.get("bb_strategy", "quick-scan"))
        self._runs_today: list[str] = []

    def fetch_new_programs(self) -> list[dict[str, Any]]:
        """Fetch + merge new programs from both platforms."""
        h1 = fetch_hackerone_programs(
            self.cfg.env.get("HACKERONE_API_USERNAME", ""),
            self.cfg.env.get("HACKERONE_API_TOKEN", ""),
        )
        bc = fetch_bugcrowd_programs(self.cfg.env.get("BUGCROWD_API_KEY", ""))
        ig = fetch_intigriti_programs(self.cfg.env.get("INTIGRITI_API_KEY", ""))
        yw = fetch_yeswehack_programs(self.cfg.env.get("YESWEHACK_API_KEY", ""))
        programs = h1 + bc + ig + yw
        # BB (paid) prioritized, then VDP.
        programs.sort(key=lambda p: (0 if p.get("type") == "bb" else 1, p.get("name", "")))
        logger.info("hunt: fetched %d new programs (bb-first)", len(programs))
        return programs

    def plan_scans(self, programs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Select programs to scan within the daily budget."""
        budget = max(0, self.max_per_day - len(self._runs_today))
        planned: list[dict[str, Any]] = []
        for p in programs:
            if len(planned) >= budget:
                break
            ptype = p.get("type", "vdp")
            strategy = self.bb_strategy if ptype == "bb" else self.vdp_strategy
            planned.append({
                "name": p.get("name", ""),
                "platform": p.get("platform", ""),
                "type": ptype,
                "strategy": strategy,
                "in_scope": p.get("in_scope", []),
            })
        return planned

    def record_run(self, program_name: str) -> None:
        """Record a scan run against today's budget."""
        stamp = _today()
        self._runs_today = [r for r in self._runs_today if r.startswith(stamp)]
        self._runs_today.append(f"{stamp}:{program_name}")

    def should_alert(self, severity: str) -> bool:
        return str(severity).upper() in self.alert_on


def run_hunt(cfg: Config, results_base: Path, scan_runner=None) -> dict[str, Any]:
    """Run the HUNT phase; returns a summary. Requires hunt.enabled."""
    hunter = AutoHunter(cfg)
    if not hunter.enabled:
        return {"status": "disabled", "reason": "hunt phase is OFF by default"}

    programs = hunter.fetch_new_programs()
    planned = hunter.plan_scans(programs)

    outcomes: list[dict[str, Any]] = []
    for plan in planned:
        if scan_runner is not None:
            try:
                outcome = scan_runner(plan)
                outcomes.append({"program": plan["name"], "result": outcome})
            except Exception as exc:
                outcomes.append({"program": plan["name"], "error": str(exc)})
        hunter.record_run(plan["name"])

    summary = {
        "status": "ok",
        "programs_fetched": len(programs),
        "scans_planned": len(planned),
        "outcomes": outcomes,
        "runs_today": len(hunter._runs_today),
    }
    logger.info("hunt complete: %s", {k: v for k, v in summary.items() if k != "outcomes"})
    return summary
