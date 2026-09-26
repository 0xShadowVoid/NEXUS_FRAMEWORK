"""PROBE phase orchestrator.

Coordinates Phase 2 scanning with smart tool selection, mode-dependent
failure handling (light: skip+continue; deep: retry ×3 then skip),
heavy-tool gating via the status detector, and checkpoint-based resume.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from lib.config import Config, TargetConfig
from lib.logger import get_logger
from lib.logic_detector import detect_logic_flaws
from lib.idor_prober import IdorProber
from phases.probe.dalfox_runner import run_dalfox
from phases.probe.nuclei_orchestrator import run_nuclei
from phases.probe.sqlmap_runner import run_sqlmap
from phases.probe.tool_runner import ToolRunner
from phases.probe.tool_runners import run_all_deep, run_all_light, run_all_light_parallel

logger = get_logger("probe_orchestrator")


def run_probe(
    cfg: Config,
    target_config: TargetConfig,
    results_dir: Path,
    urls: list[str],
    tech: dict[str, str],
    deep: bool = False,
    skip_tools: list[str] | None = None,
    run_only: list[str] | None = None,
    user_chosen_endpoints: list[str] | None = None,
    responses: list[dict[str, Any]] | None = None,
    checkpoint: dict[str, Any] | None = None,
    screenshots: bool = False,
    http_get=None,
    parallel_tools: int = 1,
) -> list[dict[str, Any]]:
    """Run the PROBE phase; returns raw findings.

    ``responses`` are pre-collected HTTP responses ({url, status_code,
    body}) used for heavy-tool gating; when absent, heavy tools are
    skipped entirely (boundary-safe default).
    """
    responses = responses or []
    skip = set(skip_tools or [])
    only = set(run_only or [])
    done_steps = set((checkpoint or {}).get("probe_steps", []))
    runner = ToolRunner(
        timeout=cfg.tool_timeout(),
        deep_mode=deep,
        results_dir=results_dir,
    )

    raw_findings: list[dict[str, Any]] = []
    target = target_config.domain

    def allowed(tool: str) -> bool:
        if tool in skip:
            return False
        if only and tool not in only:
            return False
        return True

    # 1. nuclei (smart templates).
    if "nuclei" not in done_steps and allowed("nuclei"):
        raw_findings.extend(run_nuclei(target, urls, tech, runner, results_dir))
        done_steps.add("nuclei")

    # 2. dalfox (XSS).
    if "dalfox" not in done_steps and allowed("dalfox"):
        raw_findings.extend(run_dalfox(target, urls, runner, results_dir, cookie=target_config.cookie))
        done_steps.add("dalfox")

    # 3. Light tool set.
    if "light_set" not in done_steps and not only:
        if parallel_tools > 1:
            raw_findings.extend(run_all_light_parallel(target, urls, runner, max_workers=parallel_tools))
        else:
            raw_findings.extend(run_all_light(target, urls, runner))
        done_steps.add("light_set")

    # 3b. Business-logic + IDOR detection (read-only, roadmap J1/J2).
    if "logic_idor" not in done_steps and not only:
        raw_findings.extend(detect_logic_flaws(urls))
        if http_get is not None:
            raw_findings.extend(IdorProber(fetch=http_get).probe_many(urls))
        done_steps.add("logic_idor")

    # 4. Deep tool set (only in full-scan).
    if deep and "deep_set" not in done_steps and not only:
        raw_findings.extend(run_all_deep(target, urls, responses, runner, cookie=target_config.cookie))
        done_steps.add("deep_set")

    # 5. sqlmap (heavy, gated).
    if "sqlmap" not in done_steps and allowed("sqlmap"):
        raw_findings.extend(run_sqlmap(
            target, responses, runner, results_dir,
            deep=deep,
            user_chosen=user_chosen_endpoints,
            cookie=target_config.cookie,
        ))
        done_steps.add("sqlmap")

    # 6. Optional screenshot capture (feature 32).
    if screenshots and urls:
        from lib.screenshot import capture_batch

        capture_batch(urls, target, results_dir / "screenshots", runner)

    # Persist raw findings + checkpoint.
    scans_dir = results_dir / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    (scans_dir / "raw_findings.json").write_text(
        json.dumps(raw_findings, indent=2, default=str), encoding="utf-8"
    )
    (scans_dir / "checkpoint.json").write_text(
        json.dumps({"probe_steps": sorted(done_steps)}, indent=2), encoding="utf-8"
    )
    logger.info("probe complete: %d raw findings (deep=%s)", len(raw_findings), deep)
    return raw_findings
