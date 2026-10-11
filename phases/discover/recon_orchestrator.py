"""DISCOVER phase orchestrator.

Coordinates Pegpon (15 light tools), the multi-engine dorker, Wappalyzer
tech detection, and BBot (deep scan only, after pegpon). Writes all recon
artifacts under the scan's ``recon/`` directory and returns a summary.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lib.config import Config, TargetConfig
from lib.logger import get_logger
from lib.scope_validator import validate_target_scope
from phases.discover.bbot_wrapper import run_bbot
from phases.discover.dorker import Dorker
from phases.discover.pegpon_wrapper import run_pegpon
from phases.discover.wappalyzer_wrapper import WappalyzerWrapper
from phases.probe.tool_runner import ToolRunner

logger = get_logger("discover_orchestrator")


def pipeline_surface_count(db: Any, scan_id: int | None) -> int:
    """Best-effort asset count for the summary (never raises)."""
    try:
        return len(db.list_assets(scan_id=scan_id))
    except Exception:  # pragma: no cover
        return 0


def run_discover(
    cfg: Config,
    target_config: TargetConfig,
    results_dir: Path,
    deep: bool = False,
    with_subdomains: bool = True,
    dorking: bool = True,
    github_token: str = "",
    db: Any | None = None,
    scan_id: int | None = None,
) -> dict[str, Any]:
    """Run the DISCOVER phase; returns the recon summary.

    ``db``/``scan_id`` enable attack-surface graph ingestion; when absent
    the phase behaves exactly as before (backward compatible).
    """
    domain = target_config.domain
    validate_target_scope(domain, target_config)  # hard scope gate

    # GitHub token: explicit argument wins, else GITHUB_TOKEN from .keys.env.
    gh_token = github_token or cfg.env.get("GITHUB_TOKEN", "")

    runner = ToolRunner(
        timeout=cfg.tool_timeout(),
        deep_mode=deep,
        results_dir=results_dir,
        rate_limit=target_config.rate_limit,
        rate_key=domain,
        cfg=cfg,
    )

    summary: dict[str, Any] = {"domain": domain, "deep": deep}

    # 1. Pegpon light set (always).
    pegpon = run_pegpon(domain, runner, results_dir, with_subdomains=with_subdomains)
    summary["pegpon"] = pegpon

    # 2. Multi-engine dorking (default on).
    dork_summary: dict[str, Any] = {"disabled": True}
    if dorking:
        try:
            dorker = Dorker()
            # Configured engines only (scraping engines are OFF by default).
            engines = [str(e) for e in (cfg.scanning or {}).get("dorking_engines") or []] or None
            if engines:
                dork_summary = dorker.run(domain, github_token=gh_token, engines=engines)
            else:
                dork_summary = dorker.run(domain, github_token=gh_token)
        except Exception as exc:  # dorking must never fail the phase
            dork_summary = {"error": str(exc)}
    summary["dorking"] = dork_summary

    # 3. Wappalyzer tech detection.
    tech: dict[str, Any] = {"tech": {}}
    try:
        wapp = WappalyzerWrapper()
        tech = wapp.detect(f"https://{domain}")
    except Exception as exc:
        tech = {"error": str(exc)}
    summary["wappalyzer"] = tech

    # 4. BBot (deep scan only, requires pegpon).
    bbot: dict[str, Any] = {"status": "skipped", "reason": "light scan"}
    if deep:
        bbot = run_bbot(domain, runner, results_dir)
    summary["bbot"] = bbot

    # Tool-registry view for this run (Pass 3A): truthful selection and
    # per-tool availability — unavailable tools are reported, never faked.
    try:
        from lib.tool_registry import get_registry

        reg = get_registry()
        selection = reg.resolve(
            intensity="full-scan" if deep else "quick-scan",
            cfg=cfg,
            phase="discover",
        )
        summary["tool_registry"] = {
            "selected": [e.name for e in selection],
            "availability": {
                e.name: reg.availability(e, cfg) for e in reg.by_phase("discover")
            },
        }
    except Exception:  # registry visibility must never fail the phase
        logger.debug("tool registry summary failed", exc_info=True)

    # Persist the recon summary.
    recon_dir = results_dir / "recon"
    recon_dir.mkdir(parents=True, exist_ok=True)
    (recon_dir / "tech_stack.json").write_text(
        json.dumps(tech, indent=2, default=str), encoding="utf-8"
    )
    (recon_dir / "dorking.json").write_text(
        json.dumps(dork_summary, indent=2, default=str), encoding="utf-8"
    )
    (recon_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8"
    )

    urls = list(pegpon.get("urls", []))
    dork_urls = dork_summary.get("by_intent", {}) if isinstance(dork_summary, dict) else {}
    for u_list in (dork_urls or {}).values():
        urls.extend(u_list)
    summary["urls"] = sorted(set(urls))

    # Filtration pipeline + attack-surface graph ingestion.
    # Every tool's output is normalized, scope-validated, deduplicated and
    # recorded with provenance; per-tool unique yield is measured.
    try:
        from lib.filtration import FiltrationPipeline

        pipeline = FiltrationPipeline(db, target_config, scan_id=scan_id)
        filtration: list[dict[str, Any]] = []
        filtration.append(pipeline.ingest("pegpon", "discover",
                                          pegpon.get("subdomains", []), kind="subdomain").to_dict())
        filtration.append(pipeline.ingest("dorker", "discover",
                                          # Flatten {intent: [urls]} → urls
                                          # (the audit's dorking-ingestion bug:
                                          # `list(dict)` iterated intent keys).
                                          [u for _iu in (dork_urls or {}).values()
                                           for u in _iu], kind="url").to_dict())
        pipeline.link_domain_assets(domain, tool="dnsx")
        summary["filtration"] = filtration
        summary["graph"] = {"assets": pipeline_surface_count(db, scan_id)}
    except Exception as exc:  # filtration must never fail the phase
        logger.debug("filtration failed (non-fatal): %s", exc)
        summary["filtration"] = {"error": str(exc)}

    logger.info(
        "discover complete: %d subdomains, %d urls, tech=%s",
        len(pegpon.get("subdomains", [])),
        len(summary["urls"]),
        ",".join((tech.get("tech") or {}).keys()) or "none",
    )
    return summary
