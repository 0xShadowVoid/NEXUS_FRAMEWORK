"""CVE workflow orchestration (fetch → match → generate → register → alert)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core.database import Database
from lib.config import Config
from lib.cve_fetcher import CVEFetcher, match_tech
from lib.cve_poc_generator import generate_all, register_nuclei_template
from lib.logger import get_logger
from lib.notifications import EmailAlerter, Notifier
from lib import threat_feeds

logger = get_logger("cve_workflow")


def run_cve_update(
    cfg: Config,
    db: Database,
    tech_stack: dict[str, str] | list[str] | None = None,
    hours: int = 24,
    generate_pocs: bool = True,
    notify: bool = True,
    poc_base: Path | None = None,
) -> dict[str, Any]:
    """Fetch, match, generate PoCs, register templates and alert.

    Returns a summary: {'fetched', 'matched', 'pocs_generated',
    'templates_registered', 'alerted'}.
    """
    cve_cfg = cfg.cve or {}
    min_severity = "high"
    alert_sev = [str(s).lower() for s in (cve_cfg.get("alert_severity") or ["critical", "high"])]
    if alert_sev:
        min_severity = "critical" if "critical" in alert_sev else "high"

    fetcher = CVEFetcher(api_key=cfg.env.get("NVD_API_KEY", ""))
    cves = fetcher.fetch_recent(hours=hours, min_severity=min_severity)
    logger.info("cve-update: fetched %d cves", len(cves))

    # Threat-intel enrichment (roadmap B1/B2): known-exploited + EPSS priority.
    # Off by default in code; enabled via cve.use_kev / cve.use_epss in nexus.yaml.
    kev_matched = 0
    epss_above = 0
    if (cve_cfg.get("use_kev")
            or cve_cfg.get("use_epss")):
        try:
            cves = threat_feeds.enrich_cves(cves)
            kev_matched = sum(1 for c in cves if c.get("kev"))
            epss_above = threat_feeds.epss_interesting_count(cves)
        except Exception as exc:  # enrichment must never fail the workflow
            logger.warning("threat-feed enrichment failed: %s", exc)

    matches: list[tuple[dict[str, Any], list[str]]] = []
    if tech_stack:
        matches = match_tech(cves, tech_stack)
    else:
        # No tech context → treat all fetched CVEs as candidates.
        matches = [(c, []) for c in cves]

    # Known-exploited first, then highest EPSS (roadmap B1/B2).
    matches.sort(key=lambda pair: (int(pair[0].get("priority", 1)), -float(pair[0].get("epss", 0.0))))

    generated = 0
    registered = 0
    alerted = 0
    notifier = Notifier(cfg) if notify else None
    emailer = EmailAlerter(cfg) if notify else None

    for cve, techs in matches:
        cve_id = str(cve.get("cve_id", ""))
        if not cve_id:
            continue
        row_id, created = db.get_or_create_cve(
            cve_id=cve_id,
            severity=str(cve.get("severity", "")),
            description=str(cve.get("description", ""))[:2000],
            published=str(cve.get("published", "")),
            tech_matched=",".join(techs),
        )
        if not created:
            continue  # already known — dedup guard

        cve["tech_matched"] = ", ".join(techs)

        if generate_pocs:
            cve["target_url"] = cve.get("target_url", "https://TARGET_HOST/")
            artifacts = generate_all(cve, base_dir=poc_base)
            generated += 1
            db.mark_cve_poc_generated(row_id)
            nuclei = artifacts.get("nuclei")
            if nuclei:
                register_nuclei_template(nuclei)
                registered += 1
            if emailer is not None:
                attachments = [
                    (p.name, p.read_bytes()) for p in artifacts.values() if p.exists()
                ]
                emailer.send(
                    subject=f"[NEXUS] {cve_id} detection PoC ({cve.get('severity', '')})",
                    body=(
                        f"New CVE matched to your stack: {cve_id}\n"
                        f"Severity: {cve.get('severity')}\n"
                        f"Affected: {cve.get('tech_matched')}\n\n"
                        f"{cve.get('description', '')[:1500]}\n\n"
                        "Attached: detection-only PoC scripts (.py/.js/.sh) + nuclei template."
                    ),
                    attachments=attachments,
                )

        if notifier is not None:
            notifier.send_cve(cve)
            notifier.send_cve_telegram(cve)
            db.mark_cve_alerted(row_id)
            alerted += 1

    summary = {
        "fetched": len(cves),
        "matched": len(matches),
        "new": sum(1 for _c, _t in matches),
        "pocs_generated": generated,
        "templates_registered": registered,
        "alerted": alerted,
        "kev_matched": kev_matched,
        "epss_above_0_5": epss_above,
    }
    logger.info("cve-update complete: %s", summary)
    return summary


def run_cve_scan(
    cfg: Config,
    db: Database,
    target: str,
    tech_stack: dict[str, str] | list[str] | None = None,
    cve_id: str = "",
    critical_only: bool = False,
    hours: int = 24 * 30,
) -> dict[str, Any]:
    """Scan a target's tech stack for known CVEs (optionally one CVE)."""
    fetcher = CVEFetcher(api_key=cfg.env.get("NVD_API_KEY", ""))
    min_sev = "critical" if critical_only else "high"
    cves = fetcher.fetch_recent(hours=hours, min_severity=min_sev)

    if cve_id:
        cves = [c for c in cves if str(c.get("cve_id", "")).upper() == cve_id.upper()]

    matches = match_tech(cves, tech_stack) if tech_stack else [(c, []) for c in cves]

    results: list[dict[str, Any]] = []
    for cve, techs in matches:
        cve_id_found = str(cve.get("cve_id", ""))
        results.append({
            "cve_id": cve_id_found,
            "severity": cve.get("severity"),
            "tech_matched": techs,
            "description": str(cve.get("description", ""))[:300],
        })
        db.get_or_create_cve(
            cve_id=cve_id_found,
            severity=str(cve.get("severity", "")),
            description=str(cve.get("description", ""))[:2000],
            published=str(cve.get("published", "")),
            tech_matched=",".join(techs),
        )

    return {"target": target, "candidates": len(cves), "matches": results}
