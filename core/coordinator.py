"""Main scan coordinator (core orchestrator).

Runs the DISCOVER → PROBE → ANALYZE pipeline for a single target,
supports checkpoint-based resume, batch mode (sequential/concurrent),
scheduling (croniter), scan diffing, and manual finding verification.

Modules are imported as modules (not functions) so the phase
implementations stay monkey-patchable in tests.
"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core import database as database_mod
from core import reporter as reporter_mod
from core.database import Database
from lib.config import CONFIG_DIR, Config, TargetConfig
from lib.false_positive_filter import FalsePositiveFilter
from lib.logger import get_logger
from lib.paths import RESULTS_BASE
from lib.ops_guard import KillSwitch
from lib.scope_validator import validate_target_scope
from lib.utils import create_results_tree, scan_folder_name, utc_timestamp
from phases.analyze import analyze_orchestrator
from phases.discover import recon_orchestrator
from phases.probe import probe_orchestrator
from phases.verify import verify_orchestrator

logger = get_logger("coordinator")

PHASES_IN_ORDER = ("discover", "probe", "analyze")


@dataclass
class ScanOptions:
    """Options for a single scan run."""

    target: str
    intensity: str = "quick-scan"
    discover_only: bool = False
    scan_only: bool = False
    with_subdomains: bool = True
    dorking: bool = True
    include_cdn: bool = False
    test_bypass: bool = False
    custom_fuzzing: bool = False
    skip_tools: list[str] = field(default_factory=list)
    run_tools: list[str] = field(default_factory=list)
    cookie: str = ""
    methodology: str = ""
    rate_limit: str = ""
    screenshots: bool = False
    delta: bool = False
    parallel_tools: int = 1
    min_severity: str = ""
    exclude: list[str] = field(default_factory=list)
    exclude_p4: bool = False
    resume_scan_id: int | None = None
    platform: str = "generic"
    program_type: str = "bb"
    scope_kind: str = "public"
    cve_id: str = ""

    @property
    def deep(self) -> bool:
        return self.intensity == "full-scan"


class Coordinator:
    """Runs scans and related operations."""

    def __init__(self, cfg: Config, db: Database | None = None, results_base: Path | None = None):
        self.cfg = cfg
        self.db = db or Database(cfg.database_path)
        self.results_base = results_base or RESULTS_BASE

    # -- target resolution --------------------------------------------------

    def resolve_target(self, options: ScanOptions) -> TargetConfig:
        """Build a TargetConfig, applying CLI overrides over config defaults."""
        tc = self.cfg.target(options.target)
        if options.intensity:
            tc.intensity = options.intensity
        if options.cookie:
            tc.cookie = options.cookie
        if options.rate_limit:
            tc.rate_limit = options.rate_limit
        if options.platform:
            tc.platform = options.platform
        if options.program_type:
            tc.program_type = options.program_type
        if options.scope_kind:
            tc.scope_kind = options.scope_kind
        return tc

    # -- single scan --------------------------------------------------------

    def run_scan(self, options: ScanOptions) -> dict[str, Any]:
        """Execute a full scan for one target; returns the run summary."""
        started = time.monotonic()
        target_config = self.resolve_target(options)
        domain = target_config.domain

        # Hard scope gate before any traffic.
        validate_target_scope(domain, target_config)

        # Global kill-switch gate (roadmap H2).
        killswitch = KillSwitch(self.results_base)
        if killswitch.killed():
            summary = {"target": domain, "status": "killed", "error": "kill-switch engaged"}
            logger.warning("scan aborted: kill-switch engaged")
            return summary

        target_id = self.db.upsert_target(
            domain=domain,
            platform=target_config.platform,
            program_type=target_config.program_type,
            scope_kind=target_config.scope_kind,
            in_scope=target_config.in_scope,
            out_of_scope=target_config.out_of_scope,
            config=target_config.to_dict(),
        )

        folder = scan_folder_name(
            domain, target_config.platform, target_config.program_type, target_config.scope_kind
        )
        results_dir = create_results_tree(self.results_base, folder)

        scan_id = self.db.create_scan(target_id, intensity=target_config.intensity)
        checkpoint: dict[str, Any] = {"phases_done": [], "probe_steps": []}
        if options.resume_scan_id is not None:
            prior = self.db.get_scan(options.resume_scan_id)
            if prior and prior.get("checkpoint"):
                try:
                    checkpoint = json.loads(prior["checkpoint"])
                except (json.JSONDecodeError, TypeError):
                    pass
            scan_id = options.resume_scan_id

        self.db.update_scan(scan_id, checkpoint=json.dumps(checkpoint))

        summary: dict[str, Any] = {
            "target": domain,
            "scan_id": scan_id,
            "results_dir": str(results_dir),
            "intensity": target_config.intensity,
            "phases": {},
        }

        try:
            # --- Phase 1: DISCOVER ---
            recon: dict[str, Any] = {"urls": [], "pegpon": {}, "wappalyzer": {"tech": {}}}
            if "discover" in checkpoint.get("phases_done", []) and options.resume_scan_id:
                recon_file = results_dir / "recon" / "summary.json"
                if recon_file.exists():
                    recon = json.loads(recon_file.read_text(encoding="utf-8"))
            elif options.scan_only:
                recon = self._load_cached_recon(results_dir)
            else:
                recon = recon_orchestrator.run_discover(
                    self.cfg,
                    target_config,
                    results_dir,
                    deep=options.deep,
                    with_subdomains=options.with_subdomains,
                    dorking=options.dorking,
                )
                checkpoint["phases_done"] = list(set(checkpoint.get("phases_done", []) + ["discover"]))
                self.db.update_scan(scan_id, checkpoint=json.dumps(checkpoint))
            urls = list(recon.get("urls", []))
            tech = (recon.get("wappalyzer") or {}).get("tech", {}) or {}

            # --- Delta scanning (roadmap D6): only new URLs when requested ---
            if options.delta:
                from lib.delta import ReconState, compute_delta, filter_new_urls

                state = ReconState(self.results_base, domain)
                prev = state.load()
                cur_state = {
                    "subdomains": (recon.get("pegpon") or {}).get("subdomains", []),
                    "urls": urls,
                }
                delta = compute_delta(prev, cur_state)
                urls = filter_new_urls(urls, prev.get("urls", [])) if prev.get("urls") else urls
                state.save(cur_state)
                summary["delta"] = delta
            summary["phases"]["discover"] = {
                "subdomains": len((recon.get("pegpon") or {}).get("subdomains", [])),
                "urls": len(urls),
                "tech": sorted(tech.keys()),
            }

            if options.discover_only:
                self.db.update_scan(scan_id, status="completed", duration_seconds=int(time.monotonic() - started))
                summary["status"] = "discover-only"
                return summary

            # --- Phase 2: PROBE ---
            raw_findings: list[dict[str, Any]] = []
            if "probe" in checkpoint.get("phases_done", []) and options.resume_scan_id:
                raw_file = results_dir / "scans" / "raw_findings.json"
                if raw_file.exists():
                    raw_findings = json.loads(raw_file.read_text(encoding="utf-8"))
            else:
                raw_findings = probe_orchestrator.run_probe(
                    self.cfg,
                    target_config,
                    results_dir,
                    urls=urls,
                    tech=tech,
                    deep=options.deep,
                    skip_tools=options.skip_tools,
                    run_only=options.run_tools,
                    checkpoint=checkpoint,
                    screenshots=options.screenshots,
                    parallel_tools=options.parallel_tools,
                )
                checkpoint["phases_done"] = list(set(checkpoint.get("phases_done", []) + ["probe"]))
                self.db.update_scan(scan_id, checkpoint=json.dumps(checkpoint))
            summary["phases"]["probe"] = {"raw_findings": len(raw_findings)}

            # --- Phase 2b: VERIFY (deterministic confirmation, roadmap A1) ---
            if "verify" not in checkpoint.get("phases_done", []) or not options.resume_scan_id:
                raw_findings, verify_summary = verify_orchestrator.run_verify(raw_findings)
                checkpoint["phases_done"] = list(set(checkpoint.get("phases_done", []) + ["verify"]))
                self.db.update_scan(scan_id, checkpoint=json.dumps(checkpoint))
            else:
                verify_summary = {"skipped": True}
            summary["phases"]["verify"] = verify_summary

            # --- Phase 3: ANALYZE ---
            metrics = analyze_orchestrator.run_analyze(
                self.cfg,
                self.db,
                target_config,
                raw_findings,
                scan_id,
                results_dir,
                urls_discovered=len(urls),
                endpoints_tested=len(urls),
                duration_seconds=int(time.monotonic() - started),
                min_severity=options.min_severity,
                exclude=options.exclude,
                exclude_p4=options.exclude_p4,
            )
            summary["phases"]["analyze"] = {
                "findings_total": metrics.get("findings_total", 0),
                "findings_valid": metrics.get("findings_valid", 0),
                "chains": metrics.get("chains_detected", 0),
            }

            # --- Reporting ---
            findings = self._load_processed(results_dir, "findings.json")
            chains = self._load_processed(results_dir, "chains.json")
            report_path = reporter_mod.write_report(
                results_dir,
                domain,
                target_config.platform,
                target_config.program_type,
                target_config.scope_kind,
                metrics,
                findings,
                chains,
            )
            summary["report"] = str(report_path)

            # --- Notifications (best-effort) ---
            summary["alerts"] = self._notify_summary(metrics, findings)

            # --- Post-scan intel (methodology drift + new tech, roadmap G5/J3) ---
            tools_run = list((recon.get("pegpon") or {}).get("tools_run", [])) + list(checkpoint.get("probe_steps", []))
            summary["intel"] = self._post_scan_intel(options, results_dir, domain, tech, tools_run)

            self.db.update_scan(
                scan_id,
                status="completed",
                duration_seconds=int(time.monotonic() - started),
            )
            summary["status"] = "completed"
            summary["metrics"] = metrics
            logger.info("scan %s complete: %s", domain, summary["phases"]["analyze"])
            return summary

        except KeyboardInterrupt:
            self.db.update_scan(scan_id, status="interrupted", checkpoint=json.dumps(checkpoint))
            raise
        except Exception as exc:
            self.db.update_scan(scan_id, status="failed", checkpoint=json.dumps(checkpoint))
            summary["status"] = "failed"
            summary["error"] = str(exc)
            logger.error("scan failed: %s", exc)
            return summary

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _load_processed(results_dir: Path, name: str) -> list[dict[str, Any]]:
        path = results_dir / "processed" / name
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except (json.JSONDecodeError, OSError):
            return []

    @staticmethod
    def _load_cached_recon(results_dir: Path) -> dict[str, Any]:
        recon_file = results_dir / "recon" / "summary.json"
        if recon_file.exists():
            try:
                return json.loads(recon_file.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return {"urls": [], "wappalyzer": {"tech": {}}, "pegpon": {}}

    def _post_scan_intel(
        self,
        options: ScanOptions,
        results_dir: Path,
        domain: str,
        tech: dict[str, str],
        tools_run: list[str],
    ) -> dict[str, Any]:
        """Methodology coverage/drift + new-tech detection, with alerts."""
        from lib import methodology as methodology_mod
        from lib.notifications import Notifier

        intel: dict[str, Any] = {"methodology": None, "new_tech": []}

        # 1. Methodology coverage + drift (features 46/47/80, roadmap J3).
        if options.methodology:
            try:
                methods = methodology_mod.load_methodologies()
                method = (methods.get("methodologies") or {}).get(options.methodology)
                if method:
                    cov = methodology_mod.coverage(method, tools_run)
                    mhash = methodology_mod.methodology_hash(method)
                    state_path = self.results_base / ".methodology_state.json"
                    prev_hash = ""
                    if state_path.exists():
                        try:
                            prev_hash = str(json.loads(state_path.read_text(encoding="utf-8")).get("hash", ""))
                        except (json.JSONDecodeError, OSError):
                            prev_hash = ""
                    drifted = bool(prev_hash and prev_hash != mhash)
                    intel["methodology"] = {
                        "checklist": options.methodology, "hash": mhash,
                        "drift": drifted, "coverage": cov,
                    }
                    state_path.parent.mkdir(parents=True, exist_ok=True)
                    state_path.write_text(json.dumps({"hash": mhash, "domain": domain}, indent=2), encoding="utf-8")
                    metrics_path = results_dir / "processed" / "metrics.json"
                    try:
                        if metrics_path.exists():
                            md = json.loads(metrics_path.read_text(encoding="utf-8"))
                            md["methodology_hash"] = mhash
                            md["methodology_coverage"] = cov
                            metrics_path.write_text(json.dumps(md, indent=2, default=str), encoding="utf-8")
                    except (json.JSONDecodeError, OSError):
                        pass
                    if drifted:
                        notifier = Notifier(self.cfg)
                        notifier.send_info_alert(
                            f"Methodology changed ({options.methodology})",
                            f"Checklist hash {prev_hash} → {mhash} during scan of {domain}. "
                            f"Coverage {cov['items_covered']}/{cov['items_total']} ({cov['percent']}%).",
                        )
                        notifier.send_info_telegram(
                            f"NEXUS: methodology changed ({options.methodology})",
                            f"hash {prev_hash} → {mhash}; coverage {cov['percent']}% on {domain}",
                        )
            except Exception as exc:  # intel must never fail the scan
                logger.debug("methodology intel failed: %s", exc)

        # 2. New-tech detection (CVE re-matching trigger).
        try:
            state_path = self.results_base / ".tech_state.json"
            prev_tech: dict[str, str] = {}
            if state_path.exists():
                try:
                    prev_tech = json.loads(state_path.read_text(encoding="utf-8")).get("tech", {}) or {}
                except (json.JSONDecodeError, OSError):
                    prev_tech = {}
            prev_lower = {k.lower() for k in prev_tech}
            current = {str(k): str(v or "") for k, v in (tech or {}).items()}
            new_keys = [k for k in current if k.lower() not in prev_lower]
            intel["new_tech"] = new_keys
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(json.dumps({"tech": current, "domain": domain}, indent=2), encoding="utf-8")
            if new_keys and prev_tech:
                notifier = Notifier(self.cfg)
                body = f"New technology detected on {domain}: {', '.join(new_keys)}"
                notifier.send_info_alert("New tech in stack", body)
                notifier.send_info_telegram("NEXUS: new tech detected", body)
        except Exception as exc:
            logger.debug("tech intel failed: %s", exc)

        return intel

    def _notify_summary(self, metrics: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Send P1/P2 alerts + metrics summary (best-effort, mocked in tests)."""
        from lib.notifications import Notifier

        notifier = Notifier(self.cfg)
        sent = 0
        for f in findings:
            if str(f.get("severity")) in ("P1", "P2") and f.get("valid") is not False:
                if notifier.send_finding(f):
                    sent += 1
        metrics_sent = notifier.send_metrics({
            "target": metrics.get("target", ""),
            "findings_total": metrics.get("findings_total", 0),
            "findings_valid": metrics.get("findings_valid", 0),
        })
        return {"finding_alerts_sent": sent, "metrics_sent": bool(metrics_sent)}

    # -- batch --------------------------------------------------------------

    def run_batch(
        self,
        targets: list[str],
        options_factory,
        concurrent: int = 1,
        sequential: bool = True,
    ) -> list[dict[str, Any]]:
        """Run scans for multiple targets (sequential or concurrent)."""
        results: list[dict[str, Any]] = []
        if sequential or concurrent <= 1:
            for t in targets:
                results.append(self.run_scan(options_factory(t)))
            return results

        with ThreadPoolExecutor(max_workers=concurrent) as pool:
            futures = {pool.submit(self.run_scan, options_factory(t)): t for t in targets}
            for fut in as_completed(futures):
                target = futures[fut]
                try:
                    results.append(fut.result())
                except Exception as exc:  # keep the batch alive
                    results.append({"target": target, "status": "failed", "error": str(exc)})
        return results

    # -- scheduling ---------------------------------------------------------

    def due_schedules(self, now: datetime | None = None) -> list[dict[str, Any]]:
        """Return schedules whose next_run is due."""
        from croniter import croniter

        now = now or datetime.now(timezone.utc)
        due: list[dict[str, Any]] = []
        for sched in self.db.list_schedules(enabled_only=True):
            next_run = sched.get("next_run")
            if not next_run:
                due.append(sched)
                continue
            try:
                nxt = datetime.fromisoformat(str(next_run))
            except ValueError:
                due.append(sched)
                continue
            if nxt.tzinfo is None:
                nxt = nxt.replace(tzinfo=timezone.utc)
            if nxt <= now:
                due.append(sched)
        return due

    def compute_next_run(self, cron_expression: str, base: datetime | None = None) -> str:
        """Compute the next run ISO timestamp for a cron expression."""
        from croniter import croniter

        base = base or datetime.now(timezone.utc)
        itr = croniter(cron_expression, base)
        return itr.get_next(datetime).isoformat(timespec="seconds")

    def run_schedule(self, schedule_name: str) -> dict[str, Any]:
        """Run a named schedule once and advance its next_run."""
        rows = [s for s in self.db.list_schedules() if s.get("name") == schedule_name]
        if not rows:
            return {"status": "not_found", "schedule": schedule_name}
        sched = rows[0]
        target_row = None
        for t in self.db.list_targets():
            if t["id"] == sched["target_id"]:
                target_row = t
                break
        if target_row is None:
            return {"status": "target_missing", "schedule": schedule_name}

        options = ScanOptions(
            target=target_row["domain"],
            intensity=sched.get("intensity") or "quick-scan",
        )
        result = self.run_scan(options)
        expr = sched.get("cron_expression") or "0 2 * * *"
        self.db.mark_schedule_run(
            sched["id"], last_run=utc_timestamp(), next_run=self.compute_next_run(expr)
        )
        return {"status": "ran", "schedule": schedule_name, "result": result}

    # -- diff / verify ------------------------------------------------------

    def diff_scans(self, scan_id_a: int, scan_id_b: int) -> dict[str, Any]:
        """Compare two scans: new / resolved / unchanged findings."""
        a = {(f["endpoint"], f["vuln_type"], f["severity"]) for f in self.db.query_findings(scan_id=scan_id_a)}
        b = {(f["endpoint"], f["vuln_type"], f["severity"]) for f in self.db.query_findings(scan_id=scan_id_b)}
        return {
            "scan_a": scan_id_a,
            "scan_b": scan_id_b,
            "new": sorted(b - a),
            "resolved": sorted(a - b),
            "unchanged": sorted(a & b),
        }

    def verify_finding(self, finding_id: int) -> dict[str, Any]:
        """Mark a finding as manually verified/reviewed."""
        rows = self.db.query("SELECT * FROM findings WHERE id = ?", (finding_id,))
        if not rows:
            return {"status": "not_found", "finding_id": finding_id}
        self.db.mark_finding_reviewed(finding_id, True)
        self.db.mark_finding_validity(finding_id, True)
        return {"status": "verified", "finding_id": finding_id}
