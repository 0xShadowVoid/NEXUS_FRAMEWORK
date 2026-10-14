"""Main scan coordinator (core orchestrator).

Runs the DISCOVER → PROBE → VERIFY → ANALYZE pipeline for a single target,
plus registry-gated optional cycles (authn / authz / takeover / network /
cloud / intel) dispatched on this same coordinator through
``PhaseRegistry.gate()`` + ``PhaseRegistry.load_runner()`` — never a second
execution engine. Supports checkpoint-based resume, batch mode
(sequential/concurrent),
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
from core import lifecycle as lifecycle_mod
from core import reporter as reporter_mod
from core.database import Database
from lib.config import CONFIG_DIR, Config, TargetConfig
from lib.false_positive_filter import FalsePositiveFilter
from lib.logger import get_logger
from lib.paths import RESULTS_BASE
from lib.ops_guard import KillSwitch, set_request_budget
from lib.scope_validator import validate_target_scope
from lib.utils import create_results_tree, scan_folder_name, utc_timestamp
from phases.analyze import analyze_orchestrator
from phases.discover import recon_orchestrator
from phases.probe import probe_orchestrator
from phases.verify import verify_orchestrator

logger = get_logger("coordinator")

PHASES_IN_ORDER = ("discover", "probe", "analyze")


def cfg_probe_budget(cfg: Any) -> int:
    """Per-scan HTTP probe budget (0/unset = framework default)."""
    try:
        return int((cfg.scanning or {}).get("probe_max_urls") or 0) or 50
    except (TypeError, ValueError):  # pragma: no cover
        return 50


def _make_http_get(collector: Any) -> Any:
    """Adapter: collector.fetch → probe_orchestrator's ``http_get(url)`` hook."""

    def _get(url: str) -> str:
        return collector.fetch(url).body

    return _get


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

        # Process-wide request budget (0/unset = unlimited).
        budget = int((self.cfg.scanning or {}).get("request_budget") or 0)
        set_request_budget(budget or None)

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

        # Phase lifecycle: every phase gets a state machine row. The default
        # plan reproduces the historical DISCOVER → PROBE → VERIFY → ANALYZE
        # order; optional cycles are gated and opt-in (see PhaseRegistry).
        from core.phase_registry import (
            BLOCKED,
            PAUSED,
            PhaseRegistry,
            PhaseStateMachine,
            SKIPPED,
        )

        registry = PhaseRegistry().with_optional()
        states: dict[str, PhaseStateMachine] = {
            record.name: PhaseStateMachine.recover(self.db, scan_id, record)
            for record in registry.enabled_phases(self.cfg)
        }
        # Recover interrupted phases on resume (moved to failed by recover()).
        if options.resume_scan_id:
            for name, machine in states.items():
                if machine.state in ("failed",) and name in checkpoint.get("phases_done", []):
                    machine.state = "completed"  # already-done phases stay done

        summary: dict[str, Any] = {
            "target": domain,
            "scan_id": scan_id,
            "results_dir": str(results_dir),
            "intensity": target_config.intensity,
            "phases": {},
            "phase_states": {name: m.state for name, m in states.items()},
        }

        try:
            # --- Phase 1: DISCOVER ---
            recon: dict[str, Any] = {"urls": [], "pegpon": {}, "wappalyzer": {"tech": {}}}
            discover_state = states.get("discover")
            if discover_state is not None and discover_state.state == "completed":
                discover_state = None  # already done on a resumed scan
            if discover_state is not None:
                if options.scan_only:
                    discover_state.skip("scan-only mode")
                    discover_state = None
                else:
                    discover_state.start()
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
                    db=self.db,
                    scan_id=scan_id,
                )
                checkpoint["phases_done"] = list(set(checkpoint.get("phases_done", []) + ["discover"]))
                self.db.update_scan(scan_id, checkpoint=json.dumps(checkpoint))
            urls = list(recon.get("urls", []))
            if discover_state is not None and discover_state.state == "running":
                discover_state.complete(partial=not bool(urls))
            if discover_state is not None and discover_state.state == "skipped":
                summary["phase_states"]["discover"] = "skipped"
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
            responses: list[dict[str, Any]] = []
            # ONE shared read-only collector per scan: PROBE uses it for
            # heavy-tool gating / IDOR / logic probing and the optional gated
            # phases (authz, takeover) reuse the same scope/SSRF/budget-checked
            # HTTP path. Constructing it sends no traffic.
            from lib.http_collector import HttpCollector
            from phases.probe.tool_runner import ToolRunner

            ssrf_allow = {
                str(h).strip().lower()
                for h in (getattr(self.cfg, "scanning", None) or {}).get("ssrf_allow") or []
                if str(h).strip()
            }
            collector = HttpCollector(
                target_config,
                rate_limiter=ToolRunner.shared_rate_limiter(),
                rate_key=domain,
                max_urls=cfg_probe_budget(self.cfg),
                ssrf_allow=ssrf_allow,
            )
            probe_state = states.get("probe")
            if probe_state is not None and probe_state.state == "completed":
                probe_state = None
            elif probe_state is not None:
                probe_state.start()
            if "probe" in checkpoint.get("phases_done", []) and options.resume_scan_id:
                raw_file = results_dir / "scans" / "raw_findings.json"
                if raw_file.exists():
                    raw_findings = json.loads(raw_file.read_text(encoding="utf-8"))
            else:
                # Materialize HTTP responses once so the PROBE phase can do
                # heavy-tool gating, IDOR/logic differential probing and
                # evidence collection. Scope/SSRF/budget-checked, read-only.
                responses = collector.collect(urls)
                summary.setdefault("collector", {}).update(collector.stats)

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
                    responses=responses,
                    http_get=_make_http_get(collector),
                )
                checkpoint["phases_done"] = list(set(checkpoint.get("phases_done", []) + ["probe"]))
                self.db.update_scan(scan_id, checkpoint=json.dumps(checkpoint))
                if probe_state is not None:
                    probe_state.complete(partial=not raw_findings and not urls)
            summary["phases"]["probe"] = {"raw_findings": len(raw_findings)}

            # --- Phase 2b: VERIFY (deterministic confirmation, roadmap A1) ---
            verify_state = states.get("verify")
            if "verify" not in checkpoint.get("phases_done", []) or not options.resume_scan_id:
                if verify_state is not None:
                    verify_state.start()
                raw_findings, verify_summary = verify_orchestrator.run_verify(raw_findings)
                checkpoint["phases_done"] = list(set(checkpoint.get("phases_done", []) + ["verify"]))
                self.db.update_scan(scan_id, checkpoint=json.dumps(checkpoint))
                if verify_state is not None:
                    verify_state.complete()
            else:
                verify_summary = {"skipped": True}
                if verify_state is not None:
                    verify_state.skip("already verified on resumed scan")
            summary["phases"]["verify"] = verify_summary

            # --- Optional gated phases (registry-driven; non-fatal) ---
            # Selection: PhaseRegistry.gate() → load_runner() → PhaseStateMachine
            # on THIS coordinator. Their finding-shaped output merges into
            # raw_findings BEFORE analyze, so dedup/scope/scoring/persistence
            # covers it exactly like legacy findings.
            optional_out, extra_findings = self._run_optional_phases(
                registry=registry,
                states=states,
                options=options,
                target_config=target_config,
                scan_id=scan_id,
                results_dir=results_dir,
                urls=urls,
                responses=responses,
                http_get=_make_http_get(collector),
                tech=tech,
            )
            summary["phases"].update(optional_out)
            if extra_findings:
                raw_findings = list(raw_findings) + list(extra_findings)

            # Filtration for probe/optional outputs (Pass 3A): raw findings
            # pass RAW→…→GRAPH before ANALYZE consumes them, so per-tool
            # unique yield is measured and endpoints land on the graph. This
            # is accounting + ingestion ONLY — it never drops findings (scope
            # filtering of findings stays in ANALYZE, unchanged).
            try:
                from lib.filtration import FiltrationPipeline

                fp = FiltrationPipeline(self.db, target_config, scan_id=scan_id)
                endpoints_by_tool: dict[str, list[str]] = {}
                for f in raw_findings:
                    endpoint = str(f.get("endpoint", "") or "").strip()
                    tool_name = str((f.get("tools_found") or ["unknown"])[0] or "unknown")
                    if endpoint:
                        endpoints_by_tool.setdefault(tool_name, []).append(endpoint)
                probe_stats = [
                    fp.ingest(t, "probe", eps, kind="endpoint").to_dict()
                    for t, eps in sorted(endpoints_by_tool.items())
                ]
                if probe_stats:
                    existing = summary.get("filtration")
                    if isinstance(existing, list):
                        existing.extend(probe_stats)
                    elif existing is None:
                        summary["filtration"] = probe_stats
                    else:
                        summary["filtration"] = [existing, *probe_stats]
            except Exception:  # accounting must never fail the scan
                logger.debug("probe filtration failed (non-fatal)", exc_info=True)

            # --- Phase 3: ANALYZE ---
            analyze_state = states.get("analyze")
            if analyze_state is not None:
                analyze_state.start()
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
            # The registry's "report" phase row reflects the real write above.
            report_state = states.get("report")
            if report_state is not None and report_state.state not in (
                "completed", "failed", "partial"
            ):
                try:
                    try:
                        report_state.start()
                    except Exception:
                        report_state.retry()  # failed/partial on a resumed scan
                    report_state.complete()
                except Exception:  # lifecycle bookkeeping must never fail a scan
                    logger.debug("report phase state update failed", exc_info=True)

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
            if analyze_state is not None:
                analyze_state.complete()
            summary["status"] = "completed"
            summary["metrics"] = metrics
            summary["phase_states"] = {n: m.state for n, m in states.items()}
            logger.info("scan %s complete: %s", domain, summary["phases"]["analyze"])
            return summary

        except KeyboardInterrupt:
            self.db.update_scan(scan_id, status="interrupted", checkpoint=json.dumps(checkpoint))
            for machine in states.values():
                if machine.state == "running":
                    machine.stop("interrupted by operator (Ctrl-C)")
            raise
        except Exception as exc:
            self.db.update_scan(scan_id, status="failed", checkpoint=json.dumps(checkpoint))
            for machine in states.values():
                if machine.state == "running":
                    machine.stop(str(exc)[:200])
            summary["status"] = "failed"
            summary["error"] = str(exc)
            summary["phase_states"] = {n: m.state for n, m in states.items()}
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

    # -- optional (registry-gated) phases ----------------------------------

    @staticmethod
    def _cnames_from_graph(db: Database, scan_id: int) -> dict[str, str]:
        """``{subdomain: cname}`` from persisted ``has_cname`` graph edges.

        Discovery tools that record CNAME edges make takeover candidates
        visible here. An empty dict means "no CNAME data observed" — the
        takeover cycle then degrades to its optional binary enrichment
        (read-only, never destructive).
        """
        out: dict[str, str] = {}
        try:
            for edge in db.list_edges(scan_id=scan_id):
                if edge.get("relation") != "has_cname":
                    continue
                src = db.query("SELECT * FROM assets WHERE id = ?", (edge["src_id"],))
                dst = db.query("SELECT * FROM assets WHERE id = ?", (edge["dst_id"],))
                if src and dst:
                    out[str(src[0].get("value", ""))] = str(dst[0].get("value", ""))
        except Exception:  # graph reads must never break a scan
            logger.debug("cname graph read failed", exc_info=True)
        return out

    def _optional_kwargs(
        self,
        name: str,
        *,
        target_config: TargetConfig,
        results_dir: Path,
        scan_id: int,
        urls: list[str],
        responses: list[dict[str, Any]],
        http_get: Any,
        tech: dict[str, Any],
        identities: list[dict[str, Any]],
        cnames: dict[str, str],
        notifier: Any,
    ) -> dict[str, Any] | None:
        """Explicit per-phase dispatch kwargs (no reflection, no surprises)."""
        if name == "authn":
            return {
                "cfg": self.cfg, "target_config": target_config,
                "results_dir": results_dir, "urls": urls, "responses": responses,
                "db": self.db, "scan_id": scan_id, "notifier": notifier,
            }
        if name == "authz":
            return {
                "cfg": self.cfg, "target_config": target_config,
                "results_dir": results_dir, "urls": urls,
                "identities": identities, "http_get": http_get,
                "db": self.db, "scan_id": scan_id,
            }
        if name == "takeover":
            return {
                "cfg": self.cfg, "target_config": target_config,
                "results_dir": results_dir, "db": self.db, "scan_id": scan_id,
                "cnames": cnames, "http_get": http_get,
            }
        if name in ("network", "cloud"):
            return {
                "cfg": self.cfg, "target_config": target_config,
                "results_dir": results_dir, "db": self.db, "scan_id": scan_id,
                "http_get": http_get,
            }
        if name == "intel":
            return {
                "cfg": self.cfg, "db": self.db,
                "target": target_config.domain, "tech_stack": tech or None,
            }
        return None

    def _run_optional_phases(
        self,
        *,
        registry: Any,
        states: dict[str, Any],
        options: ScanOptions,
        target_config: TargetConfig,
        scan_id: int,
        results_dir: Path,
        urls: list[str],
        responses: list[dict[str, Any]],
        http_get: Any,
        tech: dict[str, Any],
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        """Gate + dispatch optional/intel phases on the single coordinator path.

        Per record: ``PhaseRegistry.gate()`` → ``load_runner()`` →
        ``PhaseStateMachine`` lifecycle. A blocked gate, a missing runner or a
        failing runner marks THAT phase only; the scan always continues.
        Returns ``(phase_summaries, merged_findings)`` — only finding-shaped
        outputs (AUTHZ ``items``) are merged into ANALYZE; evidence-only
        cycles (AUTHN/TAKEOVER) persist through their own engines.
        """
        from lib.surface_graph import SurfaceGraph

        out: dict[str, Any] = {}
        merged: list[dict[str, Any]] = []
        profile = "deep" if options.deep else "standard"
        graph = SurfaceGraph(self.db, scan_id=scan_id)

        # Identities: prefer rows persisted by AUTHN; fall back to the
        # operator's nexus.yaml ``authn.identities`` (config is authoritative
        # even when the AUTHN phase itself was gated off).
        try:
            identities = list(self.db.list_identities(scan_id) or [])
        except Exception:
            identities = []
        if len(identities) < 2:
            try:
                from lib.authn_engine import AuthnEngine

                cfg_idents = [
                    i.to_dict()
                    for i in AuthnEngine(target_config).load_identities(self.cfg)
                ]
                if len(cfg_idents) > len(identities):
                    identities = cfg_idents
            except Exception:
                pass

        notifier = None
        try:
            from lib.notifications import Notifier

            notifier = Notifier(self.cfg)
        except Exception:  # notifications optional at construction time
            notifier = None

        cnames = self._cnames_from_graph(self.db, scan_id)

        for record in registry.all_phases():
            if record.group not in ("optional", "intel"):
                continue
            machine = states.get(record.name)
            if machine is None:
                continue  # disabled via config (not part of this run's plan)
            if machine.state == "completed":
                out[record.name] = {"status": "completed", "cached": True}
                continue

            allowed, reason = registry.gate(
                record,
                graph=graph,
                identities=len(identities),
                scope_kind=target_config.scope_kind,
                profile=profile,
            )
            if not allowed:
                machine.block(reason)
                out[record.name] = {"status": "blocked", "reason": reason}
                logger.info("phase %s blocked: %s", record.name, reason)
                continue

            runner = registry.load_runner(record)
            if runner is None:
                reason = f"runner unavailable: {record.runner}"
                machine.block(reason)
                out[record.name] = {"status": "blocked", "reason": reason}
                logger.info("phase %s blocked: %s", record.name, reason)
                continue

            kwargs = self._optional_kwargs(
                record.name,
                target_config=target_config, results_dir=results_dir,
                scan_id=scan_id, urls=urls, responses=responses,
                http_get=http_get, tech=tech, identities=identities,
                cnames=cnames, notifier=notifier,
            )
            if kwargs is None:
                machine.skip(f"no dispatch mapping for {record.name}")
                out[record.name] = {"status": "skipped"}
                continue

            try:
                if machine.state in ("failed", "partial"):
                    machine.retry()  # lifecycle op: retry a failed cycle
                else:
                    machine.start()
            except Exception as exc:  # e.g. paused — operator must resume
                out[record.name] = {"status": "not-started", "reason": str(exc)}
                continue
            try:
                result = runner(**kwargs)
            except Exception as exc:  # optional cycles never kill a scan
                machine.stop(str(exc)[:200])
                out[record.name] = {"status": "failed", "error": str(exc)[:300]}
                logger.warning("optional phase %s failed: %s", record.name, exc)
                continue
            hint = result.get("phase_state") if isinstance(result, dict) else None
            if hint == "partial":
                machine.complete(partial=True)
            elif hint == "skipped":
                machine.skip(str(result.get("reason") or "skipped by runner")[:200])
            elif hint == "blocked":
                machine.block(str(result.get("reason") or "blocked by runner")[:200])
            else:
                machine.complete()
            out[record.name] = result if isinstance(result, dict) else {"status": "completed"}
            if record.name == "authz" and isinstance(result, dict):
                items = result.get("items")
                if isinstance(items, list):
                    merged.extend(items)
        return out, merged

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
        """Manually verify a finding through the lifecycle (single mechanism).

        A candidate is first escalated to ``probable`` (manual review),
        then moved to ``validated`` with actor=manual; every step is audited.
        """
        rows = self.db.query("SELECT * FROM findings WHERE id = ?", (finding_id,))
        if not rows:
            return {"status": "not_found", "finding_id": finding_id}
        try:
            if lifecycle_mod.current_state(self.db, finding_id) == "candidate":
                lifecycle_mod.transition(self.db, finding_id, "probable", actor="manual",
                                         reason="manual review escalation")
            result = lifecycle_mod.transition(self.db, finding_id, "validated", actor="manual",
                                              reason="manual verification")
        except lifecycle_mod.InvalidTransition as exc:
            return {"status": "cannot_verify", "finding_id": finding_id,
                    "state": lifecycle_mod.current_state(self.db, finding_id), "error": str(exc)}
        return {"status": "verified", "finding_id": finding_id, "state": result["to_state"]}

    def reject_finding(self, finding_id: int) -> dict[str, Any]:
        """Mark a finding false-positive AND teach the filter (persisted).

        The state change goes through the lifecycle; the learned auto_filter
        pattern is written back to ``false_positive_filters.yaml`` so the same
        FP stops being reported.
        """
        rows = self.db.query("SELECT * FROM findings WHERE id = ?", (finding_id,))
        if not rows:
            return {"status": "not_found", "finding_id": finding_id}
        finding = dict(rows[0])
        learned = None
        try:
            learned = self._persist_fp_learning(finding)
        except Exception as exc:  # learning must never break the rejection
            logger.warning("false-positive learning failed: %s", exc)
        try:
            result = lifecycle_mod.transition(
                self.db, finding_id, "rejected", actor="manual",
                reason=str(finding.get("validity_reason") or "manual false-positive review"),
            )
        except lifecycle_mod.InvalidTransition as exc:
            return {"status": "cannot_reject", "finding_id": finding_id,
                    "state": lifecycle_mod.current_state(self.db, finding_id), "error": str(exc)}
        out: dict[str, Any] = {"status": "rejected", "finding_id": finding_id,
                               "state": result["to_state"]}
        if learned:
            out["learned"] = learned
        return out

    def _persist_fp_learning(self, finding: dict[str, Any]) -> dict[str, Any] | None:
        """Teach the FP filter from a rejected finding; persist to YAML."""
        import yaml

        path = CONFIG_DIR / "false_positive_filters.yaml"
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            return None
        learning = FalsePositiveFilter(data).learn_from_review(finding, "FP")
        if not learning:
            return None
        rules = data.get("filters") or {}
        vtype = str(learning.get("type", "")).lower()
        target_key = None
        for key in rules:
            kl = str(key).lower()
            if kl == vtype or kl in vtype or vtype in kl:
                target_key = key
                break
        if target_key is None:
            return None
        rule = rules[target_key] or {}
        pattern = str(learning.get("learned_pattern", ""))
        arr = [str(p) for p in (rule.get("auto_filter") or [])]
        if pattern and pattern not in arr:
            arr.append(pattern)
            rule["auto_filter"] = arr
            rules[target_key] = rule
            data["filters"] = rules
            try:
                path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
                learning["persisted_to"] = str(path)
            except OSError as exc:
                logger.warning("could not persist learned FP rule: %s", exc)
        return learning
