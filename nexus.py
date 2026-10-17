#!/usr/bin/env python3
"""NEXUS CLI entry point.

    python nexus.py hunt example.com --quick-scan
    python nexus.py batch targets.txt --concurrent 2
    python nexus.py cve-update
    python nexus.py ai-set-key --provider openai --key sk-...

Run ``python nexus.py --help`` for the full command list.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

# Ensure the repo root is importable even when Python runs with safe-path
# enabled (`-P` / PYTHONSAFEPATH), or when invoked from another directory.
_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from core.coordinator import Coordinator, ScanOptions
from core.database import Database
from lib.config import load_config, validate_keys
from lib.exceptions import ConfigError, NexusError, ScopeException
from lib.logger import get_logger, setup_logging
from lib.paths import CONFIG_DIR, LOGS_DIR
from lib.version import framework_version

# Version comes from the repo-level VERSION file (single source of truth).
__version__ = framework_version()
__codename__ = "Apex"
_VERSION_STR = f"NEXUS {__version__} \"{__codename__}\""

logger = get_logger("cli")

# ---------------------------------------------------------------------------
# Target-file parsing (batch mode)
# ---------------------------------------------------------------------------


def parse_targets_file(path: Path) -> list[tuple[str, dict]]:
    """Parse a batch targets file.

    Lines: ``domain`` or ``domain {json-overrides}``; ``#`` comments and
    blank lines ignored.
    """
    entries: list[tuple[str, dict]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        target = line
        overrides: dict = {}
        if "{" in line:
            idx = line.index("{")
            target = line[:idx].strip()
            try:
                overrides = json.loads(line[idx:])
            except json.JSONDecodeError:
                overrides = {}
        entries.append((target, overrides))
    return entries


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def cmd_hunt(args: argparse.Namespace) -> int:
    cfg = load_config()
    coord = Coordinator(cfg)
    options = ScanOptions(
        target=args.target,
        intensity="full-scan" if args.full_scan else "quick-scan",
        discover_only=args.discover_only,
        scan_only=args.scan_only,
        with_subdomains=args.with_subdomains,
        include_cdn=args.include_cdn,
        test_bypass=args.test_bypass,
        custom_fuzzing=args.custom_fuzzing,
        skip_tools=_split(args.skip_tools),
        run_tools=_split(args.run_tools),
        cookie=args.cookie or "",
        methodology=args.methodology or "",
        rate_limit=args.rate_limit or "",
        screenshots=args.screenshots,
        delta=args.delta,
        parallel_tools=args.parallel_tools,
        resume_scan_id=args.resume,
        cve_id=args.cve or "",
        min_severity=args.min_severity or "",
        exclude=_split(args.exclude),
        exclude_p4=args.exclude_p4,
    )
    result = coord.run_scan(options)
    print(json.dumps(result, indent=2, default=str))
    if args.hunt_new:
        from phases.hunt.hunt_orchestrator import run_hunt_phase

        print(json.dumps(run_hunt_phase(cfg, coord.results_base), indent=2, default=str))
    return 0 if result.get("status") != "failed" else 1


def cmd_batch(args: argparse.Namespace) -> int:
    cfg = load_config()
    coord = Coordinator(cfg)
    entries = parse_targets_file(Path(args.file))

    def options_factory(target: str) -> ScanOptions:
        overrides = next((o for t, o in entries if t == target), {})
        return ScanOptions(
            target=target,
            intensity="full-scan" if args.full_scan or overrides.get("intensity") == "full-scan" else "quick-scan",
            run_tools=list(overrides.get("tools", [])),
            rate_limit=str(overrides.get("rate_limit", "") or ""),
            skip_tools=_split(args.skip_tools),
            delta=args.delta,
        )

    targets = [t for t, _o in entries]
    results = coord.run_batch(
        targets, options_factory, concurrent=args.concurrent, sequential=args.sequential or args.concurrent <= 1
    )
    print(json.dumps(results, indent=2, default=str))
    return 0


def cmd_hunt_schedule(args: argparse.Namespace) -> int:
    cfg = load_config()
    coord = Coordinator(cfg)

    if args.list:
        print(json.dumps(coord.db.list_schedules(), indent=2, default=str))
        return 0

    if args.cron:
        if not args.target:
            print("error: --cron requires a target", file=sys.stderr)
            return 2
        tid = coord.db.upsert_target(args.target)
        name = args.name or f"{args.target}_cron"
        coord.db.upsert_schedule(
            name=name, target_id=tid, frequency="custom",
            cron_expression=args.cron, next_run=coord.compute_next_run(args.cron),
        )
        print(json.dumps({"created": name, "cron": args.cron, "next_run": coord.compute_next_run(args.cron)}, indent=2))
        return 0

    for flag, freq, expr in (
        (args.daily, "daily", "0 2 * * *"),
        (args.weekly, "weekly", "0 2 * * 1"),
        (args.every_6h, "every-6h", "0 */6 * * *"),
    ):
        if flag:
            tid = coord.db.upsert_target(flag)
            name = f"{flag}_{freq}"
            coord.db.upsert_schedule(
                name=name, target_id=tid, frequency=freq,
                cron_expression=expr, next_run=coord.compute_next_run(expr),
            )
            print(json.dumps({"created": name, "frequency": freq, "next_run": coord.compute_next_run(expr)}, indent=2))
            return 0

    if args.schedule_name:
        print(json.dumps(coord.run_schedule(args.schedule_name), indent=2, default=str))
        return 0

    overdue = coord.due_schedules()
    ran = [coord.run_schedule(s["name"]) for s in overdue]
    print(json.dumps({"due": len(overdue), "ran": ran}, indent=2, default=str))
    return 0


def cmd_hunt_new(args: argparse.Namespace) -> int:
    cfg = load_config()
    if args.enable or args.disable:
        _set_config_flag(CONFIG_DIR / "nexus.yaml", ["phases", "hunt", "enabled"], bool(args.enable))
        print(json.dumps({"hunt.enabled": bool(args.enable)}, indent=2))
        return 0
    from phases.hunt.hunt_orchestrator import run_hunt_phase

    print(json.dumps(run_hunt_phase(cfg, Path("results")), indent=2, default=str))
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from core.exporter import export_findings

    cfg = load_config()
    db = Database(cfg.database_path)
    targets = [t for t in db.list_targets() if args.target in (None, "", t["domain"])]
    if not targets:
        print("error: no matching target", file=sys.stderr)
        return 1
    paths = []
    for t in targets:
        scans = db.list_scans(target_id=t["id"])
        findings: list[dict] = []
        chains: list[dict] = []
        for s in scans:
            findings.extend(db.query_findings(scan_id=s["id"]))
            chains.extend(db.query_chains(s["id"]))
        if args.date:
            findings = [f for f in findings if str(f.get("created_at", "")).startswith(args.date)]
            if not findings:
                continue
        paths.append(str(export_findings(t["domain"], scans, findings, chains, fmt=args.format, date=args.date)))
    print(json.dumps({"exported": paths}, indent=2))
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    from core.importer import import_file

    cfg = load_config()
    db = Database(cfg.database_path)
    summary = import_file(db, Path(args.file), merge=args.merge)
    print(json.dumps(summary, indent=2))
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    cfg = load_config()
    coord = Coordinator(cfg)
    print(json.dumps(coord.diff_scans(args.scan1, args.scan2), indent=2, default=str))
    return 0


def cmd_cve_update(args: argparse.Namespace) -> int:
    from lib.cve_workflow import run_cve_update

    cfg = load_config()
    db = Database(cfg.database_path)
    tech: dict | None = None
    if args.target:
        tech = _tech_for_target(args.target)
    print(json.dumps(run_cve_update(cfg, db, tech_stack=tech), indent=2, default=str))
    return 0


def cmd_cve_scan(args: argparse.Namespace) -> int:
    from lib.cve_workflow import run_cve_scan

    cfg = load_config()
    db = Database(cfg.database_path)
    tech = _tech_for_target(args.target)
    print(json.dumps(
        run_cve_scan(cfg, db, args.target, tech_stack=tech, cve_id=args.cve or "", critical_only=args.critical),
        indent=2, default=str,
    ))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    cfg = load_config()
    coord = Coordinator(cfg)
    print(json.dumps(coord.verify_finding(args.finding_id), indent=2))
    return 0


def cmd_reject(args: argparse.Namespace) -> int:
    cfg = load_config()
    coord = Coordinator(cfg)
    print(json.dumps(coord.reject_finding(args.finding_id), indent=2, default=str))
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    from lib.doctor import run_doctor

    report = run_doctor()
    print(json.dumps(report, indent=2, default=str))
    return 0 if report["ok"] else 1


def cmd_self_scan(args: argparse.Namespace) -> int:
    from lib.selfscan import scan_tree
    from lib.paths import REPO_ROOT

    root = Path(args.root) if args.root else REPO_ROOT
    findings = scan_tree(root, include_allowlisted=args.include_allowlisted)
    print(json.dumps({"root": str(root), "findings": findings, "count": len(findings)}, indent=2, default=str))
    return 1 if findings else 0


def cmd_secretscan(args: argparse.Namespace) -> int:
    """Scan staged content (default), commit history, or the working tree."""
    from lib.paths import REPO_ROOT
    from lib.secretscan import SecretScanError, format_findings, scan_history, scan_staged
    from lib.selfscan import scan_tree

    allowlist = Path(args.allowlist) if getattr(args, "allowlist", None) else None
    repo = Path(args.root) if getattr(args, "root", None) else None
    try:
        if getattr(args, "history", False):
            report = scan_history(repo, max_commits=int(getattr(args, "max_commits", 0) or 0),
                                  allowlist_path=allowlist)
        elif getattr(args, "tree", None) is not None:
            root = Path(args.tree) if args.tree else (repo or REPO_ROOT)
            report = {
                "mode": "tree", "root": str(root),
                "findings": scan_tree(root, include_allowlisted=getattr(args, "include_allowlisted", False)),
                "suppressed": [], "scanned": [], "skipped": [],
                "allowlist": {"path": "", "entries": 0, "invalid": []},
            }
        else:
            report = scan_staged(repo, allowlist_path=allowlist)
    except SecretScanError as exc:
        print(f"secretscan: {exc}", file=sys.stderr)
        print("Scan could not complete (fail-closed): commit/push should be blocked.", file=sys.stderr)
        return 2

    if getattr(args, "json", False):
        print(json.dumps(report, indent=2, default=str))
    else:
        print(format_findings(report))
    return 1 if report["findings"] else 0


def cmd_hooks(args: argparse.Namespace) -> int:
    """Install/status/uninstall the NEXUS pre-commit secret-scan hook."""
    import subprocess

    from lib.paths import REPO_ROOT

    hook_dir = REPO_ROOT / "scripts" / "hooks"
    hook_src = hook_dir / "pre-commit"
    action = args.action
    target = Path(args.repo) if getattr(args, "repo", None) else REPO_ROOT

    def _git(*git_args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", *git_args], cwd=str(target),
                              capture_output=True, text=True, check=False)

    if _git("rev-parse", "--show-toplevel").returncode != 0:
        print("hooks: not inside a git repository", file=sys.stderr)
        return 2

    if action == "status":
        configured = _git("config", "--local", "--get", "core.hooksPath").stdout.strip()
        armed = bool(configured) and Path(configured, "pre-commit").is_file()
        print(json.dumps({
            "core.hooksPath": configured or None,
            "hook_source": str(hook_src),
            "hook_present": hook_src.is_file(),
            "armed": armed,
            "hint": "run 'python -m nexus hooks install' to enable pre-commit secret scanning",
        }, indent=2))
        return 0

    if action == "uninstall":
        _git("config", "--local", "--unset", "core.hooksPath")
        print("hooks: pre-commit secret scanning disabled (core.hooksPath unset)")
        return 0

    # install
    if not hook_src.is_file():
        print(f"hooks: hook source missing: {hook_src}", file=sys.stderr)
        return 2
    result = _git("config", "--local", "core.hooksPath", hook_dir.as_posix())
    if result.returncode != 0:
        print(f"hooks: could not set core.hooksPath: {result.stderr.strip()}", file=sys.stderr)
        return 2
    try:  # ensure the hook stays executable on POSIX checkouts
        import os as _os

        _os.chmod(hook_src, 0o755)
    except OSError:
        pass
    print(json.dumps({
        "installed": True,
        "core.hooksPath": hook_dir.as_posix(),
        "hook": str(hook_src),
        "note": "staged content is scanned before every commit; bypass once with: git commit --no-verify",
    }, indent=2))
    return 0


def cmd_scope_sync(args: argparse.Namespace) -> int:
    from lib.scope_sync import (
        apply_scope_to_config,
        load_program_file,
        parse_bugcrowd_program,
        parse_h1_program,
        sync_targets,
    )

    cfg = load_config()
    config_path = Path(args.config) if args.config else None

    if getattr(args, "all", False) or getattr(args, "program", None):
        domains = cfg.sync_target_names() if args.all else [args.program]
        if args.all and not domains:
            print(json.dumps({"programs": [], "count": 0, "applied": 0, "changed": 0,
                              "skipped": 0, "note": "no targets carry a sync block"}, indent=2))
            return 0
        result = sync_targets(domains, config=cfg, config_path=config_path, apply=not args.dry_run)
        if not args.dry_run:
            _audit_scope_sync(cfg, result)
        print(json.dumps(result, indent=2, default=str))
        return 1 if result["skipped"] else 0

    if not args.file or not args.domain:
        print("scope-sync: provide --file PATH --domain DOMAIN, or --program DOMAIN / --all",
              file=sys.stderr)
        return 2
    program = load_program_file(Path(args.file))
    parsed = parse_h1_program(program) if args.platform == "hackerone" else parse_bugcrowd_program(program)
    if args.dry_run:
        print(json.dumps(parsed, indent=2, default=str))
        return 0
    result = apply_scope_to_config(
        args.domain, parsed["in_scope"], parsed["out_of_scope"],
        config_path=config_path,
    )
    print(json.dumps(result, indent=2, default=str))
    return 0


def _audit_scope_sync(cfg, result: dict) -> None:
    """Record applied scope auto-syncs (best-effort; never fatal)."""
    try:
        db = Database(cfg.database_path)
    except Exception:  # pragma: no cover - defensive
        return
    try:
        for program in result.get("programs", []):
            if program.get("applied"):
                db.insert_audit_event(
                    "cli", f"scope_sync.{program['domain']}", category="scope",
                    detail=json.dumps(program.get("drift", {})),
                )
    except Exception:  # pragma: no cover - defensive
        pass
    finally:
        db.close()


def cmd_agent(args: argparse.Namespace) -> int:
    from lib.agent import ALLOWED_ACTIONS, NexusAgent
    from lib.ai_agents import analyzer_for_config

    cfg = load_config()
    if getattr(args, "agent", None):
        analyzer = analyzer_for_config(cfg, args.agent)
    elif cfg.agents:
        analyzer = analyzer_for_config(cfg, None)
    else:
        from lib.ai_analyzer import AIAnalyzer

        analyzer = AIAnalyzer.from_config(cfg.ai, cfg.env)
    agent = NexusAgent(cfg, ai=analyzer)

    def _scan(step):
        coord = Coordinator(cfg)
        return coord.run_scan(ScanOptions(target=step.get("target", ""), discover_only=step.get("action") == "discover"))

    def _dork(step):
        from phases.discover.dorker import Dorker

        return Dorker().run(step.get("target", ""), github_token=cfg.env.get("GITHUB_TOKEN", ""))

    def _cve(step):
        from lib.cve_workflow import run_cve_update

        return run_cve_update(cfg, Database(cfg.database_path))

    def _status(step):
        db = Database(cfg.database_path)
        return {"targets": len(db.list_targets()), "scans": len(db.list_scans())}

    def _report(step):
        from core.coordinator import Coordinator as _C

        return {"latest": _C(cfg).db.list_scans()[:1]}

    agent.actions.update({
        "scan": _scan, "discover": _scan, "dork": _dork,
        "cve-update": _cve, "status": _status, "report": _report,
    })
    print(json.dumps(agent.run(args.objective, max_steps=args.max_steps, dry_run=args.dry_run), indent=2, default=str))
    return 0


def cmd_team(args: argparse.Namespace) -> int:
    """Run the bounded multi-agent runtime on a plan (deterministic/mock by default)."""
    from lib.nemesis.runtime import MultiAgentRuntime, RunLimits

    cfg = load_config()
    target = getattr(args, "target", "") or ""
    tasks = None
    if getattr(args, "plan", None):
        tasks = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    else:
        objective = getattr(args, "objective", "") or "team run"
        tasks = [
            {"id": "recon", "role": "recon", "action": "discover", "target": target},
            {"id": "analysis", "role": "analysis", "action": "scan", "target": target, "depends_on": ["recon"]},
            {"id": "validation", "role": "validation", "action": "verify", "target": target, "depends_on": ["analysis"]},
            {"id": "reporting", "role": "reporting", "action": "report", "target": ""},
        ]
    target_config = cfg.target(target) if target else None
    runtime = MultiAgentRuntime(
        cfg=cfg, mock=True, target_config=target_config,
        limits=RunLimits(max_workers=getattr(args, "workers", 2) or 2),
    )
    plan = runtime.plan(getattr(args, "objective", "") or "team run", target or "default", tasks)
    print(json.dumps(runtime.run(plan).to_dict(), indent=2, default=str))
    return 0


def cmd_zap(args: argparse.Namespace) -> int:
    """Drive the ZAP adapter through the guarded, scope-checked framework."""
    from lib.adapters.base import (
        KIND_ACTIVE, KIND_PASSIVE, AdapterError, AdapterPolicy, GuardedAdapter,
        ingest_findings,
    )
    from lib.adapters.registry import build_adapter
    from lib.adapters.zap import MockZapAdapter
    from lib.scope_validator import extract_host

    cfg = load_config()
    spec = cfg.integration("zap")
    mock = bool(getattr(args, "mock", False))
    if not mock and not spec.get("enabled", False):
        print("zap integration is disabled (integrations.zap.enabled: false); use --mock to dry-run",
              file=sys.stderr)
        return 1

    target = getattr(args, "passive", "") or getattr(args, "active", "") or ""
    kind = KIND_ACTIVE if getattr(args, "active", "") else KIND_PASSIVE

    if kind == KIND_ACTIVE and not getattr(args, "authorize_active", False):
        print("active scanning requires --authorize-active (explicit authorization)", file=sys.stderr)
        return 1

    adapter = MockZapAdapter() if mock else build_adapter("zap", cfg)
    db = Database(cfg.database_path) if getattr(args, "import_scan", 0) else None

    domain = getattr(args, "domain", "") or (extract_host(target) if target else "")
    target_config = cfg.target(domain) if domain else None
    policy = AdapterPolicy(
        target_config=target_config,
        ssrf_allow={str(h).strip().lower() for h in (spec.get("ssrf_allow") or []) if str(h).strip()},
        allow_active=bool(spec.get("allow_active_scan", False)) or mock,
        db=db,
    )
    guarded = GuardedAdapter(adapter, policy)

    try:
        if getattr(args, "capabilities", False):
            print(json.dumps([c.to_dict() for c in guarded.capabilities()], indent=2))
            return 0
        if getattr(args, "health", False) or not target:
            print(json.dumps(guarded.health().to_dict(), indent=2))
            return 0

        from lib.adapters.base import JobSpec

        handle = guarded.start_job(JobSpec(target=target, kind=kind,
                                           authorized=getattr(args, "authorize_active", False)))
        handle = guarded.wait(handle, timeout=float(getattr(args, "timeout", 0) or 0),
                              poll_interval=float(getattr(args, "poll", 1) or 1))
        report: dict = {"adapter": "zap", "mock": mock, "job": handle.to_dict()}
        if handle.status in ("completed", "running") or getattr(args, "collect", False):
            findings = guarded.collect(handle)
            report["finding_count"] = len(findings)
            report["findings"] = [f.to_dict() for f in findings]
            if getattr(args, "import_scan", None):
                report["import"] = ingest_findings(
                    db, int(args.import_scan), findings, target_config, phase="zap")
        print(json.dumps(report, indent=2, default=str))
        return 0
    except AdapterError as exc:
        print(f"zap error: {exc}", file=sys.stderr)
        return 1
    finally:
        guarded.close()
        if db is not None:
            db.close()


def cmd_openapi(args: argparse.Namespace) -> int:
    from lib.openapi import endpoints_from_file, endpoints_to_urls

    endpoints = endpoints_from_file(Path(args.file))
    urls = endpoints_to_urls(args.base, endpoints) if args.base else []
    print(json.dumps({"endpoints": endpoints, "urls": urls, "count": len(endpoints)}, indent=2, default=str))
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Run due schedules; with --once, run a single pass and exit."""
    import time as _time

    cfg = load_config()
    coord = Coordinator(cfg)
    if args.once:
        overdue = coord.due_schedules()
        runs = [coord.run_schedule(s["name"])["status"] for s in overdue]
        print(json.dumps({"passes": 1, "due": len(overdue), "ran": runs}, indent=2, default=str))
        return 0
    while True:
        overdue = coord.due_schedules()
        for s in overdue:
            coord.run_schedule(s["name"])
        print(json.dumps({"ts": _time.time(), "due": len(overdue)}))
        _time.sleep(args.interval)


def cmd_gui(args: argparse.Namespace) -> int:
    """Serve the local web GUI (loopback by default; requires GUI credentials)."""
    import os

    if not os.environ.get("NEXUS_GUI_USER", "").strip() or not os.environ.get(
        "NEXUS_GUI_PASS", ""
    ).strip():
        print(
            "error: set NEXUS_GUI_USER and NEXUS_GUI_PASS before starting the GUI",
            file=sys.stderr,
        )
        return 2

    loopback = {"127.0.0.1", "localhost", "::1"}
    if args.host not in loopback and not args.allow_remote:
        print(
            f"error: refusing to bind non-loopback host {args.host!r}; "
            "pass --allow-remote to override (not recommended)",
            file=sys.stderr,
        )
        return 2

    try:
        import uvicorn
    except ImportError:
        print(
            "error: uvicorn is required to serve the GUI (it ships as a core dependency)",
            file=sys.stderr,
        )
        return 1

    print(f"NEXUS GUI: http://{args.host}:{args.port} (HTTP Basic auth required)")
    uvicorn.run("core.gui:app", host=args.host, port=args.port, log_level=args.log_level)
    return 0


def cmd_retention(args: argparse.Namespace) -> int:
    from lib.retention import retention_report

    print(json.dumps(retention_report(days=args.days), indent=2, default=str))
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    from lib.paths import RESULTS_BASE
    from lib.program_monitor import ProgramMonitor

    if args.file:
        programs = json.loads(Path(args.file).read_text(encoding="utf-8"))
        if isinstance(programs, dict):
            programs = programs.get("programs", programs.get("data", []))
    else:
        from phases.hunt.api_fetcher import (
            fetch_bugcrowd_programs,
            fetch_hackerone_programs,
            fetch_intigriti_programs,
            fetch_yeswehack_programs,
        )

        cfg = load_config()
        programs = (
            fetch_hackerone_programs(cfg.env.get("HACKERONE_API_USERNAME", ""), cfg.env.get("HACKERONE_API_TOKEN", ""))
            + fetch_bugcrowd_programs(cfg.env.get("BUGCROWD_API_KEY", ""))
            + fetch_intigriti_programs(cfg.env.get("INTIGRITI_API_KEY", ""))
            + fetch_yeswehack_programs(cfg.env.get("YESWEHACK_API_KEY", ""))
        )
    print(json.dumps(ProgramMonitor(RESULTS_BASE).check(programs), indent=2, default=str))
    return 0


def cmd_graphql(args: argparse.Namespace) -> int:
    from lib.graphql_probe import analyze_introspection_file

    print(json.dumps(analyze_introspection_file(Path(args.file)), indent=2, default=str))
    return 0


def cmd_draft(args: argparse.Namespace) -> int:
    from core.reporter import render_draft

    cfg = load_config()
    db = Database(cfg.database_path)
    rows = db.query("SELECT * FROM findings WHERE id = ?", (args.finding_id,))
    if not rows:
        print(json.dumps({"error": "finding not found"}))
        return 1
    row = rows[0]
    finding = {
        "vuln_type": row["vuln_type"], "severity": row["severity"], "endpoint": row["endpoint"],
        "confidence": row["confidence"], "payload": row["payload"],
        "response_snippet": row["response_snippet"],
        "tools_found": json.loads(row["tools_found"] or "[]"),
    }
    print(render_draft(args.platform, args.target, finding))
    return 0


def cmd_c2(args: argparse.Namespace) -> int:
    from phases.control.c2_orchestrator import run_control

    cfg = load_config()
    print(json.dumps(run_control(cfg), indent=2, default=str))
    return 0


def cmd_dork(args: argparse.Namespace) -> int:
    from phases.discover.dorker import Dorker

    cfg = load_config()
    github_token = cfg.env.get("GITHUB_TOKEN", "")
    dorker = Dorker()
    summary = dorker.run_intents(
        args.target,
        intents=_split(args.intents) or None,
        engines=_split(args.engines) or None,
        github_token=github_token,
    )
    print(json.dumps([r.to_dict() for r in summary], indent=2, default=str))
    return 0


def cmd_check_tools(args: argparse.Namespace) -> int:
    from lib.tool_registry import get_registry

    cfg = load_config()
    registry = get_registry()
    status = registry.status(cfg)
    installed = [t for t, s in status.items() if s["availability"] == "installed"]
    missing = [t for t, s in status.items() if s["availability"] == "missing"]
    key_missing = [t for t, s in status.items() if s["availability"] == "key-missing"]
    print(json.dumps({
        "installed": sorted(installed),
        "missing": sorted(missing),
        "key_missing (provider OFF/no key)": sorted(key_missing),
    }, indent=2))
    return 0


def cmd_ai_keys(args: argparse.Namespace) -> int:
    from lib.ai_agents import validate_ai_config
    from lib.ai_analyzer import AIAnalyzer

    cfg = load_config()
    try:
        analyzer = AIAnalyzer.from_config(cfg.ai, cfg.env)
        status = analyzer.status_summary()
        keys = analyzer.key_status()
    except Exception as exc:  # diagnostic command must not crash
        status, keys = {"error": str(exc)}, []
    try:
        agents = validate_ai_config(cfg)
    except Exception as exc:  # surface config errors instead of crashing
        agents = {"error": str(exc)}
    print(json.dumps(
        {"status": status, "keys": keys, "agents": agents},
        indent=2, default=str,
    ))
    return 0


def cmd_ai_providers(args: argparse.Namespace) -> int:
    from lib.ai_providers import PROVIDER_SPECS, REASONING_EFFORTS

    print(json.dumps(
        {
            "reasoning_efforts": list(REASONING_EFFORTS),
            "providers": [spec.to_dict() for spec in PROVIDER_SPECS.values()],
        },
        indent=2, default=str,
    ))
    return 0


def cmd_ai_runtime(args: argparse.Namespace) -> int:
    from lib.ai_analyzer import AIAnalyzer
    from lib.ai_providers import runtime_providers

    cfg = load_config()
    analyzer = AIAnalyzer.from_config(cfg.ai, cfg.env)
    selected = (getattr(args, "provider", "") or "").lower()
    if selected:
        adapter = analyzer.runtime(selected)
        if adapter is None:
            print(json.dumps({
                "error": f"provider {selected!r} has no discoverable local runtime",
                "runtime_providers": list(runtime_providers()),
            }, indent=2))
            return 1
        statuses = [adapter.probe().to_dict()]
    else:
        names = [p for p in analyzer.providers if analyzer.runtime(p)]
        names = names or list(runtime_providers())
        statuses = [analyzer.runtime(p).probe().to_dict() for p in names]
    print(json.dumps({"runtimes": statuses}, indent=2, default=str))
    return 0


def cmd_ai_set_key(args: argparse.Namespace) -> int:
    from lib.key_pool import set_key_in_env_file

    keys_path = CONFIG_DIR / ".keys.env"
    slot, path = set_key_in_env_file(keys_path, args.provider, args.key)
    print(json.dumps({"provider": args.provider, "slot": slot, "file": path}, indent=2))
    return 0


def cmd_update(args: argparse.Namespace) -> int:
    """Framework self-update (git-based) and/or tool updates."""
    results: dict[str, object] = {}
    if args.all or not args.tools_only:
        repo = _find_git_root()
        if repo and _shutil.which("git"):
            import subprocess

            proc = subprocess.run(["git", "-C", str(repo), "pull", "--ff-only"], capture_output=True, text=True, shell=False)
            results["framework"] = {"returncode": proc.returncode, "output": (proc.stdout + proc.stderr).strip()[:500]}
        else:
            results["framework"] = {"status": "not a git checkout; skipping"}
    if args.all or args.tools_only or args.tools_update:
        results["tools"] = _update_tools()
    print(json.dumps(results, indent=2, default=str))
    return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _split(value: str | None) -> list[str]:
    if not value:
        return []
    return [v.strip() for v in value.split(",") if v.strip()]


def _tech_for_target(target: str) -> dict | None:
    """Load cached tech for a target from the latest scan (best-effort)."""
    for folder in sorted(Path("results").glob(f"{target}*"), reverse=True):
        tech_file = folder / "recon" / "tech_stack.json"
        if tech_file.exists():
            try:
                return json.loads(tech_file.read_text(encoding="utf-8")).get("tech", {})
            except (json.JSONDecodeError, OSError):
                return None
    return None


def _set_config_flag(yaml_path: Path, path: list[str], value: bool) -> None:
    """Set a nested boolean flag in nexus.yaml (backup + re-dump)."""
    import yaml

    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8")) or {}
    yaml_path.with_suffix(".yaml.bak").write_text(yaml_path.read_text(encoding="utf-8"), encoding="utf-8")
    node = data
    for key in path[:-1]:
        node = node.setdefault(key, {})
    node[path[-1]] = value
    yaml_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _find_git_root() -> Path | None:
    import subprocess

    try:
        proc = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, shell=False)
        if proc.returncode == 0:
            return Path(proc.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def _update_tools() -> dict[str, object]:
    """Best-effort update of installed external tools."""
    import subprocess

    updates = {
        "subfinder": ["subfinder", "-up"],
        "nuclei": ["nuclei", "-update-templates"],
        "httpx": ["httpx", "-up"],
    }
    results: dict[str, object] = {}
    for tool, cmd in updates.items():
        if not shutil.which(tool):
            results[tool] = "not installed"
            continue
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, shell=False)
            results[tool] = {"returncode": proc.returncode}
        except (OSError, subprocess.SubprocessError) as exc:
            results[tool] = f"error: {exc}"
    return results


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nexus", description="NEXUS bug bounty automation framework")
    parser.add_argument("--version", action="version", version=_VERSION_STR)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_intensity_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument("--quick-scan", action="store_true", help="light scan (default)")
        p.add_argument("--full-scan", action="store_true", help="deep scan (all tools)")
        p.add_argument("--discover-only", action="store_true")
        p.add_argument("--scan-only", action="store_true")
        p.add_argument("--with-subdomains", action="store_true")
        p.add_argument("--include-cdn", action="store_true")
        p.add_argument("--test-bypass", action="store_true")
        p.add_argument("--custom-fuzzing", action="store_true")
        p.add_argument("--hunt-new", action="store_true")
        p.add_argument("--screenshots", action="store_true")
        p.add_argument("--delta", action="store_true", help="scan only new URLs since last run")
        p.add_argument("--parallel", dest="parallel_tools", type=int, default=1, help="run light tools concurrently")
        p.add_argument("--cookie")
        p.add_argument("--methodology")
        p.add_argument("--rate-limit", dest="rate_limit")
        p.add_argument("--min-severity", dest="min_severity")
        p.add_argument("--exclude")
        p.add_argument("--exclude-p4", action="store_true")
        p.add_argument("--skip-tools", dest="skip_tools")
        p.add_argument("--run-tools", dest="run_tools")
        p.add_argument("--resume", type=int)
        p.add_argument("--cve")

    # hunt
    p_hunt = sub.add_parser("hunt", help="scan a single target")
    p_hunt.add_argument("target")
    add_intensity_flags(p_hunt)
    p_hunt.set_defaults(func=cmd_hunt)

    # batch
    p_batch = sub.add_parser("batch", help="scan targets from a file")
    p_batch.add_argument("file")
    add_intensity_flags(p_batch)
    p_batch.add_argument("--concurrent", type=int, default=1)
    p_batch.add_argument("--sequential", action="store_true")
    p_batch.set_defaults(func=cmd_batch)

    # hunt-schedule
    p_sched = sub.add_parser("hunt-schedule", help="scheduling")
    p_sched.add_argument("schedule_name", nargs="?")
    p_sched.add_argument("--list", action="store_true")
    p_sched.add_argument("--cron")
    p_sched.add_argument("--daily", nargs="?", const="", metavar="TARGET")
    p_sched.add_argument("--weekly", nargs="?", const="", metavar="TARGET")
    p_sched.add_argument("--every-6h", dest="every_6h", nargs="?", const="", metavar="TARGET")
    p_sched.add_argument("--name")
    p_sched.add_argument("--target")
    p_sched.set_defaults(func=cmd_hunt_schedule)

    # hunt-new
    p_hn = sub.add_parser("hunt-new", help="first-blood auto-hunt (Phase 4)")
    p_hn.add_argument("--enable", action="store_true")
    p_hn.add_argument("--disable", action="store_true")
    p_hn.set_defaults(func=cmd_hunt_new)

    # export / import / diff
    p_exp = sub.add_parser("export", help="export findings")
    p_exp.add_argument("target", nargs="?")
    p_exp.add_argument("--format", default="zip", choices=["zip", "7z", "json", "csv", "html", "sarif"])
    p_exp.add_argument("--date")
    p_exp.set_defaults(func=cmd_export)

    p_imp = sub.add_parser("import", help="import/restore findings")
    p_imp.add_argument("file")
    p_imp.add_argument("--merge", action="store_true")
    p_imp.set_defaults(func=cmd_import)

    p_diff = sub.add_parser("diff", help="compare two scans")
    p_diff.add_argument("scan1", type=int)
    p_diff.add_argument("scan2", type=int)
    p_diff.set_defaults(func=cmd_diff)

    # cve
    p_cve = sub.add_parser("cve-update", help="manual CVE update")
    p_cve.add_argument("--target")
    p_cve.set_defaults(func=cmd_cve_update)

    p_cves = sub.add_parser("cve-scan", help="scan target tech for CVEs")
    p_cves.add_argument("target")
    p_cves.add_argument("--critical", action="store_true")
    p_cves.add_argument("--cve")
    p_cves.set_defaults(func=cmd_cve_scan)

    # verify / reject
    p_ver = sub.add_parser("verify", help="manually verify a finding")
    p_ver.add_argument("finding_id", type=int)
    p_ver.set_defaults(func=cmd_verify)

    p_rej = sub.add_parser("reject", help="mark a finding false-positive AND teach the filter")
    p_rej.add_argument("finding_id", type=int)
    p_rej.set_defaults(func=cmd_reject)

    # dork
    p_dork = sub.add_parser("dork", help="multi-engine dorking")
    p_dork.add_argument("target")
    p_dork.add_argument("--intents")
    p_dork.add_argument("--engines")
    p_dork.set_defaults(func=cmd_dork)

    # doctor / self-scan / scope-sync / agent / c2
    p_doc = sub.add_parser("doctor", help="diagnose environment, config and tools")
    p_doc.set_defaults(func=cmd_doctor)

    p_ss = sub.add_parser("self-scan", help="scan the repo for committed secrets")
    p_ss.add_argument("--root")
    p_ss.add_argument("--include-allowlisted", action="store_true")
    p_ss.set_defaults(func=cmd_self_scan)

    p_sec = sub.add_parser("secretscan", help="scan staged content (default), history, or tree for secrets")
    sec_mode = p_sec.add_mutually_exclusive_group()
    sec_mode.add_argument("--staged", action="store_true", help="scan the git index (default)")
    sec_mode.add_argument("--history", action="store_true", help="scan committed history across all refs")
    sec_mode.add_argument("--tree", nargs="?", const="", default=None, metavar="PATH",
                          help="scan the working tree (optional path; default: repo root)")
    p_sec.add_argument("--max-commits", type=int, default=0, help="limit history scan to N commits (0 = all)")
    p_sec.add_argument("--root", metavar="PATH", help="git repository to scan (default: current directory)")
    p_sec.add_argument("--allowlist", help="explicit exception file (default: .nexus-secret-allowlist)")
    p_sec.add_argument("--include-allowlisted", action="store_true", help="tree scan: ignore the fixture policy")
    p_sec.add_argument("--json", action="store_true")
    p_sec.set_defaults(func=cmd_secretscan)

    p_hooks = sub.add_parser("hooks", help="install/status/uninstall the pre-commit secret-scan hook")
    p_hooks.add_argument("action", choices=["install", "status", "uninstall"])
    p_hooks.add_argument("--repo", metavar="PATH", help="target repository (default: this checkout)")
    p_hooks.set_defaults(func=cmd_hooks)

    p_scope = sub.add_parser("scope-sync", help="import or auto-sync program scope into nexus.yaml")
    p_scope.add_argument("--domain", help="target domain (with --file)")
    p_scope.add_argument("--file", help="local program JSON (H1/Bugcrowd shape)")
    p_scope.add_argument("--platform", default="hackerone", choices=["hackerone", "bugcrowd"])
    p_scope.add_argument("--program", metavar="DOMAIN", help="auto-sync one configured target via its platform API")
    p_scope.add_argument("--all", action="store_true", help="auto-sync every target with a sync: block")
    p_scope.add_argument("--config")
    p_scope.add_argument("--dry-run", action="store_true")
    p_scope.set_defaults(func=cmd_scope_sync)

    p_ag = sub.add_parser("agent", help="plan-and-act agent over whitelisted actions")
    p_ag.add_argument("objective")
    p_ag.add_argument("--max-steps", type=int, default=5)
    p_ag.add_argument("--dry-run", action="store_true")
    p_ag.add_argument("--agent", help="named AI agent from nemesis.agents (default: 'default')")
    p_ag.set_defaults(func=cmd_agent)

    p_team = sub.add_parser("team", help="run the bounded multi-agent runtime on a task plan")
    p_team.add_argument("objective", nargs="?", default="", help="objective (used with the default plan)")
    p_team.add_argument("--target", default="", help="engagement target for the default plan + scope checks")
    p_team.add_argument("--plan", help="path to a JSON task plan [{id,role,action,target,depends_on}]")
    p_team.add_argument("--workers", type=int, default=2, help="max parallel workers")
    p_team.set_defaults(func=cmd_team)

    p_zap = sub.add_parser("zap", help="drive the OWASP ZAP adapter (health, passive/active scan, alerts)")
    p_zap.add_argument("--health", action="store_true", help="connection + version check")
    p_zap.add_argument("--capabilities", action="store_true", help="list adapter capabilities")
    p_zap.add_argument("--passive", metavar="URL", default="", help="run a passive (spider) job against URL")
    p_zap.add_argument("--active", metavar="URL", default="", help="run an ACTIVE scan against URL (needs --authorize-active)")
    p_zap.add_argument("--authorize-active", dest="authorize_active", action="store_true",
                       help="explicit authorization for intrusive active scanning")
    p_zap.add_argument("--domain", default="", help="engagement scope domain (default: target host)")
    p_zap.add_argument("--import-scan", dest="import_scan", type=int, default=0,
                       help="import collected findings into this scan id")
    p_zap.add_argument("--collect", action="store_true", help="collect alerts even if the job is not complete")
    p_zap.add_argument("--timeout", type=float, default=0.0, help="whole-job timeout seconds (0 = wait)")
    p_zap.add_argument("--poll", type=float, default=1.0, help="status poll interval seconds")
    p_zap.add_argument("--mock", action="store_true", help="offline deterministic dry run (no live ZAP)")
    p_zap.set_defaults(func=cmd_zap)

    p_c2 = sub.add_parser("c2", help="start the Discord/Telegram control bot")
    p_c2.set_defaults(func=cmd_c2)

    p_oa = sub.add_parser("openapi", help="ingest an OpenAPI/Swagger spec")
    p_oa.add_argument("--file", required=True)
    p_oa.add_argument("--base", help="base URL to materialise endpoint URLs")
    p_oa.set_defaults(func=cmd_openapi)

    p_srv = sub.add_parser("serve", help="run due schedules (daemon; --once for a single pass)")
    p_srv.add_argument("--interval", type=int, default=60)
    p_srv.add_argument("--once", action="store_true")
    p_srv.set_defaults(func=cmd_serve)

    p_gui = sub.add_parser("gui", help="serve the local web GUI (loopback, HTTP Basic auth)")
    p_gui.add_argument("--host", default="127.0.0.1", help="bind host (loopback by default)")
    p_gui.add_argument("--port", type=int, default=8080)
    p_gui.add_argument("--allow-remote", action="store_true",
                       help="allow binding a non-loopback host (not recommended)")
    p_gui.add_argument("--log-level", default="info")
    p_gui.set_defaults(func=cmd_gui)

    p_ret = sub.add_parser("retention", help="report scan folders older than N days (no deletion)")
    p_ret.add_argument("--days", type=int, default=30)
    p_ret.set_defaults(func=cmd_retention)

    p_mon = sub.add_parser("monitor", help="diff the current program list against the last snapshot")
    p_mon.add_argument("--file", help="programs JSON (else fetch via configured APIs)")
    p_mon.set_defaults(func=cmd_monitor)

    p_gql = sub.add_parser("graphql", help="analyze a GraphQL introspection result")
    p_gql.add_argument("--file", required=True)
    p_gql.set_defaults(func=cmd_graphql)

    p_draft = sub.add_parser("draft", help="render a submission draft for a finding")
    p_draft.add_argument("finding_id", type=int)
    p_draft.add_argument("--platform", default="generic",
                         choices=["hackerone", "bugcrowd", "intigriti", "generic"])
    p_draft.add_argument("--target", default="TARGET")
    p_draft.set_defaults(func=cmd_draft)

    # check-tools
    p_ct = sub.add_parser("check-tools", help="show installed/missing external tools")
    p_ct.set_defaults(func=cmd_check_tools)

    # ai
    p_ak = sub.add_parser("ai-keys", help="show AI key pool status (masked)")
    p_ak.set_defaults(func=cmd_ai_keys)

    p_ap = sub.add_parser("ai-providers", help="show AI providers, capabilities and support status")
    p_ap.set_defaults(func=cmd_ai_providers)

    p_art = sub.add_parser("ai-runtime", help="probe a local model runtime (Ollama/OpenAI-compatible)")
    p_art.add_argument("--provider", default="", help="provider to probe (default: all local runtimes)")
    p_art.set_defaults(func=cmd_ai_runtime)

    p_ask = sub.add_parser("ai-set-key", help="add an AI API key (multi-key failover)")
    p_ask.add_argument("--provider", required=True, choices=["openai", "glm", "deepseek", "gemini", "kimi", "openrouter", "custom"])
    p_ask.add_argument("--key", required=True)
    p_ask.set_defaults(func=cmd_ai_set_key)

    # update
    p_up = sub.add_parser("update", help="update framework and/or tools")
    p_up.add_argument("--all", action="store_true")
    p_up.add_argument("--tools-only", dest="tools_only", action="store_true")
    p_up.add_argument("--tools-update", dest="tools_update", action="store_true")
    p_up.set_defaults(func=cmd_update)

    return parser


def main(argv: list[str] | None = None) -> int:
    setup_logging()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 1
    except ScopeException as exc:
        print(f"scope error: {exc}", file=sys.stderr)
        return 1
    except NexusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
