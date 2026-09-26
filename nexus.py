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

__version__ = "2.0.0"
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


def cmd_scope_sync(args: argparse.Namespace) -> int:
    from lib.scope_sync import (
        apply_scope_to_config,
        load_program_file,
        parse_bugcrowd_program,
        parse_h1_program,
    )

    program = load_program_file(Path(args.file))
    parsed = parse_h1_program(program) if args.platform == "hackerone" else parse_bugcrowd_program(program)
    if args.dry_run:
        print(json.dumps(parsed, indent=2, default=str))
        return 0
    result = apply_scope_to_config(
        args.domain, parsed["in_scope"], parsed["out_of_scope"],
        config_path=Path(args.config) if args.config else None,
    )
    print(json.dumps(result, indent=2, default=str))
    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    from lib.agent import ALLOWED_ACTIONS, NexusAgent
    from lib.ai_analyzer import AIAnalyzer

    cfg = load_config()
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
    import shutil as _shutil

    from phases.probe.tool_runner import TOOL_CATALOG

    status = {tool: bool(_shutil.which(tool)) for tool in sorted(TOOL_CATALOG)}
    installed = [t for t, ok in status.items() if ok]
    print(json.dumps({"installed": installed, "missing": [t for t in status if t not in installed]}, indent=2))
    return 0


def cmd_ai_keys(args: argparse.Namespace) -> int:
    from lib.ai_analyzer import AIAnalyzer

    cfg = load_config()
    analyzer = AIAnalyzer.from_config(cfg.ai, cfg.env)
    print(json.dumps({"status": analyzer.status_summary(), "keys": analyzer.key_status()}, indent=2, default=str))
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

    p_scope = sub.add_parser("scope-sync", help="import program scope into nexus.yaml")
    p_scope.add_argument("--domain", required=True)
    p_scope.add_argument("--file", required=True)
    p_scope.add_argument("--platform", default="hackerone", choices=["hackerone", "bugcrowd"])
    p_scope.add_argument("--config")
    p_scope.add_argument("--dry-run", action="store_true")
    p_scope.set_defaults(func=cmd_scope_sync)

    p_ag = sub.add_parser("agent", help="plan-and-act agent over whitelisted actions")
    p_ag.add_argument("objective")
    p_ag.add_argument("--max-steps", type=int, default=5)
    p_ag.add_argument("--dry-run", action="store_true")
    p_ag.set_defaults(func=cmd_agent)

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
