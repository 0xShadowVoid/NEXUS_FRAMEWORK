"""Concrete C2 actions bound to the framework (CONTROL phase).

Each action returns a short, chat-safe string. Actions are whitelisted
by name and never execute a shell — they call framework APIs directly.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from core.database import Database
from lib.config import Config
from lib.logger import get_logger
from lib.paths import LOGS_DIR

logger = get_logger("c2_actions")


def build_actions(cfg: Config, db: Database | None = None, scan_runner: Callable | None = None) -> dict[str, Callable[[list[str]], str]]:
    """Build the whitelisted action map used by the C2 router."""
    database = db or Database(cfg.database_path)

    def _arg(args: list[str], idx: int, default: str = "") -> str:
        return args[idx] if len(args) > idx else default

    def hunt(args: list[str]) -> str:
        target = _arg(args, 0)
        if not target:
            return "usage: /nexus hunt <target>"
        if scan_runner is not None:
            result = scan_runner({"target": target})
            return f"scan started: {target} ({result})"
        return f"scan queued: {target}"

    def stop(_args: list[str]) -> str:
        return "stop requested (current scan will halt at the next checkpoint)"

    def logs(args: list[str]) -> str:
        lines = int(_arg(args, 0, "20") or 20)
        path = LOGS_DIR / "nexus.log"
        if not path.exists():
            return "no logs available"
        try:
            content = path.read_text(encoding="utf-8", errors="replace").splitlines()
            return "\n".join(content[-lines:])
        except OSError as exc:
            return f"log read error: {exc}"

    def report(_args: list[str]) -> str:
        from lib.paths import REPO_ROOT

        reports = sorted((REPO_ROOT / "results").rglob("*-findings.md"), key=lambda p: p.stat().st_mtime, reverse=True)
        return str(reports[0]) if reports else "no reports yet"

    def status(_args: list[str]) -> str:
        targets = database.list_targets()
        scans = database.list_scans()
        schedules = database.list_schedules()
        return (f"targets={len(targets)} scans={len(scans)} "
                f"schedules={len(schedules)} enabled={len([s for s in schedules if s.get('enabled')])}")

    def add_target(args: list[str]) -> str:
        domain = _arg(args, 0)
        if not domain:
            return "usage: /nexus add-target <domain>"
        database.upsert_target(domain)
        database.set_target_disabled(domain, False)
        return f"target registered: {domain}"

    def remove_target(args: list[str]) -> str:
        domain = _arg(args, 0)
        if not domain:
            return "usage: /nexus remove-target <domain> confirm"
        ok = database.set_target_disabled(domain, True)
        return f"target disabled: {domain}" if ok else f"target not found: {domain}"

    def schedules(_args: list[str]) -> str:
        rows = database.list_schedules()
        if not rows:
            return "no schedules"
        return "; ".join(f"{r['name']}({r.get('intensity')},{'on' if r.get('enabled') else 'off'})" for r in rows)

    def add_schedule(args: list[str]) -> str:
        name, domain, cron = _arg(args, 0), _arg(args, 1), _arg(args, 2)
        if not (name and domain and cron):
            return "usage: /nexus add-schedule <name> <domain> <cron>"
        tid = database.upsert_target(domain)
        database.upsert_schedule(name=name, target_id=tid, frequency="custom", cron_expression=cron)
        return f"schedule added: {name} → {domain} ({cron})"

    def remove_schedule(args: list[str]) -> str:
        name = _arg(args, 0)
        if not name:
            return "usage: /nexus remove-schedule <name> confirm"
        ok = database.set_schedule_enabled(name, False)
        return f"schedule disabled: {name}" if ok else f"schedule not found: {name}"

    def cve_update(_args: list[str]) -> str:
        from lib.cve_workflow import run_cve_update

        summary = run_cve_update(cfg, database)
        return f"cve update: {summary}"

    return {
        "hunt": hunt,
        "stop": stop,
        "logs": logs,
        "report": report,
        "status": status,
        "cve-update": cve_update,
        "add-target": add_target,
        "remove-target": remove_target,
        "schedules": schedules,
        "add-schedule": add_schedule,
        "remove-schedule": remove_schedule,
    }
