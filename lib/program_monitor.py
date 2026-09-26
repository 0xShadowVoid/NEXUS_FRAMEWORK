"""Program monitor (roadmap E3) — detect new/changed/removed programs.

Compares the current program list against a persisted snapshot and
reports differences (new programs, scope/payout changes, removals).
Read-only; state is stored as JSON under the results base directory.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lib.logger import get_logger

logger = get_logger("program_monitor")

STATE_NAME = ".programs_state.json"


def _signature(program: dict[str, Any]) -> tuple[str, str, str]:
    """A stable identity + changeable-fields signature for a program."""
    name = str(program.get("name", ""))
    platform = str(program.get("platform", ""))
    scope = ",".join(sorted(str(s) for s in (program.get("in_scope") or [])))
    ptype = str(program.get("type", ""))
    return (f"{platform}:{name}", scope, ptype)


def diff_programs(previous: list[dict[str, Any]], current: list[dict[str, Any]]) -> dict[str, Any]:
    """Return new / changed / removed programs between two snapshots."""
    prev = {_signature(p)[0]: _signature(p) for p in previous}
    curr = {_signature(p)[0]: _signature(p) for p in current}
    new = [name for name in curr if name not in prev]
    removed = [name for name in prev if name not in curr]
    changed = [name for name in curr if name in prev and prev[name] != curr[name]]
    return {
        "new": sorted(new),
        "removed": sorted(removed),
        "changed": sorted(changed),
    }


class ProgramMonitor:
    """Persisted program-diff monitor."""

    def __init__(self, base_dir: Path):
        self.path = Path(base_dir) / STATE_NAME

    def load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []

    def save(self, programs: list[dict[str, Any]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(programs, indent=2, default=str), encoding="utf-8")

    def check(self, programs: list[dict[str, Any]]) -> dict[str, Any]:
        """Diff against the stored snapshot, then store the new one."""
        previous = self.load()
        diff = diff_programs(previous, programs)
        self.save(programs)
        logger.info("program monitor: %d new, %d changed, %d removed",
                    len(diff["new"]), len(diff["changed"]), len(diff["removed"]))
        return diff
