"""Data-retention REPORT (roadmap H5) — non-destructive.

Lists result folders older than N days and their sizes. Deletion is
intentionally left to the operator: this module never removes anything,
in line with the platform safety boundary (no destructive file APIs in
tooling). Use it to see *what would* be pruned, then clean up manually.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from lib.logger import get_logger
from lib.paths import RESULTS_BASE

logger = get_logger("retention")


def retention_report(base_dir: Path | None = None, days: int = 30) -> dict[str, Any]:
    """Return a report of scan folders older than *days* (nothing is deleted)."""
    root = Path(base_dir) if base_dir else RESULTS_BASE
    if not root.exists():
        return {"root": str(root), "candidates": [], "would_free_bytes": 0, "days": days}

    cutoff = time.time() - days * 86400
    candidates: list[dict[str, Any]] = []
    total = 0
    for child in sorted(root.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        try:
            size = sum(p.stat().st_size for p in child.rglob("*") if p.is_file())
            mtime = child.stat().st_mtime
        except OSError:
            continue
        if mtime < cutoff:
            candidates.append({
                "folder": child.name,
                "size_bytes": size,
                "age_days": round((time.time() - mtime) / 86400, 1),
            })
            total += size

    logger.info("retention report: %d candidate folder(s), %d bytes", len(candidates), total)
    return {
        "root": str(root),
        "candidates": candidates,
        "candidate_count": len(candidates),
        "would_free_bytes": total,
        "days": days,
        "note": "report only — NEXUS never deletes result folders automatically",
    }
