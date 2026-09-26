"""Methodology checklists + change alerts (build-spec features 46/47/80).

Loads ``config/methodologies.yaml``; tracks which checklist items a scan
covered; compares the current methodology to the previous scan and
raises a change alert when the checklist drifts.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml

from lib.logger import get_logger
from lib.paths import CONFIG_DIR

logger = get_logger("methodology")

DEFAULT_METHODOLOGIES = CONFIG_DIR / "methodologies.yaml"


def load_methodologies(path: Path | None = None) -> dict[str, Any]:
    p = path or DEFAULT_METHODOLOGIES
    if not p.exists():
        return {"methodologies": {}}
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {"methodologies": {}}


def methodology_hash(methodology: dict[str, Any]) -> str:
    """Stable hash of a methodology definition (for drift detection)."""
    blob = json.dumps(methodology, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def coverage(methodology: dict[str, Any], tools_run: list[str]) -> dict[str, Any]:
    """Compute checklist coverage given the tools that ran."""
    ran = {t.lower() for t in tools_run}
    items_total = 0
    items_covered = 0
    detail: list[dict[str, Any]] = []
    for section in methodology.get("sections", []) or []:
        for item in section.get("items", []) or []:
            items_total += 1
            item_tools = {str(t).lower() for t in (item.get("tools") or [])}
            covered = bool(item_tools & ran)
            if covered:
                items_covered += 1
            detail.append({
                "id": item.get("id"),
                "title": item.get("title"),
                "covered": covered,
            })
    pct = round(100.0 * items_covered / items_total, 1) if items_total else 0.0
    return {"items_total": items_total, "items_covered": items_covered, "percent": pct, "detail": detail}


def check_drift(current_hash: str, previous_metrics_path: Path) -> dict[str, Any]:
    """Compare the current methodology hash against a previous scan."""
    if not previous_metrics_path.exists():
        return {"drift": False, "reason": "no previous scan"}
    try:
        prev = json.loads(previous_metrics_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"drift": False, "reason": "previous metrics unreadable"}
    prev_hash = str(prev.get("methodology_hash", ""))
    if prev_hash and prev_hash != current_hash:
        return {"drift": True, "reason": f"methodology changed ({prev_hash} → {current_hash})"}
    return {"drift": False, "reason": "unchanged"}
