"""Scope auto-sync (roadmap E1).

Parses a bug-bounty program's published scope (HackerOne / Bugcrowd JSON)
into NEXUS in-scope / out-of-scope entries and writes them into
``config/nexus.yaml`` under ``targets.<domain>`` (with a .bak backup).
Removes manual scope typing and the scope mistakes that come with it.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from lib.logger import get_logger
from lib.paths import CONFIG_DIR

logger = get_logger("scope_sync")

_ASSET_RE = re.compile(r"^[A-Za-z0-9.*_-]+(\.[A-Za-z0-9*_-]+)*$")


def _clean(asset: str) -> str:
    a = str(asset or "").strip().lower()
    a = re.sub(r"^https?://", "", a).rstrip("/")
    a = re.sub(r"^www\.", "", a)
    return a


def parse_h1_program(program: dict[str, Any]) -> dict[str, Any]:
    """Extract scope from a HackerOne program payload."""
    name = str(program.get("name") or program.get("handle") or "")
    in_scope: list[str] = []
    out_of_scope: list[str] = []
    scope = (program.get("attributes") or {}).get("scope") or program.get("scope") or {}
    items = scope.get("list") if isinstance(scope, dict) else scope
    for item in (items or []):
        asset = _clean(item.get("asset_identifier") or item.get("asset") or "")
        if not asset:
            continue
        if str(item.get("eligible_for_submission", True)) in ("False", "false", "0"):
            out_of_scope.append(asset)
        else:
            in_scope.append(asset)
    return {"name": name, "platform": "hackerone", "in_scope": sorted(set(in_scope)),
            "out_of_scope": sorted(set(out_of_scope))}


def parse_bugcrowd_program(program: dict[str, Any]) -> dict[str, Any]:
    """Extract scope from a Bugcrowd program payload."""
    name = str(program.get("name") or "")
    in_scope: list[str] = []
    out_of_scope: list[str] = []
    targets = program.get("targets") or {}
    if isinstance(targets, dict):
        for item in (targets.get("in_scope") or []):
            asset = _clean(item.get("target") or item.get("name") or "")
            if asset:
                in_scope.append(asset)
        for item in (targets.get("out_of_scope") or []):
            asset = _clean(item.get("target") or item.get("name") or "")
            if asset:
                out_of_scope.append(asset)
    return {"name": name, "platform": "bugcrowd", "in_scope": sorted(set(in_scope)),
            "out_of_scope": sorted(set(out_of_scope))}


def load_program_file(path: Path) -> dict[str, Any]:
    """Load a program JSON from disk (H1 or Bugcrowd shape)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "data" in data:            # H1 API envelope
        first = (data.get("data") or [{}])[0]
        return first if isinstance(first, dict) else data
    if isinstance(data, list) and data:
        return data[0]
    return data


def apply_scope_to_config(
    domain: str,
    in_scope: list[str],
    out_of_scope: list[str],
    config_path: Path | None = None,
) -> dict[str, Any]:
    """Write in/out-of-scope for *domain* into nexus.yaml (with backup)."""
    path = Path(config_path) if config_path else CONFIG_DIR / "nexus.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    path.with_suffix(".yaml.bak").write_text(path.read_text(encoding="utf-8"), encoding="utf-8")

    targets = data.setdefault("targets", {})
    entry = targets.setdefault(domain, {})
    entry["in_scope"] = list(in_scope)
    entry["out_of_scope"] = list(out_of_scope)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    logger.info("scope-sync: %s → %d in-scope, %d out-of-scope", domain, len(in_scope), len(out_of_scope))
    return {"domain": domain, "in_scope": in_scope, "out_of_scope": out_of_scope, "config": str(path)}
