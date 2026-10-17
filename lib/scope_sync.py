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


# --- automatic sync (roadmap E1) ------------------------------------------


def normalize_scope(entries: list[str]) -> list[str]:
    """Clean, de-duplicate and sort asset entries."""
    return sorted({_clean(e) for e in (entries or []) if _clean(e)})


def read_config_target_scope(domain: str, config_path: Path | None = None) -> tuple[list[str], list[str]]:
    """Return the (in_scope, out_of_scope) currently recorded for *domain*."""
    path = Path(config_path) if config_path else CONFIG_DIR / "nexus.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    raw = ((data.get("targets") or {}).get(domain) or {})
    return list(raw.get("in_scope") or []), list(raw.get("out_of_scope") or [])


def diff_scope(
    current_in: list[str], current_out: list[str], new_in: list[str], new_out: list[str]
) -> dict[str, list[str]]:
    """Compute added/removed entries between the config and a fresh pull."""
    ci, co = {_clean(e) for e in (current_in or []) if _clean(e)}, {_clean(e) for e in (current_out or []) if _clean(e)}
    ni, no = set(normalize_scope(new_in)), set(normalize_scope(new_out))
    return {
        "added_in_scope": sorted(ni - ci),
        "removed_in_scope": sorted(ci - ni),
        "added_out_of_scope": sorted(no - co),
        "removed_out_of_scope": sorted(co - no),
    }


def is_changed(drift: dict[str, list[str]]) -> bool:
    """True when any drift bucket is non-empty."""
    return any(drift.values())


def sync_program(
    domain: str,
    *,
    platform: str = "hackerone",
    handle: str = "",
    env: dict[str, Any] | None = None,
    session: Any = None,
    config_path: Path | None = None,
    username_env: str = "",
    token_env: str = "",
    apply: bool = True,
) -> dict[str, Any]:
    """Pull one program's published scope and reconcile it with the config.

    Failures are reported as ``skipped`` (never written as an empty scope).
    When *apply* is true the config is updated only if the scope actually
    changed (avoids needless backups/rewrites).
    """
    from lib.scope_providers import ScopeProviderError, fetch_program

    platform = str(platform or "hackerone").strip().lower()
    handle = handle or domain
    try:
        doc = fetch_program(
            platform, handle, env=env, session=session,
            username_env=username_env, token_env=token_env,
        )
        parsed = parse_h1_program(doc) if platform == "hackerone" else parse_bugcrowd_program(doc)
    except ScopeProviderError as exc:
        logger.warning("scope-sync: %s skipped: %s", domain, exc)
        return {"domain": domain, "platform": platform, "skipped": True, "error": str(exc)}

    new_in, new_out = normalize_scope(parsed["in_scope"]), normalize_scope(parsed["out_of_scope"])
    cur_in, cur_out = read_config_target_scope(domain, config_path)
    drift = diff_scope(cur_in, cur_out, new_in, new_out)
    report: dict[str, Any] = {
        "domain": domain, "platform": parsed.get("platform", platform),
        "name": parsed.get("name", ""), "in_scope": new_in, "out_of_scope": new_out,
        "changed": is_changed(drift), "drift": drift, "applied": False,
    }
    if apply and report["changed"]:
        apply_scope_to_config(domain, new_in, new_out, config_path=config_path)
        report["applied"] = True
    return report


def sync_targets(
    domains: list[str],
    *,
    config: Any,
    config_path: Path | None = None,
    session: Any = None,
    env: dict[str, Any] | None = None,
    apply: bool = True,
) -> dict[str, Any]:
    """Sync every named target that carries a ``sync:`` block in the config."""
    if env is None:
        env = dict(getattr(config, "env", {}) or {})
    targets = dict(getattr(config, "targets_section", {}) or {})
    reports: list[dict[str, Any]] = []
    for domain in domains:
        block = targets.get(domain) or {}
        sync = block.get("sync") or {}
        if not sync:
            reports.append({"domain": domain, "skipped": True, "error": "no sync block configured"})
            continue
        reports.append(sync_program(
            domain,
            platform=str(sync.get("platform", "hackerone")),
            handle=str(sync.get("handle") or domain),
            env=env,
            session=session,
            config_path=config_path,
            username_env=str(sync.get("username_env", "") or ""),
            token_env=str(sync.get("token_env", "") or ""),
            apply=apply,
        ))
    return {
        "programs": reports,
        "count": len(reports),
        "applied": sum(1 for r in reports if r.get("applied")),
        "changed": sum(1 for r in reports if r.get("changed")),
        "skipped": sum(1 for r in reports if r.get("skipped")),
    }
