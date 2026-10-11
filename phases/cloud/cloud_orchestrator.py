"""CLOUD phase orchestrator (Pass 6) — read-only, scope-first posture checks.

Wiring on existing NEXUS primitives:

- authorization BEFORE any provider call: explicit provider selection,
  matching cloud scope entries (when present), and per-provider account
  allowlists (fail closed — never enumerate unintended accounts);
- read-only collection (providers.py), deterministic checks (engine.py);
- graph ingestion, Evidence Engine (redacted), finding lifecycle (candidates
  only — AI never validates), accurate phase statuses;
- budgets (one spend per API call), cancellation + kill switch;
- missing SDKs/credentials degrade with clear, non-crashing statuses.
"""
from __future__ import annotations

import fnmatch
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lib.config import Config, TargetConfig
from lib.filtration import FiltrationPipeline, normalize_asset
from lib.logger import get_logger
from lib.ops_guard import KillSwitch, spend_requests
from lib.scope_validator import is_cloud_asset
from phases.cloud.engine import CheckResult, redact, run_checks, summarize
from phases.cloud.providers import (
    AwsProvider,
    AzureProvider,
    CloudProviderError,
    GcpProvider,
)

logger = get_logger("cloud_orchestrator")

PROVIDERS = {"aws": AwsProvider, "azure": AzureProvider, "gcp": GcpProvider}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _settings_from_cfg(cfg: Config) -> dict[str, Any]:
    raw: dict[str, Any] = {}
    try:
        raw = ((cfg.phases or {}).get("cloud", {}) or {}) if cfg is not None else {}
    except Exception:  # pragma: no cover - defensive
        raw = {}
    accounts_raw = raw.get("accounts") or {}
    return {
        "providers": [str(p).strip().lower() for p in (raw.get("providers") or []) if str(p).strip()],
        "accounts": {
            str(k).strip().lower(): [str(x) for x in (v or [])]
            for k, v in accounts_raw.items()
        },
        "max_resources": max(1, min(int(raw.get("max_resources", 200) or 200), 2000)),
        "region": str(raw.get("region", "") or ""),
        "project": str(raw.get("project", "") or ""),
    }


def _provider_scope_ok(provider: str, cloud_entries: list[str]) -> bool:
    if not cloud_entries:
        return True  # scope_kind gate already authorized provider-level access
    for entry in cloud_entries:
        if entry in (f"cloud:{provider}",) or entry.startswith(f"cloud:{provider}"):
            return True
        if fnmatch.fnmatch(f"cloud:{provider}", entry):
            return True
    return False


def run_cloud(
    cfg: Config,
    target_config: TargetConfig,
    results_dir: Path,
    db: Any | None = None,
    scan_id: int | None = None,
    http_get: Any | None = None,
    clients: dict[str, Any] | None = None,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    """Run the scoped cloud posture assessment phase."""
    settings = _settings_from_cfg(cfg)
    results_dir = Path(results_dir)
    selected = [p for p in settings["providers"] if p in PROVIDERS]
    if not selected:
        return {
            "status": "blocked", "phase_state": "blocked",
            "reason": "no cloud providers configured (phases.cloud.providers)",
        }

    cloud_entries = [
        str(e).strip().lower()
        for e in (target_config.in_scope or [])
        if is_cloud_asset(str(e))
    ]

    killswitch = KillSwitch()
    cancel = cancel_event or threading.Event()

    def _cancelled() -> bool:
        return cancel.is_set() or killswitch.killed()

    provider_reports: list[dict[str, Any]] = []
    all_checks: list[CheckResult] = []
    evidence_count = 0
    finding_count = 0
    asset_links = 0
    blocked_reasons: list[str] = []
    skipped_reasons: list[str] = []

    for name in selected:
        cls = PROVIDERS[name]
        injected = (clients or {}).get(name)
        if not _provider_scope_ok(name, cloud_entries):
            blocked_reasons.append(f"{name}: no matching in-scope cloud entry")
            provider_reports.append({
                "provider": name, "status": "blocked",
                "reason": "no matching in-scope cloud entry",
            })
            continue
        if not cls.sdk_available() and not injected:
            skipped_reasons.append(f"{name}: SDK not installed")
            provider_reports.append({
                "provider": name, "status": "skipped",
                "reason": "SDK not installed (optional dependency)",
            })
            continue
        allowlist = settings["accounts"].get(name) or []
        if not allowlist:
            # Fail closed: never enumerate accounts without explicit authorization.
            blocked_reasons.append(f"{name}: account allowlist required")
            provider_reports.append({
                "provider": name, "status": "blocked",
                "reason": "account allowlist required (fail closed)",
            })
            continue

        provider = cls(settings={**settings, "accounts": allowlist}, clients=injected)
        try:
            # Phase 1 — identity ONLY: authorization precedes every other call.
            identity_section = provider.identity(spend=spend_requests)
        except CloudProviderError as exc:
            provider_reports.append({"provider": name, "status": "failed", "reason": str(exc)[:200]})
            continue
        identity = identity_section.get("data") or {}
        if identity_section.get("status") != "ok" or not str(identity.get("account", "")):
            if identity_section.get("status") == "skipped":
                skipped_reasons.append(f"{name}: cancelled before identity")
                provider_reports.append({
                    "provider": name, "status": "skipped",
                    "reason": "cancelled before identity verification",
                })
            else:
                detail = str(identity_section.get("reason") or "identity could not be verified")
                provider_reports.append({
                    "provider": name, "status": "failed",
                    "reason": f"identity could not be verified (fail closed): {detail}"[:240],
                })
            continue
        account = str(identity.get("account"))
        if account not in allowlist:
            blocked_reasons.append(f"{name}: identity not authorized")
            provider_reports.append({
                "provider": name, "status": "blocked",
                "reason": f"identity {account!r} is not in the authorized allowlist",
            })
            continue

        # Phase 2 — the account is authorized; collect the remaining sections.
        try:
            sections = provider.collect(
                cancel=_cancelled, spend=spend_requests,
                only=("storage", "network", "iam", "logging"),
            )
        except CloudProviderError as exc:
            provider_reports.append({"provider": name, "status": "failed", "reason": str(exc)[:200]})
            continue

        checks = run_checks(name, sections)
        all_checks.extend(checks)
        issues = [c for c in checks if c.status == "issue"]
        degraded = [
            c for c in checks
            if c.status in (
                "insufficient_permissions", "insufficient_credentials", "error", "skipped",
            )
        ]
        provider_status = "partial" if degraded else "completed"

        if db is not None and scan_id is not None:
            try:
                pipeline = FiltrationPipeline(db, target_config, scan_id)
                pipeline.ingest(
                    "cloud-engine", "cloud", [f"cloud:{name}:{account}"], kind="cloud",
                )
            except Exception as exc:
                logger.debug("cloud graph ingestion failed: %s", exc)

            for check in checks:
                if check.status not in ("issue", "ok"):
                    continue
                try:
                    eid = db.insert_evidence(
                        scan_id,
                        url=f"{name}://{account}/{redact(str(check.resource or check.check))}",
                        method="READ",
                        tool=f"cloud-{name}",
                        source="cloud",
                        response_body=json.dumps(check.to_dict(), default=str),
                    )
                    evidence_count += 1
                    for kind in ("cloud", "service", "subdomain", "host"):
                        asset = db.get_asset(kind, normalize_asset(kind, f"cloud:{name}:{account}"))
                        if asset:
                            if db.set_evidence_asset(eid, int(asset["id"])):
                                asset_links += 1
                            break
                    if check.status == "issue":
                        fid = db.insert_finding(
                            scan_id, redact(str(check.resource or name)), check.check,
                            check.severity or "P3", 80,
                            response_snippet=(check.detail or check.check)[:400],
                        )
                        from core import lifecycle as lifecycle_mod

                        lifecycle_mod.seed_from_analysis(
                            db, fid, {"in_scope": True, "valid": True, "fp_state": "VALID"}
                        )
                        try:
                            db.set_evidence_finding(eid, fid)
                        except Exception:
                            pass
                        finding_count += 1
                except Exception as exc:
                    logger.debug("cloud evidence/finding failed: %s", exc)

        provider_reports.append({
            "provider": name,
            "status": provider_status,
            "account": account,
            "checks": summarize(checks),
            "issues": [c.to_dict() for c in issues][:50],
        })

    statuses = [str(p.get("status")) for p in provider_reports]
    if not provider_reports or all(s == "blocked" for s in statuses):
        overall = "blocked"
    elif all(s == "skipped" for s in statuses):
        overall = "skipped"
    elif any(s in ("partial", "failed", "skipped", "blocked") for s in statuses):
        overall = "partial"
    else:
        overall = "completed"
    if _cancelled() and overall not in ("blocked", "skipped"):
        overall = "partial"          # cancellation always yields a partial phase
    if overall == "blocked" and not provider_reports:
        blocked_reasons.append("no runnable cloud providers")

    snapshot = {
        "target": target_config.domain,
        "generated": _now(),
        "providers": provider_reports,
        "checks": [c.to_dict() for c in all_checks],
        "blocked": blocked_reasons,
        "skipped": skipped_reasons,
    }
    snapshot_path = results_dir / "cloud" / "cloud.json"
    try:
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_text(
            json.dumps(redact(snapshot), indent=2, default=str), encoding="utf-8",
        )
    except OSError as exc:
        logger.warning("cloud snapshot write failed: %s", exc)

    hint = overall if overall in ("blocked", "skipped", "partial") else "completed"
    issue_count = len([c for c in all_checks if c.status == "issue"])
    return {
        "status": overall,
        "phase_state": hint,
        "providers": provider_reports,
        "checks": summarize(all_checks),
        "issues": issue_count,
        "evidence": evidence_count,
        "findings": finding_count,
        "asset_links": asset_links,
        "blocked": blocked_reasons[:10],
        "skipped": skipped_reasons[:10],
        "snapshot": str(snapshot_path),
        "reason": "; ".join((blocked_reasons or skipped_reasons or [overall])[:3]),
    }
