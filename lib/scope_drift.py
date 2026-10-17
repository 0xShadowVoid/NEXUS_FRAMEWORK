"""Scope-drift alerting (roadmap E3).

Turns the diff produced by :mod:`lib.scope_sync` into structured drift
events and delivers notifications through the notification channels NEXUS
already implements (Discord webhook, Telegram bot, SMTP).

Design rules:

* A provider error (auth / transport / malformed / unavailable) is never
  interpreted as an empty scope or a scope removal: skipped programs
  produce no drift event.
* Notifications are strictly best-effort and kept separate from the
  authoritative sync result: a failed delivery never changes what was
  applied, and it is reported in its own ``notifications`` block.
* Re-syncing an unchanged drift does not re-alert (per-target signature
  dedupe), and an alert never broadens authorized scope by itself.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lib.logger import get_logger
from lib.paths import RESULTS_BASE
from lib.redaction import redact_text

logger = get_logger("scope_drift")

DEFAULT_STATE_NAME = ".scope_drift_state.json"
EVENT_NAME = "scope_drift"

ADD_BUCKETS = ("added_in_scope", "added_out_of_scope")
REMOVE_BUCKETS = ("removed_in_scope", "removed_out_of_scope")


# --- state ------------------------------------------------------------------


def _state_path(results_base: Path | None = None) -> Path:
    base = Path(results_base) if results_base else RESULTS_BASE
    return base / DEFAULT_STATE_NAME


def load_state(results_base: Path | None = None) -> dict[str, str]:
    """Load the per-target drift signature map (tolerant of corruption)."""
    try:
        data = json.loads(_state_path(results_base).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}


def save_state(state: dict[str, str], results_base: Path | None = None) -> bool:
    """Persist the drift signature map; returns False on failure."""
    path = _state_path(results_base)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state, indent=2, sort_keys=True), encoding="utf-8")
        return True
    except OSError as exc:
        logger.warning("could not persist drift state: %s", redact_text(exc))
        return False


# --- structured events ------------------------------------------------------


def build_events(result: dict[str, Any], *, timestamp: str | None = None) -> list[dict[str, Any]]:
    """Build structured drift events from a sync_program/sync_targets result.

    Only programs that actually changed are represented. Skipped programs
    (provider failures) and unchanged programs yield no event.
    """
    programs = result.get("programs")
    if programs is None:
        programs = [result] if result.get("domain") else []
    events: list[dict[str, Any]] = []
    for program in programs:
        event = _program_event(program, timestamp=timestamp)
        if event is not None:
            events.append(event)
    return events


def _program_event(program: dict[str, Any], *, timestamp: str | None) -> dict[str, Any] | None:
    if not program or program.get("skipped") or not program.get("changed"):
        return None
    drift = program.get("drift") or {}
    if not any(drift.values()):
        return None
    added = {bucket: list(drift.get(bucket) or []) for bucket in ADD_BUCKETS}
    removed = {bucket: list(drift.get(bucket) or []) for bucket in REMOVE_BUCKETS}
    n_added = sum(len(v) for v in added.values())
    n_removed = sum(len(v) for v in removed.values())
    if n_added and n_removed:
        direction = "mixed"
    elif n_added:
        direction = "added"
    else:
        direction = "removed"
    return {
        "event": EVENT_NAME,
        "target": str(program.get("domain", "")),
        "provider": str(program.get("platform", "")),
        "direction": direction,
        "added": added,
        "removed": removed,
        "counts": {"added": n_added, "removed": n_removed},
        "applied": bool(program.get("applied")),
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def drift_signature(event: dict[str, Any]) -> str:
    """Stable signature of the drift content (ignores timestamp/applied)."""
    payload = {
        "target": event.get("target", ""),
        "provider": event.get("provider", ""),
        "added": event.get("added", {}),
        "removed": event.get("removed", {}),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def filter_new(
    events: list[dict[str, Any]], state: dict[str, str]
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Return ``(new_events, state_with_new_signatures)``.

    An event whose signature already matches the stored one for its target
    is dropped, so re-syncing unchanged drift does not re-alert.
    """
    new_events: list[dict[str, Any]] = []
    updated = dict(state)
    for event in events:
        target = str(event.get("target", ""))
        signature = drift_signature(event)
        if updated.get(target) == signature:
            continue
        new_events.append(event)
        updated[target] = signature
    return new_events, updated


def format_event(event: dict[str, Any]) -> tuple[str, str]:
    """Render an event as a ``(title, body)`` pair, fully redacted."""
    target = str(event.get("target") or "?")
    provider = str(event.get("provider") or "?")
    counts = event.get("counts") or {}
    title = f"Scope drift on {target} ({event.get('direction', 'changed')})"
    lines = [
        f"Provider: {provider}",
        f"Added: {counts.get('added', 0)} | Removed: {counts.get('removed', 0)}",
    ]
    for bucket, entries in (event.get("added") or {}).items():
        if entries:
            lines.append(f"+ {bucket}: {', '.join(entries)}")
    for bucket, entries in (event.get("removed") or {}).items():
        if entries:
            lines.append(f"- {bucket}: {', '.join(entries)}")
    lines.append("Review this change; authorized scope is never broadened automatically.")
    return redact_text(title), redact_text("\n".join(lines))


# --- delivery ---------------------------------------------------------------


def dispatch(
    events: list[dict[str, Any]],
    *,
    notifier: Any,
    channels: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Send drift alerts; returns a delivery report. Never raises.

    Only the channels already implemented by NEXUS are used. Delivery
    failures are captured here so they cannot affect the sync result.
    """
    channels = channels or {}
    use_discord = bool(channels.get("discord", True))
    use_telegram = bool(channels.get("telegram", True))
    use_email = bool(channels.get("email", False))
    report: dict[str, Any] = {
        "sent": 0, "failed": 0,
        "channels": {"discord": 0, "telegram": 0, "email": 0},
        "delivered_targets": {},
    }
    for event in events:
        title, body = format_event(event)
        delivered = False
        if use_discord:
            try:
                if notifier.send_info_alert(title, body):
                    report["channels"]["discord"] += 1
                    delivered = True
            except Exception as exc:  # delivery must never propagate
                logger.warning("discord drift alert failed: %s", redact_text(exc))
        if use_telegram:
            try:
                if notifier.send_info_telegram(f"NEXUS: {title}", body):
                    report["channels"]["telegram"] += 1
                    delivered = True
            except Exception as exc:
                logger.warning("telegram drift alert failed: %s", redact_text(exc))
        if use_email:
            try:
                if _email_notify(channels, title, body):
                    report["channels"]["email"] += 1
                    delivered = True
            except Exception as exc:
                logger.warning("email drift alert failed: %s", redact_text(exc))
        if delivered:
            report["sent"] += 1
            report["delivered_targets"][str(event.get("target", ""))] = drift_signature(event)
        else:
            report["failed"] += 1
    return report


def _email_notify(channels: dict[str, Any], title: str, body: str) -> bool:
    alerter = channels.get("_email_alerter")
    if alerter is None:
        return False
    return bool(alerter.send(f"NEXUS: {title}", body))


# --- orchestration ----------------------------------------------------------


def notify_config(cfg: Any) -> dict[str, Any]:
    """Read ``scope_sync.notify`` from config; {} when unavailable."""
    try:
        return dict(cfg.scope_notify() or {})
    except Exception:
        return {}


def _build_notifier(cfg: Any) -> Any:
    from lib.notifications import Notifier

    return Notifier(cfg)


def alert_on_result(
    result: dict[str, Any],
    *,
    cfg: Any = None,
    notify: bool = False,
    dry_run: bool = False,
    results_base: Path | None = None,
    notifier: Any = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Emit/deliver drift alerts for a sync result, as a separate report.

    Dry runs only preview events: no send, no state write. Skips silently
    when notifications are disabled and ``notify`` is false.
    """
    events = build_events(result, timestamp=timestamp)
    config = notify_config(cfg)
    if dry_run:
        return {"enabled": False, "dry_run": True, "events": len(events),
                "new_events": 0, "sent": 0, "failed": 0, "preview": events}
    if not (notify or config.get("enabled")):
        return {"enabled": False, "events": len(events),
                "new_events": 0, "sent": 0, "failed": 0}
    if notifier is None and cfg is not None:
        try:
            notifier = _build_notifier(cfg)
        except Exception as exc:
            logger.warning("notifier unavailable: %s", redact_text(exc))
            notifier = None
    if notifier is None:
        return {"enabled": True, "events": len(events),
                "new_events": 0, "sent": 0, "failed": len(events),
                "error": "notification channel unavailable"}
    state = load_state(results_base)
    new_events, _updated = filter_new(events, state)
    channels: dict[str, Any] = dict(config)
    if config.get("email") and cfg is not None:
        try:
            from lib.notifications import EmailAlerter

            channels["_email_alerter"] = EmailAlerter(cfg)
        except Exception as exc:
            logger.warning("email channel unavailable: %s", redact_text(exc))
            channels["email"] = False
    delivery = dispatch(new_events, notifier=notifier, channels=channels)
    if delivery["delivered_targets"]:
        state.update(delivery["delivered_targets"])
        save_state(state, results_base)
    return {
        "enabled": True,
        "events": len(events),
        "new_events": len(new_events),
        "sent": delivery["sent"],
        "failed": delivery["failed"],
    }
