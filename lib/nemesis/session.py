"""NEMESIS session continuity (Phase H).

A resumed session knows: engagement, phase, current plan, completed and
pending actions, evidence references, findings references, relevant
memory context and previous errors.

This layer stores AGENT session state only and *references* the scan
level data via ``scan_id`` — the existing NEXUS checkpoint/recovery
model is reused, never duplicated.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from lib.logger import get_logger

logger = get_logger("nemesis.session")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class NemesisSession:
    """Resumable NEMESIS session state (one per engagement)."""

    engagement: str
    phase: str = "understand"
    state: str = "running"          # running | completed | partial | failed | paused
    scan_id: int | None = None
    plan: list[dict[str, Any]] = field(default_factory=list)
    completed_actions: list[str] = field(default_factory=list)
    pending_actions: list[str] = field(default_factory=list)
    evidence_refs: list[Any] = field(default_factory=list)
    findings_refs: list[Any] = field(default_factory=list)
    previous_errors: list[str] = field(default_factory=list)
    updated_at: str = ""

    @staticmethod
    def action_sig(step: dict[str, Any]) -> str:
        return f"{step.get('action', '?')}:{step.get('target', '')}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement": self.engagement,
            "phase": self.phase,
            "state": self.state,
            "scan_id": self.scan_id,
            "plan": self.plan,
            "completed_actions": list(self.completed_actions),
            "pending_actions": list(self.pending_actions),
            "evidence_refs": list(self.evidence_refs),
            "findings_refs": list(self.findings_refs),
            "previous_errors": list(self.previous_errors),
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "NemesisSession":
        def _load(value: str) -> Any:
            try:
                return json.loads(value or "null")
            except (TypeError, ValueError):  # pragma: no cover - defensive
                return None

        return cls(
            engagement=str(row.get("engagement", "")),
            phase=str(row.get("phase") or "understand"),
            state=str(row.get("state") or "running"),
            scan_id=row.get("scan_id"),
            plan=_load(row.get("plan")) or [],
            completed_actions=_load(row.get("completed")) or [],
            pending_actions=_load(row.get("pending")) or [],
            evidence_refs=_load(row.get("evidence_refs")) or [],
            findings_refs=_load(row.get("findings_refs")) or [],
            previous_errors=_load(row.get("errors")) or [],
            updated_at=str(row.get("updated_at") or ""),
        )


def save_session(db: Any, session: NemesisSession) -> None:
    """Upsert the session row (insert or update — never delete)."""
    session.updated_at = _now()
    values = (
        session.phase,
        session.scan_id,
        session.state,
        json.dumps(session.plan, default=str),
        json.dumps(session.completed_actions),
        json.dumps(session.pending_actions),
        json.dumps(session.evidence_refs, default=str),
        json.dumps(session.findings_refs, default=str),
        json.dumps(session.previous_errors),
        session.updated_at,
    )
    row = db.query(
        "SELECT id FROM nemesis_sessions WHERE engagement = ?",
        (str(session.engagement).strip().lower(),),
    )
    if row:
        db.execute(
            "UPDATE nemesis_sessions SET phase=?, scan_id=?, state=?, plan=?, completed=?, pending=?,"
            " evidence_refs=?, findings_refs=?, errors=?, updated_at=? WHERE id=?",
            values + (row[0]["id"],),
        )
        return
    db.execute(
        "INSERT INTO nemesis_sessions (engagement, phase, scan_id, state, plan, completed, pending,"
        " evidence_refs, findings_refs, errors, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (str(session.engagement).strip().lower(),) + values,
    )


def load_session(db: Any, engagement: str) -> NemesisSession | None:
    rows = db.query(
        "SELECT * FROM nemesis_sessions WHERE engagement = ?",
        (str(engagement).strip().lower(),),
    )
    if not rows:
        return None
    session = NemesisSession.from_row(rows[0])
    return session


def list_sessions(db: Any) -> list[dict[str, Any]]:
    return db.query("SELECT engagement, state, phase, updated_at FROM nemesis_sessions ORDER BY id")
