"""Finding lifecycle — the single authoritative state-transition mechanism.

States (Pass 3B brief):

    candidate  → raw finding, not yet corroborated
    probable   → positive signals (filters/severity/corroboration)
    validated  → confirmed with supporting evidence (manual/verifier only)
    rejected   → disproved / false positive / out of scope (terminal)

Rules enforced here (all other modules go through ``transition``):

- only transitions listed in ``_ALLOWED`` are accepted; anything else raises
  ``InvalidTransition`` and changes nothing;
- every accepted transition is recorded in ``finding_transitions`` and in the
  shared ``audit_events`` table (actor, reason, evidence link, timestamp);
- ``validated`` requires supporting evidence — except explicit manual human
  confirmation (actor ``manual``/``cli``/``operator``), which is audited as
  such; automated actors (``verifier``/``filter``/``system``) need evidence;
- AI actors (``ai``, ``ai_analyzer``, ...) can never move a finding to
  ``validated`` — AI stays advisory;
- scope controls stay authoritative: out-of-scope findings cannot validate.

Backward compatibility: rows that predate the lifecycle (no transition rows)
derive their state from the legacy columns via ``derive_state_from_legacy``
(``reviewed=1`` → validated, ``valid=1`` → probable, ``valid=0`` → rejected,
else candidate). The legacy columns ``valid`` / ``reviewed`` stay in sync as a
projection; ``verified`` / ``corroborated`` / ``fp_state`` / ``fp_reason``
remain untouched.
"""
from __future__ import annotations

from typing import Any

from lib.logger import get_logger

logger = get_logger("lifecycle")

STATES = ("candidate", "probable", "validated", "rejected")

_ALLOWED: dict[str, frozenset[str]] = {
    "candidate": frozenset({"probable", "rejected"}),
    "probable": frozenset({"validated", "rejected"}),
    "validated": frozenset({"rejected"}),
    "rejected": frozenset(),
}

# Actors that may validate WITHOUT stored evidence (explicit human act).
MANUAL_ACTORS = frozenset({"manual", "cli", "operator"})
# Actors allowed to validate at all (never AI).
VALIDATING_ACTORS = MANUAL_ACTORS | {"verifier"}
_AI_PREFIX = "ai"


class InvalidTransition(ValueError):
    """Raised for any state change the lifecycle does not permit."""


def _ai_actor(actor: str) -> bool:
    return str(actor or "").strip().lower().startswith(_AI_PREFIX)


def _normalize(state: str) -> str:
    s = str(state or "").strip().lower()
    if s not in STATES:
        raise InvalidTransition(f"unknown lifecycle state: {state!r}")
    return s


def _utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def derive_state_from_legacy(row: dict[str, Any]) -> str:
    """Backward-compat: derive a state for rows with no lifecycle records."""
    if row.get("reviewed") == 1:
        return "validated"
    if row.get("valid") == 1:
        return "probable"
    if row.get("valid") == 0:
        return "rejected"
    return "candidate"


def current_state(db: Any, finding_id: int) -> str:
    """Latest recorded state; falls back to the legacy-column mapping."""
    rows = db.query(
        "SELECT to_state FROM finding_transitions WHERE finding_id = ? ORDER BY id DESC LIMIT 1",
        (finding_id,),
    )
    if rows:
        return _normalize(rows[0]["to_state"])
    frows = db.query("SELECT valid, reviewed FROM findings WHERE id = ?", (finding_id,))
    if not frows:
        raise InvalidTransition(f"finding {finding_id} not found")
    return derive_state_from_legacy(frows[0])


def transitions_for(db: Any, finding_id: int) -> list[dict[str, Any]]:
    """Full transition audit trail for one finding (oldest first)."""
    return db.query(
        "SELECT * FROM finding_transitions WHERE finding_id = ? ORDER BY id", (finding_id,)
    )


def _record(db, finding_id, from_state, to_state, actor, reason, evidence_id) -> None:
    db.execute(
        "INSERT INTO finding_transitions (finding_id, from_state, to_state, actor,"
        " reason, evidence_id, ts) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (finding_id, from_state, to_state, str(actor or ""),
         str(reason or "")[:300], evidence_id, _utc_now()),
    )
    db.insert_audit_event(
        actor=str(actor or ""),
        action=f"finding.{to_state}",
        category="lifecycle",
        detail=f"finding {finding_id}: {from_state} -> {to_state} {reason}".strip(),
    )


def _sync_legacy(db, finding_id, state) -> None:
    """Project the lifecycle state onto the legacy columns (kept, not deleted)."""
    if state == "validated":
        db.execute(
            "UPDATE findings SET valid = 1, reviewed = 1 WHERE id = ?", (finding_id,)
        )
    elif state == "probable":
        db.execute("UPDATE findings SET valid = 1 WHERE id = ?", (finding_id,))
    elif state == "rejected":
        db.execute("UPDATE findings SET valid = 0 WHERE id = ?", (finding_id,))


def _supporting_evidence_id(db, finding_id, evidence_id):
    """Resolve the evidence backing a validation (explicit id or latest stored)."""
    if evidence_id is not None:
        rows = db.query("SELECT id FROM evidence WHERE id = ?", (evidence_id,))
        if not rows:
            raise InvalidTransition(f"evidence {evidence_id} does not exist")
        return int(evidence_id)
    rows = db.query(
        "SELECT id FROM evidence WHERE finding_id = ? ORDER BY id DESC LIMIT 1", (finding_id,)
    )
    return int(rows[0]["id"]) if rows else None


def transition(
    db: Any,
    finding_id: int,
    to_state: str,
    *,
    actor: str = "system",
    reason: str = "",
    evidence_id: int | None = None,
) -> dict[str, Any]:
    """Single authoritative state change for ``finding_id``.

    Returns ``{finding_id, from_state, to_state, changed, evidence_id}``.
    Raises ``InvalidTransition`` for anything not permitted — and never
    changes any state when it raises.
    """
    to_state = _normalize(to_state)
    from_state = current_state(db, finding_id)
    if to_state == from_state:
        return {
            "finding_id": finding_id, "from_state": from_state, "to_state": to_state,
            "changed": False, "evidence_id": evidence_id,
        }
    if to_state not in _ALLOWED[from_state]:
        raise InvalidTransition(f"transition {from_state} -> {to_state} is not allowed")

    actor_s = str(actor or "").strip().lower()
    linked_evidence = None
    if to_state == "validated":
        if _ai_actor(actor_s):
            raise InvalidTransition("AI actors are advisory only and cannot validate findings")
        if actor_s not in VALIDATING_ACTORS:
            raise InvalidTransition(f"actor {actor!r} may not validate findings")
        rows = db.query("SELECT in_scope FROM findings WHERE id = ?", (finding_id,))
        if rows and rows[0].get("in_scope") == 0:
            raise InvalidTransition("out-of-scope findings cannot be validated")
        linked_evidence = _supporting_evidence_id(db, finding_id, evidence_id)
        if linked_evidence is None and actor_s not in MANUAL_ACTORS:
            raise InvalidTransition(
                "validation requires supporting evidence (or an explicit manual review)"
            )
        if linked_evidence is None:
            reason = (str(reason) + " | manual validation without stored evidence").strip(" |")

    _record(db, finding_id, from_state, to_state, actor, reason, linked_evidence)
    _sync_legacy(db, finding_id, to_state)
    logger.info("finding %s: %s -> %s (actor=%s)", finding_id, from_state, to_state, actor_s or "?")
    return {
        "finding_id": finding_id, "from_state": from_state, "to_state": to_state,
        "changed": True, "evidence_id": linked_evidence,
    }


def record_initial(db: Any, finding_id: int, actor: str = "pipeline") -> str:
    """Record the creation event (None → candidate) for a new finding."""
    _record(db, finding_id, None, "candidate", actor, "finding created", None)
    return "candidate"


def seed_from_analysis(db: Any, finding_id: int, finding: dict[str, Any]) -> str:
    """Create + auto-advance the lifecycle for a freshly persisted finding.

    candidate → probable   when the filter/scorer marked it valid;
    candidate → rejected   when out of scope / disproved / false positive.
    """
    record_initial(db, finding_id)
    if not finding.get("in_scope", True):
        return transition(db, finding_id, "rejected", actor="scope",
                          reason="out of scope")["to_state"]
    if finding.get("valid") is False or str(finding.get("fp_state") or "") == "FALSE_POSITIVE":
        return transition(db, finding_id, "rejected", actor="filter",
                          reason=str(finding.get("validity_reason") or "false-positive filter"))["to_state"]
    if finding.get("valid") is True:
        return transition(db, finding_id, "probable", actor="filter",
                          reason="passed false-positive filters")["to_state"]
    return "candidate"
