"""Pass 3B — finding lifecycle tests (single authoritative transitions)."""
from __future__ import annotations

import pytest
import yaml

from core import lifecycle
from core.coordinator import Coordinator
from core.database import Database


def _seed(db: Database, *, valid=None, reviewed=False, in_scope=1, vuln_type="xss",
          payload="", snippet=""):
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid)
    fid = db.insert_finding(sid, "https://example.com/a", vuln_type, "P2", 90,
                            payload=payload, response_snippet=snippet, valid=valid)
    if reviewed:
        db.mark_finding_reviewed(fid, True)
    if in_scope == 0:
        db.execute("UPDATE findings SET in_scope = 0 WHERE id = ?", (fid,))
    return sid, fid


def test_valid_transitions_flow(db):
    sid, fid = _seed(db)
    assert lifecycle.current_state(db, fid) == "candidate"

    lifecycle.transition(db, fid, "probable", actor="filter", reason="passed filters")
    assert lifecycle.current_state(db, fid) == "probable"

    ev = db.insert_evidence(sid, url="https://example.com/a", response_body="proof", finding_id=fid)
    lifecycle.transition(db, fid, "validated", actor="verifier", evidence_id=ev)
    assert lifecycle.current_state(db, fid) == "validated"

    row = db.query_findings(scan_id=sid)[0]
    assert row["valid"] == 1 and row["reviewed"] == 1  # legacy projection kept in sync

    trail = lifecycle.transitions_for(db, fid)
    assert [t["to_state"] for t in trail] == ["probable", "validated"]
    assert trail[0]["from_state"] == "candidate"
    assert trail[-1]["evidence_id"] == ev


def test_invalid_transitions_are_rejected_and_change_nothing(db):
    _, fid = _seed(db)
    with pytest.raises(lifecycle.InvalidTransition):
        lifecycle.transition(db, fid, "validated", actor="manual")  # candidate → validated
    assert lifecycle.current_state(db, fid) == "candidate"
    assert lifecycle.transitions_for(db, fid) == []

    with pytest.raises(lifecycle.InvalidTransition):
        lifecycle.transition(db, fid, "banana", actor="manual")  # unknown state

    lifecycle.transition(db, fid, "rejected", actor="filter")
    with pytest.raises(lifecycle.InvalidTransition):
        lifecycle.transition(db, fid, "probable", actor="manual")  # rejected is terminal
    with pytest.raises(lifecycle.InvalidTransition):
        lifecycle.transition(db, fid, "validated", actor="manual")  # rejected cannot validate


def test_rejection_from_candidate_and_probable(db):
    _, fid_a = _seed(db)
    lifecycle.transition(db, fid_a, "rejected", actor="filter", reason="disproved")
    assert lifecycle.current_state(db, fid_a) == "rejected"
    _, fid_b = _seed(db)
    lifecycle.transition(db, fid_b, "probable", actor="filter")
    lifecycle.transition(db, fid_b, "rejected", actor="manual", reason="FP")
    assert lifecycle.current_state(db, fid_b) == "rejected"


def test_validation_requires_evidence_for_automated_actors(db):
    sid, fid = _seed(db)
    lifecycle.transition(db, fid, "probable", actor="filter")
    with pytest.raises(lifecycle.InvalidTransition):
        lifecycle.transition(db, fid, "validated", actor="verifier")  # no evidence stored
    assert lifecycle.current_state(db, fid) == "probable"

    db.insert_evidence(sid, url="https://example.com/a", response_body="proof", finding_id=fid)
    result = lifecycle.transition(db, fid, "validated", actor="verifier")
    assert result["changed"] is True and result["evidence_id"] is not None


def test_ai_actor_cannot_validate(db):
    sid, fid = _seed(db)
    lifecycle.transition(db, fid, "probable", actor="filter")
    db.insert_evidence(sid, url="https://example.com/a", response_body="proof", finding_id=fid)
    with pytest.raises(lifecycle.InvalidTransition):
        lifecycle.transition(db, fid, "validated", actor="ai_analyzer")
    assert lifecycle.current_state(db, fid) == "probable"


def test_manual_review_may_validate_without_stored_evidence(db):
    _, fid = _seed(db)
    lifecycle.transition(db, fid, "probable", actor="filter")
    result = lifecycle.transition(db, fid, "validated", actor="manual", reason="checked in browser")
    assert result["changed"] is True and result["evidence_id"] is None
    reason = lifecycle.transitions_for(db, fid)[-1]["reason"]
    assert "manual validation without stored evidence" in reason


def test_out_of_scope_cannot_validate(db):
    _, fid = _seed(db, in_scope=0)
    lifecycle.transition(db, fid, "probable", actor="filter")
    with pytest.raises(lifecycle.InvalidTransition):
        lifecycle.transition(db, fid, "validated", actor="manual")


def test_legacy_mapping_backward_compatibility(db):
    _, fid_valid = _seed(db, valid=True)
    _, fid_reviewed = _seed(db, valid=True, reviewed=True)
    _, fid_fp = _seed(db, valid=False)
    assert lifecycle.current_state(db, fid_valid) == "probable"
    assert lifecycle.current_state(db, fid_reviewed) == "validated"
    assert lifecycle.current_state(db, fid_fp) == "rejected"


def test_seed_from_analysis_states(db):
    tid = db.upsert_target("seed.com")
    sid = db.create_scan(tid)
    cases = [
        ({"in_scope": False, "valid": False}, "rejected"),
        ({"in_scope": True, "valid": False, "fp_state": "FALSE_POSITIVE"}, "rejected"),
        ({"in_scope": True, "valid": True, "fp_state": "VALID"}, "probable"),
        ({"in_scope": True, "valid": None, "fp_state": "POTENTIAL"}, "candidate"),
    ]
    for finding, expected in cases:
        fid = db.insert_finding(sid, "https://seed.com/x", "xss", "P3", 70)
        state = lifecycle.seed_from_analysis(db, fid, finding)
        assert state == expected and lifecycle.current_state(db, fid) == expected


def test_transitions_are_audited(db):
    _, fid = _seed(db)
    lifecycle.transition(db, fid, "probable", actor="filter", reason="r1")
    events = db.list_audit_events(category="lifecycle")
    assert any(e["action"] == "finding.probable" for e in events)
    trail = lifecycle.transitions_for(db, fid)
    assert trail and trail[0]["actor"] == "filter" and trail[0]["ts"]


def test_persistence_and_reload(tmp_path):
    db1 = Database(tmp_path / "life.db")
    sid, fid = _seed(db1)
    lifecycle.transition(db1, fid, "probable", actor="filter")
    db1.close()

    db2 = Database(tmp_path / "life.db")  # reload; additive migration is idempotent
    assert lifecycle.current_state(db2, fid) == "probable"
    assert len(lifecycle.transitions_for(db2, fid)) == 1
    db2.close()


def test_manual_verification_uses_lifecycle(db):
    sid, fid = _seed(db)
    coord = Coordinator.__new__(Coordinator)
    coord.db = db
    out = coord.verify_finding(fid)
    assert out["status"] == "verified"
    assert lifecycle.current_state(db, fid) == "validated"
    trail = [t["to_state"] for t in lifecycle.transitions_for(db, fid)]
    assert trail == ["probable", "validated"]  # escalated, then validated
    assert db.query_findings(scan_id=sid)[0]["reviewed"] == 1


def test_reject_finding_uses_lifecycle_and_teaches_filter(db, tmp_path, monkeypatch):
    filters = tmp_path / "false_positive_filters.yaml"
    filters.write_text(
        yaml.safe_dump({"filters": {"xss": {"strictness": "aggressive",
                                           "confidence_threshold": 90, "auto_filter": []}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr("core.coordinator.CONFIG_DIR", tmp_path)
    sid, fid = _seed(db, snippet="FalsePositiveMarkerAlpha reflected here")
    coord = Coordinator.__new__(Coordinator)
    coord.db = db
    out = coord.reject_finding(fid)
    assert out["status"] == "rejected"
    assert lifecycle.current_state(db, fid) == "rejected"
    assert db.query_findings(scan_id=sid)[0]["valid"] == 0
    assert out.get("learned"), out
    persisted = yaml.safe_load(filters.read_text(encoding="utf-8"))
    assert "FalsePositiveMarkerAlpha" in (persisted["filters"]["xss"]["auto_filter"] or [])
