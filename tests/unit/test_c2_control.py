"""Unit tests for the C2 control plane (auth, confirm, audit, actions)."""
from __future__ import annotations

import json
from pathlib import Path

from phases.control.c2_actions import build_actions
from phases.control.c2_commands import C2Router, CONFIRM_REQUIRED


def _router(owner="OWNER", db=None, tmp_cfg=None, audit=None):
    actions = build_actions(tmp_cfg, db=db)
    return C2Router(owner_id=owner, actions=actions, audit_path=audit)


def test_unauthorized_rejected_and_audited(tmp_cfg, db, tmp_path):
    audit = tmp_path / "c2.jsonl"
    router = _router(owner="OWNER", db=db, tmp_cfg=tmp_cfg, audit=audit)
    outcome = router.handle("INTRUDER", "/nexus status")
    assert outcome.ok is False and outcome.output == "unauthorized"
    records = [json.loads(l) for l in audit.read_text(encoding="utf-8").splitlines()]
    assert records[0]["ok"] is False


def test_destructive_requires_confirm(tmp_cfg, db, tmp_path):
    router = _router(owner="OWNER", db=db, tmp_cfg=tmp_cfg, audit=tmp_path / "a.jsonl")
    # Without confirm token → rejected.
    outcome = router.handle("OWNER", "/nexus remove-target example.com")
    assert outcome.ok is False and "confirm" in outcome.output
    # With confirm → allowed.
    db.upsert_target("example.com")
    outcome = router.handle("OWNER", "/nexus remove-target example.com confirm")
    assert outcome.ok is True


def test_add_and_remove_target(db, tmp_cfg, tmp_path):
    router = _router(owner="OWNER", db=db, tmp_cfg=tmp_cfg, audit=tmp_path / "a.jsonl")
    assert router.handle("OWNER", "/nexus add-target acme.com").ok is True
    assert db.get_target("acme.com") is not None
    router.handle("OWNER", "/nexus remove-target acme.com confirm")
    assert db.get_target("acme.com")["config"] and "disabled" in db.get_target("acme.com")["config"]


def test_schedule_management(db, tmp_cfg, tmp_path):
    router = _router(owner="OWNER", db=db, tmp_cfg=tmp_cfg, audit=tmp_path / "a.jsonl")
    router.handle("OWNER", "/nexus add-schedule nightly acme.com '0 2 * * *'")
    names = [s["name"] for s in db.list_schedules()]
    assert "nightly" in names
    router.handle("OWNER", "/nexus remove-schedule nightly confirm")
    assert db.list_schedules()[0]["enabled"] == 0


def test_confirm_set_is_complete():
    assert CONFIRM_REQUIRED == {"remove-target", "remove-schedule", "stop"}


def test_unknown_action_returns_error(tmp_cfg, db, tmp_path):
    router = _router(owner="OWNER", db=db, tmp_cfg=tmp_cfg, audit=tmp_path / "a.jsonl")
    outcome = router.handle("OWNER", "/nexus frobnicate")
    assert outcome.ok is False and "no handler" in outcome.output


def test_status_and_logs_smoke(tmp_cfg, db, tmp_path):
    router = _router(owner="OWNER", db=db, tmp_cfg=tmp_cfg, audit=tmp_path / "a.jsonl")
    assert router.handle("OWNER", "/nexus status").ok is True
    assert router.handle("OWNER", "/nexus logs").ok is True
