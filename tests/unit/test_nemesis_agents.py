"""NEMESIS Alpha — loop (Phase C) + team (Phase D) tests."""
from __future__ import annotations

import pytest

from core import lifecycle
from lib.config import load_config
from lib.paths import CONFIG_DIR
from lib.ops_guard import KillSwitch
from lib.nemesis.loop import NemesisLoop
from lib.nemesis.memory import EngagementMemory
from lib.nemesis.team import NemesisTeam


def _cfg():
    return load_config(CONFIG_DIR)


def _actions():
    calls = {"status": 0}
    actions = {
        "status": lambda step: calls.__setitem__("status", calls["status"] + 1)
        or {"changed": "checked status"},
    }
    return calls, actions


# --- loop -----------------------------------------------------------------------

def test_loop_plan_act_observe_verify_report(db, tmp_path):
    calls, actions = _actions()
    loop = NemesisLoop(_cfg(), db=db, actions=actions, killswitch=KillSwitch(tmp_path))
    out = loop.run_cycle("check status please", "alpha.com")
    assert out["status"] == "ok"
    assert calls["status"] == 1
    assert out["contract_ok"] is True
    assert out["session"]["state"] == "completed"
    assert EngagementMemory(db, "alpha.com").recall("tool_results")


def test_loop_contract_requires_evidence_for_verification(db, tmp_path):
    actions = {"status": lambda step: {"verified": True}}  # claims verification, no evidence
    loop = NemesisLoop(_cfg(), db=db, actions=actions, killswitch=KillSwitch(tmp_path))
    out = loop.run_cycle("check status", "beta.com")
    assert out["contract_ok"] is False
    assert any("evidence" in i for i in out["contract_issues"])


def test_loop_killswitch_blocks(db, tmp_path):
    ks = KillSwitch(tmp_path)
    ks.kill()
    loop = NemesisLoop(_cfg(), db=db, actions={"status": lambda s: {}}, killswitch=ks)
    out = loop.run_cycle("check status", "alpha.com")
    assert out["status"] == "blocked"


def test_loop_resumes_without_repeating(db, tmp_path):
    calls, actions = _actions()
    loop = NemesisLoop(_cfg(), db=db, actions=actions, killswitch=KillSwitch(tmp_path))
    loop.run_cycle("check status", "alpha.com")
    assert calls["status"] == 1

    second = loop.run_cycle("check status", "alpha.com")
    assert calls["status"] == 1  # completed step skipped on resume
    assert second["session"]["completed_actions"] == ["status:"]


# --- team ------------------------------------------------------------------------

def _seed_finding(db):
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid)
    fid = db.insert_finding(sid, "https://example.com/a", "xss", "P2", 90)
    return sid, fid


def test_team_sequential_flow_with_validation(db):
    sid, fid = _seed_finding(db)
    lifecycle.transition(db, fid, "probable", actor="filter")
    ev = db.insert_evidence(sid, url="https://example.com/a", response_body="proof", finding_id=fid)

    roles = {
        "recon": lambda task, ctx: [{"asset": "sub.example.com"}],
        "analysis": lambda task, ctx: [{"finding_id": fid, "evidence_id": ev}],
        "validation": lambda item, ctx: {
            "finding_id": item["finding_id"], "verdict": "validated",
            "evidence_id": item.get("evidence_id"),
        },
        "reporting": lambda payload, ctx: {"summary": f"{len(payload['validated'])} validated"},
    }
    out = NemesisTeam(db, roles=roles).run({"objective": "validate"}, {"actor": "operator"})
    assert [v["state"] for v in out["validated"]] == ["validated"]
    assert out["held"] == []
    assert out["merged_evidence"] == 1
    assert out["report"]["summary"] == "1 validated"
    assert lifecycle.current_state(db, fid) == "validated"


def test_team_cannot_validate_without_evidence(db):
    _sid, fid = _seed_finding(db)
    lifecycle.transition(db, fid, "probable", actor="filter")
    roles = {
        "analysis": lambda task, ctx: [{"finding_id": fid}],
        "validation": lambda item, ctx: {"finding_id": item["finding_id"], "verdict": "validated"},
    }
    out = NemesisTeam(db, roles=roles).run({"objective": "validate"}, {"actor": "operator"})
    assert out["validated"] == []
    assert out["held"] and "evidence" in out["held"][0]["error"]
    assert lifecycle.current_state(db, fid) == "probable"  # never promoted


def test_team_rejects_through_lifecycle(db):
    _sid, fid = _seed_finding(db)
    lifecycle.transition(db, fid, "probable", actor="filter")
    roles = {
        "analysis": lambda task, ctx: [{"finding_id": fid}],
        "validation": lambda item, ctx: {
            "finding_id": item["finding_id"], "verdict": "rejected", "reason": "fp",
        },
    }
    NemesisTeam(db, roles=roles).run({"objective": "x"}, {})
    assert lifecycle.current_state(db, fid) == "rejected"


def test_team_rejects_unknown_roles(db):
    with pytest.raises(ValueError):
        NemesisTeam(db, roles={"hacker": lambda task, ctx: []})


def test_team_parallel_runs_independent_roles(db):
    roles = {
        "recon": lambda task, ctx: [{"a": 1}],
        "analysis": lambda task, ctx: [{"b": 2}],
    }
    out = NemesisTeam(db, roles=roles, parallel=True).run({"objective": "x"}, {})
    assert sorted(out["results"]) == ["analysis", "recon"]
