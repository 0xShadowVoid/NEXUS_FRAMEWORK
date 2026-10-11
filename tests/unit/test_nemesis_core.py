"""NEMESIS Alpha — memory / skills / contract / session tests."""
from __future__ import annotations

import pytest

from core.database import Database
from lib.config import load_config
from lib.paths import CONFIG_DIR
from lib.nemesis.contract import CompletionContract, build_from_run
from lib.nemesis.memory import EngagementMemory
from lib.nemesis.session import NemesisSession, list_sessions, load_session, save_session
from lib.nemesis.skills import SecuritySkill, SecuritySkillRegistry, validate_skill_tools


def _cfg():
    return load_config(CONFIG_DIR)


# --- memory -------------------------------------------------------------------

def test_memory_requires_engagement(db):
    with pytest.raises(ValueError):
        EngagementMemory(db, "")


def test_memory_roundtrip_and_isolation(db):
    a = EngagementMemory(db, "alpha.com")
    b = EngagementMemory(db, "beta.com")
    a.remember("technologies", "server", {"name": "nginx", "version": "1.24"})
    a.remember("endpoints", "admin", "/admin")
    b.remember("technologies", "server", {"name": "apache"})
    assert a.get("technologies", "server")["name"] == "nginx"
    assert b.get("technologies", "server")["name"] == "apache"
    assert len(a.recall("technologies")) == 1
    assert len(b.recall("technologies")) == 1


def test_memory_blocks_secrets(db):
    mem = EngagementMemory(db, "alpha.com")
    mem.remember("auth", "obs1", {
        "authorization": "Bearer secret-token-value-1234567890",
        "password": "hunter2",
        "note": "ok",
    })
    stored = mem.get("auth", "obs1")
    assert stored["password"] == "[REDACTED]"
    assert stored["authorization"] == "[REDACTED]"
    assert stored["note"] == "ok"


def test_memory_unknown_category_rejected(db):
    with pytest.raises(ValueError):
        EngagementMemory(db, "alpha.com").remember("not-a-category", "k", "v")


def test_memory_hypothesis_reject_flow(db):
    mem = EngagementMemory(db, "alpha.com")
    mem.remember("hypotheses", "h1", "possible IDOR on /api/users")
    mem.remember("hypotheses", "h2", "possible XSS")
    mem.reject_hypothesis("h2", "payload escaped")
    assert [h["key"] for h in mem.hypotheses()] == ["h1"]


def test_memory_survives_reload(tmp_path):
    db1 = Database(tmp_path / "mem.db")
    EngagementMemory(db1, "alpha.com").remember("decisions", "d1", {"decision": "skip brute"})
    db1.close()
    db2 = Database(tmp_path / "mem.db")
    assert EngagementMemory(db2, "alpha.com").get("decisions", "d1")["decision"] == "skip brute"
    db2.close()


# --- skills --------------------------------------------------------------------

def test_skill_registry_loads_and_disabled_by_default():
    reg = SecuritySkillRegistry()
    names = reg.names()
    assert "idor" in names and "jwt" in names and "recon" in names
    assert reg.enabled(_cfg()) == []          # nothing auto-enabled


def test_skill_gate():
    reg = SecuritySkillRegistry()
    cfg = _cfg()
    ok, reason = reg.gate("idor", cfg)
    assert not ok and "not enabled" in reason

    cfg._main["nemesis"] = {"skills": {"enabled": ["idor"]}}
    ok_scope, reason2 = reg.gate("idor", cfg)
    assert not ok_scope and "scope" in reason2

    ok2, reason3 = reg.gate("idor", cfg, target_config=cfg.target("example.com"))
    assert ok2 and reason3 == "ok"

    ok_unknown, _ = reg.gate("nope", cfg, target_config=cfg.target("example.com"))
    assert not ok_unknown


def test_skill_tool_validation_flags_unknown():
    reg = SecuritySkillRegistry()
    skill = reg.get("idor")
    assert skill is not None
    out = validate_skill_tools(skill, reg.tool_registry)
    assert out["known"] and not out["unknown"]
    fake = SecuritySkill(name="fake", candidate_tools=["definitely-not-a-tool"])
    out2 = validate_skill_tools(fake, reg.tool_registry)
    assert out2["unknown"] == ["definitely-not-a-tool"]


def test_legacy_skill_fields_map():
    reg = SecuritySkillRegistry()
    web = reg.get("web_hunt")
    assert web is not None
    assert web.safety_constraints          # legacy `guardrails`
    assert web.candidate_tools             # legacy `tools`


# --- contract -------------------------------------------------------------------

def test_contract_check_rules():
    ok, issues = CompletionContract(objective="x").check()
    assert not ok
    assert any("observations" in i for i in issues)
    assert any("uncertainty" in i for i in issues)

    good = CompletionContract(
        objective="x",
        what_changed=["did a thing"],
        what_was_observed=["status: ok"],
        what_was_verified=["scan: ok"],
        evidence=["evidence://1"],
        remaining_uncertainty=["none known"],
        next_state="completed",
    )
    ok2, issues2 = good.check()
    assert ok2 and issues2 == []

    without_evidence = CompletionContract(
        what_was_observed=["x"], what_was_verified=["claimed"],
        remaining_uncertainty=["none known"], next_state="completed",
    )
    ok3, issues3 = without_evidence.check()
    assert not ok3 and any("evidence" in i for i in issues3)


def test_contract_build_from_run():
    contract = build_from_run("obj", [
        {"action": "status", "status": "ok",
         "result": {"evidence_refs": [7], "verified": True}},
        {"action": "scan", "status": "error", "error": "boom"},
    ], errors=["scan: boom"])
    data = contract.to_dict()
    assert data["EVIDENCE"] == [7]
    assert data["WHAT_WAS_VERIFIED"] == ["status"]
    assert data["REMAINING_UNCERTAINTY"] == ["scan: boom"]
    assert data["NEXT_STATE"] == "completed"


# --- session --------------------------------------------------------------------

def test_session_roundtrip_and_resume(db):
    s = NemesisSession(engagement="alpha.com", scan_id=7)
    s.plan = [{"action": "status", "target": ""}]
    s.completed_actions = ["status:"]
    s.pending_actions = ["scan:example.com"]
    s.previous_errors = ["x: boom"]
    save_session(db, s)

    loaded = load_session(db, "alpha.com")
    assert loaded is not None
    assert loaded.scan_id == 7
    assert loaded.completed_actions == ["status:"]
    assert loaded.pending_actions == ["scan:example.com"]
    assert loaded.previous_errors == ["x: boom"]


def test_session_update_not_duplicate(db):
    save_session(db, NemesisSession(engagement="alpha.com", state="running"))
    save_session(db, NemesisSession(engagement="alpha.com", state="completed"))
    rows = list_sessions(db)
    assert len(rows) == 1 and rows[0]["state"] == "completed"
