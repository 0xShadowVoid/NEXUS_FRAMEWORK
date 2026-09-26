"""Unit tests for the agent loop (roadmap C1)."""
from __future__ import annotations

import json
from pathlib import Path

from lib.agent import NexusAgent, load_skills, Skill


def _agent(tmp_cfg, ai=None, actions=None, audit=None, skills=None):
    return NexusAgent(
        tmp_cfg, ai=ai, actions=actions or {},
        skills=skills if skills is not None else {},
        audit_path=audit,
    )


def test_load_skills_from_repo():
    skills = load_skills()
    assert "recon" in skills and "web_hunt" in skills
    assert skills["recon"].tools


def test_heuristic_plan_maps_intents(tmp_cfg):
    agent = _agent(tmp_cfg, actions={"discover": lambda s: None, "scan": lambda s: None,
                                     "dork": lambda s: None, "cve-update": lambda s: None,
                                     "status": lambda s: None, "report": lambda s: None})
    steps = agent.plan("run a cve-update for the latest zero-days")
    assert steps and steps[0]["action"] == "cve-update"


def test_plan_whitelist_drops_unknown_actions(tmp_cfg):
    class _AI:
        def plan_steps(self, objective, skills):
            return {"steps": [
                {"action": "scan", "target": "x.com", "why": "t"},
                {"action": "rm-rf-everything", "target": "", "why": "bad"},
            ]}

    agent = _agent(tmp_cfg, ai=_AI())
    steps = agent.plan("anything")
    assert [s["action"] for s in steps] == ["scan"]


def test_dry_run_does_not_execute(tmp_cfg, tmp_path):
    calls = []

    def handler(step):
        calls.append(step)
        return "ran"

    agent = _agent(tmp_cfg, actions={"scan": handler}, audit=tmp_path / "audit.log")
    report = agent.run("scan x.com", dry_run=True)
    assert calls == []
    assert report["dry_run"] is True


def test_run_executes_and_audits(tmp_cfg, tmp_path):
    audit = tmp_path / "audit.log"

    def handler(step):
        return {"target": step.get("target")}

    agent = _agent(tmp_cfg, actions={"scan": handler, "status": lambda s: "ok"}, audit=audit)
    report = agent.run("scan example.com", max_steps=2)
    assert report["executed"] >= 1
    records = [json.loads(l) for l in audit.read_text(encoding="utf-8").splitlines()]
    assert records and records[0]["step"]["action"] == "scan"


def test_run_without_matching_action_handles_no_handler(tmp_cfg, tmp_path):
    agent = _agent(tmp_cfg, actions={"status": lambda s: "ok"}, audit=tmp_path / "a.log")
    # plan heuristic for "report" intent → action "report", which has no handler.
    report = agent.run("give me a report", max_steps=3)
    outcomes = report["observations"]
    assert any(o.get("status") == "no-handler" for o in outcomes)


def test_ai_planner_used_when_available(tmp_cfg, tmp_path):
    class _AI:
        def plan_steps(self, objective, skills):
            return {"steps": [{"action": "status", "target": "", "why": "health"}]}

    agent = _agent(tmp_cfg, ai=_AI(), actions={"status": lambda s: "ok"}, audit=tmp_path / "a.log")
    assert agent.plan("whatever")[0]["action"] == "status"
