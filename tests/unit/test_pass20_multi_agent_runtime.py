"""Pass 20 — bounded multi-agent runtime (Task 13). Offline/deterministic only."""
from __future__ import annotations

import json

import pytest

from lib.nemesis.runtime import (
    COMPLETED,
    FAILED,
    F_APPROVAL,
    F_BUDGET,
    F_DEPENDENCY,
    F_MALFORMED,
    F_PERMISSION,
    F_SCOPE,
    F_TIMEOUT,
    RunLimits,
    TaskPlan,
    TaskResult,
    AgentTask,
    DeterministicAgent,
    MultiAgentRuntime,
    redact,
)
from lib.ops_guard import KillSwitch


class StubCfg:
    """Minimal config stand-in (only what the runtime reads)."""

    def __init__(self, nemesis=None, target=None):
        self.nemesis = nemesis or {}
        self._target = target

    def target(self, host):  # pragma: no cover - only used when target set
        return self._target


def build_plan(plan_id, specs, mock=True):
    tasks = [AgentTask.from_dict(s) for s in specs]
    return TaskPlan(plan_id=plan_id, objective="obj", engagement="eng", tasks=tasks, mock=mock)


def run_mock(specs, **kwargs):
    kwargs.setdefault("limits", RunLimits(max_workers=2))
    rt = MultiAgentRuntime(mock=True, **kwargs)
    plan = rt.plan("obj", "eng", specs)
    return rt, plan, rt.run(plan)


# -- plan validation -----------------------------------------------------------


def test_plan_rejects_duplicate_ids():
    rt = MultiAgentRuntime(mock=True)
    with pytest.raises(ValueError):
        rt.plan("o", "e", [
            {"id": "a", "role": "recon", "action": "discover"},
            {"id": "a", "role": "recon", "action": "scan"},
        ])


def test_plan_rejects_unknown_dependency():
    rt = MultiAgentRuntime(mock=True)
    with pytest.raises(ValueError):
        rt.plan("o", "e", [{"id": "a", "role": "recon", "action": "scan", "depends_on": ["ghost"]}])


def test_plan_rejects_cycle():
    rt = MultiAgentRuntime(mock=True)
    with pytest.raises(ValueError):
        rt.plan("o", "e", [
            {"id": "a", "role": "recon", "action": "scan", "depends_on": ["b"]},
            {"id": "b", "role": "recon", "action": "scan", "depends_on": ["a"]},
        ])


def test_topological_order_respects_dependencies():
    plan = build_plan("p", [
        {"id": "c", "role": "reporting", "action": "report", "depends_on": ["b"]},
        {"id": "b", "role": "analysis", "action": "scan", "depends_on": ["a"]},
        {"id": "a", "role": "recon", "action": "discover"},
    ])
    order = plan.topological_order()
    assert order.index("a") < order.index("b") < order.index("c")


def test_task_from_dict_requires_fields():
    with pytest.raises(ValueError):
        AgentTask.from_dict({"role": "recon", "action": "scan"})


def test_plan_rejects_too_many_tasks():
    rt = MultiAgentRuntime(mock=True, limits=RunLimits(max_tasks=1))
    with pytest.raises(ValueError):
        rt.plan("o", "e", [
            {"id": "a", "role": "recon", "action": "discover"},
            {"id": "b", "role": "recon", "action": "scan"},
        ])


# -- success + ordering --------------------------------------------------------


def test_successful_dag_completes_in_order():
    order = []

    def worker(task, ctx):
        order.append(task.id)
        return {"status": "completed", "summary": f"did {task.id}"}

    rt = MultiAgentRuntime(mock=True, limits=RunLimits(max_workers=1),
                           workers={"recon": worker, "analysis": worker, "reporting": worker})
    plan = rt.plan("o", "e", [
        {"id": "recon", "role": "recon", "action": "discover"},
        {"id": "analysis", "role": "analysis", "action": "scan", "depends_on": ["recon"]},
        {"id": "reporting", "role": "reporting", "action": "report", "depends_on": ["analysis"]},
    ])
    report = rt.run(plan)
    assert report.status == "ok"
    assert report.counts == {"completed": 3}
    assert order == ["recon", "analysis", "reporting"]


def test_dependency_failure_skips_dependents():
    def worker(task, ctx):
        if task.id == "recon":
            return {"status": "failed", "error": "boom"}
        return {"status": "completed", "summary": "ok"}

    rt = MultiAgentRuntime(mock=True, workers={"recon": worker, "analysis": worker})
    plan = rt.plan("o", "e", [
        {"id": "recon", "role": "recon", "action": "discover"},
        {"id": "analysis", "role": "analysis", "action": "scan", "depends_on": ["recon"]},
    ])
    report = rt.run(plan)
    by_id = {t["id"]: t for t in report.tasks}
    assert by_id["recon"]["status"] == FAILED
    assert by_id["analysis"]["status"] == "skipped"
    assert by_id["analysis"]["failure_class"] == F_DEPENDENCY


# -- retries -------------------------------------------------------------------


def test_retry_then_success():
    attempts = {"n": 0}

    def flaky(task, ctx):
        attempts["n"] += 1
        if attempts["n"] == 1:
            return {"status": "failed", "error": "transient"}
        return {"status": "completed", "summary": "recovered"}

    rt = MultiAgentRuntime(mock=True, limits=RunLimits(max_retries=2),
                           workers={"recon": flaky})
    plan = rt.plan("o", "e", [{"id": "a", "role": "recon", "action": "scan"}])
    report = rt.run(plan)
    assert report.counts == {"completed": 1}
    assert report.tasks[0]["attempts"] == 2


def test_retry_bound_is_respected():
    calls = {"n": 0}

    def always_fail(task, ctx):
        calls["n"] += 1
        return {"status": "failed", "error": "nope"}

    rt = MultiAgentRuntime(mock=True, limits=RunLimits(max_retries=1),
                           workers={"recon": always_fail})
    plan = rt.plan("o", "e", [{"id": "a", "role": "recon", "action": "scan"}])
    report = rt.run(plan)
    assert report.tasks[0]["status"] == FAILED
    assert report.tasks[0]["attempts"] == 2
    assert calls["n"] == 2


def test_task_timeout_marks_timed_out():
    rt = MultiAgentRuntime(
        mock=True, limits=RunLimits(max_workers=1),
        workers={"_mock": DeterministicAgent(sleep=0.4)},
    )
    plan = rt.plan("o", "e", [{"id": "a", "role": "recon", "action": "scan",
                               "timeout": 0.05, "max_retries": 0}])
    report = rt.run(plan)
    assert report.tasks[0]["status"] == "timed_out"
    assert report.tasks[0]["failure_class"] == F_TIMEOUT
    assert report.status == "partial"


# -- policy: authorization -----------------------------------------------------


def test_permission_denied_when_role_restricted():
    cfg = StubCfg(nemesis={"runtime": {"roles": {"recon": {"actions": ["discover"]}}}})
    rt = MultiAgentRuntime(cfg=cfg, mock=True)
    plan = rt.plan("o", "e", [{"id": "a", "role": "recon", "action": "scan"}])
    report = rt.run(plan)
    assert report.tasks[0]["status"] == FAILED
    assert report.tasks[0]["failure_class"] == F_PERMISSION


def test_role_restriction_cannot_expand_permissions():
    cfg = StubCfg(nemesis={"runtime": {"roles": {"recon": {"actions": ["launch-missiles"]}}}})
    rt = MultiAgentRuntime(cfg=cfg, mock=True)
    plan = rt.plan("o", "e", [{"id": "a", "role": "recon", "action": "launch-missiles"}])
    report = rt.run(plan)
    assert report.tasks[0]["failure_class"] == F_PERMISSION


def test_allowed_action_passes_restriction():
    cfg = StubCfg(nemesis={"runtime": {"roles": {"recon": {"actions": ["discover"]}}}})
    rt = MultiAgentRuntime(cfg=cfg, mock=True)
    plan = rt.plan("o", "e", [{"id": "a", "role": "recon", "action": "discover"}])
    report = rt.run(plan)
    assert report.tasks[0]["status"] == COMPLETED


# -- policy: scope -------------------------------------------------------------


def test_out_of_scope_target_fails(cfg):
    rt = MultiAgentRuntime(mock=True, target_config=cfg.target("example.com"))
    plan = rt.plan("o", "e", [{"id": "a", "role": "recon", "action": "scan",
                               "target": "evil.invalid"}])
    report = rt.run(plan)
    assert report.tasks[0]["status"] == FAILED
    assert report.tasks[0]["failure_class"] == F_SCOPE


def test_in_scope_target_passes(cfg):
    rt = MultiAgentRuntime(mock=True, target_config=cfg.target("example.com"))
    plan = rt.plan("o", "e", [{"id": "a", "role": "recon", "action": "scan",
                               "target": "example.com"}])
    report = rt.run(plan)
    assert report.tasks[0]["status"] == COMPLETED


def test_target_bound_task_fails_closed_without_scope_context():
    rt = MultiAgentRuntime(mock=True)
    plan = rt.plan("o", "e", [{"id": "a", "role": "recon", "action": "scan",
                               "target": "example.com"}])
    report = rt.run(plan)
    assert report.tasks[0]["failure_class"] == F_SCOPE


# -- policy: approval ----------------------------------------------------------


def test_destructive_action_requires_approval():
    rt = MultiAgentRuntime(mock=True)
    plan = rt.plan("o", "e", [{"id": "a", "role": "analysis", "action": "scan",
                               "destructive": True}])
    report = rt.run(plan)
    assert report.tasks[0]["status"] == "skipped"
    assert report.tasks[0]["failure_class"] == F_APPROVAL


def test_destructive_action_runs_when_approved():
    rt = MultiAgentRuntime(mock=True, approvals={"a"})
    plan = rt.plan("o", "e", [{"id": "a", "role": "analysis", "action": "scan",
                               "destructive": True}])
    report = rt.run(plan)
    assert report.tasks[0]["status"] == COMPLETED


def test_configured_destructive_action_requires_approval():
    cfg = StubCfg(nemesis={"runtime": {"destructive_actions": ["scan"]}})
    rt = MultiAgentRuntime(cfg=cfg, mock=True)
    plan = rt.plan("o", "e", [{"id": "a", "role": "analysis", "action": "scan"}])
    report = rt.run(plan)
    assert report.tasks[0]["failure_class"] == F_APPROVAL


# -- budgets + kill switch -----------------------------------------------------


def test_call_budget_caps_executions():
    rt = MultiAgentRuntime(mock=True, limits=RunLimits(max_workers=2, max_calls=1))
    plan = rt.plan("o", "e", [
        {"id": "a", "role": "recon", "action": "discover"},
        {"id": "b", "role": "recon", "action": "scan"},
    ])
    report = rt.run(plan)
    assert report.counts.get(COMPLETED, 0) == 1
    assert report.counts.get("skipped", 0) == 1
    assert report.budget["calls_used"] == 1


def test_kill_switch_cancels_run(tmp_path):
    ks = KillSwitch(tmp_path)
    ks.kill()
    rt = MultiAgentRuntime(mock=True, killswitch=ks)
    plan = rt.plan("o", "e", [{"id": "a", "role": "recon", "action": "discover"}])
    report = rt.run(plan)
    assert report.status == "blocked"
    assert report.tasks[0]["status"] == "cancelled"
    assert report.halted


# -- output handling -----------------------------------------------------------


def test_malformed_worker_output_is_classified():
    rt = MultiAgentRuntime(mock=True,
                           workers={"_mock": DeterministicAgent(malformed=("a",))})
    plan = rt.plan("o", "e", [{"id": "a", "role": "recon", "action": "scan"}])
    report = rt.run(plan)
    assert report.tasks[0]["status"] == FAILED
    assert report.tasks[0]["failure_class"] == F_MALFORMED


def test_taskresult_validate_rules():
    ok, issues = TaskResult(task_id="a", status=COMPLETED).validate()
    assert not ok and issues
    ok, _ = TaskResult(task_id="a", status=COMPLETED, summary="done").validate()
    assert ok
    ok, issues = TaskResult(task_id="a", status=FAILED, summary="x").validate()
    assert not ok and issues


def test_secrets_are_redacted_in_report():
    def leaky(task, ctx):
        return {
            "status": "completed",
            "summary": "used authorization: Bearer abcdefghijklmnop",
            "data": {"authorization": "Bearer abcdefghijklmnop", "note": "fine"},
        }

    rt = MultiAgentRuntime(mock=True, workers={"recon": leaky})
    plan = rt.plan("o", "e", [{"id": "a", "role": "recon", "action": "scan"}])
    report = rt.run(plan)
    blob = json.dumps(report.to_dict())
    assert "abcdefghijklmnop" not in blob
    assert report.tasks[0]["result"]["data"]["authorization"] == "[REDACTED]"


def test_redact_helper_scrubs_nested_secrets():
    out = redact({"outer": {"api_key": "x", "list": ["secret-token-abcdef"]}})
    assert out["outer"]["api_key"] == "[REDACTED]"


# -- limits config -------------------------------------------------------------


def test_runlimits_from_config():
    cfg = StubCfg(nemesis={"runtime": {"max_workers": 4, "max_tasks": 9,
                                       "timeout_seconds": 12, "max_retries": 3}})
    limits = RunLimits.from_config(cfg)
    assert limits.max_workers == 4 and limits.max_tasks == 9
    assert limits.timeout_seconds == 12 and limits.max_retries == 3


def test_runlimits_from_config_ignores_bad_values():
    cfg = StubCfg(nemesis={"runtime": {"max_workers": "lots"}})
    limits = RunLimits.from_config(cfg)
    assert limits.max_workers == 2


# -- persistence + resume ------------------------------------------------------


def test_tasks_persist_to_db(db):
    rt = MultiAgentRuntime(mock=True, db=db)
    plan = rt.plan("o", "e", [{"id": "a", "role": "recon", "action": "discover"}])
    rt.run(plan)
    rows = db.query("SELECT * FROM nemesis_tasks WHERE plan_id = ?", (plan.plan_id,))
    assert len(rows) == 1
    assert rows[0]["status"] == COMPLETED
    assert rows[0]["task_id"] == "a"


def test_resume_skips_completed_without_reexecution(db):
    run = {"n": 0}

    def counting(task, ctx):
        run["n"] += 1
        return {"status": "completed", "summary": "ok"}

    specs = [{"id": "a", "role": "recon", "action": "discover"}]

    first = MultiAgentRuntime(mock=True, db=db, workers={"recon": counting})
    p1 = first.plan("o", "e", specs)
    first.run(p1)
    assert run["n"] == 1

    second = MultiAgentRuntime(mock=True, db=db, workers={"recon": counting})
    p2 = TaskPlan(plan_id=p1.plan_id, objective="o", engagement="e",
                  tasks=[AgentTask.from_dict(s) for s in specs], mock=True)
    report = second.run(p2)
    assert run["n"] == 1                       # not executed a second time
    assert report.counts.get(COMPLETED, 0) == 1
    assert report.budget["calls_used"] == 0


def test_interrupted_task_is_requeued(db):
    rt = MultiAgentRuntime(mock=True, db=db)
    plan = rt.plan("o", "e", [{"id": "a", "role": "recon", "action": "discover"}])
    db.execute(
        "INSERT INTO nemesis_tasks (plan_id, engagement, task_id, role, action, target,"
        " status, attempts, depends_on, result) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (plan.plan_id, "e", "a", "recon", "discover", "", "running", 1, "[]", "null"),
    )
    report = rt.run(plan)
    assert report.tasks[0]["status"] == COMPLETED
    assert report.tasks[0]["attempts"] == 2     # attempt preserved on re-run


def test_audit_events_recorded(db):
    rt = MultiAgentRuntime(mock=True, db=db)
    plan = rt.plan("o", "e", [{"id": "a", "role": "recon", "action": "discover"}])
    rt.run(plan)
    events = db.query("SELECT action FROM audit_events WHERE category = 'nemesis'")
    actions = {e["action"] for e in events}
    assert "nemesis.runtime.run" in actions
    assert "nemesis.task.completed" in actions
