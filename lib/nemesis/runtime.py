"""Bounded multi-agent runtime (supervisor / worker) — Task 13.

A **supervisor** turns an objective into a bounded :class:`TaskPlan` (a DAG of
:class:`AgentTask` objects with stable ids, explicit dependencies, timeouts and
retry limits); **specialized workers** execute the tasks; the runtime
schedules them with configurable, bounded parallelism and persists their state.

This is an *extension* of the existing NEMESIS layer, not a second
orchestration system:

- role workers may be a :class:`lib.nemesis.team.NemesisTeam` (multi-role
  coordination) or the same whitelisted action callables ``NexusAgent`` uses;
- scope stays authoritative through :func:`lib.scope_validator.validate_target_scope`;
- finding promotion stays authoritative through :mod:`core.lifecycle`
  (AI/agent results are advisory — they reference evidence, never validate);
- secrets are scrubbed via :func:`core.sanitizer.sanitize_evidence` before any
  prompt, log, trace, persisted row or returned result;
- the kill switch and request budget come from :mod:`lib.ops_guard`;
- task state persists through the existing DB (additive schema v5) and reuses
  the session/recovery model — completed tasks are never re-executed.

Lifecycle::

    pending -> ready -> running -> completed
                                 -> failed  --(bounded retry)--> running
                                 -> timed_out
           -> cancelled (kill switch / budget / explicit)
           -> skipped   (dependency failed / approval withheld / budget)

Everything is deterministic when ``mock=True``: workers are replaced by
:class:`DeterministicAgent` and no AI/network call is ever made.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from core.sanitizer import sanitize_evidence
from lib.agent import ALLOWED_ACTIONS
from lib.logger import get_logger
from lib.ops_guard import KillSwitch
from lib.scope_validator import validate_target_scope

logger = get_logger("nemesis.runtime")

# -- task statuses --------------------------------------------------------------
PENDING = "pending"
READY = "ready"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"
TIMED_OUT = "timed_out"
CANCELLED = "cancelled"
SKIPPED = "skipped"

TERMINAL = frozenset({COMPLETED, FAILED, TIMED_OUT, CANCELLED, SKIPPED})
ACTIVE = frozenset({PENDING, READY, RUNNING})

# -- failure classes ------------------------------------------------------------
F_TIMEOUT = "timeout"
F_ERROR = "error"
F_MALFORMED = "malformed_output"
F_SCOPE = "out_of_scope"
F_PERMISSION = "permission_denied"
F_DEPENDENCY = "dependency_failed"
F_PROVIDER = "provider_unavailable"
F_BUDGET = "budget_exhausted"
F_APPROVAL = "needs_approval"
F_CANCELLED = "cancelled"

#: Failures that may be retried (bounded + deliberate).
RETRYABLE = frozenset({F_ERROR, F_TIMEOUT, F_PROVIDER, F_MALFORMED})

# Result statuses a worker is allowed to report.
_RESULT_STATUSES = frozenset({COMPLETED, FAILED, TIMED_OUT, CANCELLED, SKIPPED})

_BANNED_KEYS = (
    "password", "passwd", "pwd", "api_key", "apikey", "token", "secret",
    "cookie", "authorization", "session_id", "credential", "bearer",
)

WORKER_SUPERVISOR = "supervisor"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def redact(value: Any, depth: int = 0) -> Any:
    """Structurally scrub a value: redact secret-ish keys, sanitize strings.

    Used on task args, results, logs and the returned report so secrets never
    leave an agent boundary. Bounded in depth and width.
    """
    if depth > 6:
        return "[depth-limit]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in list(value.items())[:200]:
            if any(b in str(key).lower() for b in _BANNED_KEYS):
                out[str(key)] = "[REDACTED]"
            else:
                out[str(key)] = redact(item, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(v, depth + 1) for v in list(value)[:200]]
    if isinstance(value, str):
        return sanitize_evidence(value, max_length=2000)
    return value


def _as_int_list(value: Any) -> list[int]:
    if isinstance(value, (list, tuple, set)):
        out: list[int] = []
        for item in value:
            try:
                out.append(int(item))
            except (TypeError, ValueError):
                continue
        return out
    return []


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


@dataclass
class RunLimits:
    """Per-run bounds (parallelism, tasks, wall clock, calls, tokens)."""

    max_workers: int = 2
    max_tasks: int = 25
    timeout_seconds: float = 0.0        # whole-run wall clock (0 = unlimited)
    max_calls: int = 0                  # worker invocations (0 = unlimited)
    max_tokens: int = 0                 # token budget (0 = unlimited)
    max_retries: int = 1                # default per-task retries

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_workers": self.max_workers,
            "max_tasks": self.max_tasks,
            "timeout_seconds": self.timeout_seconds,
            "max_calls": self.max_calls,
            "max_tokens": self.max_tokens,
            "max_retries": self.max_retries,
        }

    @classmethod
    def from_config(cls, cfg: Any, base: "RunLimits | None" = None) -> "RunLimits":
        """Read ``nemesis.runtime`` overrides from a :class:`lib.config.Config`."""
        limits = base or cls()
        if cfg is None:
            return limits
        raw = (getattr(cfg, "nemesis", {}) or {}).get("runtime", {}) or {}

        def _num(key: str, current: Any, cast: Callable[[Any], Any]) -> Any:
            if key in raw and raw[key] is not None:
                try:
                    return cast(raw[key])
                except (TypeError, ValueError):
                    return current
            return current

        return cls(
            max_workers=max(1, int(_num("max_workers", limits.max_workers, int))),
            max_tasks=max(1, int(_num("max_tasks", limits.max_tasks, int))),
            timeout_seconds=max(0.0, float(_num("timeout_seconds", limits.timeout_seconds, float))),
            max_calls=max(0, int(_num("max_calls", limits.max_calls, int))),
            max_tokens=max(0, int(_num("max_tokens", limits.max_tokens, int))),
            max_retries=max(0, int(_num("max_retries", limits.max_retries, int))),
        )


@dataclass
class TaskResult:
    """Validated structured result of one task (evidence referenced, never inline)."""

    task_id: str
    status: str
    summary: str = ""
    evidence_refs: list[int] = field(default_factory=list)
    findings_refs: list[int] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    failure_class: str = ""
    worker: str = ""
    tokens: int = 0

    def validate(self) -> tuple[bool, list[str]]:
        issues: list[str] = []
        if not str(self.task_id or "").strip():
            issues.append("task_id is required")
        if self.status not in _RESULT_STATUSES:
            issues.append(f"invalid result status: {self.status!r}")
        if self.status == COMPLETED and not str(self.summary or "").strip():
            issues.append("completed result requires a summary")
        if self.status in (FAILED, TIMED_OUT) and not str(self.error or "").strip():
            issues.append("failed/timed_out result requires an error")
        return (not issues, issues)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "status": self.status,
            "summary": self.summary,
            "evidence_refs": list(self.evidence_refs),
            "findings_refs": list(self.findings_refs),
            "data": dict(self.data),
            "error": self.error,
            "failure_class": self.failure_class,
            "worker": self.worker,
            "tokens": self.tokens,
        }

    @classmethod
    def from_worker(cls, task_id: str, raw: Any, worker: str = "") -> "TaskResult":
        """Coerce arbitrary worker output into a result (malformed → classified)."""
        if isinstance(raw, TaskResult):
            coerced = TaskResult(
                task_id=raw.task_id or task_id, status=raw.status, summary=raw.summary,
                evidence_refs=list(raw.evidence_refs), findings_refs=list(raw.findings_refs),
                data=dict(raw.data), error=raw.error, failure_class=raw.failure_class,
                worker=raw.worker or worker, tokens=int(raw.tokens or 0),
            )
        elif isinstance(raw, dict):
            status = str(raw.get("status") or COMPLETED).lower()
            if status not in _RESULT_STATUSES:
                return cls(task_id=task_id, status=FAILED,
                           error=f"malformed output: unknown status {status!r}",
                           failure_class=F_MALFORMED, worker=worker)
            data = raw.get("data")
            coerced = cls(
                task_id=str(raw.get("task_id") or task_id), status=status,
                summary=str(raw.get("summary", "") or ""),
                evidence_refs=_as_int_list(raw.get("evidence_refs")),
                findings_refs=_as_int_list(raw.get("findings_refs")),
                data=data if isinstance(data, dict) else {},
                error=str(raw.get("error", "") or ""),
                failure_class=str(raw.get("failure_class", "") or ""),
                worker=worker, tokens=int(raw.get("tokens", 0) or 0),
            )
        else:
            return cls(task_id=task_id, status=FAILED,
                       error=f"malformed output: expected dict, got {type(raw).__name__}",
                       failure_class=F_MALFORMED, worker=worker)

        # scrub before the result crosses any boundary
        coerced.summary = str(redact(coerced.summary))
        coerced.error = str(redact(coerced.error))
        coerced.data = redact(coerced.data)
        # default failure class so self-reported failures stay retry-classified
        if not coerced.failure_class:
            if coerced.status == FAILED:
                coerced.failure_class = F_ERROR
            elif coerced.status == TIMED_OUT:
                coerced.failure_class = F_TIMEOUT
        ok, issues = coerced.validate()
        if not ok:
            return cls(task_id=task_id, status=FAILED,
                       error="malformed output: " + "; ".join(issues),
                       failure_class=F_MALFORMED, worker=worker)
        return coerced


@dataclass
class AgentTask:
    """One unit of work assigned to a specialized role."""

    id: str
    role: str
    action: str
    target: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    timeout: float = 0.0
    max_retries: int = -1               # -1 => RunLimits.max_retries
    destructive: bool = False
    requires_approval: bool = False
    status: str = PENDING
    attempts: int = 0
    result: TaskResult | None = None
    error: str = ""
    failure_class: str = ""
    started_at: str = ""
    ended_at: str = ""

    def retries_allowed(self, limits: RunLimits) -> int:
        return self.max_retries if self.max_retries >= 0 else limits.max_retries

    def max_attempts(self, limits: RunLimits) -> int:
        return 1 + max(0, self.retries_allowed(limits))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "role": self.role,
            "action": self.action,
            "target": self.target,
            "args": dict(self.args),
            "depends_on": list(self.depends_on),
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "destructive": self.destructive,
            "requires_approval": self.requires_approval,
            "status": self.status,
            "attempts": self.attempts,
            "result": self.result.to_dict() if self.result else None,
            "error": self.error,
            "failure_class": self.failure_class,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AgentTask":
        if not isinstance(raw, dict):
            raise ValueError("each task must be a mapping")
        task_id = str(raw.get("id", "") or "").strip()
        role = str(raw.get("role", "") or "").strip()
        action = str(raw.get("action", "") or "").strip()
        if not task_id or not role or not action:
            raise ValueError("each task requires 'id', 'role' and 'action'")
        deps = raw.get("depends_on") or []
        if isinstance(deps, str):
            deps = [deps]
        return cls(
            id=task_id, role=role, action=action,
            target=str(raw.get("target", "") or ""),
            args=dict(raw.get("args") or {}),
            depends_on=[str(d) for d in deps],
            timeout=float(raw.get("timeout", 0) or 0),
            max_retries=int(raw.get("max_retries", -1)),
            destructive=bool(raw.get("destructive", False)),
            requires_approval=bool(raw.get("requires_approval", False)),
        )


@dataclass
class TaskPlan:
    """A validated, bounded task DAG produced by the supervisor."""

    plan_id: str
    objective: str
    engagement: str
    tasks: list[AgentTask] = field(default_factory=list)
    mock: bool = False

    def by_id(self) -> dict[str, AgentTask]:
        return {t.id: t for t in self.tasks}

    def validate(self) -> tuple[bool, list[str]]:
        issues: list[str] = []
        if not str(self.plan_id or "").strip():
            issues.append("plan_id is required")
        ids = [t.id for t in self.tasks]
        if len(ids) != len(set(ids)):
            issues.append("duplicate task ids")
        known = set(ids)
        for task in self.tasks:
            for dep in task.depends_on:
                if dep not in known:
                    issues.append(f"task {task.id!r} depends on unknown task {dep!r}")
        if not issues and self._has_cycle():
            issues.append("task graph contains a cycle")
        return (not issues, issues)

    def _has_cycle(self) -> bool:
        try:
            self.topological_order()
            return False
        except ValueError:
            return True

    def topological_order(self) -> list[str]:
        """Kahn's algorithm; raises ValueError on a cycle."""
        indeg = {t.id: 0 for t in self.tasks}
        edges: dict[str, list[str]] = {t.id: [] for t in self.tasks}
        for task in self.tasks:
            for dep in task.depends_on:
                if dep in indeg:
                    indeg[task.id] += 1
                    edges[dep].append(task.id)
        queue = [tid for tid, deg in indeg.items() if deg == 0]
        order: list[str] = []
        while queue:
            node = queue.pop(0)
            order.append(node)
            for nxt in edges[node]:
                indeg[nxt] -= 1
                if indeg[nxt] == 0:
                    queue.append(nxt)
        if len(order) != len(self.tasks):
            raise ValueError("task graph contains a cycle")
        return order

    def ready_tasks(self, done: set[str], not_available: set[str]) -> list[AgentTask]:
        out: list[AgentTask] = []
        for task in self.tasks:
            if task.status not in (PENDING, READY):
                continue
            if any(d in not_available for d in task.depends_on):
                continue
            if all(d in done for d in task.depends_on):
                out.append(task)
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "objective": self.objective,
            "engagement": self.engagement,
            "mock": self.mock,
            "tasks": [t.to_dict() for t in self.tasks],
        }


@dataclass
class RunReport:
    """Outcome of one supervised run."""

    plan_id: str
    objective: str
    engagement: str
    status: str = "ok"                  # ok | partial | blocked
    mock: bool = False
    halted: str = ""
    tasks: list[dict[str, Any]] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    budget: dict[str, Any] = field(default_factory=dict)
    started_at: str = ""
    ended_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "objective": self.objective,
            "engagement": self.engagement,
            "status": self.status,
            "mock": self.mock,
            "halted": self.halted,
            "counts": dict(self.counts),
            "budget": dict(self.budget),
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "tasks": list(self.tasks),
        }


class DeterministicAgent:
    """Mock worker: deterministic, offline results (for tests + ``mock`` mode).

    Optional injections keep tests deterministic without real work:

        sleep      — seconds to block (drives timeout tests)
        fail       — task ids that fail with a transient error (drives retry)
        malformed  — task ids that return non-dict output (drives schema tests)
        tokens     — tokens reported per call (drives budget tests)
    """

    def __init__(
        self,
        sleep: float = 0.0,
        fail: tuple[str, ...] = (),
        malformed: tuple[str, ...] = (),
        tokens: int = 0,
    ):
        self.sleep = float(sleep)
        self.fail = set(fail)
        self.malformed = set(malformed)
        self.tokens = int(tokens)

    def __call__(self, task: AgentTask, ctx: dict[str, Any]) -> Any:
        overrides = task.args.get("_mock") if isinstance(task.args, dict) else None
        if isinstance(overrides, dict):
            if overrides.get("sleep") is not None:
                time.sleep(float(overrides["sleep"]))
            if overrides.get("malformed"):
                return "this-is-not-a-mapping"
            if overrides.get("fail"):
                return {"status": FAILED, "error": str(overrides.get("error") or "mock failure")}
        if task.id in self.malformed:
            return "not-a-mapping"
        if self.sleep:
            time.sleep(self.sleep)
        if task.id in self.fail:
            return {"status": FAILED, "error": "mock transient failure"}
        summary = task.args.get("_mock_summary") if isinstance(task.args, dict) else None
        return {
            "status": COMPLETED,
            "summary": str(summary or f"mock {task.action}"),
            "data": {"role": task.role, "target": task.target},
            "tokens": self.tokens,
        }


def _role_actions(cfg: Any) -> dict[str, set[str]]:
    raw = ((getattr(cfg, "nemesis", {}) or {}).get("runtime", {}) or {}).get("roles", {}) or {}
    out: dict[str, set[str]] = {}
    if isinstance(raw, dict):
        for role, spec in raw.items():
            actions = (spec or {}).get("actions") if isinstance(spec, dict) else spec
            if actions is None:
                continue
            if isinstance(actions, str):
                actions = [actions]
            out[str(role)] = {str(a) for a in actions}
    return out


def _destructive_actions(cfg: Any) -> set[str]:
    raw = ((getattr(cfg, "nemesis", {}) or {}).get("runtime", {}) or {}).get("destructive_actions", [])
    if isinstance(raw, str):
        raw = [raw]
    return {str(a) for a in (raw or [])}


class MultiAgentRuntime:
    """Supervisor executing a bounded task DAG over specialized workers."""

    def __init__(
        self,
        cfg: Any = None,
        db: Any = None,
        workers: dict[str, Callable[[AgentTask, dict[str, Any]], Any]] | None = None,
        team: Any = None,
        limits: RunLimits | None = None,
        mock: bool = False,
        killswitch: KillSwitch | None = None,
        target_config: Any = None,
        approvals: Any = None,
        scan_id: int | None = None,
        actor: str = "supervisor",
    ):
        self.cfg = cfg
        self.db = db
        self.team = team
        self.limits = limits or RunLimits.from_config(cfg)
        self.mock = bool(mock)
        self.killswitch = killswitch or KillSwitch()
        self.target_config = target_config
        self.approvals = {str(a) for a in (approvals or [])}
        self.scan_id = scan_id
        self.actor = actor
        self.workers = dict(workers or {})
        if self.mock and "_mock" not in self.workers:
            self.workers["_mock"] = DeterministicAgent()
        self.role_actions = _role_actions(cfg)
        self.destructive_actions = _destructive_actions(cfg)
        self._calls = 0
        self._tokens = 0
        self._cancel = threading.Event()
        self._cancel_reason = ""

    # -- planning -----------------------------------------------------------

    def plan(self, objective: str, engagement: str, tasks: list[dict[str, Any]] | None = None) -> TaskPlan:
        """Build + validate a bounded task plan (supervisor step)."""
        parsed = [AgentTask.from_dict(t) for t in (tasks or [])]
        if self.limits.max_tasks and len(parsed) > self.limits.max_tasks:
            raise ValueError(f"plan exceeds max_tasks ({self.limits.max_tasks})")
        plan = TaskPlan(
            plan_id=_new_id("plan"), objective=str(objective or ""),
            engagement=str(engagement or ""), tasks=parsed, mock=self.mock,
        )
        ok, issues = plan.validate()
        if not ok:
            raise ValueError("invalid task plan: " + "; ".join(issues))
        return plan

    # -- policy -------------------------------------------------------------

    def _allowed_actions(self, role: str) -> set[str]:
        base = set(ALLOWED_ACTIONS) | set(self.workers)
        specific = self.role_actions.get(role)
        if specific is None:
            return base
        return base & specific          # config may restrict, never expand

    def _worker_for(self, task: AgentTask) -> tuple[str, Callable[..., Any]] | None:
        if task.role in self.workers:
            return task.role, self.workers[task.role]
        if task.action in self.workers:
            return task.action, self.workers[task.action]
        if self.team is not None and task.role == "team":
            return "team", lambda t, ctx: self.team.run(
                {"objective": self.plan_objective(t), "task": t.to_dict()}, ctx
            )
        if self.mock:
            return "_mock", self.workers["_mock"]
        return None

    @staticmethod
    def plan_objective(task: AgentTask) -> str:
        return str(task.args.get("objective") or task.target or task.action)

    def _authorize(self, task: AgentTask) -> str:
        allowed = self._allowed_actions(task.role)
        if task.action not in allowed:
            return f"role {task.role!r} may not run action {task.action!r}"
        return ""

    def _check_scope(self, task: AgentTask) -> str:
        if not task.target:
            return ""
        if self.target_config is None:
            return "no scope context configured; refusing target-bound action"
        try:
            if not validate_target_scope(task.target, self.target_config):
                return f"target {task.target!r} is out of scope"
        except Exception as exc:  # malformed scope input → fail closed
            return f"scope check failed: {exc}"
        return ""

    def _needs_approval(self, task: AgentTask) -> bool:
        return bool(
            task.requires_approval
            or task.destructive
            or task.action in self.destructive_actions
        )

    # -- persistence --------------------------------------------------------

    def _persist_task(self, plan: TaskPlan, task: AgentTask) -> None:
        if self.db is None:
            return
        row = {
            "plan_id": plan.plan_id, "engagement": plan.engagement, "task_id": task.id,
            "role": task.role, "action": task.action, "target": task.target,
            "status": task.status, "attempts": task.attempts,
            "failure_class": task.failure_class, "error": task.error,
            "depends_on": json.dumps(task.depends_on),
            "result": json.dumps(task.result.to_dict() if task.result else None, default=str),
            "evidence_refs": json.dumps(task.result.evidence_refs if task.result else []),
            "findings_refs": json.dumps(task.result.findings_refs if task.result else []),
            "started_at": task.started_at, "ended_at": task.ended_at,
            "updated_at": _now(),
        }
        try:
            existing = self.db.query(
                "SELECT id FROM nemesis_tasks WHERE plan_id = ? AND task_id = ?",
                (plan.plan_id, task.id),
            )
            if existing:
                self.db.execute(
                    "UPDATE nemesis_tasks SET status=?, attempts=?, failure_class=?, error=?,"
                    " result=?, evidence_refs=?, findings_refs=?, started_at=?, ended_at=?,"
                    " updated_at=? WHERE id=?",
                    (row["status"], row["attempts"], row["failure_class"], row["error"],
                     row["result"], row["evidence_refs"], row["findings_refs"],
                     row["started_at"], row["ended_at"], row["updated_at"], existing[0]["id"]),
                )
            else:
                self.db.execute(
                    "INSERT INTO nemesis_tasks (plan_id, engagement, task_id, role, action,"
                    " target, status, attempts, failure_class, error, depends_on, result,"
                    " evidence_refs, findings_refs, started_at, ended_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (row["plan_id"], row["engagement"], row["task_id"], row["role"],
                     row["action"], row["target"], row["status"], row["attempts"],
                     row["failure_class"], row["error"], row["depends_on"], row["result"],
                     row["evidence_refs"], row["findings_refs"], row["started_at"],
                     row["ended_at"], row["updated_at"]),
                )
        except Exception as exc:  # persistence must never break the run
            logger.debug("task persistence skipped: %s", exc)

    def load_task_states(self, plan_id: str) -> dict[str, dict[str, Any]]:
        """Persisted per-task state for *plan_id* (empty when none/unavailable)."""
        if self.db is None:
            return {}
        try:
            rows = self.db.query("SELECT * FROM nemesis_tasks WHERE plan_id = ?", (plan_id,))
        except Exception:  # pragma: no cover - defensive
            return {}
        return {str(r["task_id"]): r for r in rows}

    def _apply_resume(self, plan: TaskPlan) -> int:
        """Restore persisted state; skip completed tasks, re-queue interrupted ones.

        Returns the number of tasks satisfied from persisted state (never
        executed again — the duplicate-execution guard).
        """
        rows = self.load_task_states(plan.plan_id)
        if not rows:
            return 0
        skipped = 0
        for task in plan.tasks:
            row = rows.get(task.id)
            if not row:
                continue
            task.attempts = int(row.get("attempts") or 0)
            stored = row.get("status")
            if stored == COMPLETED:
                try:
                    data = json.loads(row.get("result") or "null")
                except (TypeError, ValueError):
                    data = None
                task.result = TaskResult.from_worker(task.id, data, WORKER_SUPERVISOR) if data else None
                task.status = COMPLETED
                task.failure_class = ""
                task.ended_at = str(row.get("ended_at") or "")
                skipped += 1
            elif stored in (RUNNING, READY):
                # Interrupted by a previous crash → safe to re-run.
                task.status = PENDING
                task.failure_class = ""
                task.error = ""
        if skipped:
            logger.info("resume: %d completed task(s) skipped for plan %s", skipped, plan.plan_id)
        return skipped

    # -- audit + provenance -------------------------------------------------

    def _audit(self, action: str, detail: dict[str, Any]) -> None:
        if self.db is None:
            return
        try:
            self.db.insert_audit_event(
                actor=self.actor, action=action, category="nemesis",
                detail=redact(json.dumps(detail, default=str))[:300],
            )
        except Exception:  # audit must never break the run
            pass

    def _record_provenance(self, task: AgentTask, result: TaskResult) -> None:
        """Link task → tool execution → evidence/findings (best-effort)."""
        if self.db is None:
            return
        if self.scan_id is not None:
            try:
                self.db.record_tool_run(
                    self.scan_id, "nemesis", task.action,
                    status=result.status, returncode=None,
                )
            except Exception:  # provenance is best-effort
                pass
        if result.evidence_refs and self.scan_id is not None:
            try:
                self.db.insert_evidence(
                    self.scan_id, task.target or "nemesis://task",
                    source="nemesis.runtime", tool=task.action,
                    response_body=json.dumps(result.to_dict(), default=str)[:2000],
                )
            except Exception:
                pass

    # -- execution ----------------------------------------------------------

    def _finish(self, plan: TaskPlan, task: AgentTask, result: TaskResult) -> None:
        task.status = result.status
        task.result = result
        task.error = result.error
        task.failure_class = result.failure_class
        task.ended_at = _now()
        self._persist_task(plan, task)
        self._record_provenance(task, result)
        self._audit(f"nemesis.task.{result.status}", {
            "plan_id": plan.plan_id, "task_id": task.id, "action": task.action,
            "target": task.target, "role": task.role,
            "failure_class": result.failure_class, "evidence_refs": result.evidence_refs,
        })

    def _preflight(self, plan: TaskPlan, task: AgentTask) -> TaskResult | None:
        """Policy checks done before a worker slot is used. None = proceed."""
        if self._cancel.is_set():
            return TaskResult(task_id=task.id, status=CANCELLED, summary="cancelled",
                              error=self._cancel_reason or "run cancelled", failure_class=F_CANCELLED)
        if self.killswitch.killed():
            return TaskResult(task_id=task.id, status=CANCELLED, summary="kill switch engaged",
                              error="kill switch engaged", failure_class=F_CANCELLED)

        reason = self._authorize(task)
        if reason:
            return TaskResult(task_id=task.id, status=FAILED, summary="permission denied",
                              error=reason, failure_class=F_PERMISSION, worker=WORKER_SUPERVISOR)

        reason = self._check_scope(task)
        if reason:
            return TaskResult(task_id=task.id, status=FAILED, summary="out of scope",
                              error=reason, failure_class=F_SCOPE, worker=WORKER_SUPERVISOR)

        if self._needs_approval(task) and task.id not in self.approvals:
            return TaskResult(task_id=task.id, status=SKIPPED, summary="approval required",
                              error="high-impact action requires explicit approval",
                              failure_class=F_APPROVAL, worker=WORKER_SUPERVISOR)

        if self.limits.max_calls and self._calls >= self.limits.max_calls:
            return TaskResult(task_id=task.id, status=SKIPPED, summary="call budget exhausted",
                              error="max_calls reached", failure_class=F_BUDGET, worker=WORKER_SUPERVISOR)
        if self.limits.max_tokens and self._tokens >= self.limits.max_tokens:
            return TaskResult(task_id=task.id, status=SKIPPED, summary="token budget exhausted",
                              error="max_tokens reached", failure_class=F_BUDGET, worker=WORKER_SUPERVISOR)

        if self._worker_for(task) is None:
            return TaskResult(task_id=task.id, status=FAILED, summary="no worker available",
                              error=f"no worker registered for role {task.role!r}",
                              failure_class=F_PROVIDER, worker=WORKER_SUPERVISOR)
        return None

    def _invoke(self, task: AgentTask, ctx: dict[str, Any]) -> TaskResult:
        resolved = self._worker_for(task)
        if resolved is None:  # pragma: no cover - preflight guarantees this
            return TaskResult(task_id=task.id, status=FAILED, summary="no worker available",
                              error="worker vanished", failure_class=F_PROVIDER, worker=WORKER_SUPERVISOR)
        name, worker = resolved
        ctx = {**ctx, "task": task, "redact": redact}
        try:
            raw = worker(task, ctx)
        except Exception as exc:
            return TaskResult(task_id=task.id, status=FAILED, summary="worker error",
                              error=str(redact(str(exc))), failure_class=F_ERROR, worker=name)
        result = TaskResult.from_worker(task.id, raw, name)
        self._tokens += int(result.tokens or 0)
        return result

    def _retry_or_finish(self, plan: TaskPlan, task: AgentTask, result: TaskResult) -> None:
        if result.failure_class in RETRYABLE and task.attempts < task.max_attempts(self.limits):
            logger.info("retrying task %s (attempt %d/%d)", task.id, task.attempts,
                        task.max_attempts(self.limits))
            task.status = PENDING
            task.result = None
            task.error = result.error
            task.failure_class = result.failure_class
            task.ended_at = ""
            self._persist_task(plan, task)
            return
        self._finish(plan, task, result)

    # -- supervisor loop ----------------------------------------------------

    def cancel(self, reason: str = "cancelled by supervisor") -> None:
        self._cancel_reason = reason
        self._cancel.set()

    def run(self, plan: TaskPlan, context: dict[str, Any] | None = None) -> RunReport:
        """Execute *plan* with bounded parallelism; returns a structured report."""
        ok, issues = plan.validate()
        if not ok:
            raise ValueError("invalid task plan: " + "; ".join(issues))
        ctx = dict(context or {})
        started = _now()
        start_mono = time.monotonic()
        deadline = start_mono + self.limits.timeout_seconds if self.limits.timeout_seconds else None
        self._calls = 0
        self._tokens = 0
        self._cancel.clear()
        self._cancel_reason = ""

        self._audit("nemesis.runtime.run", {"plan_id": plan.plan_id, "objective": plan.objective,
                                            "tasks": len(plan.tasks), "mock": plan.mock})
        self._apply_resume(plan)
        for task in plan.tasks:
            self._persist_task(plan, task)

        halted = ""
        executor = ThreadPoolExecutor(max_workers=max(1, self.limits.max_workers))
        running: dict[Future, tuple[AgentTask, float]] = {}
        try:
            while True:
                if self._cancel.is_set():
                    halted = self._cancel_reason or "cancelled"
                    self._cancel_active(plan, F_CANCELLED, halted)
                    break
                if self.killswitch.killed():
                    halted = "kill switch engaged"
                    self._cancel_active(plan, F_CANCELLED, halted)
                    break
                if deadline and time.monotonic() >= deadline:
                    halted = "run timeout"
                    self._cancel_active(plan, F_BUDGET, halted)
                    break

                done_ids = {t.id for t in plan.tasks if t.status == COMPLETED}
                unavailable = {t.id for t in plan.tasks if t.status in TERMINAL and t.status != COMPLETED}

                # dependency failures become skips (never silently dropped)
                for task in plan.tasks:
                    if task.status in (PENDING, READY) and any(d in unavailable for d in task.depends_on):
                        self._finish(plan, task, TaskResult(
                            task_id=task.id, status=SKIPPED, summary="dependency failed",
                            error="a dependency did not complete", failure_class=F_DEPENDENCY,
                            worker=WORKER_SUPERVISOR))

                ready = plan.ready_tasks(done_ids, unavailable)
                submitted = False
                while ready and len(running) < self.limits.max_workers:
                    task = ready.pop(0)
                    pre = self._preflight(plan, task)
                    if pre is not None:
                        self._finish(plan, task, pre)
                        submitted = True
                        continue
                    task.status = RUNNING
                    task.started_at = _now()
                    task.attempts += 1
                    self._calls += 1
                    fut = executor.submit(self._invoke, task, dict(ctx))
                    running[fut] = (task, time.monotonic())
                    submitted = True

                if running:
                    timeout = self._next_wait(running, deadline)
                    done, _pending = wait(set(running), timeout=timeout, return_when=FIRST_COMPLETED)
                    if not done:
                        self._expire(running, plan)
                        continue
                    for fut in done:
                        task, _t0 = running.pop(fut)
                        try:
                            result = fut.result()
                        except Exception as exc:  # pragma: no cover - defensive
                            result = TaskResult(task_id=task.id, status=FAILED, summary="worker error",
                                                error=str(exc), failure_class=F_ERROR, worker=task.role)
                        self._retry_or_finish(plan, task, result)
                    continue

                if not any(t.status in ACTIVE for t in plan.tasks):
                    break
                if not submitted:
                    break
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        counts: dict[str, int] = {}
        for task in plan.tasks:
            counts[task.status] = counts.get(task.status, 0) + 1
        status = "ok"
        if halted:
            status = "blocked"
        elif counts.get(FAILED, 0) or counts.get(TIMED_OUT, 0) or counts.get(CANCELLED, 0):
            status = "partial"

        report = RunReport(
            plan_id=plan.plan_id, objective=plan.objective, engagement=plan.engagement,
            status=status, mock=plan.mock, halted=halted,
            tasks=[t.to_dict() for t in plan.tasks], counts=counts,
            budget={
                "limits": self.limits.to_dict(),
                "calls_used": self._calls, "tokens_used": self._tokens,
                "elapsed_seconds": round(time.monotonic() - start_mono, 4),
            },
            started_at=started, ended_at=_now(),
        )
        self._audit("nemesis.runtime.report", {
            "plan_id": plan.plan_id, "status": status, "counts": counts, "halted": halted,
        })
        return report

    def _next_wait(self, running: dict[Future, tuple[AgentTask, float]], deadline: float | None) -> float | None:
        waits: list[float] = []
        now = time.monotonic()
        for task, t0 in running.values():
            if task.timeout:
                waits.append(max(0.0, task.timeout - (now - t0)))
        if deadline is not None:
            waits.append(max(0.0, deadline - now))
        return min(waits) if waits else None

    def _expire(self, running: dict[Future, tuple[AgentTask, float]], plan: TaskPlan) -> None:
        now = time.monotonic()
        for fut in list(running):
            task, t0 = running[fut]
            if task.timeout and (now - t0) >= task.timeout:
                fut.cancel()
                running.pop(fut, None)
                self._retry_or_finish(plan, task, TaskResult(
                    task_id=task.id, status=TIMED_OUT, summary="task timed out",
                    error=f"exceeded {task.timeout}s", failure_class=F_TIMEOUT, worker=task.role))

    def _cancel_active(self, plan: TaskPlan, failure_class: str, reason: str) -> None:
        for task in plan.tasks:
            if task.status in ACTIVE:
                self._finish(plan, task, TaskResult(
                    task_id=task.id, status=CANCELLED if failure_class == F_CANCELLED else SKIPPED,
                    summary=reason, error=reason, failure_class=failure_class,
                    worker=WORKER_SUPERVISOR))
