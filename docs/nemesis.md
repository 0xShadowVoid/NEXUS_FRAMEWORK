# NEMESIS layer (Alpha upgrade)

> NEXUS executes. NEMESIS reasons. Help Me Learn explains.

The NEMESIS layer (`lib/nemesis/`) adds security reasoning, planning,
coordination and skill execution on top of the existing NEXUS engine.
It is strictly additive: scope validation, ToolRegistry, the evidence
engine, the finding lifecycle, audit, and checkpoint/recovery are reused
as-is — nothing is duplicated.

## Components

| Module | Purpose |
|---|---|
| `memory.py` | Engagement-scoped, restart-safe memory (sanitized; evidence refs over secrets) |
| `skills.py` | Security Skills — methodology above tools; disabled by default; scope-gated |
| `loop.py` | understand → plan → act → observe → verify → report (kill-switch + budget aware) |
| `team.py` | Recon / Analysis / Validation / Reporting coordination (validation via lifecycle only) |
| `runtime.py` | Bounded multi-agent runtime: supervisor plans a task DAG, workers execute it with policy, budgets, persistence and resume |
| `browser.py` | Browser adapter (mock-first; Playwright optional; OFF by default; content untrusted) |
| `mcp.py` | MCP security gateway (AUTH → AUTHZ → SCOPE → SAFETY → EXEC → AUDIT) |
| `contract.py` | Completion contract (changed / observed / verified / evidence / uncertainty / next) |
| `session.py` | Resumable sessions (references scan checkpoints; never duplicates them) |

## Configuration (`config/nexus.yaml`)

```yaml
nemesis:
  enabled: true              # additive layer; optional parts stay OFF
  memory:
    enabled: true            # local SQLite (no external services)
  skills:
    enabled: []              # NO skill is auto-enabled; list names to activate
  browser:
    enabled: false           # real browser automation (Playwright) — off by default
  mcp:
    enabled: false           # external MCP tools — off by default
```

## Safety model

- Engagement isolation; secrets redacted before persistence; evidence referenced by id.
- AI cannot validate findings — the lifecycle enforces evidence + actor rules.
- Kill switch and request budget apply; actions remain whitelisted.
- Browser page content is always untrusted; optional capabilities ship disabled.
- Audit categories: `nemesis`, `mcp` (plus the existing agent audit log).

Schema v4 adds `engagement_memory` and `nemesis_sessions` (additive; auto-applies).

## Bounded multi-agent runtime (`runtime.py`)

A **supervisor** turns an objective into a bounded `TaskPlan` (a DAG of `AgentTask`
objects with stable ids, explicit `depends_on`, timeouts and retry limits); **workers**
execute them under `RunLimits` (parallelism, tasks, wall clock, calls, tokens).

- Task lifecycle: `pending → ready → running → completed | failed | timed_out | cancelled | skipped`.
- Policy before each task: role→action allowlist (config may only **restrict**, never
  expand), `validate_target_scope` (fail-closed), explicit approval for `destructive`
  actions, kill switch + request/token budgets.
- Secrets are scrubbed (`core.sanitizer`) from args, results, logs and the returned report.
- Results reference evidence by id; findings are advisory (never validated by the runtime).
- State persists to `nemesis_tasks` (schema v5); `resume` skips completed tasks and
  re-queues interrupted ones — completed work is never executed twice.
- Offline/deterministic with `mock=True` (no AI or network call).

Run it via `nexus team [OBJECTIVE] [--target HOST] [--plan FILE] [--workers N]`.

Schema v5 adds `nemesis_tasks` (additive; auto-applies) for runtime state + provenance.
