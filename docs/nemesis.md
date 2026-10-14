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
