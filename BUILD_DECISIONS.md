# NEXUS — Build Decisions & Trade-offs

Running log of engineering decisions made while building the framework,
recording deviations from the spec and the reasons.

## Build environment

1. **Output location.** The spec's `/mnt/user-data/outputs/nexus-framework/`
   came from the planning environment (Linux). The framework was built in the
   authoritative repository workspace instead, as a flat package layout
   (`lib/`, `core/`, `phases/`, `config/`, `tests/`, `nexus.py` at the repo root).
2. **Python.** Target 3.11+ per spec; built and tested on 3.13 (verified
   compatible — no 3.12+-only syntax used).

## Architecture

3. **Layering.** `lib` (no internal deps) → `core` (may import lib) →
   `phases` (import both) → `nexus.py`. Prevents circular imports.
4. **Analysis logic lives in `lib` + `core`.** The spec lists `deduplicator`,
   `severity_scorer` and `chain_detector` under both `lib/` and `phases/analyze/`.
   Resolution: implementations live in `lib/` (dedup/chainer/severity) and
   `core/analyzer.py` runs the pipeline; `phases/analyze/analyze_orchestrator.py`
   is the thin phase adapter.
5. **Single subprocess choke point.** All external tool execution goes through
   `phases/probe/tool_runner.py::ToolRunner` (argv lists, `shell=False`,
   timeouts, boundary screening). This is both a security gate and the seam
   that lets the entire suite run offline with fake runners.
6. **8th database table (`cves`).** The spec says "all 8 tables" but lists 7.
   Added a `cves` table (dedup guard + PoC/alert state) — required by the CVE
   workflow. Documented here as the intended 8th table.

## Security boundary

7. **`lib/payload_guard.py`** implements the "payload restrictions" the
   security boundary references (labelled `payload_builder.py` in that doc).
   Named `payload_guard` because it validates rather than builds.
8. **`lib/scope_validator.py`** is the sole scope authority; `validate_target_scope`
   is called before any phase work, and out-of-scope findings are marked
   `OUT_OF_SCOPE` (never silently dropped, never submitted).
9. **DB layer has no delete/drop API** by construction; destructive SQL is
   additionally rejected at `execute()`. This was a deliberate over-constraint
   to satisfy the boundary doc, which forbids `DELETE FROM findings`.
10. **Output sanitizer** (`core/sanitizer.py`) strips cookies/auth/tokens and
    caps snippet length so reports contain proof only.

## Additions requested by the author (beyond the 82)

11. **Multi-engine dorking** (`phases/discover/dorker.py`) — DuckDuckGo,
    Google, Bing, GitHub; six intents; runs in DISCOVER. Collects URLs only,
    never content (boundary-safe).
12. **AI multi-key failover** (`lib/key_pool.py` + `lib/ai_analyzer.py`) —
    multiple keys per provider (`PROVIDER_API_KEY[_2..10]`, comma-separated
    supported), automatic rotation on empty/401/403/429, cross-provider
    fallback, masked key status, and `nexus.py ai-set-key` / `ai-keys` CLI.

## Portability & offline safety

13. **Dorking/Wappalyzer/NVD/H1/Bugcrowd** all degrade gracefully when offline
    or unconfigured — no crash, log + empty result.
14. **Screenshots** use `gowitness` when present; otherwise a documented no-op.
15. **C2 bots** use `requests`-only frontends (no heavy SDKs); Discord uses
    `discord.py` when installed, else a stub that still exposes routing for tests.
16. **Concurrency** — batch mode uses a thread pool; `core/database.py` uses a
    single connection with `check_same_thread=False` + an `RLock` to stay safe
    under concurrent scans.
17. **Scheduling** does not touch OS cron/Task Scheduler. `hunt-schedule`
    computes `next_run` (croniter) and runs due schedules when invoked; the
    operator wires it to their own scheduler.

## Phase 6 (SCALE)

18. Scaffold only, per spec ("no code yet"). `MasterCoordinator` / `WorkerManager`
    expose dataclasses + `status()` and raise `ScaleNotApprovedError` on
    functional calls, pending approval.

## Verification

19. 244 offline tests (unit + integration + e2e). All pass. Grep audit: no
    `shell=True`, no hardcoded secrets, destructive SQL only inside the guard.
20. **Not verified offline:** live behaviour against real targets, real scanner
    binaries, real NVD/H1/Bugcrowd endpoints, and real chat transports — these
    require installed tools, credentials, and authorized targets.

## v1.1.0 (Horizon) — roadmap waves

21. **VERIFY phase** (`lib/verifier.py`, `phases/verify/`) — deterministic
    confirmation before submission; encoded reflection disproved, multi-tool
    corroboration; wired between PROBE and ANALYZE.
22. **Threat feeds** (`lib/threat_feeds.py`) — CISA KEV + EPSS; enrichment and
    priority ordering in `lib/cve_workflow.py`; enabled via `cve.use_kev/use_epss`
    (code default off → offline-safe; shipped nexus.yaml enables both).
23. **Agent loop** (`lib/agent.py`, `skills/`) — plan→act→observe over a
    whitelisted action map; AI planner with heuristic fallback; JSONL audit.
24. **Ops commands** — `lib/doctor.py` (nexus doctor), `lib/selfscan.py`
    (nexus self-scan), `lib/delta.py` (--delta scanning), `lib/scope_sync.py`
    (nexus scope-sync).
25. **Control plane** — `phases/control/c2_actions.py` (target/schedule
    management), confirm-gated destructive ops + JSONL audit in
    `c2_commands.py`, drift/new-tech dispatch via `Coordinator._post_scan_intel`.
26. **Reporting/packaging** — HTML export (`core/exporter.export_html`),
    `pyproject.toml`, `Dockerfile`, `docker-compose.yml`, GitHub Actions CI
    (tests + self-scan gate).
27. **Version** bumped to 1.1.0 “Horizon”.

## v1.2.0 (Ascend) — Wave 2 finish

28. **IDOR prober** (`lib/idor_prober.py`) — read-only differential testing
    (injected fetch, shape-compare); **logic detector** (`lib/logic_detector.py`)
    flags price/role/bulk patterns as POTENTIAL only; both wired into PROBE.
29. **OpenAPI ingestion** (`lib/openapi.py`), **SARIF export**
    (`core/exporter.export_sarif`), **Intigriti + YesWeHack** fetchers
    (merged into auto-hunt).
30. **AI upgrades** — model routing (`route`), per-run call budget (`max_calls`),
    adversarial FP check (`disprove_finding`); config `ai.strong_model`/`ai.max_calls`.
31. **Ops guards** (`lib/ops_guard.py`) — kill-switch + request budget; payload-guard
    audit log; digest alerts; `nexus serve` daemon.
32. **Boundary fuzzing** — seeded property tests (1700+ assertions) on payload guard
    and scope validator.
33. **Version** bumped to 1.2.0 “Ascend”; CI now runs with coverage.

## Not shipped (documented gaps)

34. **H5 data-retention pruning** was blocked by the platform safety guard
    (`shutil.rmtree` classified as destructive file API); intentionally omitted.
35. Remaining: D4 parallel tool execution, E3/E5, C4/C5 (AI narratives/local models),
    B4–B6 (exploit feeds/zero-day watch), and Wave 3 (SCALE, mobile, cloud depth,
    dashboards, signed releases).

## v2.0.0 (Apex) — tractable-completion release

36. **E3 program monitor** (`lib/program_monitor.py`) — persisted snapshot diff
    (new/changed/removed programs incl. scope/payout drift); `nexus monitor`.
37. **K2 GraphQL analysis** (`lib/graphql_probe.py`) — introspection result
    analysis (sensitive types, mutation surface, deprecated fields); `nexus graphql`.
38. **E5 submission drafts** — `core/reporter.render_draft` + `nexus draft <id>`;
    drafts auto-written per high-value finding under `reports/drafts/`.
    XSS payloads are intentionally kept in drafts (they ARE the proof);
    cookies/tokens stay redacted.
39. **D4 parallel execution** — `run_all_light_parallel` (thread pool) behind
    `--parallel N`.
40. **D8 SCALE (functional local)** — `MasterCoordinator` with a real queue +
    thread pool and `WorkerManager.execute`; multi-host `dispatch_remote` still
    raises NotImplementedError (needs SSH/Redis infra).
41. **C4/C5/B3/B5 AI & feeds** — Ollama keyless provider, `write_narrative`,
    GHSA feed, CPE matchers in generated nuclei templates.
42. **H5 retention, re-scoped** — the safety guard denied `shutil.rmtree`, so
    retention is a **report-only** command (`nexus retention`); NEXUS never
    deletes operator data by design. Documented rather than worked around.
43. **I3 golden-file tests** — real-shaped nuclei/dalfox/sqlmap outputs.
44. **Version** 2.0.0 “Apex”; 282 tests green.
