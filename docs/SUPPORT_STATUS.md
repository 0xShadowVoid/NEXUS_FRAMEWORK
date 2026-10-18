# Support Status & Documentation Inventory

This page is the **single authoritative map** of what NEXUS documents, where each
item is implemented, how it is verified, and its honest support status. It is the
consistency checklist referenced by [FEATURE_MAP.md](FEATURE_MAP.md) (product
history) and [SECURITY.md](SECURITY.md) (enforcement).

## Status legend

| Status | Meaning |
|---|---|
| **supported** | Implemented **and** exercised by the automated test suite. |
| **partial** | Implemented with documented limits (see the limitation column/notes). |
| **unverified** | Implemented and safe, but **not** covered by an automated test and/or not validated against a live external system (no fixture exists offline). |
| **unavailable** | Documented/known but **not** implemented — always fails closed or is explicitly rejected. |

`unverified` is not a defect: most live external systems (ZAP, Burp, Caido, cloud
SDKs, third-party tools) cannot be contacted from the offline test suite. The
point of this page is to say so plainly rather than imply coverage that does not
exist.

## CLI commands

All commands share the scope gate, kill switch and budget controls unless noted.
Evidence is the test file that exercises the command (blank = no direct
automated test → `unverified`).

| Command | Implementation | Status | Evidence |
|---|---|---|---|
| `hunt` | `nexus.cmd_hunt` → `core/coordinator.py` | supported | `tests/e2e/test_full_scan.py`, `tests/integration/test_phase_flow.py` |
| `batch` | `nexus.cmd_batch` | supported | `tests/integration/test_phase_flow.py` |
| `hunt-schedule` | `nexus.cmd_hunt_schedule`, `core/database.py` | supported | `tests/unit/test_status_and_rate.py` |
| `hunt-new` | `nexus.cmd_hunt_new`, `phases/hunt/auto_hunter.py` | partial (auto-hunt off by default) | `tests/unit/` |
| `export` | `nexus.cmd_export`, `core/exporter.py` | supported | `tests/unit/test_export_and_intel.py`, `tests/integration/test_cve_and_export.py` |
| `import` | `nexus.cmd_import`, `core/importer.py` | supported | `tests/unit/test_export_and_intel.py` |
| `diff` | `nexus.cmd_diff`, `core/coordinator.py` | supported | `tests/unit/` |
| `cve-update` | `nexus.cmd_cve_update`, `lib/cve_workflow.py` | supported | `tests/unit/test_pass3c_cve.py` |
| `cve-scan` | `nexus.cmd_cve_scan`, `lib/cve_fetcher.py` | supported | `tests/unit/test_pass3c_cve.py` |
| `verify` | `nexus.cmd_verify`, `core/lifecycle.py` | supported | `tests/unit/test_pass3b_lifecycle.py`, `test_verifier.py` |
| `reject` | `nexus.cmd_reject`, `lib/false_positive_filter.py` | supported | `tests/unit/test_fp_learning.py` |
| `dork` | `nexus.cmd_dork`, `phases/discover/dorker.py` | supported (engines off by default) | `tests/unit/test_dorker.py` |
| `doctor` | `nexus.cmd_doctor`, `lib/doctor.py` | supported | `tests/unit/test_ops_tools.py` |
| `self-scan` | `nexus.cmd_self_scan`, `lib/selfscan.py` | supported | `tests/unit/test_pass24_precommit_secret_scan.py` |
| `secretscan` | `nexus.cmd_secretscan`, `lib/selfscan.py` | supported | `tests/unit/test_pass24_precommit_secret_scan.py` |
| `hooks` | `nexus.cmd_hooks`, `scripts/hooks/pre-commit` | supported | `tests/unit/test_pass24_precommit_secret_scan.py` |
| `scope-sync` | `nexus.cmd_scope_sync`, `lib/scope_sync.py`, `lib/scope_providers.py` | supported (live platform API `unverified`) | `tests/unit/test_pass23_scope_auto_sync.py`, `test_pass25_scope_drift_alerts.py` |
| `agent` | `nexus.cmd_agent`, `lib/agent.py`, `lib/ai_agents.py` | supported (dry-run deterministic) | `tests/unit/test_agent.py`, `test_nemesis_agents.py` |
| `team` | `nexus.cmd_team`, `lib/nemesis/runtime.py` | partial (local only; multi-host out of scope) | `tests/unit/test_pass20_multi_agent_runtime.py` |
| `zap` | `nexus.cmd_zap`, `lib/adapters/zap.py` | partial (needs a live ZAP; `--mock` supported) | `tests/unit/test_pass22_zap_adapter.py` |
| `burp` | `nexus.cmd_burp`, `lib/adapters/burp.py` | partial (Burp Pro REST; live use `unverified`) | `tests/unit/test_pass26_burp_adapter.py` |
| `caido` | `nexus.cmd_caido`, `lib/adapters/caido.py` | partial (read-only; live use `unverified`) | `tests/unit/test_pass27_caido_adapter.py` |
| `mcp` | `nexus.cmd_mcp`, `lib/mcp/` | supported (`--mock` offline) | `tests/unit/test_pass28_mcp_client.py`, `test_pass29_mcp_hardening.py` |
| `c2` | `nexus.cmd_c2`, `phases/control/` | partial (needs bot tokens; live `unverified`) | `tests/unit/test_c2_control.py` |
| `openapi` | `nexus.cmd_openapi`, `lib/openapi.py` | supported | `tests/unit/` |
| `serve` | `nexus.cmd_serve`, `core/coordinator.py` | supported (`--once`) | `tests/unit/test_status_and_rate.py` |
| `gui` | `nexus.cmd_gui`, `core/gui.py` | supported (fails closed without creds) | `tests/unit/test_pass7_gui.py`, `test_pass13_gui_authz.py`, `test_gui_launcher.py` |
| `retention` | `nexus.cmd_retention`, `lib/retention.py` | supported (report-only by design) | `tests/unit/` |
| `monitor` | `nexus.cmd_monitor`, `lib/program_monitor.py` | supported (live feed `unverified`) | `tests/unit/` |
| `graphql` | `nexus.cmd_graphql`, `lib/graphql_probe.py` | supported | `tests/unit/` |
| `draft` | `nexus.cmd_draft`, `core/reporter.py` | supported | `tests/unit/` |
| `check-tools` | `nexus.cmd_check_tools` | supported | `tests/unit/test_ops_tools.py` |
| `ai-keys` | `nexus.cmd_ai_keys`, `lib/key_pool.py` | supported | `tests/unit/test_key_pool.py` |
| `ai-providers` | `nexus.cmd_ai_providers`, `lib/ai_providers.py` | supported | `tests/unit/test_nemesis_agents.py` |
| `ai-runtime` | `nexus.cmd_ai_runtime`, `lib/local_runtime.py` | partial (needs a local runtime; live `unverified`) | `tests/unit/test_pass19_local_runtime.py` |
| `ai-set-key` | `nexus.cmd_ai_set_key`, `lib/key_pool.py` | supported | `tests/unit/test_key_pool.py` |
| `update` | `nexus.cmd_update` | **unverified** (pulls from the network; no offline test) | — |

## Subsystems & security controls

| Capability | Implementation | Status | Notes |
|---|---|---|---|
| Scope gate (in/out-of-scope, anchored wildcards, fail closed) | `lib/scope_validator.py` | supported | `tests/unit/test_scope_validator.py`, `test_pass10_scope_handoff.py` |
| Finding lifecycle (`candidate → probable → validated → rejected`) | `core/lifecycle.py` | supported | `tests/unit/test_pass3b_lifecycle.py` |
| Evidence + audit persistence (redaction at the choke point) | `core/database.py`, `core/sanitizer.py` | supported | `tests/unit/test_database.py`, `test_pass3b_evidence.py` |
| Schema migrations (additive, target v5) | `core/migrations.py` | supported | `tests/unit/test_pass30_integration_audit.py` |
| Backup / restore | `core/database.py` (`backup_to`/`restore_from`) | supported | `tests/unit/test_pass9_backup.py` |
| SSRF guard | `lib/ssrf_guard.py` | supported | `tests/unit/test_pass3b_ssrf.py` |
| Payload guard (recursive) | `lib/payload_guard.py` | supported | `tests/unit/test_payload_guard.py` |
| Kill switch + request budget | `lib/ops_guard.py` | supported | `tests/unit/` |
| Secret redaction | `lib/redaction.py`, `core/sanitizer.py` | supported | `tests/unit/test_utils_and_sanitizer.py` |
| AI provider pool + failover | `lib/ai_analyzer.py`, `lib/ai_errors.py`, `lib/key_pool.py` | supported (live calls `unverified`) | `tests/unit/test_ai_analyzer.py`, `test_pass11_ai_orchestration.py` |
| Local model runtime probe | `lib/local_runtime.py` | partial (best-effort metadata) | `tests/unit/test_pass19_local_runtime.py` |
| Tool-handoff re-validation | `phases/probe/tool_runner.py` | supported | `tests/unit/test_pass10_scope_handoff.py` |
| Boundary fuzzing (seeded properties) | `tests/unit/test_fuzz_boundary.py` | supported | self |

## External integrations (all disabled by default)

| Integration | Module | Status | Live-instance evidence |
|---|---|---|---|
| OWASP ZAP adapter | `lib/adapters/zap.py` | partial | `unverified` — needs a running ZAP; `--mock` is deterministic |
| Burp Suite Pro adapter | `lib/adapters/burp.py` | partial | `unverified` — Burp Pro REST API required |
| Caido adapter (read-only) | `lib/adapters/caido.py` | partial | `unverified` — needs a running Caido |
| MCP client | `lib/mcp/` | supported (offline) | `unverified` against a third-party server |
| AI HTTP providers | `lib/ai_analyzer.py` | supported (offline) | `unverified` against live provider APIs |
| OpenCode / Cline | `lib/ai_providers.py` | **unavailable** | rejected where validated (`nemesis.agents`); see [AI_AND_NEMESIS.md](AI_AND_NEMESIS.md) |
| Cloud posture (AWS/Azure/GCP) | `phases/cloud/` | partial | `unverified` — needs cloud credentials |
| Browser automation | `lib/` (Playwright) | partial | `tests/integration/test_pass4_browser_real.py` (skips without a browser) |

## Docker & packaging

| Item | Status | Notes |
|---|---|---|
| `Dockerfile` / `docker-compose.yml` (tag `2.0.2`) | supported | `docker compose config` validates; `docker compose build` + in-container `doctor` smoke test pass locally (Docker Engine 29.7.2, linux/amd64, 281 MB) and in the CI `docker` job. The image installs runtime deps only (`pip install .`) and bakes no secrets. |
| Console script (`nexus`) + `pip install .` | supported | the Docker image is built with `pip install .`; also covered by clean-venv install checks |

## Known residual limitations (cross-reference)

- Scope applies to NEXUS's own requests and to targets handed to external tools; a
  third-party binary's *internal* behavior (its own redirects/enumeration) cannot
  be policed. Keep `in_scope` precise.
- An exact `in_scope` entry does not authorize subdomains — add `*.domain`.
- Adapters are read-only or opt-in; active scanning is intrusive and per-run
  authorized (`--authorize-active`).
- Reserved (documented-but-unwired) config keys are listed in
  [CONFIGURATION.md](CONFIGURATION.md): `results.base_dir`/`exports_dir`,
  top-level `schedules:`, `cve.auto_update`/`frequency`/`time`/`script_delivery`,
  `c2_bot.use_same_webhook`, `phases.control.enabled`/`phases.scale.enabled`,
  `nemesis.enabled` (informational), `nemesis.mcp.enabled` (not the MCP switch).
- A corrupt SQLite database raises `sqlite3.DatabaseError`; recover by moving the
  file aside and restoring a backup (see [NEXUS_OPERATIONS_GUIDE.md](NEXUS_OPERATIONS_GUIDE.md)).

## Documentation inventory

| Doc | Purpose |
|---|---|
| [../README.md](../README.md) | Overview, install, quick start, doc map |
| [GETTING_STARTED.md](GETTING_STARTED.md) | Step-by-step first scan |
| [BEGINNER_GUIDE.md](BEGINNER_GUIDE.md) | Gentler walkthrough |
| [INSTALLATION.md](INSTALLATION.md) | Source/wheel/clean-venv installs |
| [NEXUS_FIRST_RUN_CHECKLIST.md](NEXUS_FIRST_RUN_CHECKLIST.md) | Post-install checklist (1060 tests) |
| [CONFIGURATION.md](CONFIGURATION.md) | Every config key + env var |
| [CLI_REFERENCE.md](CLI_REFERENCE.md) | All commands and flags |
| [WORKFLOWS.md](WORKFLOWS.md) | End-to-end workflows |
| [EXAMPLES.md](EXAMPLES.md) | Copy-paste examples |
| [NEXUS_OPERATIONS_GUIDE.md](NEXUS_OPERATIONS_GUIDE.md) | Deployment, GUI, backup/recovery |
| [REPORTS_AND_DATABASE.md](REPORTS_AND_DATABASE.md) | Results layout, exports, DB |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Diagnostics and common errors |
| [PHASES.md](PHASES.md) | Phase registry |
| [TOOLS_REFERENCE.md](TOOLS_REFERENCE.md) | Built-in vs optional tools |
| [NEXUS_DEPENDENCY_MATRIX.md](NEXUS_DEPENDENCY_MATRIX.md) | Python deps and external tools |
| [ADAPTERS.md](ADAPTERS.md) | ZAP/Burp/Caido adapter contract |
| [MCP.md](MCP.md) | MCP client + gateway |
| [AI_AND_NEMESIS.md](AI_AND_NEMESIS.md) | Providers and no-AI behavior |
| [SECURITY.md](SECURITY.md) | Enforcement matrix and safe-use policy |
| [HOOKS.md](HOOKS.md) | Secret scanning + pre-commit hook |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Component/data-flow diagram + repo structure |
| [FEATURE_MAP.md](FEATURE_MAP.md) | Feature history and status |
| [ROADMAP.md](ROADMAP.md) | Planned future work |
| [SKILLS_REFERENCE.md](SKILLS_REFERENCE.md) | NEMESIS skill files |
| [SUPPORT_STATUS.md](SUPPORT_STATUS.md) | **This page** |
| [RELEASE_READINESS.md](RELEASE_READINESS.md) | Release-readiness checklist |
| [../SECURITY.md](../SECURITY.md) | Vulnerability disclosure policy (distinct from docs/SECURITY.md) |
