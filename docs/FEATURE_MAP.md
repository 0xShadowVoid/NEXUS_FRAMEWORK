# NEXUS — Feature Map (82 features)

Status legend: **done** = implemented + covered by tests · **partial** = implemented
with documented limits · **scaffold** = placeholder pending approval.

## Core features (1–70)

| # | Feature | Module | Status |
|---|---|---|---|
| 1 | Multi-phase automation (DISCOVER → SCALE) | `core/coordinator.py` | done |
| 2 | Pegpon (15 light tools) | `phases/discover/pegpon_wrapper.py` | done |
| 3 | BBot (100+ modules, deep only) | `phases/discover/bbot_wrapper.py` | done |
| 4 | 14 additional tools | `phases/probe/tool_runners.py` | done |
| 5 | Wappalyzer tech detection | `phases/discover/wappalyzer_wrapper.py` | done |
| 6 | Smart nuclei template matching | `phases/probe/nuclei_orchestrator.py` | done |
| 7 | Dalfox XSS detection | `phases/probe/dalfox_runner.py` | done |
| 8 | SQLmap (light mode default) | `phases/probe/sqlmap_runner.py` | done |
| 9 | Commix command injection | `phases/probe/tool_runners.py` | done |
| 10 | Ghauri blind SQLi | `phases/probe/tool_runners.py` | done |
| 11 | 401/403/404 fuzzing + bypass | `tool_runners.run_nomore403` | done |
| 12 | JWT analysis | `tool_runners.run_jwt_tool` | done |
| 13 | LFI detection | `tool_runners.run_lfihunt` | done |
| 14 | GraphQL scanning | `tool_runners.run_graphql_cop` | done |
| 15 | WAF detection | `tool_runners.run_waf_probe` | done |
| 16 | Cloud scanning (S3/AWS/Azure) | `tool_runners` cloud tools | done |
| 17 | Light vs deep scanning modes | `ScanOptions.deep` | done |
| 18 | Tool-specific timeout | `phases/probe/tool_runner.py` | done |
| 19 | Concurrent execution | `core/coordinator.py` batch | done |
| 20 | Tool failure handling (mode-dependent) | `ToolRunner.run` | done |
| 21 | Exact checkpoint resume | `coordinator` + probe checkpoint | done |
| 22 | Auto-dependency detection | probe→discover, bbot→pegpon | done |
| 23 | Tool skip/run-only flags | `--skip-tools` / `--run-tools` | done |
| 24 | Deduplication (fuzzy match) | `lib/deduplicator.py` | done |
| 25 | Severity scoring (impact-based) | `lib/severity_scorer.py` | done |
| 26 | Chain detection (dependency graphs) | `lib/chainer.py` | done |
| 27 | False-positive filtering | `lib/false_positive_filter.py` | done |
| 28 | IDOR auto-detection | heuristics in scorer/chainer | partial (heuristic, no active prober) |
| 29 | Business-logic pattern detection | heuristics in scorer/chainer | partial (heuristic) |
| 30 | Database (SQLite) | `core/database.py` | done |
| 31 | Findings storage + querying | `core/database.py` | done |
| 32 | Screenshot capture (named) | `lib/screenshot.py` | done (needs `gowitness`) |
| 33 | API key management (.keys.env) | `lib/config.py`, `lib/key_pool.py` | done |
| 34 | Platform API integration (H1/Bugcrowd) | `phases/hunt/api_fetcher.py` | done |
| 35 | Scope validation | `lib/scope_validator.py` | done |
| 36 | Wildcard target support | `lib/scope_validator.py` | done |
| 37 | Single domain scanning | `nexus.py hunt` | done |
| 38 | Multi-domain scanning | `nexus.py batch` | done |
| 39 | Cloud target support | `scope_validator` + cloud tools | done |
| 40 | Cookie injection | `--cookie` → runners | done |
| 41 | Rate limiting (per-target) | `lib/rate_limiter.py` | done |
| 42 | Config file (nexus.yaml) | `lib/config.py` | done |
| 43 | Target-specific overrides | `lib/config.py`, coordinator | done |
| 44 | Batch mode (per-target settings) | `nexus.parse_targets_file` | done |
| 45 | Scheduling (--daily/--weekly/--every-6h/--cron) | `core/coordinator.py` | done |
| 46 | Methodology checklist | `lib/methodology.py`, `config/methodologies.yaml` | done |
| 47 | Methodology change alerts | `lib/methodology.check_drift` | partial (drift detection; alert dispatch manual) |
| 48 | CVE auto-update (daily) | `lib/cve_workflow.py` | done (invoke from scheduler) |
| 49 | CVE filtering (severity) | `lib/cve_fetcher.py` | done |
| 50 | CVE auto-POC generation | `lib/cve_poc_generator.py` | done |
| 51 | CVE nuclei template registration | `register_nuclei_template` | done |
| 52 | CVE email delivery (scripts attached) | `notifications.EmailAlerter` | done |
| 53 | CVE Discord alerts | `Notifier.send_cve` | done |
| 54 | CVE Telegram alerts | `Notifier.send_cve_telegram` | done |
| 55 | Scan resume (checkpoint) | `--resume` | done |
| 56 | Phase skip (--discover-only/--scan-only) | `ScanOptions` | done |
| 57 | Tool ordering (tech-first) | discover→probe ordering | done |
| 58 | Result naming (standardized) | `lib/utils.py` | done |
| 59 | Export (zip/7z/json/csv) | `core/exporter.py` | done |
| 60 | Import (restore) | `core/importer.py` | done |
| 61 | Scan comparison (diff) | `Coordinator.diff_scans` | done |
| 62 | Batch mode (concurrent/sequential) | `nexus.py batch` | done |
| 63 | C2 bot (Discord + Telegram) | `phases/control/*` | done |
| 64 | C2 commands (/hunt /stop /logs /report /status) | `phases/control/c2_commands.py` | done |
| 65 | GitHub bug hunt agent | `dorker.py` (github_leaks) | partial (dork intent, not a full agent) |
| 66 | AI finding categorization | `lib/ai_analyzer.py` | done |
| 67 | AI chain detection | `ai_analyzer.suggest_chains` | done |
| 68 | AI error analysis | `ai_analyzer.analyze_error` | done |
| 69 | Any AI provider (OpenAI/GLM/DeepSeek/Gemini) | `lib/ai_analyzer.py` | done (+ multi-key failover) |
| 70 | Real reports + skills (FP filters) | `core/reporter.py`, templates | done |

## Enhancement features (71–82)

| # | Feature | Module | Status |
|---|---|---|---|
| 71 | Arjun (light scan only) | `tool_runners.run_arjun` | done |
| 72 | Exclude findings (--exclude-p4) | `--exclude-p4` → analyzer | done |
| 73 | Min severity (--min-severity) | `--min-severity` → analyzer | done |
| 74 | Smart tool pipeline (Wappalyzer → selection) | `nuclei_orchestrator` | done |
| 75 | Export/import workflows | `core/exporter.py`, `core/importer.py` | done |
| 76 | Enhanced naming (scope type) | `lib/utils.py` | done |
| 77 | Email alerting (CVE scripts attached) | `lib/cve_workflow.py` | done |
| 78 | Separate alert webhooks (findings/CVE/metrics) | `lib/notifications.py` | done |
| 79 | Per-type FP strictness | `lib/false_positive_filter.py` | done |
| 80 | Methodology checklist + alerts | `lib/methodology.py` | done |
| 81 | Auto-generated POC scripts (4 formats) | `lib/cve_poc_generator.py` | done |
| 82 | Permission-boundary enforcement | `payload_guard`, `scope_validator`, DB guard, `sanitizer` | done |

## Extensions requested by the author

| Feature | Module | Status |
|---|---|---|
| Multi-engine dorking (DDG/Google/Bing/GitHub) | `phases/discover/dorker.py` | done |
| AI multi-key pool + failover | `lib/key_pool.py`, `lib/ai_analyzer.py` | done |
| `nexus.py ai-set-key` / `ai-keys` | `nexus.py` | done |

## Roadmap waves shipped in 1.1.0 (Horizon)

| # | Feature | Module | Status |
|---|---|---|---|
| A1 | VERIFY phase (deterministic confirmation) | `lib/verifier.py`, `phases/verify/` | done |
| A2 | Multi-tool corroboration policy | `lib/verifier.py`, `core/analyzer.py` | done |
| B1 | CISA KEV known-exploited feed | `lib/threat_feeds.py` | done |
| B2 | EPSS exploitation scoring | `lib/threat_feeds.py` | done |
| C1 | Agent loop (plan→act→observe) | `lib/agent.py`, `skills/` | done |
| D1/D2 | Docker + GitHub Actions CI | `Dockerfile`, `.github/workflows/ci.yml` | done |
| D3 | Packaging (`nexus` console script) | `pyproject.toml` | done |
| D5 | `nexus doctor` | `lib/doctor.py` | done |
| D6 | Delta scanning (`--delta`) | `lib/delta.py` | done |
| E1 | Scope auto-sync | `lib/scope_sync.py` | done |
| F1 | HTML export | `core/exporter.py` | done |
| G1/G2/G5 | C2 target/schedule mgmt + audit + drift alerts | `phases/control/`, `core/coordinator.py` | done |
| H1 | Self secret-scan | `lib/selfscan.py` | done |
| J3 | Methodology drift dispatch | `core/coordinator.py` | done |

## Roadmap waves shipped in 1.2.0 (Ascend)

| # | Feature | Module | Status |
|---|---|---|---|
| J1 | Active IDOR prober (read-only differential) | `lib/idor_prober.py` | done |
| J2 | Business-logic detector | `lib/logic_detector.py` | done |
| K1 | OpenAPI/Swagger ingestion | `lib/openapi.py` | done |
| F2 | SARIF export | `core/exporter.export_sarif` | done |
| E2 | Intigriti + YesWeHack fetchers | `phases/hunt/api_fetcher.py` | done |
| C2 | AI model routing (triage vs reason) | `lib/ai_analyzer.route` | done |
| C3 | Adversarial FP check | `lib/ai_analyzer.disprove_finding` | done |
| C6 | AI per-run call budget | `lib/ai_analyzer.max_calls` | done |
| D7 | Scheduler daemon (`nexus serve`) | `nexus.py` | done |
| G4 | Digest alerts | `lib/notifications.send_digest` | done |
| H2 | Kill-switch + request budget | `lib/ops_guard.py` | done |
| H3 | Boundary fuzzing (seeded property tests) | `tests/unit/test_fuzz_boundary.py` | done |
| H4 | Payload-guard audit log | `lib/payload_guard.py` | done |
| I1 | Coverage in CI | `.github/workflows/ci.yml` | done |

**Not shipped in 1.2.0 (remaining):** H5 data-retention (blocked by the platform safety guard on
`shutil.rmtree`), D4 parallel tool execution, E3/E5 (program monitor, submission drafts),
C4/C5 (AI narratives, local models), B4–B6 (exploit feeds, zero-day watch), and all of
Wave 3 (Phase 6 SCALE, mobile, cloud-depth, dashboards, signed releases).

## Roadmap waves shipped in 2.0.0 (Apex)

| # | Feature | Module | Status |
|---|---|---|---|
| E3 | Program monitor (new/changed/removed) | `lib/program_monitor.py`, `nexus monitor` | done |
| K2 | GraphQL introspection analysis | `lib/graphql_probe.py`, `nexus graphql` | done |
| E5 | Submission drafts (per finding + auto) | `core/reporter.render_draft`, `nexus draft` | done |
| D4 | Parallel light-tool execution | `tool_runners.run_all_light_parallel`, `--parallel` | done |
| D8 | SCALE phase (functional local master/worker) | `phases/scale/` | done (local; multi-host flagged) |
| C5 | Local models (Ollama, keyless) | `lib/ai_analyzer` | done |
| C4 | AI report narratives | `ai_analyzer.write_narrative` | done |
| B3 | GHSA advisory feed | `threat_feeds.fetch_ghsa` | done |
| B5 | CPE matchers in nuclei templates | `cve_poc_generator` | done |
| H5 | Retention (non-destructive report) | `lib/retention.py`, `nexus retention` | done (report-only by design) |
| I3 | Golden-file parser tests | `tests/unit/test_golden_parsers.py` | done |

**Remaining not built (needs live infra/credentials, or explicitly out of scope offline):**
multi-host SCALE dispatch (SSH/Redis — `dispatch_remote` raises NotImplementedError by design),
K3 cloud-posture depth (needs cloud creds), K4 source-assisted (needs Semgrep), K6 mobile/APK
(needs APK tooling), H6 signed releases (needs packaging keys), I4/I5 (VCR/mutation rigs),
G3 live bot UI buttons, F4 screenshot PII blur (needs imaging pipeline), B4/B6 commercial
exploit feeds & zero-day watch (paid/beyond-NVD sources), K5 supply-chain recon.

## Summary

- **done:** 74
- **partial:** 5 (28, 29, 47, 65, + screenshot capture depends on an external binary)
- **scaffold:** Phase 6 SCALE (per spec, intentionally not implemented)
