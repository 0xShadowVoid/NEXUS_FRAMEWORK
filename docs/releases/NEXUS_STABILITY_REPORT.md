# NEXUS Stability & Maintenance Review (Task 29)

**Verdict: STABLE FOR MAINTENANCE**

- Reviewed commit: **`995c095`** (`HEAD == origin/main`), version **2.0.2 ("Apex")**.
- Published release: tag `v2.0.2` (commit `c41ee6e`) — **unchanged**. No tag or release
  was created or modified during this review.
- Review date: 2026-10-19.

This review re-verifies release-critical behavior, residual risk, coverage and CI at
the current tree, then sets a maintenance policy. It is evidence-based only: no
feature was added and no coverage target was pursued for its own sake. No
release-blocking defect was found, so no code was changed.

## 1. Verified results

### 1.1 Test suite & coverage

```bash
python -m pytest tests -q --cov=lib --cov=core --cov-report=term-missing
```

| Environment | Result |
|---|---|
| **Default** (no browser backend — matches CI) | **1081 passed, 11 skipped, 0 failed — 84%** |
| With Playwright + Chromium installed | **1091 passed, 1 skipped, 0 failed — 85%** |

The 11 default skips are **all** in `tests/integration/test_pass4_browser_real.py`
with the explicit reason `playwright browser backend unavailable` (Playwright is an
optional dependency, absent from the runtime and `dev` sets and from default CI).

When a browser backend is present, all 11 execute. The single remaining skip is
`tests/unit/test_nemesis_adapters.py::test_playwright_adapter_degrades_cleanly`,
which **by design** skips only when Playwright *is* installed (it exercises the
no-Playwright degradation path otherwise). It does not affect the opt-in browser job,
which targets only the browser file.

### 1.2 Real-browser verification (opt-in, not default CI)

`.github/workflows/browser.yml` (trigger `workflow_dispatch`, `permissions: contents: read`,
`timeout-minutes: 20`) installs Playwright + Chromium and runs
`scripts/run_browser_tests.py`, which fails unless every test in the file executes.

- CI run **39272549207** — **success**. Playwright **1.64.0**, Chromium
  **156.0.8078.4 (playwright chromium v1248)**.
- Log evidence: `11 tests collected` → `11 passed in 12.67s` →
  `ok: 11 real-browser tests executed, 0 skipped`.
- The same 11 tests were executed locally (11 passed, 0 skipped).
- Isolation: the tests use only throwaway local servers on `127.0.0.1`/`localhost`;
  the metadata hop (`169.254.169.254`) is blocked pre-fetch with a zero-contact
  canary assertion. No external target is contacted.

### 1.3 CI

- Default `ci.yml` run **39262214664** (commit `995c095`): `test` = **success**,
  `docker` = **success**. The default jobs remain lightweight and do not install
  Playwright.
- The `docker` job builds the image and asserts required files are present, no
  secrets/build artifacts are baked in, and the `dev` extra (pytest) is excluded.
- Local Docker verification (Task 25): Engine 29.7.2, linux/amd64, image 281 MB,
  in-container `doctor` exit 0.

### 1.4 Security scans & hygiene

| Check | Result |
|---|---|
| `python nexus.py self-scan` | 0 findings |
| `python nexus.py secretscan --staged` | 0 findings |
| `python nexus.py secretscan --history` | 0 findings (57 commits, all refs) |
| `sh -n scripts/hooks/pre-commit` | exit 0 |
| `git diff --check` | clean |
| `python nexus.py doctor` | exit 0 |
| `python nexus.py --version` | `NEXUS 2.0.2 "Apex"` |

## 2. Security-control review (uncovered critical branches)

Authorization, scope enforcement, SSRF controls, adapter policy, MCP, AI failover,
database integrity and audit redaction were inspected against the coverage report.
The **enforcement logic is exercised**; uncovered lines are defensive/error branches,
untested persistence helpers, or live-I/O integration paths — none hides a broken or
bypassed control.

| Area | Module (coverage) | Judgment |
|---|---|---|
| Scope enforcement | `lib/scope_validator.py` (90%) | deny-overrides, anchored wildcards, IP/CIDR grants, fail-closed all tested; gaps are empty-entry/defensive branches |
| SSRF guard | `lib/ssrf_guard.py` (76%) | metadata/private/loopback/DNS-rebinding block tested; gaps are error paths and the thin `assert_safe_url` wrapper |
| Audit redaction | `lib/redaction.py` (92%), `core/sanitizer.py` (100%) | core secret shapes tested; gaps are defensive |
| GUI authorization | `core/gui.py` (93%) | constant-time Basic auth, fail-closed, config-only scope boundary tested; gaps are the `/api/findings` route and an error branch |
| Adapter policy | `lib/adapters/base.py` (94%) | kill-switch → scope → active-authorization → budget gate tested; gaps are passthrough/`to_dict` helpers |
| MCP | `lib/mcp/transport.py` (37%), `gateway.py` (84%), `client.py` (95%) | policy/SSRF gate in `start()` tested; Stdio-subprocess and Streamable-HTTP network paths uncovered (live I/O) |
| AI failover | `lib/ai_analyzer.py` (87%), `ai_errors.py` (95%), `key_pool.py` (92%) | error classification and failover policy tested; uncovered = live HTTP + advisory prompt builders |
| Database integrity | `core/database.py` (89%) | schema/backup/restore tested; uncovered = untested insert helpers and defensive paths |

## 3. Supported vs unverified

Per [../SUPPORT_STATUS.md](../SUPPORT_STATUS.md): the CLI, scope gate, finding
lifecycle, evidence/audit persistence (redacted at the choke point), schema
migrations, backup/restore, SSRF/payload guards, kill switch + budget, redaction,
and AI failover policy are **supported** (implemented and exercised by the suite).

**Unverified by design** (safe, fail-closed or opt-in, but not validated against a
live external system): ZAP / Burp Pro / Caido adapters against live instances, MCP
against a third-party server, AI HTTP providers against live APIs, cloud posture
(AWS/Azure/GCP) without credentials, live scope-sync platforms, notification
providers, and the Browser/Playwright path outside the opt-in workflow.

## 4. Remaining skips (all justified)

- 11 default skips — the browser integration file, optional Playwright backend absent.
- Conditional skips that do **not** trigger in the default environment:
  `test_pass3a_registry.py` ("python not on PATH"), `test_pass24_precommit_secret_scan.py`
  ("git is required"), and `test_nemesis_adapters.py` (only skips when Playwright *is*
  installed).

No security-critical gateway, scope-enforcement or core-verification test is skipped.

## 5. Residual risks & accepted limitations

- Live external integrations remain `unverified` against real systems by design
  (no live fixtures offline). Deterministic `--mock`/offline paths are tested.
- MCP Stdio-subprocess and Streamable-HTTP transports, AI HTTP calls and adapter live
  transport paths have no offline tests (subprocess/network I/O).
- A third-party binary's internal behavior (its own redirects/enumeration) cannot be
  policed by NEXUS; keep `in_scope` precise.
- An exact `in_scope` entry does not authorize subdomains — add `*.domain`.
- A corrupt SQLite database raises `sqlite3.DatabaseError`; recover by moving the file
  aside and restoring a backup.
- The real-browser path has no continuous CI coverage (opt-in only, by design).

## 6. Maintenance policy

Future work on NEXUS is triggered **only** by:

1. a reproducible defect (with a failing/regression test),
2. a security issue (disclosure or scan finding),
3. a compatibility change (Python, dependency, OS/runner, or interface breakage),
4. an explicitly approved feature.

There is **no automatic task creation**: passing tests are a baseline, not a mandate
for more work, and coverage percentage is not pursued for its own sake. When the
browser path, transports, or adapters change, re-run the relevant opt-in workflow or
live check in addition to the default suite and scans. Published tags and releases
(e.g. `v2.0.2`) are preserved as immutable history.
