# Testing

NEXUS is tested **offline and deterministically**. The default suite never contacts a live
target, third-party tool, AI provider, or platform API, and it needs no credentials. Live
integrations are covered by mock/contract tests and are labelled `unverified` where no offline
fixture can exist (see [SUPPORT_STATUS.md](SUPPORT_STATUS.md)).

## Quick start

```powershell
pip install .[dev]
python -m pytest tests -q
```

With coverage (the same shape used in CI):

```powershell
python -m pytest tests -q --cov=lib --cov=core --cov-report=term-missing
```

### Windows note

If a test run cannot create its temporary directory, point pytest at a writable location:

```powershell
python -m pytest tests -q --basetemp="$env:TEMP\nexus-pytest"
```

## Test layout

| Path | Purpose |
|---|---|
| `tests/unit/` | Fast, isolated tests for modules, guards, parsers, and CLI helpers |
| `tests/integration/` | Cross-module flows: phase pipeline, adapters, MCP, browser, CVE/export |
| `tests/e2e/` | End-to-end scan paths against local fixtures |
| `tests/cve_pocs/` | Fixtures for CVE/PoC generation |
| `conftest.py` | Adds the repository root to `sys.path` so `lib` / `core` / `phases` import without installation |

Tests use temporary databases and temporary result directories; they never read or overwrite a
real `config/nexus.yaml`, `config/.keys.env`, `nexus.db`, or `results/` tree.

## Expected results (baseline)

Recorded on the 2.0.2 baseline (`e15c19c`) with Python 3.13:

| Environment | Result |
|---|---|
| Default (no Playwright browser) | **1081 passed, 11 skipped** (~84% coverage) |
| With Playwright + Chromium installed | **1091 passed, 1 skipped** (~85% coverage) |

- The 11 default skips are the opt-in real-browser tests in
  `tests/integration/test_pass4_browser_real.py`; they skip when no browser executable is
  installed.
- With a browser installed, those 11 run; the single remaining skip is the deliberate
  degradation test in `tests/unit/test_nemesis_adapters.py`, which asserts graceful fallback
  precisely when Playwright **is** available.
- CI runs on Python **3.11**; exact counts can shift when dependencies change. Treat the
  numbers above as a baseline, not a contract.

## Running a subset

```powershell
python -m pytest tests/unit -q
python -m pytest tests/integration -q
python -m pytest tests/unit/test_scope_validator.py -q
python -m pytest tests -q -k "scope or ssrf or payload"
```

## Real-browser tests (opt-in)

The browser tests drive a real Chromium instance and are intentionally excluded from the
default job. Install the backend, then use the runner (it fails if any collected test is
skipped, so a missing browser cannot silently pass):

```powershell
pip install playwright
playwright install --with-deps chromium
python scripts/run_browser_tests.py
```

Expected on a healthy install: `11 passed`, `0 skipped`, and the final line
`ok: 11 real-browser tests executed, 0 skipped`.

The runner accepts extra pytest arguments (for example `--basetemp`) and forwards them.

## CI workflows

| Workflow | Trigger | Jobs |
|---|---|---|
| `.github/workflows/ci.yml` | push / pull request | **test** (pytest + coverage + self-scan/hook lint) and **docker** (build + in-container `doctor` smoke test) |
| `.github/workflows/browser.yml` | `workflow_dispatch` only | installs Playwright + Chromium and runs `scripts/run_browser_tests.py`; fails if any real-browser test is skipped |

The browser workflow is opt-in so the default CI stays fast and deterministic.

## Writing tests

- **Offline only.** Mock HTTP/SDK calls; never require a live account, target, or API key.
- **Isolate state.** Use `tmp_path` for configuration, databases, and results. Do not mutate the
  repository's real config or `nexus.db`.
- **Deterministic.** No sleeps for synchronization; no random data without a fixed seed.
- **Test the boundary.** Security changes should include a fail-closed test (out-of-scope,
  blocked payload, malformed input, missing credentials).
- **Prefer focused tests.** Add to the nearest existing module instead of creating broad new
  suites; follow the surrounding naming and fixtures.

## Coverage

Coverage is reported for `lib/` and `core/`. The remaining uncovered branches are mostly
defensive/error paths and live-I/O adapters; they are reviewed in
[releases/NEXUS_STABILITY_REPORT.md](releases/NEXUS_STABILITY_REPORT.md) rather than chased for
a number. Do not weaken assertions or add `# pragma: no cover` to raise coverage artificially.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `No module named nexus` | Run pytest from the repository root, or install with `pip install .` |
| Browser tests skipped | Install Playwright **and** a browser (`playwright install chromium`); `playwright_available()` requires an executable, not just the package |
| `PermissionError` on temp dirs (Windows) | Use `--basetemp` under `%TEMP%` |
| A test writes to the real `results/` | Bug in the test — use `tmp_path`; report it |
| Counts differ from the baseline | Dependency or Python-version drift; compare with the CI run for the same commit |
