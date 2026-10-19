# NEXUS Dependency & Tool Matrix

## 1. Core Python Dependencies (Declared in `pyproject.toml`)
Installed automatically via `pip install`:
- `PyYAML >= 6.0` (YAML configuration parsing)
- `python-dotenv >= 1.0` (Environment variable loading)
- `requests >= 2.31` (HTTP collections & API calls)
- `croniter >= 2.0` (Schedule recurrence calculations)
- `py7zr >= 0.21` (Archive management & export/import support)
- `fastapi >= 0.110` (local web GUI)
- `uvicorn >= 0.29` (ASGI server for the local GUI)
- `pydantic >= 2.6` (GUI request/response schemas)

---

## 2. Optional Extra Dependencies
- **`[project.optional-dependencies]` (c2):** `discord.py >= 2.3`, `python-telegram-bot >= 20` (C2 control bots).
- **`[project.optional-dependencies]` (dev):** `pytest >= 8.0`, `pytest-cov >= 4.0` (coverage gate), `httpx2 >= 2.0` (FastAPI/Starlette `TestClient` transport for the GUI tests).

---

## 3. External Security Tools (Optional / Graceful Degradation)
NEXUS detects installed external binaries at startup. These external security binaries are **not** bundled within the wheel package and must be installed separately on the host system (via system package managers or Go/Python tooling) if full multi-tool scanning is desired. Missing tools are skipped gracefully without crashing scans:

| Phase / Capability | Optional Binaries / Tools | Functionality Unavailable When Missing |
|---|---|---|
| **DISCOVER** | `subfinder`, `assetfinder`, `httpx`, `ffuf`, `katana`, `nuclei`, `bbot` | Advanced subdomain enumeration and passive reconnaissance. |
| **PROBE** | `nuclei`, `dalfox`, `sqlmap`, `arjun` | Automated vulnerability probing and fuzzing. |
| **SCREENSHOTS** | `gowitness` | Headless browser URL screenshot capture. |

To check installed vs. missing tools on your system:
```powershell
python -m nexus check-tools
```

---

## 4. Optional Real-Browser Verification (Playwright)

The browser-backed integration tests in `tests/integration/test_pass4_browser_real.py`
are **skipped by default** — Playwright is optional and is not part of the runtime
or `dev` dependency sets, and the default CI never installs a browser. These tests
exercise the real Chromium driver against local, throwaway test servers
(`127.0.0.1`) only; no external target is contacted.

Run them locally:

```powershell
pip install playwright
playwright install chromium          # Linux also: playwright install-deps chromium
python scripts/run_browser_tests.py  # fails unless every test executes (0 skipped)
```

- **Prerequisites:** Python 3.11+, the `dev` dependencies (`pytest`), and network
  access for the one-time browser download.
- **Expected runtime:** ~1–3 min for the first browser download; the test file
  itself runs in well under a minute.
- **Interpreting failures:** a non-zero exit reporting `skipped=` means the
  backend is not installed (run `playwright install chromium`); `failed=` means a
  real assertion failed — treat it as a browser-policy defect, not a flake.

**Opt-in CI:** `.github/workflows/browser.yml` installs Playwright + Chromium
(`playwright install --with-deps chromium`) and runs the same script. Trigger it
manually (**Actions → browser → Run workflow**, or `gh workflow run browser.yml`).
It is **not** wired to `push`/`pull_request`, so the default CI stays lightweight
and never acquires a browser dependency.
