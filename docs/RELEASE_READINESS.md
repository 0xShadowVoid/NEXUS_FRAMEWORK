# Release Readiness Checklist

Version under review: **2.0.2 ("Apex")**. This checklist is the sign-off gate for
a release. Fill in the commit/run identifiers at the point of release; every row
must be **PASS** or explicitly **N/A with a reason**.

## 0. Audit results (release candidate `715d11d` + Docker hardening)

| Gate | Result |
|---|---|
| Full suite + coverage | **PASS** — `1064 passed, 11 skipped`, **84%** (`lib`+`core`) |
| Self-scan | **PASS** — 0 potential secrets |
| Secret scan (staged) | **PASS** — 0 findings |
| Secret scan (history) | **PASS** — full history (all refs), 0 findings |
| Diff hygiene | **PASS** — `git diff --check` clean |
| Pre-commit hook syntax | **PASS** — `sh -n` exits 0 |
| Documented-command validation | **PASS** — `--version`, `doctor` (exit 0), `mcp --mock`, `zap --mock` |
| `docker compose config` | **PASS** — validates; image tag `nexus-framework:2.0.2` |
| `docker compose build` | **PASS** — image built (Docker Engine 29.7.2, linux/amd64; 281 MB) |
| Container smoke test | **PASS** — `doctor` exits 0 inside the container (13 checks) |
| CI | **PASS** — `test` + `docker` jobs green (see §7) |

## 1. Version & metadata

- [ ] `VERSION` is `2.0.2` and matches `pyproject.toml`, `lib/version.py`, `README.md` and the Docker tag.
- [ ] The `2.0.1` → `2.0.2` bump is the intentional metadata change for this patch release (no other version drift).
- [ ] `LICENSE` and `SECURITY.md` (disclosure policy) are present.

## 2. Automated tests & coverage

Command:

```bash
python -m pytest tests -q --cov=lib --cov=core --cov-report=term-missing
```

- [ ] Full suite passes (the `2.0.2` release commit ran **1064 passed, 11 skipped**;
      the current tree runs **1081 passed, 11 skipped** — see §9).
- [ ] Coverage meets the CI threshold (reported **84%**).
- [ ] A clean-venv install (`pip install .`) passes the same suite.

## 3. Security scans

```bash
python -m nexus self-scan
python -m nexus secretscan --staged
python -m nexus secretscan --history
```

- [ ] `self-scan` finds no committed secrets.
- [ ] `secretscan --staged` is clean.
- [ ] `secretscan --history` is clean across all refs.
- [ ] Pre-commit hook syntax check: `sh -n scripts/hooks/pre-commit`.

## 4. Repository hygiene

- [ ] `git diff --check` reports no whitespace errors.
- [ ] No unintended files staged (no `nexus.db`, `.coverage`, `results/`, `exports/`, `dist/`, `build/`).
- [ ] Docs updated for any behavior change in this release.

## 5. Documented-command validation

- [ ] `python -m nexus --version` prints `NEXUS 2.0.2`.
- [ ] `python -m nexus doctor` exits 0.
- [ ] `python -m nexus hunt --help` and every documented subcommand resolves.
- [ ] `nexus mcp --mock --tools` and `nexus zap --mock --capabilities` run offline.

## 6. External / environment-dependent checks

- [ ] `docker compose build` succeeds (Docker daemon required; see note below).
- [ ] CI workflow green for the release commit (pytest+coverage, self-scan, history scan, hook lint).
- [ ] Live optional integrations are out of scope for the offline gate (see
      [SUPPORT_STATUS.md](SUPPORT_STATUS.md): ZAP/Burp/Caido/MCP/cloud/AI are
      `unverified` against live systems by design).

> **Docker:** the image was built and smoke-tested locally with `docker compose
> build` (Docker Engine 29.7.2, linux/amd64). A dedicated `docker` job in
> `.github/workflows/ci.yml` builds the image and asserts required files are
> present, no secrets/build artifacts are baked in, and the `dev` extra (pytest)
> is excluded. The image is self-sufficient (config baked in) and also supports
> the bind-mounts in `docker-compose.yml`.

## 7. Sign-off

| Gate | Result | Evidence |
|---|---|---|
| Tests + coverage | PASS | `1064 passed, 11 skipped`, 84% |
| Self-scan | PASS | 0 potential secrets |
| Secret scans (staged + history) | PASS | 0 findings (full history) |
| Diff hygiene | PASS | `git diff --check` clean |
| Docker build + smoke test | PASS | local build (Engine 29.7.2, linux) + `docker` CI job |
| CI | PASS | `test` + `docker` jobs green |

**Verdict:** `READY` — code, tests, security scans, CI and the Docker image build
all pass. Live optional integrations (ZAP/Burp/Caido/MCP/cloud/AI) remain
`unverified` against live systems by design (see
[SUPPORT_STATUS.md](SUPPORT_STATUS.md)); this is a documented, non-blocking
limitation, not a defect.

## 8. Change history

- **2.0.2** (`2a0313e` + version bump) — patch release on top of 2.0.1:
  - Fix: Burp active scan honors `--authorize-active` (was hard-coded authorized).
  - Fix: `mcp --tools` returns a non-zero exit code on connect failure.
  - Fix: `ingest_findings` fails closed when scope context is missing.
  - Fix: `SCHEMA_VERSION` is derived from `core.migrations.TARGET` (was stale).
  - Docker: runtime-only install (`pip install .`), artifact-free build context,
    and a CI `docker` job (build + smoke test + hygiene asserts).
  - Docs: corrected adapter/AI/CLI/config docs; added ARCHITECTURE,
    SUPPORT_STATUS and RELEASE_READINESS.
- **2.0.1** — security-hardening (Pass 9) release.

## 9. Post-release stability review (Task 29)

Sections 0–8 record the **`2.0.2` release gate** at commit `c41ee6e` (tag `v2.0.2`),
which is immutable history. The current tree (`995c095`) was re-verified afterwards:

- Full suite (default): **1081 passed, 11 skipped, 0 failed — 84%** (the 11 skips are
  the optional Playwright browser tests; the count grew from 1064 via regression tests
  added in the post-release commits `1128e98` and `995c095`).
- Opt-in browser CI (`browser.yml`): **11/11 real-browser tests executed, 0 skipped**
  (Playwright 1.64.0, Chromium 156.0.8078.4).
- Default CI (`ci.yml`): `test` + `docker` jobs green.
- Scans/`doctor`/hook/diff hygiene: all clean.

Full findings, residual risks and the maintenance policy are in
[NEXUS_STABILITY_REPORT.md](releases/NEXUS_STABILITY_REPORT.md)
(**verdict: STABLE FOR MAINTENANCE**).

