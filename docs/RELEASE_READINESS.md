# Release Readiness Checklist

Version under review: **2.0.1 ("Apex")**. This checklist is the sign-off gate for
a release. Fill in the commit/run identifiers at the point of release; every row
must be **PASS** or explicitly **N/A with a reason**.

## 0. Audit results (release candidate `aa5e22f`)

| Gate | Result |
|---|---|
| Full suite + coverage | **PASS** — `1064 passed, 11 skipped`, **84%** (`lib`+`core`) |
| Self-scan | **PASS** — 0 potential secrets |
| Secret scan (staged) | **PASS** — 0 findings |
| Secret scan (history) | **PASS** — 51 commits, 0 findings |
| Diff hygiene | **PASS** — `git diff --check` clean |
| Pre-commit hook syntax | **PASS** — `sh -n` exits 0 |
| Documented-command validation | **PASS** — `--version`, `doctor` (exit 0), `mcp --mock`, `zap --mock` |
| CI | **PASS** — run [`39155660782`](https://github.com/0xShadowVoid/NEXUS_FRAMEWORK/actions/runs/39155660782), all steps green |
| `docker compose build` | **NOT RUN** — Docker daemon unavailable in the audit environment (environment limitation, not a repo defect) |

## 1. Version & metadata

- [ ] `VERSION` is `2.0.1` and matches `pyproject.toml`, `README.md` and the Docker tag.
- [ ] No version bump is introduced incidentally by this release.
- [ ] `LICENSE` and `SECURITY.md` (disclosure policy) are present.

## 2. Automated tests & coverage

Command:

```bash
python -m pytest tests -q --cov=lib --cov=core --cov-report=term-missing
```

- [ ] Full suite passes (expected: **1060 passed, 11 skipped**).
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

- [ ] `python -m nexus --version` prints `NEXUS 2.0.1`.
- [ ] `python -m nexus doctor` exits 0.
- [ ] `python -m nexus hunt --help` and every documented subcommand resolves.
- [ ] `nexus mcp --mock --tools` and `nexus zap --mock --capabilities` run offline.

## 6. External / environment-dependent checks

- [ ] `docker compose build` succeeds (Docker daemon required; see note below).
- [ ] CI workflow green for the release commit (pytest+coverage, self-scan, history scan, hook lint).
- [ ] Live optional integrations are out of scope for the offline gate (see
      [SUPPORT_STATUS.md](SUPPORT_STATUS.md): ZAP/Burp/Caido/MCP/cloud/AI are
      `unverified` against live systems by design).

> **Environment note:** in the current audit environment the Docker **daemon was
> not running**, so `docker compose build` could not be executed. This is an
> environment limitation, not a repository defect; the Dockerfile/compose tag is
> `2.0.1`. Confirm on a host/CI with Docker available.

## 7. Sign-off

| Gate | Result | Evidence |
|---|---|---|
| Tests + coverage | PASS | commit `aa5e22f`, `1064 passed, 11 skipped`, 84% |
| Self-scan | PASS | 0 potential secrets |
| Secret scans (staged + history) | PASS | 0 findings (51 commits) |
| Diff hygiene | PASS | `git diff --check` clean |
| CI | PASS | workflow run `39155660782` (all steps green) |
| Docker build | NOT RUN | Docker daemon unavailable |

**Verdict:** `CONDITIONALLY READY` — the code, tests, security scans and CI all
pass for `aa5e22f`. The single open condition is the **Docker image build**,
which could not be executed here because the Docker daemon was not running;
confirm it on a host/CI with Docker before publishing. All live optional
integrations (ZAP/Burp/Caido/MCP/cloud/AI) remain `unverified` against live
systems by design (see [SUPPORT_STATUS.md](SUPPORT_STATUS.md)).

