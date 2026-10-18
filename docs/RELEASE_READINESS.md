# Release Readiness Checklist

Version under review: **2.0.1 ("Apex")**. This checklist is the sign-off gate for
a release. Fill in the commit/run identifiers at the point of release; every row
must be **PASS** or explicitly **N/A with a reason**.

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
| Tests + coverage | | commit `____`, run `____` |
| Self-scan | | |
| Secret scans (staged + history) | | |
| Diff hygiene | | |
| CI | | workflow run `____` |
| Docker build | | |

**Verdict:** `READY` / `CONDITIONALLY READY` / `NOT READY` — `____`
