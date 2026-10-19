# Contributing

Thanks for improving NEXUS. This project handles offensive security tooling, so changes are
held to two standards at once: **correctness** and **safety**. A feature that works but can
escape scope, weaken a fail-closed check, or misrepresent its support status is not ready.

> NEXUS is for legally authorized testing only. Do not add features whose purpose is
> unauthorized access, data extraction, persistence, or evasion of authorization.

## Before you start

- Read [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY_MODEL.md](SECURITY_MODEL.md).
- Check [SUPPORT_STATUS.md](SUPPORT_STATUS.md) for what is implemented, partial, or unverified.
- For anything large or security-sensitive, open an issue describing the design before coding.
- Never include real target data, credentials, or private infrastructure details in an issue,
  test fixture, or commit.

## Development setup

```powershell
git clone https://github.com/0xShadowVoid/NEXUS_FRAMEWORK.git
cd NEXUS_FRAMEWORK
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install .[dev]
python -m pytest tests -q
python -m nexus doctor
```

Python **3.11+** is required. CI exercises 3.11; development commonly uses 3.13. Do not rely on
3.13-only syntax.

## Conventions

- **Follow the surrounding code.** Match module layout, naming, typing, logging, and error
  handling. Prefer existing helpers over new abstractions.
- **Stdlib and existing dependencies first.** Adding a runtime dependency needs a concrete
  justification and an update to `pyproject.toml`, `requirements.txt`, and
  [NEXUS_DEPENDENCY_MATRIX.md](NEXUS_DEPENDENCY_MATRIX.md). Never add a heavy framework for a
  small utility.
- **Type hints and docstrings.** Public functions and security boundaries should be typed and
  documented.
- **Offline by default.** New tests must not require network access, credentials, or a live
  target. Mock the integration; mark genuinely live-only behaviour `unverified` in docs.
- **Fail closed.** New gates must deny on missing, empty, or malformed context. Never treat
  "unknown" as "allowed".
- **No silent degradation of security.** If an optional dependency is missing, skip the
  capability with a clear reason — do not bypass the control.
- **No secrets in code, tests, logs, or fixtures.** Use obvious placeholders and temporary
  directories.
- **Config compatibility.** New config keys must be optional and documented in
  [CONFIGURATION.md](CONFIGURATION.md); reserved-but-unwired keys must be labelled as such.

## Making a change

1. Create a focused branch.
2. Add or update tests next to the relevant existing suite (see [TESTING.md](TESTING.md)).
3. Update the affected documentation in the same change. Keep claims evidence-based.
4. Run the checks below.
5. Commit with an imperative message (for example `Add scope check to adapter import`).
6. Open a pull request describing behaviour, risk, and verification.

### Required checks

```powershell
python -m pytest tests -q --cov=lib --cov=core --cov-report=term-missing
python -m nexus --version
python -m nexus doctor
python -m nexus self-scan
python -m nexus secretscan --staged
git diff --check
```

If you touched the browser layer, also run the opt-in suite (see [TESTING.md](TESTING.md)):

```powershell
python scripts/run_browser_tests.py
```

## Pull-request checklist

- [ ] Behaviour is covered by an offline, deterministic test.
- [ ] Security-relevant changes include a fail-closed test (scope, SSRF, payload, authz).
- [ ] No secrets, real targets, or private paths were added.
- [ ] `VERSION` / tags / release metadata were **not** changed unless the task is a release.
- [ ] Docs are updated and links resolve; no fabricated terminal output.
- [ ] `self-scan` and `secretscan --staged` pass.
- [ ] The change does not weaken an existing control or broaden scope implicitly.

## Documentation style

- Use GitHub-flavoured Markdown and relative links within `docs/`.
- Prefer Mermaid diagrams (`flowchart`, `sequenceDiagram`) with a short caption; add alt-like
  prose so the diagram is understandable when images are unavailable.
- Show commands, not invented output. If output is shown, it must be from a real run.
- Label behaviour honestly: **supported**, **partial**, **unverified**, or **unavailable** —
  matching [SUPPORT_STATUS.md](SUPPORT_STATUS.md).
- Keep `README.md` scannable; move depth into a dedicated page and link it.

## Security disclosures

Do **not** open a public issue for a vulnerability in NEXUS itself. Follow the root
[SECURITY.md](../SECURITY.md) policy. For vulnerabilities in a third-party tool, follow that
project's process.
