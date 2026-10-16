# NEXUS — Unified Bug Bounty Automation Framework

NEXUS is a modular, offline-first Python framework for **authorized** security testing: scoped
multi-phase scans (discover → probe → analyze → hunt → control → scale → verify → authz →
takeover → cloud → network), structured evidence, and exportable reports — with **NEMESIS**
as the optional AI-reasoning layer on top.

> **Authorized use only.** NEXUS enforces engagement scope before issuing any traffic and is
> designed for bug-bounty programs and lab environments where you have explicit permission.

---

## What NEXUS is

- **NEXUS executes.** A phase-registry-driven engine runs deterministic security checks with
  strict scope validation (`lib/scope_validator.py`), SSRF guarding, secret redaction, finding
  lifecycle (`candidate → probable → validated → rejected`), and evidence provenance in SQLite.
- **NEMESIS reasons.** An optional AI layer (multi-provider key pool, skill whitelists, agent
  loops, MCP transport through a security gateway) assists triage and analysis. Without an AI
  provider, every NEXUS phase still works deterministically.
- **You stay in control.** Local GUI (loopback-only, fails closed without credentials), local
  database, local reports. Optional integrations (C2 bots, cloud providers, external scanners)
  degrade gracefully when unconfigured.

## Key capabilities

| Area | What it does |
|---|---|
| Multi-phase scans | `hunt` (single target), `batch` (target list), `hunt-new` (first-blood auto-hunt) |
| Recon & discovery | Subdomain enumeration, multi-engine dorking, tech detection (external tools optional) |
| Probing & verification | nuclei/dalfox/sqlmap/arjun wrappers (optional), evidence-backed verification workflow |
| CVE intelligence | Manual/automated CVE feed updates, version-range matching against detected tech |
| Cloud & network posture | Read-only AWS/Azure/GCP posture checks and scoped TCP/TLS/HTTP network checks |
| Reporting | SARIF + JSON + ZIP export/import, submission drafts, scan diffs, retention reports |
| Local GUI | FastAPI web interface on `127.0.0.1` with HTTP Basic auth (fails closed: HTTP 503) |
| MCP | Model Context Protocol transport gated by the NEXUS security gateway |

## Requirements

- Python **3.11+** (developed against 3.13)
- Windows PowerShell, Linux, or macOS
- Optional external tools (not bundled): `subfinder`, `httpx`, `nuclei`, `dalfox`, `sqlmap`,
  `arjun`, `ffuf`, `katana`, `bbot`, `gowitness` — NEXUS degrades gracefully when missing
  (`python nexus.py check-tools` shows installed vs missing).

## Installation (from source)

```powershell
git clone https://github.com/0xShadowVoid/NEXUS_FRAMEWORK.git
cd NEXUS_FRAMEWORK

python -m venv venv
.\venv\Scripts\Activate.ps1        # Windows (PowerShell)
# source venv/bin/activate         # Linux / macOS

pip install --upgrade pip
pip install .
```

Or from a built wheel:

```powershell
pip install dist/nexus_framework-2.0.1-py3-none-any.whl
```

## First run (beginner quick start)

1. **Verify the installation:**
   ```powershell
   python -m nexus --version        # NEXUS 2.0.1 "Apex"
   python -m nexus --help
   ```
2. **Set up secrets (optional):** copy `config/.keys.env.example` to `config/.keys.env`
   (git-ignored) and fill in only the integrations you want (AI keys, webhooks).
3. **Define your scope:** edit `config/nexus.yaml` and list only targets you are authorized to
   test under the target's `in_scope` (and `oos` for explicit exclusions).
4. **Check your environment:**
   ```powershell
   python -m nexus doctor
   python -m nexus check-tools
   ```
5. **Run a first scan against a target you own** (example uses a local lab):
   ```powershell
   python -m nexus hunt lab.local --discover-only
   ```

## Configuration and scope

All runtime configuration lives in `config/nexus.yaml` (targets, scope, phase toggles, rate
limits) and `config/.keys.env` (secrets — never commit this file). Scope is enforced before any
network traffic; out-of-scope findings are dropped. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Where results live

| Path | Contents |
|---|---|
| `nexus.db` | SQLite database: scans, findings, evidence (git-ignored) |
| `results/` | Per-scan folders with `cloud.json` / `network.json` snapshots and reports |
| `logs/` | Runtime logs (git-ignored) |
| `exports/` | ZIP export/import bundles |

## Optional AI / NEMESIS setup

Add one or more provider keys to `config/.keys.env` (`OPENAI_API_KEY`, `DEEPSEEK_API_KEY`, …)
or run `python -m nexus ai-set-key`. Without any key, AI features stay inactive and every other
phase runs normally. See [docs/AI_AND_NEMESIS.md](docs/AI_AND_NEMESIS.md).

## Security model and limitations

- Read-only posture checks only: no exploitation, no credential attacks, no destructive payloads
  (payload guard is built in).
- The GUI binds to loopback and **fails closed** without `NEXUS_GUI_USER` / `NEXUS_GUI_PASS`.
- External tools, cloud SDKs, and AI providers are optional integrations, not dependencies —
  absent tooling never blocks the core workflow.
- NEXUS is a detection/verification aid; it does not replace human review of findings.

## Troubleshooting

Start with:

```powershell
python -m nexus doctor
```

Common symptoms and fixes: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) | Step-by-step first scan walkthrough |
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | Source, wheel, and clean-venv installs |
| [docs/NEXUS_FIRST_RUN_CHECKLIST.md](docs/NEXUS_FIRST_RUN_CHECKLIST.md) | Post-install verification checklist |
| [docs/NEXUS_OPERATIONS_GUIDE.md](docs/NEXUS_OPERATIONS_GUIDE.md) | Deployment, secure GUI startup, backup/recovery |
| [docs/NEXUS_DEPENDENCY_MATRIX.md](docs/NEXUS_DEPENDENCY_MATRIX.md) | Python dependencies and optional external tools |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Every config key and environment variable |
| [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) | All commands and flags |
| [docs/PHASES.md](docs/PHASES.md) | Phase registry reference |
| [docs/TOOLS_REFERENCE.md](docs/TOOLS_REFERENCE.md) | Built-in vs optional external tools |
| [docs/SKILLS_REFERENCE.md](docs/SKILLS_REFERENCE.md) | NEMESIS skill files |
| [docs/WORKFLOWS.md](docs/WORKFLOWS.md) | End-to-end beginner workflows |
| [docs/REPORTS_AND_DATABASE.md](docs/REPORTS_AND_DATABASE.md) | Results layout, DB backup/restore |
| [docs/AI_AND_NEMESIS.md](docs/AI_AND_NEMESIS.md) | AI provider setup and behavior without AI |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Diagnostics and common errors |
| [docs/SECURITY.md](docs/SECURITY.md) | Authorization requirements and safe-use policy |
| [docs/releases/](docs/releases/) | Historical pass and release reports |

## Testing

```powershell
python -m pytest tests -q -p no:cacheprovider
```

## Contributing, license, support

- **Issues/PRs:** via <https://github.com/0xShadowVoid/NEXUS_FRAMEWORK>
- **License:** custom permission-based — see [LICENSE](LICENSE)
- **Security policy:** [SECURITY.md](SECURITY.md)
