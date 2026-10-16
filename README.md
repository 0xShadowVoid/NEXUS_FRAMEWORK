# NEXUS — Unified Bug Bounty Automation Framework

NEXUS is a modular, offline-first Python framework for **authorized** security testing. It runs
scope-guarded, multi-phase assessments (`discover → probe → analyze → hunt → control → scale →
verify → auth → takeover → cloud → network`), records structured evidence in SQLite, and exports
review-ready reports. **NEMESIS** is the optional AI-assisted reasoning layer on top — it can
suggest and summarize, but it never validates findings on its own. Every NEXUS phase works
deterministically **without any AI provider configured**.

> **Authorized use only.** NEXUS is built for systems you own, lab environments, and bug-bounty
> programs where you have explicit permission. The framework enforces a technical scope gate, but
> **you** remain responsible for authorization.

---

## Table of contents

- [Safety and authorization](#safety-and-authorization)
- [Key capabilities](#key-capabilities)
- [Requirements and installation](#requirements-and-installation)
- [Beginner quick start](#beginner-quick-start)
- [Configuration and results](#configuration-and-results)
- [NEMESIS and optional AI](#nemesis-and-optional-ai)
- [Security model and limitations](#security-model-and-limitations)
- [Troubleshooting](#troubleshooting)
- [Documentation map](#documentation-map)
- [Testing, contributing, license, and support](#testing-contributing-license-and-support)

## Safety and authorization

NEXUS is a **detection and verification aid**, not an exploitation framework. It sends read-only
GET/HEAD requests on its own HTTP path, rejects destructive payloads, and never runs brute-force
or post-exploitation logic by itself. Deeper detection is performed by *optional external tools
you install* (nuclei, dalfox, sqlmap, …) — those tools are your responsibility to configure and
use within scope.

Before any scan:

- **Authorize.** Only test assets you have explicit written permission to test.
- **Configure scope.** Each target in `config/nexus.yaml` carries `in_scope` and `out_of_scope`
  entries. `out_of_scope` always wins. The scan target and the built-in HTTP collector are
  validated against `in_scope` before traffic is sent.
- **Verify scope manually.** Recon (for example dorking) can surface third-party hosts; those
  URLs are passed to the optional external tools you install and are not re-filtered per host by
  NEXUS. Keep `in_scope` accurate and review recon output before enabling active probing.

Findings that fall outside scope are marked `OUT_OF_SCOPE` and excluded from submission drafts,
alerts, and chains — but they are still written to the raw output so you can audit what was seen.
See [docs/SECURITY.md](docs/SECURITY.md) for the full policy.

## Key capabilities

| Area | Built-in | Optional (you install) |
|---|---|---|
| Multi-phase scans | `hunt` (single target), `batch` (target list), `hunt-new` (first-blood auto-hunt) | — |
| Recon & discovery | Scope gate, attack-surface graph, multi-engine dorking (engines off by default) | `subfinder`, `httpx`, `ffuf`, `katana`, `bbot`, `assetfinder`, … |
| Probing & verification | Evidence-backed verification workflow, IDOR/authz differential checks | `nuclei`, `dalfox`, `sqlmap`, `arjun`, … |
| CVE intelligence | CVE feed update, version-range matching against detected tech (KEV/EPSS) | — |
| Cloud & network posture | Read-only AWS/Azure/GCP posture checks; scoped TCP/TLS/HTTP checks | provider SDKs |
| Reporting | Markdown reports, SARIF/JSON/CSV/HTML/ZIP/7z export, import/merge, scan diffs, submission drafts | — |
| Local GUI | FastAPI dashboard + JSON API with HTTP Basic auth (fails closed) | — |
| NEMESIS | Optional AI triage/summaries, agent loop over whitelisted actions, MCP transport | AI provider key |

## Requirements and installation

- **Python 3.11+** (developed against 3.13).
- Windows (PowerShell), Linux, or macOS.
- Optional external security tools are **not** bundled. NEXUS degrades gracefully when they are
  missing — run `python -m nexus check-tools` to see installed vs. missing.

### Install from source

Windows (PowerShell):

```powershell
git clone https://github.com/0xShadowVoid/NEXUS_FRAMEWORK.git
cd NEXUS_FRAMEWORK

python -m venv venv
.\venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
pip install .
```

Linux / macOS:

```bash
git clone https://github.com/0xShadowVoid/NEXUS_FRAMEWORK.git
cd NEXUS_FRAMEWORK

python3 -m venv venv
source venv/bin/activate

python -m pip install --upgrade pip
pip install .
```

### Install from a wheel

The `dist/` directory is not committed, so build the wheel first:

```bash
python -m pip install build
python -m build --wheel
pip install dist/nexus_framework-2.0.1-py3-none-any.whl
```

(The filename reflects the version in `VERSION`; adjust if you build a different version.)

## Beginner quick start

```powershell
# 1. Confirm the install
python -m nexus --version        # -> NEXUS 2.0.1 "Apex"
python -m nexus --help

# 2. (Optional) create your secrets file — never commit it
#    Windows:  copy config\.keys.env.example config\.keys.env
#    Linux:    cp config/.keys.env.example config/.keys.env
#    Fill in only the integrations you want (AI keys, webhooks).

# 3. Diagnose the environment and tools
python -m nexus doctor           # config, dependencies, scope, tools
python -m nexus check-tools      # installed vs. missing external tools
```

Define an **authorized** target in `config/nexus.yaml`, then run a safe first scan against a
target you own (a local lab is ideal):

```powershell
python -m nexus hunt lab.local --discover-only   # recon only, no active probing
python -m nexus hunt lab.local                   # then a light scan (default quick-scan)
```

What the important commands do:

| Command | Purpose |
|---|---|
| `hunt TARGET` | run the full phase pipeline against one target |
| `hunt TARGET --discover-only` | recon only — safe exploration, sends no probes |
| `doctor` | checks Python, dependencies, config, scope, and tool availability |
| `check-tools` | lists which optional external tools are present |
| `batch FILE` | scan a list of targets (one per line) |
| `export TARGET --format sarif` | export findings for review/upload |

For a full walkthrough see [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md).

## Configuration and results

All runtime configuration lives in `config/`:

| File | Purpose | Committed? |
|---|---|---|
| `config/nexus.yaml` | targets, scope (`in_scope`/`out_of_scope`), phase toggles, rate limits, AI/CVE/webhook settings | yes (defaults) |
| `config/false_positive_filters.yaml` | noise filters (required; loaded at startup) | yes |
| `config/tools.yaml`, `config/methodologies.yaml` | tool registry and methodology presets | yes |
| `config/.keys.env` | secrets (AI keys, webhooks, API tokens) | **no — git-ignored** |

Create `config/.keys.env` from `config/.keys.env.example` and fill in only what you need. `${VAR}`
placeholders in `nexus.yaml` resolve from `.keys.env` first, then the OS environment; missing
values resolve to empty string so the framework runs offline. `nexus.yaml` and
`false_positive_filters.yaml` are required — a missing or malformed file fails startup with a
clear error.

Where results live (all git-ignored):

| Path | Contents |
|---|---|
| `nexus.db` | SQLite database: scans, findings, evidence, assets, lifecycle transitions |
| `results/<scan>/` | per-scan `recon/`, `scans/`, `processed/`, `reports/`, `cloud/`, `network/`, `screenshots/` |
| `exports/` | `export`/`import` bundles (zip / 7z) |
| `logs/` | runtime logs (rotating) and audit logs |
| `browser-artifacts/` | NEMESIS browser session artifacts (opt-in) |

When installed as a package (rather than run from a checkout), `nexus.db` is created under your
Python prefix. See [docs/REPORTS_AND_DATABASE.md](docs/REPORTS_AND_DATABASE.md) for the layout,
export formats, and online backup/restore.

## NEMESIS and optional AI

NEMESIS adds AI-assisted triage, summaries, and an agent loop over a whitelist of actions. It is
**entirely optional**: with no provider key, AI calls are skipped and every deterministic phase
still runs.

Add a provider key to `config/.keys.env` or use the CLI:

```powershell
python -m nexus ai-set-key --provider deepseek --key <YOUR-KEY>
python -m nexus ai-keys                 # masked key-pool status
python -m nexus agent "triage latest findings for lab.local" --dry-run
```

Supported providers and their key variables: `openai` (`OPENAI_API_KEY`), `glm` (`GLM_API_KEY`),
`deepseek` (`DEEPSEEK_API_KEY`), `gemini` (`GEMINI_API_KEY`), `kimi` (`KIMI_API_KEY`),
`openrouter` (`OPENROUTER_API_KEY`), `custom` (`CUSTOM_API_KEY` + `CUSTOM_BASE_URL`), and local
`ollama` (no key). Multiple keys per provider form a failover pool. AI actors are advisory only
and can never move a finding to `validated`. See [docs/AI_AND_NEMESIS.md](docs/AI_AND_NEMESIS.md).

## Security model and limitations

Controls implemented in code (see [docs/SECURITY.md](docs/SECURITY.md) for the verified matrix):

- **Scope gate** — `lib/scope_validator.py` validates the scan target and the built-in HTTP
  collector against `in_scope`; `out_of_scope` entries always win.
- **SSRF guard** — `lib/ssrf_guard.py` blocks metadata endpoints, private/loopback/link-local
  addresses, and DNS-rebinding, and is applied across the internal HTTP paths.
- **Payload guard** — `lib/payload_guard.py` rejects destructive SQL, reverse shells, webshells,
  and download-and-execute payloads.
- **Secret redaction** — `core/sanitizer.py` redacts credentials/tokens from evidence at the
  persistence choke point; `python -m nexus self-scan` scans the repo for committed secrets.
- **Finding lifecycle** — `core/lifecycle.py` enforces `candidate → probable → validated →
  rejected`; only the deterministic verifier (or a human) can validate.
- **Local GUI** — `core/gui.py` requires `NEXUS_GUI_USER`/`NEXUS_GUI_PASS` on every protected
  route and fails closed (HTTP 503) when they are unset. Serve it loopback-only with
  `python -m nexus gui` (default `127.0.0.1:8080`).

Honest limitations:

- NEXUS validates the **target** and its own HTTP requests; recon-discovered URLs handed to
  **external tools** are not re-filtered per host. Configure scope carefully.
- Detection is heuristic and tool-dependent; findings need human review before submission.
- Optional integrations (C2 bot, cloud SDKs, browser automation, MCP) are disabled until
  configured and are not required for the core workflow.

## Troubleshooting

Start with the built-in diagnostics:

```powershell
python -m nexus doctor
```

Common symptoms and fixes: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## Documentation map

**Beginner**

- [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) — step-by-step first scan
- [docs/INSTALLATION.md](docs/INSTALLATION.md) — source, wheel, and clean-venv installs
- [docs/NEXUS_FIRST_RUN_CHECKLIST.md](docs/NEXUS_FIRST_RUN_CHECKLIST.md) — post-install checklist

**Usage and operations**

- [docs/CONFIGURATION.md](docs/CONFIGURATION.md) — every config key and environment variable
- [docs/WORKFLOWS.md](docs/WORKFLOWS.md) — end-to-end workflows
- [docs/NEXUS_OPERATIONS_GUIDE.md](docs/NEXUS_OPERATIONS_GUIDE.md) — deployment, GUI, backup/recovery
- [docs/REPORTS_AND_DATABASE.md](docs/REPORTS_AND_DATABASE.md) — results layout, exports, DB backup
- [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) — diagnostics and common errors

**Technical reference**

- [docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md) — all commands and flags
- [docs/PHASES.md](docs/PHASES.md) — phase registry reference
- [docs/TOOLS_REFERENCE.md](docs/TOOLS_REFERENCE.md) — built-in vs. optional external tools
- [docs/SKILLS_REFERENCE.md](docs/SKILLS_REFERENCE.md) — NEMESIS skill files
- [docs/NEXUS_DEPENDENCY_MATRIX.md](docs/NEXUS_DEPENDENCY_MATRIX.md) — Python deps and external tools

**AI and security**

- [docs/AI_AND_NEMESIS.md](docs/AI_AND_NEMESIS.md) — provider setup and no-AI behavior
- [docs/SECURITY.md](docs/SECURITY.md) — enforcement matrix and safe-use policy
- [SECURITY.md](SECURITY.md) — vulnerability disclosure policy

**Historical records**

- [docs/releases/](docs/releases/) — past pass, release-candidate, and review reports

## Testing, contributing, license, and support

```powershell
python -m pytest tests -q -p no:cacheprovider
```

- **Issues / PRs:** <https://github.com/0xShadowVoid/NEXUS_FRAMEWORK>
- **License:** custom permission-based (not an OSI-approved open-source license) — see [LICENSE](LICENSE)
- **Security policy:** [SECURITY.md](SECURITY.md)
