# NEXUS — Unified Bug Bounty Automation Framework

A modular Python security automation framework for **authorized** vulnerability discovery, reconnaissance, probing, analysis, hunting, and evidence management. NEXUS is a detection + proof-of-concept tool: no data extraction, no modification, no backdoors, no shells.

---

## Quick Overview

- **NEXUS Executes:** Orchestrates multi-phase workflows — DISCOVER → PROBE → ANALYZE → HUNT → CONTROL → SCALE — with strict scope enforcement, deduplication, severity scoring, and vulnerability-chain detection.
- **NEMESIS Reasons:** AI-assisted triage, threat-intel correlation, and agent loops over a whitelisted skill/action registry.
- **GUI:** Local, FastAPI-based web interface (loopback-only) with authentication and audit logging.
- **MCP:** Model Context Protocol transport gated by the NEXUS security gateway.
- **Help Me Learn Explains:** Beginner guides, a developer glossary, and phase/tool reference documentation in `docs/`.

---

## Prerequisites

- Python **3.11+** (tested on 3.13)
- Windows PowerShell, WSL, Linux/macOS
- Read-only, authorized testing only

---

## Installation

### From source

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
pip install .
```

### From a built wheel

```powershell
pip install dist/nexus_framework-2.0.1-py3-none-any.whl
```

---

## First-run

1. Inspect the configuration templates:
   ```powershell
   Copy-Item config\.keys.env.example config\.keys.env   # secrets, git-ignored
   ```
2. Review `config/nexus.yaml` and define your authorized targets and scope.
3. (Optional) Configure administrator credentials for the local web GUI:
   ```powershell
   $env:NEXUS_GUI_USER = "admin"
   $env:NEXUS_GUI_PASS = "change-this-secure-password"
   ```
   The GUI **fails closed** (HTTP 503) if these are unset.
4. Verify the installation:
   ```powershell
   python -m nexus --version
   python -m nexus check-tools
   ```

---

## Scope configuration and authorized testing

NEXUS enforces strict engagement scope before issuing any traffic (`lib/scope_validator.py`): out-of-scope targets and findings are blocked. Add only hosts you are authorized to test to `in_scope` in `config/nexus.yaml`. External security tools (nuclei, sqlmap, bbot, etc.) are **optional** and not bundled — install them separately if you want deep-scanning features; NEXUS degrades gracefully when they are missing.

---

## Usage examples

```powershell
python -m nexus hunt example.com                      # quick scan
python -m nexus hunt example.com --full-scan          # deep scan (all tools)
python -m nexus hunt example.com --discover-only      # recon only
python -m nexus batch targets.txt --concurrent 2      # batch from file
python -m nexus dork example.com                       # multi-engine dorking
python -m nexus check-tools                            # installed vs missing tools
python -m nexus export example.com --format zip        # export findings
python -m nexus verify 42                              # manual finding verification
python -m nexus doctor                                 # diagnose environment/config
```

A full command reference is in `docs/CLI_REFERENCE.md`, phase details in `docs/PHASES.md`, and tool requirements in `docs/TOOLS_REFERENCE.md`.

---

## Testing

```powershell
python -m pytest tests -q -p no:cacheprovider
```

The verified suite result is **483 passed, 11 skipped, 0 failed** (external tools/cloud credentials degrade to skips).

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `tool not found` in logs | Install the tool or ignore — NEXUS skips missing tools by design |
| No alerts sent | Set the relevant webhooks/tokens in `config/.keys.env` |
| AI features inactive | Add a provider key (`python -m nexus ai-set-key`) or set `ai.provider: none` |
| `scope error: ... out of scope` | Add the host to the target's `in_scope` in `config/nexus.yaml` |

See `docs/TROUBLESHOOTING.md` for complete diagnostics.

---

## Security limitations

- Local GUI binds to `127.0.0.1` by default; never exposes unauthenticated endpoints.
- Scope enforcement, payload guarding, secret redaction, and audit logging are enforced server-side.
- Optional external integrations (Discord/Telegram C2, cloud providers, search engines, AI APIs) require explicit configuration and degrade gracefully.

---

## Documentation

- `README.md` — overview and quick start
- `docs/GETTING_STARTED.md` — installation and first run
- `docs/CONFIGURATION.md` — all settings and environment variables
- `docs/CLI_REFERENCE.md` — command and flag reference
- `docs/PHASES.md`, `docs/TOOLS_REFERENCE.md` — phase and tool documentation
- `docs/SECURITY.md` — authorization, scope, and safe-use policy
- `docs/releases/` — historical release and audit reports

---

## License

Custom permission-based license (see [LICENSE](LICENSE)).