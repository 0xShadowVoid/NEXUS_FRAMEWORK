# NEXUS Operations Guide

## 1. Overview & Architecture
NEXUS 2.0.1 ("Apex") is a modular bug bounty and security automation framework designed for offline-first, permission-gated vulnerability discovery, probing, analysis, hunting, control, and scaling.

This guide outlines operational deployment, configuration, secure execution, backup, and recovery procedures for NEXUS 2.0.1.

---

## 2. Secure Installation Workflow
To install NEXUS 2.0.1, follow these steps in an isolated Python 3.11+ environment. Install from a source checkout, or build a wheel first with `python -m build --wheel` and install the resulting `dist/nexus_framework-2.0.1-py3-none-any.whl`.

```powershell
# 1. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 2. Upgrade pip and install NEXUS (from the checkout)
python -m pip install --upgrade pip
pip install .

# 3. Verify installation and CLI help
python -m nexus --help
```

---

## 3. Configuration & Environment Setup
NEXUS requires two configuration files located under `config/`:
1. `config/nexus.yaml` — Scanning defaults, phase registries, rate limits, and target scopes.
2. `config/.keys.env` — API keys and webhooks (git-ignored, never committed).

### Sample Environment File (`config/.keys.env.example` placeholder)
```ini
# AI Provider Keys (Optional — multi-key failover supported)
OPENAI_API_KEY=
GLM_API_KEY=
DEEPSEEK_API_KEY=
GEMINI_API_KEY=

# Platform API Keys (Optional — Auto-Hunt & Program Monitoring)
HACKERONE_API_USERNAME=
HACKERONE_API_TOKEN=
BUGCROWD_API_KEY=

# Alerts & C2 Webhooks (Optional)
DISCORD_FINDINGS_WEBHOOK=
DISCORD_METRICS_WEBHOOK=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
```

---

## 4. Local GUI & MCP Secure Startup
- **Local Web GUI (`core/gui.py`):** Requires HTTP Basic authentication; administrator credentials **must** be provided via environment variables (`NEXUS_GUI_USER` and `NEXUS_GUI_PASS`). If these variables are unset, the GUI fails closed with HTTP 503 Service Unavailable. Start it loopback-only with `python -m nexus gui` (defaults to `127.0.0.1:8080`; it refuses a non-loopback host unless `--allow-remote` is passed).
- **MCP Transport (`lib/nemesis/mcp_transport.py`):** Enforces authentication, role authorization, engagement scope verification, and audit logging on every invocation.

---

## 5. Scope Configuration & Safety Policies
- **Scope Enforcement:** Every scan target is validated against `in_scope` and `oos` (out-of-scope) definitions in `config/nexus.yaml` prior to issuing any network traffic.
- **Payload Guard:** Prohibits destructive SQL, reverse shells, download-and-execute payloads, and webshells.
- **Audit Logs:** Recorded in SQLite (`nexus.db` at the repository root) and audit log files.

---

## 6. Backup & Recovery
- **Database Backup & Restore:** NEXUS provides built-in online backup and restore methods on the `Database` class (`db.backup_to(path)` and `db.restore_from(path)`) leveraging SQLite's online backup API. This ensures transactional consistency without blocking writes.
- **Export / Import:**
  ```powershell
  python -m nexus export target.com --format zip
  python -m nexus import exported.zip --merge
  ```

---

## 7. Tested vs. Unverified Instructions
- **Tested:** Wheel installation, CLI startup (`python -m nexus --help`), configuration parsing, scope validation, and database initialization.
- **Unverified:** Live public cloud API collection and C2 bot gateway connection (requires live external credentials and third-party APIs).
