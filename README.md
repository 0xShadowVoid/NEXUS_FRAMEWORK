# NEXUS — Unified Bug Bounty Automation Framework

**Version 2.0.0 — “Apex”** · Released 2026-09-26
**Language:** Python 3.11+ (tested on 3.13) · **Platforms:** Windows, WSL, Linux, VPS, Kali, Parrot
**Author:** Mohamed (0xShadowVoid) · **License:** custom permission-based (see [`LICENSE`](LICENSE))

NEXUS consolidates multi-phase bug bounty automation into one framework:
**DISCOVER → PROBE → ANALYZE → HUNT → CONTROL → SCALE**, with 82 features,
scope enforcement, deduplication, severity scoring, vulnerability-chain
detection, a CVE workflow, multi-channel alerting, and a C2 bot.

> **Golden rule:** detection + proof-of-concept only. No data extraction,
> no modification, no backdoors, no shells. See `NEXUS_SECURITY_BOUNDARY.md`.

---

## Version & release

| Field | Value |
|---|---|
| Framework version | **2.0.0** |
| Release name | **Apex** (line: 1.0.0 Genesis → 1.1.0 Horizon → 1.2.0 Ascend → 2.0.0 Apex) |
| Release date | 2026-09-26 |
| Repository | `nexus-framework` |
| Python | 3.11+ (development/tested on 3.13) |
| Coverage | 82 spec features + roadmap Waves 1–3 (all tractable items; see docs/ROADMAP.md for the short not-built list) |
| Tests | 282 offline tests, all passing |

Version is declared in [`VERSION`](VERSION) and `nexus.py` (`__version__` / `__codename__`);
check it at runtime with `python nexus.py --version`.

---

---

## New in 2.0.0 (Apex)

- **Program monitor** — `nexus monitor` diffs programs (new/changed/removed, scope & payout drift).
- **GraphQL introspection analysis** — `nexus graphql`.
- **Submission drafts** — `nexus draft <id>` renders platform-formatted drafts; auto-generated per high-value finding.
- **Parallel tool execution** — `--parallel N` runs the light tool set concurrently.
- **SCALE phase (functional local)** — master/worker coordinator with a real task queue and thread pool.
- **AI additions** — local models (Ollama, keyless), report narratives, GHSA advisory feed, CPE matchers in nuclei templates.
- **Retention report** — `nexus retention` (report-only by design; NEXUS never deletes your data).
- **Golden-file parser tests** — real-shaped nuclei/dalfox/sqlmap outputs.

## New in 1.2.0 (Ascend)

- **Active IDOR prober** + **business-logic detector** — read-only differential/logic detection wired into PROBE.
- **OpenAPI ingestion** — `nexus openapi` turns a Swagger spec into endpoints.
- **SARIF export** — `nexus export --format sarif`.
- **More platforms** — Intigriti + YesWeHack program fetchers (auto-hunt now merges all 4).
- **AI model routing + cost budget + adversarial FP check** (`ai.strong_model`, `ai.max_calls`, `disprove_finding`).
- **Ops guards** — kill-switch, per-run request budget, payload-guard audit log.
- **Digest alerts** (`send_digest`), **`nexus serve`** scheduler daemon (`--once`).
- **Boundary fuzzing** — 1700+ seeded property assertions on the security guards.

## New in 1.1.0 (Horizon)

- **VERIFY phase** — deterministic confirmation before submission; encoded reflections are disproved, multi-tool findings corroborated.
- **Threat-intel feeds** — CISA KEV (known-exploited) + EPSS scoring; alerts prioritise exploited CVEs.
- **Agent loop** — `nexus agent` plans → acts → observes over a whitelisted action map + `skills/` registry.
- **Ops commands** — `nexus doctor`, `nexus self-scan` (secret scan), `--delta` (scan only new URLs).
- **Scope auto-sync** — `nexus scope-sync` imports a program's published scope into `nexus.yaml`.
- **Control-plane upgrades** — add/remove targets & schedules, audit log, confirm-gated destructive ops, methodology/tech drift alerts.
- **HTML export** — `nexus export --format html` (self-contained).
- **Packaging** — `pyproject.toml` (pip-installable), `Dockerfile`, `docker-compose.yml`, GitHub Actions CI.

## Contents

1. [Install](#1-install) · 2. [Configure](#2-configure) · 3. [AI provider keys — multi-key failover](#3-ai-provider-keys--multi-key-failover) ·
4. [Usage](#4-usage) · 5. [Architecture](#5-architecture) · 6. [Security boundary](#6-security-boundary-enforced-in-code) ·
7. [Testing](#7-testing) · 8. [Troubleshooting](#8-troubleshooting) · 9. [License](#9-license)

## 1. Install

```powershell
# Python 3.11+ required (3.13 tested)
python -m pip install -r requirements.txt
```

Runtime dependencies: `pyyaml`, `python-dotenv`, `requests`, `croniter`, `py7zr`.
Optional: `discord.py` + `python-telegram-bot` (C2 bots), `gowitness` (screenshots).

**External security tools** are optional — NEXUS detects what is installed and
skips the rest gracefully:

| Phase | Tools (optional) |
|---|---|
| DISCOVER (Pegpon 15) | subfinder, assetfinder, httpx, ffuf, katana, waybackurls, gau, findomain, chaos, github-subdomains, dnsx, nuclei, jsluice |
| DISCOVER (deep) | bbot (100+ modules) |
| PROBE (light) | nuclei, dalfox, arjun |
| PROBE (deep) | sqlmap, commix, ghauri, jwt-tool, lfihunt, graphql-cop, waf-probe, nomore403, cloudenum, s3scanner, prowler |

```powershell
python nexus.py check-tools      # show installed vs missing tools
```

---

## 2. Configure

1. `config/nexus.yaml` — scanning defaults, phases, per-target overrides, schedules, webhooks, CVE, C2, AI.
2. `config/false_positive_filters.yaml` — per-type strictness + confidence thresholds.
3. `config/.keys.env` — your secrets (git-ignored). Copy from the template:

```powershell
Copy-Item config\.keys.env.example config\.keys.env
```

`.keys.env` keys: `DISCORD_FINDINGS_WEBHOOK`, `DISCORD_CVE_WEBHOOK`,
`DISCORD_METRICS_WEBHOOK`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`,
`SMTP_*`, `HACKERONE_API_*`, `BUGCROWD_API_KEY`, `NVD_API_KEY`,
`OPENAI_API_KEY`, `GLM_API_KEY`, `DEEPSEEK_API_KEY`, `GEMINI_API_KEY`.

---

## 3. AI provider keys — multi-key failover (any provider)

NEXUS ships a **key pool** so an empty, dead (401/403) or rate-limited (429)
key is skipped automatically and the next key — or next provider — is used.
Supported providers (any OpenAI-compatible API): **OpenAI, GLM (Zhipu),
DeepSeek, Gemini, Kimi (Moonshot), OpenRouter**, and **custom/self-hosted**
endpoints — free-tier keys work fine.

Add keys either by editing `.keys.env`:

```ini
OPENAI_API_KEY=sk-primary
OPENAI_API_KEY_2=sk-secondary
OPENAI_API_KEY_3=sk-third
```

…or with comma-separated values in one slot (`OPENAI_API_KEY=sk-a,sk-b,sk-c`),
or via the CLI (writes into `config/.keys.env`, with a `.bak` backup):

```powershell
python nexus.py ai-set-key --provider openai --key sk-...
python nexus.py ai-keys          # masked status of every provider/key
```

Provider failover order is configured in `nexus.yaml`:

```yaml
ai:
  provider: openai
  fallback_providers: [glm, deepseek, gemini, kimi, openrouter]
  model: ""                    # empty = provider default
  base_url: ""                # optional; or CUSTOM_BASE_URL / <PROVIDER>_BASE_URL
```

Custom endpoints: set `CUSTOM_API_KEY` + `CUSTOM_BASE_URL` in `.keys.env`
(or `<PROVIDER>_BASE_URL` for any provider), then `ai.provider: custom`.

Keys are always masked in logs and CLI output. AI features (finding
categorization, chain hints, error analysis) degrade gracefully to `None`
when no key is available — scans never block on AI.

---

## 4. Usage

### Scan a single target

```powershell
python nexus.py hunt example.com                      # quick scan (default)
python nexus.py hunt example.com --full-scan          # deep scan (all tools)
python nexus.py hunt example.com --discover-only      # recon only
python nexus.py hunt example.com --scan-only          # reuse cached recon
python nexus.py hunt example.com --run-tools nuclei,dalfox
python nexus.py hunt example.com --skip-tools sqlmap
python nexus.py hunt example.com --cookie "session=abc"
python nexus.py hunt example.com --screenshots
python nexus.py hunt example.com --min-severity P2 --exclude-p4
python nexus.py hunt example.com --test-bypass --custom-fuzzing
python nexus.py hunt example.com --resume 12           # resume from checkpoint
python nexus.py hunt example.com --hunt-new            # also run Phase 4 hunt
```

### Multi-engine dorking

```powershell
python nexus.py dork example.com
python nexus.py dork example.com --engines duckduckgo,google,bing,github
python nexus.py dork example.com --intents exposed_docs,backups
```

Engines: **DuckDuckGo, Google, Bing, GitHub** (code search uses
`GITHUB_TOKEN` when present). Intents: `exposed_docs`, `login_pages`,
`error_pages`, `backups`, `directories`, `github_leaks`. Dorking runs
automatically as part of DISCOVER.

### Batch scanning

```powershell
# targets.txt: one target per line, optional JSON overrides
# example.com
# startup.com {"intensity": "full-scan", "tools": ["nuclei"], "rate_limit": "10/minute"}
python nexus.py batch targets.txt --concurrent 2
python nexus.py batch targets.txt --sequential
```

### Scheduling

```powershell
python nexus.py hunt-schedule --daily example.com
python nexus.py hunt-schedule --weekly example.com
python nexus.py hunt-schedule --every-6h example.com
python nexus.py hunt-schedule --cron "0 2 * * *" --target example.com
python nexus.py hunt-schedule --list
python nexus.py hunt-schedule nightly            # run a named schedule now
python nexus.py hunt-schedule                    # run all due schedules (call from your own cron/Task Scheduler)
```

### CVE workflow

```powershell
python nexus.py cve-update
python nexus.py cve-update --target example.com   # match against detected tech
python nexus.py cve-scan example.com --critical
python nexus.py cve-scan example.com --cve CVE-2026-09999
```

Generates detection-only PoCs (`.py`, `.js`, `.nexus-poc.sh`, `.yaml`) under
`scripts/cve_pocs/<cve-id>/`, registers the nuclei template, and alerts via
Discord/Telegram/Email (scripts attached).

### Results & portability

```powershell
python nexus.py export example.com --format zip
python nexus.py export example.com --format 7z --date 2026-09-21
python nexus.py import exported.zip --merge
python nexus.py diff 3 4
python nexus.py verify 42
```

### Phase 4 (auto-hunt) and Phase 5 (C2)

```powershell
python nexus.py hunt-new --enable      # toggle hunt (OFF by default)
python nexus.py hunt-new               # fetch new programs, queue quick scans
```

C2: set `c2_bot.enabled: true` and `DISCORD_BOT_TOKEN` / Telegram creds, then
run a coordinator that starts the frontends. Commands:
`/nexus hunt <target>`, `/nexus stop`, `/nexus logs`, `/nexus report`,
`/nexus status`, `/nexus cve-update`. Only the configured owner may issue them.

### Updates

```powershell
python nexus.py update             # framework (git pull --ff-only) + tools
python nexus.py update --tools-only
```

---

## 5. Architecture

```
nexus.py                 CLI entry point
config/                  nexus.yaml, false_positive_filters.yaml, methodologies.yaml, .keys.env
lib/                     config, logger, scope_validator, payload_guard, deduplicator,
                         severity_scorer, chainer, false_positive_filter, status_detector,
                         rate_limiter, notifications, ai_analyzer, key_pool, cve_fetcher,
                         cve_poc_generator, cve_workflow, methodology, screenshot, utils
core/                    database, analyzer, reporter, sanitizer, exporter, importer, coordinator
phases/discover/         pegpon_wrapper, bbot_wrapper, wappalyzer_wrapper, dorker, recon_orchestrator
phases/probe/            tool_runner, nuclei_orchestrator, dalfox_runner, sqlmap_runner,
                         tool_runners, probe_orchestrator
phases/analyze/          analyze_orchestrator
phases/hunt/             api_fetcher, auto_hunter, hunt_orchestrator
phases/control/          c2_commands, discord_c2, telegram_c2, c2_orchestrator
phases/scale/            master_coordinator, worker_manager   (SCAFFOLD — Phase 6)
results/                 per-scan artifacts (recon/, scans/, processed/, reports/, screenshots/)
```

**Result folder naming:** `{domain}-{platform}-{type}-{scope}-{YYYY-MM-DD}-{HH-MM}/`
**Report naming:** `{domain}-{platform}-{type}-{scope}-{YYYY-MM-DD}-findings.md`

---

## 6. Security boundary (enforced in code)

- **Scope** — `lib/scope_validator.py` blocks out-of-scope targets before any
  traffic and marks out-of-scope findings as non-submittable.
- **Payloads** — `lib/payload_guard.py` blocks destructive SQL, reverse
  shells, download-and-execute, webshells and filesystem destruction; every
  tool command line is screened before execution.
- **No deletion** — `core/database.py` exposes no delete/drop API and rejects
  destructive SQL; findings are mutated only via audited status flags.
- **Proof-only output** — `core/sanitizer.py` strips cookies, auth headers,
  tokens and extra PII, and caps snippet length in reports.
- **No shells** — all external tools run via argv lists with `shell=False` and
  timeouts.
- **Heavy tools gated** — sqlmap/commix run only on 200-auth-keyword or
  401/403 candidate endpoints, or user-chosen endpoints.

---

## 7. Testing

```powershell
python -m pytest tests -q            # 182 tests, fully offline
python -m pytest tests/unit -q
python -m pytest tests/integration -q
python -m pytest tests/e2e -q
```

Tests never touch the network or run real scanners: external tools and HTTP
transports are stubbed, so the suite is safe on any machine.

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `tool not found` in logs | Install the tool or ignore — NEXUS skips missing tools by design |
| No alerts sent | Set the relevant webhooks/tokens in `config/.keys.env` |
| AI features inactive | Add a provider key (`nexus.py ai-set-key`) or set `ai.provider: none` |
| `scope error: ... out of scope` | Add the host to the target's `in_scope` in `nexus.yaml` |
| Dorking returns nothing | Search engines throttle scraping; run less often or add a `GITHUB_TOKEN` |

---

## 9. License

Custom permission-based license — personal use, no redistribution, AI tools
may not use/read/learn from this code. See `LICENSE`.
