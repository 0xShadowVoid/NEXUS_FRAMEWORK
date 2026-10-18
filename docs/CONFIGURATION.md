# Configuration Reference

All runtime configuration lives in `config/nexus.yaml` (committed defaults) and
`config/.keys.env` (your secrets, git-ignored, created from `config/.keys.env.example`).

Two files are **required** and are committed with the repository:
`config/nexus.yaml` and `config/false_positive_filters.yaml`. `load_config()` raises
`ConfigError` if either is missing (or contains malformed YAML); only `config/.keys.env`
is optional.

`${VAR}` placeholders inside `nexus.yaml` resolve from the OS environment first, then from
`config/.keys.env` (which only fills in variables the OS environment does not already define).
Missing variables resolve to the empty string so the framework degrades gracefully offline.

## `scanning:`

| Key | Default | Meaning |
|---|---|---|
| `default_intensity` | `quick-scan` | intensity used when a target does not override it |
| `tool_timeout_seconds` | `300` | per external-tool invocation timeout |
| `rate_limit_default` | `50/minute` | rate limit when a target does not define one |
| `request_budget` | `0` | positive N caps requests per scan (0 = unlimited) |
| `probe_max_urls` | `50` | HTTP collector budget per scan |
| `ssrf_allow` | `[]` | hosts explicitly permitted despite resolving to private IPs |
| `dorking_engines` | `[duckduckgo, github]` | scraping engines (off unless enabled) |

## `phases:`

| Phase key | Default | Notes |
|---|---|---|
| `discover.enabled` | `true` | `tools:` selects discover tools |
| `probe.enabled` | `true` | `default_tools: [nuclei, dalfox]` |
| `hunt.enabled` | `false` | auto-hunt stays off by design (also `hunt.intensity`, `hunt.max_scans_per_day`, `hunt.alert_on`, `hunt.vdp_strategy`, `hunt.bb_strategy`) |
| `control.enabled` | `false` | **not wired** — the C2 bot runs only via explicit `nexus control` (gated by `c2_bot.enabled`) |
| `scale.enabled` | `false` | **not wired** — scaffold only |
| `network.*` | enabled, gated | `ports: []` (conservative default set), `concurrency: 16`, `connect_timeout: 1.5`, `probe_timeout: 2.0`, `max_ports: 512`, `allow_private: false` |
| `cloud.*` | enabled, gated | `providers: []`, `accounts: {}` (fails closed when empty), `max_resources: 200`, optional `region` / `project` hints |

Only **registered** phase names honor `phases.<name>.enabled`:
`discover, probe, verify, analyze, authn, authz, takeover, network, cloud, intel, report`.
Keys for unregistered phases (`control`, `scale`) are ignored.

`network` and `cloud` also require explicit scope (an in-scope IP grant / `scope_kind: cloud`
target). See [SECURITY.md](SECURITY.md) and [PHASES.md](PHASES.md).

## `targets:`

Map of target key → per-target settings. Example (samples in the file are placeholders —
replace with your own authorized targets):

```yaml
targets:
  lab.local:
    intensity: quick-scan          # quick-scan | full-scan | deep
    tools: [nuclei, dalfox]        # empty = profile default
    rate_limit: "50/minute"
    in_scope: [lab.local, "*.lab.local", 127.0.0.1]
    out_of_scope: [admin.lab.local, 10.0.0.0/16]
```

| Key | Meaning |
|---|---|
| `platform` | reporting platform (`generic` / `hackerone` / `bugcrowd` / `intigriti` / `yeswehack`) |
| `type` | program type (`bb` bounty / `vdp`) |
| `scope` | scope kind (`public` / …) — feeds phase gating (e.g. cloud/network) |
| `intensity` | tool-profile selector (`quick-scan` / `full-scan` / `deep`) |
| `tools` | explicit tool list; overrides profile membership |
| `rate_limit` | per-target rate limit string |
| `cookie` | session cookie passed to authenticated checks (stored locally, never committed) |
| `in_scope` | the only hosts/URLs/IPs testable for this target |
| `out_of_scope` | hard exclusions — win over `in_scope` |
| `sync` | optional block enabling scope auto-sync (roadmap E1); see below |

### `sync:` (scope auto-sync, roadmap E1)

Give a target a `sync:` block to pull its published in/out-of-scope from the
platform API with `nexus scope-sync --program <domain>` (or `--all`).
Credentials are referenced by environment-variable **name** only:

```yaml
targets:
  acme.com:
    sync:
      platform: hackerone        # hackerone | bugcrowd
      handle: acme               # program handle/slug on the platform
      username_env: HACKERONE_API_USERNAME  # hackerone only (HTTP basic auth)
      token_env: HACKERONE_API_TOKEN        # name of the env var holding the API token
```

`username_env`/`token_env` are optional per target; when omitted they default to
the names in `config/.keys.env.example` — `HACKERONE_API_USERNAME` /
`HACKERONE_API_TOKEN` for HackerOne and `BUGCROWD_API_KEY` for Bugcrowd. Set the
matching values in `config/.keys.env` (or the OS environment) for the sync to
authenticate; a missing/empty credential is reported as `skipped`, never as an
empty scope.

`scope-sync` writes `in_scope`/`out_of_scope` back into this file (keeping a
`.bak`) **only when the scope changed**, and records the drift. Out-of-scope
entries always win over in-scope.

### `scope_sync.notify:` (scope-drift alerts, roadmap E3)

When an auto-sync changes a target's scope, NEXUS can emit a structured drift
event and send it through the channels it already implements. Alerts are
**off by default**; enable them here or per run with `--notify`:

```yaml
scope_sync:
  notify:
    enabled: false       # global default; `scope-sync --all --notify` overrides
    discord: true        # Discord findings webhook
    telegram: true       # Telegram bot
    email: false         # SMTP (see email: below)
```

Each event carries the target id, source provider, direction
(`added`/`removed`/`mixed`), the affected in/out-of-scope entries and a
timestamp. Repeated syncs of an unchanged drift are not re-alerted, and a
provider error is **never** reported as a removal. Delivery is best-effort:
failures are surfaced in the sync output's separate `notifications` block and
never block or alter the sync result. An alert only reports the observed
change — it never broadens authorized scope.

### Scope semantics (authoritative)

NEXUS enforces scope before any traffic, again before **every handoff to an external tool**
(nuclei, dalfox, sqlmap, httpx, dnsx, ffuf, katana, gowitness, …), and on every HTTP redirect
hop. It never broadens authorization implicitly:

- **Exact host only.** `in_scope: [lab.local]` authorizes `lab.local` — **not** `api.lab.local`.
  Add `*.lab.local` to authorize the apex and every subdomain.
- **Anchored wildcards.** `*.lab.local` matches `lab.local` and `a.b.lab.local`, but never
  `lab.local.attacker.test` or `evil-lab.local`.
- **Ports are ignored** for host matching (authorize ports separately in the network phase).
- **IP literals** must be authorized explicitly by an exact entry or a CIDR (`10.0.0.0/24`).
  Unlisted IPs are out of scope. Private/loopback/metadata addresses also need the network
  phase's explicit grants (`allow_private` + an in-scope grant).
- **Malformed** entries/URLs fail closed.

Discovered hosts/URLs that are out of scope are dropped from tool input lists (`urls.txt`,
`domains.txt`) and never reach an external tool; the full discovered set remains in the recon
summary for audit.

## `schedules:`

**Reserved — not read by the runtime.** Schedules executed by `python -m nexus serve`
live in the **database**, created and managed with the `nexus hunt-schedule` command
(`--daily TARGET`, `--weekly TARGET`, `--every-6h TARGET`, or `--cron EXPR --target T`).
The `schedules:` block below is parsed but currently has no effect:

```yaml
schedules:
  my_daily:
    target: lab.local
    frequency: daily          # daily | weekly | cron (via --cron)
    time: "02:00"
    intensity: full-scan
```

## `webhooks:` / `email:`

Discord findings/CVE/metrics webhook URLs, Telegram bot token + chat id, and SMTP settings —
all via `${...}` references into `.keys.env`. Without values, notifications are skipped.

## `ai:`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | master switch for AI calls (unset = on) |
| `provider` | `openai` | one of `openai, glm, deepseek, gemini, kimi, openrouter, custom` (ollama needs no key) |
| `fallback_providers` | `[]` | tried in order on failure (shipped `nexus.yaml` sets `[glm, deepseek, gemini, kimi, openrouter]`) |
| `model` / `strong_model` | `""` | empty = provider default; strong model for chains/reports |
| `max_calls` | `0` | per-run AI call budget (0 = unlimited) |
| `max_retries` | `2` | bounded same-provider retries on transient errors |
| `reasoning_effort` | `""` | `off`/`low`/`medium`/`high`; **only `openai` and `openrouter`** support it |
| `timeout_seconds` | `0` | per-request read timeout (seconds); `0` = no read timeout (shipped `nexus.yaml` sets `60`) |
| `base_url` | `""` | override, or `<PROVIDER>_BASE_URL` / `CUSTOM_BASE_URL` env |

> The top-level `ai.provider` / `ai.fallback_providers` values are **not** validated against the
> provider registry; an unknown or unsupported name there is simply unusable (AI stays disabled).
> Use `nemesis.agents` for validated, fail-fast per-agent configuration.

Multiple keys per provider are read from numbered slots (`GEMINI_API_KEY`,
`GEMINI_API_KEY_2` … `_10`, or comma-separated) and rotated on failure.

### `nemesis.agents:` (per-agent AI)

Optional. Each entry names an agent and pins its AI provider/model/effort/limits and an ordered
fallback chain. Invalid entries (unknown provider, unverified integration, unsupported
`reasoning_effort`) are **rejected at startup**, never silently ignored.

```yaml
nemesis:
  agents:
    default:
      provider: gemini
      model: gemini-1.5-flash
      reasoning_effort: ""          # off | low | medium | high (provider-dependent)
      timeout_seconds: 60
      max_retries: 2
      max_calls: 20
      fallback:
        - {provider: openai, model: gpt-4o-mini}
        - {provider: openrouter}
```

Select it with `python -m nexus agent "..." --agent default`. When no `nemesis.agents` section is
present, the legacy `ai:` settings are used unchanged.


## `cve:`

Read: `use_kev: true` (CISA KEV), `use_epss: true` (EPSS scoring), `alert_severity: [critical, high]`.

**Reserved — not wired:** `auto_update`, `frequency`, `time`, `script_delivery`. There is no
built-in scheduler that acts on these; refresh explicitly with `nexus cve-update` (e.g. from an
external cron / Windows Task Scheduler).

## `c2_bot:`

Read: `enabled: true` and `channels: [discord, telegram]`. The C2 bot runs only via the explicit
`nexus control` command (there is no auto-scheduled control phase).

**Reserved — not wired:** `use_same_webhook` (each channel uses its own webhook/token).

## `nemesis:`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | informational only — components gate themselves individually (not read as a master switch) |
| `memory.enabled` | `true` | local SQLite engagement memory |
| `skills.enabled` | `[]` | **no skill is auto-enabled**; list names to activate (see [SKILLS_REFERENCE.md](SKILLS_REFERENCE.md)) |
| `browser.enabled` | `false` | Playwright browser automation (off by default) |
| `agents` | `{}` | per-agent AI provider/model/effort chains (validated; see above) |
| `runtime` | `{}` | bounded multi-agent runtime limits used by `nexus team` |
| `mcp.enabled` | `false` | **not the MCP client switch** — the MCP client is gated by the top-level `mcp.enabled` |

## `results:` / `database:`

Read: `database.path` (relative paths resolve against the repository root).

**Reserved — not wired:** `results.base_dir` and `results.exports_dir`. Output paths are fixed by
`lib/paths.py` (`<repo>/results`, `<repo>/exports`); the `results:` block currently has no effect.

## `mcp:`

External **MCP (Model Context Protocol) client** servers (see [MCP.md](MCP.md)).
Disabled by default; every server must also be explicitly enabled, and every
callable tool must be on its per-server allowlist. MCP servers are untrusted —
NEXUS still enforces scope, SSRF, authorization, budgets, result bounds and
redaction, and the server can never change NEXUS configuration.

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | master switch; no server is contacted while false |
| `servers` | `[]` | list (or name → entry map) of server definitions |
| `servers[].name` | — | stable server id (used in status/audit) |
| `servers[].enabled` | `false` | server must be enabled **and** the master switch on |
| `servers[].transport` | `stdio` | `stdio` or `streamable-http` |
| `servers[].command` | `[]` | stdio only: argv **list** (never a shell string) |
| `servers[].url` | `""` | streamable-http only: single MCP endpoint |
| `servers[].tools` | `[]` | per-server allowlist (**empty = deny all**) |
| `servers[].allow_active` | `false` | master switch for active/destructive tools (also needs `--authorize-active`) |
| `servers[].timeout_seconds` | `30` | per-request timeout |
| `servers[].max_result_bytes` | `262144` | hard cap on a single result/message |
| `servers[].max_concurrency` | `2` | concurrent invocations per server |
| `servers[].auth_token_env` | `""` | **name** of the env var holding a bearer token (never inline) |
| `servers[].ssrf_allow` | `[]` | extra hosts permitted for the endpoint |
| `servers[].scope_tools` | `{}` | map of tool name → target argument (e.g. `{scan: target}`) |

## `integrations:`

Third-party security-tool adapters (see [ADAPTERS.md](ADAPTERS.md)). Every
integration ships **disabled** and every scan still passes NEXUS scope +
authorization + budget controls.

| Key | Default | Meaning |
|---|---|---|
| `zap.enabled` | `false` | enable the OWASP ZAP adapter |
| `zap.base_url` | `http://127.0.0.1:8080` | running ZAP JSON API endpoint |
| `zap.api_key_env` | `ZAP_API_KEY` | **name** of the env var holding the API key (never inline) |
| `zap.timeout_seconds` | `30` | per-request timeout |
| `zap.allow_active_scan` | `false` | master switch for intrusive active scanning (also needs `--authorize-active`) |
| `zap.ssrf_allow` | `[]` | extra hosts for the SSRF guard (remote ZAP) |
| `burp.enabled` | `false` | enable the Burp Suite Professional adapter |
| `burp.base_url` | `http://127.0.0.1:1337` | running Burp REST API endpoint (Pro only) |
| `burp.api_key_env` | `BURP_API_KEY` | **name** of the env var holding the API key (never inline) |
| `burp.timeout_seconds` | `30` | per-request timeout |
| `burp.allow_scan` | `false` | master switch for intrusive crawl+audit (also needs `--authorize-active`) |
| `burp.ssrf_allow` | `[]` | extra hosts for the SSRF guard (remote Burp) |
| `caido.enabled` | `false` | enable the Caido adapter (read-only) |
| `caido.base_url` | `http://127.0.0.1:8080` | running Caido instance GraphQL API endpoint |
| `caido.api_key_env` | `CAIDO_PAT` | **name** of the env var holding a Personal Access Token / access token (never inline) |
| `caido.timeout_seconds` | `30` | per-request timeout |
| `caido.ssrf_allow` | `[]` | extra hosts for the SSRF guard (remote Caido) |

## `authn:`

Operator-configured identities for the optional AUTHN / takeover phases. NEXUS never guesses
credentials; it only uses what is declared here (these override identities persisted by a prior
AUTHN run):

```yaml
authn:
  identities:
    - name: member
      kind: user                 # user | admin | lowpriv | highpriv
      credential_ref: TEST_USER_TOKEN   # env-var NAME only, never the secret
    - name: admin
      kind: admin
      credential_ref: TEST_ADMIN_TOKEN
```

Declaring **≥2** identities unlocks the AUTHZ phase (which is otherwise gated off).

## Environment variables

Secrets and credentials (all optional; set in `config/.keys.env`):

```
DISCORD_FINDINGS_WEBHOOK, DISCORD_CVE_WEBHOOK, DISCORD_METRICS_WEBHOOK
TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID
SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, ALERT_EMAIL_FROM, ALERT_EMAIL_TO
HACKERONE_API_USERNAME, HACKERONE_API_TOKEN, BUGCROWD_API_KEY
INTIGRITI_API_KEY, YESWEHACK_API_KEY
NVD_API_KEY, GITHUB_TOKEN
OPENAI_API_KEY, GLM_API_KEY, DEEPSEEK_API_KEY, GEMINI_API_KEY,
KIMI_API_KEY, OPENROUTER_API_KEY, CUSTOM_API_KEY, CUSTOM_BASE_URL
ZAP_API_KEY, BURP_API_KEY, CAIDO_PAT, MCP_REMOTE_TOKEN
DISCORD_BOT_TOKEN, C2_OWNER_ID
```

Framework variables (set in the OS environment, never in files):

| Variable | Meaning |
|---|---|
| `NEXUS_GUI_USER` / `NEXUS_GUI_PASS` | Local GUI administrator credentials. If unset the GUI **fails closed** (HTTP 503). Scan targets submitted through the GUI are authorized against the configured `targets:` scope; a target not covered by any configured `in_scope` is rejected (HTTP 403). |
| *(MCP bearer token)* | Each `mcp.servers[].auth_token_env` names an env var (e.g. `MCP_REMOTE_TOKEN`) holding a Streamable-HTTP bearer token. Set in `config/.keys.env` or the OS environment; the value is never written to `nexus.yaml` and is never logged. |

## Startup failures

`load_config()` raises `ConfigError` for malformed YAML or an unreadable config directory —
`python -m nexus doctor` reports the exact cause. Missing `${VAR}` values do **not** fail
startup; the related integration simply stays inactive.
