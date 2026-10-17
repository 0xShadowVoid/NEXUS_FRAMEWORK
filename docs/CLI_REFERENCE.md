# CLI Reference

Entry points: `python -m nexus <command>` (from the repository root) or the installed `nexus`
script (from a pip install). Global flags: `--help`, `--version` (prints `NEXUS 2.0.1 "Apex"`).

Shared scan flags (accepted by `hunt`; several also by `batch`):

| Flag | Meaning |
|---|---|
| `--quick-scan` / `--full-scan` | intensity override (light default / all tools) |
| `--discover-only` | recon only, no active probing |
| `--scan-only` | skip discovery |
| `--with-subdomains` | include subdomain enumeration |
| `--include-cdn` | do not skip CDN-hosted assets |
| `--test-bypass` / `--custom-fuzzing` | extended probe modules |
| `--screenshots` | capture screenshots (needs `gowitness`) |
| `--delta` | scan only URLs new since the last run |
| `--parallel N` | run light tools concurrently (default 1) |
| `--cookie VALUE` | session cookie for authenticated checks |
| `--methodology NAME` | methodology preset |
| `--rate-limit RATE` | e.g. `50/minute` |
| `--min-severity SEV` | floor for reporting |
| `--exclude PATTERN` | exclude matcher |
| `--exclude-p4` | skip P4 noise |
| `--skip-tools / --run-tools LIST` | explicit tool exclusion/selection |
| `--resume SCAN_ID` | resume a previous scan |
| `--cve ID` | include a specific CVE in context |

## Commands (32)

### Scanning
- `hunt TARGET` — scan a single target (accepts the shared scan flags above).
- `batch FILE [--concurrent N] [--sequential]` — scan targets from a text file (one per line).
- `hunt-schedule [NAME] [--list | --daily TARGET | --weekly TARGET | --every-6h TARGET | --cron EXPR | --name S | --target T]` — manage schedules executed by `serve`.
- `hunt-new [--enable | --disable]` — first-blood auto-hunt toggle/status (Phase 4).
- `dork TARGET [--intents LIST] [--engines LIST]` — multi-engine Google-dorking (engines off unless configured).

### Findings & evidence
- `verify FINDING_ID` — manually mark a finding verified.
- `reject FINDING_ID` — mark false-positive **and** teach the FP filter.
- `draft FINDING_ID [--platform P] [--target T]` — render a submission draft (`generic`/`hackerone`/`bugcrowd`/`intigriti` templates).
- `diff SCAN1 SCAN2` — compare two scans (both int ids).
- `export [TARGET] [--format zip|7z|json|csv|html|sarif] [--date DATE]` — export findings/evidence.
- `import FILE [--merge]` — restore an export bundle.

### Intelligence
- `cve-update [--target T]` — manual CVE feed update (KEV/EPSS per config).
- `cve-scan TARGET [--critical] [--cve ID]` — match recorded tech against CVE data.

### Operations
- `doctor` — diagnose environment, config, scope, and tools.
- `check-tools` — installed vs missing external tools.
- `self-scan [--root PATH] [--include-allowlisted]` — scan the repo for committed secrets.
- `secretscan [--staged | --history | --tree [PATH]] [--root PATH] [--max-commits N] [--allowlist F] [--json]` — scan staged content (default), commit history, or the tree; masked output; exit 2 = fail-closed. See [HOOKS.md](HOOKS.md).
- `hooks install|status|uninstall [--repo PATH]` — enable/inspect/disable the pre-commit secret-scan hook (`core.hooksPath`).
- `scope-sync --domain D --file F [--platform hackerone|bugcrowd] [--config PATH] [--dry-run]` — import a local program scope JSON into `nexus.yaml`.
- `scope-sync --program DOMAIN [--dry-run]` / `scope-sync --all [--dry-run]` — auto-pull a configured target's published in/out-of-scope from its platform API (roadmap E1); updates `nexus.yaml` only when the scope changed. Credentials come from env vars named in the target's `sync:` block.
- `scope-sync --program DOMAIN|--all [--notify]` — opt in to scope-drift alerts (roadmap E3): on a change, send a structured drift event through the configured channels (Discord/Telegram/email). Off unless `scope_sync.notify.enabled` is true or `--notify` is passed; alerts never broaden scope and delivery failures are reported separately from the sync result.
- `serve [--interval S] [--once]` — run due schedules (daemon; `--once` for a single pass).
- `gui [--host H] [--port P] [--allow-remote] [--log-level L]` — serve the local web GUI (loopback by default; requires `NEXUS_GUI_USER`/`NEXUS_GUI_PASS`, otherwise it refuses to start).
- `retention --days N` — report scan folders older than N days (**report only, deletes nothing**).
- `monitor [--file programs.json]` — diff current program list against the last snapshot.
- `update [--all | --tools-only | --tools-update]` — update framework metadata and/or external tools.

### Agents & integrations
- `agent OBJECTIVE [--max-steps N] [--dry-run] [--agent NAME]` — plan-and-act agent over whitelisted actions (`scan`, `discover`, `dork`, `cve-update`, `status`, `report`). `--agent NAME` selects per-agent AI settings from `nemesis.agents`.
- `team [OBJECTIVE] [--target HOST] [--plan FILE] [--workers N]` — run the bounded multi-agent runtime on a task plan (deterministic/offline by default; `--plan` loads a JSON task DAG `[{id,role,action,target,depends_on}]`).
- `c2` — start the Discord/Telegram control bot (requires `c2_bot` config + tokens; the `control` phase is off by default).
- `openapi --file SPEC [--base URL]` — ingest an OpenAPI/Swagger spec into endpoints.
- `graphql --file RESULT.json` — analyze a GraphQL introspection result.
- `ai-keys` — show AI key-pool status (masked) and configured agents.
- `ai-providers` — list AI providers, capabilities and verified/supported status.
- `ai-runtime [--provider NAME]` — probe a local model runtime (Ollama / OpenAI-compatible) for connection and installed models.
- `ai-set-key --provider openai|glm|deepseek|gemini|kimi|openrouter|custom --key KEY` — store an AI key (multi-key failover pool).
- `zap [--health] [--capabilities] [--passive URL | --active URL --authorize-active] [--domain D] [--import-scan ID] [--mock]` — drive the OWASP ZAP adapter through the guarded, scope-checked framework (see [ADAPTERS.md](ADAPTERS.md)).
- `burp [--health] [--capabilities] [--issue-definitions] [--active URL --authorize-active] [--scan-id ID] [--domain D] [--import-scan ID] [--collect] [--timeout S] [--poll S] [--mock]` — drive the Burp Suite Professional adapter (Pro REST API) through the same guarded, scope-checked framework (see [ADAPTERS.md](ADAPTERS.md)).

## Exit behavior

`0` on success; non-zero on usage errors, failed scope validation, or command failure.
`--version`/`--help` exit `0`.

## Optional integrations

Cloud checks (`phases.cloud`), browser automation (`nemesis.browser`), MCP (`nemesis.mcp`),
C2 bots, and AI providers are inactive until configured. Absent optional SDKs/tools never
block the CLI — affected phases/tools report `skipped`/`missing` instead.
