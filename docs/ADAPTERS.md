# Security-Tool Adapters

NEXUS can drive external security tools through a small **adapter framework**
(`lib/adapters/`) without letting those tools bypass the framework's security
controls. The core knows nothing about any specific product: an adapter only
*translates* a tool's concepts into NEXUS concepts. Three adapters ship today —
**OWASP ZAP**, **Burp Suite Professional** and **Caido**; others plug in through
the same interface.

## Why an adapter layer

External DAST tools speak their own language (own REST API, own scan IDs, own
alert schema). Rather than couple NEXUS to each one, the framework defines one
contract and one policy boundary. Every job started through the guard passes:

```
kill switch → SCOPE + AUTHORIZATION → request budget → tool call
                                                   → findings/evidence (untrusted, sanitized)
```

## Enabling ZAP

ZAP runs as a daemon exposing its JSON REST API (default `http://127.0.0.1:8080`).
Enable the integration in `config/nexus.yaml`:

```yaml
integrations:
  zap:
    enabled: true
    base_url: http://127.0.0.1:8080
    api_key_env: ZAP_API_KEY     # env var NAME holding the API key (never inline)
    timeout_seconds: 30
    allow_active_scan: false     # intrusive scanning stays off until enabled
    ssrf_allow: []               # extra hosts if ZAP is remote
```

Set the API key out-of-band (never in YAML): `ZAP_API_KEY=...` in the
environment or `config/.keys.env` (slots for `ZAP_API_KEY`, `BURP_API_KEY`,
`CAIDO_PAT` and `MCP_REMOTE_TOKEN` are included in `config/.keys.env.example`).
Adapters ship **disabled**.

## Enabling Burp

The Burp adapter targets the **Burp Suite Professional** REST API (`v0.1`),
which is a **Professional-only** feature — Burp Community exposes no REST API.
Burp must be running with the REST API enabled (default `http://127.0.0.1:1337`);
the API key is part of the request **path**, so it is treated as a secret and
never appears in logs or error strings.

```yaml
integrations:
  burp:
    enabled: true
    base_url: http://127.0.0.1:1337
    api_key_env: BURP_API_KEY    # env var NAME holding the API key (never inline)
    timeout_seconds: 30
    allow_scan: false            # intrusive crawl+audit stays off until enabled
    ssrf_allow: []               # extra hosts if Burp is remote
```

### Burp capabilities & limitations

Only capabilities verified against the documented REST API are exposed:

| Capability | Supported | Notes |
|---|---|---|
| Connection / health | yes | driven by `GET knowledge_base/issue_definitions` |
| Capability discovery | yes | declared, no I/O |
| Active scan (crawl+audit) | yes | `POST scan` → id, `GET scan/{id}` → status |
| Issue / finding retrieval | yes | issues are read from `issue_events` |
| Proxy history / site map | **no** | only via a BApp/Montoya extension; not driven here |
| Stop / cancel a scan | **no** | no documented endpoint — see below |

Because there is **no stop endpoint**, `cancel_job` reports "unsupported" and
every timeout/cancellation result carries the note "Burp may still be scanning
(no stop endpoint)" in its job `message`; a timeout is **not** proof that Burp
stopped. Reading results from an existing scan id (`--scan-id`) performs **no**
active requests.

## Enabling Caido

The Caido adapter talks to a running instance's documented **instance GraphQL
API** (`POST <base_url>/graphql`, default `http://127.0.0.1:8080`). This is the
same endpoint Caido's own `@caido/sdk-client` wraps, so no Node SDK, extension
or community MCP server is required.

```yaml
integrations:
  caido:
    enabled: true
    base_url: http://127.0.0.1:8080   # note: same default port as ZAP
    api_key_env: CAIDO_PAT            # env var NAME holding a token (never inline)
    timeout_seconds: 30
    ssrf_allow: []                    # extra hosts if Caido is remote
```

Authenticate with an OAuth access token or a **Personal Access Token**
(`caido_…`) via `Authorization: Bearer <token>`; the token is a secret and never
appears in logs or error strings. Findings and requests are **project-scoped** —
a project must be open on the instance.

### Caido capabilities & limitations

| Capability | Supported | Notes |
|---|---|---|
| Connection / health | yes | `viewer { __typename id }` liveness + auth probe |
| Capability discovery | yes | declared, plus live `__schema` introspection (`--introspect`) |
| Finding retrieval | yes | `findings(…)` normalized, scope-checked at import |
| HTTP-history retrieval | yes | `requests(…)` metadata only — never sends traffic |
| Active scan / job start | **no** | Caido exposes **no documented remote scan API** |
| Stop / cancel | **no** | no job is started and no cancel endpoint exists |

Caido is a manual intercepting proxy: findings come from plugins/scripts, not
from a "scan this URL" endpoint. The adapter is therefore **read-only** —
`start_job` refuses to invent a scan API, and forwarding traffic (Replay /
Automate) is deliberately not driven. The Cloud API (`api.caido.io`) is
account/team management and out of scope. Caido's schema "is intentionally
public … however, stability is not guaranteed": a schema change surfaces as a
normalized `AdapterProtocolError`, never fabricated data.

## CLI

```bash
nexus zap --health                     # connection + version check
nexus zap --capabilities               # declared capabilities
nexus zap --passive https://ex.com/ --domain ex.com
nexus zap --active  https://ex.com/ --authorize-active --domain ex.com
nexus zap --passive https://ex.com/ --import-scan 12   # persist findings+evidence
nexus zap --mock --passive https://ex.com/ --domain ex.com   # offline dry run
```

Burp uses the same shape (scanning is always an active crawl+audit):

```bash
nexus burp --health                    # connection + API probe
nexus burp --capabilities              # declared capabilities
nexus burp --issue-definitions         # live issue-type discovery
nexus burp --active https://ex.com/ --authorize-active --domain ex.com
nexus burp --scan-id 42                # read-only: fetch an existing scan's issues
nexus burp --active https://ex.com/ --authorize-active --import-scan 12
nexus burp --mock --active https://ex.com/ --authorize-active --domain ex.com
```

Caido is read-only (no scan flags):

```bash
nexus caido --health                                  # connection + auth probe
nexus caido --capabilities                            # declared capabilities
nexus caido --introspect                              # live schema discovery
nexus caido --findings                                 # normalized project findings
nexus caido --findings --reporter my-plugin            # filter by reporter
nexus caido --requests --httpql 'resp.code.gte:400'    # history metadata (no traffic)
nexus caido --findings --import-scan 12 --domain ex.com
nexus caido --mock --findings                          # offline dry run
```

- Passive/spider jobs are non-intrusive; **active** scanning requires both
  `integrations.zap.allow_active_scan: true` *and* the per-run
  `--authorize-active` flag.
- The target is validated against scope before any scan activity. The tool
  endpoint and target URL additionally pass `lib.ssrf_guard.is_safe_url` with
  `local_ok=True` (loopback/private allowed for a local or self-hosted
  instance); cloud-metadata hosts/paths are still refused.
- Caido never starts a job; its retrieval endpoint passes the SSRF guard and
  imported finding endpoints are scope-checked (see the scope note below).

## Adapter contract

`lib/adapters/base.py` — `SecurityToolAdapter`:

| Method | Purpose |
|---|---|
| `capabilities()` | capability discovery (declared, no I/O) |
| `health()` | connection/health check (never raises; reports failure) |
| `validate_config()` | configuration problems (secret-redacted) |
| `start_job(spec)` | start a job → `JobHandle` |
| `job_status(handle)` | monitor progress/status |
| `wait(handle, ...)` | poll to completion, timeout, or cancellation |
| `cancel_job(handle)` | cancellation where supported |
| `collect(handle)` | normalized findings (`RawFinding`) |

Value objects: `JobSpec` (target/kind/params/authorized/timeout),
`JobHandle` (job id + normalized status), `AdapterHealth`, `RawFinding`,
`AdapterResult`. Normalized errors: `AdapterUnavailable`, `AdapterAuthError`,
`AdapterPolicyError`, `AdapterTimeout`, `AdapterProtocolError` (all extend
`AdapterError` → `NexusError`).

## Security model (enforced by `GuardedAdapter`)

- **Scope (fail closed):** `validate_target_scope` runs before any job starts;
  an out-of-scope or malformed target raises `AdapterPolicyError`. A missing
  `target_config` is **not** treated as "everything is in scope" — the gate
  denies with `scope: no target configuration (fail closed)`. The scan CLI
  derives one from `--domain` (or the active target, `cfg.target(extract_host(target))`).
  Read-only import paths without a scope context (`--import-scan` with no
  `--domain`/target, e.g. `caido --findings`) store findings out-of-scope
  (fail closed).
- **Authorization:** active/intrusive jobs require the policy master switch
  (`allow_active`) *and* per-run authorization (`spec.authorized`), which the
  CLI wires from `--authorize-active` for ZAP and Burp.
- **SSRF:** the tool endpoint and target URL pass `lib.ssrf_guard.is_safe_url`
  with `local_ok=True` — loopback/private destinations are permitted (for a
  local/self-hosted instance) while cloud-metadata hosts/paths remain refused.
- **Budgets & kill switch:** `lib.ops_guard` (`spend_requests`, `KillSwitch`).
- **Untrusted output:** tool alerts and HTTP content are never executed; free-text
  fields are redacted (`lib.redaction`) and length-capped (`core.sanitizer`)
  before they become a finding/log/evidence row. Short identifiers copied from
  an alert (`method`, `cwe_id`, `plugin_id`, `alert_id`) are preserved as
  provenance and are **not** run through the redactor.
- **Audit:** start/stop/collect are recorded (`category="adapter"`) **when a
  database is attached** (i.e. `--import-scan`); standalone read-only runs write
  no audit rows.

## Findings & evidence provenance

`ingest_findings(db, scan_id, findings, target_config, phase=...)` persists
each finding with its source tool and re-checks scope (out-of-scope findings
are stored `in_scope=False`). Evidence rows record the tool, source and the
originating plugin/alert id, and the DB choke point sanitizes them again on
write. ZAP risk words map to NEXUS severities (`High→P2`, `Medium→P3`,
`Low/Informational→P4`); Burp severities/confidence map through its own words.
Caido findings carry no severity field, so they import as `P4`/`50` with the
`reporter` preserved as the plugin id.

## Adding another adapter

Create a module that implements `SecurityToolAdapter` and self-registers:

```python
from lib.adapters.registry import register

@register("myproxy")
def build_myproxy(spec): return MyProxyAdapter(...)
```

`GuardedAdapter`, `ingest_findings` and the policy layer are product-agnostic,
but a new product additionally needs: (1) its module added to the loader tuple
in `lib/adapters/registry.py` (`("zap", "burp", "caido")`), and (2) a CLI
subcommand (`cmd_*` + `add_parser`) in `nexus.py`. The registry does **not**
auto-discover adapter modules.

## Limitations

- The adapter translates a documented API; it does not bundle or install
  the tool. ZAP, Burp, or Caido must already be running and reachable.
- Burp support is limited to the **Professional** REST API and to the
  capabilities listed above; it cannot read proxy history or stop a scan.
- Caido support is **read-only** and limited to its documented GraphQL API
  (findings + HTTP history); it cannot start, stop, or drive active scanning.
- Active scanning is intrusive: it is opt-in and per-run authorized, and is
  only as safe as the configured scope.
- **Scope model (residual risk):** an unlisted domain self-scopes — `cfg.target(d)`
  defaults `in_scope` to `[d]` when the domain has no `targets:` entry, so the
  scope gate authorizes exactly the target you passed (it never widens to
  siblings/subdomains). To restrict a target you must add an explicit `targets:`
  entry with `in_scope`/`out_of_scope`. Review scope config before active runs.
- Read-only retrieval paths (Caido `findings`/`requests`, Burp issue definitions,
  adapter `capabilities`/`health`) do not send traffic to the target and are not
  routed through `GuardedAdapter`; findings they return are scope-checked at
  import (`ingest_findings`).
- `--mock` uses a deterministic in-memory backend for offline validation; it
  performs **no** real scanning.
- The standard test suite never contacts a live ZAP, Burp, Caido, or external target.
