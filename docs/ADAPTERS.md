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
environment / `config/.keys.env`. Adapters ship **disabled**.

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
every timeout/cancellation result is flagged `burp_may_still_be_running: true`.
A timeout is **not** proof that Burp stopped. Reading results from an existing
scan id (`--scan-id`) performs **no** active requests.

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
- The target is validated against scope before any scan activity; the ZAP
  endpoint itself passes the SSRF guard.
- Caido never starts a job; its retrieval endpoint passes the SSRF guard and
  imported finding endpoints are scope-checked.

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
  an out-of-scope or malformed target raises `AdapterPolicyError`.
- **Authorization:** active/intrusive jobs require the policy master switch
  (`allow_active`) *and* per-run authorization (`spec.authorized`).
- **SSRF:** the tool endpoint and target URLs pass `lib.ssrf_guard.is_safe_url`.
- **Budgets & kill switch:** `lib.ops_guard` (`spend_requests`, `KillSwitch`).
- **Untrusted output:** tool alerts and HTTP content are never executed;
  every string is redacted (`lib.redaction`) and length-capped
  (`core.sanitizer`) before it becomes a finding, log line or evidence row.
- **Audit:** every start/stop/collect is recorded (`category="adapter"`).

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

That is the only change required — `GuardedAdapter`, the CLI wiring point, and
`ingest_findings` are product-agnostic.

## Limitations

- The adapter translates a documented API; it does not bundle or install
  the tool. ZAP, Burp, or Caido must already be running and reachable.
- Burp support is limited to the **Professional** REST API and to the
  capabilities listed above; it cannot read proxy history or stop a scan.
- Caido support is **read-only** and limited to its documented GraphQL API
  (findings + HTTP history); it cannot start, stop, or drive active scanning.
- Active scanning is intrusive: it is opt-in and per-run authorized, and is
  only as safe as the configured scope.
- `--mock` uses a deterministic in-memory backend for offline validation; it
  performs **no** real scanning.
- The standard test suite never contacts a live ZAP, Burp, Caido, or external target.
