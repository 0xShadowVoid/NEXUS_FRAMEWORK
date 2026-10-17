# Security-Tool Adapters

NEXUS can drive external security tools through a small **adapter framework**
(`lib/adapters/`) without letting those tools bypass the framework's security
controls. The core knows nothing about any specific product: an adapter only
*translates* a tool's concepts into NEXUS concepts. The first adapter is
**OWASP ZAP**; Burp and Caido plug in through the same interface.

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

## CLI

```bash
nexus zap --health                     # connection + version check
nexus zap --capabilities               # declared capabilities
nexus zap --passive https://ex.com/ --domain ex.com
nexus zap --active  https://ex.com/ --authorize-active --domain ex.com
nexus zap --passive https://ex.com/ --import-scan 12   # persist findings+evidence
nexus zap --mock --passive https://ex.com/ --domain ex.com   # offline dry run
```

- Passive/spider jobs are non-intrusive; **active** scanning requires both
  `integrations.zap.allow_active_scan: true` *and* the per-run
  `--authorize-active` flag.
- The target is validated against scope before any scan activity; the ZAP
  endpoint itself passes the SSRF guard.

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
`Low/Informational→P4`).

## Adding another adapter (Burp / Caido)

Create a module that implements `SecurityToolAdapter` and self-registers:

```python
from lib.adapters.registry import register

@register("burp")
def build_burp(spec): return BurpAdapter(...)
```

That is the only change required — `GuardedAdapter`, the CLI wiring point, and
`ingest_findings` are product-agnostic. (Burp/Caido adapters are not part of
this task.)

## Limitations

- The adapter translates a documented REST API; it does not bundle or install
  the tool. ZAP must already be running and reachable.
- Active scanning is intrusive: it is opt-in and per-run authorized, and is
  only as safe as the configured scope.
- `--mock` uses a deterministic in-memory backend for offline validation; it
  performs **no** real scanning.
- The standard test suite never contacts a live ZAP or external target.
