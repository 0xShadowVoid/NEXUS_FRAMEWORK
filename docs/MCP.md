# MCP Client & Tool Gateway

NEXUS includes a **Model Context Protocol (MCP) client** that lets the framework
discover and invoke tools exposed by external MCP servers *without ever treating
those servers as trusted*. NEXUS stays the policy authority: scope,
authorization, SSRF, budgets, result bounds and redaction are all enforced here,
before and after every tool invocation.

This is the **client** half of MCP (`lib/mcp/`). It is separate from, and
additive to, the server-side tool gateway that NEMESIS already exposes for
NEXUS's own tools (`lib/nemesis/mcp.py`).

MCP is **disabled by default**. No server is contacted, no transport is opened,
and no tool is callable until an operator explicitly enables both the feature and
the individual server.

## Design principle: an MCP server is untrusted input

Everything a server sends is data, never instruction:

- Tool **metadata**, **schemas** and **results** are parsed, validated and
  redacted — never applied back to configuration.
- An MCP server **cannot** change NEXUS scope, permissions, credentials,
  allowlists or any security configuration. It has no write path to them.
- Discovery is not authorization: seeing a tool (`tools/list`) never makes it
  callable. Only a tool on the **per-server allowlist** is registered.
- Every gate **fails closed**: unknown server, unknown tool, malformed schema,
  missing/extra/mistyped argument, out-of-scope host, blocked destination or a
  disallowed action is denied with a reason, never executed.

## Policy pipeline

Each invocation passes the same boundaries the rest of the framework uses:

```
server enabled? → kill switch → config valid (transport/SSRF/argv)
    → connect + discover → allowlist → schema (args vs inputSchema)
    → active-approval (allow_active + --authorize-active)
    → SSRF (URL arguments) → NEMESIS gateway:
          AUTH → AUTHORIZATION → SCOPE → SAFETY → EXECUTION → EVIDENCE → AUDIT
    → bounded + redacted result
```

The NEMESIS gateway (`lib/nemesis/mcp.py`) provides the auth/authz/scope/payload
safety/audit stages; the MCP layer adds the MCP-specific gates (explicit
enablement, allowlist, schema validation, active-tool approval, SSRF on both the
endpoint and URL arguments, and result bounds + redaction).

## Enabling MCP

Enable the master switch, then enable each server individually:

```yaml
mcp:
  enabled: true                  # master switch
  servers:
    - name: filesystem
      enabled: true
      transport: stdio           # stdio | streamable-http
      command: [npx, -y, "@modelcontextprotocol/server-filesystem", /data]
      tools: [read_file, list_directory]   # per-server allowlist
      allow_active: false        # active/destructive tools need true + --authorize-active
      timeout_seconds: 30
      max_result_bytes: 262144
      max_concurrency: 2
    - name: remote-tools
      enabled: true
      transport: streamable-http
      url: https://mcp.example.com/mcp
      auth_token_env: MCP_REMOTE_TOKEN     # env var NAME holding a bearer token
      tools: [echo]
      ssrf_allow: []             # extra hosts if the endpoint is on a private network
```

| Key | Default | Meaning |
|---|---|---|
| `enabled` (top level) | `false` | master switch; nothing runs while false |
| `servers` | `[]` | list (or map of name → entry) of server definitions |
| `name` | — | stable server id, used in status/audit |
| `enabled` (per server) | `false` | server must be enabled **and** the master switch on |
| `transport` | `stdio` | `stdio` or `streamable-http` |
| `command` | `[]` | stdio only: **argv list** (never a shell string) |
| `url` | `""` | streamable-http only: single MCP endpoint |
| `tools` | `[]` | per-server allowlist; **empty = deny all** |
| `allow_active` | `false` | master switch for active/destructive tools (also needs per-call approval) |
| `timeout_seconds` | `30` | per-request timeout |
| `max_result_bytes` | `262144` | hard cap on a single result/message |
| `max_concurrency` | `2` | concurrent invocations per server |
| `auth_token_env` | `""` | **name** of the env var holding a bearer token (never inline) |
| `ssrf_allow` | `[]` | extra hosts permitted for the endpoint |
| `scope_tools` | `{}` | map of tool name → the argument that holds its target (e.g. `{scan: target}`) |

## Transports

| Transport | Status | Notes |
|---|---|---|
| **stdio** | supported | launches a local server as a subprocess and speaks newline-delimited JSON-RPC over its stdio. The command is an explicit argv **list** (never a shell) and is re-validated by the payload guard before launch. |
| **Streamable HTTP** | supported | POSTs each JSON-RPC message to one MCP endpoint; accepts a JSON or request-scoped SSE response. The endpoint passes the SSRF guard and redirects are refused. |
| HTTP+SSE (legacy) | **not supported** | deprecated by the spec in favour of Streamable HTTP; not implemented. |
| 2026-07-28 stateless revision | **not supported** | the handshake-based revisions are targeted; the newer stateless discovery flow is not implemented. |
| Server / sampling / prompts | **not supported** | only the `tools` capability is used. |

The client negotiates one of the handshake-based protocol revisions
(`2025-06-18`, `2025-03-26`, `2024-11-05`). The official Python SDK (`mcp`) is
the maintained reference implementation; NEXUS ships a small self-contained
client so the framework keeps **zero new runtime dependencies** and its tests
stay fully offline. See [Limitations](#limitations--non-goals).

## CLI

```bash
python -m nexus mcp --list                 # configured servers + master switch state
python -m nexus mcp --config-check         # validate every server (secret-free report)
python -m nexus mcp --server NAME --status # connect, discover, report (no tool runs)
python -m nexus mcp --server NAME --tools  # discovered tool metadata (no tool runs)
python -m nexus mcp --server NAME --call TOOL --arg k=v [--arg k=v] \
    [--authorize-active] [--domain D]      # invoke through the full policy pipeline
python -m nexus mcp --mock [--status|--tools|--call TOOL --arg k=v ...]  # offline backend
```

`--domain D` loads the engagement scope for a target so scope-checked tools can
be evaluated. `--mock` uses an in-memory server — no network, no subprocess — for
demonstration and testing. Exit code is non-zero on denial or failure; `--status`
and `--tools` never execute a tool.

## Security controls

- **Disabled by default** — master switch plus per-server opt-in.
- **Allowlist by default-deny** — only named tools are registered; an empty
  `tools` list denies everything.
- **Schema validation** — arguments are checked against the discovered
  `inputSchema` before execution; unknown/extra arguments are rejected when the
  schema forbids them, and a tool with an invalid schema is never registered.
- **Read-only vs active** — an active/destructive tool needs both `allow_active`
  in policy **and** a per-call `--authorize-active`.
- **Scope** — a tool mapped in `scope_tools` has its target argument checked
  against the engagement scope; with no scope configured it fails closed.
- **SSRF** — remote endpoints and URL arguments pass the SSRF guard; redirects
  are refused; cloud-metadata hosts/paths are always blocked.
- **Bounds** — per-message and per-result byte caps; retained text is capped.
- **Redaction** — results, errors and audit details are scrubbed of secrets
  before they reach logs, reports or evidence.
- **No shell** — stdio servers launch via an argv list with `shell=False`, and
  the command is screened by the payload guard.

## Audit

When a database is attached, every MCP action is recorded through
`insert_audit_event` with category `mcp` (`mcp.<server>.connect`, `.denied`,
`.config_rejected`, …). Details are redacted before storage.

## Offline testing

The whole layer is exercised without a server, socket or process: an injectable
`FakeTransport` drives a canned `FakeMcpServer`, and `nexus mcp --mock` uses the
same backend. See `tests/unit/test_pass28_mcp_client.py`.

## Limitations / non-goals

This client is deliberately minimal. It does **not** implement: the 2026-07-28
stateless revision, HTTP+SSE, server-initiated features (sampling, roots,
elicitation, prompts/resources subscription), OAuth flows, or automatic retries
and reconnection beyond a single bounded attempt. It reuses NEXUS's existing
policy pipeline rather than introducing a second tool-execution framework, and it
never lets an MCP server alter NEXUS configuration.
