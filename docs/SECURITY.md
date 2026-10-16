# Security

Read this before running NEXUS against anything.

## Authorization is the entry condition

NEXUS is built for **legally authorized** security testing: your own systems, lab
environments, or bug-bounty program assets that are explicitly in scope. Unauthorized use is
prohibited by the license. Operators are responsible for authorization — the framework
enforces technical scope, not legal permission.

## What NEXUS enforces in code

| Control | Implementation |
|---|---|
| Target scope | `lib/scope_validator.py` — the scan target, the internal HTTP collector, **and every target handed to an external tool** are validated against the active target's `in_scope`; `out_of_scope` entries always win. See the semantics note below. |
| External-tool handoff | `phases/probe/tool_runner.py` re-validates every target/URL immediately before spawning an external tool (scope guard fails closed → the tool is skipped, nothing reaches the subprocess). URL lists written for nuclei/dalfox/httpx/dnsx are scope-filtered first. |
| Private-IP protection | loopback/private/link-local/metadata addresses need an explicit in-scope IP grant (network phase additionally needs `phases.network.allow_private`) |
| SSRF protection | `lib/ssrf_guard.py` — applied to every outbound HTTP path, including redirect chains and provider/AI endpoints |
| Payload boundary | `lib/payload_guard.py` — destructive SQL, reverse shells, download-and-execute, and webshell payloads are rejected |
| Detection + PoC only | no data extraction, no modification, no persistence, no backdoors, no shells |
| Secret hygiene | `core/sanitizer.py` redacts credentials/keys/tokens before evidence or reports are written; `self-scan` detects committed secrets |
| Finding lifecycle | `core/lifecycle.py` — `candidate → probable → validated/rejected`; deterministic verification gates promotion; AI cannot validate |
| Local GUI | `core/gui.py` requires `NEXUS_GUI_USER`/`NEXUS_GUI_PASS` on every protected route and fails closed (HTTP 503) when unset; serve it loopback-only with `python -m nexus gui` (default `127.0.0.1:8080`). Scan targets are authorized only against the configured `targets:` scope (a request can never define its own boundary; missing/empty/malformed scope fails closed) |
| Cloud phases | identity verified against a mandatory per-provider account allowlist **before any other API call**; read-only checks only; empty allowlist = zero calls |
| Audit trail | finding transitions, evidence provenance (tool, source, phase), and scan records in SQLite |

## Scope semantics — read this

Scope is enforced **before any traffic**, again **before any external-tool handoff**, and on
**every HTTP redirect hop**. In-scope is determined only by `in_scope`; `out_of_scope` always
wins. NEXUS never broadens authorization implicitly:

- **Exact host** — `in_scope: [example.com]` authorizes `example.com` only. Subdomains are **not**
  implied: `api.example.com` is out of scope. To test subdomains, authorize them explicitly with
  `*.example.com` (covers the apex and all subdomains).
- **Anchored wildcards** — `*.example.com` matches `example.com` and `a.b.example.com` but never
  `example.com.attacker.test` or `evilexample.com`.
- **Ports** are ignored for host matching (a host is authorized regardless of port); restrict
  ports separately via the network phase.
- **IP literals** require an explicit `in_scope` exact entry or CIDR (e.g. `10.0.0.0/24`).
  Unlisted IPs fail closed; private/loopback/metadata addresses additionally require the network
  phase's two-key grants.
- **Malformed input** (spaces, backslashes, `user@` userinfo tricks, bare paths) is rejected.

The web GUI (`core/gui.py`) derives its authorization boundary **only** from the configured
`targets:` scope — the union of every configured target's `in_scope`, minus its `out_of_scope`.
The target named in an HTTP request never contributes to that boundary, so a request cannot
authorize itself, and a missing, empty, or malformed scope fails closed (HTTP 403/503). The
explicit "confirm" checkbox is a UX guard, not a security control.

Recon (`discover`) can surface third-party hosts (for example via dorking). Those discovered
URLs/hosts are filtered at every external-tool handoff: out-of-scope entries are dropped from the
tool input lists (`urls.txt`, `domains.txt`) and never reach nuclei, dalfox, sqlmap, httpx, dnsx,
ffuf, katana, gowitness, subdominator, etc. The full discovered set is still recorded in the recon
summary for audit. Out-of-scope findings are marked `OUT_OF_SCOPE` and excluded from drafts,
alerts, and chains, but remain in the raw findings/report so you can audit what was seen.

## Default-off surfaces

Auto-hunt (`hunt`), the C2 control bot, NEMESIS browser automation, MCP transport, and cloud
providers are **off by default** and require explicit configuration. Optional external tools
are never bundled.

## Reporting a vulnerability in NEXUS itself

1. Do **not** open a public issue with exploit details.
2. Contact the maintainer (see the GitHub profile) with description, impact, reproduction
   steps, and affected version (`python -m nexus --version`).
3. Allow up to 30 days for a response before any disclosure.

## Operational hygiene

- Keep `config/.keys.env` out of git (already ignored) and out of backups of the repo.
- Run `python -m nexus self-scan` before publishing anything from the workspace.
- Put `nexus.db`, `results/`, and `logs/` outside any public artifact — they contain evidence
  about your targets (all three are git-ignored by default).
- Use `--dry-run` (`agent`, `scope-sync`) to preview actions before execution.
