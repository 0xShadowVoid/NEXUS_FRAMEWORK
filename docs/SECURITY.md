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
| Target scope | `lib/scope_validator.py` — every outbound action validates against the active target's `in_scope`; `out_of_scope` entries always win |
| Private-IP protection | loopback/private/link-local/metadata addresses need an explicit in-scope IP grant (network phase additionally needs `phases.network.allow_private`) |
| SSRF protection | `lib/ssrf_guard.py` — applied to every outbound HTTP path, including redirect chains and provider/AI endpoints |
| Payload boundary | `lib/payload_guard.py` — destructive SQL, reverse shells, download-and-execute, and webshell payloads are rejected |
| Detection + PoC only | no data extraction, no modification, no persistence, no backdoors, no shells |
| Secret hygiene | `core/sanitizer.py` redacts credentials/keys/tokens before evidence or reports are written; `self-scan` detects committed secrets |
| Finding lifecycle | `core/lifecycle.py` — `candidate → probable → validated/rejected`; deterministic verification gates promotion; AI cannot validate |
| Local GUI | `core/gui.py` binds to `127.0.0.1`, requires `NEXUS_GUI_USER`/`NEXUS_GUI_PASS`, fails closed (HTTP 503) when unset |
| Cloud phases | identity verified against a mandatory per-provider account allowlist **before any other API call**; read-only checks only; empty allowlist = zero calls |
| Audit trail | finding transitions, evidence provenance (tool, source, phase), and scan records in SQLite |

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
