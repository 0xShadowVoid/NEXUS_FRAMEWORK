# Phase Reference

Phases are declared in `core/phase_registry.py`. The default plan (every `hunt`) runs the four
core phases; optional phases run only when their gates are satisfied (profile, scope kind,
explicit enablement). Each phase is attributed per finding/evidence via the canonical
`EVIDENCE_PHASES` set.

## Core plan (default path)

| # | Phase | Runner | Purpose | Outputs |
|---|---|---|---|---|
| 10 | `discover` | `phases.discover.recon_orchestrator:run_discover` | Reconnaissance + attack-surface discovery (subdomains, URLs, tech fingerprint) | asset graph entries, surface records |
| 20 | `probe` | `phases.probe.probe_orchestrator:run_probe` | Web vulnerability testing via the ToolRegistry (external tools optional) | findings + raw evidence |
| 30 | `verify` | `phases.verify.verify_orchestrator:run_verify` | Deterministic verification of findings (marker/behavior checks) | lifecycle transitions |
| 40 | `analyze` | `phases.analyze.analyze_orchestrator:run_analyze` | Dedup, severity, false-positive filtering, chain detection, persistence | final finding set |
| 90 | `report` | `core.reporter:write_report` | Report + export generation | `results/<target>/<scan>/`, SARIF/JSON |

## Optional plan (gated)

| # | Phase | Gate | Purpose |
|---|---|---|---|
| 50 | `authn` | `requires_capability="login"` | Authentication / account-takeover surface detection |
| 55 | `authz` | `requires_identities=true` | Authorization / IDOR / BOLA differential testing |
| 60 | `takeover` | profiles `extended`/`deep` | Subdomain takeover + domain lifecycle intelligence |
| 65 | `network` | profiles `extended`/`deep` **and** `scope_kind` containing `ip` | Port + service discovery (nmap/naabu parsers; bounded TCP/TLS/HTTP probes) |
| 70 | `cloud` | `scope_kind` containing `cloud` | Read-only AWS/Azure/GCP posture checks (identity-first authorization, per-provider allowlists) |
| 75 | `intel` | `enabled_by_default=false` (enable with `phases.intel.enabled`) | CVE/GHSA/CPE enrichment for detected technologies |

## Execution controls

- **Scope first:** every phase validates targets against `in_scope`/`out_of_scope` before
  issuing traffic; network/cloud phases additionally require explicit grants (see
  [CONFIGURATION.md](CONFIGURATION.md) and [SECURITY.md](SECURITY.md)).
- **Cancellation & budgets:** request budgets, per-tool timeouts, and kill-switch/cancel events
  are honored; cancelled scans are recorded `partial`, never silently dropped.
- **Findings lifecycle:** candidates enter as `candidate` and move `probable → validated` only
  through deterministic verification; AI/NEMESIS can *suggest* but never validate.
- **Evidence:** every phase writes evidence rows (source-attributed, sanitized) linked to
  assets and findings; phases map to the canonical evidence-phase set (`discover`, `probe`,
  `verify`, `analyze`, `hunt`, `control`, `authn`, `authz`, `takeover`, `intel`, `report`,
  `browser`, `network`, `cloud`).

## Example invocations

```powershell
python -m nexus hunt lab.local --discover-only      # discover only
python -m nexus hunt lab.local                      # core plan
python -m nexus hunt lab.local --full-scan          # includes extended-profile optional phases when gated in
```
