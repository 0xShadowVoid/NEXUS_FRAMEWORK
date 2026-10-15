# NEMESIS Skills Reference

Skills are the NEMESIS **methodology layer** above tools: YAML playbooks describing *what to
do* inside a phase, constrained by guardrails and scope. Files live in `skills/*.yaml`; loading
is implemented in `lib/nemesis/skills.py` (tool references are validated against the existing
ToolRegistry — skills can never introduce new execution paths).

**No skill is enabled automatically.** Activate explicitly:

```yaml
nemesis:
  skills:
    enabled: [recon, triage]     # in config/nexus.yaml
```

## Bundled skills

| Skill | Description | Tools referenced | Guardrails |
|---|---|---|---|
| `recon` | Map the attack surface (subdomains, URLs, tech, OSINT) | subfinder, assetfinder, httpx, katana, gau, waybackurls, dorker | scope-validated target only; read-only enumeration; stop at detection |
| `web_hunt` | Test a discovered surface for web vulnerabilities (detection + PoC) | nuclei, dalfox, httpx, ffuf | detection + PoC only; no exploitation |
| `idor` | IDOR/BOLA differential testing methodology | httpx, arjun | requires identities; differential access checks only |
| `jwt` | JWT weakness checks (alg confusion, missing validation) | httpx | decode/verify only; no brute-force |
| `triage` | Verify findings, kill false positives, prioritise by real impact | — (analysis skill) | evidence-based; deterministic verification wins over AI opinion |
| `report` | Produce a submission-ready, proof-only report | — (reporting skill) | sanitized evidence only |

## Structure of a skill file

```yaml
name: recon
description: Map the attack surface for a target (subdomains, URLs, tech, OSINT).
prompt: |
  Enumerate subdomains and URLs, fingerprint technology, and run
  multi-engine dorking. Never leave the authorized scope. Stop at
  detection — collect surface, do not test vulnerabilities here.
tools: [subfinder, assetfinder, httpx, katana, gau, waybackurls, dorker]
guardrails:
  - scope-validated target only
  - read-only enumeration
```

## Security model

- Skills are **suggestions for the reasoning layer**; every action still passes scope
  validation, payload guarding, and the SSRF guard.
- Tool lists are validated against the ToolRegistry; unknown tools are rejected.
- Skills cannot enable destructive behavior — the detection + PoC boundary applies
  (see [SECURITY.md](SECURITY.md)).
- With `nemesis.skills.enabled: []` (the default) no skill logic runs at all.
