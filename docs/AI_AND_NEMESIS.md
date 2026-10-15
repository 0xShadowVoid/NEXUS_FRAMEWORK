# AI and NEMESIS

NEMESIS is the optional reasoning layer on top of NEXUS. NEXUS executes; NEMESIS helps you
think: triage, threat-intel correlation, agent loops over whitelisted skills/actions.

## Providers

Configured in `config/nexus.yaml` (`ai:`) with keys in `config/.keys.env`:

| Provider | Key variable | Notes |
|---|---|---|
| `openai` | `OPENAI_API_KEY` | default provider |
| `glm` | `GLM_API_KEY` | |
| `deepseek` | `DEEPSEEK_API_KEY` | |
| `gemini` | `GEMINI_API_KEY` | |
| `kimi` | `KIMI_API_KEY` | |
| `openrouter` | `OPENROUTER_API_KEY` | |
| `custom` | `CUSTOM_API_KEY` + `CUSTOM_BASE_URL` | your own OpenAI-compatible endpoint |
| `ollama` | — | local, no key needed |

Multi-key failover: several keys per provider form a pool (`python -m nexus ai-set-key` adds;
`python -m nexus ai-keys` shows masked status). `ai.fallback_providers` lists the order of
providers tried after the primary. `ai.max_calls` caps AI calls per run (0 = unlimited).

## Behavior without an AI provider

**Everything in NEXUS works without any AI key.** AI absence means: no triage suggestions, no
AI-assisted summaries, no NEMESIS agent loops. Scans, verification, exports, GUI, network and
cloud phases are fully deterministic and unaffected. `ai.provider: none` is not a special
mode — simply having no keys has the same effect.

## NEMESIS components

| Component | Config | Default |
|---|---|---|
| Engagement memory (local SQLite) | `nemesis.memory.enabled` | on |
| Skills (methodology playbooks) | `nemesis.skills.enabled: []` | none active — see [SKILLS_REFERENCE.md](SKILLS_REFERENCE.md) |
| Browser automation (Playwright) | `nemesis.browser.enabled` | off |
| MCP transport | `nemesis.mcp.enabled` | off |

## Security model

- NEMESIS can **suggest**; it can never **validate** — finding promotion requires the
  deterministic verifier (enforced in `core/lifecycle.py`).
- Agent actions (`python -m nexus agent ...`) run over a whitelist
  (`scan`, `discover`, `dork`, `cve-update`, `status`, `report`) — no arbitrary execution.
- Outbound AI traffic goes through the SSRF guard with provider-host allowlisting.
- Skills are scope- and registry-constrained; guardrails live in the YAML and are enforced
  by the runtime (see [SKILLS_REFERENCE.md](SKILLS_REFERENCE.md)).

## Quick start

```powershell
python -m nexus ai-set-key --provider deepseek --key <YOUR-KEY>
python -m nexus ai-keys
# then, for example:
python -m nexus agent "triage latest findings for lab.local" --max-steps 5 --dry-run
```
