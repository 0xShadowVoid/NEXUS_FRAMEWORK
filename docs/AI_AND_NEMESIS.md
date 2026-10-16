# AI and NEMESIS

NEMESIS is the optional reasoning layer on top of NEXUS. NEXUS executes; NEMESIS helps you
think: triage, threat-intel correlation, agent loops over whitelisted skills/actions.

## Providers

Configured in `config/nexus.yaml` (`ai:`) with keys in `config/.keys.env`:

| Provider | Key variable | Integration | Multi-key | Reasoning effort |
|---|---|---|---|---|
| `openai` | `OPENAI_API_KEY` | OpenAI-compatible HTTP | yes | yes |
| `glm` | `GLM_API_KEY` | OpenAI-compatible HTTP | yes | no |
| `deepseek` | `DEEPSEEK_API_KEY` | OpenAI-compatible HTTP | yes | no |
| `gemini` | `GEMINI_API_KEY` | OpenAI-compatible HTTP | yes | no |
| `kimi` | `KIMI_API_KEY` | OpenAI-compatible HTTP | yes | no |
| `openrouter` | `OPENROUTER_API_KEY` | OpenAI-compatible HTTP | yes | yes |
| `custom` | `CUSTOM_API_KEY` + `CUSTOM_BASE_URL` | OpenAI-compatible HTTP | yes | no |
| `ollama` | — | OpenAI-compatible HTTP (local) | n/a | no |
| `opencode` | — | local CLI | — | — |
| `cline` | — | IDE extension | — | — |

**Verified support.** Only the OpenAI-compatible HTTP providers ship a working adapter
(`lib/ai_analyzer.py`). `opencode` and `cline` are listed for completeness but have **no
verified programmatic integration** — see "OpenCode and Cline" below. Configure them and NEXUS
**rejects the configuration at startup** rather than pretending to work. Run
`python -m nexus ai-providers` to see the current capability matrix.

### Multiple keys & rotation

Several keys per provider form a pool:

```powershell
python -m nexus ai-set-key --provider gemini --key <KEY-1>
python -m nexus ai-set-key --provider gemini --key <KEY-2>   # → GEMINI_API_KEY_2
python -m nexus ai-keys                                       # masked status
```

`GEMINI_API_KEY`, `GEMINI_API_KEY_2` … `_10` (or comma-separated in slot 1) are all read. On
failure the next eligible key is tried; keys that are dead or cooling down are **never**
reselected.

### Failover policy (by error class)

Every HTTP status/exception is classified (`lib/ai_errors.py`) and handled specifically — NEXUS
never retries permanent errors blindly, and never rotates keys to evade a genuine quota or usage
restriction:

| Error class | Trigger | Action |
|---|---|---|
| invalid credentials | 401 | retire key, try next |
| rate limit | 429 | sideline key (exponential backoff), try next |
| quota exhausted | 402 / quota 429/403 | sideline key, **skip provider** for the run |
| outage | 5xx / connection error | bounded retry with backoff, then skip provider |
| timeout | read/connect timeout | bounded retry with backoff |
| unsupported model | 400/404 model errors | skip provider (no retry) |
| invalid request | 400 malformed | skip provider (no retry) |
| permission | 403 (no quota hint) | skip provider (no retry) |

`ai.max_retries` bounds same-provider retries; backoff is exponential (capped at 8s). Each
decision records the provider, model, error category and fallback outcome — **never** the
credential or prompt. When every provider fails, the call returns `None` and the deterministic
NEXUS workflow continues untouched.

### Per-agent model & effort (`nemesis.agents`)

Each agent can pin its provider, model, reasoning effort, timeout, retry limit, call budget and
ordered fallback chain. Configuration is validated at startup; unsupported model parameters
(for example `reasoning_effort` on Gemini/GLM) are rejected with a clear error. See
[CONFIGURATION.md](CONFIGURATION.md#nemesisagents-per-agent-ai) for the schema and
`python -m nexus agent "..." --agent default` to select one.

### OpenCode and Cline

- **OpenCode** is integrated through its own CLI and its own authentication. NEXUS does **not**
  assume OpenCode exposes raw API keys or a stable key-free programmatic chat interface, and no
  verified adapter ships. Select a model/agent from OpenCode itself.
- **Cline** is an IDE/VS Code extension. Free/entitled IDE model access is not exposed to
  external automation, and there is no documented key-free programmatic interface. It is **not
  supported**.

Both are represented in the provider registry (`lib/ai_providers.py`) so configuration using
them is rejected explicitly, and `lib.ai_providers.ProviderAdapter` documents the extension point
if a verified adapter becomes available. NEXUS will not reverse-engineer endpoints or bypass
access restrictions.

## Behavior without an AI provider

**Everything in NEXUS works without any AI key.** AI absence means: no triage suggestions, no
AI-assisted summaries, no NEMESIS agent loops. Scans, verification, exports, GUI, network and
cloud phases are fully deterministic and unaffected. `ai.provider: none` is not a special
mode — simply having no keys has the same effect. A failed AI request never breaks a phase:
agent planning falls back to deterministic heuristics.

## NEMESIS components

| Component | Config | Default |
|---|---|---|
| Engagement memory (local SQLite) | `nemesis.memory.enabled` | on |
| Skills (methodology playbooks) | `nemesis.skills.enabled: []` | none active — see [SKILLS_REFERENCE.md](SKILLS_REFERENCE.md) |
| Browser automation (Playwright) | `nemesis.browser.enabled` | off |
| MCP transport | `nemesis.mcp.enabled` | off |

## Security and privacy

- NEMESIS can **suggest**; it can never **validate** — finding promotion requires the
  deterministic verifier (enforced in `core/lifecycle.py`).
- Agent actions (`python -m nexus agent ...`) run over a whitelist
  (`scan`, `discover`, `dork`, `cve-update`, `status`, `report`) — no arbitrary execution.
- Outbound AI traffic goes through the SSRF guard with provider-host allowlisting.
- **API keys** are never hardcoded or committed; they live in the git-ignored
  `config/.keys.env`, are read only through `lib/key_pool.py`, and are masked in every log,
  `repr`, `ai-keys` and error message. `python -m nexus self-scan` checks for committed secrets.
- **No transmission without the AI workflow authorizing it.** Scan data reaches a provider only
  when the configured AI/agent workflow explicitly makes a call; with no keys (or `ai.enabled:
  false`) nothing is transmitted. Prompts are trimmed (response snippets ≤ 500 chars) and route
  through the same code path that excludes credentials, session cookies and bulk evidence.
- **Provider responses are untrusted input.** Replies are parsed defensively as JSON and never
  executed or used to promote findings; determinism and the finding lifecycle remain the source
  of truth.
- Rotating keys is limited to genuine failover — dead keys are retired and rate-limited/quota
  keys sidelined, but NEXUS never rotates keys to circumvent a provider's terms or quotas.

## Quick start

```powershell
python -m nexus ai-set-key --provider deepseek --key <YOUR-KEY>
python -m nexus ai-set-key --provider gemini   --key <YOUR-KEY>   # rotate across keys
python -m nexus ai-keys
# then, for example:
python -m nexus agent "triage latest findings for lab.local" --max-steps 5 --dry-run
python -m nexus ai-providers     # capabilities + verified support
```
