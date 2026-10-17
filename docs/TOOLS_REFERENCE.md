# Tools Reference

Two layers exist: **built-in Python capability** (ships with NEXUS) and **external security
binaries** (never bundled; used only when found on `PATH`). The registry of record is
`config/tools.yaml` (69 tool entries), loaded by `lib/tool_registry.py`.

## Built-in (no external binary needed)

| Capability | Location | Notes |
|---|---|---|
| Scope validation | `lib/scope_validator.py` | all traffic gated; private-IP rules |
| SSRF guard | `lib/ssrf_guard.py` | outbound HTTP protection incl. redirect chains |
| HTTP collection | `lib/http_collector.py` | bounded, rate-limited fetcher |
| Dorking | `phases/discover/dorker.py` | multi-engine; scraping engines off by default |
| Tech detection | `phases/discover/wappalyzer_wrapper.py` | Wappalyzer dataset |
| CVE workflow | `lib/cve_workflow.py`, `lib/cve_fetcher.py`, `lib/versioning.py` | KEV/EPSS, version-range matching |
| Verification | `lib/verifier.py`, `phases/verify/` | deterministic proof checks |
| FP filtering | `lib/false_positive_filter.py` | learns from `reject` |
| Chains | `lib/chainer.py` | vulnerability chain detection |
| Payload guard | `lib/payload_guard.py` | blocks destructive payloads |
| Sanitizer | `core/sanitizer.py` | secret redaction in evidence/reports |
| Export/import | `core/exporter.py`, `core/importer.py` | zip/7z/json/csv/html/sarif |
| Database | `core/database.py` | SQLite; `backup_to` / `restore_from` |
| GUI | `core/gui.py` | FastAPI, loopback-only, fails closed without credentials |
| MCP gateway | `lib/nemesis/mcp*.py` | gated Model Context Protocol transport |
| Tool adapters | `lib/adapters/` | scope-checked third-party tool integrations (ZAP, Burp Suite Professional, Caido; see [ADAPTERS.md](ADAPTERS.md)) |
| Doctor / self-scan | `lib/doctor.py`, `lib/self_scan.py` | diagnostics; committed-secret scan |

## External binaries (optional)

| Tool | Phase | Purpose | When missing |
|---|---|---|---|
| `subfinder`, `assetfinder` | discover | passive subdomain enumeration | skipped |
| `httpx` | discover | live-host probing | skipped |
| `bbot`, `meg` | discover | surface enumeration | skipped |
| `katana`, `gau`, `waybackurls` | discover | URL/archive discovery | skipped |
| `ffuf` | probe | directory/fuzzing | skipped |
| `nuclei` | probe | template scanning | skipped |
| `dalfox` | probe | XSS scanning | skipped |
| `sqlmap` | probe | SQLi (read-only PoC policy) | skipped |
| `arjun` | probe | hidden-parameter discovery | skipped |
| `gowitness` | screenshots | headless screenshots | skipped |

Check availability anytime:

```powershell
python -m nexus check-tools
```

Availability states used by the registry: `installed` (binary on PATH or builtin adapter),
`key-missing` (needs a provider key that is not set), `disabled` (config).

## Optional SDK-backed integrations

- **Cloud (AWS/Azure/GCP):** provider SDKs are optional; when absent, cloud checks report
  `skipped` per provider. When present, checks stay read-only with identity-first
  authorization and per-provider account allowlists (see [PHASES.md](PHASES.md)).
- **AI providers:** `openai`, `glm`, `deepseek`, `gemini`, `kimi`, `openrouter`, `custom`,
  `ollama` (keyless). Keys come from `config/.keys.env`; see [AI_AND_NEMESIS.md](AI_AND_NEMESIS.md).
- **C2 bots:** `discord.py` / `python-telegram-bot` extras (`pip install .[c2]`).

## Network/filesystem side effects

External tools run through `phases/probe/tool_runner.py` with per-tool timeouts, retry caps,
and evidence capture. NEXUS itself writes only to `results/`, `logs/`, `exports/`, and
`nexus.db` (all under the repository root).
