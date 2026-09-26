# NEXUS — BUILD OUTCOME RECORD

**Status:** SPEC → BUILD COMPLETE · **Framework version:** 2.0.0 "Apex" · **Closed:** 2026-09-26
**Companion to:** NEXUS_BUILD_SPEC.md, NEXUS_AGENT_BRIEF.md, NEXUS_SECURITY_BOUNDARY.md, NEXUS_HANDOFF_SUMMARY.md

This file records what was actually built against the four planning documents
above — what shipped, what changed, what was added beyond spec, and what was
intentionally left out. It closes the loop the handoff summary opened.

---

## 1. Spec compliance (the 82 locked features)

- **74 delivered as specified** (see `docs/FEATURE_MAP.md` for the per-feature map).
- **5 partial → completed in later waves:** IDOR detection (now an active read-only
  prober), business-logic detection, methodology drift alerts (now dispatched to
  Discord/Telegram), GitHub hunting (dorking + token auth), screenshots (gowitness
  backend, optional).
- **Phase 6 SCALE:** scaffold per spec → upgraded to a **functional local**
  master/worker coordinator with a real task queue and thread pool. Multi-host
  (SSH/Redis) dispatch intentionally raises `NotImplementedError` (needs live infra).
- **Security boundary:** enforced in code, not docs — scope gate, payload guard,
  DB no-delete layer, proof-only output sanitizer, heavy-tool gating. Verified by
  1,700+ seeded property/fuzz assertions.

## 2. Versions shipped (all 2026-09-26)

| Version | Codename | Scope |
|---|---|---|
| 1.0.0 | Genesis | Full spec: 6 phases, 82 features, 183 offline tests |
| 1.1.0 | Horizon | Roadmap Wave 1: VERIFY phase, KEV+EPSS, agent loop, doctor, self-scan, delta, scope-sync, HTML export, C2 upgrades, Docker/CI/packaging (244 tests) |
| 1.2.0 | Ascend | Wave 2: IDOR/logic detection, OpenAPI, SARIF, Intigriti+YesWeHack, AI routing/budget/adversarial-FP, kill-switch, serve daemon, boundary fuzzing (264 tests) |
| 2.0.0 | Apex | Tractable completion: program monitor, GraphQL analysis, submission drafts, parallel tools, local SCALE, Ollama, GHSA, CPE matchers, golden-file tests (282 tests) |

## 3. Added beyond the four spec files (author-requested)

1. **Multi-engine dorking** — DuckDuckGo, Google, Bing, GitHub (token-authenticated
   code search via `GITHUB_TOKEN`), six intents, wired into DISCOVER + `nexus dork`.
2. **AI multi-key failover** — key pool per provider (slots + comma lists), auto
   rotation on empty/401/403/429, cross-provider fallback, masked status, 8
   providers (OpenAI, GLM, DeepSeek, Gemini, Kimi, OpenRouter, Ollama, custom).
3. **FP learning loop** — `nexus reject <id>` marks a false positive AND persists a
   learned auto-filter pattern (with backup) so repeat noise dies.
4. **Ops commands** — `doctor`, `self-scan` (secret scan, CI-gated), `retention`
   (report-only), `check-tools`, `ai-keys`/`ai-set-key`.
5. **Threat intel** — CISA KEV + EPSS + GHSA enrichment with priority ordering.
6. **Agent loop** — plan→act→observe over a whitelisted action map + `skills/`
   registry (recon, web_hunt, triage, report), AI planner with offline heuristics.
7. **Program monitor, drafts, GraphQL analysis, OpenAPI ingestion, SARIF/HTML
   export, parallel tools, kill-switch/request budget, digest alerts, serve daemon.**

## 4. Deviations & decisions

Full log in `BUILD_DECISIONS.md`. Highlights:

- Built in the authoritative repo workspace (spec's `/mnt/user-data/...` path was
  from the planning environment).
- 8th DB table `cves` added (spec said 8, listed 7).
- `payload_guard.py` implements the boundary doc's "payload_builder" role
  (validates rather than builds).
- **Data-retention pruning re-scoped to report-only** after the platform safety
  guard denied `shutil.rmtree` — NEXUS never deletes operator data by design.
- Scheduling never touches OS cron; `serve`/`hunt-schedule` are invoked by the
  operator's scheduler.

## 5. Explicitly not built (needs live infra/credentials)

Multi-host SCALE dispatch · cloud-posture depth (cloud creds) · Semgrep
source-assist · mobile/APK · signed releases · VCR/mutation test rigs · live bot
UI buttons · screenshot PII blur · commercial exploit/zero-day feeds ·
supply-chain recon. Each is tracked in `docs/ROADMAP.md`.

## 6. Verification evidence

- 282 offline tests green on the repo (`python -m pytest tests -q`).
- CLI smoke: `--version`, `--help` (26 commands), `doctor`, `self-scan` (0 findings).
- Grep audits: no `shell=True`, no hardcoded secrets, destructive SQL only in the guard.
- GitHub Actions CI runs tests + secret scan on every push.

**Planning documents: CLOSED. Build record: CLOSED.**
