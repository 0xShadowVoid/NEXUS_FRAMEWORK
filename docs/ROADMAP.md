# NEXUS — Upgrade & Enhancement Roadmap

> **Status @ 2.0.0 “Apex”:** all tractable roadmap items across Waves 1–3 are shipped.
> What remains requires live infrastructure or credentials (multi-host SCALE dispatch,
> cloud-posture depth, mobile/APK, Semgrep, signed releases, VCR/mutation rigs, bot UI
> buttons, screenshot PII blur, commercial exploit feeds) — each is documented in
> FEATURE_MAP.md as the explicit not-built list.

Companion to `BUILD_DECISIONS.md` and `docs/FEATURE_MAP.md`.
Priorities: **P0** = do next (high impact, low/medium effort) · **P1** = next wave ·
**P2** = later / larger. Status: ✅ already shipped · ⚠️ partial · ⬜ not started.

---

## A. Detection quality (biggest bounty impact)

| # | Upgrade | Why | Effort | Pri |
|---|---|---|---|---|
| A1 | **VERIFY phase** — deterministic replay/confirmation before a finding is marked VALID (reflect-vs-execute check, DOM check via headless browser, control-request diff) | Cuts false positives more than any threshold tuning | M | P0 |
| A2 | **Multi-tool corroboration policy** — require ≥2 independent tools (or 1 tool + replay) for high confidence | Precision over recall on submissions | S | P0 |
| A3 | **Per-tool precision priors** learned from your accept/reject history (`reject` already learns patterns) | Tunes itself to your programs | M | P1 |
| A4 | **Stable finding fingerprints** across scans (fuzzy hash) → suppress known noise, track lifecycle | Less duplicate review work | S | P1 |
| A5 | **WAF/block-page detection** so "403 Access Denied" isn't counted as a bypass win | Kills a classic FP class | S | P1 |
| A6 | **Regression re-test** of prior findings each scan (fixed vs still-vulnerable) | Proves fixes, finds regressions | M | P2 |
| A7 | **Import triager verdicts** (H1/Bugcrowd) back into the FP learner | Learns from real dispositions | M | P2 |

## B. Intel & zero-day coverage

| # | Upgrade | Why | Effort | Pri |
|---|---|---|---|---|
| B1 | **CISA KEV feed** (free JSON) — alert when an exploited-in-the-wild CVE matches your stack | Highest-signal CVE feed | S | P0 |
| B2 | **EPSS scoring** (free API) — prioritise by exploitation probability, not just CVSS | Better triage order | S | P0 |
| B3 | **GitHub Security Advisories (GHSA)** feed — ecosystems (npm/pip/maven) many CVEs miss | Broader coverage | S | P1 |
| B4 | **Verified-exploit enrichment** (Exploit-DB / VulnCheck / Metasploit module presence) | Separates theoretical from weaponised | M | P1 |
| B5 | **Better auto-PoC templates** — derive version-range matchers from CPE, not just a marker | Higher-fidelity detection templates | M | P1 |
| B6 | **Zero-day watch** (vendor advisories, research feeds) + alerting | Beyond NVD's lag | L | P2 |
| B7 | **Tech-drift alerting** — new tech on a target triggers a CVE re-match (state already tracked) | Catches new exposure fast | S | P1 |

## C. Agentic / AI

| # | Upgrade | Why | Effort | Pri |
|---|---|---|---|---|
| C1 | **Agent loop** — plan → act → observe → report, driven by a skills registry (`skills/*.yaml`) | The "AI agent" vision | L | P0 |
| C2 | **Model routing** — cheap model bulk-triages, strong model reasons over chains + writes reports | Cost vs quality | M | P1 |
| C3 | **Adversarial AI check** — AI tries to *disprove* each P1/P2 before submission | FP reduction | S | P1 |
| C4 | **AI report narratives** — exec summary + repro steps auto-drafted per platform | Saves write-up time | M | P1 |
| C5 | **Local model support** (Ollama/llama.cpp, OpenAI-compatible) | Zero-cloud / offline option | M | P2 |
| C6 | **Cost + token budget guardrails** per scan; prompt caching | Keeps AI cheap | S | P2 |
| C7 | **`nexus ai-suggest`** — feed scan metrics to AI for upgrade ideas (your item 3) | Self-improvement loop | S | P2 |
| C8 | **AI-generated methodology checklists** tailored to the detected stack | Smarter walkthroughs | M | P2 |

## D. Orchestration & delivery

| # | Upgrade | Why | Effort | Pri |
|---|---|---|---|---|
| D1 | **Dockerfile + compose** (framework + tool image) | One-command VPS deploy | M | P0 |
| D2 | **GitHub Actions**: tests + ruff + mypy on push | Keeps the repo honest | S | P0 |
| D3 | **`pyproject.toml` + `nexus` console script** → `pipx install` | Real install UX | S | P1 |
| D4 | **Parallel tool execution** inside a phase + adaptive throttling | Faster scans | M | P1 |
| D5 | **`nexus doctor`** — validate env, deps, config, permissions, tool availability | Cuts setup pain | S | P1 |
| D6 | **Delta scanning** — only scan new/changed subdomains & URLs since last run | Big time saver | M | P1 |
| D7 | **Service mode** — long-running scheduler daemon (queue + timers) vs cron-invoked | Real scheduling | L | P2 |
| D8 | **Phase 6 SCALE** — distributed master/worker (SSH or Redis queue) + aggregation | Parallel VPS scanning | L | P2 |
| D9 | **Tool health tracking + circuit breaker** (auto-disable a flaky tool) | Robustness | S | P2 |

## E. Platform integration

| # | Upgrade | Why | Effort | Pri |
|---|---|---|---|---|
| E1 | **Scope auto-sync** — pull each program's published in/out-of-scope, populate config automatically | Removes manual scope typing + scope mistakes | M | P0 |
| E2 | **More platforms** — Intigriti API, YesWeHack, Synack, Immunefi, OpenBugBounty | Broader hunting | M | P1 |
| E3 | **Program monitor** — alert on scope changes / new assets / payout changes | Early on new surface | M | P1 |
| E4 | **Report status tracking** — link findings ↔ submitted reports, import triage states | Closure visibility | M | P2 |
| E5 | **Submission drafts** (never auto-submit) in each platform's exact format | Faster, safer submits | M | P1 |

## F. Reporting & knowledge

| # | Upgrade | Why | Effort | Pri |
|---|---|---|---|---|
| F1 | **HTML + PDF export** of findings (report already Markdown) | Shareable deliverables | M | P1 |
| F2 | **SARIF export** | CI/code-scan integration | S | P2 |
| F3 | **Raw HTTP request + cURL repro** captured per finding automatically | Triagers accept faster | S | P1 |
| F4 | **Screenshot redaction** (blur PII) before attaching | Boundary + professionalism | M | P2 |
| F5 | **Target knowledge base** — tech timeline, past findings, remediation state | Continuity across scans | M | P2 |
| F6 | **Report diffing** across scans | See what changed | S | P2 |

## G. Control plane (Discord/Telegram)

| # | Upgrade | Why | Effort | Pri |
|---|---|---|---|---|
| G1 | **Target + schedule management via bot** (add/list/remove, enable/disable) | Your item 6 | M | P0 |
| G2 | **Command audit log + confirmation step** for destructive ops | Safety | S | P0 |
| G3 | **Slash commands / inline buttons**; Telegram keyboards | Better UX | M | P1 |
| G4 | **Digest mode** — periodic summary instead of per-finding pings | Less noise | S | P1 |
| G5 | **Alert auto-routing** — methodology drift + tech drift + scan failures through the bot (drift detection exists, dispatch pending) | Your item 2 | S | P0 |

## H. Security hardening (self + operational)

| # | Upgrade | Why | Effort | Pri |
|---|---|---|---|---|
| H1 | **Pre-commit secret scan** (gitleaks/trufflehog) on the framework repo itself | Never leak `.keys.env` | S | P0 |
| H2 | **Global kill-switch + request budget caps + per-host rate limits** | Operational safety | S | P1 |
| H3 | **Fuzz the security boundary** — property-based tests (hypothesis) on scope + payload guard | Prove the guards hold | M | P1 |
| H4 | **Audit log of blocked payloads/commands** | Accountability | S | P1 |
| H5 | **Data retention policy** — auto-purge raw responses after N days | Minimises stored target data | S | P1 |
| H6 | **Signed releases / checksum manifest** for exports | Integrity | S | P2 |

## I. Quality engineering

| # | Upgrade | Why | Effort | Pri |
|---|---|---|---|---|
| I1 | **Coverage gate** (pytest-cov threshold) in CI | Prevents regressions | S | P1 |
| I2 | **Type check + lint** (mypy/pyright + ruff) in CI | Fewer bugs | S | P1 |
| I3 | **Golden-file parser tests** with real tool outputs (nuclei/dalfox/sqlmap/httpx) | Parser robustness | M | P1 |
| I4 | **Contract tests with recorded fixtures** (VCR) for NVD/H1/Bugcrowd/chat APIs | Safe refactors | M | P2 |
| I5 | **Mutation testing** on security-critical modules | Boundary assurance | M | P2 |

## J. Known feature gaps (from FEATURE_MAP)

| # | Upgrade | Status | Pri |
|---|---|---|---|
| J1 | Active **IDOR prober** (two-account differential, safe) | ⚠️ heuristic only | P1 |
| J2 | **Business-logic detector** (price/role/quantity manipulation, safe probes) | ⚠️ heuristic only | P1 |
| J3 | **Methodology drift alert dispatch** through notifications | ⚠️ detection only | P0 |
| J4 | **Full GitHub bug-hunt agent** (dork → validate → report) | ⚠️ dork intent only | P1 |
| J5 | **Screenshot backend** independent of gowitness (Playwright) | ⚠️ optional dep | P2 |

## K. Domain expansion

| # | Upgrade | Why | Effort | Pri |
|---|---|---|---|---|
| K1 | **OpenAPI/Swagger ingestion** → auto endpoint tests (schemathesis-style) | API programs are the modern bulk | M | P1 |
| K2 | **GraphQL schema-first fuzzing** (introspection → deep query abuse) | High-value class | M | P1 |
| K3 | **Cloud posture depth** (ScoutSuite/Prowler profiles, IAM privesc paths) | Cloud programs | M | P2 |
| K4 | **Source-assisted hunting** (Semgrep rules mapped to runtime findings, in-scope only) | Finds what scanners miss | L | P2 |
| K5 | **Supply-chain recon** (dependency confusion, typosquat detection for target packages) | Emerging payout area | M | P2 |
| K6 | **Mobile/API artifacts** (APK/IPA static recon) | Widens scope | L | P2 |

---

## Recommended sequence

**Wave 1 (P0):** A1 verify phase · A2 corroboration · B1 KEV · B2 EPSS · C1 agent loop ·
D1 Docker · D2 CI · E1 scope auto-sync · G1/G2/G5 bot control + drift dispatch · H1 secret scan · J3.

**Wave 2 (P1):** D3–D6, E2/E3/E5, F1/F3, G3/G4, H2–H5, I1–I3, J1/J2/J4, K1/K2, A3–A5, C2–C4.

**Wave 3 (P2):** everything else, plus Phase 6 SCALE (D8).

> Rule of thumb: **A1 (verify) + B1/B2 (KEV/EPSS) + E1 (scope sync)** give the
> largest gain per hour spent; **C1 (agent loop)** is the largest project.
