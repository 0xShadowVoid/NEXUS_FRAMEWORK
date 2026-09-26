# NEXUS — Examples & Workflows

Practical, copy-paste workflows for real bug bounty use. Every command
assumes you are in the repo root and have authorization for the target.

---

## Workflow 1: First scan of a program (the daily driver)

```powershell
# 1. Import the program's published scope (no manual typos)
python nexus.py scope-sync --domain acme.com --file acme_h1_scope.json --platform hackerone --dry-run
python nexus.py scope-sync --domain acme.com --file acme_h1_scope.json --platform hackerone

# 2. Verify your environment
python nexus.py doctor

# 3. Quick scan (light, safe default)
python nexus.py hunt acme.com

# 4. Found something interesting? Go deeper — full tool set
python nexus.py hunt acme.com --full-scan --screenshots
```

Where results land (`results/<target>-<platform>-<type>-<scope>-<date>-<time>/`):

| Path | Contents |
|---|---|
| `recon/` | domains.txt, urls, tech_stack.json, dorking.json |
| `scans/` | raw tool outputs + raw_findings.json |
| `processed/` | findings.json, chains.json, high_value_findings.json, metrics.json |
| `reports/` | findings.md + `drafts/` (per-finding submission drafts) |

---

## Workflow 2: Bug-hunting session (finding real bugs)

```powershell
# Recon only, with dorking across all 4 engines
python nexus.py hunt acme.com --discover-only

# Check what the dorker found (exposed docs, backups, GitHub leaks)
type results\<latest>\recon\dorking.json

# Hunt specific CVEs on the detected stack
python nexus.py cve-scan acme.com --critical

# Target only the interesting endpoints with heavy tools (explicit choice)
python nexus.py hunt acme.com --full-scan --run-tools "nuclei,dalfox" --min-severity P3

# Verify a finding before reporting (deterministic confirmation)
python nexus.py verify 42

# Reject noise — AND teach the filter to skip it next time
python nexus.py reject 43

# Render a platform-ready draft
python nexus.py draft 42 --platform hackerone --target acme.com
```

---

## Workflow 3: Continuous monitoring (VPS autopilot)

```powershell
# Nightly full scan
python nexus.py hunt-schedule --daily acme.com --name acme_nightly

# CVE watch rides along (KEV/EPSS prioritized alerts)
python nexus.py cve-update --target acme.com

# Run the scheduler daemon (or wire `hunt-schedule` to cron/Task Scheduler)
python nexus.py serve            # Ctrl+C to stop
python nexus.py serve --once     # single pass, script-friendly

# Watch for NEW programs → first blood
python nexus.py hunt-new --enable
python nexus.py monitor          # diff programs vs last snapshot
```

Control from your phone (Discord/Telegram, owner-only):

```
/nexus status
/nexus hunt acme.com
/nexus logs 30
/nexus report
/nexus add-target globex.com
/nexus remove-target globex.com confirm
/nexus cve-update
```

---

## Workflow 4: AI-powered triage

```powershell
# Add keys (multi-key failover: dead key → next key → next provider)
python nexus.py ai-set-key --provider glm --key <key1>
python nexus.py ai-set-key --provider glm --key <key2>
python nexus.py ai-keys          # masked status

# Agent one-liners (plans → acts → observes, whitelisted actions)
python nexus.py agent "recon acme.com" --dry-run
python nexus.py agent "scan acme.com for xss and cve"
```

AI is optional: with no keys, the agent uses deterministic heuristics and
every scan phase works unchanged.

---

## Workflow 5: Reporting & portability

```powershell
python nexus.py export acme.com --format html     # shareable report
python nexus.py export acme.com --format sarif    # CI/code-scanning
python nexus.py export acme.com --format zip      # full archive
python nexus.py import acme-export.zip --merge    # restore/merge
python nexus.py diff 3 4                          # scan-vs-scan comparison
```

---

## Recipes (quick copy)

| Goal | Command |
|---|---|
| Subdomains only | `nexus hunt acme.com --discover-only --with-subdomains` |
| Only new URLs since last run | `nexus hunt acme.com --delta` |
| Faster scans (parallel light tools) | `nexus hunt acme.com --parallel 4` |
| Skip aggressive scanners | `nexus hunt acme.com --skip-tools sqlmap,commix` |
| Authenticated scanning | `nexus hunt acme.com --cookie "session=abc"` |
| Custom rate limit | `nexus hunt acme.com --rate-limit "30/minute"` |
| Dork a target directly | `nexus dork acme.com --engines duckduckgo,github` |
| GraphQL introspection check | `nexus graphql --file introspection.json` |
| OpenAPI → endpoints | `nexus openapi --file swagger.json --base https://api.acme.com` |
| Old results audit | `nexus retention --days 30` (report-only, never deletes) |
| Emergency stop | create `results/.nexus_killswitch` file (blocks new scans) |
| Repo hygiene | `nexus self-scan` (committed-secret check) |

---

## Severity & triage model (what the pipeline does for you)

```
raw tool output
  → dedup (fuzzy merge; multi-tool = confidence boost)
  → VERIFY (deterministic: encoded reflection disproved; ≥2 tools = corroborated)
  → severity (impact-based P1–P4 + context upgrades)
  → FP filter (per-type strictness + your learned patterns)
  → scope filter (OOS blocked from submission)
  → chains (stored XSS→RCE, IDOR→ATO, SQLi→DB, SSRF→internal, redirect→token)
  → alerts (P1/P2 to Discord/Telegram) + drafts + metrics
```

## Safety model (always on)

- Scope gate before any traffic; OOS findings never submitted.
- Payload guard blocks destructive SQL / shells / implants before execution.
- Heavy tools (sqlmap/commix) only on 200-auth or 401/403 candidates.
- Reports sanitized to proof-only evidence (cookies/tokens/PII stripped).
- Kill-switch + request budget for operational control.

**Reminder:** NEXUS proves vulnerabilities exist (detection + PoC). It never
extracts data, modifies targets, or persists access. Authorization is your
responsibility — the scope gate helps, but the program's rules are the law.
