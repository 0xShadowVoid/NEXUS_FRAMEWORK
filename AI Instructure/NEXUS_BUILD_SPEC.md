# NEXUS FRAMEWORK — COMPLETE BUILD SPECIFICATION

**Framework Name:** NEXUS (Unified Bug Bounty Automation Framework)  
**Repository:** nexus-framework  
**Language:** Python 3.11+  
**License:** Custom permission-based ("No AI tools used/read/learned from this code")  
**OS Support:** Windows, WSL, Linux, VPS, Kali, Parrot  
**Author Build:** Mohamed (0xShadowVoid)  
**Build Status:** READY TO BUILD  
**Feature Count:** 82 total (70 core + 12 enhancements)

---

## PART 1: CORE IDENTITY & SCOPE

### Purpose
Consolidates 4 existing repos (BBWorkspace, Bug-Hunt-Automation-Scripts, Recon-Ranger, ShadowWalker) into one elite bug bounty automation framework.

### Scope
- **Detection + PoC ONLY** (no data read/write/delete beyond proof)
- Legally authorized bug bounty hunting only
- In-scope enforcement (blocks out-of-scope submissions)
- Multi-phase automation (DISCOVER → PROBE → ANALYZE → HUNT → CONTROL → SCALE)
- Platform support: HackerOne, Bugcrowd, Intigriti, YesWeHack, Synack, VDP programs

### Not In Scope
- RCE shells / backdoors / persistence
- Data exfiltration beyond PoC
- Modifying/deleting target data
- Unauthorized access

---

## PART 2: 6-PHASE ARCHITECTURE

### Phase 1: DISCOVER (Recon)
**Purpose:** Find targets, endpoints, tech stack  
**Tools:** Pegpon (15 light tools), BBot (100+ modules for deep), 14 additional tools

**Pegpon (Light, always runs):**
- subfinder, assetfinder, httpx, ffuf, katana, waybackurls, gau, findomain
- chaos, github-subdomains, dnsx, nuclei (light), jsluice, crt.sh, securitytrails

**BBot (Deep only, --full-scan):**
- 100+ modules: paramminer, nuclei, gowitness, portscan, dnsbrute, wafw00f, trufflehog, gitdumper, graphql_introspection, waf_bypass, bypass403, lightfuzz, hunt, 80+ passive

**14 Additional Tools:**
- Recon: cewl, shuffledns, metabigor, github-recon, reverse-whois
- Scanning: ghauri, jwt-tool, lfihunt, graphql-cop, waf-probe, nomore403
- Other: linkfinder, trufflehog, arjun (light scan only)

**Wappalyzer:** Tech detection (WordPress, Apache, Java, etc.)  
**Meg:** HTTP header analysis

**Output:** domains.txt, endpoints.json, tech_stack.json, urls_wayback.txt

---

### Phase 2: PROBE (Scanning)
**Purpose:** Test endpoints for vulnerabilities

**Smart Tool Selection:**
- Wappalyzer detects tech → Nuclei loads ONLY matching templates
- Example: WordPress 6.0 → Load only wordpress/ templates, skip java/, asp/

**Primary Tools:**
- **nuclei** (smart: tech-matched templates only)
- **dalfox** (XSS detection)
- **sqlmap** (light: risk=1, level=1 by default)
- **commix** (command injection)
- **ghauri** (blind SQLi)
- **nomore403 / 403bypasser** (bypass)
- **jwt-tool** (JWT analysis)
- **lfihunt** (local file inclusion)
- **graphql-cop** (GraphQL vulnerabilities)
- **waf-probe** (WAF detection)
- **cloudenum, s3scanner, prowler** (cloud scanning)

**Scanning Rules:**
- Light scan (default): Arjun, nuclei (light templates), dalfox only
- Deep scan (--full-scan): All tools + heavy scanners (sqlmap, commix)
- Heavy tools (sqlmap, commix) run ONLY on:
  - 200 endpoints with auth keywords
  - 401/403 bypass candidates
  - User-explicitly-chosen endpoints

**Tool Timeout:** Per-tool configurable, global default 300s  
**Tool Failure Handling:**
- Light scan: Skip + continue (C)
- Deep scan: Retry 3× → skip (B)

**Scan Resume:** Exact checkpoint (A) - resume from exact progress point

**Dependencies:**
- Scanning needs recon URLs: Auto-run missing recon (B)
- BBot requires pegpon: Auto-run if missing

**Output:** raw_findings.json, nuclei_results.yaml, dalfox_results.json, sqlmap_results.txt

---

### Phase 3: ANALYZE (Processing)
**Purpose:** Dedup, severity scoring, chain detection

**Deduplication:** Fuzzy match findings across tools  
- Same endpoint found by nuclei + dalfax → Merge, show both tools
- Confidence boosted (multiple tools = higher confidence)

**Severity Scoring:** Impact-based
- RCE > SQLi > XSS > IDOR > Info Disclosure
- Confidence threshold applied per finding type

**Chain Detection:** Dependency graphs
- XSS + stored → RCE
- IDOR + write permission → Account takeover
- SQLi + auth bypass → Full DB access

**False Positive Filtering:**
- Per-type strictness (XSS aggressive, SQLi conservative, IDOR conservative)
- User configurable: aggressive/conservative/custom
- Confidence threshold per finding type (XSS 90%, SQLi 70%, IDOR 85%)

**Output:** findings.json, chains.json, high_value_findings.json, metrics.json

---

### Phase 4: HUNT (First-Blood Auto-Scan)
**Purpose:** Automatically scan new programs for first-blood findings

**Status:** OFF by default  
**Enable:** `nexus hunt-new --enable` or config  
**Behavior:**
- Fetches new programs from H1/Bugcrowd APIs
- Runs quick-scan by default
- Filters: BB (paid bounty) prioritized, VDP (light scan)
- Max 5 scans/day (configurable)
- Alerts on P1/P2 findings

**Output:** auto_scan_results.json, first_blood_alerts.md

---

### Phase 5: CONTROL (C2 Bot)
**Purpose:** Remote command execution via Discord/Telegram

**Bot Commands:**
- `/nexus hunt target.com` — Start scan
- `/nexus stop` — Stop current scan
- `/nexus logs` — Show latest logs
- `/nexus report` — Get findings report
- `/nexus status` — Show running scans
- `/nexus cve-update` — Manual CVE update

**Execution:**
- SSHes to VPS
- Executes nexus commands
- Returns results to Discord/Telegram
- Private channel only (Mohamed only)

**Config:**
```yaml
c2_bot:
  enabled: true
  use_same_webhook: true  # Use existing or new bot
  channels: [discord, telegram]
```

---

### Phase 6: SCALE (Microservices)
**Purpose:** Parallel VPS-based scanning

**Status:** Scaffold only (no code yet)  
**Concept:**
- Master VPS coordinates
- Worker VPS instances scan in parallel
- Queue-based task distribution
- Aggregate results

**Future:** Build on approval

---

## PART 3: CLI INTERFACE & FLAGS

### Main Commands

```bash
nexus hunt <target> [flags]                    # Scan single target
nexus batch <file> [flags]                     # Batch scan from file
nexus hunt-schedule [schedule-name]             # Run scheduled scan
nexus hunt-schedule --list                      # List all schedules
nexus hunt-schedule --cron "0 2 * * *" target  # Create cron schedule
nexus hunt-schedule --daily target              # Named frequency
nexus hunt-schedule --weekly target             # Weekly scan
nexus hunt-schedule --every-6h target           # Every 6 hours

nexus export [target] [flags]                  # Export findings
nexus import <file> [flags]                    # Import/restore findings
nexus diff <scan1> <scan2>                     # Compare two scans
nexus update                                    # Update framework
nexus tools-update                              # Update all tools
nexus update --all                              # Framework + tools
nexus cve-update                                # Manual CVE update
nexus cve-scan <target> [flags]                # Scan target for known CVEs
nexus verify <finding_id>                      # Manual verification before report
```

### Intensity Flags

```bash
--quick-scan              # Light scan (default)
--full-scan               # Deep scan (all tools)
--discover-only           # Recon phase only
--scan-only               # Skip recon, use cached
--with-subdomains         # Include subdomain scans
--include-cdn             # Include CDN targets
--test-bypass             # 401/403/404 fuzzing + bypass
--custom-fuzzing          # Custom payloads + wordlists
--hunt-new                # Phase 4 (auto-hunt new programs)
```

### Tool Control Flags

```bash
--skip-tools nuclei,dalfox           # Disable specific tools
--run-tools nuclei,dalfax,sqlmap     # Run ONLY these tools
--run-tools "nuclei --severity high" # Pass tool-specific flags
```

### Config & Data Flags

```bash
--methodology web_app_checklist      # Use specific methodology
--target-config paypal.yaml          # Target-specific override
--cookie "session=abc; user_id=456"  # Auth cookies for deeper testing
--exclude-p4                         # Don't report P4 findings
--exclude "P3,P4"                    # Skip multiple severities
--min-severity P2                    # Only P1 + P2
--rate-limit "50/minute"             # Custom rate limiting
```

### Export/Import Flags

```bash
--format zip                         # ZIP archive (default)
--format 7z                          # 7Z compression
--format json                        # JSON only
--format csv                         # CSV only
--date "2026-09-21"                 # Export specific date
--merge                              # Merge with existing (import)
```

### Other Flags

```bash
--concurrent 2                       # Parallel batch scans
--sequential                         # Run one-by-one (batch)
--screenshots                        # Capture screenshots
--cve-2026-09999                    # Scan for specific CVE
--critical                           # Only critical CVEs
```

---

## PART 4: CONFIGURATION FILES

### nexus.yaml — Main Configuration

```yaml
# Scanning
scanning:
  default_intensity: quick-scan
  tool_timeout_seconds: 300
  rate_limit_default: "50/minute"
  
# Phases
phases:
  discover:
    enabled: true
    tools: [pegpon, bbot, meg, wappalyzer]
    
  probe:
    enabled: true
    default_tools: [nuclei, dalfax]
    
  hunt:
    enabled: false                    # OFF by default
    intensity: quick-scan
    max_scans_per_day: 5
    alert_on: [P1, P2]
    vdp_strategy: light_scan
    bb_strategy: quick-scan
    
# Targets with overrides
targets:
  paypal.com:
    intensity: full-scan
    tools: [nuclei, dalfax, sqlmap]
    rate_limit: "50/minute"
    
  startup.com:
    intensity: quick-scan
    tools: [nuclei, dalfax]
    rate_limit: "100/minute"

# Schedules
schedules:
  paypal_daily:
    target: paypal.com
    frequency: daily
    time: "02:00"
    intensity: full-scan

# Webhooks
webhooks:
  discord:
    findings: ${DISCORD_FINDINGS_WEBHOOK}
    cve: ${DISCORD_CVE_WEBHOOK}
    metrics: ${DISCORD_METRICS_WEBHOOK}
    
  telegram:
    bot_token: ${TELEGRAM_BOT_TOKEN}
    chat_id: ${TELEGRAM_CHAT_ID}

# CVE tracking
cve:
  auto_update: true
  frequency: daily
  time: "02:00"
  alert_severity: [critical, high]
  script_delivery: [email, discord]

# C2 Bot
c2_bot:
  enabled: true
  channels: [discord, telegram]
```

### false_positive_filters.yaml — Finding Validation

```yaml
filters:
  xss:
    strictness: aggressive
    confidence_threshold: 90
    auto_filter:
      - "HTML entity &lt;script&gt;"
      - "Displayed as plain text"
    
  sqli:
    strictness: conservative
    confidence_threshold: 70
    auto_filter:
      - "UNION without data extraction"
    
  idor:
    strictness: conservative
    confidence_threshold: 85
```

### .keys.env — API Keys & Webhooks
(See .keys.env.example for complete list)

---

## PART 5: DATA STRUCTURES

### Directory Structure

```
nexus-framework/
├── config/
│   ├── nexus.yaml
│   ├── false_positive_filters.yaml
│   ├── .keys.env (git-ignored)
│   └── .keys.env.example
│
├── phases/
│   ├── discover/
│   │   ├── pegpon_wrapper.py
│   │   ├── bbot_wrapper.py
│   │   └── wappalyzer_wrapper.py
│   │
│   ├── probe/
│   │   ├── nuclei_orchestrator.py
│   │   ├── dalfox_runner.py
│   │   ├── sqlmap_runner.py
│   │   └── tool_runners.py
│   │
│   ├── analyze/
│   │   ├── deduplicator.py
│   │   ├── severity_scorer.py
│   │   └── chain_detector.py
│   │
│   ├── hunt/
│   │   ├── auto_hunter.py
│   │   └── api_fetcher.py
│   │
│   ├── control/
│   │   ├── discord_c2.py
│   │   └── telegram_c2.py
│   │
│   └── scale/
│       ├── master_coordinator.py
│       └── worker_manager.py
│
├── results/
│   └── {target}-{platform}-{type}-{scope}-{date}-{time}/
│       ├── findings.md
│       ├── metrics.json
│       ├── recon/
│       ├── scans/
│       ├── processed/
│       ├── reports/
│       └── screenshots/
│
├── wordlists/
│   ├── seclists/ (auto-downloaded)
│   └── custom/
│
├── payloads/
│   ├── xss/, sqli/, ssti/, custom/
│   └── (organized by vulnerability type)
│
├── templates/
│   ├── nuclei-custom/
│   └── reports/ (platform-specific)
│
├── core/
│   ├── coordinator.py (main orchestrator)
│   ├── analyzer.py
│   ├── reporter.py
│   └── database.py
│
├── lib/
│   ├── config.py
│   ├── logger.py
│   ├── notifications.py
│   ├── rate_limiter.py
│   ├── deduplicator.py
│   ├── chainer.py
│   ├── status_detector.py
│   ├── ai_analyzer.py
│   └── scope_validator.py
│
├── scripts/
│   └── cve_pocs/
│       └── cve-xxxx-xxxxx/
│           ├── cve-xxxx-xxxxx.py
│           ├── cve-xxxx-xxxxx.js
│           ├── cve-xxxx-xxxxx.sh
│           └── cve-xxxx-xxxxx.yaml
│
├── nexus.py (CLI entry)
├── requirements.txt
├── LICENSE
└── README.md
```

### Database Schema (SQLite)

```sql
-- targets
CREATE TABLE targets (
  id INTEGER PRIMARY KEY,
  domain TEXT UNIQUE,
  platform TEXT,          -- hackerone, bugcrowd, etc.
  type TEXT,              -- bb, vdp, internal
  scope TEXT,             -- public, private, freelance, external
  in_scope TEXT,          -- JSON: ["paypal.com", "*.api.paypal.com"]
  out_of_scope TEXT,      -- JSON: ["blog.paypal.com"]
  config TEXT,            -- JSON: target-specific overrides
  created_at TIMESTAMP
);

-- scans
CREATE TABLE scans (
  id INTEGER PRIMARY KEY,
  target_id INTEGER,
  scan_date TIMESTAMP,
  intensity TEXT,         -- quick-scan, full-scan
  duration_seconds INTEGER,
  findings_total INTEGER,
  findings_valid INTEGER,
  findings_oos INTEGER,
  status TEXT,            -- completed, failed, interrupted
  checkpoint TEXT,        -- Phase:Step for resume
  created_at TIMESTAMP,
  FOREIGN KEY(target_id) REFERENCES targets(id)
);

-- findings
CREATE TABLE findings (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER,
  endpoint TEXT,
  vuln_type TEXT,         -- xss, sqli, idor, etc.
  severity TEXT,          -- P1, P2, P3, P4
  confidence INTEGER,     -- 0-100
  payload TEXT,
  response_snippet TEXT,
  tools_found TEXT,       -- JSON: ["nuclei", "dalfox"]
  in_scope INTEGER,       -- 1=yes, 0=no
  valid INTEGER,          -- 1=real, 0=false_positive, null=pending
  reviewed INTEGER,       -- 1=verified, 0=not reviewed
  created_at TIMESTAMP,
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

-- chains
CREATE TABLE chains (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER,
  finding_ids TEXT,       -- JSON: [1, 2, 3]
  chain_type TEXT,        -- xss_to_rce, idor_to_ata, etc.
  impact TEXT,            -- High, Critical
  steps TEXT,             -- JSON: chain steps
  created_at TIMESTAMP,
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);

-- schedules
CREATE TABLE schedules (
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE,
  target_id INTEGER,
  frequency TEXT,         -- daily, weekly, every-6h, custom
  cron_expression TEXT,
  intensity TEXT,
  enabled INTEGER,        -- 1=yes, 0=no
  last_run TIMESTAMP,
  next_run TIMESTAMP,
  created_at TIMESTAMP,
  FOREIGN KEY(target_id) REFERENCES targets(id)
);

-- high_value_alerts
CREATE TABLE high_value_alerts (
  id INTEGER PRIMARY KEY,
  finding_id INTEGER,
  alert_type TEXT,        -- critical_cve, p1_finding, first_blood
  sent_to TEXT,           -- JSON: ["discord", "telegram", "email"]
  created_at TIMESTAMP,
  FOREIGN KEY(finding_id) REFERENCES findings(id)
);

-- screenshots
CREATE TABLE screenshots (
  id INTEGER PRIMARY KEY,
  finding_id INTEGER,
  path TEXT,
  uploaded INTEGER,       -- 1=yes, 0=no
  created_at TIMESTAMP,
  FOREIGN KEY(finding_id) REFERENCES findings(id)
);
```

---

## PART 6: NAMING CONVENTIONS

### Scan Result Folders

```
Format: {domain}-{platform}-{type}-{scope}-{date}-{time}/

Examples:
  amazon-amazon-bb-public-2026-09-21-10-00/
  paypal-hackerone-bb-private-2026-09-21-14-30/
  startup-intigriti-vdp-public-2026-09-21-08-15/
  client-freelance-pentest-external-2026-09-21-16-45/
  company-internal-pentest-private-2026-09-21-12-00/

Scope Types:
  public     - Public bug bounty program
  private    - Invite-only program
  vdp        - Vulnerability disclosure (no bounty)
  freelance  - Contract-based hunting
  internship - Part of internship program
  fulltime   - Employment-based
  external   - CISO/external pentest
```

### Finding Reports

```
Format: {domain}-{platform}-{type}-{scope}-{date}-findings.md

Examples:
  amazon-amazon-bb-public-2026-09-21-findings.md
  paypal-hackerone-bb-private-2026-09-21-findings.md
```

### Screenshots

```
Format: {domain}-{date}-{time}-{type}-{id}.png

Examples:
  paypal-2026-09-21-10-30-finding-001.png
  paypal-2026-09-21-10-45-chain-001.png
  amazon-2026-09-21-14-20-finding-002.png
```

---

## PART 7: ALERT SYSTEM

### Alert Channels

**Discord:**
- Separate webhooks: findings, CVE, metrics
- Configurable per-channel
- Rich embeds: severity, endpoint, payload, proof

**Telegram:**
- Bot-based
- Formatted messages
- Finding details + screenshots (if enabled)

**Email:**
- SMTP (Gmail or custom)
- CVE scripts attached (.py, .js, .sh, .yaml)
- Summary reports
- Configurable recipients

### CVE Alert Workflow

```
1. Daily auto-update (2 AM)
2. NVD API fetch → New CVEs
3. Filter by severity (critical, high, medium)
4. Check against target tech stack
5. Generate POC scripts (.py, .js, .sh, .yaml)
6. Alert to Discord/Telegram/Email
7. Store in nexus/scripts/cve_pocs/
8. Register nuclei templates
9. Send scripts to email as attachments
```

---

## PART 8: SECURITY BOUNDARY

### ALLOWED (Detection + PoC)

```
✅ Enumerate (subdomains, endpoints, parameters)
✅ Scan (identify vulnerabilities)
✅ Fingerprint (detect tech, CVEs)
✅ Test (payload injection, bypass attempts)
✅ Prove (PoC: execute payload, capture response)
✅ Screenshot (evidence of vulnerability)
✅ Read response (analyze for vulnerability indicators)
✅ Send payloads (detect behavior changes)
```

### BLOCKED (No Harm)

```
❌ Read target data (no data extraction beyond PoC)
❌ Write files to target system
❌ Delete/modify target data
❌ Execute arbitrary commands (no RCE shells)
❌ Access internal systems beyond scope
❌ Persist backdoors/implants
❌ Exfiltrate sensitive data
❌ Create accounts/resources
❌ Modify application logic
```

### Enforcement

```
1. All tools run with minimal permissions
2. Payloads validated against scope
3. Out-of-scope findings blocked from submission
4. Data extraction capped at PoC level
5. Code review before script generation
6. No automated account creation/resource provisioning
```

---

## PART 9: 82 FEATURES (LOCKED)

### Core Features (70)

1. Multi-phase automation (DISCOVER → SCALE)
2. Pegpon (15 light tools)
3. BBot (100+ modules)
4. 14 additional tools
5. Wappalyzer tech detection
6. Smart nuclei template matching
7. Dalfox XSS detection
8. SQLmap (light mode)
9. Commix command injection
10. Ghauri blind SQLi
11. 401/403/404 fuzzing + bypass
12. JWT analysis
13. LFI detection
14. GraphQL scanning
15. WAF detection
16. Cloud scanning (S3, AWS, Azure)
17. Light vs deep scanning modes
18. Tool-specific timeout
19. Concurrent execution
20. Tool failure handling (mode-dependent)
21. Exact checkpoint resume
22. Auto-dependency detection
23. Tool skip/run-only flags
24. Deduplication (fuzzy match)
25. Severity scoring (impact-based)
26. Chain detection (dependency graphs)
27. False positive filtering (per-type strictness)
28. IDOR auto-detection
29. Business logic pattern detection
30. Database (SQLite)
31. Findings storage + querying
32. Screenshot capture (named)
33. API key management (.keys.env)
34. Platform API integration (H1/Bugcrowd)
35. Scope validation (in-scope/out-of-scope)
36. Wildcard target support
37. Single domain scanning
38. Multi-domain scanning
39. Cloud target support
40. Cookie injection (auth testing)
41. Rate limiting (per-target)
42. Config file (nexus.yaml)
43. Target-specific overrides
44. Batch mode (different settings per target)
45. Scheduling (--daily, --weekly, --every-6h, --cron)
46. Methodology checklist
47. Methodology change alerts
48. CVE auto-update (daily)
49. CVE filtering (severity-based)
50. CVE auto-POC generation (.py, .js, .sh, .yaml)
51. CVE nuclei template registration
52. CVE email delivery
53. CVE Discord alerts
54. CVE Telegram alerts
55. Scan resume (checkpoint)
56. Phase skip (--discover-only, --scan-only)
57. Tool ordering (tech-first)
58. Result naming (standardized)
59. Export (zip, 7z, json, csv)
60. Import (restore findings)
61. Scan comparison (nexus diff)
62. Batch mode (concurrent/sequential)
63. C2 bot (Discord + Telegram)
64. C2 commands (/hunt, /stop, /logs, /report, /status)
65. GitHub bug hunt agent
66. AI finding categorization
67. AI chain detection
68. AI error analysis
69. Any AI provider (OpenAI, GLM, DeepSeek, Gemini)
70. Real reports + skills (false positive filters)

### Enhancement Features (12)

71. Arjun (light scan only)
72. Exclude findings (--exclude-p4)
73. Min severity (--min-severity)
74. Smart tool pipeline (Wappalyzer → tool selection)
75. Export/import workflows
76. Enhanced naming (scope type indicator)
77. Email alerting (CVE scripts attached)
78. Separate alert webhooks (findings/CVE/metrics)
79. Per-type false positive strictness
80. Methodology checklist + alerts
81. Auto-generated POC scripts (4 formats)
82. Permission boundary enforcement

---

## PART 10: ACCEPTANCE CRITERIA

### Build Verification

**Phase 1 (DISCOVER):**
- [ ] Pegpon runs all 15 tools
- [ ] BBot runs only on --full-scan
- [ ] Wappalyzer detects tech correctly
- [ ] Recon data saved (domains.txt, endpoints.json, tech.json)

**Phase 2 (PROBE):**
- [ ] Nuclei loads tech-matched templates
- [ ] Dalfox detects XSS
- [ ] SQLmap runs light mode by default
- [ ] Tool timeout respected
- [ ] Tool failure handled per mode (light/deep)

**Phase 3 (ANALYZE):**
- [ ] Findings deduplicated correctly
- [ ] Severity scored by impact
- [ ] Chains detected (dependency graphs)
- [ ] False positives filtered per type
- [ ] Confidence calculated

**Phase 4 (HUNT):**
- [ ] OFF by default
- [ ] Respects max_scans_per_day
- [ ] Filters BB vs VDP
- [ ] Alerts on P1/P2

**Phase 5 (CONTROL):**
- [ ] Discord bot functional
- [ ] Telegram bot functional
- [ ] Commands execute correctly
- [ ] Results returned to user

**Phase 6 (SCALE):**
- [ ] Scaffold created (no code yet)

**Config & Data:**
- [ ] nexus.yaml loads correctly
- [ ] .keys.env validated on startup
- [ ] Database schema created
- [ ] Findings stored + queryable
- [ ] Naming conventions applied

**Alerts:**
- [ ] Discord webhooks send findings
- [ ] Discord webhooks send CVEs
- [ ] Telegram alerts work
- [ ] Email alerts work (with scripts attached)
- [ ] Alerts configurable (enable/disable per channel)

**CVE System:**
- [ ] Auto-update runs daily
- [ ] Scripts generated (.py, .js, .sh, .yaml)
- [ ] Templates registered in nuclei
- [ ] Email delivery works
- [ ] Alert severity filter works

**Export/Import:**
- [ ] Export to zip, 7z, json, csv
- [ ] Import restores findings
- [ ] Metadata preserved

**Security:**
- [ ] No data extraction beyond PoC
- [ ] No arbitrary command execution
- [ ] Out-of-scope blocked
- [ ] Permission boundary enforced

---

## PART 11: TESTING CHECKLIST

### Unit Tests
- [ ] Deduplicator (same finding merged)
- [ ] Severity scorer (correct P1-P4 assignment)
- [ ] Chain detector (correct dependency graphs)
- [ ] Scope validator (in-scope/out-of-scope logic)
- [ ] False positive filter (per-type strictness)
- [ ] Config parser (nexus.yaml loading)
- [ ] API key validator (.keys.env validation)

### Integration Tests
- [ ] Phase 1 → Phase 2 (recon → scanning)
- [ ] Phase 2 → Phase 3 (scanning → analysis)
- [ ] Tool orchestration (wappalyzer → nuclei)
- [ ] CVE update → Script generation → Email
- [ ] Export → Import (data preservation)
- [ ] Scan resume (checkpoint recovery)

### End-to-End Tests
- [ ] Full scan: target.com
- [ ] Batch scan: targets.txt
- [ ] Scheduled scan: nexus hunt-schedule
- [ ] Export findings: nexus export --format zip
- [ ] C2 bot: /nexus hunt target.com
- [ ] CVE scan: nexus cve-scan target.com --critical

### Security Tests
- [ ] No data extraction beyond PoC
- [ ] Out-of-scope filtered
- [ ] No RCE shells
- [ ] Permission boundary enforced

---

## PART 12: HANDOFF REQUIREMENTS

**Agent must:**
1. Implement all 82 features
2. Pass all acceptance criteria
3. Run all tests (unit + integration + e2e)
4. Enforce security boundary
5. Generate complete working framework
6. Document any build decisions

**Output location:** `/mnt/user-data/outputs/nexus-framework/`

**Deliverables:**
- [ ] Complete source code
- [ ] All config files
- [ ] All templates
- [ ] requirements.txt
- [ ] README.md (with usage examples)
- [ ] LICENSE
- [ ] Test suite (passing)

---

**Status: READY FOR AGENT BUILD**
