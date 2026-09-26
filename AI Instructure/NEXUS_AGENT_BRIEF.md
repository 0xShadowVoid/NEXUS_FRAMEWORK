# NEXUS FRAMEWORK — AGENT BUILD BRIEF

**Target:** AI Agent (code implementation)  
**Task:** Build NEXUS Framework from specification  
**Spec Location:** `/mnt/user-data/outputs/NEXUS_BUILD_SPEC.md`  
**Output Location:** `/mnt/user-data/outputs/nexus-framework/`  
**Status:** Ready to execute

---

## YOUR JOB (READ THIS FIRST)

**You are building:**
- A Python 3.11+ bug bounty automation framework
- 6 phases of security scanning (DISCOVER → SCALE)
- 82 features (locked, no changes without Mohamed approval)
- Detection + PoC only (no data harm, no backdoors)
- Elite-level bug bounty hunting tool

**You must:**
1. ✅ Read NEXUS_BUILD_SPEC.md completely (all 12 parts)
2. ✅ Implement all 82 features exactly as specified
3. ✅ Pass all acceptance criteria
4. ✅ Run full test suite (unit + integration + e2e)
5. ✅ Enforce security boundary (no data extraction beyond PoC)
6. ✅ Document any build decisions/trade-offs

**You cannot:**
- ❌ Add features without Mohamed approval
- ❌ Skip security boundary enforcement
- ❌ Modify acceptance criteria
- ❌ Deploy to production (test only)
- ❌ Hard-code API keys

---

## PHASE 1: READING & PLANNING (Before Writing Code)

### Step 1a: Read Complete Spec
- Read NEXUS_BUILD_SPEC.md all 12 parts
- Understand 6-phase architecture
- Map 82 features to code modules
- Identify dependencies between features

### Step 1b: Create Implementation Plan
```
Document:
  - Which features go in which files
  - Tool integration order
  - Database schema verification
  - Test strategy per phase
  - Potential blockers/risks
```

### Step 1c: Verify Spec Completeness
Questions to answer BEFORE writing code:
1. Are all CLI flags documented? ✅ YES
2. Are all database tables specified? ✅ YES
3. Are all config keys in nexus.yaml? ✅ YES
4. Are all alert channels documented? ✅ YES
5. Are security boundaries clear? ✅ YES

---

## PHASE 2: DIRECTORY SETUP

Create folder structure (already started):
```
/mnt/user-data/outputs/nexus-framework/
├── config/
│   ├── nexus.yaml
│   ├── false_positive_filters.yaml
│   ├── .keys.env.example (DONE)
│   └── .keys.env (git-ignored template)
│
├── phases/
│   ├── discover/
│   │   ├── __init__.py
│   │   ├── pegpon_wrapper.py
│   │   ├── bbot_wrapper.py
│   │   ├── wappalyzer_wrapper.py
│   │   └── recon_orchestrator.py
│   │
│   ├── probe/
│   │   ├── __init__.py
│   │   ├── nuclei_orchestrator.py
│   │   ├── dalfox_runner.py
│   │   ├── sqlmap_runner.py
│   │   ├── tool_runners.py
│   │   └── probe_orchestrator.py
│   │
│   ├── analyze/
│   │   ├── __init__.py
│   │   ├── deduplicator.py
│   │   ├── severity_scorer.py
│   │   ├── chain_detector.py
│   │   └── analyze_orchestrator.py
│   │
│   ├── hunt/
│   │   ├── __init__.py
│   │   ├── auto_hunter.py
│   │   ├── api_fetcher.py
│   │   └── hunt_orchestrator.py
│   │
│   ├── control/
│   │   ├── __init__.py
│   │   ├── discord_c2.py
│   │   ├── telegram_c2.py
│   │   └── c2_orchestrator.py
│   │
│   └── scale/
│       ├── __init__.py
│       ├── master_coordinator.py
│       └── worker_manager.py
│
├── core/
│   ├── __init__.py
│   ├── coordinator.py (main orchestrator)
│   ├── analyzer.py
│   ├── reporter.py
│   └── database.py
│
├── lib/
│   ├── __init__.py
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
├── templates/
│   ├── nuclei-custom/
│   ├── reports/
│   │   ├── hackerone.md
│   │   ├── bugcrowd.md
│   │   ├── intigriti.md
│   │   └── generic.md
│   └── (create other platforms)
│
├── scripts/
│   ├── cve_pocs/ (auto-populated)
│   └── __init__.py
│
├── tests/
│   ├── unit/
│   │   ├── test_deduplicator.py
│   │   ├── test_severity_scorer.py
│   │   ├── test_chain_detector.py
│   │   ├── test_scope_validator.py
│   │   ├── test_false_positive_filter.py
│   │   ├── test_config_parser.py
│   │   └── test_api_validator.py
│   │
│   ├── integration/
│   │   ├── test_phase_flow.py
│   │   ├── test_tool_orchestration.py
│   │   ├── test_cve_workflow.py
│   │   └── test_export_import.py
│   │
│   └── e2e/
│       ├── test_full_scan.py
│       ├── test_batch_scan.py
│       ├── test_scheduled_scan.py
│       └── test_c2_bot.py
│
├── nexus.py (CLI entry)
├── requirements.txt
├── LICENSE
├── README.md
└── .gitignore
```

---

## PHASE 3: CORE MODULES (Build Order)

### Module 1: Config + Logger + Database
**Must-have first, used by everything else**

```python
# lib/config.py
- Load nexus.yaml
- Load false_positive_filters.yaml
- Load .keys.env
- Validate all required keys
- Handle target-specific overrides

# lib/logger.py
- Structured logging
- Log levels (DEBUG, INFO, WARNING, ERROR)
- Log rotation
- Log to file + console

# core/database.py
- SQLite connection
- Schema creation (all 8 tables)
- CRUD operations
- Query builders
```

### Module 2: Scope & Validation
**Before scanning, validate targets**

```python
# lib/scope_validator.py
- Parse in_scope (wildcard support)
- Parse out_of_scope
- Validate finding against scope
- Block OOS submissions

# lib/config.py (extends)
- Load target-specific configs
- Apply overrides
```

### Module 3: Phase 1 (DISCOVER)
**Recon data collection**

```python
# phases/discover/pegpon_wrapper.py
- Run all 15 tools
- Parse output (domains, IPs, URLs)
- Store in results/

# phases/discover/wappalyzer_wrapper.py
- Detect tech stack
- Store in database

# phases/discover/bbot_wrapper.py
- Run 100+ modules (deep scan)
- Prerequisite: pegpon complete
- Conditional: --full-scan only

# phases/discover/recon_orchestrator.py
- Coordinate phase 1
- Handle tool dependencies
- Store recon data
```

### Module 4: Phase 2 (PROBE)
**Vulnerability scanning**

```python
# phases/probe/nuclei_orchestrator.py
- Load tech from phase 1
- Load ONLY matching templates
- Run nuclei (save results)
- Parse YAML output

# phases/probe/dalfox_runner.py
- Run dalfox (XSS)
- Parse results

# phases/probe/sqlmap_runner.py
- Light mode by default (risk=1, level=1)
- Heavy mode on --full-scan
- Parse results

# phases/probe/tool_runners.py
- Wrapper for other tools
- Timeout handling
- Error handling (per mode)

# phases/probe/probe_orchestrator.py
- Manage phase 2 flow
- Tool failure logic (light vs deep)
- Resume from checkpoint
```

### Module 5: Phase 3 (ANALYZE)
**Processing findings**

```python
# lib/deduplicator.py
- Fuzzy match findings
- Merge duplicates (show both tools)
- Boost confidence for multi-tool matches

# lib/severity_scorer.py
- Impact-based severity (RCE > SQLi > XSS)
- Confidence threshold per type

# lib/chain_detector.py
- Detect vulnerability chains
- Build dependency graphs
- Calculate chain impact

# phases/analyze/analyze_orchestrator.py
- Run dedup → scoring → chains
- Apply false positive filters
- Generate findings.json
```

### Module 6: False Positive Filtering
**Per-type strictness**

```python
# lib/false_positive_filter.py
- Load false_positive_filters.yaml
- Per-type strictness (XSS aggressive, SQLi conservative)
- Confidence threshold per type
- Mark findings as VALID / FALSE_POSITIVE / POTENTIAL
```

### Module 7: Alert System
**Multi-channel notifications**

```python
# lib/notifications.py
- Discord webhook sender
- Telegram bot sender
- Email sender (SMTP)
- Alert formatting (rich embeds)

# Separate webhook paths:
  - DISCORD_FINDINGS_WEBHOOK
  - DISCORD_CVE_WEBHOOK
  - Telegram bot
  - Email (with scripts attached)
```

### Module 8: Phase 4 (HUNT)
**Auto-hunting**

```python
# phases/hunt/api_fetcher.py
- H1 API fetch new programs
- Bugcrowd API fetch
- Filter BB vs VDP

# phases/hunt/auto_hunter.py
- Respect max_scans_per_day
- Queue management
- Trigger scans

# phases/hunt/hunt_orchestrator.py
- Coordinate phase 4
- Alert on P1/P2
```

### Module 9: Phase 5 (CONTROL)
**C2 Bot**

```python
# phases/control/discord_c2.py
- Listen for commands (/nexus hunt, /stop, etc.)
- Execute locally
- Return results

# phases/control/telegram_c2.py
- Same as Discord

# phases/control/c2_orchestrator.py
- Multi-channel support
- Command routing
```

### Module 10: CVE System
**Auto-update + POC generation**

```python
# lib/cve_fetcher.py
- Daily NVD API fetch
- Check against tech stack
- Generate POC scripts

# lib/cve_poc_generator.py
- Generate Python POC
- Generate JavaScript POC
- Generate Bash POC
- Generate Nuclei template

# Delivery:
  - Save to nexus/scripts/cve_pocs/
  - Register nuclei templates
  - Alert via Discord/Telegram/Email
  - Email scripts as attachments
```

### Module 11: Export/Import
**Data portability**

```python
# core/exporter.py
- Export to zip
- Export to 7z
- Export to JSON
- Export to CSV
- Include metadata

# core/importer.py
- Import zip
- Import JSON
- Restore database
- Merge with existing (--merge flag)
```

### Module 12: CLI Entry
**nexus.py**

```python
# nexus.py
- argparse setup
- Command routing:
  - nexus hunt <target>
  - nexus batch <file>
  - nexus hunt-schedule ...
  - nexus export ...
  - nexus cve-scan ...
  - etc.
- Load config
- Call coordinator
```

### Module 13: Main Coordinator
**Orchestrates all phases**

```python
# core/coordinator.py
- Parse CLI args
- Load config
- Validate scope
- Execute phases (1 → 5)
- Handle resume
- Call reporter
```

---

## PHASE 4: REPORTING & TEMPLATES

### Finding Report Template

```markdown
# NEXUS Findings Report

**Target:** example.com  
**Platform:** HackerOne  
**Type:** BB (Public)  
**Scan Date:** 2026-09-21  
**Scan Duration:** 2h 15m  

## Metrics

- URLs Discovered: 342
- Endpoints Tested: 156
- Findings Total: 18
- Findings Valid: 15
- Findings OOS: 3
- By Severity: P1: 2, P2: 3, P3: 5, P4: 5

## Findings

### Finding 1: XSS in /search

**Type:** Stored XSS  
**Severity:** P2  
**Confidence:** 95%  
**Tools Found:** nuclei, dalfox  

**Endpoint:** GET /search?q=PAYLOAD  
**Payload:** `<img src=x onerror=alert(1)>`  

**Response:**
```
<input value="<img src=x onerror=alert(1)>">
```

**Impact:** Attacker can steal user sessions  
**Steps to Reproduce:** [...]  
**Screenshot:** [screenshot-001.png]

---

### Finding 2: SQLi in /filter

**Type:** Blind Boolean-based SQLi  
**Severity:** P1  
**Confidence:** 88%  
**Tools Found:** nuclei, ghauri, sqlmap  

**Endpoint:** GET /api/users?filter=PAYLOAD  
**Payload:** `1' AND SLEEP(5)--`  

**Impact:** Full database access  
**Steps to Reproduce:** [...]  
**Screenshot:** [screenshot-002.png]

---

## Vulnerability Chains

### Chain 1: IDOR → Account Takeover

1. IDOR in /api/users/{id}/profile (P2)
2. Can enumerate all user IDs (P3)
3. Access to payment info (P1 combined)

**Overall Impact:** HIGH  
**Combined Severity:** P1

---

## Summary

- Real Findings: 15
- False Positives: 3 (filtered)
- Estimated Bounty: $5,000 - $25,000
```

---

## PHASE 5: TESTING STRATEGY

### Unit Tests (Must Pass)

```python
# tests/unit/test_deduplicator.py
test_same_finding_merged()
test_duplicate_detection_fuzzy()
test_confidence_boost_multi_tool()

# tests/unit/test_severity_scorer.py
test_p1_rce()
test_p2_sqli()
test_p3_xss()
test_confidence_threshold()

# tests/unit/test_chain_detector.py
test_xss_to_rce_chain()
test_idor_to_account_takeover()
test_dependency_graph()

# tests/unit/test_scope_validator.py
test_in_scope_single_domain()
test_in_scope_wildcard()
test_out_of_scope_blocked()
test_cloud_target_validation()

# tests/unit/test_false_positive_filter.py
test_xss_aggressive_filter()
test_sqli_conservative_filter()
test_confidence_threshold_enforcement()

# tests/unit/test_config_parser.py
test_nexus_yaml_loading()
test_target_overrides()
test_env_variable_substitution()

# tests/unit/test_api_validator.py
test_keys_env_validation()
test_missing_api_key_handling()
test_webhook_url_validation()
```

### Integration Tests (Must Pass)

```python
# tests/integration/test_phase_flow.py
test_discover_to_probe()
test_probe_to_analyze()
test_all_phases_sequential()

# tests/integration/test_tool_orchestration.py
test_wappalyzer_to_nuclei()
test_tool_failure_light_skip()
test_tool_failure_deep_retry()

# tests/integration/test_cve_workflow.py
test_cve_update_daily()
test_cve_script_generation()
test_cve_email_delivery()

# tests/integration/test_export_import.py
test_export_zip()
test_export_7z()
test_import_restore()
test_import_merge()
```

### End-to-End Tests (Must Pass)

```python
# tests/e2e/test_full_scan.py
test_full_scan_single_target()
test_quick_scan_vs_full_scan()
test_findings_accuracy()

# tests/e2e/test_batch_scan.py
test_batch_mode_sequential()
test_batch_mode_concurrent()
test_different_settings_per_target()

# tests/e2e/test_scheduled_scan.py
test_scheduled_scan_creation()
test_scheduled_scan_execution()
test_cron_expression_parsing()

# tests/e2e/test_c2_bot.py
test_discord_bot_commands()
test_telegram_bot_commands()
test_scan_execution_via_bot()
```

---

## PHASE 6: SECURITY VERIFICATION

Before code review, verify:

- [ ] No hardcoded credentials
- [ ] No data extraction beyond PoC
- [ ] Out-of-scope findings blocked
- [ ] No RCE shells (commands are read-only)
- [ ] Permission boundary enforced
- [ ] All API calls read-only
- [ ] No account creation
- [ ] No resource provisioning
- [ ] No persistent modifications

---

## PHASE 7: CODE REVIEW (Self-Check)

Before final submission, review:

### Design
- [ ] Modular (each phase independent)
- [ ] Testable (dependencies injected)
- [ ] Maintainable (clear structure)
- [ ] Scalable (Phase 6 ready)

### Quality
- [ ] Consistent naming (snake_case for functions)
- [ ] Documented (docstrings + comments)
- [ ] Type hints (Python 3.11+)
- [ ] Error handling (try/catch with logging)
- [ ] No magic numbers (use constants)

### Security
- [ ] Permission boundary enforced
- [ ] Input validation
- [ ] No SQL injection (use parameterized queries)
- [ ] No command injection (no shell=True)

### Testing
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] All e2e tests pass
- [ ] No test coverage gaps

---

## BUILD CHECKLIST

**Before Submitting:**

- [ ] Read NEXUS_BUILD_SPEC.md completely
- [ ] Create implementation plan
- [ ] Build Phase 1 (DISCOVER)
- [ ] Build Phase 2 (PROBE)
- [ ] Build Phase 3 (ANALYZE)
- [ ] Build Phase 4 (HUNT)
- [ ] Build Phase 5 (CONTROL)
- [ ] Create Phase 6 scaffold (no code)
- [ ] Build Alert System
- [ ] Build CVE System
- [ ] Build Export/Import
- [ ] Build CLI (nexus.py)
- [ ] Create all tests
- [ ] Run all tests (100% pass)
- [ ] Security review
- [ ] Code review (self)
- [ ] Write README.md
- [ ] Create requirements.txt
- [ ] Create .gitignore
- [ ] Create LICENSE

---

## DELIVERABLES

**Output directory:** `/mnt/user-data/outputs/nexus-framework/`

**Files to create:**
1. All Python modules (listed above)
2. requirements.txt (all dependencies)
3. nexus.yaml (config template)
4. false_positive_filters.yaml (filtering rules)
5. .keys.env.example (API key template)
6. .gitignore (ignore .keys.env, __pycache__, etc.)
7. LICENSE (custom)
8. README.md (usage + examples)
9. All tests (passing)
10. Report templates (H1, Bugcrowd, etc.)

---

## SUCCESS CRITERIA

**You're done when:**

1. ✅ All 82 features implemented
2. ✅ All acceptance criteria met
3. ✅ All tests pass (unit + integration + e2e)
4. ✅ Security boundary enforced
5. ✅ Code is documented
6. ✅ README.md is complete
7. ✅ Framework is ready to use

---

**Status: READY FOR BUILD**

**Start with Phase 1: Reading & Planning**
