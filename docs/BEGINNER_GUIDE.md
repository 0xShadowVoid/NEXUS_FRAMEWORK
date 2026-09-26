# NEXUS — Beginner's Guide (Explain It Like I'm New)

> **Why this file exists:** you will forget everything. Everyone does.
> This is the manual you read after 6 months away and think "oh right, THAT's
> how my own tool works." Zero assumptions. Read top to bottom once, then
> use it as a lookup.

---

## Part 1 — The Big Picture (30 seconds)

**NEXUS is a robot that finds security bugs in websites for you.**

You give it a target (a website you're **allowed** to test), and it:

1. **Finds** everything about that website (subdomains, pages, technology)
2. **Tests** those things for known weaknesses
3. **Filters** the noise so you only see real bugs
4. **Writes** the report you'd submit for a bounty

You never have to run 15 tools by hand and copy-paste outputs. NEXUS runs
them, collects results, removes duplicates, ranks by severity, and hands
you a report. That's it. That's the whole product.

**The one rule that never changes:** NEXUS only *proves* a bug exists
(detection + PoC). It never steals data, never changes anything on the
target, never leaves anything behind. Bounties are paid for *reporting*
bugs, not for exploiting them.

---

## Part 2 — The 6 Phases (what happens when you press go)

Think of it like a factory assembly line. Each phase feeds the next.

| Phase | Name | Plain English | Automatic? |
|---|---|---|---|
| 1 | **DISCOVER** | "Map the target." Find subdomains, URLs, what tech the site runs, what Google/GitHub leaks about it | Always runs |
| 2 | **PROBE** | "Test for bugs." Fire scanners at the map from phase 1 | Always runs |
| 2b | **VERIFY** | "Is it real?" Checks each finding's evidence so fake results die here | Always runs |
| 3 | **ANALYZE** | "Make sense of it." Merge duplicates, score severity, find bug-chains, drop false positives | Always runs |
| 4 | **HUNT** | "New programs? Scan them first." Auto-scans brand-new bug bounty programs for first-blood findings | OFF by default |
| 5 | **CONTROL** | "Boss mode." You send commands from Discord/Telegram like `/nexus hunt target.com` | Optional |
| 6 | **SCALE** | "More power." Run scans in parallel (currently on one machine; multi-VPS is future) | Optional |

**Example:** you run `python nexus.py hunt acme.com` →

```
scope check     → is acme.com in my allowed list? (yes/no, stops here if no)
DISCOVER        → finds 340 URLs, learns site runs WordPress 6.0 + Nginx
PROBE           → nuclei loads ONLY WordPress templates (smart!), dalfox hunts XSS
VERIFY          → "reflected but HTML-encoded" findings are killed as fake
ANALYZE         → 89 raw findings → 14 real ones (2 are P2!), 1 chain detected
report          → results/acme-.../reports/*-findings.md ← you read this
alerts          → your Discord pings: 2× P2 found
```

---

## Part 3 — Every Tool, Explained Like You're New

You don't need these installed — NEXUS skips missing ones automatically
(`python nexus.py check-tools` shows what you have). But knowing what each
does helps you read logs and reports.

### The recon crew (Phase 1 — map the target)

| Tool | What it actually does | Analogy |
|---|---|---|
| `subfinder`, `assetfinder`, `findomain`, `chaos`, `github-subdomains` | Find **subdomains** (like `blog.acme.com`, `api.acme.com`) | Phone book lookup: you know "acme.com", they find every branch office |
| `httpx` | Checks which subdomains are **actually alive websites** | Knocks on every door, notes which ones open |
| `ffuf` | Brute-forces **hidden paths** (`/admin`, `/backup`, `/secret`) | Tries every key on every door in the hallway |
| `katana`, `waybackurls`, `gau`, `jsluice` | Collect **URLs** — from crawling, from the Wayback Machine, from old archives | Archaeologist: digs up every page the site ever had, including "deleted" ones |
| `dnsx` | Resolves **DNS records** (what IPs point where) | The postal service address lookup |
| **dorker** (built-in) | Runs **search-engine dorks** on DuckDuckGo, Google, Bing, GitHub to find exposed files, logins, backups, leaks | Asks 4 search engines "show me acme.com's dirty laundry" |
| **tech detection** (built-in) | Identifies the tech stack: "WordPress 6.0, Nginx 1.24, PHP 8.1" | Reads the site's fingerprints |
| `bbot` | Deep recon framework, 100+ modules (only in `--full-scan`) | The full forensic team (slow, thorough) |

### The attack crew (Phase 2 — test for bugs)

| Tool | Bug it hunts | Plain English |
|---|---|---|
| `nuclei` | **Everything known** | Runs thousands of community-written "bug recipes" (templates). NEXUS smart-loads ONLY the ones matching the detected tech — WordPress site? No point running Java templates |
| `dalfox` | **XSS** | Injects fake "alert(1)" scripts to see if the site reflects them back to victims |
| `sqlmap` | **SQL injection** | Tricks the database into misbehaving. NEXUS runs it in gentle mode by default (risk=1, level=1) and ONLY on endpoints that look auth-related |
| `ghauri` | **Blind SQLi** | SQLi's silent cousin — no error messages, just timing differences |
| `commix` | **Command injection** | Checks if user input reaches the server's command line |
| `jwt-tool` | **JWT flaws** | Tests those `eyJhbG...` login tokens for weak secrets / algorithm bugs |
| `lfihunt` | **LFI** | Asks "can I read server files I shouldn't?" (`../../etc/passwd`) |
| `graphql-cop` | **GraphQL misconfig** | Tests the API Swiss-army-knife for open doors |
| `nomore403` | **403 bypass** | Tries known tricks to walk past "Forbidden" doors |
| `arjun` | **Hidden parameters** | Finds secret URL parameters the frontend never mentions |
| `cloudenum`, `s3scanner`, `prowler` | **Cloud exposure** | Find public buckets and cloud misconfigurations |
| **IDOR prober** (built-in) | **IDOR** | The read-only differential check: "if I change user ID 5→6, do I see a stranger's data?" |
| `gowitness` | Screenshots | Takes pictures of pages as evidence (optional) |

**Don't panic about installing all of these.** Start with the big three —
`nuclei`, `subfinder`, `httpx` — and add the rest as you need them.

---

## Part 4 — Bug Types for Humans (what did I actually find?)

When the report says "P2 — reflected XSS", here's what that means:

| Bug | One-liner | Analogy | Typical severity |
|---|---|---|---|
| **XSS** (Cross-Site Scripting) | I can make the site show MY script to OTHER users | Slipping a note into someone's mail that says "give me your keys" | P3 (reflected) / P2 (stored) |
| **SQLi** (SQL Injection) | I can talk to the database directly | Speaking to the bank vault in the vault's own language | P1 |
| **IDOR** (Insecure Direct Object Reference) | Changing `user_id=5` to `user_id=6` shows a stranger's data | Every apartment has the same lock; yours opens theirs | P2–P3 |
| **RCE** (Remote Code Execution) | I can run commands on the server | Getting the keys to the building AND the intercom system | P1 (critical) |
| **SSRF** (Server-Side Request Forgery) | I make the server visit websites for me | Asking a bank employee to check a "suspicious link" from inside the secure office | P2 |
| **LFI** (Local File Inclusion) | I can read files on the server | Convincing the librarian to fetch "the employee phone list" | P2 |
| **Open Redirect** | I control where the site sends users | Replacing the "Exit" sign to point at my shop | P3–P4 |
| **Info disclosure** | The site leaks config/versions/secrets | Bank statement left on the printer | P4 |

### Severity ladder (what P1–P4 means)

```
P1 = critical  → full system access, all user data     (bounty: 💰💰💰💰)
P2 = high      → serious: accounts, sensitive data      (bounty: 💰💰💰)
P3 = medium    → real but limited impact                (bounty: 💰💰)
P4 = low       → minor info leaks, hardening issues     (bounty: 💰)
```

---

## Part 5 — Chains: When 1+1 = 10 (the bounty multipliers)

A **chain** is combining two small bugs into one big one. Individually
they're worth $100; together they're worth $5,000. NEXUS hunts these
automatically in ANALYZE.

**Real-world analogy:** a unlocked side door (bug 1) is bad. A master key
hanging in the unlocked side door (bug 2) is catastrophic. Together =
full building access.

The 5 chains NEXUS detects:

| Chain | Recipe | Why it's deadly |
|---|---|---|
| **XSS → RCE** | Stored XSS on an *admin page* | You poison an admin's browser → hijack their admin session → admin actions = code execution. Two medium bugs = one critical |
| **IDOR → Account Takeover** | IDOR on a *write* endpoint (email/password change) | Change the victim's email to yours → click "forgot password" → their account is yours |
| **SQLi → Full DB** | SQLi on a *login* endpoint | Bypass authentication → the database serves you everything, unauthenticated |
| **SSRF → Internal** | SSRF that reaches internal addresses (like cloud metadata `169.254.169.254`) | Steal cloud credentials from inside the network → take over the cloud account |
| **Redirect → Token Theft** | Open redirect inside an *OAuth login flow* | Steal the login authorization code → log in as the victim |

**In reports, chains appear in their own section** with combined severity —
always look there first, that's where the big bounties live.

---

## Part 6 — Reading Your Results (where's my bug?)

After a scan, open `results/<target>-<stuff>-<date>-<time>/`:

```
results/acme-hackerone-bb-public-2026-09-26-0230/
├── recon/           ← the map (domains, URLs, tech, dorks)
├── scans/           ← raw tool output (only open if debugging)
├── processed/
│   ├── findings.json            ← every finding, machine format
│   ├── high_value_findings.json ← ★ START HERE (P1/P2 only)
│   ├── chains.json              ← ★ AND HERE (the combos)
│   └── metrics.json             ← scan stats
└── reports/
    ├── acme-...-findings.md     ← ★ THE report (human-readable)
    └── drafts/                  ← per-finding submission drafts
```

**Your daily routine: open `reports/` → read findings top-to-bottom →
P1/P2 first → check `chains.json` → submit the good ones.**

Finding fields decoded:

| Field | Meaning |
|---|---|
| `severity` | P1–P4 (see ladder above) |
| `confidence` | 0–100, how sure NEXUS is (90+ = very sure) |
| `verified` | survived the deterministic VERIFY phase |
| `corroborated` | ≥2 independent tools agree it's real |
| `tools_found` | which tools reported it |
| `payload` | the exact input that triggers the bug (your PoC) |
| `response_snippet` | the proof (what came back) |

---

## Part 7 — "I Forgot Everything" Recovery Card

Six months from now, start here:

```powershell
cd "F:\CyberSec_3\Projects_3\Github Repo Online\NEXUS_FRAMEWORK"

python nexus.py doctor                    # 1. is everything OK?
python nexus.py check-tools               # 2. what scanners do I have?
python nexus.py hunt <target.com>         # 3. GO. (quick scan, safe)
python nexus.py hunt <target.com> --full-scan --screenshots   # deeper

# results → results\<target>\reports\    ← read the .md file
# emergency stop → create file: results\.nexus_killswitch
# what's old?    → python nexus.py retention --days 30
```

That's 90% of daily use. Everything else is in `docs/EXAMPLES.md`
(the 5 detailed workflows) and `README.md` (full command reference).

---

## Part 8 — Glossary (terms the logs will throw at you)

| Term | Meaning |
|---|---|
| **Scope** | The list of targets you're ALLOWED to test. NEXUS blocks everything else — this is the law |
| **Out-of-scope (OOS)** | Explicitly forbidden targets (often `blog.x.com` etc.). Findings there are never submitted |
| **PoC** | Proof of Concept — the minimal demonstration a bug is real ("run this, see that") |
| **False positive (FP)** | A "bug" that isn't real (noise). NEXUS filters these; `nexus reject <id>` teaches it |
| **Dedup** | Same bug found by 2 tools = 1 finding, higher confidence |
| **Dorking** | Advanced search queries to find exposed stuff (`site:acme.com ext:pdf`) |
| **First blood** | First valid bug reported to a new program (often pays a bonus) |
| **Template** (nuclei) | A community bug-recipe: "send X, if response contains Y → vulnerable" |
| **CPE** | Standardized tech identifier — used to match CVEs to your target's stack |
| **KEV** | CISA's Known Exploited Vulnerabilities list — "attackers are using this RIGHT NOW" |
| **EPSS** | Probability a CVE gets exploited in the wild (0–1) — NEXUS sorts alerts by it |
| **Kill-switch** | The file `results/.nexus_killswitch` — while it exists, no new scans start |
| **BB / VDP** | Bug Bounty (paid) / Vulnerability Disclosure (unpaid, kudos) programs |
| **C2** | Command & Control — NEXUS's Discord/Telegram remote control |
| **Delta scan** | Only test what's NEW since last run (`--delta`) |

---

## Part 9 — Safety Rules (engraved)

1. **Authorization first.** No scope = no scan. The program's rules page beats everything, always.
2. NEXUS enforces **detection + PoC only** in code — never try to make it "do more". The moment you extract data or modify the target, you're not bounty hunting, you're attacking.
3. Heavy tools run gated for a reason (only on auth-looking endpoints). Respect the gates.
4. If unsure whether something's in scope: **don't scan it.**
5. `.keys.env` never gets committed, never gets shared, never goes in screenshots.

*Guide version: for NEXUS 2.0.0 "Apex". Update this file when you learn something future-you will forget.*
