# Getting Started

A step-by-step first run. All commands are tested against the repository at version 2.0.1.

## 0. What you need

- Python **3.11+** (`python --version` to check)
- A terminal (Windows PowerShell, Linux shell, or macOS)
- A target you are **authorized to test** (your own lab, or an in-scope bounty program asset)

## 1. Install

```powershell
git clone https://github.com/0xShadowVoid/NEXUS_FRAMEWORK.git
cd NEXUS_FRAMEWORK

python -m venv venv
.\venv\Scripts\Activate.ps1        # Windows
# source venv/bin/activate         # Linux / macOS

pip install --upgrade pip
pip install .
```

Full details (wheel install, offline machines): [INSTALLATION.md](INSTALLATION.md).

## 2. Verify

```powershell
python -m nexus --version      # -> NEXUS 2.0.1 "Apex"
python -m nexus --help         # list of all 27 commands
python -m nexus doctor         # environment/config diagnostics
python -m nexus check-tools    # which optional external tools are installed
```

Missing external tools (nuclei, sqlmap, …) are **not** an error — NEXUS degrades gracefully.
See [TOOLS_REFERENCE.md](TOOLS_REFERENCE.md).

## 3. Configure scope (required before scanning)

Edit `config/nexus.yaml`. Every scan target must be declared and scoped:

```yaml
targets:
  lab.local:                    # your target key
    intensity: quick-scan
    rate_limit: "50/minute"
    in_scope:                   # only these are testable
      - lab.local
      - 127.0.0.1
    out_of_scope: []            # explicit exclusions win over in_scope
```

Rules enforced before any traffic is issued:

- Only hosts in the active target's `in_scope` may be contacted.
- Anything listed in `out_of_scope` is blocked even if it also appears in `in_scope`.
- Private/loopback/link-local addresses additionally require an explicit in-scope IP grant
  (network phase) and `phases.network.allow_private: true` where applicable.

Review your settings before the first run:

```powershell
python -m nexus doctor         # re-checks config after edits
```

## 4. Run your first scan

Recon-only first (no active probing):

```powershell
python -m nexus hunt lab.local --discover-only
```

Then a light scan:

```powershell
python -m nexus hunt lab.local
```

Output: scan summary in the console; full results in `results/<target>/<scan-id>/`, findings
and evidence in the SQLite database `nexus.db` (see [REPORTS_AND_DATABASE.md](REPORTS_AND_DATABASE.md)).

## 5. Look at what you found

```powershell
python -m nexus draft 1              # render a submission draft for finding #1
python -m nexus verify 1             # mark finding #1 manually verified
python -m nexus reject 2             # mark #2 false-positive and teach the filter
python -m nexus export lab.local --format zip
```

## 6. Optional: AI (NEMESIS)

Without any AI key everything above works deterministically. To enable AI-assisted triage:

```powershell
python -m nexus ai-set-key --provider deepseek --key <YOUR-KEY>
python -m nexus ai-keys             # shows the key pool (masked)
```

Details: [AI_AND_NEMESIS.md](AI_AND_NEMESIS.md).

## 7. Back up

```powershell
python -c "from core.database import Database; Database('nexus.db').backup_to('backup.db')"
```

More workflows (schedules, batch scans, scope import, updates): [WORKFLOWS.md](WORKFLOWS.md).
