# Workflows

Verified end-to-end recipes. Prereqs: installed NEXUS ([INSTALLATION.md](INSTALLATION.md)),
a scoped target in `config/nexus.yaml` ([CONFIGURATION.md](CONFIGURATION.md)).

## 1. Install and verify

```powershell
pip install .
python -m nexus --version        # NEXUS 2.0.2 "Apex"
python -m nexus doctor
python -m nexus check-tools
```

## 2. Inspect `--help` and version output

```powershell
python -m nexus --help
python -m nexus hunt --help      # flags of one command
```

## 3. Configure a permitted lab target and scope

Edit `config/nexus.yaml`:

```yaml
targets:
  lab.local:
    intensity: quick-scan
    rate_limit: "50/minute"
    in_scope: [lab.local, 127.0.0.1]
    out_of_scope: []
```

Replace `lab.local` with a host you own or are authorized to test.

## 4. Review settings before running a scan

```powershell
python -m nexus doctor           # re-reads config; reports scope/tool/env issues
python -m nexus check-tools
```

## 5. Run a selected phase or tool

```powershell
python -m nexus hunt lab.local --discover-only          # recon only
python -m nexus hunt lab.local --run-tools nuclei       # one specific tool
python -m nexus hunt lab.local --skip-tools sqlmap      # everything except sqlmap
```

## 6. Interpret findings and generated reports

- Console: per-phase summary with finding counts by severity.
- `results/<domain>-<platform>-<type>-<scope>-<date>-<time>/` — per-scan artifacts
  (`cloud.json`/`network.json` snapshots when those phases ran, plus reports).
- `nexus.db` — queryable findings/evidence; export instead of poking the DB when possible:

```powershell
python -m nexus export lab.local --format json
python -m nexus export lab.local --format sarif   # for IDE/GitHub code scanning
python -m nexus draft 1                            # submission draft for finding 1
```

## 7. Back up and restore the database

```powershell
# backup (transactional, online-safe)
python -c "from core.database import Database; Database('nexus.db').backup_to('nexus-backup.db')"

# restore
python -c "from core.database import Database; Database('nexus.db').restore_from('nexus-backup.db')"
```

Stop NEXUS before a restore. Keep backups outside the repository folder.

## 8. Configure optional AI safely

```powershell
Copy-Item config\.keys.env.example config\.keys.env
# edit .keys.env: set one or more provider keys
python -m nexus ai-set-key --provider deepseek --key <KEY>
python -m nexus ai-keys                 # masked pool status
```

Keys never leave your machine except toward the provider endpoint. Without keys, NEXUS runs
fully deterministically (see [AI_AND_NEMESIS.md](AI_AND_NEMESIS.md)).

## 9. Diagnose common errors

```powershell
python -m nexus doctor
python -m nexus self-scan          # ensure no secrets were committed
```

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## 10. Update or reinstall without mixing environments

```powershell
git pull
.\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install .                      # same venv, clean reinstall of the package
python -m nexus --version          # confirm the expected version
```

If versions look inconsistent (repo `VERSION` vs `--version`), rebuild the venv from scratch
([INSTALLATION.md](INSTALLATION.md) → *Clean-venv reinstall*).

## 11. Scheduled runs

```powershell
python -m nexus hunt-schedule --daily lab.local --name lab_daily
python -m nexus serve --once       # run due schedules once (daemon: omit --once)
python -m nexus retention --days 30   # report old scan folders (no deletion)
```

## 12. Program scope import

```powershell
python -m nexus scope-sync --domain example.com --file scope.json --platform hackerone --dry-run
python -m nexus scope-sync --domain example.com --file scope.json --platform hackerone
python -m nexus monitor --file programs.json
```
