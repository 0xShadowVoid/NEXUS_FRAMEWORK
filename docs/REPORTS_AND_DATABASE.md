# Reports and Database

## Where things live

| Path | Contents | Git status |
|---|---|---|
| `nexus.db` | SQLite database (scans, findings, evidence, assets, transitions, engagement memory) | ignored |
| `results/<target>/<scan-id>/` | per-scan artifacts: `report.md`/JSON, `cloud.json`, `network.json`, tool outputs | ignored |
| `exports/` | `export`/`import` bundles (zip/7z) | ignored |
| `logs/` | runtime logs | ignored |
| `browser-artifacts/` | NEMESIS browser session artifacts (opt-in) | ignored |

## Database schema (v4, additive migrations)

Core tables: `scans`, `findings` (with lifecycle state), `evidence` (sanitized, source- and
phase-attributed), `assets` (+ `evidence_assets` linkage), `finding_transitions` (lifecycle
audit), `engagement_memory` and `nemesis_sessions` (NEMESIS). Opening an older `nexus.db`
upgrades it in place via `core/migrations.py`; nothing is deleted.

Key invariants:

- Evidence is sanitized at the choke point (`insert_evidence` → `core/sanitizer.py`): secret
  headers, bearer/API-key tokens, and banned keys are redacted **before** persistence.
- Every finding carries a lifecycle state (`candidate → probable → validated | rejected`);
  deterministic verification drives promotion — AI suggestions cannot validate.
- Evidence rows link to assets and (when produced by verification) to findings.

## Handy queries

```powershell
python -c "import sqlite3; c = sqlite3.connect('nexus.db'); print(c.execute('select id, target, started_at, status from scans order by id desc limit 5').fetchall())"
python -c "import sqlite3; c = sqlite3.connect('nexus.db'); print(c.execute('select severity, count(*) from findings group by severity').fetchall())"
```

## Export formats

`python -m nexus export [TARGET] --format zip|7z|json|csv|html|sarif` — SARIF is suitable for
GitHub code-scanning upload; `--date DATE` narrows a day; `import FILE --merge` re-imports a
bundle (dedup rules apply).

## Backup & restore

Transactional, online-safe:

```powershell
python -c "from core.database import Database; Database('nexus.db').backup_to('nexus-backup.db')"
python -c "from core.database import Database; Database('nexus.db').restore_from('nexus-backup.db')"
```

Run restores while NEXUS is not executing scans. `retention --days N` only *reports* folders
older than N days — it never deletes.
