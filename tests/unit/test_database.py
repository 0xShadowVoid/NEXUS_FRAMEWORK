"""Unit tests for the database layer (schema, CRUD, security guards)."""
from __future__ import annotations

import sqlite3

import pytest

from core.database import Database

EXPECTED_TABLES = {
    "targets", "scans", "findings", "chains",
    "schedules", "high_value_alerts", "screenshots", "cves",
}


def test_schema_created(db: Database):
    rows = db.query("SELECT name FROM sqlite_master WHERE type='table'")
    names = {r["name"] for r in rows}
    assert EXPECTED_TABLES.issubset(names)


def test_schema_idempotent(tmp_path):
    p = tmp_path / "x.db"
    Database(p).close()
    Database(p)  # must not raise on re-init


def test_target_upsert_and_get(db: Database):
    tid = db.upsert_target("example.com", platform="hackerone", in_scope=["*.example.com"])
    assert db.get_target("example.com")["platform"] == "hackerone"
    assert db.upsert_target("example.com") == tid  # idempotent


def test_scan_lifecycle_and_checkpoint(db: Database):
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid, intensity="quick-scan")
    db.update_scan(sid, checkpoint='{"phases_done": ["discover"]}', status="running")
    row = db.get_scan(sid)
    assert "discover" in row["checkpoint"]
    db.update_scan(sid, status="completed", findings_total=3)
    assert db.get_scan(sid)["findings_total"] == 3


def test_findings_insert_query_and_stats(db: Database):
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid)
    db.insert_finding(sid, "https://example.com/a", "xss", "P2", 90, tools_found=["nuclei"], valid=True)
    db.insert_finding(sid, "https://example.com/b", "sqli", "P1", 80, tools_found=["sqlmap"], in_scope=False, valid=False)
    rows = db.query_findings(scan_id=sid)
    assert len(rows) == 2
    assert db.query_findings(scan_id=sid, severity="P1")[0]["vuln_type"] == "sqli"
    stats = db.scan_stats(sid)
    assert stats["findings_total"] == 2
    assert stats["findings_oos"] == 1


def test_finding_validity_and_review(db: Database):
    tid = db.upsert_target("x.com")
    sid = db.create_scan(tid)
    fid = db.insert_finding(sid, "https://x.com/a", "xss", "P2", 50)
    db.mark_finding_validity(fid, True)
    db.mark_finding_reviewed(fid, True)
    row = db.query_findings(scan_id=sid)[0]
    assert row["valid"] == 1 and row["reviewed"] == 1


def test_chains_roundtrip(db: Database):
    tid = db.upsert_target("x.com")
    sid = db.create_scan(tid)
    db.insert_chain(sid, [1, 2], "sqli_to_db_access", "Full DB access", ["step1", "step2"], "P1")
    chains = db.query_chains(sid)
    assert chains[0]["chain_type"] == "sqli_to_db_access"
    assert chains[0]["finding_ids"] == [1, 2]
    assert chains[0]["combined_severity"] == "P1"


def test_schedules_crud_without_delete(db: Database):
    tid = db.upsert_target("x.com")
    db.upsert_schedule("daily_x", tid, frequency="daily", cron_expression="0 2 * * *", next_run="2026-01-01T02:00:00+00:00")
    sched = db.list_schedules()[0]
    db.mark_schedule_run(sched["id"], "2026-01-01T02:00:00+00:00", "2026-01-02T02:00:00+00:00")
    assert db.list_schedules()[0]["last_run"] == "2026-01-01T02:00:00+00:00"


def test_cve_get_or_create_dedup(db: Database):
    rid, created = db.get_or_create_cve("CVE-2026-0001", severity="critical", tech_matched="wordpress")
    assert created is True
    rid2, created2 = db.get_or_create_cve("CVE-2026-0001")
    assert created2 is False and rid2 == rid
    db.mark_cve_poc_generated(rid)
    assert db.list_cves()[0]["poc_generated"] == 1


def test_no_delete_or_drop_api(db: Database):
    """Security boundary: no delete/drop methods may be exposed."""
    for name in dir(db):
        low = name.lower()
        assert "delete" not in low, f"unexpected delete API: {name}"
        assert "drop" not in low, f"unexpected drop API: {name}"


def test_destructive_sql_is_blocked(db: Database):
    with pytest.raises(sqlite3.ProgrammingError):
        db.execute("DELETE FROM findings")
    with pytest.raises(sqlite3.ProgrammingError):
        db.execute("DROP TABLE findings")


def test_parameterized_queries_only(db: Database):
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid)
    db.insert_finding(sid, "https://example.com/a", "xss", "P2", 50)
    # Injection attempt via value is treated as data, not SQL.
    rows = db.query_findings(scan_id=sid, severity="P2' OR '1'='1")
    assert rows == []
