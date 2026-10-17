"""Concurrency regression tests for the remaining SQLite upserts (Pass 17).

``upsert_target`` (``targets.domain`` UNIQUE) and ``upsert_schedule``
(``schedules.name`` UNIQUE) now use a single conflict-safe statement
(``INSERT ... ON CONFLICT ... DO NOTHING`` / ``DO UPDATE``). ``upsert_phase_run``
has no unique constraint, so its read-then-write is serialized inside the
connection lock.

These tests prove: no duplicate rows, no ``IntegrityError`` under the real
concurrency model (one shared connection + RLock, as used by ``--concurrent``),
correct update semantics, and that real errors still surface. Concurrency is
driven by a ``threading.Barrier`` — no sleeps.
"""
from __future__ import annotations

import sqlite3
import threading

import pytest

from core.database import Database


def _run_concurrently(work, n: int):
    """Run ``work(i)`` on ``n`` threads released simultaneously."""
    barrier = threading.Barrier(n)
    results: list = [None] * n
    errors: list = [None] * n

    def worker(i: int) -> None:
        barrier.wait()
        try:
            results[i] = work(i)
        except BaseException as exc:  # noqa: BLE001 - captured for assertions
            errors[i] = exc

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results, errors


# -- upsert_target: behavior --------------------------------------------------


def test_upsert_target_first_write_wins(db: Database):
    tid = db.upsert_target("example.com", platform="hackerone", in_scope=["*.example.com"])
    again = db.upsert_target("example.com", platform="other")
    assert again == tid
    row = db.get_target("example.com")
    assert row["platform"] == "hackerone"  # existing fields untouched
    assert db.query("SELECT COUNT(*) AS c FROM targets")[0]["c"] == 1


def test_upsert_target_repeated_is_stable(db: Database):
    ids = [db.upsert_target("a.example") for _ in range(5)]
    assert len(set(ids)) == 1
    assert db.query("SELECT COUNT(*) AS c FROM targets")[0]["c"] == 1


# -- upsert_target: concurrency (shared connection + RLock) -------------------


def test_concurrent_upsert_target_same_domain_shared_conn(db: Database):
    results, errors = _run_concurrently(lambda i: db.upsert_target("example.com"), 16)
    assert errors == [None] * 16
    assert len(set(results)) == 1
    assert db.query("SELECT COUNT(*) AS c FROM targets")[0]["c"] == 1


def test_concurrent_upsert_target_distinct_domains(db: Database):
    results, errors = _run_concurrently(lambda i: db.upsert_target(f"host{i}.example.com"), 24)
    assert errors == [None] * 24
    assert len(set(results)) == 24
    assert db.query("SELECT COUNT(*) AS c FROM targets")[0]["c"] == 24


def test_concurrent_upsert_target_across_connections(tmp_path):
    path = tmp_path / "t.db"
    Database(path).close()  # create schema once, sequentially
    dbs = [Database(path) for _ in range(8)]
    try:
        results, errors = _run_concurrently(
            lambda i: dbs[i].upsert_target("example.com"), len(dbs)
        )
        assert errors == [None] * len(dbs)
        assert len(set(results)) == 1
        assert dbs[0].query("SELECT COUNT(*) AS c FROM targets")[0]["c"] == 1
    finally:
        for d in dbs:
            d.close()


def test_target_domain_unique_constraint_backstop(tmp_path):
    db = Database(tmp_path / "unique.db")
    try:
        db.execute("INSERT INTO targets (domain, created_at) VALUES (?, ?)", ("x.com", "t"))
        with pytest.raises(sqlite3.IntegrityError):
            db.execute("INSERT INTO targets (domain, created_at) VALUES (?, ?)", ("x.com", "t"))
    finally:
        db.close()


# -- upsert_schedule: behavior ------------------------------------------------


def test_upsert_schedule_insert_then_update_semantics(db: Database):
    tid = db.upsert_target("x.com")
    sid = db.upsert_schedule(
        "daily_x", tid, frequency="daily", cron_expression="0 2 * * *",
        intensity="quick-scan", next_run="2026-01-01T02:00:00+00:00",
    )
    first = db.list_schedules()[0]
    assert first["id"] == sid and first["next_run"] == "2026-01-01T02:00:00+00:00"

    sid2 = db.upsert_schedule(
        "daily_x", tid, frequency="weekly", cron_expression="0 3 * * 1",
        intensity="full-scan", enabled=False, next_run="2099-01-01T00:00:00+00:00",
    )
    row = db.list_schedules()[0]
    assert sid2 == sid
    assert row["frequency"] == "weekly"          # updated
    assert row["cron_expression"] == "0 3 * * 1"  # updated
    assert row["intensity"] == "full-scan"        # updated
    assert row["enabled"] == 0                    # updated
    # preserved fields (previous semantics: only the UPDATE columns change)
    assert row["next_run"] == "2026-01-01T02:00:00+00:00"
    assert row["created_at"] == first["created_at"]
    assert db.query("SELECT COUNT(*) AS c FROM schedules")[0]["c"] == 1


def test_upsert_schedule_preserves_last_run(db: Database):
    tid = db.upsert_target("x.com")
    sid = db.upsert_schedule("daily_x", tid, next_run="2026-01-01T02:00:00+00:00")
    db.mark_schedule_run(sid, "2026-01-01T02:00:00+00:00", "2026-01-02T02:00:00+00:00")
    db.upsert_schedule("daily_x", tid, intensity="full-scan")
    row = db.list_schedules()[0]
    assert row["last_run"] == "2026-01-01T02:00:00+00:00"
    assert row["intensity"] == "full-scan"


# -- upsert_schedule: concurrency ---------------------------------------------


def test_concurrent_upsert_schedule_same_name_shared_conn(db: Database):
    tid = db.upsert_target("x.com")
    results, errors = _run_concurrently(
        lambda i: db.upsert_schedule("nightly", tid, intensity="quick-scan"), 16
    )
    assert errors == [None] * 16
    assert len(set(results)) == 1
    assert db.query("SELECT COUNT(*) AS c FROM schedules")[0]["c"] == 1


def test_concurrent_upsert_schedule_distinct_names(db: Database):
    tid = db.upsert_target("x.com")
    results, errors = _run_concurrently(
        lambda i: db.upsert_schedule(f"sched{i}", tid), 16
    )
    assert errors == [None] * 16
    assert len(set(results)) == 16
    assert db.query("SELECT COUNT(*) AS c FROM schedules")[0]["c"] == 16


def test_concurrent_upsert_schedule_across_connections(tmp_path):
    path = tmp_path / "s.db"
    Database(path).close()
    dbs = [Database(path) for _ in range(8)]
    try:
        tid = dbs[0].upsert_target("x.com")
        results, errors = _run_concurrently(
            lambda i: dbs[i].upsert_schedule("nightly", tid), len(dbs)
        )
        assert errors == [None] * len(dbs)
        assert len(set(results)) == 1
        assert dbs[0].query("SELECT COUNT(*) AS c FROM schedules")[0]["c"] == 1
    finally:
        for d in dbs:
            d.close()


# -- upsert_phase_run: behavior -----------------------------------------------


def test_upsert_phase_run_insert_then_update_semantics(db: Database):
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid)
    rid = db.upsert_phase_run(
        sid, "discover", "running", started_at="2026-01-01T00:00:00+00:00", attempts=1
    )
    rid2 = db.upsert_phase_run(sid, "discover", "completed", ended_at="2026-01-01T00:01:00+00:00")
    row = db.get_phase_run(sid, "discover")
    assert rid2 == rid
    assert row["state"] == "completed"
    assert row["ended_at"] == "2026-01-01T00:01:00+00:00"
    assert row["started_at"] == "2026-01-01T00:00:00+00:00"  # unchanged
    assert row["attempts"] == 1                              # unchanged
    assert db.query("SELECT COUNT(*) AS c FROM phase_runs")[0]["c"] == 1


def test_upsert_phase_run_checkpoint_and_error_update(db: Database):
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid)
    db.upsert_phase_run(sid, "probe", "running")
    db.upsert_phase_run(sid, "probe", "failed", error="boom", checkpoint='{"k":1}')
    row = db.get_phase_run(sid, "probe")
    assert row["state"] == "failed" and row["error"] == "boom"
    assert row["checkpoint"] == '{"k":1}'


# -- upsert_phase_run: concurrency (shared-connection model) ------------------


def test_concurrent_upsert_phase_run_same_phase_shared_conn(db: Database):
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid)
    results, errors = _run_concurrently(
        lambda i: db.upsert_phase_run(sid, "discover", "running"), 16
    )
    assert errors == [None] * 16
    assert len(set(results)) == 1
    assert db.query(
        "SELECT COUNT(*) AS c FROM phase_runs WHERE scan_id = ? AND phase = ?", (sid, "discover")
    )[0]["c"] == 1


def test_concurrent_upsert_phase_run_distinct_phases(db: Database):
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid)
    results, errors = _run_concurrently(
        lambda i: db.upsert_phase_run(sid, f"phase{i}", "running"), 8
    )
    assert errors == [None] * 8
    assert len(set(results)) == 8
    assert db.query(
        "SELECT COUNT(*) AS c FROM phase_runs WHERE scan_id = ?", (sid,)
    )[0]["c"] == 8


def test_phase_run_cross_connection_completes_without_error(tmp_path):
    """Cross-connection phase-run writes never raise (busy_timeout handles
    contention). ``phase_runs`` has no UNIQUE(scan_id, phase) constraint, so
    duplicate rows are still *possible* across independent connections — that
    is a documented limitation; the app's concurrency model shares one
    connection, where correctness is exact (test above)."""
    path = tmp_path / "p.db"
    Database(path).close()
    dbs = [Database(path) for _ in range(6)]
    try:
        tid = dbs[0].upsert_target("example.com")
        sid = dbs[0].create_scan(tid)
        _, errors = _run_concurrently(
            lambda i: dbs[i].upsert_phase_run(sid, "discover", "running"), len(dbs)
        )
        assert errors == [None] * len(dbs)
        count = dbs[0].query(
            "SELECT COUNT(*) AS c FROM phase_runs WHERE scan_id = ? AND phase = ?", (sid, "discover")
        )[0]["c"]
        assert 1 <= count <= len(dbs)  # robustness, not uniqueness (see docstring)
    finally:
        for d in dbs:
            d.close()


# -- failure / error surfacing ------------------------------------------------


def test_upserts_surface_errors_after_close(tmp_path):
    db = Database(tmp_path / "err.db")
    db.close()
    with pytest.raises(sqlite3.ProgrammingError):
        db.upsert_target("example.com")
    with pytest.raises(sqlite3.ProgrammingError):
        db.upsert_schedule("s", 1)
    with pytest.raises(sqlite3.ProgrammingError):
        db.upsert_phase_run(1, "discover", "running")


def test_reopen_database_keeps_single_rows(tmp_path):
    path = tmp_path / "reopen.db"
    db1 = Database(path)
    tid = db1.upsert_target("example.com")
    db1.upsert_schedule("nightly", tid)
    sid = db1.create_scan(tid)
    db1.upsert_phase_run(sid, "discover", "running")
    db1.close()

    db2 = Database(path)
    try:
        assert db2.upsert_target("example.com") == tid
        assert db2.upsert_schedule("nightly", tid) == db2.list_schedules()[0]["id"]
        assert db2.upsert_phase_run(sid, "discover", "running") == db2.get_phase_run(sid, "discover")["id"]
        assert db2.query("SELECT COUNT(*) AS c FROM targets")[0]["c"] == 1
        assert db2.query("SELECT COUNT(*) AS c FROM schedules")[0]["c"] == 1
        assert db2.query("SELECT COUNT(*) AS c FROM phase_runs")[0]["c"] == 1
    finally:
        db2.close()
