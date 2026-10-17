"""Concurrency regression tests for the CVE dedup guard (Pass 18).

``get_or_create_cve`` used a read-then-write (``SELECT`` then ``INSERT``) and
``cves.cve_id`` is ``UNIQUE``, so two callers could both miss the row and both
insert — one raising ``IntegrityError``. The fix uses a single conflict-safe
``INSERT ... ON CONFLICT(cve_id) DO NOTHING`` plus a fallback ``SELECT`` id.

Existing records are never modified (the former contract: an already-known CVE
is a pure dedup hit returning ``created=False``), so ``DO NOTHING`` — not
``DO UPDATE`` — is the behavior-preserving choice.

Concurrency is driven by a ``threading.Barrier`` — no sleeps.
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


def _cve_count(db: Database) -> int:
    return db.query("SELECT COUNT(*) AS c FROM cves")[0]["c"]


# -- behavior -----------------------------------------------------------------


def test_repeated_get_or_create_is_idempotent(db: Database):
    rid, created = db.get_or_create_cve(
        "CVE-2026-0001", severity="critical", description="d", published="2026-01-01",
        tech_matched="wordpress",
    )
    assert created is True
    rid2, created2 = db.get_or_create_cve("CVE-2026-0001")
    assert created2 is False and rid2 == rid
    assert _cve_count(db) == 1


def test_existing_record_metadata_is_preserved(db: Database):
    rid, _ = db.get_or_create_cve(
        "CVE-2026-0001", severity="critical", description="original",
        published="2026-01-01", tech_matched="nginx",
    )
    before = db.query("SELECT * FROM cves WHERE id = ?", (rid,))[0]

    rid2, created = db.get_or_create_cve(
        "CVE-2026-0001", severity="low", description="changed",
        published="2099-09-09", tech_matched="other",
    )
    after = db.query("SELECT * FROM cves WHERE id = ?", (rid2,))[0]

    assert created is False and rid2 == rid
    assert after == before  # no metadata update on an existing CVE
    assert after["severity"] == "critical"
    assert after["description"] == "original"
    assert after["poc_generated"] == 0


def test_mark_helpers_and_listing_still_work(db: Database):
    rid, _ = db.get_or_create_cve("CVE-2026-0002", severity="high")
    db.mark_cve_poc_generated(rid)
    db.mark_cve_alerted(rid)
    row = db.list_cves()[0]
    assert row["poc_generated"] == 1 and row["alerted_at"]
    assert db.list_cves(severity="high")[0]["cve_id"] == "CVE-2026-0002"
    assert db.list_cves(severity="low") == []


# -- concurrency: shared connection (the app's model) -------------------------


def test_concurrent_same_cve_shared_conn(db: Database):
    results, errors = _run_concurrently(lambda i: db.get_or_create_cve("CVE-2026-1234"), 16)
    assert errors == [None] * 16
    ids = {r[0] for r in results}
    assert len(ids) == 1
    assert sum(1 for r in results if r[1]) == 1  # exactly one creator
    assert _cve_count(db) == 1


def test_concurrent_distinct_cves(db: Database):
    results, errors = _run_concurrently(
        lambda i: db.get_or_create_cve(f"CVE-2026-{i:04d}"), 24
    )
    assert errors == [None] * 24
    assert len({r[0] for r in results}) == 24
    assert all(r[1] for r in results)  # each distinct CVE is newly created
    assert _cve_count(db) == 24


# -- concurrency: independent connections -------------------------------------


def test_concurrent_same_cve_across_connections(tmp_path):
    path = tmp_path / "cves.db"
    Database(path).close()  # create schema once, sequentially
    dbs = [Database(path) for _ in range(8)]
    try:
        results, errors = _run_concurrently(
            lambda i: dbs[i].get_or_create_cve("CVE-2026-7777"), len(dbs)
        )
        assert errors == [None] * len(dbs)
        assert len({r[0] for r in results}) == 1
        assert sum(1 for r in results if r[1]) == 1
        assert dbs[0].query("SELECT COUNT(*) AS c FROM cves")[0]["c"] == 1
    finally:
        for d in dbs:
            d.close()


# -- error propagation / integrity --------------------------------------------


def test_cve_unique_constraint_backstop(tmp_path):
    db = Database(tmp_path / "unique.db")
    try:
        db.execute(
            "INSERT INTO cves (cve_id, created_at) VALUES (?, ?)", ("CVE-2026-0003", "t")
        )
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO cves (cve_id, created_at) VALUES (?, ?)", ("CVE-2026-0003", "t")
            )
    finally:
        db.close()


def test_get_or_create_cve_surfaces_errors_after_close(tmp_path):
    db = Database(tmp_path / "err.db")
    db.close()
    with pytest.raises(sqlite3.ProgrammingError):
        db.get_or_create_cve("CVE-2026-0004")


def test_reopen_keeps_single_cve_row(tmp_path):
    path = tmp_path / "reopen.db"
    db1 = Database(path)
    rid, _ = db1.get_or_create_cve("CVE-2026-0005", severity="high")
    db1.close()

    db2 = Database(path)
    try:
        rid2, created = db2.get_or_create_cve("CVE-2026-0005")
        assert rid2 == rid and created is False
        assert db2.query("SELECT COUNT(*) AS c FROM cves")[0]["c"] == 1
    finally:
        db2.close()
