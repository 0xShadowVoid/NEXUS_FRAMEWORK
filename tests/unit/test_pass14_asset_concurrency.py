"""Concurrency regression tests for atomic asset/graph upserts (Pass 14).

The ``assets``/``asset_edges`` tables carry ``UNIQUE(kind, normalized)`` /
``UNIQUE(src_id, dst_id, relation)``. These tests prove the upserts are
conflict-safe under concurrency: no duplicate rows, no ``IntegrityError``,
no lost metadata, and distinct assets stay distinct. Concurrency is driven by
a ``threading.Barrier`` (all workers released together) — no arbitrary sleeps.
"""
from __future__ import annotations

import json
import sqlite3
import threading

import pytest

from core import migrations
from core.database import Database


def _run_concurrently(work, n: int):
    """Run ``work(i)`` on ``n`` threads released simultaneously.

    Returns ``(results, errors)`` in worker-index order.
    """
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


# -- repeated upserts ------------------------------------------------------


def test_repeated_upsert_is_idempotent(db: Database):
    a1, c1 = db.upsert_asset("subdomain", "API.example.com", "api.example.com", metadata={"a": 1})
    a2, c2 = db.upsert_asset("subdomain", "api.example.com", "api.example.com", metadata={"a": 2})
    a3, c3 = db.upsert_asset("subdomain", "api.example.com", "api.example.com")
    assert a1 == a2 == a3
    assert (c1, c2, c3) == (True, False, False)
    rows = db.query(
        "SELECT * FROM assets WHERE kind = ? AND normalized = ?", ("subdomain", "api.example.com")
    )
    assert len(rows) == 1
    assert json.loads(rows[0]["metadata"]) == {"a": 1}  # first write wins


# -- concurrent create of the same asset -----------------------------------


def test_concurrent_create_same_asset_shared_connection(db: Database):
    n = 16
    results, errors = _run_concurrently(
        lambda i: db.upsert_asset(
            "subdomain", "race.example.com", "race.example.com",
            source_tool=f"t{i}", metadata={"i": i},
        ),
        n,
    )
    assert errors == [None] * n
    assert len({r[0] for r in results}) == 1
    assert sum(1 for r in results if r[1] is True) == 1
    rows = db.query(
        "SELECT * FROM assets WHERE kind = ? AND normalized = ?", ("subdomain", "race.example.com")
    )
    assert len(rows) == 1


def test_concurrent_create_same_asset_across_connections(tmp_path):
    path = tmp_path / "race_multi.db"
    Database(path).close()  # create schema once, sequentially
    dbs = [Database(path) for _ in range(8)]
    try:
        results, errors = _run_concurrently(
            lambda i: dbs[i].upsert_asset("subdomain", "multi.example.com", "multi.example.com"),
            len(dbs),
        )
        assert errors == [None] * len(dbs)
        assert len({r[0] for r in results}) == 1
        assert sum(1 for r in results if r[1] is True) == 1
        count = dbs[0].query(
            "SELECT COUNT(*) AS c FROM assets WHERE kind = ? AND normalized = ?",
            ("subdomain", "multi.example.com"),
        )
        assert count[0]["c"] == 1
    finally:
        for d in dbs:
            d.close()


# -- concurrent updates to an existing asset -------------------------------


def test_concurrent_updates_preserve_identity_and_metadata(db: Database):
    asset_id, created = db.upsert_asset(
        "host", "upd.example.com", "upd.example.com", metadata={"keep": True}
    )
    assert created is True

    n = 16
    results, errors = _run_concurrently(
        lambda i: db.upsert_asset(
            "host", "upd.example.com", "upd.example.com",
            source_tool=f"x{i}", metadata={"i": i},
        ),
        n,
    )
    assert errors == [None] * n
    assert {r[0] for r in results} == {asset_id}
    assert all(r[1] is False for r in results)

    rows = db.query("SELECT * FROM assets WHERE id = ?", (asset_id,))
    assert len(rows) == 1
    assert json.loads(rows[0]["metadata"]) == {"keep": True}  # not clobbered
    assert rows[0]["source_tool"] == ""                       # not overwritten
    assert rows[0]["last_seen"]                                # refreshed


# -- distinct assets stay distinct -----------------------------------------


def test_concurrent_distinct_assets_all_persisted(db: Database):
    n = 24
    results, errors = _run_concurrently(
        lambda i: db.upsert_asset("subdomain", f"h{i}.example.com", f"h{i}.example.com"),
        n,
    )
    assert errors == [None] * n
    assert len({r[0] for r in results}) == n
    assert all(r[1] is True for r in results)
    assert db.query("SELECT COUNT(*) AS c FROM assets")[0]["c"] == n


# -- graph relationships ---------------------------------------------------


def test_repeated_upsert_edge_is_idempotent(db: Database):
    a, _ = db.upsert_asset("domain", "example.com", "example.com")
    b, _ = db.upsert_asset("subdomain", "api.example.com", "api.example.com")
    e1, c1 = db.upsert_edge(a, b, "has_subdomain")
    e2, c2 = db.upsert_edge(a, b, "has_subdomain")
    assert e1 == e2 and c1 is True and c2 is False
    assert db.query("SELECT COUNT(*) AS c FROM asset_edges")[0]["c"] == 1


def test_concurrent_edges_single_row(db: Database):
    a, _ = db.upsert_asset("domain", "example.com", "example.com")
    b, _ = db.upsert_asset("subdomain", "api.example.com", "api.example.com")
    n = 16
    results, errors = _run_concurrently(
        lambda i: db.upsert_edge(a, b, "has_subdomain", source_tool=f"t{i}"), n
    )
    assert errors == [None] * n
    assert len({r[0] for r in results}) == 1
    assert sum(1 for r in results if r[1] is True) == 1
    assert db.query("SELECT COUNT(*) AS c FROM asset_edges")[0]["c"] == 1


def test_concurrent_graph_relationships_consistent(db: Database):
    root, _ = db.upsert_asset("domain", "example.com", "example.com")
    n = 20

    def work(i: int):
        aid, _ = db.upsert_asset("subdomain", f"s{i}.example.com", f"s{i}.example.com")
        db.upsert_edge(root, aid, "has_subdomain")
        return aid

    results, errors = _run_concurrently(work, n)
    assert errors == [None] * n
    assert len(set(results)) == n
    assert db.query("SELECT COUNT(*) AS c FROM assets WHERE kind = 'subdomain'")[0]["c"] == n
    assert db.query(
        "SELECT COUNT(*) AS c FROM asset_edges WHERE relation = 'has_subdomain'"
    )[0]["c"] == n


# -- contention + error propagation ----------------------------------------


def test_cross_connection_contention_completes(tmp_path):
    path = tmp_path / "contention.db"
    Database(path).close()
    dbs = [Database(path) for _ in range(6)]
    try:
        results, errors = _run_concurrently(
            lambda i: dbs[i].upsert_asset("subdomain", f"c{i}.example.com", f"c{i}.example.com"),
            len(dbs),
        )
        assert errors == [None] * len(dbs)
        assert all(r[1] is True for r in results)
        assert dbs[0].query("SELECT COUNT(*) AS c FROM assets")[0]["c"] == len(dbs)
    finally:
        for d in dbs:
            d.close()


def test_database_errors_are_not_suppressed(tmp_path):
    db = Database(tmp_path / "err.db")
    db.close()
    with pytest.raises(sqlite3.ProgrammingError):
        db.upsert_asset("subdomain", "x.example.com", "x.example.com")


# -- schema / compatibility ------------------------------------------------


def test_assets_unique_constraint_is_the_atomicity_backstop(tmp_path):
    db = Database(tmp_path / "unique.db")
    db.execute("INSERT INTO assets (kind, normalized) VALUES ('host', 'u.example.com')")
    with pytest.raises(sqlite3.IntegrityError):
        db.execute("INSERT INTO assets (kind, normalized) VALUES ('host', 'u.example.com')")
    db.close()


def test_reopen_existing_database_keeps_dedup_and_metadata(tmp_path):
    path = tmp_path / "compat.db"
    db1 = Database(path)
    a1, c1 = db1.upsert_asset(
        "host", "compat.example.com", "compat.example.com", metadata={"k": "v"}
    )
    db1.close()

    db2 = Database(path)  # additive migration is idempotent
    a2, c2 = db2.upsert_asset("host", "compat.example.com", "compat.example.com")
    assert c1 is True and c2 is False and a1 == a2
    assert db2.schema_version == migrations.TARGET
    row = db2.get_asset("host", "compat.example.com")
    assert json.loads(row["metadata"]) == {"k": "v"}
    db2.close()


def test_legacy_v1_database_migrates_and_dedups(tmp_path):
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(path))
    conn.executescript(
        """
        CREATE TABLE targets (id INTEGER PRIMARY KEY, domain TEXT UNIQUE);
        CREATE TABLE scans (id INTEGER PRIMARY KEY, target_id INTEGER);
        CREATE TABLE findings (id INTEGER PRIMARY KEY, scan_id INTEGER);
        CREATE TABLE chains (id INTEGER PRIMARY KEY, scan_id INTEGER);
        CREATE TABLE schedules (id INTEGER PRIMARY KEY, name TEXT UNIQUE);
        CREATE TABLE high_value_alerts (id INTEGER PRIMARY KEY, finding_id INTEGER);
        CREATE TABLE screenshots (id INTEGER PRIMARY KEY, finding_id INTEGER);
        CREATE TABLE cves (id INTEGER PRIMARY KEY, cve_id TEXT UNIQUE);
        """
    )
    conn.commit()
    conn.close()

    db = Database(path)
    try:
        assert db.schema_version == migrations.TARGET
        assert db.get_asset("host", "legacy.example.com") is None
        a1, c1 = db.upsert_asset("host", "legacy.example.com", "legacy.example.com")
        a2, c2 = db.upsert_asset("host", "legacy.example.com", "legacy.example.com")
        assert a1 == a2 and c1 is True and c2 is False
    finally:
        db.close()
