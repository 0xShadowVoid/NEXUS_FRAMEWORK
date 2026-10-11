"""Pass 3C — evidence auto asset-link + phase attribution tests."""
from __future__ import annotations

from core.database import EVIDENCE_PHASES, Database


def _scan(db: Database):
    return db.create_scan(db.upsert_target("example.com"))


def test_known_asset_auto_linked(db):
    sid = _scan(db)
    asset_id, _ = db.upsert_asset("subdomain", "api.example.com", "api.example.com")
    eid = db.insert_evidence(sid, url="https://api.example.com/v1/users", response_body="ok")
    rows = db.query("SELECT * FROM evidence_assets WHERE evidence_id = ?", (eid,))
    assert rows and rows[0]["asset_id"] == asset_id


def test_url_asset_priority_over_host(db):
    sid = _scan(db)
    url_id, _ = db.upsert_asset("url", "https://example.com/a", "example.com/a")
    db.upsert_asset("subdomain", "example.com", "example.com")
    eid = db.insert_evidence(sid, url="https://example.com/a", response_body="ok")
    rows = db.query("SELECT * FROM evidence_assets WHERE evidence_id = ?", (eid,))
    assert rows and rows[0]["asset_id"] == url_id


def test_unknown_asset_not_fabricated(db):
    sid = _scan(db)
    eid = db.insert_evidence(sid, url="https://nowhere.example/x", response_body="ok")
    assert db.query("SELECT * FROM evidence_assets WHERE evidence_id = ?", (eid,)) == []
    assert db.list_assets() == []


def test_duplicate_normalization_single_link(db):
    sid = _scan(db)
    asset_id, _ = db.upsert_asset("host", "dup.example.com", "dup.example.com")
    eid1 = db.insert_evidence(sid, url="https://DUP.example.com/x")
    eid2 = db.insert_evidence(sid, url="https://dup.example.com/y")
    rows = db.query("SELECT * FROM evidence_assets")
    linked = [r for r in rows if r["evidence_id"] in (eid1, eid2)]
    assert len(linked) == 2
    assert {r["asset_id"] for r in linked} == {asset_id}


def test_upsert_asset_dedup_normalized(db):
    a1, created1 = db.upsert_asset("subdomain", "API.example.com", "api.example.com")
    a2, created2 = db.upsert_asset("subdomain", "api.example.com", "api.example.com")
    assert a1 == a2 and created1 is True and created2 is False


def test_links_survive_reload(tmp_path):
    db1 = Database(tmp_path / "ev3c.db")
    sid = db1.create_scan(db1.upsert_target("example.com"))
    asset_id, _ = db1.upsert_asset("subdomain", "keep.example.com", "keep.example.com")
    eid = db1.insert_evidence(sid, url="https://keep.example.com/x", response_body="ok")
    db1.close()

    db2 = Database(tmp_path / "ev3c.db")
    rows = db2.query("SELECT * FROM evidence_assets WHERE evidence_id = ?", (eid,))
    assert rows and rows[0]["asset_id"] == asset_id
    assert db2.query_evidence(scan_id=sid)
    db2.close()


def test_phase_attribution_roundtrip(db):
    sid = _scan(db)
    for phase in EVIDENCE_PHASES:
        eid = db.insert_evidence(sid, url="https://example.com/x", source=phase, tool="unit")
        row = [r for r in db.query_evidence(scan_id=sid) if r["id"] == eid][0]
        assert row["source"] == phase
        assert row["tool"] == "unit"


def test_unknown_source_preserved_for_backward_compat(db):
    sid = _scan(db)
    eid = db.insert_evidence(sid, url="https://example.com/x", source="custom-legacy", tool="t")
    row = [r for r in db.query_evidence(scan_id=sid) if r["id"] == eid][0]
    assert row["source"] == "custom-legacy"
