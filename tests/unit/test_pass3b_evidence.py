"""Pass 3B — evidence linkage + sanitization enforcement tests."""
from __future__ import annotations

from core.database import Database
from core.sanitizer import (
    EVIDENCE_MAX_LENGTH,
    sanitize_evidence_record,
    sanitize_headers,
)


def _scan(db: Database):
    tid = db.upsert_target("example.com")
    return db.create_scan(tid)


def test_sanitize_headers_redacts_credentials():
    headers = {
        "Authorization": "Bearer sk-secret-value-1234567890",
        "Cookie": "session=abcdef123456",
        "Set-Cookie": "session=abcdef123456; HttpOnly",
        "X-Api-Key": "AKIAABCDEFGHIJKLMNOP",
        "X-Trace": "keep-me",
    }
    out = sanitize_headers(headers)
    for key in ("Authorization", "Cookie", "Set-Cookie", "X-Api-Key"):
        assert out[key] == "[REDACTED]"
    assert out["X-Trace"] == "keep-me"


def test_insert_evidence_redacts_before_persistence(db):
    sid = _scan(db)
    db.insert_evidence(
        sid,
        url="https://example.com/api?token=abcdef",
        method="GET",
        request_headers={"Authorization": "Bearer abcdef0123456789", "Accept": "application/json"},
        request_body='{"password": "hunter2"}',
        status_code=200,
        response_headers={"Set-Cookie": "sid=secret123", "Content-Type": "application/json"},
        response_body='{"token": "abcdef0123456789", "note": "openai key sk-ABCDEF0123456789abcd"}',
        tool="probe",
        source="probe",
    )
    row = db.query_evidence(scan_id=sid)[0]
    blob = repr(row)
    assert "abcdef0123456789" not in blob
    assert "secret123" not in blob
    assert "hunter2" not in blob
    assert row["request_headers"]["Authorization"] == "[REDACTED]"
    assert row["response_headers"]["Set-Cookie"] == "[REDACTED]"
    assert row["sanitized"] == 1
    # reproducibility context stays intact
    assert row["url"].startswith("https://example.com/api")
    assert row["status_code"] == 200 and row["method"] == "GET"


def test_evidence_finding_linkage_roundtrip(db):
    sid = _scan(db)
    fid = db.insert_finding(sid, "https://example.com/a", "xss", "P2", 90)
    eid = db.insert_evidence(sid, url="https://example.com/a", response_body="proof")
    assert db.query_evidence(finding_id=fid) == []
    assert db.set_evidence_finding(eid, fid) is True
    linked = db.query_evidence(finding_id=fid)
    assert [r["id"] for r in linked] == [eid]
    assert any(r["finding_id"] == fid for r in db.query_evidence(scan_id=sid))


def test_sanitize_record_keeps_repro_context():
    req_h, req_b, resp_h, resp_b = sanitize_evidence_record(
        {"Authorization": "Bearer x"}, "user=admin", {"Set-Cookie": "a=b"}, "hello world"
    )
    assert req_h["Authorization"] == "[REDACTED]"
    assert resp_h["Set-Cookie"] == "[REDACTED]"
    assert "user=admin" in req_b
    assert "hello world" in resp_b


def test_evidence_cap_is_generous_but_bounded():
    body = "x" * (EVIDENCE_MAX_LENGTH - 1)
    _, _, _, out = sanitize_evidence_record(None, "", None, body)
    assert out == body
    _, _, _, out2 = sanitize_evidence_record(None, "", None, body + "x")
    assert len(out2) <= EVIDENCE_MAX_LENGTH + len("\u2026[truncated]")


def test_evidence_asset_linkage(db):
    sid = _scan(db)
    asset_id, _created = db.upsert_asset("host", "example.com", "example.com")
    eid = db.insert_evidence(sid, url="https://example.com/a", response_body="proof")
    link_id = db.set_evidence_asset(eid, asset_id)
    assert link_id
    rows = db.query("SELECT * FROM evidence_assets WHERE evidence_id = ?", (eid,))
    assert rows and rows[0]["asset_id"] == asset_id
    assert rows[0]["relation"] == "observed-on"
