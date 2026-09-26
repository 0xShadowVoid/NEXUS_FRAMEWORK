"""Integration: CVE workflow and export/import round-trip."""
from __future__ import annotations

import json
from pathlib import Path

from core.database import Database
from core.exporter import export_findings
from core.importer import import_file, load_payload
from lib.config import Config
from lib.cve_workflow import run_cve_update
from lib.cve_fetcher import CVEFetcher


class _FakeSession:
    def __init__(self, payload):
        self.payload = payload
        self.headers = {}

    def get(self, url, params=None, headers=None, timeout=None):
        class _R:
            status_code = 200

            @staticmethod
            def json():
                return self.payload

        return _R()


CVE_PAYLOAD = {
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2026-9999",
            "published": "2026-09-25T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Nginx RCE."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.9, "baseSeverity": "CRITICAL"}}]},
            "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:nginx:nginx:1.0:*:*:*:*:*:*:*"}]}]}],
        }
    }]
}


def test_cve_workflow_fetch_generate_alert(tmp_cfg: Config, tmp_path: Path, monkeypatch):
    db = Database(tmp_path / "cve.db")

    # Stub the NVD fetch.
    monkeypatch.setattr(
        "lib.cve_workflow.CVEFetcher",
        lambda api_key="": CVEFetcher(session=_FakeSession(CVE_PAYLOAD)),
    )

    summary = run_cve_update(
        tmp_cfg, db,
        tech_stack={"Nginx": "1.24"},
        poc_base=tmp_path / "pocs",
        notify=True,
    )
    assert summary["fetched"] == 1
    assert summary["matched"] == 1
    assert summary["pocs_generated"] == 1
    assert summary["templates_registered"] == 1

    # PoC artifacts exist.
    assert list((tmp_path / "pocs").rglob("CVE-2026-9999.py"))

    # CVE recorded once (dedup on second run).
    assert db.list_cves()[0]["cve_id"] == "CVE-2026-9999"
    summary2 = run_cve_update(tmp_cfg, db, tech_stack={"Nginx": "1.24"}, poc_base=tmp_path / "pocs2", notify=False)
    assert summary2["pocs_generated"] == 0  # already known


def test_export_import_roundtrip(tmp_cfg: Config, tmp_path: Path):
    db = Database(tmp_path / "src.db")
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid, intensity="quick-scan")
    db.insert_finding(sid, "https://example.com/a", "xss", "P2", 90, payload="<img>", tools_found=["nuclei"], valid=True)
    db.insert_finding(sid, "https://example.com/b", "sqli", "P1", 80, tools_found=["sqlmap"], valid=True)
    db.insert_chain(sid, [1, 2], "sqli_to_db_access", "Full DB", ["s1"], "P1")

    scans = db.list_scans(target_id=tid)
    findings = db.query_findings(scan_id=sid)
    chains = db.query_chains(sid)

    zip_path = export_findings("example.com", scans, findings, chains, fmt="zip", out_base=tmp_path / "exports")
    assert zip_path.exists() and zip_path.suffix == ".zip"

    payload = load_payload(zip_path)
    assert len(payload["findings"]) == 2

    # Import into a fresh DB.
    db2 = Database(tmp_path / "dst.db")
    summary = import_file(db2, zip_path, merge=True, target_domain="example.com")
    assert summary["findings"] == 2
    assert summary["chains"] == 1
    assert len(db2.query_findings()) == 2


def test_export_json_and_csv_and_7z(tmp_cfg: Config, tmp_path: Path):
    db = Database(tmp_path / "src.db")
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid)
    db.insert_finding(sid, "https://example.com/a", "xss", "P2", 90, tools_found=["nuclei"], valid=True)
    scans = db.list_scans(target_id=tid)
    findings = db.query_findings(scan_id=sid)

    j = export_findings("example.com", scans, findings, [], fmt="json", out_base=tmp_path / "e")
    c = export_findings("example.com", scans, findings, [], fmt="csv", out_base=tmp_path / "e")
    s = export_findings("example.com", scans, findings, [], fmt="7z", out_base=tmp_path / "e")
    assert j.exists() and c.exists() and s.exists()
    data = json.loads(j.read_text(encoding="utf-8"))
    assert data["findings"][0]["vuln_type"] == "xss"


def test_import_merge_skips_duplicates(tmp_cfg: Config, tmp_path: Path):
    db = Database(tmp_path / "src.db")
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid)
    db.insert_finding(sid, "https://example.com/a", "xss", "P2", 90, tools_found=[], valid=True)
    payload = {"findings": db.query_findings(scan_id=sid), "chains": [], "scans": []}

    from core.importer import import_payload

    # Import into a fresh DB → inserts.
    db2 = Database(tmp_path / "dst.db")
    first = import_payload(db2, payload, target_domain="example.com", merge=True)
    assert first["findings"] == 1
    # Re-import the same data with merge → de-duplicated (natural key).
    second = import_payload(db2, payload, target_domain="example.com", merge=True)
    assert second["skipped"] == 1
    assert second["findings"] == 0
