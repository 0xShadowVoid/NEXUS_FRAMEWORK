"""Unit tests for HTML export + intel alerts (drift / new tech)."""
from __future__ import annotations

import json
from pathlib import Path

from core.coordinator import Coordinator, ScanOptions
from core.database import Database
from core.exporter import export_html, export_findings
from lib.config import load_config

REPO = Path(__file__).resolve().parent.parent.parent


# --- HTML export ----------------------------------------------------------


def test_export_html_escapes_payload(tmp_path: Path):
    findings = [{
        "severity": "P3", "vuln_type": "xss", "endpoint": "https://x/a",
        "confidence": 90, "tools_found": ["nuclei"],
        "payload": "<script>alert(1)</script>", "response_snippet": "reflected",
    }]
    path = export_html("example.com", findings, [], {"findings_total": 1}, out_base=tmp_path)
    text = path.read_text(encoding="utf-8")
    assert path.exists()
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;" in text


def test_export_findings_html_via_router(tmp_path: Path):
    db = Database(tmp_path / "s.db")
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid)
    db.insert_finding(sid, "https://example.com/a", "xss", "P2", 90, valid=True)
    path = export_findings(
        "example.com", db.list_scans(target_id=tid), db.query_findings(scan_id=sid), [],
        fmt="html", out_base=tmp_path,
    )
    assert path.suffix == ".html" and path.exists()


# --- intel alerts (drift + new tech) --------------------------------------


def _make_coordinator(tmp_path, cfg):
    cfg._main["database"] = {"path": str(tmp_path / "i.db")}
    db = Database(tmp_path / "i.db")
    coord = Coordinator(cfg, db=db, results_base=tmp_path / "results")
    return coord


def test_new_tech_detection_alerts(tmp_path, monkeypatch):
    cfg = load_config(REPO / "config")
    coord = _make_coordinator(tmp_path, cfg)
    (tmp_path / "results").mkdir(exist_ok=True)
    (tmp_path / "results" / ".tech_state.json").write_text(
        json.dumps({"tech": {"WordPress": "6.0"}}), encoding="utf-8"
    )

    captured = []
    monkeypatch.setattr("lib.notifications.Notifier.send_info_alert",
                        lambda self, title, body: captured.append((title, body)))
    monkeypatch.setattr("lib.notifications.Notifier.send_info_telegram",
                        lambda self, title, body: None)

    options = ScanOptions(target="example.com")
    intel = coord._post_scan_intel(
        options, tmp_path / "results", "example.com",
        tech={"WordPress": "6.0", "Nginx": "1.24"}, tools_run=["subfinder"],
    )
    assert intel["new_tech"] == ["Nginx"]
    assert any("New tech" in t for t, _b in captured)


def test_methodology_drift_alerts(tmp_path, monkeypatch):
    cfg = load_config(REPO / "config")
    coord = _make_coordinator(tmp_path, cfg)
    (tmp_path / "results").mkdir(exist_ok=True)
    # Pre-seed a DIFFERENT hash so drift triggers on first intel run.
    (tmp_path / "results" / ".methodology_state.json").write_text(
        json.dumps({"hash": "deadbeef00000000"}), encoding="utf-8"
    )

    captured = []
    monkeypatch.setattr("lib.notifications.Notifier.send_info_alert",
                        lambda self, title, body: captured.append((title, body)))
    monkeypatch.setattr("lib.notifications.Notifier.send_info_telegram",
                        lambda self, title, body: None)

    options = ScanOptions(target="example.com", methodology="web_app_checklist")
    intel = coord._post_scan_intel(
        options, tmp_path / "results", "example.com", tech={}, tools_run=["subfinder", "dalfox"],
    )
    assert intel["methodology"]["drift"] is True
    assert any("Methodology changed" in t for t, _b in captured)
