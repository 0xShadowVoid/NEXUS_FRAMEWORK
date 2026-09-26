"""Integration: Phase 1 → 2 → 3 flow and the analyze pipeline."""
from __future__ import annotations

import json
from pathlib import Path

from core.analyzer import Analyzer
from core.database import Database
from lib.config import Config


def _raw_findings():
    return [
        # duplicate pair (nuclei + dalfox) — should merge
        {"endpoint": "https://example.com/search?q=1", "vuln_type": "reflected_xss",
         "confidence": 70, "payload": "<img src=x onerror=alert(1)>",
         "response_snippet": "reflected: <img src=x onerror=alert(1)>",
         "tools_found": ["nuclei"], "severity": "P3"},
        {"endpoint": "https://example.com/search?q=1", "vuln_type": "reflected_xss",
         "confidence": 70, "payload": "", "response_snippet": "x",
         "tools_found": ["dalfox"], "severity": "P3"},
        # OOS finding — must be blocked
        {"endpoint": "https://evil.com/x", "vuln_type": "sqli",
         "confidence": 90, "tools_found": ["sqlmap"], "severity": "P1"},
        # stored XSS on admin surface → chain
        {"endpoint": "https://example.com/admin/comments", "vuln_type": "stored_xss",
         "confidence": 95, "tools_found": ["nuclei"], "severity": "P2"},
    ]


def test_analyze_pipeline_end_to_end(tmp_cfg: Config, tmp_path: Path):
    db = Database(tmp_path / "t.sqlite")
    scan_id = db.create_scan(db.upsert_target("example.com"))
    analyzer = Analyzer(tmp_cfg, db)
    results_dir = tmp_path / "results" / "example.com-run"
    results_dir.mkdir(parents=True)

    metrics = analyzer.run(
        raw_findings=_raw_findings(),
        target_config=tmp_cfg.target("example.com"),
        scan_id=scan_id,
        results_dir=results_dir,
        urls_discovered=10,
        endpoints_tested=8,
        duration_seconds=5,
    )

    # Dedup merged the duplicate pair.
    assert metrics["dedup"]["duplicates_merged"] >= 1
    assert metrics["findings_total"] == 3          # 4 raw → 3 after dedup
    assert metrics["findings_oos"] == 1            # evil.com blocked
    assert metrics["chains_detected"] >= 1         # stored XSS → RCE chain

    # Outputs written.
    for name in ("findings.json", "chains.json", "high_value_findings.json", "metrics.json"):
        assert (results_dir / "processed" / name).exists()

    # DB persisted with scope flags.
    rows = db.query_findings(scan_id=scan_id)
    oos = [r for r in rows if r["in_scope"] == 0]
    assert len(oos) == 1 and oos[0]["endpoint"].endswith("evil.com/x")

    # Chains persisted.
    assert db.query_chains(scan_id)

    # Scan row updated.
    scan = db.get_scan(scan_id)
    assert scan["status"] == "completed"


def test_analyze_marks_false_positive(tmp_cfg: Config, tmp_path: Path):
    db = Database(tmp_path / "t.sqlite")
    scan_id = db.create_scan(db.upsert_target("example.com"))
    analyzer = Analyzer(tmp_cfg, db)
    results_dir = tmp_path / "r"
    results_dir.mkdir()

    raw = [
        # aggressive xss threshold 90 → 50 is a false positive
        {"endpoint": "https://example.com/a", "vuln_type": "xss", "confidence": 50,
         "tools_found": ["nuclei"], "response_snippet": "nothing"},
    ]
    metrics = analyzer.run(raw, tmp_cfg.target("example.com"), scan_id, results_dir)
    assert metrics["false_positives"] == 1
    findings = json.loads((results_dir / "processed" / "findings.json").read_text(encoding="utf-8"))
    assert findings[0]["valid"] is False


def test_severity_exclusion_filters(tmp_cfg: Config, tmp_path: Path):
    db = Database(tmp_path / "t.sqlite")
    scan_id = db.create_scan(db.upsert_target("example.com"))
    analyzer = Analyzer(tmp_cfg, db)
    results_dir = tmp_path / "r"
    results_dir.mkdir()

    raw = [
        {"endpoint": "https://example.com/a", "vuln_type": "sqli", "confidence": 90,
         "tools_found": ["sqlmap"], "severity": "P1"},
        {"endpoint": "https://example.com/b", "vuln_type": "info_disclosure", "confidence": 70,
         "tools_found": ["nuclei"], "severity": "P4"},
    ]
    metrics = analyzer.run(
        raw, tmp_cfg.target("example.com"), scan_id, results_dir,
        min_severity="P2", exclude_p4=True,
    )
    # Only the P1 survives (P4 excluded, nothing worse than P2 allowed).
    assert metrics["findings_total"] == 1
    assert metrics["filtered_out"] == 1


def test_evidence_is_sanitized_in_output(tmp_cfg: Config, tmp_path: Path):
    db = Database(tmp_path / "t.sqlite")
    scan_id = db.create_scan(db.upsert_target("example.com"))
    analyzer = Analyzer(tmp_cfg, db)
    results_dir = tmp_path / "r"
    results_dir.mkdir()

    raw = [{
        "endpoint": "https://example.com/a", "vuln_type": "sqli", "confidence": 90,
        "tools_found": ["sqlmap"],
        "response_snippet": "Set-Cookie: session=TOPSECRET\nSQL syntax error near '1'",
    }]
    analyzer.run(raw, tmp_cfg.target("example.com"), scan_id, results_dir)
    findings = json.loads((results_dir / "processed" / "findings.json").read_text(encoding="utf-8"))
    assert "TOPSECRET" not in findings[0]["response_snippet"]
    assert "SQL syntax" in findings[0]["response_snippet"]
