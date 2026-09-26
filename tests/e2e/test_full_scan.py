"""End-to-end: full scan, batch, scheduling and CLI (all offline)."""
from __future__ import annotations

import json
from pathlib import Path

from core.coordinator import Coordinator, ScanOptions
from core.database import Database
from lib.config import Config
import nexus


def _patch_phases(monkeypatch, tmp_path: Path):
    """Replace discover/probe with deterministic offline doubles."""

    def fake_discover(cfg, target_config, results_dir, **kwargs):
        (results_dir / "recon").mkdir(parents=True, exist_ok=True)
        summary = {
            "domain": target_config.domain,
            "urls": [f"https://{target_config.domain}/", f"https://{target_config.domain}/search?q=1"],
            "pegpon": {"subdomains": [target_config.domain]},
            "wappalyzer": {"tech": {"WordPress": "6.0"}},
        }
        (results_dir / "recon" / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
        (results_dir / "recon" / "tech_stack.json").write_text(
            json.dumps({"url": f"https://{target_config.domain}/", "tech": {"WordPress": "6.0"}}),
            encoding="utf-8",
        )
        return summary

    def fake_probe(cfg, target_config, results_dir, urls, tech, **kwargs):
        (results_dir / "scans").mkdir(parents=True, exist_ok=True)
        findings = [{
            "endpoint": f"https://{target_config.domain}/search?q=1",
            "vuln_type": "reflected_xss",
            "confidence": 95,
            "payload": "<img src=x onerror=alert(1)>",
            "response_snippet": "reflected payload in body",
            "tools_found": ["nuclei", "dalfox"],
            "severity": "P3",
        }]
        (results_dir / "scans" / "raw_findings.json").write_text(json.dumps(findings), encoding="utf-8")
        return findings

    monkeypatch.setattr("phases.discover.recon_orchestrator.run_discover", fake_discover)
    monkeypatch.setattr("phases.probe.probe_orchestrator.run_probe", fake_probe)


def test_full_scan_single_target(tmp_path: Path, monkeypatch):
    from lib.config import load_config

    cfg = load_config(Path(__file__).resolve().parent.parent.parent / "config")
    cfg._main["database"] = {"path": str(tmp_path / "e2e.db")}
    db = Database(tmp_path / "e2e.db")
    coord = Coordinator(cfg, db=db, results_base=tmp_path / "results")
    _patch_phases(monkeypatch, tmp_path)

    result = coord.run_scan(ScanOptions(target="example.com"))
    assert result["status"] == "completed"
    assert result["phases"]["discover"]["urls"] == 2
    assert result["phases"]["analyze"]["findings_total"] == 1

    results_dir = Path(result["results_dir"])
    assert (results_dir / "processed" / "findings.json").exists()
    assert Path(result["report"]).exists()
    report_text = Path(result["report"]).read_text(encoding="utf-8")
    assert "NEXUS Findings Report" in report_text

    # DB persisted.
    assert db.query_findings(scan_id=result["scan_id"])


def test_discover_only_mode(tmp_path: Path, monkeypatch):
    from lib.config import load_config

    cfg = load_config(Path(__file__).resolve().parent.parent.parent / "config")
    db = Database(tmp_path / "e2e.db")
    coord = Coordinator(cfg, db=db, results_base=tmp_path / "results")
    _patch_phases(monkeypatch, tmp_path)

    result = coord.run_scan(ScanOptions(target="example.com", discover_only=True))
    assert result["status"] == "discover-only"
    assert "probe" not in result["phases"]


def test_batch_scan_per_target_options(tmp_path: Path, monkeypatch):
    from lib.config import load_config

    cfg = load_config(Path(__file__).resolve().parent.parent.parent / "config")
    db = Database(tmp_path / "e2e.db")
    coord = Coordinator(cfg, db=db, results_base=tmp_path / "results")
    _patch_phases(monkeypatch, tmp_path)

    targets = ["example.com", "startup.com"]
    results = coord.run_batch(
        targets,
        options_factory=lambda t: ScanOptions(target=t),
        concurrent=2,
        sequential=False,
    )
    assert len(results) == 2
    assert all(r["status"] == "completed" for r in results)


def test_scheduling_create_due_and_run(tmp_path: Path, monkeypatch):
    from lib.config import load_config

    cfg = load_config(Path(__file__).resolve().parent.parent.parent / "config")
    db = Database(tmp_path / "e2e.db")
    coord = Coordinator(cfg, db=db, results_base=tmp_path / "results")
    _patch_phases(monkeypatch, tmp_path)

    tid = db.upsert_target("example.com")
    next_run = coord.compute_next_run("0 2 * * *")
    db.upsert_schedule("nightly", tid, frequency="custom", cron_expression="0 2 * * *", next_run="2000-01-01T00:00:00+00:00")

    due = coord.due_schedules()
    assert any(s["name"] == "nightly" for s in due)

    out = coord.run_schedule("nightly")
    assert out["status"] == "ran"
    assert db.list_schedules()[0]["last_run"]


def test_diff_scans(tmp_path: Path):
    db = Database(tmp_path / "d.db")
    tid = db.upsert_target("example.com")
    s1 = db.create_scan(tid)
    s2 = db.create_scan(tid)
    db.insert_finding(s1, "https://example.com/a", "xss", "P2", 90, valid=True)
    db.insert_finding(s2, "https://example.com/a", "xss", "P2", 90, valid=True)
    db.insert_finding(s2, "https://example.com/b", "sqli", "P1", 90, valid=True)
    diff = Coordinator.__new__(Coordinator)
    diff.db = db
    result = diff.diff_scans(s1, s2)
    assert result["new"] and not result["resolved"]


def test_verify_finding(tmp_path: Path):
    db = Database(tmp_path / "v.db")
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid)
    fid = db.insert_finding(sid, "https://example.com/a", "xss", "P2", 90)
    coord = Coordinator.__new__(Coordinator)
    coord.db = db
    assert coord.verify_finding(fid)["status"] == "verified"
    assert db.query_findings(scan_id=sid)[0]["reviewed"] == 1


def test_cli_check_tools_and_ai_keys(capsys):
    assert nexus.main(["check-tools"]) == 0
    out = capsys.readouterr().out
    assert "installed" in out

    assert nexus.main(["ai-keys"]) == 0
    out = capsys.readouterr().out
    assert "keys" in out


def test_cli_version(capsys):
    import pytest

    with pytest.raises(SystemExit) as exc:
        nexus.main(["--version"])
    assert exc.value.code == 0


def test_cli_targets_file_parsing(tmp_path: Path):
    f = tmp_path / "targets.txt"
    f.write_text(
        "# comment\n"
        "example.com\n"
        'startup.com {"intensity": "full-scan", "tools": ["nuclei"], "rate_limit": "10/minute"}\n',
        encoding="utf-8",
    )
    entries = nexus.parse_targets_file(f)
    assert entries[0] == ("example.com", {})
    assert entries[1][0] == "startup.com"
    assert entries[1][1]["intensity"] == "full-scan"
