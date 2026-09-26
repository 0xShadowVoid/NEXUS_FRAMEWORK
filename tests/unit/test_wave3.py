"""Tests for Wave-3 finish: retention, monitor, graphql, draft, scale,
parallel tools, AI ollama/narrative, GHSA, CPE matcher."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from core.reporter import render_draft
from lib.ai_analyzer import AIAnalyzer
from lib.cve_poc_generator import generate_nuclei_template
from lib.graphql_probe import analyze_introspection
from lib.program_monitor import ProgramMonitor, diff_programs
from lib.retention import retention_report
from lib.threat_feeds import ThreatFeeds
from phases.probe.tool_runners import run_all_light_parallel
from phases.scale.master_coordinator import MasterCoordinator
from phases.scale.worker_manager import WorkerManager, WorkerSpec
from phases.probe.tool_runner import ToolResult


# --- retention (non-destructive) ------------------------------------------


def test_retention_reports_but_never_deletes(tmp_path):
    old = tmp_path / "old-scan"
    old.mkdir()
    (old / "findings.json").write_text("{}", encoding="utf-8")
    old_time = time.time() - 40 * 86400
    os.utime(old, (old_time, old_time))

    report = retention_report(base_dir=tmp_path, days=30)
    assert report["candidate_count"] == 1
    assert old.exists()  # nothing deleted
    assert "never deletes" in report["note"]


def test_retention_empty_dir(tmp_path):
    assert retention_report(base_dir=tmp_path, days=30)["candidate_count"] == 0


# --- program monitor -------------------------------------------------------


def test_diff_programs():
    prev = [{"name": "A", "platform": "h1", "in_scope": ["a.com"], "type": "bb"}]
    cur = [
        {"name": "A", "platform": "h1", "in_scope": ["a.com", "b.com"], "type": "bb"},
        {"name": "B", "platform": "h1", "in_scope": [], "type": "vdp"},
    ]
    diff = diff_programs(prev, cur)
    assert diff["new"] == ["h1:B"]
    assert diff["changed"] == ["h1:A"]


def test_program_monitor_check_persists(tmp_path):
    mon = ProgramMonitor(tmp_path)
    mon.check([{"name": "A", "platform": "h1", "in_scope": [], "type": "bb"}])
    diff = mon.check([{"name": "A", "platform": "h1", "in_scope": [], "type": "bb"}])
    assert diff == {"new": [], "removed": [], "changed": []}


# --- graphql probe ---------------------------------------------------------


def test_graphql_introspection_analysis():
    introspection = {"data": {"__schema": {"types": [
        {"name": "Query", "fields": [{"name": "me"}]},
        {"name": "UserPassword", "fields": []},
        {"name": "Mutation", "fields": [{"name": "deleteUser"}]},
    ]}}}
    findings = analyze_introspection(introspection)
    assert any(f["payload"] == "introspection enabled" for f in findings)
    assert any("UserPassword" in f.get("response_snippet", "") for f in findings)


# --- submission draft ------------------------------------------------------


def test_render_draft_contains_preamble_and_sanitized_finding():
    text = render_draft(
        "hackerone", "example.com",
        {"vuln_type": "xss", "severity": "P2", "endpoint": "https://x/a",
         "confidence": 90, "payload": "<script>alert(1)</script>",
         "response_snippet": "Set-Cookie: a=b\nreflected", "tools_found": ["nuclei"]},
        metrics={"findings_total": 3, "findings_valid": 2},
    )
    assert "Submission Draft" in text
    assert "HackerOne Submission Notes" in text
    assert "Set-Cookie: a=b" not in text          # cookie redacted
    assert "[REDACTED]" in text                   # redaction marker present
    assert "<script>alert(1)</script>" in text    # payload IS the proof


# --- scale (functional local) ---------------------------------------------


def test_master_coordinator_run_local():
    master = MasterCoordinator(scan_fn=lambda t: {"ok": t.get("_id")})
    for i in range(4):
        master.submit({"target": f"t{i}"})
    result = master.run_local(max_workers=2)
    assert result["completed"] == 4
    assert len(result["results"]) == 4
    assert master.status()["pending"] == 0


def test_worker_manager_execute():
    wm = WorkerManager(scan_fn=lambda t: {"done": t["x"]})
    wm.add(WorkerSpec(worker_id="w1"))
    assert wm.execute({"x": 1}) == {"done": 1}
    assert wm.status()["workers"] == 1


def test_master_dispatch_remote_not_implemented():
    master = MasterCoordinator()
    try:
        master.dispatch_remote({"target": "x"})
        assert False, "should raise"
    except NotImplementedError:
        pass


# --- parallel light tools --------------------------------------------------


def test_parallel_light_no_tools_returns_empty():
    class _R:
        def __init__(self):
            self.calls = []

        def tool_available(self, tool):
            return False

        def run(self, tool, args, stdin_data=None, env=None):
            return ToolResult(tool=tool, cmd=[tool], returncode=None, status="not_found")

    findings = run_all_light_parallel("x.com", ["https://x.com/"], _R(), max_workers=3)
    assert findings == []


# --- AI ollama + narrative -------------------------------------------------


def test_ollama_provider_wired_keyless():
    analyzer = AIAnalyzer(env={}, providers=["ollama"])
    assert analyzer.base_url_for("ollama") == "http://localhost:11434/v1"
    assert analyzer.model_for("ollama") == "llama3.1"
    assert analyzer.available() is True  # keyless provider usable


def test_write_narrative(monkeypatch):
    analyzer = AIAnalyzer(env={"OPENAI_API_KEY": "k"}, providers=["openai"])

    def fake_post(url, headers=None, json=None, timeout=None):
        class _R:
            status_code = 200

            @staticmethod
            def json():
                return {"choices": [{"message": {"content": '{"summary":"s","bullets":["b1"]}'}}]}

        return _R()

    monkeypatch.setattr("lib.ai_analyzer.requests.post", fake_post)
    result = analyzer.write_narrative([{"vuln_type": "xss", "severity": "P2"}])
    assert result == {"summary": "s", "bullets": ["b1"]}


# --- GHSA feed -------------------------------------------------------------


def test_fetch_ghsa_parses(monkeypatch):
    class _S:
        def get(self, url, params=None, timeout=None):
            class _R:
                status_code = 200

                @staticmethod
                def json():
                    return [{"ghsa_id": "GHSA-1", "severity": "high",
                             "summary": "s", "ecosystem": "pip",
                             "identifiers": [{"type": "CVE", "value": "CVE-2026-1"}]}]
            return _R()

    feeds = ThreatFeeds(session=_S())
    advisories = feeds.fetch_ghsa(ecosystem="pip")
    assert advisories and advisories[0]["cve_ids"] == ["CVE-2026-1"]


# --- CPE matcher in PoC ----------------------------------------------------


def test_nuclei_template_includes_cpe_matcher():
    tpl = generate_nuclei_template({
        "cve_id": "CVE-2026-9", "severity": "high", "description": "x",
        "version_marker": "M", "cpe": "cpe:2.3:a:acme:server:1.0:*:*:*:*:*:*:*",
    })
    assert "type: cpe" in tpl
    assert "cpe:2.3:a:acme:server" in tpl


def test_nuclei_template_without_cpe_still_valid():
    import yaml

    tpl = generate_nuclei_template({"cve_id": "CVE-2026-8", "description": "x", "version_marker": "M"})
    doc = yaml.safe_load(tpl)
    assert "requests" in doc
