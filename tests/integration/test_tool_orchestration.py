"""Integration: tool orchestration (tech→templates, failure modes, resume)."""
from __future__ import annotations

import json
from pathlib import Path

from lib.config import Config
from phases.discover import recon_orchestrator
from phases.probe import probe_orchestrator
from phases.probe.dalfox_runner import parse_dalfox_output
from phases.probe.nuclei_orchestrator import parse_nuclei_output, select_template_dirs
from phases.probe.sqlmap_runner import gate_endpoints, parse_sqlmap_output
from phases.probe.tool_runner import ToolResult


def test_wappalyzer_to_nuclei_template_selection():
    dirs = select_template_dirs({"WordPress": "6.0", "Nginx": "1.24"})
    assert "wordpress" in dirs
    assert "nginx" in dirs
    # Unrelated stacks are not loaded.
    assert "asp" not in dirs and "java" not in dirs


def test_nuclei_output_parsed_findings():
    import json as _json

    line = _json.dumps({
        "template-id": "xss-basic",
        "matched-at": "https://x.com/a?q=1",
        "info": {"name": "Reflected XSS", "severity": "high"},
        "extracted-results": ["<script>"],
    })
    findings = parse_nuclei_output(line, "x.com")
    assert findings[0]["vuln_type"] == "reflected_xss"
    assert findings[0]["severity"] == "P1"
    assert findings[0]["tools_found"] == ["nuclei"]


def test_dalfox_plain_and_json_parsing():
    plain = "[V] https://x.com/search?q=1"
    findings = parse_dalfox_output(plain, "x.com")
    assert findings and findings[0]["vuln_type"] == "reflected_xss"

    js = json.dumps({"type": "vuln", "data": {"pocurl": "https://x.com/a", "inject": "q"}})
    findings2 = parse_dalfox_output(js, "x.com")
    assert findings2 and findings2[0]["endpoint"] == "https://x.com/a"


def test_sqlmap_heavy_tool_gating():
    responses = [
        {"url": "https://x.com/login", "status_code": 200, "body": "please login"},
        {"url": "https://x.com/admin", "status_code": 403, "body": ""},
        {"url": "https://x.com/about", "status_code": 200, "body": "hello"},
    ]
    gated = gate_endpoints(responses, user_chosen=[])
    assert "https://x.com/login" in gated
    assert "https://x.com/admin" in gated
    assert "https://x.com/about" not in gated
    # user-chosen always allowed
    assert "https://x.com/about" in gate_endpoints(responses, user_chosen=["https://x.com/about"])


def test_sqlmap_output_parsing():
    output = (
        "[INFO] testing URL 'https://x.com/item?id=1'\n"
        "Parameter: id (GET)\n"
        "    Type: boolean-based blind\n"
        "    Title: AND boolean-based blind - WHERE or HAVING clause\n"
        "    Payload: id=1 AND 1=1\n"
        "GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]\n"
        "the back-end DBMS is MySQL\n"
    )
    findings = parse_sqlmap_output(output, "x.com")
    assert findings
    assert findings[0]["vuln_type"] == "sqli"
    assert findings[0]["severity"] == "P1"


def test_probe_light_failure_skips_and_continues(tmp_cfg: Config, tmp_path: Path):
    """A missing tool in light mode must not abort the phase."""
    # No tools are installed in the test environment; probe should still finish.
    raw = probe_orchestrator.run_probe(
        tmp_cfg, tmp_cfg.target("example.com"), tmp_path,
        urls=["https://example.com/"], tech={"WordPress": "6.0"},
        deep=False,
    )
    assert isinstance(raw, list)  # completed without raising
    assert (tmp_path / "scans" / "raw_findings.json").exists()


def test_probe_checkpoint_resume(tmp_cfg: Config, tmp_path: Path):
    # Mark nuclei as already done; probe must record steps and still complete.
    raw = probe_orchestrator.run_probe(
        tmp_cfg, tmp_cfg.target("example.com"), tmp_path,
        urls=["https://example.com/"], tech={},
        deep=False, checkpoint={"probe_steps": ["nuclei"]},
    )
    checkpoint = json.loads((tmp_path / "scans" / "checkpoint.json").read_text(encoding="utf-8"))
    assert "nuclei" in checkpoint["probe_steps"]
    assert isinstance(raw, list)


def test_discover_orchestrator_writes_artifacts(tmp_cfg: Config, tmp_path: Path, monkeypatch):
    """Discover writes recon artifacts (network calls stubbed out)."""
    # Stub out network-touching pieces.
    monkeypatch.setattr(
        "phases.discover.recon_orchestrator.run_pegpon",
        lambda domain, runner, results_dir, with_subdomains=True: {
            "subdomains": [domain, "api." + domain],
            "urls": [f"https://{domain}/", f"https://api.{domain}/v1"],
            "tools_run": ["subfinder"], "tools_skipped": [], "tools_failed": [],
        },
    )
    monkeypatch.setattr(
        "phases.discover.wappalyzer_wrapper.WappalyzerWrapper.detect",
        lambda self, url, extra_paths=None, headers=None: {"url": url, "tech": {"WordPress": "6.0"}},
    )
    monkeypatch.setattr(
        "phases.discover.dorker.Dorker.run",
        lambda self, domain, github_token="": {"domain": domain, "queries_run": 0, "urls_found": 0, "by_intent": {}},
    )

    summary = recon_orchestrator.run_discover(
        tmp_cfg, tmp_cfg.target("example.com"), tmp_path, deep=False, dorking=True
    )
    assert (tmp_path / "recon" / "summary.json").exists()
    assert (tmp_path / "recon" / "tech_stack.json").exists()
    assert summary["wappalyzer"]["tech"]["WordPress"] == "6.0"
    assert len(summary["urls"]) >= 2
