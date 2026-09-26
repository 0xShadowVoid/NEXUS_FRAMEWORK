"""Golden-file parser tests (roadmap I3) — real-world-shaped outputs."""
from __future__ import annotations

from phases.probe.dalfox_runner import parse_dalfox_output
from phases.probe.nuclei_orchestrator import parse_nuclei_output
from phases.probe.sqlmap_runner import parse_sqlmap_output

NUCLEI_JSONL = "\n".join([
    '{"template-id":"xss","matched-at":"https://x.com/q?a=1","info":{"name":"Reflected XSS","severity":"medium"},"extracted-results":["<img src=x>"]}',
    '{"template-id":"cve-2026","matched-at":"https://x.com/","info":{"name":"CVE RCE","severity":"critical"},"extracted-results":[]}',
])

DALFOX_JSON = "\n".join([
    '{"type":"vuln","data":{"pocurl":"https://x.com/search?q=1","inject":"q","cwe":"CWE-79"}}',
    '{"type":"info","data":{"pocurl":"https://x.com/x","inject":""}}',
])

SQLMAP_LOG = (
    "Parameter: id (GET)\n"
    "    Type: boolean-based blind\n"
    "    Payload: id=1 AND 1=1\n"
    "GET parameter 'id' is vulnerable.\n"
    "the back-end DBMS is MySQL\n"
)


def test_nuclei_golden_parses_both_severities():
    findings = parse_nuclei_output(NUCLEI_JSONL, "x.com")
    assert len(findings) == 2
    sevs = {f["severity"] for f in findings}
    assert "P2" in sevs and "P1" in sevs  # medium→P2, critical→P1


def test_dalfox_golden_ignores_info_events():
    findings = parse_dalfox_output(DALFOX_JSON, "x.com")
    assert len(findings) == 1
    assert findings[0]["endpoint"] == "https://x.com/search?q=1"


def test_sqlmap_golden_extracts_param_and_dbms():
    findings = parse_sqlmap_output(SQLMAP_LOG, "x.com")
    assert findings and findings[0]["vuln_type"] == "sqli"
    assert "id" in findings[0]["payload"]
    assert "MySQL" in findings[0]["response_snippet"]
