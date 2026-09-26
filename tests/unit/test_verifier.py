"""Unit tests for the verifier (roadmap A1/A2)."""
from __future__ import annotations

from lib.verifier import corroborated, verify_finding
from phases.verify.verify_orchestrator import run_verify


def _f(vtype, payload="", response="", tools=None):
    return {
        "endpoint": "https://x/a", "vuln_type": vtype, "payload": payload,
        "response_snippet": response, "tools_found": tools or ["nuclei"], "confidence": 80,
    }


def test_corroboration_two_tools_verifies():
    f = _f("xss", tools=["nuclei", "dalfox"])
    assert corroborated(f) is True
    result = verify_finding(f)
    assert result.verified is True
    assert result.method == "corroboration"


def test_xss_unescaped_reflection_verified():
    f = _f("reflected_xss", payload="<img src=x onerror=alert(1)>",
           response="<input value='<img src=x onerror=alert(1)>'>")
    result = verify_finding(f)
    assert result.verified is True
    assert result.method == "reflection"


def test_xss_encoded_reflection_disproved():
    f = _f("reflected_xss", payload="<img src=x onerror=alert(1)>",
           response="&lt;img src=x onerror=alert(1)&gt;")
    result = verify_finding(f)
    assert result.disproved is True
    assert result.verified is False


def test_sqli_error_signature_verified():
    f = _f("sqli", response="You have an error in your SQL syntax near '1'")
    assert verify_finding(f).verified is True


def test_sqli_without_signature_unverified():
    f = _f("sqli", response="welcome")
    result = verify_finding(f)
    assert result.verified is False and result.disproved is False


def test_rce_command_output_verified():
    f = _f("rce", response="uid=33(www-data) gid=33(www-data)")
    assert verify_finding(f).method == "command-output"


def test_lfi_file_content_verified():
    f = _f("lfi", response="root:x:0:0:root:/root:/bin/bash")
    assert verify_finding(f).method == "file-content"


def test_redirect_evidence_verified():
    f = _f("open_redirect", response="HTTP/1.1 302 Found\nLocation: https://evil.com")
    assert verify_finding(f).verified is True


def test_run_verify_marks_disproved_invalid():
    findings = [
        _f("reflected_xss", payload="<img src=x onerror=alert(1)>", response="&lt;img src=x onerror=alert(1)&gt;"),
        _f("xss", tools=["nuclei", "dalfox"]),
    ]
    out, summary = run_verify(findings)
    assert out[0]["valid"] is False
    assert "disproved" in out[0]["validity_reason"]
    assert out[1]["verified"] is True
    assert summary["disproved"] == 1 and summary["verified"] == 1


def test_live_replay_fallback_used_when_no_evidence():
    f = _f("xss", payload="MARKER123", response="")
    called = {}

    def probe(url):
        called["url"] = url
        return "before MARKER123 after"

    result = verify_finding(f, http_probe=probe)
    assert called["url"] == "https://x/a"
    assert result.verified is True and result.method == "replay"
