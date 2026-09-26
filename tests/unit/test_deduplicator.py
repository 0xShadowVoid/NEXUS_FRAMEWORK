"""Unit tests for the deduplicator."""
from __future__ import annotations

from lib.deduplicator import deduplicate, normalize_endpoint


def _f(endpoint, vtype, tool, conf=50, payload="", response=""):
    return {
        "endpoint": endpoint,
        "vuln_type": vtype,
        "confidence": conf,
        "payload": payload,
        "response_snippet": response,
        "tools_found": [tool],
    }


def test_same_finding_merged():
    findings = [
        _f("https://example.com/search?q=1", "reflected_xss", "nuclei", 70),
        _f("https://example.com/search?q=1", "reflected_xss", "dalfox", 70),
    ]
    merged, report = deduplicate(findings)
    assert len(merged) == 1
    assert set(merged[0]["tools_found"]) == {"nuclei", "dalfox"}
    assert report["duplicates_merged"] == 1


def test_confidence_boost_multi_tool():
    findings = [
        _f("https://example.com/a?id=1", "sqli", "nuclei", 60),
        _f("https://example.com/a?id=1", "sqli", "sqlmap", 60),
        _f("https://example.com/a?id=1", "sqli", "ghauri", 60),
    ]
    merged, _ = deduplicate(findings)
    assert len(merged) == 1
    assert merged[0]["confidence"] == 80  # +10 per extra tool
    assert len(merged[0]["tools_found"]) == 3


def test_non_duplicates_kept_separate():
    findings = [
        _f("https://example.com/a", "xss", "nuclei"),
        _f("https://example.com/b", "sqli", "nuclei"),
    ]
    merged, report = deduplicate(findings)
    assert len(merged) == 2
    assert report["duplicates_merged"] == 0


def test_fuzzy_endpoint_match():
    findings = [
        _f("https://example.com/api/users?b=2&a=1", "idor", "nuclei"),
        _f("https://example.com/api/users?a=1&b=2", "idor", "custom"),
    ]
    merged, _ = deduplicate(findings)
    assert len(merged) == 1


def test_normalize_endpoint_sorts_params_and_strips():
    assert normalize_endpoint("https://Example.com:443/a/?b=2&a=1#frag") == "example.com/a?a=1&b=2"


def test_evidence_prefers_longer():
    findings = [
        _f("https://example.com/x", "xss", "nuclei", 50, payload="<img>", response="short"),
        _f("https://example.com/x", "xss", "dalfox", 50, payload="<img src=x onerror=alert(1)>", response="a much longer proof body"),
    ]
    merged, _ = deduplicate(findings)
    assert "onerror" in merged[0]["payload"]
    assert "longer proof" in merged[0]["response_snippet"]
