"""Unit tests for the false-positive filter."""
from __future__ import annotations

from lib.false_positive_filter import FalsePositiveFilter

FILTERS = {
    "filters": {
        "xss": {"strictness": "aggressive", "confidence_threshold": 90,
                "auto_filter": ["HTML entity &lt;script&gt;", "Displayed as plain text"]},
        "sqli": {"strictness": "conservative", "confidence_threshold": 70, "auto_filter": []},
        "idor": {"strictness": "conservative", "confidence_threshold": 85, "auto_filter": []},
    }
}


def test_xss_aggressive_below_threshold_is_false_positive():
    f = FalsePositiveFilter(FILTERS)
    state, reason = f.classify({"vuln_type": "xss", "confidence": 60, "endpoint": "https://x"})
    assert state == "FALSE_POSITIVE"
    assert "aggressive" in reason


def test_xss_aggressive_above_threshold_valid():
    f = FalsePositiveFilter(FILTERS)
    state, _ = f.classify({"vuln_type": "xss", "confidence": 95, "endpoint": "https://x"})
    assert state == "VALID"


def test_xss_auto_filter_pattern_drops():
    f = FalsePositiveFilter(FILTERS)
    state, reason = f.classify({
        "vuln_type": "xss", "confidence": 99, "endpoint": "https://x",
        "response_snippet": "Displayed as plain text",
    })
    assert state == "FALSE_POSITIVE"
    assert "auto_filter" in reason


def test_sqli_conservative_keeps_potential():
    f = FalsePositiveFilter(FILTERS)
    state, reason = f.classify({"vuln_type": "sqli", "confidence": 60, "endpoint": "https://x"})
    assert state == "POTENTIAL"
    assert "conservative" in reason


def test_sqli_conservative_above_threshold_valid():
    f = FalsePositiveFilter(FILTERS)
    state, _ = f.classify({"vuln_type": "sqli", "confidence": 75, "endpoint": "https://x"})
    assert state == "VALID"


def test_idor_threshold_enforced():
    f = FalsePositiveFilter(FILTERS)
    assert f.classify({"vuln_type": "idor", "confidence": 80, "endpoint": "https://x"})[0] == "POTENTIAL"
    assert f.classify({"vuln_type": "idor", "confidence": 90, "endpoint": "https://x"})[0] == "VALID"


def test_unknown_type_defaults_valid():
    f = FalsePositiveFilter(FILTERS)
    state, _ = f.classify({"vuln_type": "weird_thing", "confidence": 10, "endpoint": "https://x"})
    assert state == "VALID"
