"""Unit tests for the severity scorer."""
from __future__ import annotations

from lib.severity_scorer import SeverityScorer, severity_rank


def test_rce_is_p1():
    scorer = SeverityScorer()
    severity, _ = scorer.score({"vuln_type": "rce", "confidence": 90})
    assert severity == "P1"


def test_sqli_p1_with_auth_context():
    scorer = SeverityScorer()
    sev, _ = scorer.score({"vuln_type": "sqli", "confidence": 85, "endpoint": "https://x/login?id=1"})
    assert sev == "P1"


def test_sqli_plain_p1():
    scorer = SeverityScorer()
    sev, _ = scorer.score({"vuln_type": "sqli", "confidence": 80})
    assert sev == "P1"


def test_stored_xss_p2_reflected_p3():
    scorer = SeverityScorer()
    assert scorer.score({"vuln_type": "stored_xss", "confidence": 90})[0] == "P2"
    assert scorer.score({"vuln_type": "reflected_xss", "confidence": 90})[0] == "P3"


def test_idor_sensitive_vs_plain():
    scorer = SeverityScorer()
    sensitive = scorer.score({"vuln_type": "idor", "confidence": 90, "endpoint": "https://x/api/users/2/profile/email"})[0]
    plain = scorer.score({"vuln_type": "idor", "confidence": 90, "endpoint": "https://x/api/items/2"})[0]
    assert sensitive == "P2"
    assert plain == "P3"


def test_info_disclosure_p4():
    scorer = SeverityScorer()
    assert scorer.score({"vuln_type": "info_disclosure", "confidence": 50})[0] == "P4"


def test_redirect_oauth_upgrade():
    scorer = SeverityScorer()
    sev, _ = scorer.score({"vuln_type": "open_redirect", "confidence": 80, "endpoint": "https://x/oauth/callback?next=1"})
    assert sev == "P3"


def test_confidence_threshold_applied():
    filters = {"filters": {"xss": {"confidence_threshold": 90}}}
    scorer = SeverityScorer(filters)
    assert scorer.meets_threshold("xss", 95) is True
    assert scorer.meets_threshold("xss", 60) is False
    assert scorer.threshold_for("xss") == 90


def test_severity_rank_ordering():
    assert severity_rank("P1") < severity_rank("P2") < severity_rank("P3") < severity_rank("P4")
