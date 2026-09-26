"""Unit tests for chain detection."""
from __future__ import annotations

from lib.chainer import ChainDetector, detect_chains


def _f(vtype, endpoint, severity="P2", **extra):
    d = {"vuln_type": vtype, "endpoint": endpoint, "severity": severity, "id": abs(hash(endpoint)) % 1000}
    d.update(extra)
    return d


def test_stored_xss_to_rce_chain():
    findings = [_f("stored_xss", "https://x/admin/comments", "P2")]
    chains = detect_chains(findings)
    assert any(c["chain_type"] == "xss_to_rce" for c in chains)
    c = [c for c in chains if c["chain_type"] == "xss_to_rce"][0]
    assert c["combined_severity"] == "P1"


def test_idor_to_account_takeover():
    findings = [_f("idor", "https://x/api/users/5/profile/email", "P2", method="POST")]
    chains = detect_chains(findings)
    assert any(c["chain_type"] == "idor_to_ato" for c in chains)


def test_sqli_with_auth_context_to_db():
    findings = [_f("sqli", "https://x/login?id=1", "P1")]
    chains = detect_chains(findings)
    assert any(c["chain_type"] == "sqli_to_db_access" for c in chains)


def test_sqli_plus_auth_bypass_combined():
    findings = [
        _f("sqli", "https://x/item?id=1", "P1"),
        _f("auth_bypass", "https://x/admin", "P1"),
    ]
    chains = detect_chains(findings)
    assert any(c["chain_type"] == "sqli_to_db_access" for c in chains)


def test_ssrf_to_internal():
    findings = [_f("ssrf", "https://x/fetch?url=http://169.254.169.254/latest/meta-data", "P2")]
    chains = detect_chains(findings)
    assert any(c["chain_type"] == "ssrf_to_internal" for c in chains)


def test_redirect_to_token_theft():
    findings = [_f("open_redirect", "https://x/oauth/callback?redirect_uri=evil", "P4")]
    chains = detect_chains(findings)
    assert any(c["chain_type"] == "redirect_to_token_theft" for c in chains)


def test_no_chain_for_unrelated():
    findings = [
        _f("info_disclosure", "https://x/robots.txt", "P4"),
        _f("reflected_xss", "https://x/search?q=1", "P3"),
    ]
    chains = ChainDetector().detect(findings)
    assert chains == []


def test_chain_steps_and_members():
    findings = [_f("stored_xss", "https://x/admin/panel", "P2")]
    chain = detect_chains(findings)[0]
    assert chain["steps"]
    assert "https://x/admin/panel" in chain["members"]
