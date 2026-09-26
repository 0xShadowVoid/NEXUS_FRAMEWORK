"""Unit tests for naming utils and the evidence sanitizer."""
from __future__ import annotations

from lib.utils import (
    create_results_tree,
    findings_report_name,
    sanitize_path_component,
    scan_folder_name,
    screenshot_name,
)
from core.sanitizer import sanitize_evidence, sanitize_finding


def test_scan_folder_name_format():
    name = scan_folder_name("paypal.com", "hackerone", "bb", "private", "2026-09-21", "14-30")
    assert name == "paypal.com-hackerone-bb-private-2026-09-21-14-30"


def test_findings_report_name_format():
    name = findings_report_name("amazon.com", "bugcrowd", "bb", "public", "2026-09-21")
    assert name == "amazon.com-bugcrowd-bb-public-2026-09-21-findings.md"


def test_screenshot_name_format():
    assert screenshot_name("paypal.com", "2026-09-21", "10-30", "finding", 1) == "paypal.com-2026-09-21-10-30-finding-001.png"


def test_sanitize_path_component():
    assert sanitize_path_component("PayPal.COM/evil") == "paypal.com-evil"
    assert sanitize_path_component("") == "unknown"


def test_create_results_tree(tmp_path):
    root = create_results_tree(tmp_path, "target-x")
    for sub in ("recon", "scans", "processed", "reports", "screenshots"):
        assert (root / sub).is_dir()


def test_sanitize_evidence_strips_cookies_and_auth():
    raw = (
        "HTTP/1.1 200 OK\r\n"
        "Set-Cookie: session=SECRET123; HttpOnly\r\n"
        "Authorization: Bearer abcdef123456ok\r\n"
        "body here"
    )
    out = sanitize_evidence(raw)
    assert "SECRET123" not in out
    assert "abcdef123456ok" not in out
    assert "body here" in out


def test_sanitize_evidence_caps_length():
    out = sanitize_evidence("A" * 2000)
    assert len(out) <= 520
    assert out.endswith("[truncated]")


def test_sanitize_evidence_masks_api_keys():
    out = sanitize_evidence("key=sk-abcdefghijklmnop1234")
    assert "sk-abcdefghijklmnop1234" not in out


def test_sanitize_evidence_keeps_single_proof_email_masks_others():
    raw = "user@corp.com and victim@corp.com"
    out = sanitize_evidence(raw)
    assert "user@corp.com" in out
    assert "victim@corp.com" not in out


def test_sanitize_finding_copies_and_sanitizes():
    f = {"endpoint": "https://x", "response_snippet": "Set-Cookie: a=b\n" + "x" * 900}
    out = sanitize_finding(f)
    assert out is not f
    assert "Set-Cookie: a=b" not in out["response_snippet"]
