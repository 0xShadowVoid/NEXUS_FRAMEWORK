"""Unit tests for CVE fetching, PoC generation, and the logger."""
from __future__ import annotations

import logging

import yaml

from lib.cve_fetcher import CVEFetcher, match_tech, severity_from_score
from lib.cve_poc_generator import generate_all, register_nuclei_template
from lib.logger import redact
from lib.payload_guard import validate_payload


# --- CVE fetcher ----------------------------------------------------------


def test_severity_from_score():
    assert severity_from_score(9.5) == "critical"
    assert severity_from_score(7.5) == "high"
    assert severity_from_score(5.0) == "medium"
    assert severity_from_score(2.0) == "low"


def _nvd_payload():
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-1111",
                    "published": "2026-09-20T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "WordPress plugin RCE."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                    "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:wordpress:wp_plugin:1.0:*:*:*:*:*:*:*"}]}]}],
                }
            },
            {
                "cve": {
                    "id": "CVE-2026-2222",
                    "published": "2026-09-20T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Low-severity info leak."}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 3.1, "baseSeverity": "LOW"}}]},
                    "configurations": [],
                }
            },
        ]
    }


class _FakeSession:
    def __init__(self, payload, status=200):
        self.payload = payload
        self.status = status
        self.requests = []
        self.headers = {}

    def get(self, url, params=None, headers=None, timeout=None):
        self.requests.append((url, params))
        outer = self

        class _R:
            status_code = outer.status

            @staticmethod
            def json():
                return outer.payload

        return _R()


def test_fetch_recent_filters_by_severity():
    session = _FakeSession(_nvd_payload())
    fetcher = CVEFetcher(session=session)
    cves = fetcher.fetch_recent(hours=24, min_severity="high")
    assert len(cves) == 1
    assert cves[0]["cve_id"] == "CVE-2026-1111"
    assert cves[0]["severity"] == "critical"
    assert "wordpress:wp_plugin" in cves[0]["affected_products"]


def test_fetch_recent_handles_http_error():
    session = _FakeSession({}, status=503)
    fetcher = CVEFetcher(session=session)
    assert fetcher.fetch_recent() == []


def test_match_tech():
    cves = [{
        "cve_id": "CVE-1",
        "affected_products": ["wordpress:wp_plugin"],
        "severity": "critical",
    }]
    matches = match_tech(cves, {"WordPress": "6.0"})
    assert matches and matches[0][0]["cve_id"] == "CVE-1"
    assert match_tech(cves, {"Nginx": "1.0"}) == []


# --- CVE PoC generator ----------------------------------------------------


def test_generate_all_four_artifacts(tmp_path):
    cve = {
        "cve_id": "CVE-2026-3333", "severity": "high",
        "description": "Test CVE", "version_marker": "v1.2.3",
        "target_url": "https://target/",
    }
    artifacts = generate_all(cve, base_dir=tmp_path)
    assert set(artifacts) == {"python", "js", "sh", "nuclei"}
    for path in artifacts.values():
        assert path.exists()


def test_nuclei_template_is_valid_yaml_with_matchers(tmp_path):
    cve = {"cve_id": "CVE-2026-4444", "severity": "critical", "description": "x", "version_marker": "MARKER"}
    artifacts = generate_all(cve, base_dir=tmp_path)
    template = yaml.safe_load(artifacts["nuclei"].read_text(encoding="utf-8"))
    assert "requests" in template
    assert any("matchers" in r for r in template["requests"])


def test_generated_python_poc_uses_only_detection_content(tmp_path):
    cve = {"cve_id": "CVE-2026-5555", "severity": "high", "description": "x", "version_marker": "MARKER"}
    artifacts = generate_all(cve, base_dir=tmp_path)
    source = artifacts["python"].read_text(encoding="utf-8")
    # The generated PoC body must not contain destructive content.
    for line in source.splitlines():
        if line.strip().startswith("#") or not line.strip():
            continue
        allowed, _ = validate_payload(line)
        assert allowed, f"generated line violates boundary: {line}"


def test_sh_artifact_uses_whitelisted_suffix(tmp_path):
    cve = {"cve_id": "CVE-2026-6666", "description": "x", "version_marker": "M"}
    artifacts = generate_all(cve, base_dir=tmp_path)
    assert artifacts["sh"].name.endswith(".nexus-poc.sh")


def test_register_nuclei_template(tmp_path):
    cve = {"cve_id": "CVE-2026-7777", "description": "x", "version_marker": "M"}
    artifacts = generate_all(cve, base_dir=tmp_path / "pocs")
    dest_dir = tmp_path / "nuclei-custom"
    dest = register_nuclei_template(artifacts["nuclei"], templates_dir=dest_dir)
    assert dest.exists() and dest.parent == dest_dir


# --- Logger ---------------------------------------------------------------


def test_redact_masks_secrets():
    redacted = redact({
        "token": "supersecret",
        "nested": {"api_key": "abc", "safe": "value"},
        "list": ["x"],
    })
    assert redacted["token"] == "***REDACTED***"
    assert redacted["nested"]["api_key"] == "***REDACTED***"
    assert redacted["nested"]["safe"] == "value"


def test_redact_masks_inline_secrets_in_strings():
    out = redact("Authorization: Bearer abc12345 and webhook https://discord.com/api/webhooks/1/secret")
    assert "secret" not in out


def test_logger_redacting_formatter():
    from lib.logger import RedactingFormatter

    fmt = RedactingFormatter("%(message)s")
    record = logging.LogRecord("nexus", logging.INFO, __file__, 1, "token=abc123", None, None)
    out = fmt.format(record)
    assert "abc123" not in out
