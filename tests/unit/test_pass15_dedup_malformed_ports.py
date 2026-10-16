"""Regression: a malformed port must never abort the ANALYZE phase.

``lib.deduplicator.normalize_endpoint`` read ``urlsplit(...).port`` outside
its ``ValueError`` guard, so a finding whose endpoint carried a non-numeric
or out-of-range port raised during the dedup loop and propagated out of
``Analyzer.run`` -- the coordinator then failed the *entire* scan over one
bad endpoint. The fix quarantines unparseable endpoints under a stable
lowercased raw-form identity instead of raising, and never drops the invalid
port (so an invalid value is not silently converted into a valid target).

These tests pin the established normalization of valid inputs and the new
fail-soft behavior for invalid ones.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import lib.deduplicator as dedup_mod
from core.analyzer import Analyzer
from core.database import Database
from lib.config import Config
from lib.deduplicator import deduplicate, normalize_endpoint


def _f(endpoint, vtype="xss", tool="nuclei", conf=50, payload="", response=""):
    return {
        "endpoint": endpoint,
        "vuln_type": vtype,
        "confidence": conf,
        "payload": payload,
        "response_snippet": response,
        "tools_found": [tool],
    }


# --- valid inputs: established normalization must be unchanged ---------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        # hostname + explicit non-default port (kept)
        ("https://Example.com:8443/a/", "example.com:8443/a"),
        # default ports dropped
        ("http://example.com:80/x", "example.com/x"),
        ("https://example.com:443/a/?b=2&a=1#frag", "example.com/a?a=1&b=2"),
        # missing port
        ("http://example.com/x", "example.com/x"),
        # IPv4 with and without port
        ("http://192.168.0.1:8080/x", "192.168.0.1:8080/x"),
        ("https://10.0.0.5/a", "10.0.0.5/a"),
        # bracketed IPv6 (established behavior: hostname loses its brackets)
        ("http://[2001:db8::1]:8080/x", "2001:db8::1:8080/x"),
        ("http://[2001:db8::1]/x", "2001:db8::1/x"),
        # boundary ports are valid
        ("http://example.com:0/x", "example.com:0/x"),
        ("http://example.com:65535/x", "example.com:65535/x"),
    ],
)
def test_valid_endpoints_normalize_unchanged(raw, expected):
    assert normalize_endpoint(raw) == expected


def test_valid_dedup_identity_ignores_scheme_keeps_port():
    # scheme is stripped for comparison...
    assert normalize_endpoint("http://a.example:8080/x") == normalize_endpoint(
        "https://a.example:8080/x"
    )
    # ...but a different explicit port is a distinct identity
    assert normalize_endpoint("http://a.example:8080/x") != normalize_endpoint(
        "http://a.example:9090/x"
    )


# --- invalid ports: must not raise, must not be coerced ----------------------


@pytest.mark.parametrize(
    "raw",
    [
        "http://example.com:abc/x",      # non-numeric
        "http://example.com:-1/x",       # negative
        "http://example.com:70000/x",    # out of range (high)
        "http://example.com:65536/x",    # just past max
        "http://example.com:999999999/x",
        "http://[::1]:99999/x",          # bracketed IPv6 + bad port
        "http://[::1]:abc/x",
        "http://[::1/x",                 # malformed IPv6 bracket
    ],
)
def test_malformed_endpoint_does_not_raise(raw):
    out = normalize_endpoint(raw)  # must not raise ValueError
    assert out == raw.lower().rstrip("/")


def test_malformed_port_is_preserved_not_coerced():
    out = normalize_endpoint("http://example.com:70000/x")
    assert out != "example.com/x"          # not silently made a valid target
    assert ":70000" in out                 # invalid literal retained


def test_empty_port_is_treated_as_missing():
    # "http://host:/path" parses (urlsplit .port is None) -> plain host
    assert normalize_endpoint("http://example.com:/x") == "example.com/x"


# --- deduplication identity of malformed vs valid endpoints ------------------


def test_malformed_endpoints_dedup_with_identical_self():
    findings = [
        _f("http://example.com:70000/x", tool="nuclei"),
        _f("http://example.com:70000/x", tool="dalfox"),
    ]
    merged, report = deduplicate(findings)
    assert len(merged) == 1
    assert report["duplicates_merged"] == 1


def test_malformed_endpoint_not_fuzzy_merged_with_valid_endpoint():
    findings = [
        _f("http://example.com:70000/x", tool="nuclei"),
        _f("http://example.com/x", tool="dalfox"),
    ]
    merged, report = deduplicate(findings)
    assert len(merged) == 2
    assert report["duplicates_merged"] == 0


def test_distinct_invalid_ports_stay_distinct():
    findings = [
        _f("http://example.com:70000/x", tool="nuclei"),
        _f("http://example.com:99999/x", tool="dalfox"),
    ]
    merged, _ = deduplicate(findings)
    assert len(merged) == 2


def test_mixed_input_keeps_valid_and_quarantines_invalid():
    findings = [
        _f("https://example.com/search?q=1", tool="nuclei", conf=70),
        _f("https://example.com/search?q=1", tool="dalfox", conf=70),
        _f("http://example.com:notaport/broken", tool="nuclei"),
        _f("http://192.168.0.1:8080/admin", vtype="sqli", tool="sqlmap"),
    ]
    merged, report = deduplicate(findings)
    # the valid duplicate pair merged; the malformed asset survived as its own
    assert report["input_count"] == 4
    assert len(merged) == 3
    assert report["duplicates_merged"] == 1
    endpoints = {m["endpoint"] for m in merged}
    assert "example.com/search?q=1" in endpoints
    assert "http://example.com:notaport/broken" in endpoints
    assert "192.168.0.1:8080/admin" in endpoints


# --- unexpected internal errors still surface (no broad handler) ------------


def test_unexpected_parse_error_propagates(monkeypatch):
    def boom(_raw):
        raise RuntimeError("simulated internal failure")

    monkeypatch.setattr(dedup_mod, "urlsplit", boom)
    with pytest.raises(RuntimeError):
        deduplicate([_f("http://example.com/x")])


# --- end-to-end: ANALYZE phase is not aborted by a malformed port -----------


def test_analyze_phase_survives_malformed_port(tmp_cfg: Config, tmp_path: Path):
    db = Database(tmp_path / "t.sqlite")
    scan_id = db.create_scan(db.upsert_target("example.com"))
    analyzer = Analyzer(tmp_cfg, db)
    results_dir = tmp_path / "r"
    results_dir.mkdir()

    raw = [
        _f("https://example.com/search?q=1", tool="nuclei", conf=70),
        _f("https://example.com/search?q=1", tool="dalfox", conf=70),
        _f("http://example.com:70000/broken", tool="nuclei", conf=90),
    ]

    metrics = analyzer.run(raw, tmp_cfg.target("example.com"), scan_id, results_dir)

    # One unparseable endpoint did not abort the phase; outputs still written.
    assert (results_dir / "processed" / "findings.json").exists()
    findings = json.loads(
        (results_dir / "processed" / "findings.json").read_text(encoding="utf-8")
    )
    # 3 raw → 2 after dedup (valid pair merged), malformed asset retained.
    assert metrics["findings_total"] == 2
    endpoints = {f["endpoint"] for f in findings}
    assert "http://example.com:70000/broken" in endpoints


def test_analyze_only_malformed_input_does_not_raise(tmp_cfg: Config, tmp_path: Path):
    db = Database(tmp_path / "t.sqlite")
    scan_id = db.create_scan(db.upsert_target("example.com"))
    analyzer = Analyzer(tmp_cfg, db)
    results_dir = tmp_path / "r"
    results_dir.mkdir()

    raw = [
        _f("http://example.com:bad/x", tool="nuclei"),
        _f("http://[::1/x", tool="dalfox"),
    ]
    metrics = analyzer.run(raw, tmp_cfg.target("example.com"), scan_id, results_dir)
    assert metrics["findings_total"] == 2
