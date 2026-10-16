"""Pass 10 — centralized scope enforcement at the external-tool handoff.

Covers the audit finding: URLs/hosts discovered by recon were passed to
optional external tools without re-validation. These tests are fully offline
(no traffic to public targets); every handoff is exercised with doubles.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from lib.config import TargetConfig
from lib.exceptions import ScopeException
from lib.scope_validator import (
    extract_host,
    filter_targets,
    host_in_scope,
    validate_target_scope,
)


def _tc(in_scope=None, out_of_scope=None, domain="example.com") -> TargetConfig:
    return TargetConfig(
        domain=domain,
        in_scope=list(in_scope if in_scope is not None else [domain]),
        out_of_scope=list(out_of_scope or []),
    )


# ---------------------------------------------------------------------------
# Semantics: exact hosts, subdomains, wildcards, deceptive suffixes, ports
# ---------------------------------------------------------------------------

def test_exact_host_does_not_imply_subdomains():
    tc = _tc(["example.com"])
    assert host_in_scope("example.com", tc) is True
    assert host_in_scope("api.example.com", tc) is False


def test_wildcard_covers_apex_and_subdomains():
    tc = _tc(["*.example.com"])
    for host in ("example.com", "api.example.com", "a.b.example.com"):
        assert host_in_scope(host, tc) is True


def test_deceptive_suffix_is_not_a_subdomain():
    # example.com.attacker.test must NEVER be treated as example.com.
    for entries in (["example.com"], ["*.example.com"]):
        tc = _tc(entries)
        assert host_in_scope("example.com.attacker.test", tc) is False
        assert host_in_scope("evilexample.com", tc) is False
        assert host_in_scope("notexample.com", tc) is False


def test_prefix_suffix_lookalikes_rejected():
    tc = _tc(["*.example.com"])
    assert host_in_scope("example.com.evil.test", tc) is False
    assert host_in_scope("xexample.com", tc) is False


def test_out_of_scope_overrides_in_scope():
    tc = _tc(["*.example.com"], ["admin.example.com"])
    assert host_in_scope("api.example.com", tc) is True
    assert host_in_scope("admin.example.com", tc) is False
    with pytest.raises(ScopeException):
        validate_target_scope("admin.example.com", tc)


def test_port_is_ignored_for_host_matching():
    tc = _tc(["example.com"])
    assert host_in_scope("https://example.com:8443/x", tc) is True
    assert host_in_scope("example.com:9999", tc) is True
    # Port does not make an out-of-scope host in scope.
    assert host_in_scope("evil.com:443", tc) is False


def test_uppercase_and_trailing_dot_normalize():
    tc = _tc(["example.com"])
    assert host_in_scope("EXAMPLE.COM.", tc) is True
    assert validate_target_scope("https://Example.COM/path", tc) is True


# ---------------------------------------------------------------------------
# IP literals: exact grant, CIDR grant, fail closed otherwise
# ---------------------------------------------------------------------------

def test_ip_literal_requires_explicit_grant():
    tc = _tc(["example.com"])
    assert host_in_scope("1.2.3.4", tc) is False
    assert host_in_scope("http://1.2.3.4/", tc) is False


def test_ip_literal_exact_and_cidr_grant():
    assert host_in_scope("1.2.3.4", _tc(["1.2.3.4"])) is True
    assert host_in_scope("1.2.3.4", _tc(["1.2.3.0/24"])) is True
    assert host_in_scope("1.2.3.4", _tc(["10.0.0.0/8"])) is False


def test_private_ip_requires_explicit_grant():
    assert host_in_scope("10.0.0.5", _tc(["example.com"])) is False
    assert host_in_scope("10.0.0.5", _tc(["10.0.0.0/8"])) is True


def test_out_of_scope_cidr_wins():
    tc = _tc(["10.0.0.0/8"], ["10.0.0.0/16"])
    assert host_in_scope("10.1.2.3", tc) is True
    assert host_in_scope("10.0.5.5", tc) is False


# ---------------------------------------------------------------------------
# Malformed input fails closed
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "",
    "   ",
    "/just/a/path",
    "example.com /evil",
    "exa\tmple.com",
    "example\\.com",
    "user@",
    "http://",
    "https:///path",
])
def test_malformed_targets_are_rejected(bad):
    tc = _tc(["example.com"])
    assert host_in_scope(extract_host(bad), tc) is False
    with pytest.raises(ScopeException):
        validate_target_scope(bad, tc)


def test_userinfo_trick_uses_real_host():
    # The real host is evil.com (after the @), not example.com.
    assert extract_host("https://example.com@evil.com/") == "evil.com"
    tc = _tc(["example.com"])
    with pytest.raises(ScopeException):
        validate_target_scope("https://example.com@evil.com/", tc)


# ---------------------------------------------------------------------------
# filter_targets (list-level handoff filtering)
# ---------------------------------------------------------------------------

def test_filter_targets_keeps_in_scope_only():
    tc = _tc(["*.example.com"])
    urls = [
        "https://example.com/",
        "https://api.example.com/v1",
        "https://evil.com/x",
        "https://example.com.attacker.test/",
        "/not/a/url",
    ]
    kept = filter_targets(urls, tc, context="test")
    assert kept == ["https://example.com/", "https://api.example.com/v1"]


def test_filter_targets_handles_empty():
    assert filter_targets([], _tc()) == []
    assert filter_targets(None, _tc()) == []


# ---------------------------------------------------------------------------
# ToolRunner: the external-tool invocation boundary (fail closed)
# ---------------------------------------------------------------------------

def _fake_completed(returncode=0, stdout="", stderr=""):
    class _P:
        pass

    p = _P()
    p.returncode = returncode
    p.stdout = stdout
    p.stderr = stderr
    return p


def test_tool_runner_blocks_oos_url_in_args(monkeypatch):
    from phases.probe import tool_runner as tr

    calls = []

    def _boom(*a, **k):
        calls.append(a)
        raise AssertionError("subprocess must not run for an out-of-scope target")

    monkeypatch.setattr(tr.subprocess, "run", _boom)
    monkeypatch.setattr(tr, "validate_tool_command", lambda cmd: (True, ""))

    runner = tr.ToolRunner(timeout=5, target_config=_tc(["example.com"]))
    monkeypatch.setattr(runner, "tool_available", lambda tool: True)

    res = runner.run("scanner", ["-u", "https://evil.com/x"])
    assert res.status == "skipped"
    assert "out of scope" in res.reason
    assert calls == []


def test_tool_runner_blocks_oos_explicit_target(monkeypatch):
    from phases.probe import tool_runner as tr

    monkeypatch.setattr(tr.subprocess, "run", lambda *a, **k: _fake_completed())
    monkeypatch.setattr(tr, "validate_tool_command", lambda cmd: (True, ""))
    runner = tr.ToolRunner(timeout=5, target_config=_tc(["example.com"]))
    monkeypatch.setattr(runner, "tool_available", lambda tool: True)

    # Bare host is passed via targets= (file-based handoffs).
    res = runner.run("scanner", ["-l", "targets.txt"], targets=["evil.com"])
    assert res.status == "skipped" and "out of scope" in res.reason


def test_tool_runner_blocks_malformed_target(monkeypatch):
    from phases.probe import tool_runner as tr

    monkeypatch.setattr(tr.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError()))
    monkeypatch.setattr(tr, "validate_tool_command", lambda cmd: (True, ""))
    runner = tr.ToolRunner(timeout=5, target_config=_tc(["example.com"]))
    monkeypatch.setattr(runner, "tool_available", lambda tool: True)

    res = runner.run("scanner", ["-u", "https://"])
    assert res.status == "skipped" and "malformed" in res.reason


def test_tool_runner_allows_in_scope_and_runs_subprocess(monkeypatch):
    from phases.probe import tool_runner as tr

    seen = {}

    def _run(cmd, **kwargs):
        seen["cmd"] = cmd
        return _fake_completed(stdout="ok")

    monkeypatch.setattr(tr.subprocess, "run", _run)
    monkeypatch.setattr(tr, "validate_tool_command", lambda cmd: (True, ""))
    runner = tr.ToolRunner(timeout=5, target_config=_tc(["example.com"]))
    monkeypatch.setattr(runner, "tool_available", lambda tool: True)

    res = runner.run("scanner", ["-u", "https://example.com/x"])
    assert res.status == "ok"
    assert seen["cmd"][0] == "scanner"


def test_tool_runner_without_target_config_is_legacy(monkeypatch):
    """No target_config → legacy behaviour (no scope gating)."""
    from phases.probe import tool_runner as tr

    seen = {}
    monkeypatch.setattr(tr.subprocess, "run", lambda cmd, **k: (seen.setdefault("cmd", cmd), _fake_completed())[1])
    monkeypatch.setattr(tr, "validate_tool_command", lambda cmd: (True, ""))
    runner = tr.ToolRunner(timeout=5)
    monkeypatch.setattr(runner, "tool_available", lambda tool: True)

    res = runner.run("scanner", ["-u", "https://anything.example/x"])
    assert res.status == "ok" and "cmd" in seen


# ---------------------------------------------------------------------------
# Orchestrator boundary: run_probe filters before any tool sees the URLs
# ---------------------------------------------------------------------------

def test_run_probe_filters_urls_before_tools(tmp_cfg, tmp_path, monkeypatch):
    from phases.probe import probe_orchestrator as po

    captured: dict[str, list[str]] = {}

    def _capture(name):
        def _fn(target, urls, *a, **k):
            captured[name] = list(urls)
            return []
        return _fn

    monkeypatch.setattr(po, "run_nuclei", _capture("nuclei"))
    monkeypatch.setattr(po, "run_dalfox", _capture("dalfox"))
    monkeypatch.setattr(po, "run_all_light", _capture("light"))
    monkeypatch.setattr(po, "run_all_light_parallel", _capture("light_parallel"))

    tc = tmp_cfg.target("example.com")
    urls = ["https://example.com/", "https://evil.com/x", "https://example.com.attacker.test/"]
    po.run_probe(tmp_cfg, tc, tmp_path, urls=urls, tech={}, deep=False)

    for name in ("nuclei", "dalfox", "light"):
        if name in captured:
            assert "https://evil.com/x" not in captured[name]
            assert "https://example.com.attacker.test/" not in captured[name]
            assert captured[name] == ["https://example.com/"]


def test_run_probe_scope_filters_wildcard_subdomains(tmp_cfg, tmp_path, monkeypatch):
    from phases.probe import probe_orchestrator as po

    captured: dict[str, list[str]] = {}
    monkeypatch.setattr(po, "run_nuclei", lambda target, urls, *a, **k: captured.__setitem__("u", list(urls)) or [])

    tc = tmp_cfg.target("example.com")
    tc.in_scope = ["*.example.com"]
    urls = ["https://example.com/", "https://api.example.com/v1", "https://evil.com/"]
    po.run_probe(tmp_cfg, tc, tmp_path, urls=urls, tech={}, deep=False)
    assert captured["u"] == ["https://example.com/", "https://api.example.com/v1"]


# ---------------------------------------------------------------------------
# Redirect destinations cannot leave scope (HTTP collector path)
# ---------------------------------------------------------------------------

def test_collector_blocks_redirect_to_out_of_scope_host(monkeypatch):
    from lib import http_collector as hc

    calls = []

    class _Resp:
        def __init__(self, status, location=""):
            self.status_code = status
            self.headers = {"Location": location} if location else {}
            self.text = ""

    def fake_get(url, **kwargs):
        calls.append(url)
        if url == "https://example.com/start":
            return _Resp(302, "https://evil.com/landing")
        return _Resp(200, text="should not happen")

    monkeypatch.setattr(hc.requests, "get", fake_get)
    # SSRF guard is not the subject here; scope must block before DNS.
    monkeypatch.setattr(hc, "is_safe_url", lambda url, allow=None, local_ok=False: (True, "ok"))

    collector = hc.HttpCollector(_tc(["example.com"]))
    out = collector.fetch("https://example.com/start")
    assert "scope blocked on redirect" in out.error
    assert all("evil.com" not in u for u in calls)


def test_collector_follows_redirect_within_scope(monkeypatch):
    from lib import http_collector as hc

    class _Resp:
        def __init__(self, status, location="", text=""):
            self.status_code = status
            self.headers = {"Location": location} if location else {}
            self.text = text

    def fake_get(url, **kwargs):
        if url == "https://example.com/start":
            return _Resp(302, "https://api.example.com/final")
        return _Resp(200, text="final-page")

    monkeypatch.setattr(hc.requests, "get", fake_get)
    monkeypatch.setattr(hc, "is_safe_url", lambda url, allow=None, local_ok=False: (True, "ok"))

    collector = hc.HttpCollector(_tc(["*.example.com"]))
    out = collector.fetch("https://example.com/start")
    assert out.status_code == 200 and "final-page" in out.body
