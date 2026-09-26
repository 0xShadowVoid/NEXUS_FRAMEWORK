"""GitHub token wiring for dorking (GITHUB_TOKEN → dorker)."""
from __future__ import annotations

import json
from pathlib import Path

import nexus
from phases.discover import recon_orchestrator


def test_run_discover_forwards_github_token_from_cfg(tmp_cfg, tmp_path, monkeypatch):
    """GITHUB_TOKEN from config env must reach the GitHub dork engine."""
    captured = {}

    class _FakeDorker:
        def run(self, domain, github_token=""):
            captured["token"] = github_token
            return {"domain": domain, "queries_run": 0, "urls_found": 0, "by_intent": {}}

    monkeypatch.setattr("phases.discover.recon_orchestrator.Dorker", lambda: _FakeDorker())
    monkeypatch.setattr(
        "phases.discover.recon_orchestrator.run_pegpon",
        lambda domain, runner, results_dir, with_subdomains=True: {
            "subdomains": [domain], "urls": [], "tools_run": [], "tools_skipped": [], "tools_failed": [],
        },
    )
    monkeypatch.setattr(
        "phases.discover.recon_orchestrator.WappalyzerWrapper",
        lambda: type("W", (), {"detect": lambda self, url: {"url": url, "tech": {}}})(),
    )

    tmp_cfg.env["GITHUB_TOKEN"] = "ghp_testtoken123"
    recon_orchestrator.run_discover(tmp_cfg, tmp_cfg.target("example.com"), tmp_path, dorking=True)
    assert captured["token"] == "ghp_testtoken123"


def test_run_discover_explicit_token_overrides_cfg(tmp_cfg, tmp_path, monkeypatch):
    captured = {}

    class _FakeDorker:
        def run(self, domain, github_token=""):
            captured["token"] = github_token
            return {"domain": domain, "queries_run": 0, "urls_found": 0, "by_intent": {}}

    monkeypatch.setattr("phases.discover.recon_orchestrator.Dorker", lambda: _FakeDorker())
    monkeypatch.setattr(
        "phases.discover.recon_orchestrator.run_pegpon",
        lambda domain, runner, results_dir, with_subdomains=True: {
            "subdomains": [domain], "urls": [], "tools_run": [], "tools_skipped": [], "tools_failed": [],
        },
    )
    monkeypatch.setattr(
        "phases.discover.recon_orchestrator.WappalyzerWrapper",
        lambda: type("W", (), {"detect": lambda self, url: {"url": url, "tech": {}}})(),
    )

    tmp_cfg.env["GITHUB_TOKEN"] = "from-cfg"
    recon_orchestrator.run_discover(
        tmp_cfg, tmp_cfg.target("example.com"), tmp_path, dorking=True, github_token="explicit"
    )
    assert captured["token"] == "explicit"


def test_cli_dork_uses_env_github_token(monkeypatch, capsys):
    """`nexus dork` must pass GITHUB_TOKEN from the environment."""
    captured = {}

    class _FakeDorker:
        def run_intents(self, target, intents=None, engines=None, github_token=""):
            captured["token"] = github_token
            captured["target"] = target
            return []

    monkeypatch.setenv("GITHUB_TOKEN", "ghp_cli_token")
    monkeypatch.setattr("phases.discover.dorker.Dorker", lambda: _FakeDorker())

    rc = nexus.main(["dork", "example.com", "--engines", "github"])
    assert rc == 0
    assert captured["token"] == "ghp_cli_token"
    assert captured["target"] == "example.com"
    json.loads(capsys.readouterr().out)  # valid JSON output


def test_dorker_github_intent_uses_token(monkeypatch):
    from phases.discover.dorker import Dorker

    dorker = Dorker()
    seen = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        seen["url"] = url
        seen["auth"] = (headers or {}).get("Authorization", "")

        class _R:
            status_code = 200

            @staticmethod
            def json():
                return {"items": [{"html_url": "https://github.com/o/r/blob/main/x"}]}

        return _R()

    monkeypatch.setattr(dorker.session, "get", fake_get)
    results = dorker.run_intents("example.com", intents=["github_leaks"], engines=["github"], github_token="tok")
    assert results
    assert seen["auth"] == "Bearer tok"
    assert results[0].urls == ["https://github.com/o/r/blob/main/x"]
