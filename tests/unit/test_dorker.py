"""Unit tests for the multi-engine dorker."""
from __future__ import annotations

from phases.discover.dorker import DORK_TEMPLATES, Dorker, extract_engine_names


def test_engines_available():
    engines = extract_engine_names()
    assert set(engines) >= {"duckduckgo", "google", "bing", "github"}


def test_dork_templates_cover_intents():
    for intent in ("exposed_docs", "login_pages", "error_pages", "backups", "directories", "github_leaks"):
        assert intent in DORK_TEMPLATES
        assert all("{domain}" in t for t in DORK_TEMPLATES[intent])


def test_dorker_parses_ddg_results(monkeypatch):
    html = (
        '<a class="result__a" href="https://target.com/admin/login">admin</a>'
        '<a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Ftarget.com%2Fsecret.pdf">doc</a>'
    )

    class _R:
        status_code = 200
        text = html

    dorker = Dorker()
    monkeypatch.setattr(dorker.session, "get", lambda *a, **k: _R())
    result = dorker._search_ddg("exposed_docs", "site:target.com ext:pdf")
    assert "https://target.com/admin/login" in result.urls
    assert "https://target.com/secret.pdf" in result.urls


def test_dorker_handles_engine_error(monkeypatch):
    import requests

    def boom(*a, **k):
        raise requests.RequestException("blocked")

    dorker = Dorker()
    monkeypatch.setattr(dorker.session, "get", boom)
    result = dorker._search_google("login_pages", "site:x inurl:login")
    assert result.error
    assert result.urls == []


def test_dorker_run_summary(monkeypatch):
    dorker = Dorker()

    def fake_get(url, **kwargs):
        class _R:
            status_code = 200
            text = '<a class="result__a" href="https://target.com/x">x</a>'
        return _R()

    monkeypatch.setattr(dorker.session, "get", fake_get)
    summary = dorker.run("target.com", github_token="")
    assert summary["domain"] == "target.com"
    assert summary["queries_run"] > 0
    assert "by_intent" in summary


def test_github_engine_uses_token(monkeypatch):
    dorker = Dorker()
    seen = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        seen["url"] = url
        seen["headers"] = headers or {}

        class _R:
            status_code = 200

            @staticmethod
            def json():
                return {"items": [{"html_url": "https://github.com/x/y/blob/main/.env"}]}

        return _R()

    monkeypatch.setattr(dorker.session, "get", fake_get)
    result = dorker._search_github("github_leaks", '"target.com" password', token="ghp_token")
    assert result.urls == ["https://github.com/x/y/blob/main/.env"]
    assert "Authorization" in seen["headers"]
