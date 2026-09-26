"""Unit tests for the AI analyzer multi-key failover."""
from __future__ import annotations


from lib.ai_analyzer import AIAnalyzer


class _Resp:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = {}

    def json(self):
        return self._payload


def test_available_false_without_keys():
    analyzer = AIAnalyzer(env={}, providers=["openai"])
    assert analyzer.available() is False
    assert analyzer.categorize_finding({"vuln_type": "xss"}) is None


def test_failover_from_dead_key_to_good_key(monkeypatch):
    analyzer = AIAnalyzer(
        env={"OPENAI_API_KEY": "dead-key", "OPENAI_API_KEY_2": "good-key"},
        providers=["openai"],
    )
    calls = []

    def fake_post(url, headers=None, json=None, timeout=None):
        key = (headers or {}).get("Authorization", "")
        calls.append(key)
        if "dead-key" in key:
            return _Resp(401)
        return _Resp(200, {"choices": [{"message": {"content": '{"category":"xss"}'}}]})

    monkeypatch.setattr("lib.ai_analyzer.requests.post", fake_post)

    result = analyzer.categorize_finding({"vuln_type": "xss"})
    assert result == {"category": "xss"}
    assert any("dead-key" in c for c in calls)
    assert any("good-key" in c for c in calls)
    assert analyzer.stats["failovers"] >= 1
    assert analyzer.stats["dead_keys"] == 1


def test_rate_limit_fails_over(monkeypatch):
    analyzer = AIAnalyzer(
        env={"GLM_API_KEY": "k1", "GLM_API_KEY_2": "k2"},
        providers=["glm"],
    )

    def fake_post(url, headers=None, json=None, timeout=None):
        key = (headers or {}).get("Authorization", "")
        if "k1" in key:
            return _Resp(429)
        return _Resp(200, {"choices": [{"message": {"content": '{"cause":"ok","action":"retry"}'}}]})

    monkeypatch.setattr("lib.ai_analyzer.requests.post", fake_post)
    result = analyzer.analyze_error("boom")
    assert result == {"cause": "ok", "action": "retry"}


def test_all_providers_exhausted_returns_none(monkeypatch):
    analyzer = AIAnalyzer(
        env={"OPENAI_API_KEY": "bad", "DEEPSEEK_API_KEY": "bad2"},
        providers=["openai", "deepseek"],
    )
    monkeypatch.setattr("lib.ai_analyzer.requests.post", lambda *a, **k: _Resp(401))
    assert analyzer.categorize_finding({"vuln_type": "xss"}) is None
    assert analyzer.stats["dead_keys"] == 2


def test_provider_fallback(monkeypatch):
    """Primary provider has no keys → next provider with keys is used."""
    analyzer = AIAnalyzer(
        env={"DEEPSEEK_API_KEY": "ds-key"},
        providers=["openai", "deepseek"],
    )
    used = []

    def fake_post(url, headers=None, json=None, timeout=None):
        used.append(url)
        return _Resp(200, {"choices": [{"message": {"content": '{"category":"sqli"}'}}]})

    monkeypatch.setattr("lib.ai_analyzer.requests.post", fake_post)
    result = analyzer.categorize_finding({"vuln_type": "sqli"})
    assert result == {"category": "sqli"}
    assert any("deepseek" in u for u in used)


def test_disabled_returns_none():
    analyzer = AIAnalyzer(env={"OPENAI_API_KEY": "k"}, providers=["openai"], enabled=False)
    assert analyzer.available() is False
    assert analyzer.categorize_finding({}) is None


def test_key_status_masks_keys():
    analyzer = AIAnalyzer(env={"OPENAI_API_KEY": "sk-supersecretvalue"}, providers=["openai"])
    status = analyzer.key_status()
    assert status[0]["key"].startswith("sk-s")
    assert "supersecretvalue" not in status[0]["key"]


def test_from_config_builds_provider_order():
    analyzer = AIAnalyzer.from_config(
        {"provider": "glm", "fallback_providers": ["openai"], "model": "glm-4"},
        {"GLM_API_KEY": "g"},
    )
    assert analyzer.providers[0] == "glm"
    assert "openai" in analyzer.providers
    assert analyzer.model_for("glm") == "glm-4"
