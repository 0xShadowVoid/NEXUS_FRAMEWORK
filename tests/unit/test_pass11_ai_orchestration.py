"""Pass 11 — NEMESIS multi-provider AI orchestration (mocked, deterministic).

No live API calls: every HTTP interaction is monkeypatched. Covers error
classification, multi-key rotation, credential/rate-limit/quota/outage/
timeout failover, key cooldown + recovery, provider/model fallback order,
per-agent model/effort configuration, unsupported-parameter rejection,
all-providers-unavailable, secret redaction, backward compatibility and
the guarantee that AI failures never break deterministic NEXUS phases.
"""
from __future__ import annotations

import time

import pytest
import requests

from lib.ai_errors import AIErrorClass, classify_exception, classify_status, decision_for
from lib.ai_providers import (
    PROVIDER_SPECS,
    ProviderUnsupportedError,
    http_providers,
    require_supported,
    validate_reasoning_effort,
)
from lib.ai_agents import (
    build_analyzer_for_agent,
    load_agent_specs,
    parse_agent_spec,
    resolve_agent_spec,
    validate_ai_config,
)
from lib.ai_analyzer import _PROVIDER_BASE, AIAnalyzer
from lib.config import load_config
from lib.exceptions import ConfigError
from lib.key_pool import KeyPool, mask_key
from lib.paths import CONFIG_DIR


class _Resp:
    def __init__(self, status_code: int, payload=None, text: str = ""):
        self.status_code = status_code
        self._payload = payload or {}
        self.text = text
        self.headers: dict[str, str] = {}

    def json(self):
        return self._payload


def _ok(content: str = '{"category":"xss"}') -> _Resp:
    return _Resp(200, {"choices": [{"message": {"content": content}}]})


# --- error classification ---------------------------------------------------------

def test_classify_status_categories():
    assert classify_status(401) == AIErrorClass.INVALID_CREDENTIALS
    assert classify_status(403) == AIErrorClass.PERMISSION
    assert classify_status(403, "quota exceeded") == AIErrorClass.QUOTA_EXHAUSTED
    assert classify_status(429) == AIErrorClass.RATE_LIMIT
    assert classify_status(429, '{"error":"insufficient_quota"}') == AIErrorClass.QUOTA_EXHAUSTED
    assert classify_status(402) == AIErrorClass.QUOTA_EXHAUSTED
    assert classify_status(404) == AIErrorClass.UNSUPPORTED_MODEL
    assert classify_status(400, "model not found") == AIErrorClass.UNSUPPORTED_MODEL
    assert classify_status(400, "bad json") == AIErrorClass.INVALID_REQUEST
    assert classify_status(503) == AIErrorClass.OUTAGE
    assert classify_status(418) == AIErrorClass.UNKNOWN


def test_classify_exception_categories():
    assert classify_exception(requests.exceptions.Timeout()) == AIErrorClass.TIMEOUT
    assert classify_exception(requests.exceptions.ConnectionError()) == AIErrorClass.OUTAGE
    assert classify_exception(ValueError("x")) == AIErrorClass.UNKNOWN


def test_decision_policy_is_specific_per_class():
    assert decision_for(AIErrorClass.INVALID_CREDENTIALS).retire_key
    assert not decision_for(AIErrorClass.INVALID_CREDENTIALS).retry
    assert decision_for(AIErrorClass.RATE_LIMIT).cool_key
    assert decision_for(AIErrorClass.QUOTA_EXHAUSTED).skip_provider
    assert decision_for(AIErrorClass.UNSUPPORTED_MODEL).skip_provider
    assert decision_for(AIErrorClass.OUTAGE).retry
    assert not decision_for(AIErrorClass.PERMISSION).retry


# --- provider registry ------------------------------------------------------------

def test_provider_base_map_in_sync_with_registry():
    assert set(_PROVIDER_BASE) == set(http_providers())
    assert "gemini" in _PROVIDER_BASE


def test_unverified_providers_rejected():
    with pytest.raises(ProviderUnsupportedError):
        require_supported("opencode")
    with pytest.raises(ProviderUnsupportedError):
        require_supported("cline")
    with pytest.raises(ProviderUnsupportedError):
        require_supported("totally-made-up")
    assert PROVIDER_SPECS["opencode"].verified is False
    assert PROVIDER_SPECS["cline"].supported is False


# --- multi-key rotation + credential failover -------------------------------------

def test_multiple_gemini_keys_rotate_on_invalid_credentials(monkeypatch):
    analyzer = AIAnalyzer(
        env={"GEMINI_API_KEY": "dead", "GEMINI_API_KEY_2": "good"},
        providers=["gemini"], backoff_base=0,
    )
    seen: list[str] = []

    def fake_post(url, headers=None, json=None, timeout=None):
        key = (headers or {}).get("Authorization", "")
        seen.append(key)
        return _Resp(401) if "dead" in key else _ok('{"category":"sqli"}')

    monkeypatch.setattr("lib.ai_analyzer.requests.post", fake_post)
    assert analyzer.categorize_finding({"vuln_type": "sqli"}) == {"category": "sqli"}
    assert analyzer.stats["dead_keys"] == 1
    assert any("dead" in s for s in seen) and any("good" in s for s in seen)


def test_rate_limit_fails_over_and_cools_key(monkeypatch):
    analyzer = AIAnalyzer(
        env={"GLM_API_KEY": "k1", "GLM_API_KEY_2": "k2"},
        providers=["glm"], backoff_base=0,
    )
    monkeypatch.setattr(
        "lib.ai_analyzer.requests.post",
        lambda url, headers=None, json=None, timeout=None: (
            _Resp(429) if "k1" in (headers or {}).get("Authorization", "") else _ok('{"cause":"ok","action":"retry"}')
        ),
    )
    assert analyzer.analyze_error("boom") == {"cause": "ok", "action": "retry"}
    states = {s.key: s.status for s in analyzer.pools.get("glm").states}
    assert states["k1"] == "rate_limited"


def test_quota_exhausted_skips_provider(monkeypatch):
    analyzer = AIAnalyzer(
        env={"GEMINI_API_KEY": "g", "OPENAI_API_KEY": "o"},
        providers=["gemini", "openai"], backoff_base=0,
    )
    urls: list[str] = []

    def fake_post(url, headers=None, json=None, timeout=None):
        urls.append(url)
        if "generativelanguage" in url:
            return _Resp(429, text='{"error":{"message":"You exceeded your current quota"}}')
        return _ok('{"category":"rce"}')

    monkeypatch.setattr("lib.ai_analyzer.requests.post", fake_post)
    assert analyzer.categorize_finding({"vuln_type": "rce"}) == {"category": "rce"}
    assert sum("generativelanguage" in u for u in urls) == 1  # not retried
    assert analyzer.pools.get("gemini").states[0].status == "quota"
    assert analyzer.stats["errors"]["quota_exhausted"] == 1


# --- transient errors: retry with backoff -----------------------------------------

def test_outage_retries_then_recovers(monkeypatch):
    analyzer = AIAnalyzer(env={"OPENAI_API_KEY": "k"}, providers=["openai"], max_retries=2, backoff_base=0)
    calls = {"n": 0}

    def fake_post(url, headers=None, json=None, timeout=None):
        calls["n"] += 1
        return _Resp(503, text="upstream down") if calls["n"] < 3 else _ok('{"category":"xss"}')

    monkeypatch.setattr("lib.ai_analyzer.requests.post", fake_post)
    assert analyzer.categorize_finding({"vuln_type": "xss"}) == {"category": "xss"}
    assert calls["n"] == 3
    assert analyzer.stats["errors"]["outage"] == 2


def test_timeout_retries_then_recovers(monkeypatch):
    analyzer = AIAnalyzer(env={"OPENAI_API_KEY": "k"}, providers=["openai"], max_retries=1, backoff_base=0)
    calls = {"n": 0}

    def fake_post(url, headers=None, json=None, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise requests.exceptions.ConnectTimeout("slow")
        return _ok('{"category":"ssrf"}')

    monkeypatch.setattr("lib.ai_analyzer.requests.post", fake_post)
    assert analyzer.categorize_finding({"vuln_type": "ssrf"}) == {"category": "ssrf"}
    assert analyzer.stats["errors"]["timeout"] == 1


def test_outage_exhausts_retries_and_fails_over(monkeypatch):
    analyzer = AIAnalyzer(
        env={"OPENAI_API_KEY": "o", "DEEPSEEK_API_KEY": "d"},
        providers=["openai", "deepseek"], max_retries=1, backoff_base=0,
    )
    urls: list[str] = []

    def fake_post(url, headers=None, json=None, timeout=None):
        urls.append(url)
        if "openai" in url:
            return _Resp(500, text="down")
        return _ok('{"category":"idor"}')

    monkeypatch.setattr("lib.ai_analyzer.requests.post", fake_post)
    assert analyzer.categorize_finding({"vuln_type": "idor"}) == {"category": "idor"}
    assert analyzer.stats["errors"]["outage"] >= 2
    assert any("deepseek" in u for u in urls)


def test_unsupported_model_skips_provider_without_retry(monkeypatch):
    analyzer = AIAnalyzer(
        env={"OPENAI_API_KEY": "o", "GLM_API_KEY": "g"},
        providers=["openai", "glm"], backoff_base=0,
    )
    urls: list[str] = []

    def fake_post(url, headers=None, json=None, timeout=None):
        urls.append(url)
        if "openai" in url:
            return _Resp(404, text="model does not exist")
        return _ok('{"category":"lfi"}')

    monkeypatch.setattr("lib.ai_analyzer.requests.post", fake_post)
    assert analyzer.categorize_finding({"vuln_type": "lfi"}) == {"category": "lfi"}
    assert sum("openai" in u for u in urls) == 1


# --- key cooldown + recovery ------------------------------------------------------

def test_key_cooldown_blocks_then_recovers():
    pool = KeyPool("openai", ["k1"])
    assert pool.next_key() == "k1"
    pool.mark_rate_limited("k1")
    assert pool.next_key() is None                    # cooling → skipped
    pool.states[0].cooldown_until = time.monotonic() - 1  # simulate elapsed cooldown
    assert pool.next_key() == "k1"
    assert pool.states[0].status == "active"


def test_rate_limit_backoff_is_exponential_and_bounded():
    pool = KeyPool("openai", ["k1"])
    pool.mark_rate_limited("k1")
    first = pool.states[0].cooldown_until - time.monotonic()
    pool.mark_rate_limited("k1")
    second = pool.states[0].cooldown_until - time.monotonic()
    assert 50 < first < 65
    assert second > first
    for _ in range(20):
        pool.mark_rate_limited("k1")
    capped = pool.states[0].cooldown_until - time.monotonic()
    assert capped <= 900 + 1


# --- provider/model fallback order + per-agent config -----------------------------

def test_provider_fallback_order_and_models(monkeypatch):
    analyzer = AIAnalyzer(
        env={"DEEPSEEK_API_KEY": "d"},
        providers=["openai", "deepseek"], model_map={"deepseek": "deepseek-chat"},
        backoff_base=0,
    )
    urls: list[str] = []

    def fake_post(url, headers=None, json=None, timeout=None):
        urls.append(url)
        return _ok('{"category":"x"}')

    monkeypatch.setattr("lib.ai_analyzer.requests.post", fake_post)
    analyzer.categorize_finding({"vuln_type": "x"})
    assert len(urls) == 1 and "deepseek" in urls[0]


def test_parse_agent_spec_and_factory():
    spec = parse_agent_spec("triage", {
        "provider": "gemini",
        "model": "gemini-1.5-flash",
        "reasoning_effort": "off",
        "timeout_seconds": 30,
        "max_retries": 3,
        "max_calls": 10,
        "fallback": [{"provider": "openai", "model": "gpt-4o-mini"}, "openrouter"],
    })
    assert spec.provider == "gemini"
    assert [r.provider for r in spec.chain()] == ["gemini", "openai", "openrouter"]
    analyzer = build_analyzer_for_agent(spec, {"enabled": True}, {"GEMINI_API_KEY": "g"})
    assert analyzer.providers == ["gemini", "openai", "openrouter"]
    assert analyzer.model_for("gemini") == "gemini-1.5-flash"
    assert analyzer.model_for("openai") == "gpt-4o-mini"
    assert analyzer.max_retries == 3
    assert analyzer.timeout == (5, 30)


def test_reasoning_effort_sent_only_when_supported(monkeypatch):
    analyzer = AIAnalyzer(
        env={"OPENAI_API_KEY": "o"}, providers=["openai"],
        reasoning_effort="high", backoff_base=0,
    )
    bodies: list[dict] = []

    def fake_post(url, headers=None, json=None, timeout=None):
        bodies.append(json)
        return _ok('{"category":"x"}')

    monkeypatch.setattr("lib.ai_analyzer.requests.post", fake_post)
    analyzer.categorize_finding({"vuln_type": "x"})
    assert bodies[0]["reasoning_effort"] == "high"


def test_reasoning_effort_off_is_omitted(monkeypatch):
    analyzer = AIAnalyzer(env={"OPENAI_API_KEY": "o"}, providers=["openai"], backoff_base=0)
    bodies: list[dict] = []
    monkeypatch.setattr(
        "lib.ai_analyzer.requests.post",
        lambda url, headers=None, json=None, timeout=None: (bodies.append(json), _ok())[1],
    )
    analyzer.categorize_finding({"vuln_type": "x"})
    assert "reasoning_effort" not in bodies[0]


# --- unsupported parameter / provider rejection -----------------------------------

def test_unsupported_effort_for_provider_rejected_at_startup():
    with pytest.raises(ProviderUnsupportedError):
        AIAnalyzer(env={"GEMINI_API_KEY": "g"}, providers=["gemini"], reasoning_effort="high")
    with pytest.raises(ProviderUnsupportedError):
        parse_agent_spec("a", {"provider": "gemini", "reasoning_effort": "high"})
    with pytest.raises(ProviderUnsupportedError):
        validate_reasoning_effort("glm", "extreme")
    assert validate_reasoning_effort("openai", "medium") == "medium"
    assert validate_reasoning_effort("openai", "off") == ""


def test_agent_spec_rejects_unverified_and_unknown_providers():
    with pytest.raises(ProviderUnsupportedError):
        parse_agent_spec("a", {"provider": "cline"})
    with pytest.raises(ProviderUnsupportedError):
        parse_agent_spec("a", {"provider": "opencode"})
    with pytest.raises(ConfigError):
        parse_agent_spec("a", {"model": "x"})           # missing provider
    with pytest.raises(ConfigError):
        parse_agent_spec("a", {"provider": "openai", "fallback": [{"model": "x"}]})


# --- all providers unavailable ----------------------------------------------------

def test_all_providers_unavailable_returns_none(monkeypatch):
    analyzer = AIAnalyzer(
        env={"OPENAI_API_KEY": "a", "DEEPSEEK_API_KEY": "b"},
        providers=["openai", "deepseek"], backoff_base=0,
    )
    monkeypatch.setattr("lib.ai_analyzer.requests.post", lambda *a, **k: _Resp(401))
    assert analyzer.categorize_finding({"vuln_type": "x"}) is None
    assert analyzer.stats["dead_keys"] == 2


def test_no_keys_at_all_is_graceful():
    analyzer = AIAnalyzer(env={}, providers=["openai", "gemini"])
    assert analyzer.available() is False
    assert analyzer.categorize_finding({"vuln_type": "x"}) is None


# --- secret redaction -------------------------------------------------------------

def test_keys_are_masked_everywhere():
    analyzer = AIAnalyzer(env={"OPENAI_API_KEY": "sk-verysecretvalue123"}, providers=["openai"])
    assert "verysecretvalue123" not in analyzer.key_status()[0]["key"]
    assert "verysecretvalue123" not in mask_key("sk-verysecretvalue123")
    assert "verysecretvalue123" not in str(analyzer.status_summary())


# --- backward compatibility -------------------------------------------------------

def test_legacy_config_still_builds_analyzer():
    analyzer = AIAnalyzer.from_config(
        {"provider": "glm", "fallback_providers": ["openai"], "model": "glm-4"},
        {"GLM_API_KEY": "g"},
    )
    assert analyzer.providers[0] == "glm"
    assert analyzer.model_for("glm") == "glm-4"
    assert analyzer.reasoning_effort == ""


def test_no_agents_section_is_noop():
    assert load_agent_specs({}) == {}
    assert resolve_agent_spec(None, {}) is None


def test_config_loads_numbered_ai_keys(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY_2", "g2")
    monkeypatch.setenv("OPENAI_API_KEY_3", "o3")
    cfg = load_config(CONFIG_DIR)
    assert cfg.env.get("GEMINI_API_KEY_2") == "g2"
    assert cfg.env.get("OPENAI_API_KEY_3") == "o3"


def test_validate_ai_config_summary_and_errors():
    good = {"agents": {"default": {"provider": "openai"}}}
    assert validate_ai_config(type("C", (), {"nemesis": good})())["default"]["provider"] == "openai"
    bad = {"agents": {"default": {"provider": "cline"}}}
    with pytest.raises(ProviderUnsupportedError):
        validate_ai_config(type("C", (), {"nemesis": bad})())


# --- AI failures never break deterministic phases ---------------------------------

def test_agent_falls_back_to_heuristics_when_ai_fails(monkeypatch):
    from lib.agent import NexusAgent

    analyzer = AIAnalyzer(env={"OPENAI_API_KEY": "bad"}, providers=["openai"], backoff_base=0)
    monkeypatch.setattr("lib.ai_analyzer.requests.post", lambda *a, **k: _Resp(401))
    assert analyzer.plan_steps("recon example.com") is None

    cfg = load_config(CONFIG_DIR)
    agent = NexusAgent(cfg, ai=analyzer)
    steps = agent.plan("recon subdomains for example.com")
    assert steps and steps[0]["action"] in ("discover", "scan")
    report = agent.run("recon example.com", max_steps=1, dry_run=True)
    assert report["planned"] >= 1 and report["dry_run"] is True


def test_analyzer_for_config_uses_agent_spec_and_legacy(tmp_path):
    from lib.ai_agents import analyzer_for_config

    with_agents = type("C", (), {
        "ai": {"enabled": True}, "env": {"OPENAI_API_KEY": "o"},
        "nemesis": {"agents": {"default": {"provider": "openai", "model": "gpt-4o-mini"}}},
    })()
    a = analyzer_for_config(with_agents, None)
    assert a.providers == ["openai"] and a.model_for("openai") == "gpt-4o-mini"

    legacy = type("C", (), {
        "ai": {"provider": "glm", "fallback_providers": ["openai"]},
        "env": {"GLM_API_KEY": "g"}, "nemesis": {},
    })()
    a2 = analyzer_for_config(legacy, None)
    assert a2.providers[0] == "glm"


def test_config_numbered_keys_reach_analyzer(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g1")
    monkeypatch.setenv("GEMINI_API_KEY_2", "g2")
    cfg = load_config(CONFIG_DIR)
    analyzer = AIAnalyzer.from_config({"provider": "gemini"}, cfg.env)
    assert len(analyzer.pools.get("gemini")) == 2


def test_nemesis_loop_uses_injected_analyzer(monkeypatch):
    from lib.nemesis.loop import NemesisLoop

    analyzer = AIAnalyzer(env={"OPENAI_API_KEY": "bad"}, providers=["openai"], backoff_base=0)
    monkeypatch.setattr("lib.ai_analyzer.requests.post", lambda *a, **k: _Resp(401))
    cfg = load_config(CONFIG_DIR)
    loop = NemesisLoop(cfg, db=None, actions={"status": lambda s: {"ok": True}}, ai=analyzer)
    assert loop.agent.ai is analyzer
    report = loop.run_cycle("status", "eng", dry_run=True)
    assert report["status"] == "ok"

