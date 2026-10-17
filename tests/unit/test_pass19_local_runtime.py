"""Pass 19 — local-model runtime adapter (mocked, deterministic).

No live runtime: every HTTP interaction is monkeypatched. Covers the provider
registry metadata for local runtimes, Ollama/OpenAI-compatible discovery,
connection and HTTP/JSON error handling, missing-model detection, capability
metadata (context length, tools/vision), the SSRF guard, ``AIAnalyzer``
integration, and backward compatibility (Ollama stays a keyless provider).
"""
from __future__ import annotations

import json

import pytest
import requests

from lib.ai_analyzer import AIAnalyzer
from lib.ai_providers import (
    PROVIDER_SPECS,
    is_runtime_provider,
    local_providers,
    runtime_providers,
)
from lib.local_runtime import (
    FLAVOR_OLLAMA,
    LocalRuntimeAdapter,
    RuntimeModel,
    RuntimeStatus,
    _native_root,
    runtime_for,
)


class _Resp:
    def __init__(self, status_code: int, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


# --- provider registry integration ------------------------------------------------

def test_registry_marks_local_runtimes():
    assert PROVIDER_SPECS["ollama"].runtime == "ollama"
    assert PROVIDER_SPECS["ollama"].local is True
    assert PROVIDER_SPECS["custom"].runtime == "openai-compatible"
    assert PROVIDER_SPECS["custom"].local is False
    assert is_runtime_provider("ollama") and is_runtime_provider("custom")
    assert not is_runtime_provider("openai")
    assert "ollama" in runtime_providers()
    assert local_providers() == ("ollama",)
    dumped = PROVIDER_SPECS["ollama"].to_dict()
    assert dumped["runtime"] == "ollama" and dumped["local"] is True


def test_runtime_for_cloud_and_unknown_is_none():
    assert runtime_for("openai") is None
    assert runtime_for("totally-made-up") is None
    adapter = runtime_for("ollama")
    assert adapter is not None and adapter.flavor == FLAVOR_OLLAMA


def test_native_root_strips_openai_v1_suffix():
    assert _native_root("http://localhost:11434/v1") == "http://localhost:11434"
    assert _native_root("http://localhost:11434/v1/") == "http://localhost:11434"
    assert _native_root("http://127.0.0.1:8080") == "http://127.0.0.1:8080"


# --- Ollama discovery + capabilities ----------------------------------------------

def test_ollama_probe_lists_models_and_hits_native_api(monkeypatch):
    urls: list[str] = []

    def fake_get(url, timeout=None):
        urls.append(url)
        return _Resp(200, {"models": [
            {"name": "llama3.1:latest", "size": 4_700_000_000,
             "details": {"family": "llama", "parameter_size": "8B",
                         "quantization_level": "Q4_0"}},
            {"name": "llava:13b", "size": 8_000_000_000, "details": {"family": "llama"}},
        ]})

    monkeypatch.setattr("lib.local_runtime.requests.get", fake_get)
    status = LocalRuntimeAdapter("ollama", "http://localhost:11434/v1", flavor=FLAVOR_OLLAMA).probe()
    assert urls == ["http://localhost:11434/api/tags"]
    assert status.available and status.error == ""
    assert status.model_names() == ["llama3.1:latest", "llava:13b"]
    assert status.has_model("llama3.1")            # bare-name prefix match
    assert status.find("llava:13b").supports("vision")
    assert not status.find("llama3.1:latest").supports("vision")
    assert status.models[0].parameter_size == "8B"
    assert status.models[0].quantization == "Q4_0"


def test_describe_model_reads_context_length_and_capabilities(monkeypatch):
    monkeypatch.setattr(
        "lib.local_runtime.requests.get",
        lambda *a, **k: _Resp(200, {"models": [
            {"name": "llama3.1:latest", "size": 10, "details": {"family": "llama"}}
        ]}),
    )

    def fake_post(url, json=None, timeout=None):
        assert url.endswith("/api/show")
        return _Resp(200, {
            "model": "llama3.1:latest",
            "capabilities": ["completion", "tools"],
            "model_info": {"llama.context_length": 131072, "general.architecture": "llama"},
            "details": {"family": "llama", "parameter_size": "8B", "quantization_level": "Q4_0"},
        })

    monkeypatch.setattr("lib.local_runtime.requests.post", fake_post)
    adapter = LocalRuntimeAdapter("ollama", "http://localhost:11434/v1", flavor=FLAVOR_OLLAMA)
    model = adapter.describe_model("llama3.1:latest")
    assert model.context_length == 131072
    assert model.supports("tools") and model.supports("completion")
    assert model.parameter_size == "8B"
    assert adapter.describe_model("") is None


def test_describe_model_falls_back_to_inventory(monkeypatch):
    monkeypatch.setattr(
        "lib.local_runtime.requests.get",
        lambda *a, **k: _Resp(200, {"models": [{"name": "llama3.1:latest"}]}),
    )
    monkeypatch.setattr("lib.local_runtime.requests.post", lambda *a, **k: _Resp(404, {}))
    adapter = LocalRuntimeAdapter("ollama", "http://localhost:11434/v1", flavor=FLAVOR_OLLAMA)
    model = adapter.describe_model("llama3.1:latest")
    assert model is not None and model.name == "llama3.1:latest"


def test_missing_configured_model_is_detected(monkeypatch):
    monkeypatch.setattr(
        "lib.local_runtime.requests.get",
        lambda *a, **k: _Resp(200, {"models": [{"name": "llama3.1:latest"}]}),
    )
    adapter = LocalRuntimeAdapter(
        "ollama", "http://localhost:11434/v1", model="qwen2.5:7b", flavor=FLAVOR_OLLAMA
    )
    status = adapter.probe()
    assert status.available is True
    assert status.has_model("qwen2.5:7b") is False       # not installed
    assert adapter.has_model("llama3.1") is True


# --- OpenAI-compatible flavor (llama.cpp / LM Studio / vLLM / custom) --------------

def test_openai_compatible_models_endpoint(monkeypatch):
    urls: list[str] = []

    def fake_get(url, timeout=None):
        urls.append(url)
        return _Resp(200, {"data": [{"id": "gpt-oss-20b"}, {"id": "qwen2-vl-7b"}]})

    monkeypatch.setattr("lib.local_runtime.requests.get", fake_get)
    status = runtime_for("custom", "http://127.0.0.1:8080/v1").probe()
    assert status.available and status.model_names() == ["gpt-oss-20b", "qwen2-vl-7b"]
    assert status.find("qwen2-vl-7b").supports("vision")
    assert urls == ["http://127.0.0.1:8080/models"]


# --- error handling (never raises) ------------------------------------------------

def test_unreachable_runtime_reports_error(monkeypatch):
    def boom(url, timeout=None):
        raise requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr("lib.local_runtime.requests.get", boom)
    status = LocalRuntimeAdapter("ollama", "http://localhost:11434/v1", flavor=FLAVOR_OLLAMA).probe()
    assert status.available is False
    assert "unreachable" in status.error and status.models == []


def test_http_error_is_reported(monkeypatch):
    monkeypatch.setattr("lib.local_runtime.requests.get", lambda *a, **k: _Resp(500, {}))
    status = LocalRuntimeAdapter("ollama", "http://localhost:11434/v1", flavor=FLAVOR_OLLAMA).probe()
    assert status.available is False and status.error == "HTTP 500"


def test_invalid_json_is_reported(monkeypatch):
    def bad(url, timeout=None):
        resp = _Resp(200, {})

        def _raise():
            raise ValueError("no json")

        resp.json = _raise
        return resp

    monkeypatch.setattr("lib.local_runtime.requests.get", bad)
    status = LocalRuntimeAdapter("ollama", "http://localhost:11434/v1", flavor=FLAVOR_OLLAMA).probe()
    assert status.available is False and "invalid JSON" in status.error


def test_missing_base_url_skips_network(monkeypatch):
    monkeypatch.setattr(
        "lib.local_runtime.requests.get",
        lambda *a, **k: pytest.fail("no network call expected without a base URL"),
    )
    status = LocalRuntimeAdapter("custom", "", flavor="openai-compatible").probe()
    assert status.available is False and "no base URL" in status.error


def test_ssrf_guard_blocks_non_http_scheme(monkeypatch):
    monkeypatch.setattr(
        "lib.local_runtime.requests.get",
        lambda *a, **k: pytest.fail("guarded request must not be sent"),
    )
    status = LocalRuntimeAdapter("custom", "file:///etc/passwd", flavor="openai-compatible").probe()
    assert status.available is False and "SSRF" in status.error


# --- AIAnalyzer integration -------------------------------------------------------

def test_analyzer_check_runtime_and_summary(monkeypatch):
    monkeypatch.setattr(
        "lib.local_runtime.requests.get",
        lambda *a, **k: _Resp(200, {"models": [{"name": "llama3.1:latest"}]}),
    )
    analyzer = AIAnalyzer(env={}, providers=["ollama"])
    info = analyzer.check_runtime()
    assert info["provider"] == "ollama" and info["available"] is True
    assert info["model_count"] == 1
    assert analyzer.status_summary()["runtime_providers"] == ["ollama"]

    cloud = AIAnalyzer(env={"OPENAI_API_KEY": "k"}, providers=["openai"])
    assert cloud.runtime() is None
    assert cloud.check_runtime()["available"] is False


def test_runtime_respects_env_base_url_override(monkeypatch):
    urls: list[str] = []

    def fake_get(url, timeout=None):
        urls.append(url)
        return _Resp(200, {"models": []})

    monkeypatch.setattr("lib.local_runtime.requests.get", fake_get)
    analyzer = AIAnalyzer(env={"OLLAMA_BASE_URL": "http://10.0.0.5:11434/v1"}, providers=["ollama"])
    analyzer.check_runtime("ollama")
    assert urls == ["http://10.0.0.5:11434/api/tags"]


# --- backward compatibility -------------------------------------------------------

def test_ollama_stays_keyless_provider(monkeypatch):
    monkeypatch.setattr(
        "lib.ai_analyzer.requests.post",
        lambda *a, **k: _Resp(200, {"choices": [{"message": {"content": '{"category":"x"}'}}]}),
    )
    analyzer = AIAnalyzer(env={}, providers=["ollama"])
    assert analyzer.available() is True
    assert analyzer.categorize_finding({"vuln_type": "x"}) == {"category": "x"}


def test_status_to_dict_is_json_serializable():
    status = RuntimeStatus(
        provider="ollama", flavor=FLAVOR_OLLAMA, base_url="http://localhost:11434",
        available=True, models=[RuntimeModel(name="m", capabilities=("completion",))],
    )
    json.dumps(status.to_dict())
