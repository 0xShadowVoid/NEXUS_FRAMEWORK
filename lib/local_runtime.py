"""Local-model runtime adapter (roadmap C5: zero-cloud / offline AI).

Discovers and health-checks the **runtime** behind a local, OpenAI-compatible
AI provider so a local model can be validated and reported before use:

    ollama              — native Ollama API (``/api/tags`` + ``/api/show``)
    openai-compatible   — any ``/models``-exposing server (llama.cpp, LM Studio,
                          vLLM, text-generation-webui, a remote ``custom`` box)

NEXUS talks to every local model through the **same** OpenAI-compatible
``/chat/completions`` path as cloud providers — implemented once by
:class:`lib.ai_analyzer.AIAnalyzer`. This module deliberately adds only
discovery, connection checks and capability metadata; it never re-implements
the chat client, key rotation or failover (that logic would otherwise be
duplicated and could drift).

Everything here fails soft: an unreachable runtime, a bad response body or an
SSRF rejection is reported as ``available=False`` with a reason, never raised,
so diagnostics and scans never block on a local server being down. No secrets
are read, stored or transmitted — a keyless local endpoint has none.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import requests

from lib.ai_providers import get_spec
from lib.logger import get_logger
from lib.ssrf_guard import is_safe_url

logger = get_logger("local_runtime")

#: Runtime probe flavors.
FLAVOR_OLLAMA = "ollama"
FLAVOR_OPENAI = "openai-compatible"

#: Short timeouts — a local runtime is either up now or not worth waiting on.
DEFAULT_TIMEOUT: tuple[int, int] = (2, 5)

#: Name hints for a vision-capable local model (defensive, best-effort only).
_VISION_HINTS = (
    "vision", "llava", "-vl", "vl-", "qwen-vl", "qwen2-vl", "qwen2.5-vl",
    "minicpm-v", "moondream", "pixtral",
)


@dataclass(frozen=True)
class RuntimeModel:
    """One model installed on a local runtime."""

    name: str
    family: str = ""
    parameter_size: str = ""
    quantization: str = ""
    size_bytes: int = 0
    context_length: int = 0
    capabilities: tuple[str, ...] = ()

    def supports(self, capability: str) -> bool:
        return capability in self.capabilities

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "family": self.family,
            "parameter_size": self.parameter_size,
            "quantization": self.quantization,
            "size_bytes": self.size_bytes,
            "context_length": self.context_length,
            "capabilities": list(self.capabilities),
        }


@dataclass
class RuntimeStatus:
    """Health + inventory of one local runtime."""

    provider: str
    flavor: str = ""
    base_url: str = ""
    available: bool = False
    models: list[RuntimeModel] = field(default_factory=list)
    error: str = ""

    def model_names(self) -> list[str]:
        return [m.name for m in self.models]

    def find(self, name: str) -> RuntimeModel | None:
        """Return the model matching *name* (exact, else ``name:tag`` prefix)."""
        target = (name or "").strip()
        if not target:
            return None
        for model in self.models:
            if model.name == target:
                return model
        for model in self.models:
            if model.name.split(":")[0] == target.split(":")[0]:
                return model
        return None

    def has_model(self, name: str) -> bool:
        return self.find(name) is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "flavor": self.flavor,
            "base_url": self.base_url,
            "available": self.available,
            "error": self.error,
            "model_count": len(self.models),
            "models": [m.to_dict() for m in self.models],
        }


def _native_root(base_url: str) -> str:
    """Strip the OpenAI ``/v1`` suffix to reach a runtime's native root."""
    root = (base_url or "").strip().rstrip("/")
    if root.endswith("/v1"):
        root = root[:-3]
    return root.rstrip("/")


def _infer_capabilities(name: str) -> tuple[str, ...]:
    lowered = (name or "").lower()
    caps = ["completion"]
    if any(hint in lowered for hint in _VISION_HINTS):
        caps.append("vision")
    return tuple(caps)


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _ollama_model(raw: dict[str, Any]) -> RuntimeModel:
    details = raw.get("details") or {}
    if not isinstance(details, dict):
        details = {}
    name = str(raw.get("name") or raw.get("model") or "").strip()
    return RuntimeModel(
        name=name,
        family=str(details.get("family") or ""),
        parameter_size=str(details.get("parameter_size") or ""),
        quantization=str(details.get("quantization_level") or ""),
        size_bytes=_as_int(raw.get("size")),
        capabilities=_infer_capabilities(name),
    )


def _context_length(model_info: dict[str, Any]) -> int:
    """Extract a context window from Ollama ``model_info`` (best-effort)."""
    for key, value in (model_info or {}).items():
        if str(key).endswith(".context_length"):
            return _as_int(value)
    return 0


class LocalRuntimeAdapter:
    """Discovery/health adapter for one local OpenAI-compatible runtime.

    The chat path stays in :class:`lib.ai_analyzer.AIAnalyzer`; this class only
    answers "is the runtime up?" and "which models/capabilities does it have?".
    """

    def __init__(
        self,
        provider: str,
        base_url: str = "",
        model: str = "",
        flavor: str = FLAVOR_OPENAI,
        timeout: tuple[int, int] | None = None,
    ):
        self.provider = str(provider or "").lower()
        self.flavor = flavor or FLAVOR_OPENAI
        self.default_model = model or ""
        self.timeout = tuple(timeout) if timeout else DEFAULT_TIMEOUT
        spec = get_spec(self.provider)
        self.base_url = (base_url or (spec.base_url if spec else "") or "").strip()

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return f"LocalRuntimeAdapter(provider={self.provider!r}, flavor={self.flavor!r})"

    # -- helpers ------------------------------------------------------------

    def _get(self, url: str) -> tuple[bool, Any, str]:
        """GET *url* through the SSRF guard. Returns (ok, payload, error)."""
        safe, reason = is_safe_url(url, local_ok=True)
        if not safe:
            return False, None, f"blocked by SSRF guard: {reason}"
        try:
            resp = requests.get(url, timeout=self.timeout)
        except requests.RequestException as exc:
            return False, None, f"unreachable ({exc.__class__.__name__})"
        if resp.status_code != 200:
            return False, None, f"HTTP {resp.status_code}"
        try:
            return True, resp.json(), ""
        except ValueError:
            return False, None, "invalid JSON from runtime"

    def _post_json(self, url: str, body: dict[str, Any]) -> tuple[bool, Any, str]:
        safe, reason = is_safe_url(url, local_ok=True)
        if not safe:
            return False, None, f"blocked by SSRF guard: {reason}"
        try:
            resp = requests.post(url, json=body, timeout=self.timeout)
        except requests.RequestException as exc:
            return False, None, f"unreachable ({exc.__class__.__name__})"
        if resp.status_code != 200:
            return False, None, f"HTTP {resp.status_code}"
        try:
            return True, resp.json(), ""
        except ValueError:
            return False, None, "invalid JSON from runtime"

    # -- public API ---------------------------------------------------------

    def probe(self) -> RuntimeStatus:
        """Check connection + list installed models. Never raises."""
        status = RuntimeStatus(provider=self.provider, flavor=self.flavor, base_url=self.base_url)

        def _fail(reason: str) -> RuntimeStatus:
            status.available = False
            status.error = reason
            logger.debug("local runtime %s unavailable: %s", self.provider, reason)
            return status

        if not self.base_url:
            return _fail("no base URL configured for runtime")
        if self.flavor == FLAVOR_OLLAMA:
            ok, payload, error = self._get(f"{_native_root(self.base_url)}/api/tags")
            if not ok:
                return _fail(error)
            raw_models = payload.get("models") if isinstance(payload, dict) else None
            status.models = [_ollama_model(m) for m in (raw_models or []) if isinstance(m, dict)]
        else:
            ok, payload, error = self._get(f"{_native_root(self.base_url)}/models")
            if not ok:
                return _fail(error)
            data = payload.get("data") if isinstance(payload, dict) else None
            status.models = [
                RuntimeModel(name=str(m.get("id") or "").strip(),
                            capabilities=_infer_capabilities(str(m.get("id") or "")))
                for m in (data or [])
                if isinstance(m, dict) and str(m.get("id") or "").strip()
            ]
        status.available = True
        return status

    def models(self) -> list[RuntimeModel]:
        """Installed models only (``[]`` when the runtime is unreachable)."""
        return self.probe().models

    def has_model(self, name: str) -> bool:
        return self.probe().has_model(name)

    def describe_model(self, name: str) -> RuntimeModel | None:
        """Return capability metadata for one model (Ollama ``/api/show``).

        Falls back to the ``/api/tags`` inventory entry when the richer
        detail endpoint is unavailable. Returns ``None`` for a bad name.
        """
        target = (name or "").strip()
        if not target:
            return None
        if self.flavor != FLAVOR_OLLAMA:
            return self.probe().find(target)
        ok, payload, _ = self._post_json(
            f"{_native_root(self.base_url)}/api/show",
            {"name": target, "model": target},
        )
        if not ok or not isinstance(payload, dict):
            return self.probe().find(target)
        base = self.probe().find(target) or RuntimeModel(name=target)
        details = payload.get("details") or {}
        if not isinstance(details, dict):
            details = {}
        caps = payload.get("capabilities")
        capabilities = (
            tuple(str(c) for c in caps) if isinstance(caps, list) and caps
            else base.capabilities
        )
        return RuntimeModel(
            name=str(payload.get("model") or base.name or target),
            family=str(details.get("family") or base.family),
            parameter_size=str(details.get("parameter_size") or base.parameter_size),
            quantization=str(details.get("quantization_level") or base.quantization),
            size_bytes=base.size_bytes,
            context_length=_context_length(payload.get("model_info") or {}) or base.context_length,
            capabilities=capabilities,
        )


def runtime_for(
    provider: str,
    base_url: str = "",
    model: str = "",
    timeout: tuple[int, int] | None = None,
) -> LocalRuntimeAdapter | None:
    """Build a runtime adapter for *provider*, or ``None`` when it has none."""
    spec = get_spec(provider)
    if spec is None or not spec.runtime:
        return None
    return LocalRuntimeAdapter(
        provider=spec.name,
        base_url=base_url or spec.base_url,
        model=model,
        flavor=spec.runtime,
        timeout=timeout,
    )
