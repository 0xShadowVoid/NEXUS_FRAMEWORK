"""Per-agent AI configuration (roadmap: multi-provider orchestration).

Each NEMESIS agent may specify, where supported:

    provider          — primary AI provider (must have a verified adapter)
    model             — provider model id (empty = provider default)
    reasoning_effort  — off | low | medium | high (provider-dependent)
    timeout_seconds   — per-request read timeout
    max_retries       — bounded same-provider retries on transient errors
    max_calls         — per-run AI call budget (0 = unlimited)
    fallback          — ordered fallback providers/models

Configuration is validated up front: unknown providers, unverified
integrations (OpenCode/Cline), invalid effort levels, and unsupported
effort/provider combinations raise a clear error instead of being
silently ignored. Existing ``ai:`` configuration keeps working when no
``nemesis.agents`` section is present.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from lib.ai_providers import validate_reasoning_effort, require_supported
from lib.exceptions import ConfigError

DEFAULT_AGENT = "default"


@dataclass(frozen=True)
class ModelRef:
    """One provider (+ optional model) in an agent's fallback chain."""

    provider: str
    model: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"provider": self.provider, "model": self.model}


@dataclass
class AgentAISpec:
    """Validated per-agent AI settings."""

    name: str
    provider: str
    model: str = ""
    reasoning_effort: str = ""
    timeout_seconds: int = 0
    max_retries: int = 2
    max_calls: int = 0
    fallback: list[ModelRef] = field(default_factory=list)

    def chain(self) -> list[ModelRef]:
        """Primary first, then the ordered fallbacks."""
        return [ModelRef(self.provider, self.model)] + list(self.fallback)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "provider": self.provider,
            "model": self.model,
            "reasoning_effort": self.reasoning_effort or "off",
            "timeout_seconds": self.timeout_seconds,
            "max_retries": self.max_retries,
            "max_calls": self.max_calls,
            "fallback": [f.to_dict() for f in self.fallback],
        }


def _as_model_ref(value: Any) -> ModelRef:
    if isinstance(value, dict):
        provider = str(value.get("provider", "") or "").lower()
        model = str(value.get("model", "") or "")
    else:
        provider = str(value or "").lower()
        model = ""
    if not provider:
        raise ConfigError("agent fallback entry is missing 'provider'")
    return ModelRef(provider=provider, model=model)


def _int_field(name: str, raw: dict[str, Any], key: str, default: int) -> int:
    value = raw.get(key, default)
    if value is None:
        return default
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"agent {name!r}: {key} must be an integer") from exc
    if number < 0:
        raise ConfigError(f"agent {name!r}: {key} must be >= 0")
    return number


def parse_agent_spec(name: str, raw: dict[str, Any]) -> AgentAISpec:
    """Parse + validate one agent entry (raising a clear ConfigError)."""
    raw = dict(raw or {})
    provider = str(raw.get("provider", "") or "").lower()
    if not provider:
        raise ConfigError(f"agent {name!r}: 'provider' is required")
    require_supported(provider)

    model = str(raw.get("model", "") or "")
    effort = str(raw.get("reasoning_effort", "") or "")
    timeout_seconds = _int_field(name, raw, "timeout_seconds", 0)
    max_retries = _int_field(name, raw, "max_retries", 2)
    max_calls = _int_field(name, raw, "max_calls", 0)
    fallback = [_as_model_ref(f) for f in (raw.get("fallback") or [])]

    normalized = validate_reasoning_effort(provider, effort)
    for ref in fallback:
        require_supported(ref.provider)
        validate_reasoning_effort(ref.provider, effort)

    return AgentAISpec(
        name=str(name),
        provider=provider,
        model=model,
        reasoning_effort=normalized,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
        max_calls=max_calls,
        fallback=fallback,
    )


def load_agent_specs(nemesis_cfg: dict[str, Any] | None) -> dict[str, AgentAISpec]:
    """Load + validate every ``nemesis.agents`` entry (empty when absent)."""
    agents = (nemesis_cfg or {}).get("agents", {}) or {}
    if not isinstance(agents, dict):
        raise ConfigError("nemesis.agents must be a mapping of agent name → settings")
    return {str(name): parse_agent_spec(str(name), raw or {}) for name, raw in agents.items()}


def resolve_agent_spec(
    name: str | None, nemesis_cfg: dict[str, Any] | None
) -> AgentAISpec | None:
    """Return the spec for *name* (or ``default``), or None when unconfigured."""
    specs = load_agent_specs(nemesis_cfg)
    if name:
        spec = specs.get(str(name))
        if spec is None:
            raise ConfigError(
                f"unknown agent {name!r}; configured: {', '.join(sorted(specs)) or '(none)'}"
            )
        return spec
    return specs.get(DEFAULT_AGENT)


def build_analyzer_for_agent(spec: AgentAISpec, ai_cfg: dict[str, Any], env: dict[str, str]):
    """Build an :class:`AIAnalyzer` honoring one agent spec."""
    from lib.ai_analyzer import AIAnalyzer

    ai_cfg = ai_cfg or {}
    chain = spec.chain()
    providers = [ref.provider for ref in chain]
    model_map = {ref.provider: ref.model for ref in chain if ref.model}
    strong_model = str(ai_cfg.get("strong_model", "") or "")
    if spec.model:
        strong_model = spec.model if not strong_model else strong_model
    return AIAnalyzer(
        env=env,
        providers=providers,
        model=spec.model,
        model_map=model_map,
        enabled=bool(ai_cfg.get("enabled", True)),
        strong_model=strong_model,
        max_calls=spec.max_calls or int(ai_cfg.get("max_calls", 0) or 0),
        reasoning_effort=spec.reasoning_effort or str(ai_cfg.get("reasoning_effort", "") or ""),
        timeout=(5, spec.timeout_seconds) if spec.timeout_seconds else None,
        max_retries=spec.max_retries,
    )


def validate_ai_config(cfg: Any) -> dict[str, Any]:
    """Validate all agent specs from a :class:`lib.config.Config`.

    Returns a summary ``{agent: spec.to_dict()}``; raises on the first
    invalid entry. Safe to call from ``doctor`` and ``agent`` startup.
    """
    specs = load_agent_specs(getattr(cfg, "nemesis", {}) or {})
    return {name: spec.to_dict() for name, spec in sorted(specs.items())}


def analyzer_for_config(cfg: Any, agent: str | None = None):
    """Build the analyzer for *agent* (or the legacy ``ai:`` config).

    Validation of ``nemesis.agents`` happens here, so an invalid spec fails
    loudly at startup; with no agent section the behavior is unchanged.
    """
    from lib.ai_analyzer import AIAnalyzer

    ai_cfg = getattr(cfg, "ai", {}) or {}
    env = getattr(cfg, "env", {}) or {}
    spec = resolve_agent_spec(agent, getattr(cfg, "nemesis", {}) or {})
    if spec is not None:
        return build_analyzer_for_agent(spec, ai_cfg, env)
    return AIAnalyzer.from_config(ai_cfg, env)
