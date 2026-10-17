"""AI provider capability registry and adapter interface.

Single source of truth for **which providers NEMESIS can actually talk to**
and *how*, so per-agent configuration is validated against reality instead
of silently accepting unsupported providers or parameters.

Integration kinds:

    openai-compatible-http  — a base URL + OpenAI ``/chat/completions``
                              schema; implemented by
                              :class:`lib.ai_analyzer.AIAnalyzer`.
    local-cli               — a locally installed binary that already owns
                              its own credentials (OpenCode, Cline). NEXUS
                              does **not** assume such a CLI exposes raw API
                              keys or a stable programmatic interface, so no
                              verified adapter ships for these yet; they are
                              listed only so configuration can be validated
                              and rejected clearly. See :class:`CliAdapter`
                              for the documented extension point.

Nothing here reads, stores, or transmits secrets — only capability
metadata and booleans.
"""
from __future__ import annotations

from dataclasses import dataclass

#: Reasoning-effort levels accepted by the OpenAI-compatible
#: ``reasoning_effort`` parameter. ``off`` means "do not send the field".
REASONING_EFFORTS = ("off", "low", "medium", "high")


class ProviderUnsupportedError(ValueError):
    """Raised when configuration requests a provider/parameter we cannot honor."""


@dataclass(frozen=True)
class ProviderSpec:
    """Capability + integration metadata for one provider."""

    name: str
    integration: str = "openai-compatible-http"
    base_url: str = ""
    default_model: str = ""
    keyless: bool = False
    supports_multi_key: bool = False
    supports_reasoning_effort: bool = False
    verified: bool = True
    runtime: str = ""            # local-runtime probe flavor ("" = none)
    local: bool = False          # True when no cloud egress is involved
    notes: str = ""

    @property
    def supported(self) -> bool:
        """True when a working NEXUS integration exists and is verified."""
        return self.verified and self.integration == "openai-compatible-http"

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "integration": self.integration,
            "default_model": self.default_model,
            "keyless": self.keyless,
            "supports_multi_key": self.supports_multi_key,
            "supports_reasoning_effort": self.supports_reasoning_effort,
            "verified": self.verified,
            "supported": self.supported,
            "runtime": self.runtime,
            "local": self.local,
            "notes": self.notes,
        }


PROVIDER_SPECS: dict[str, ProviderSpec] = {
    "openai": ProviderSpec(
        "openai", base_url="https://api.openai.com/v1",
        default_model="gpt-4o-mini", supports_multi_key=True,
        supports_reasoning_effort=True,
    ),
    "glm": ProviderSpec(
        "glm", base_url="https://open.bigmodel.cn/api/paas/v4",
        default_model="glm-4-flash", supports_multi_key=True,
    ),
    "deepseek": ProviderSpec(
        "deepseek", base_url="https://api.deepseek.com/v1",
        default_model="deepseek-chat", supports_multi_key=True,
    ),
    "gemini": ProviderSpec(
        "gemini", base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        default_model="gemini-1.5-flash", supports_multi_key=True,
        notes="OpenAI-compatible endpoint; multiple GEMINI_API_KEY* keys rotate.",
    ),
    "kimi": ProviderSpec(
        "kimi", base_url="https://api.moonshot.cn/v1",
        default_model="moonshot-v1-8k", supports_multi_key=True,
    ),
    "openrouter": ProviderSpec(
        "openrouter", base_url="https://openrouter.ai/api/v1",
        default_model="openrouter/auto", supports_multi_key=True,
        supports_reasoning_effort=True,
    ),
    "ollama": ProviderSpec(
        "ollama", base_url="http://localhost:11434/v1",
        default_model="llama3.1", keyless=True, runtime="ollama", local=True,
        notes="Local, no API key; operator runs the server.",
    ),
    "custom": ProviderSpec(
        "custom", base_url="", default_model="", supports_multi_key=True,
        runtime="openai-compatible",
        notes="Any OpenAI-compatible endpoint; set CUSTOM_BASE_URL / <PROVIDER>_BASE_URL.",
    ),
    "opencode": ProviderSpec(
        "opencode", integration="local-cli", verified=False,
        notes=(
            "Requires the local `opencode` CLI and its own auth. No verified "
            "programmatic adapter ships; select a model/agent from the CLI "
            "itself. Configured here only so misuse is rejected clearly."
        ),
    ),
    "cline": ProviderSpec(
        "cline", integration="local-cli", verified=False,
        notes=(
            "Cline is an IDE/VS Code extension; it has no documented public "
            "API-key-free programmatic chat interface. Free/entitled IDE model "
            "access is not exposed to external automation. Not supported."
        ),
    ),
}


def get_spec(provider: str) -> ProviderSpec | None:
    """Return the spec for *provider* (case-insensitive), or None."""
    return PROVIDER_SPECS.get(str(provider or "").lower())


def known_providers() -> tuple[str, ...]:
    return tuple(PROVIDER_SPECS)


def http_providers() -> tuple[str, ...]:
    """Providers with a verified OpenAI-compatible HTTP integration."""
    return tuple(p for p, s in PROVIDER_SPECS.items() if s.supported)


def runtime_providers() -> tuple[str, ...]:
    """Providers with a discoverable local/OpenAI-compatible runtime."""
    return tuple(p for p, s in PROVIDER_SPECS.items() if s.runtime)


def local_providers() -> tuple[str, ...]:
    """Providers that are local-only (no cloud egress, no API key)."""
    return tuple(p for p, s in PROVIDER_SPECS.items() if s.local)


def is_runtime_provider(provider: str) -> bool:
    """True when *provider* has a discoverable runtime flavor (local/custom)."""
    spec = get_spec(provider)
    return bool(spec and spec.runtime)


def supports_reasoning_effort(provider: str, effort: str = "") -> bool:
    """True when *provider* accepts a non-empty reasoning-effort level."""
    if not effort or effort == "off":
        return True
    spec = get_spec(provider)
    return bool(spec and spec.supports_reasoning_effort)


def require_supported(provider: str) -> ProviderSpec:
    """Validate a provider name, raising a clear error when unusable.

    Unknown names and known-but-unverified integrations (OpenCode, Cline)
    are rejected with an explanatory message rather than silently ignored.
    """
    spec = get_spec(provider)
    if spec is None:
        raise ProviderUnsupportedError(
            f"unknown AI provider {provider!r}; known: {', '.join(known_providers())}"
        )
    if not spec.supported:
        raise ProviderUnsupportedError(
            f"AI provider {provider!r} has no verified integration: {spec.notes}"
        )
    return spec


def validate_reasoning_effort(provider: str, effort: str) -> str:
    """Validate an effort level for *provider*; return the normalized value."""
    value = str(effort or "").lower()
    if not value:
        return ""
    if value not in REASONING_EFFORTS:
        raise ProviderUnsupportedError(
            f"invalid reasoning_effort {effort!r}; choose one of {', '.join(REASONING_EFFORTS)}"
        )
    if not supports_reasoning_effort(provider, value):
        raise ProviderUnsupportedError(
            f"reasoning_effort is not supported by provider {provider!r}"
        )
    return "" if value == "off" else value


class ProviderAdapter:
    """Documented extension point for non-HTTP providers.

    The verified path for every shipped provider is the OpenAI-compatible
    HTTP client in :class:`lib.ai_analyzer.AIAnalyzer`. A subclass may
    implement a CLI-backed provider by overriding :meth:`complete`; until a
    real implementation is verified it must raise
    :class:`ProviderUnsupportedError` so configuration fails closed.
    """

    def __init__(self, spec: ProviderSpec):
        self.spec = spec

    def available(self) -> bool:
        raise ProviderUnsupportedError(
            f"{self.spec.name}: adapter not implemented"
        )

    def complete(
        self,
        prompt: str,
        *,
        system_prompt: str = "",
        model: str = "",
        reasoning_effort: str = "",
        timeout: tuple[int, int] | None = None,
    ) -> dict[str, object] | None:
        raise ProviderUnsupportedError(
            f"{self.spec.name}: adapter not implemented ({self.spec.notes})"
        )


class CliAdapter(ProviderAdapter):
    """Base for local-CLI providers (OpenCode, Cline).

    Intentionally unimplemented: invoking a third-party CLI with NEXUS prompts
    would transmit scan data to a provider under that CLI's own terms, and no
    stable, documented, key-free programmatic interface has been verified.
    NEXUS fails closed here instead of fabricating support.
    """
