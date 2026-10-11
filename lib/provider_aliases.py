"""External-provider key aliases for NEXUS.

Multiple environment names map to the same logical provider so users can
use either spelling (e.g. ``SHODAN_API_KEY`` or ``SHODAN_KEY``). This module
resolves aliases at config-load time only; it never stores, logs or
transmits secret values.

SECURITY BOUNDARY: this module only ever returns *key names* and booleans
about their presence. Secret values stay in the environment / ``.keys.env``
and are handled exclusively by ``lib/key_pool.py`` (masked).
"""
from __future__ import annotations

# logical provider -> accepted environment spellings (first wins as canonical)
PROVIDER_ALIASES: dict[str, list[str]] = {
    "virustotal": ["VT_API_KEY", "VIRUSTOTAL_API_KEY"],
    "github": ["GITHUB_TOKEN", "GIT_TOKEN"],
    "shodan": ["SHODAN_API_KEY", "SHODAN_KEY"],
    "securitytrails": ["SECURITYTRAILS_KEY", "SECURITY_TRAILS_KEY"],
    "chaos": ["CHAOS_KEY", "PDCP_API_KEY", "PROJECTDISCOVERY_API_KEY"],
    "censys": ["CENSYS_API_ID", "CENSYS_ID"],           # paired with secret below
    "censys_secret": ["CENSYS_API_SECRET", "CENSYS_SECRET"],
    "fofa": ["FOFA_KEY", "FOFA_API_KEY"],               # paired with FOFA_EMAIL
    "zoomeye": ["ZOOMEYE_API_KEY", "ZOOMEYE_KEY"],
    "nvd": ["NVD_API_KEY"],
}

# Environment names every provider subsystem may read.
EXTRA_ENV_KEYS: list[str] = [
    "FOFA_EMAIL",
    "FOFA_KEY",
    "FOFA_API_KEY",
    "VT_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "SHODAN_API_KEY",
    "SHODAN_KEY",
    "SECURITYTRAILS_KEY",
    "SECURITY_TRAILS_KEY",
    "CHAOS_KEY",
    "PDCP_API_KEY",
    "PROJECTDISCOVERY_API_KEY",
    "CENSYS_API_ID",
    "CENSYS_ID",
    "CENSYS_API_SECRET",
    "CENSYS_SECRET",
    "ZOOMEYE_API_KEY",
    "ZOOMEYE_KEY",
]

# Providers that require two env values (id + secret).
PAIRED_PROVIDERS: dict[str, tuple[str, str]] = {
    "censys": ("censys", "censys_secret"),
    "fofa": ("fofa", "fofa_email"),
}

FOFA_EMAIL_ENV = "FOFA_EMAIL"


def canonical_provider_alias(provider: str) -> str:
    """Return the canonical (first) env spelling for a logical provider."""
    names = PROVIDER_ALIASES.get((provider or "").lower())
    return names[0] if names else ""


def resolve_aliases(env: dict[str, str]) -> dict[str, str]:
    """Return ``{logical_provider: env_name_that_is_set}`` for present keys.

    Only names are returned — never values. If neither alias of a provider
    is set, the provider is absent from the result (callers treat that as
    "provider disabled / key missing").
    """
    resolved: dict[str, str] = {}
    for provider, names in PROVIDER_ALIASES.items():
        for name in names:
            if env.get(name):
                resolved[provider] = name
                break
    return resolved


def provider_keys_available(env: dict[str, str], provider: str) -> bool:
    """True when all env values required by *provider* are present."""
    provider = (provider or "").lower()
    if provider in PAIRED_PROVIDERS:
        id_prov, secret_prov = PAIRED_PROVIDERS[provider]
        return bool(resolve_aliases(env).get(id_prov)) and bool(
            resolve_aliases(env).get(secret_prov)
        )
    return bool(resolve_aliases(env).get(provider))
