"""Adapter registry — name → factory, so integrations stay pluggable.

The core never imports a specific product: adapters self-register here (see
:mod:`lib.adapters.zap`) and are built from the ``integrations:`` config
section by name. Adding a future Burp or Caido adapter is a new module that
registers itself — no change to :mod:`lib.adapters.base`.

All secret values are referenced by *env var name* in configuration
(``api_key_env``); the factory reads the value from the process environment,
so no credential is ever written to ``nexus.yaml`` or logged.
"""
from __future__ import annotations

import os
from typing import Any, Callable

from lib.adapters.base import SecurityToolAdapter
from lib.exceptions import NexusError
from lib.logger import get_logger
from lib.redaction import redact_text

logger = get_logger("adapters.registry")

_FACTORIES: dict[str, Callable[[dict[str, Any]], SecurityToolAdapter]] = {}
_LOADED = False


def register(name: str) -> Callable[[Callable[[dict[str, Any]], SecurityToolAdapter]], Callable[[dict[str, Any]], SecurityToolAdapter]]:
    """Register an adapter factory under *name*."""

    def _wrap(factory):
        key = str(name).strip().lower()
        _FACTORIES[key] = factory
        return factory

    return _wrap


def _ensure_loaded() -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    # Importing the module triggers its self-registration.
    try:
        from lib.adapters import zap  # noqa: F401
    except Exception as exc:  # a broken adapter must not break the registry
        logger.warning("adapter 'zap' unavailable: %s", redact_text(str(exc)))


def adapter_names() -> list[str]:
    _ensure_loaded()
    return sorted(_FACTORIES)


def has_adapter(name: str) -> bool:
    _ensure_loaded()
    return str(name).strip().lower() in _FACTORIES


def build_adapter(name: str, cfg: Any = None, **overrides: Any) -> SecurityToolAdapter:
    """Build an adapter from ``cfg.integrations[name]`` (+ factory overrides)."""
    _ensure_loaded()
    key = str(name).strip().lower()
    factory = _FACTORIES.get(key)
    if factory is None:
        raise NexusError(f"unknown adapter: {name!r} (known: {', '.join(adapter_names()) or 'none'})")
    spec: dict[str, Any] = {}
    if cfg is not None:
        section = (getattr(cfg, "integrations", {}) or {}).get(key, {}) or {}
        if isinstance(section, dict):
            spec = dict(section)
    spec.update(overrides)
    return factory(spec)


def api_key_for(spec: dict[str, Any]) -> str:
    """Resolve an adapter's API key from the named env var (never inline)."""
    env_name = str((spec or {}).get("api_key_env") or "").strip()
    if not env_name:
        return ""
    return os.environ.get(env_name, "") or ""
