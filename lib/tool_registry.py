"""Data-driven Tool Registry for NEXUS.

Loads ``config/tools.yaml`` into :class:`ToolEntry` objects and resolves
which tools are applicable for a given run. This module is the *single
source of truth* for tool metadata; execution still goes exclusively
through :class:`phases.probe.tool_runner.ToolRunner` (never the registry).

Backward compatibility: the legacy ``TOOL_CATALOG`` dict and
``PEGPON_TOOLS`` list are preserved as *views* over the registry, so
``run_pegpon``, ``run_all_light``/``run_all_deep``, ``--skip-tools``,
``--run-tools``, ``nexus check-tools`` and every existing test keep working
unchanged.

Resolution order for ``enabled``:
    1. explicit CLI selection (``--run-tools``)      -> only those
    2. explicit CLI exclusion (``--skip-tools``)      -> those off
    3. per-target ``tools:`` list in nexus.yaml       -> those only
    4. profile membership (``custom`` > intensity map)
    5. per-tool ``enabled`` flag in tools.yaml

Availability is computed at runtime:
    ``installed``  binary on PATH (or builtin adapter present)
    ``key-missing`` requires_provider whose key is not set
    ``disabled``   turned off by config
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from importlib import import_module
from pathlib import Path
from typing import Any, Callable

import yaml

from lib.logger import get_logger
from lib.paths import CONFIG_DIR

logger = get_logger("tool_registry")

REGISTRY_FILE = CONFIG_DIR / "tools.yaml"

PROFILE_BY_INTENSITY = {
    "quick-scan": "standard",
    "full-scan": "deep",
}

ALL_PROFILES = ("minimal", "standard", "extended", "deep", "custom")


@dataclass(frozen=True)
class ToolEntry:
    """One registered tool."""

    name: str
    enabled: bool = True
    phase: str = "discover"
    domain: str = "recon"
    category: str = ""
    mode: str = "light"                    # light | deep
    profiles: tuple[str, ...] = ()
    requires_tools: tuple[str, ...] = ()
    requires_provider: str = ""
    timeout: int = 0                       # 0 = cfg.tool_timeout()
    retries: int | None = None             # None = mode default (light 1, deep 3)
    safety: str = "safe"                   # safe | moderate | heavy
    parser: str = ""
    evidence_type: str = "raw_findings"
    capabilities: tuple[str, ...] = ()
    builtin: bool = False                  # not an external binary

    @property
    def deep_only(self) -> bool:
        return self.mode == "deep"

    @property
    def is_heavy(self) -> bool:
        return self.safety == "heavy"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "phase": self.phase,
            "domain": self.domain,
            "category": self.category,
            "mode": self.mode,
            "profiles": list(self.profiles),
            "requires_tools": list(self.requires_tools),
            "requires_provider": self.requires_provider,
            "timeout": self.timeout,
            "retries": self.retries,
            "safety": self.safety,
            "parser": self.parser,
            "evidence_type": self.evidence_type,
            "capabilities": list(self.capabilities),
            "builtin": self.builtin,
        }


def _to_bool(value: Any) -> bool:
    return bool(value)


def _entry(name: str, raw: dict[str, Any]) -> ToolEntry:
    return ToolEntry(
        name=name,
        enabled=_to_bool(raw.get("enabled", True)),
        phase=str(raw.get("phase", "discover")),
        domain=str(raw.get("domain", "recon")),
        category=str(raw.get("category", "")),
        mode=str(raw.get("mode", "light")),
        profiles=tuple(raw.get("profiles") or []),
        requires_tools=tuple(raw.get("requires_tools") or []),
        requires_provider=str(raw.get("requires_provider") or ""),
        timeout=int(raw.get("timeout") or 0),
        retries=(int(raw["retries"]) if raw.get("retries") is not None else None),
        safety=str(raw.get("safety", "safe")),
        parser=str(raw.get("parser") or ""),
        evidence_type=str(raw.get("evidence_type", "raw_findings")),
        capabilities=tuple(raw.get("capabilities") or []),
        builtin=_to_bool(raw.get("builtin", False)),
    )


class ToolRegistry:
    """Central tool catalogue with profile/availability resolution."""

    def __init__(self, path: Path | None = None, entries: dict[str, ToolEntry] | None = None):
        self.path = Path(path) if path is not None else REGISTRY_FILE
        if entries is not None:
            self.entries: dict[str, ToolEntry] = dict(entries)
            self.profiles: dict[str, list[str]] = {}
        else:
            data = self._load()
            raw_profiles = data.get("profiles") or {}
            self.profiles = {
                str(name): [str(t) for t in (raw.get("tools") or [])]
                for name, raw in raw_profiles.items()
                if isinstance(raw, dict)
            }
            self.entries = {name: _entry(name, raw) for name, raw in (data.get("tools") or {}).items()}
        logger.debug("tool registry: %d tools loaded", len(self.entries))

    def _load(self) -> dict[str, Any]:
        if not self.path.exists():
            logger.warning("tools.yaml not found at %s; registry is empty", self.path)
            return {}
        try:
            return yaml.safe_load(self.path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            logger.error("invalid tools.yaml: %s", exc)
            return {}

    # -- lookups -----------------------------------------------------------

    def __contains__(self, name: str) -> bool:
        return name in self.entries

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, name: str) -> ToolEntry | None:
        return self.entries.get(name)

    def names(self) -> list[str]:
        return sorted(self.entries)

    def by_phase(self, phase: str) -> list[ToolEntry]:
        return [e for e in self.entries.values() if e.phase == phase]

    def by_category(self, category: str, phase: str | None = None) -> list[ToolEntry]:
        return [
            e for e in self.entries.values()
            if e.category == category and (phase is None or e.phase == phase)
        ]

    def has_capability(self, capability: str, phase: str | None = None) -> bool:
        return any(
            capability in e.capabilities and (phase is None or e.phase == phase)
            for e in self.entries.values()
        )

    # -- availability ------------------------------------------------------

    def availability(self, entry: ToolEntry, cfg: Any | None = None) -> str:
        """``installed`` | ``key-missing`` | ``disabled`` | ``missing``."""
        if not entry.enabled:
            return "disabled"
        if entry.requires_provider:
            if cfg is None or not cfg.provider_available(entry.requires_provider):
                return "key-missing"
        if entry.builtin:
            return "installed"
        return "installed" if shutil.which(entry.name) is not None else "missing"

    def status(self, cfg: Any | None = None) -> dict[str, dict[str, str]]:
        """Per-tool availability map (used by ``nexus check-tools``)."""
        return {name: {"availability": self.availability(e, cfg)} for name, e in sorted(self.entries.items())}

    # -- resolution ----------------------------------------------------------

    def resolve(
        self,
        intensity: str = "quick-scan",
        profile: str = "",
        deep: bool | None = None,
        only: list[str] | None = None,
        skip: list[str] | None = None,
        target_tools: list[str] | None = None,
        cfg: Any | None = None,
        phase: str | None = None,
    ) -> list[ToolEntry]:
        """Return the applicable, enabled, available tools for a run.

        ``only`` wins over everything (CLI ``--run-tools``). Then
        ``target_tools`` (per-target config), then profile membership,
        then the per-tool ``enabled`` flag. ``skip`` always excludes.
        """
        if deep is None:
            deep = intensity == "full-scan"
        profile = profile or PROFILE_BY_INTENSITY.get(intensity, "standard")
        profile_tools = set(self.profiles.get(profile) or [])
        only_set = {str(t) for t in (only or [])}
        skip_set = {str(t) for t in (skip or [])}
        target_set = {str(t) for t in (target_tools or [])}

        selected: list[ToolEntry] = []
        for name, entry in sorted(self.entries.items()):
            if name in skip_set:
                continue
            if only_set:
                if name not in only_set:
                    continue
            elif target_set:
                if name not in target_set:
                    continue
            elif profile_tools and name not in profile_tools:
                continue
            if not entry.enabled:
                continue
            # Deep-only tools never run in a light scan.
            if entry.deep_only and not deep:
                continue
            if phase is not None and entry.phase != phase:
                continue
            if cfg is not None and self.availability(entry, cfg) in ("disabled", "key-missing"):
                continue
            selected.append(entry)
        return selected

    def unresolved_dependencies(self, selected: list[ToolEntry]) -> dict[str, list[str]]:
        """Report selected tools whose declared tool deps are not also selected."""
        chosen = {e.name for e in selected}
        missing: dict[str, list[str]] = {}
        for entry in selected:
            absent = [d for d in entry.requires_tools if d not in chosen]
            if absent:
                missing[entry.name] = absent
        return missing

    # -- parser resolution ---------------------------------------------------

    def load_parser(self, entry: ToolEntry) -> Callable[..., Any] | None:
        """Import the ``module:function`` parser reference (never executes tools)."""
        ref = entry.parser
        if not ref or ":" not in ref:
            return None
        module_name, func_name = ref.split(":", 1)
        try:
            module = import_module(module_name)
            return getattr(module, func_name)
        except (ImportError, AttributeError) as exc:
            logger.debug("parser %s unavailable for %s: %s", ref, entry.name, exc)
            return None


# ---------------------------------------------------------------------------
# Module-level registry + backward-compatibility views
# -----------------------------------------------------------------

_REGISTRY: ToolRegistry | None = None


def get_registry(path: Path | None = None, reload: bool = False) -> ToolRegistry:
    """Process-wide registry singleton (tests may pass an explicit path)."""
    global _REGISTRY
    if _REGISTRY is None or reload or path is not None:
        _REGISTRY = ToolRegistry(path)
    return _REGISTRY


# Legacy compatibility: existing code does ``from phases.probe.tool_runner
# import TOOL_CATALOG`` and ``PEGPON_TOOLS``. Both are derived from the
# registry so tool metadata has exactly one source of truth.
def tool_catalog_view() -> dict[str, dict[str, Any]]:
    """``TOOL_CATALOG`` shape: {name: {"phase":..., "light":...}}."""
    registry = get_registry()
    return {
        name: {
            "phase": entry.phase,
            "light": not entry.deep_only,
            "domain": entry.domain,
            "category": entry.category,
            "safety": entry.safety,
            "enabled": entry.enabled,
        }
        for name, entry in sorted(registry.entries.items())
    }


def pegpon_tools_view() -> list[str]:
    """The Pegpon 15 light set, in the historical order."""
    canonical = [
        "subfinder", "assetfinder", "httpx", "ffuf", "katana", "waybackurls",
        "gau", "findomain", "chaos", "github_subdomains", "dnsx", "nuclei",
        "jsluice", "crtsh", "securitytrails",
    ]
    registry = get_registry()
    return [name for name in canonical if name in registry]
