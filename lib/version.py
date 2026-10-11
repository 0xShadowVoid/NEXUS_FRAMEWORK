"""Single source of truth for the NEXUS framework version string.

Reads the repository ``VERSION`` file so the CLI and the exporters can
never drift apart (Pass 3B §5: exporter reported 1.0.0 while the actual
version is 2.0.0).
"""
from __future__ import annotations

from lib.paths import REPO_ROOT

_FALLBACK = "2.0.0"


def framework_version() -> str:
    """Return the framework version (``VERSION`` file), with a safe fallback."""
    try:
        raw = (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    except OSError:  # pragma: no cover - packaging edge case
        return _FALLBACK
    return raw or _FALLBACK
