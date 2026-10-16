"""Path resolution helpers for the NEXUS framework.

All modules resolve paths relative to the repository root (the parent
of this ``lib`` package), so NEXUS works from any working directory.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Repository root = parent of lib/
_PKG_ROOT = Path(__file__).resolve().parent.parent


def _resolve_root() -> Path:
    """Return the directory that holds the NEXUS resources.

    From a source checkout this is the repository root (``config/`` lives
    next to ``lib/``). When installed from a wheel the code lives in
    ``site-packages`` while ``config/``, ``skills/`` and ``templates/`` are
    deployed under ``sys.prefix``, so prefer whichever root actually
    contains the ``config`` directory.
    """
    if (_PKG_ROOT / "config").is_dir():
        return _PKG_ROOT
    prefix = Path(sys.prefix)
    if (prefix / "config").is_dir():
        return prefix
    return _PKG_ROOT


REPO_ROOT = _resolve_root()

CONFIG_DIR = REPO_ROOT / "config"
RESULTS_BASE = REPO_ROOT / "results"
EXPORTS_BASE = REPO_ROOT / "exports"
LOGS_DIR = REPO_ROOT / "logs"
TEMPLATES_DIR = REPO_ROOT / "templates"
SCRIPTS_DIR = REPO_ROOT / "scripts"
WORDLISTS_DIR = REPO_ROOT / "wordlists"
