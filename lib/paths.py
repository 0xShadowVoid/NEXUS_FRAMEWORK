"""Path resolution helpers for the NEXUS framework.

All modules resolve paths relative to the repository root (the parent
of this ``lib`` package), so NEXUS works from any working directory.
"""
from __future__ import annotations

from pathlib import Path

# Repository root = parent of lib/
REPO_ROOT = Path(__file__).resolve().parent.parent

CONFIG_DIR = REPO_ROOT / "config"
RESULTS_BASE = REPO_ROOT / "results"
EXPORTS_BASE = REPO_ROOT / "exports"
LOGS_DIR = REPO_ROOT / "logs"
TEMPLATES_DIR = REPO_ROOT / "templates"
SCRIPTS_DIR = REPO_ROOT / "scripts"
WORDLISTS_DIR = REPO_ROOT / "wordlists"
