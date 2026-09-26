"""Environment self-diagnosis — `nexus doctor` (roadmap D5)."""
from __future__ import annotations

import importlib
import shutil
import sys
from pathlib import Path
from typing import Any

from lib.config import Config, load_config, validate_keys
from lib.exceptions import ConfigError
from lib.logger import get_logger
from lib.paths import CONFIG_DIR, RESULTS_BASE

logger = get_logger("doctor")

REQUIRED_MODULES = ["yaml", "dotenv", "requests", "croniter", "py7zr"]
OPTIONAL_MODULES = ["discord", "telegram"]
TOOLS_OF_INTEREST = ["subfinder", "httpx", "nuclei", "dalfox", "sqlmap", "ffuf", "katana"]


def run_doctor(root: Path | None = None, cfg: Config | None = None) -> dict[str, Any]:
    """Run all environment checks; returns {'ok': bool, 'checks': [...]}."""
    root = Path(root) if root else Path(__file__).resolve().parent.parent
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    # Python version
    py_ok = sys.version_info >= (3, 11)
    add("python>=3.11", py_ok, f"{sys.version.split()[0]}")

    # Required dependencies
    for module in REQUIRED_MODULES:
        try:
            importlib.import_module(module)
            add(f"dep:{module}", True, "importable")
        except ImportError as exc:
            add(f"dep:{module}", False, f"missing ({exc})")

    # Optional dependencies
    for module in OPTIONAL_MODULES:
        try:
            importlib.import_module(module)
            add(f"optional:{module}", True, "installed")
        except ImportError:
            add(f"optional:{module}", True, "not installed (optional)")

    # Configuration
    try:
        loaded = cfg or load_config(CONFIG_DIR)
        add("config:nexus.yaml", True, "loaded")
        report = validate_keys(loaded)
        add("config:keys", True,
            f"{len(report['missing'])} unset (graceful), {len(report['invalid'])} invalid")
        add("config:keys.env", bool((CONFIG_DIR / ".keys.env").exists()),
            ".keys.env present" if (CONFIG_DIR / ".keys.env").exists()
            else "not created yet (copy from .keys.env.example)")
    except ConfigError as exc:
        loaded = None
        add("config:nexus.yaml", False, str(exc))

    # Database directory writable
    try:
        RESULTS_BASE.mkdir(parents=True, exist_ok=True)
        probe = RESULTS_BASE / ".write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        add("results:writable", True, str(RESULTS_BASE))
    except OSError as exc:
        add("results:writable", False, str(exc))

    # External tools
    installed = [t for t in TOOLS_OF_INTEREST if shutil.which(t)]
    add("tools:installed", True, f"{len(installed)}/{len(TOOLS_OF_INTEREST)} present "
                                 f"({', '.join(installed) or 'none'})")

    ok = all(c["ok"] for c in checks)
    logger.info("doctor: %s (%d checks)", "ok" if ok else "issues found", len(checks))
    return {"ok": ok, "checks": checks}
