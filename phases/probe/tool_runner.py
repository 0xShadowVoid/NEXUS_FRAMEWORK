"""Base tool-runner: safe subprocess execution for external tools.

SECURITY BOUNDARY: every command passes through
:func:`lib.payload_guard.validate_tool_command` before execution; no
``shell=True``; every run has a timeout; output is captured to the
scan directory. Tools are expected to be on PATH or explicitly
configured — absence degrades per mode (light: skip+continue,
deep: retry ×3 then skip).
"""
from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lib.exceptions import ToolRunnerError
from lib.logger import get_logger
from lib.ops_guard import spend_requests
from lib.payload_guard import validate_tool_command
from lib.rate_limiter import RateLimiter

logger = get_logger("tool_runner")

DEFAULT_TIMEOUT = 300
DEEP_RETRIES = 3

# Process-wide rate limiter shared by every ToolRunner instance so per-target
# windows are honoured across parallel light tools and batch scans.
_RATE_LIMITER = RateLimiter()


@dataclass
class ToolResult:
    """Outcome of one external tool invocation."""

    tool: str
    cmd: list[str]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    status: str = "ok"            # ok | timeout | not_found | error | skipped
    attempts: int = 0

    @property
    def ok(self) -> bool:
        return self.status == "ok"


class ToolRunner:
    """Runs external tools with boundary checks, timeouts, retries."""

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        deep_mode: bool = False,
        results_dir: Path | None = None,
        rate_limit: str = "",
        rate_key: str = "",
        cfg: Any = None,
    ):
        self.timeout = timeout
        self.deep_mode = deep_mode
        # Optional Config — when present, every run() consults the tool
        # registry for enabled/provider/timeout/retries (Pass 3A choke point).
        self._cfg = cfg
        self.results_dir = results_dir
        self.rate_limit = rate_limit or ""
        self.rate_key = rate_key or ""
        if self.rate_limit and self.rate_key:
            _RATE_LIMITER.configure(self.rate_key, self.rate_limit)
        if results_dir is not None:
            (results_dir / "scans").mkdir(parents=True, exist_ok=True)

    @classmethod
    def shared_rate_limiter(cls) -> RateLimiter:
        return _RATE_LIMITER

    def _throttle(self) -> None:
        """Block until a rate-limit slot is free (per target key)."""
        if self.rate_limit and self.rate_key:
            _RATE_LIMITER.acquire(self.rate_key)

    def _budget(self) -> bool:
        """Reserve one request from the process-wide budget (if configured)."""
        return spend_requests(1)

    def tool_available(self, tool: str) -> bool:
        """True when the tool binary is on PATH."""
        return shutil.which(tool) is not None

    def run(
        self,
        tool: str,
        args: list[str],
        stdin_data: str | None = None,
        env: dict[str, str] | None = None,
    ) -> ToolResult:
        """Run a tool. Light mode: skip on failure. Deep: retry ×3."""
        cmd = [tool] + [str(a) for a in args]

        allowed, reason = validate_tool_command(cmd)
        if not allowed:
            logger.warning("blocked tool command (%s): %s", reason, cmd)
            return ToolResult(tool=tool, cmd=cmd, returncode=None, status="skipped")

        # Registry choke point (Pass 3A): per-tool `enabled`, provider-key
        # availability, `timeout` and `retries` from config/tools.yaml apply
        # to EVERY invocation regardless of caller — this is what makes the
        # registry authoritative while ToolRunner stays the only executor.
        entry = None
        try:
            from lib.tool_registry import get_registry

            entry = get_registry().get(tool)
        except Exception:  # registry unreadable → legacy behaviour
            entry = None
        if entry is not None:
            if not entry.enabled:
                logger.info("tool %s disabled in registry; skipping", tool)
                return ToolResult(tool=tool, cmd=cmd, returncode=None, status="skipped")
            if self._cfg is not None:
                try:
                    avail = get_registry().availability(entry, self._cfg)
                except Exception:
                    avail = "installed"
                if avail in ("disabled", "key-missing"):
                    logger.info("tool %s unavailable (%s); skipping", tool, avail)
                    return ToolResult(tool=tool, cmd=cmd, returncode=None, status="skipped")

        timeout = (int(entry.timeout) if entry is not None and entry.timeout else 0) or self.timeout
        if entry is not None and entry.retries is not None:
            attempts_allowed = max(1, int(entry.retries))
        else:
            # Legacy mode default: light = single attempt, deep = retry ×3.
            attempts_allowed = DEEP_RETRIES if self.deep_mode else 1

        if not self.tool_available(tool):
            if self.deep_mode:
                logger.info("tool %s not found in deep mode; skipping after checks", tool)
            else:
                logger.debug("tool %s not on PATH; skipping (light mode)", tool)
            return ToolResult(tool=tool, cmd=cmd, returncode=None, status="not_found")

        last: ToolResult | None = None
        for attempt in range(1, attempts_allowed + 1):
            self._throttle()           # per-target rate window
            if not self._budget():     # global request budget
                last = ToolResult(
                    tool=tool, cmd=cmd, returncode=None,
                    stdout="", stderr="request budget exhausted",
                    status="skipped", attempts=attempt,
                )
                return last
            started = time.monotonic()
            try:
                proc = subprocess.run(
                    cmd,
                    input=stdin_data,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=env,
                    shell=False,
                )
                duration = time.monotonic() - started
                result = ToolResult(
                    tool=tool,
                    cmd=cmd,
                    returncode=proc.returncode,
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                    duration_seconds=duration,
                    status="ok" if proc.returncode == 0 else "error",
                    attempts=attempt,
                )
                if result.ok:
                    self._save_output(tool, result)
                    return result
                last = result
                if not self.deep_mode:
                    # Light mode: skip + continue.
                    self._save_output(tool, result)
                    return result
                logger.debug("deep mode: %s attempt %d failed (rc=%d)", tool, attempt, proc.returncode)
            except subprocess.TimeoutExpired:
                duration = time.monotonic() - started
                last = ToolResult(
                    tool=tool, cmd=cmd, returncode=None,
                    stdout="", stderr=f"timeout after {timeout}s",
                    duration_seconds=duration, status="timeout", attempts=attempt,
                )
                if not self.deep_mode:
                    return last
                logger.debug("deep mode: %s attempt %d timed out", tool, attempt)
            except FileNotFoundError:
                return ToolResult(tool=tool, cmd=cmd, returncode=None, status="not_found")
            except OSError as exc:
                last = ToolResult(
                    tool=tool, cmd=cmd, returncode=None,
                    stdout="", stderr=str(exc), status="error", attempts=attempt,
                )
                if not self.deep_mode:
                    return last

        assert last is not None
        self._save_output(tool, last)
        return last

    def _save_output(self, tool: str, result: ToolResult) -> None:
        if self.results_dir is None:
            return
        out_file = self.results_dir / "scans" / f"{tool}.output.txt"
        try:
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(
                f"# cmd: {' '.join(result.cmd)}\n# rc: {result.returncode}\n"
                f"# status: {result.status}\n\n{result.stdout}\n--- stderr ---\n{result.stderr}",
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            pass


# Tool catalogue is now data-driven (config/tools.yaml via lib.tool_registry).
# TOOL_CATALOG is kept as a compatibility *view* over the registry so legacy
# callers (``run_pegpon``, ``run_all_light``, ``nexus check-tools``) and all
# existing tests keep working unchanged.
from lib.tool_registry import get_registry, tool_catalog_view

TOOL_CATALOG: dict[str, dict[str, Any]] = tool_catalog_view()


def refresh_catalog() -> dict[str, dict[str, Any]]:
    """Re-read the registry (used after config/tools.yaml changes)."""
    global TOOL_CATALOG
    TOOL_CATALOG = tool_catalog_view()
    return TOOL_CATALOG
