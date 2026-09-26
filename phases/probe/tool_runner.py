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
from lib.payload_guard import validate_tool_command

logger = get_logger("tool_runner")

DEFAULT_TIMEOUT = 300
DEEP_RETRIES = 3


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
    ):
        self.timeout = timeout
        self.deep_mode = deep_mode
        self.results_dir = results_dir
        if results_dir is not None:
            (results_dir / "scans").mkdir(parents=True, exist_ok=True)

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

        if not self.tool_available(tool):
            if self.deep_mode:
                logger.info("tool %s not found in deep mode; skipping after checks", tool)
            else:
                logger.debug("tool %s not on PATH; skipping (light mode)", tool)
            return ToolResult(tool=tool, cmd=cmd, returncode=None, status="not_found")

        attempts_allowed = DEEP_RETRIES if self.deep_mode else 1
        last: ToolResult | None = None
        for attempt in range(1, attempts_allowed + 1):
            started = time.monotonic()
            try:
                proc = subprocess.run(
                    cmd,
                    input=stdin_data,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
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
                    stdout="", stderr=f"timeout after {self.timeout}s",
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


TOOL_CATALOG: dict[str, dict[str, Any]] = {
    # Pegpon light set (15) — always attempted in discover.
    "subfinder": {"phase": "discover", "light": True},
    "assetfinder": {"phase": "discover", "light": True},
    "httpx": {"phase": "discover", "light": True},
    "ffuf": {"phase": "discover", "light": True},
    "katana": {"phase": "discover", "light": True},
    "waybackurls": {"phase": "discover", "light": True},
    "gau": {"phase": "discover", "light": True},
    "findomain": {"phase": "discover", "light": True},
    "chaos": {"phase": "discover", "light": True},
    "github-subdomains": {"phase": "discover", "light": True},
    "dnsx": {"phase": "discover", "light": True},
    "nuclei": {"phase": "probe", "light": True},
    "jsluice": {"phase": "discover", "light": True},
    "crt.sh": {"phase": "discover", "light": True},
    "securitytrails": {"phase": "discover", "light": True},
    # Deep-only tools.
    "bbot": {"phase": "discover", "light": False},
    "sqlmap": {"phase": "probe", "light": False},
    "commix": {"phase": "probe", "light": False},
    # Additional tools.
    "dalfox": {"phase": "probe", "light": True},
    "ghauri": {"phase": "probe", "light": False},
    "arjun": {"phase": "probe", "light": True},
    "jwt-tool": {"phase": "probe", "light": False},
    "lfihunt": {"phase": "probe", "light": False},
    "graphql-cop": {"phase": "probe", "light": False},
    "waf-probe": {"phase": "probe", "light": False},
    "nomore403": {"phase": "probe", "light": False},
    "cloudenum": {"phase": "probe", "light": False},
    "s3scanner": {"phase": "probe", "light": False},
    "prowler": {"phase": "probe", "light": False},
}
