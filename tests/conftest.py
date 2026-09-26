"""Shared pytest fixtures for the NEXUS test suite (offline only)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lib.config import Config, load_config  # noqa: E402
from phases.probe.tool_runner import ToolResult  # noqa: E402

REPO = ROOT


@pytest.fixture
def cfg() -> Config:
    """The repository's real configuration (no secrets present)."""
    return load_config(REPO / "config")


@pytest.fixture
def tmp_cfg(tmp_path: Path) -> Config:
    """A minimal throwaway config directory."""
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    (cfg_dir / "nexus.yaml").write_text(
        """
scanning:
  default_intensity: quick-scan
  tool_timeout_seconds: 30
  rate_limit_default: "50/minute"
phases:
  hunt:
    enabled: false
    max_scans_per_day: 5
targets:
  example.com:
    intensity: full-scan
    tools: [nuclei, dalfox, sqlmap]
    rate_limit: "100/minute"
""",
        encoding="utf-8",
    )
    (cfg_dir / "false_positive_filters.yaml").write_text(
        """
filters:
  xss:
    strictness: aggressive
    confidence_threshold: 90
    auto_filter: ["Displayed as plain text"]
  sqli:
    strictness: conservative
    confidence_threshold: 70
    auto_filter: []
""",
        encoding="utf-8",
    )
    return load_config(cfg_dir)


class FakeRunner:
    """Deterministic stand-in for ToolRunner (no subprocess)."""

    def __init__(self, responses: dict[str, ToolResult] | None = None, default: str = ""):
        self.responses = responses or {}
        self.default = default
        self.calls: list[tuple[str, list[str]]] = []

    def tool_available(self, tool: str) -> bool:
        return tool in self.responses

    def run(self, tool: str, args: list[str], stdin_data=None, env=None) -> ToolResult:
        self.calls.append((tool, list(args)))
        if tool in self.responses:
            return self.responses[tool]
        return ToolResult(tool=tool, cmd=[tool] + list(args), returncode=0, stdout=self.default, status="ok")


@pytest.fixture
def fake_runner_factory():
    """Factory returning a FakeRunner with given canned outputs."""

    def _make(mapping: dict[str, str], missing: bool = False):
        responses = {}
        for tool, stdout in mapping.items():
            responses[tool] = ToolResult(
                tool=tool, cmd=[tool], returncode=0, stdout=stdout, status="ok"
            )
        runner = FakeRunner(responses)
        return runner

    return _make
