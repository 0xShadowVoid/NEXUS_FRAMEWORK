"""Unit tests for methodology coverage/drift and screenshots."""
from __future__ import annotations

from pathlib import Path

from lib.methodology import (
    coverage,
    load_methodologies,
    methodology_hash,
)
from lib.screenshot import capture_batch, capture_screenshot


def test_load_repo_methodologies():
    data = load_methodologies()
    assert "web_app_checklist" in data["methodologies"]


def test_coverage_counts_covered_items():
    methodology = {
        "sections": [
            {"id": "recon", "items": [
                {"id": "subs", "tools": ["subfinder"]},
                {"id": "urls", "tools": ["katana"]},
            ]},
            {"id": "inj", "items": [
                {"id": "xss", "tools": ["dalfox", "nuclei"]},
            ]},
        ]
    }
    result = coverage(methodology, ["subfinder", "dalfox"])
    assert result["items_total"] == 3
    assert result["items_covered"] == 2
    assert result["percent"] == 66.7


def test_methodology_hash_stable():
    m = {"sections": [{"items": [{"id": "a"}]}]}
    assert methodology_hash(m) == methodology_hash(m)


class _Runner:
    def __init__(self, available: bool):
        self._available = available
        self.calls = []

    def tool_available(self, tool: str) -> bool:
        return self._available

    def run(self, tool, args, stdin_data=None, env=None):
        self.calls.append((tool, args))

        class _R:
            status = "ok"

        return _R()


def test_screenshot_skipped_when_tool_missing(tmp_path: Path):
    runner = _Runner(available=False)
    assert capture_screenshot("https://x/", "x.com", tmp_path, runner) is None


def test_screenshot_naming_when_tool_present(tmp_path: Path):
    runner = _Runner(available=True)
    # Simulate gowitness writing a png.
    (tmp_path / "shot.png").write_bytes(b"\x89PNG")

    class _RunnerWithFile(_Runner):
        def run(self, tool, args, stdin_data=None, env=None):
            self.calls.append((tool, args))
            (tmp_path / "out.png").write_bytes(b"\x89PNG")

            class _R:
                status = "ok"

            return _R()

    r = _RunnerWithFile(available=True)
    path = capture_screenshot("https://x/", "x.com", tmp_path, r, kind="finding", idx=1)
    assert path is not None
    # Naming per spec: {domain}-{date}-{time}-{kind}-{id}.png
    assert path.name.startswith("x.com-")
    assert path.name.endswith("-finding-001.png")
    # {domain}-{Y}-{m}-{d}-{H}-{M}-{kind}-{id}.png
    assert len(path.name.split("-")) == 8


def test_capture_batch_respects_limit(tmp_path: Path):
    runner = _Runner(available=False)
    assert capture_batch(["a", "b", "c"], "x.com", tmp_path, runner, limit=2) == []
