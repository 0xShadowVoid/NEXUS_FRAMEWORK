"""Screenshot capture (feature 32) with standard naming.

Uses ``gowitness`` when installed; otherwise records nothing and logs.
Filenames follow BUILD_SPEC Part 6:
``{domain}-{date}-{time}-{kind}-{id}.png``.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from lib.logger import get_logger
from lib.utils import now_utc, screenshot_name

logger = get_logger("screenshot")


def capture_screenshot(
    url: str,
    domain: str,
    out_dir: Path,
    runner: Any,
    kind: str = "finding",
    idx: int = 1,
) -> Path | None:
    """Capture a screenshot of *url*; returns the saved path or None.

    ``runner`` is a ToolRunner-like object exposing ``run``/``tool_available``.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    now = now_utc()
    name = screenshot_name(domain, now.strftime("%Y-%m-%d"), now.strftime("%H-%M"), kind, idx)
    dest = out_dir / name

    if hasattr(runner, "tool_available") and not runner.tool_available("gowitness"):
        logger.debug("gowitness not installed; skipping screenshot for %s", url)
        return None

    result = runner.run(
        "gowitness",
        ["single", "--url", url, "--screenshot-path", str(out_dir), "--write-db"],
    )
    if getattr(result, "status", "error") != "ok":
        logger.debug("screenshot failed for %s (%s)", url, getattr(result, "status", "?"))
        return None
    # gowitness names files itself; normalize by renaming the newest png.
    pngs = sorted(out_dir.glob("*.png"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not pngs:
        return None
    newest = pngs[0]
    if newest != dest:
        try:
            newest.replace(dest)
        except OSError:
            return newest
    return dest


def capture_batch(
    urls: list[str],
    domain: str,
    out_dir: Path,
    runner: Any,
    limit: int = 5,
) -> list[Path]:
    """Capture up to *limit* screenshots; returns saved paths."""
    saved: list[Path] = []
    for i, url in enumerate(urls[:limit], start=1):
        path = capture_screenshot(url, domain, out_dir, runner, kind="finding", idx=i)
        if path:
            saved.append(path)
    logger.info("screenshots captured: %d", len(saved))
    return saved
