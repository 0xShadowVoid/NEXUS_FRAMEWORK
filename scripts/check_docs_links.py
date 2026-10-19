"""Offline documentation link checker.

Scans Markdown files at the repository root and under ``docs/`` for relative
links and verifies that each target path exists. External links (http/https/
mailto) and pure anchors (``#section``) are ignored. Fenced code blocks are
skipped so example commands never produce false positives.

Exit codes: 0 = all relative links resolve, 1 = one or more broken links.

Usage::

    python scripts/check_docs_links.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

_LINK_RE = re.compile(r"\]\(([^)]+)\)")
_SKIP_PREFIXES = ("http://", "https://", "mailto:", "#")


def _iter_markdown() -> list[Path]:
    files: list[Path] = []
    for path in REPO_ROOT.glob("*.md"):
        files.append(path)
    docs = REPO_ROOT / "docs"
    if docs.is_dir():
        files.extend(sorted(docs.rglob("*.md")))
    return sorted(set(files))


def _strip_target(raw: str) -> str:
    target = raw.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    target = target.split("#", 1)[0].strip()
    target = target.split(" ", 1)[0].strip()
    return target


def check_file(path: Path) -> list[tuple[int, str]]:
    broken: list[tuple[int, str]] = []
    in_fence = False
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for raw in _LINK_RE.findall(line):
            target = _strip_target(raw)
            if not target or target.startswith(_SKIP_PREFIXES):
                continue
            resolved = (path.parent / target).resolve()
            if not resolved.exists():
                broken.append((lineno, target))
    return broken


def main() -> int:
    failures = 0
    checked = 0
    for md in _iter_markdown():
        checked += 1
        for lineno, target in check_file(md):
            rel = md.relative_to(REPO_ROOT)
            print(f"BROKEN {rel}:{lineno}: {target}")
            failures += 1
    if failures:
        print(f"\n{failures} broken link(s) across {checked} file(s).")
        return 1
    print(f"ok: all relative links resolve across {checked} markdown file(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
