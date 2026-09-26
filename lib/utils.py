"""Naming conventions and result-directory management (BUILD_SPEC Part 6)."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def now_utc() -> datetime:
    """Current UTC time (aware)."""
    return datetime.now(timezone.utc)


def utc_timestamp() -> str:
    """ISO-8601 UTC timestamp string."""
    return now_utc().isoformat(timespec="seconds")


def sanitize_path_component(value: str) -> str:
    """Make *value* safe as a single path component."""
    cleaned = _UNSAFE_CHARS.sub("-", (value or "").strip().lower())
    cleaned = re.sub(r"-{2,}", "-", cleaned).strip("-.")
    return cleaned or "unknown"


def scan_folder_name(
    domain: str,
    platform: str,
    program_type: str,
    scope_kind: str,
    date: str | None = None,
    time: str | None = None,
) -> str:
    """``{domain}-{platform}-{type}-{scope}-{date}-{time}`` folder name.

    Date/time default to now (UTC). Time uses ``HH-MM`` so it is
    filesystem-safe.
    """
    now = now_utc()
    d = date or now.strftime("%Y-%m-%d")
    t = time or now.strftime("%H-%M")
    parts = [
        sanitize_path_component(domain),
        sanitize_path_component(platform),
        sanitize_path_component(program_type),
        sanitize_path_component(scope_kind),
        sanitize_path_component(d),
        sanitize_path_component(t),
    ]
    return "-".join(parts)


def findings_report_name(
    domain: str,
    platform: str,
    program_type: str,
    scope_kind: str,
    date: str | None = None,
) -> str:
    """``{domain}-{platform}-{type}-{scope}-{date}-findings.md``."""
    now = now_utc()
    d = date or now.strftime("%Y-%m-%d")
    parts = [
        sanitize_path_component(domain),
        sanitize_path_component(platform),
        sanitize_path_component(program_type),
        sanitize_path_component(scope_kind),
        sanitize_path_component(d),
    ]
    return "-".join(parts) + "-findings.md"


def screenshot_name(domain: str, date: str, time: str, kind: str, idx: int) -> str:
    """``{domain}-{date}-{time}-{type}-{id}.png`` (kind=finding|chain)."""
    return "{domain}-{date}-{time}-{kind}-{idx:03d}.png".format(
        domain=sanitize_path_component(domain),
        date=sanitize_path_component(date),
        time=sanitize_path_component(time),
        kind=sanitize_path_component(kind),
        idx=idx,
    )


RESULT_SUBDIRS = ("recon", "scans", "processed", "reports", "screenshots")


def create_results_tree(base_dir: Path | str, folder_name: str) -> Path:
    """Create ``base_dir/folder_name`` with the standard subdirectories.

    Returns the scan-results directory path.
    """
    root = Path(base_dir) / folder_name
    for sub in RESULT_SUBDIRS:
        (root / sub).mkdir(parents=True, exist_ok=True)
    return root
