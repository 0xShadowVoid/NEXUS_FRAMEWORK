"""Delta scanning helpers (roadmap D6).

Compares the current recon surface with the previous run's state so a
scan can target only what is new (new subdomains / URLs).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lib.logger import get_logger

logger = get_logger("delta")

STATE_FILE = ".recon_state.json"


def compute_delta(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Return new/removed subdomains and URLs between two recon summaries."""
    prev_subs = {str(s).lower() for s in (previous.get("subdomains") or [])}
    cur_subs = {str(s).lower() for s in (current.get("subdomains") or [])}
    prev_urls = {str(u) for u in (previous.get("urls") or [])}
    cur_urls = {str(u) for u in (current.get("urls") or [])}
    return {
        "new_subdomains": sorted(cur_subs - prev_subs),
        "removed_subdomains": sorted(prev_subs - cur_subs),
        "new_urls": sorted(cur_urls - prev_urls),
        "removed_urls": sorted(prev_urls - cur_urls),
    }


class ReconState:
    """Persisted previous-recon state for one target."""

    def __init__(self, base_dir: Path, domain: str):
        self.path = Path(base_dir) / f"{domain}{STATE_FILE}"

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def save(self, summary: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "subdomains": list(summary.get("subdomains") or []),
            "urls": list(summary.get("urls") or []),
        }
        self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def filter_new_urls(urls: list[str], previous_urls: list[str]) -> list[str]:
    """Return URLs not present in the previous run (all when none known)."""
    if not previous_urls:
        return list(urls)
    prev = {str(u) for u in previous_urls}
    return [u for u in urls if str(u) not in prev]
