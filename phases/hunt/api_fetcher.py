"""Platform API fetcher (HUNT phase).

Fetches new program listings from HackerOne and Bugcrowd APIs.
Best-effort: missing credentials or API failures degrade to an empty
list with a log entry — the hunt phase never crashes the framework.
"""
from __future__ import annotations

from typing import Any

import requests

from lib.logger import get_logger

logger = get_logger("api_fetcher")

_TIMEOUT = (10, 30)

H1_ENDPOINT = "https://api.hackerone.com/v1/hackers/programs"
BUGCROWD_ENDPOINT = "https://api.bugcrowd.com/programs"


INTIGRITI_ENDPOINT = "https://api.intigriti.com/external/researcher/v2/programs"
YESWEHACK_ENDPOINT = "https://api.yeswehack.com/programs"


def fetch_intigriti_programs(api_key: str, session: requests.Session | None = None) -> list[dict[str, Any]]:
    """Fetch Intigriti programs (bearer auth). Normalized shape."""
    if not api_key:
        logger.debug("intigriti key unset; skipping fetch")
        return []
    sess = session or requests
    try:
        resp = sess.get(
            INTIGRITI_ENDPOINT,
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return []
        programs = []
        for p in (resp.json() or []):
            programs.append({
                "name": p.get("name", ""),
                "platform": "intigriti",
                "url": p.get("url", ""),
                "type": "bb" if p.get("maxBounty") else "vdp",
                "in_scope": [d.get("endpoint", "") for d in (p.get("domains") or [])],
            })
        return programs
    except (requests.RequestException, ValueError) as exc:
        logger.warning("intigriti fetch error: %s", exc)
        return []


def fetch_yeswehack_programs(api_key: str, session: requests.Session | None = None) -> list[dict[str, Any]]:
    """Fetch YesWeHack programs. Normalized shape."""
    if not api_key:
        logger.debug("yeswehack key unset; skipping fetch")
        return []
    sess = session or requests
    try:
        resp = sess.get(
            YESWEHACK_ENDPOINT,
            headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            return []
        programs = []
        for p in (resp.json() or {}).get("items", []) or []:
            programs.append({
                "name": p.get("title", ""),
                "platform": "yeswehack",
                "url": p.get("url", ""),
                "type": "bb" if p.get("bounty_reward") else "vdp",
                "in_scope": [s.get("scope", "") for s in (p.get("scopes") or [])],
            })
        return programs
    except (requests.RequestException, ValueError) as exc:
        logger.warning("yeswehack fetch error: %s", exc)
        return []


def fetch_hackerone_programs(username: str, api_token: str, session: requests.Session | None = None) -> list[dict[str, Any]]:
    """Fetch H1 program listings (basic auth). Returns normalized programs."""
    if not username or not api_token:
        logger.debug("hackerone credentials unset; skipping fetch")
        return []
    sess = session or requests
    try:
        resp = sess.get(
            H1_ENDPOINT,
            auth=(username, api_token),
            headers={"Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            logger.warning("hackerone fetch failed: HTTP %d", resp.status_code)
            return []
        data = resp.json()
        programs = []
        for p in (data.get("data") or []):
            attrs = p.get("attributes") or {}
            programs.append({
                "name": attrs.get("name", ""),
                "platform": "hackerone",
                "url": attrs.get("url", ""),
                "started": attrs.get("started_accepting_at"),
                "type": "bb" if attrs.get("offers_bounties") else "vdp",
                "in_scope": [
                    s.get("asset_identifier", "")
                    for s in (attrs.get("scope") or {}).get("list", [])
                    if s.get("eligible_for_bounty")
                ],
            })
        return programs
    except (requests.RequestException, ValueError) as exc:
        logger.warning("hackerone fetch error: %s", exc)
        return []


def fetch_bugcrowd_programs(api_key: str, session: requests.Session | None = None) -> list[dict[str, Any]]:
    """Fetch Bugcrowd program listings (token auth). Returns normalized programs."""
    if not api_key:
        logger.debug("bugcrowd key unset; skipping fetch")
        return []
    sess = session or requests
    try:
        resp = sess.get(
            BUGCROWD_ENDPOINT,
            headers={"Authorization": f"Token {api_key}", "Accept": "application/json"},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 200:
            logger.warning("bugcrowd fetch failed: HTTP %d", resp.status_code)
            return []
        programs = []
        for p in (resp.json() or {}).get("programs", []) or []:
            programs.append({
                "name": p.get("name", ""),
                "platform": "bugcrowd",
                "url": p.get("url", ""),
                "started": p.get("launched_at"),
                "type": "bb" if p.get("max_payout") else "vdp",
                "in_scope": [
                    t.get("target", "")
                    for t in (p.get("targets") or {}).get("in_scope", [])
                ],
            })
        return programs
    except (requests.RequestException, ValueError) as exc:
        logger.warning("bugcrowd fetch error: %s", exc)
        return []
