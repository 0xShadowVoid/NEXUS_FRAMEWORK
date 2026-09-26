"""Threat-intel feeds: CISA KEV (known-exploited) + EPSS exploitation scoring.

Read-only fetch of public threat-intel used to **prioritise** CVE alerts —
known-exploited CVEs first, then by exploitation probability.

Detection prioritisation only: this module never exploits anything and
never sends data anywhere except the two public read-only APIs below.

Both fetchers degrade gracefully (log + empty result) so an offline or
rate-limited environment never breaks a scan.
"""
from __future__ import annotations

from typing import Any

import requests

from lib.logger import get_logger

logger = get_logger("threat_feeds")

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
GHSA_URL = "https://api.github.com/advisories"

_TIMEOUT = (10, 30)
_EPSS_BATCH = 100          # ids per EPSS request
EPSS_INTERESTING = 0.5     # "notable" exploitation probability


class ThreatFeeds:
    """Read-only client for CISA KEV and FIRST EPSS."""

    def __init__(self, session: requests.Session | None = None, timeout: tuple[int, int] = _TIMEOUT):
        self.session = session or requests
        self.timeout = timeout

    def fetch_kev(self) -> set[str]:
        """Return the set of CVE ids in the CISA KEV catalog (upper-cased)."""
        try:
            resp = self.session.get(KEV_URL, timeout=self.timeout)
            if getattr(resp, "status_code", 0) != 200:
                logger.warning("KEV fetch failed: HTTP %s", getattr(resp, "status_code", "?"))
                return set()
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning("KEV fetch error: %s", exc)
            return set()

        ids: set[str] = set()
        for entry in (data.get("vulnerabilities") or []):
            cve_id = str(entry.get("cveID") or entry.get("cve_id") or "").strip().upper()
            if cve_id:
                ids.add(cve_id)
        return ids

    def fetch_epss(self, cve_ids: list[str]) -> dict[str, float]:
        """Return ``{CVE-id: epss_score}`` for the given ids (batched)."""
        out: dict[str, float] = {}
        ids = [str(c).strip().upper() for c in (cve_ids or []) if str(c).strip()]
        for start in range(0, len(ids), _EPSS_BATCH):
            chunk = ids[start : start + _EPSS_BATCH]
            try:
                resp = self.session.get(
                    EPSS_URL, params={"cve": ",".join(chunk)}, timeout=self.timeout
                )
                if getattr(resp, "status_code", 0) != 200:
                    logger.warning("EPSS fetch failed: HTTP %s", getattr(resp, "status_code", "?"))
                    continue
                data = resp.json()
            except (requests.RequestException, ValueError) as exc:
                logger.warning("EPSS fetch error: %s", exc)
                continue
            for row in (data.get("data") or []):
                cve_id = str(row.get("cve", "")).strip().upper()
                try:
                    score = float(row.get("epss", 0.0))
                except (TypeError, ValueError):
                    score = 0.0
                if cve_id:
                    out[cve_id] = score
        return out


    def fetch_ghsa(self, ecosystem: str = "") -> list[dict[str, Any]]:
        """Fetch recent GitHub Security Advisories (roadmap B6).

        Returns ``[{ghsa_id, cve_ids, severity, summary, ecosystem}]``.
        Degrades to an empty list on any error.
        """
        params = {"per_page": 100}
        if ecosystem:
            params["ecosystem"] = ecosystem
        try:
            resp = self.session.get(GHSA_URL, params=params, timeout=self.timeout)
            if getattr(resp, "status_code", 0) != 200:
                logger.warning("GHSA fetch failed: HTTP %s", getattr(resp, "status_code", "?"))
                return []
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning("GHSA fetch error: %s", exc)
            return []

        out: list[dict[str, Any]] = []
        for a in (data or []):
            cve_ids = [i.get("value", "") for i in (a.get("identifiers") or [])
                       if str(i.get("type", "")).upper() == "CVE"]
            out.append({
                "ghsa_id": a.get("ghsa_id", ""),
                "cve_ids": cve_ids,
                "severity": str(a.get("severity", "")).lower(),
                "summary": str(a.get("summary", ""))[:300],
                "ecosystem": a.get("ecosystem", ""),
            })
        return out


def enrich_cves(cves: list[dict[str, Any]], feeds: ThreatFeeds | None = None) -> list[dict[str, Any]]:
    """Add ``kev`` (bool), ``epss`` (float) and ``priority`` (KEV=0 else 1)."""
    feeds = feeds or ThreatFeeds()
    cve_ids = [str(c.get("cve_id", "")).strip().upper() for c in (cves or []) if c.get("cve_id")]
    kev = feeds.fetch_kev()
    epss = feeds.fetch_epss(cve_ids)
    for cve in cves or []:
        cve_id = str(cve.get("cve_id", "")).strip().upper()
        cve["kev"] = cve_id in kev
        cve["epss"] = float(epss.get(cve_id, 0.0))
        cve["priority"] = 0 if cve["kev"] else 1
    logger.info("threat feeds: %d KEV ids, %d EPSS scores", len(kev), len(epss))
    return cves


def sort_by_priority(cves: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Known-exploited first, then highest EPSS, then original order."""
    return sorted(
        cves or [],
        key=lambda c: (int(c.get("priority", 1)), -float(c.get("epss", 0.0))),
    )


def epss_interesting_count(cves: list[dict[str, Any]], threshold: float = EPSS_INTERESTING) -> int:
    """Count CVEs whose EPSS score is at or above *threshold*."""
    return sum(1 for c in (cves or []) if float(c.get("epss", 0.0)) >= threshold)
