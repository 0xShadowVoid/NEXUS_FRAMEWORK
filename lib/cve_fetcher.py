"""NVD CVE fetcher (REST API 2.0).

Fetches recent CVEs published in a time window, filters by severity
(critical/high), and matches affected technology against a target tech
stack. All requests go through ``requests`` with timeouts; failures
degrade gracefully (empty result + log).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import requests

from lib.logger import get_logger

logger = get_logger("cve_fetcher")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TIMEOUT = (10, 30)
_MAX_RESULTS_DEFAULT = 500

# CVSS severity label → minimum CVSS3 score band.
_SEVERITY_SCORES = {
    "critical": (9.0, 10.0),
    "high": (7.0, 8.99),
    "medium": (4.0, 6.99),
    "low": (0.1, 3.99),
}


def severity_from_score(score: float) -> str:
    """Map a CVSS3 score to a severity label."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _iso_nvd(dt: datetime) -> str:
    """NVD expects ISO-8601 with offset and no microseconds."""
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


class CVEFetcher:
    """NVD 2.0 client with severity filtering and tech matching."""

    def __init__(self, api_key: str = "", session: requests.Session | None = None):
        self.api_key = api_key
        self.session = session or requests

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def fetch_recent(
        self,
        hours: int = 24,
        min_severity: str = "high",
        max_results: int = _MAX_RESULTS_DEFAULT,
    ) -> list[dict[str, Any]]:
        """Fetch CVEs published in the last *hours* hours.

        Returns normalized records:
        ``{cve_id, severity, score, description, published, affected_products}``.
        """
        now = datetime.now(timezone.utc)
        start = now - timedelta(hours=hours)
        params = {
            "pubStartDate": _iso_nvd(start),
            "pubEndDate": _iso_nvd(now),
            "resultsPerPage": min(max_results, 2000),
        }
        try:
            resp = self.session.get(
                NVD_API_URL, params=params, headers=self._headers(), timeout=_TIMEOUT
            )
            if resp.status_code != 200:
                logger.warning("NVD fetch failed: HTTP %d", resp.status_code)
                return []
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            logger.warning("NVD fetch error: %s", exc)
            return []

        threshold = _SEVERITY_SCORES.get(min_severity, (7.0, 10.0))[0]
        out: list[dict[str, Any]] = []
        for vuln in (data.get("vulnerabilities") or [])[:max_results]:
            cve = vuln.get("cve") or {}
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
            # Metrics: prefer CVSS31, fall back to CVSS2.
            score, severity = self._extract_metrics(cve)
            if score is not None and score < threshold:
                continue
            description = self._english_description(cve)
            products = self._affected_products(cve)
            out.append({
                "cve_id": cve_id,
                "severity": severity or "unknown",
                "score": score,
                "description": description,
                "published": cve.get("published", ""),
                "affected_products": products,
            })
        return out

    @staticmethod
    def _extract_metrics(cve: dict[str, Any]) -> tuple[float | None, str | None]:
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key) or []
            if entries:
                data = entries[0].get("cvssData") or {}
                score = data.get("baseScore")
                severity = (
                    data.get("baseSeverity")
                    or entries[0].get("baseSeverity")
                )
                if score is not None:
                    return float(score), str(severity or "").lower() or None
        return None, None

    @staticmethod
    def _english_description(cve: dict[str, Any]) -> str:
        for desc in cve.get("descriptions") or []:
            if desc.get("lang") == "en":
                return str(desc.get("value", ""))
        return ""

    @staticmethod
    def _affected_products(cve: dict[str, str | list[dict[str, Any]]]) -> list[str]:
        """Extract affected product names from CPE configurations."""
        products: set[str] = set()
        for conf in cve.get("configurations") or []:
            nodes = conf.get("nodes") or []
            for node in nodes:
                for cpe_match in node.get("cpeMatch") or []:
                    cpe = str(cpe_match.get("criteria", "") or "")
                    if not cpe:
                        continue
                    # cpe:2.3:a:vendor:product:version:...
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        vendor, product = parts[3], parts[4]
                        if product:
                            products.add(f"{vendor}:{product}")
        return sorted(products)


def match_tech(cves: list[dict[str, Any]], tech_stack: list[str] | dict[str, Any]) -> list[tuple[dict[str, Any], list[str]]]:
    """Match CVE affected products against a target's tech stack.

    *tech_stack* is a list of tech names (e.g. ``["WordPress 6.0", "Apache"]``)
    or a Wappalyzer-style dict ``{"WordPress": "6.0", ...}``.
    Returns ``(cve, matched_techs)`` pairs.
    """
    if isinstance(tech_stack, dict):
        techs = [f"{name} {ver}".strip() for name, ver in tech_stack.items()]
    else:
        techs = list(tech_stack or [])

    matches: list[tuple[dict[str, Any], list[str]]] = []
    for cve in cves:
        matched: list[str] = []
        for tech in techs:
            tech_l = str(tech).lower()
            tech_name = tech_l.split()[0] if tech_l.split() else tech_l
            for product in cve.get("affected_products", []):
                p_l = product.lower()
                if tech_name and (tech_name in p_l or p_l in tech_l or p_l.split(":")[-1] in tech_l):
                    matched.append(str(tech))
                    break
        if matched:
            matches.append((cve, matched))
    return matches
