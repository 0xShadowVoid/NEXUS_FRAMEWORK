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
from lib.ssrf_guard import is_safe_url
from lib.versioning import (
    VersionRange,
    aggregate_status,
    cpe_fields,
    name_tokens,
    parse_version,
)

logger = get_logger("cve_fetcher")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Fixed public destination: explicit SSRF guard allowlist (Pass 3B).
_SSRF_ALLOW = {"services.nvd.nist.gov"}
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
        safe, reason = is_safe_url(NVD_API_URL, allow=_SSRF_ALLOW)
        if not safe:
            logger.warning("ssrf guard blocked %s: %s", NVD_API_URL, reason)
            return []
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
                # Pass 3C: version-aware CPE details (vendor/product/version/range).
                "affected_details": self._affected_details(cve),
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

    @staticmethod
    def _affected_details(cve: dict[str, Any]) -> list[dict[str, Any]]:
        """Version-aware per-CPE detail entries (Pass 3C).

        Each entry: ``{vendor, product, version, range: VersionRange}``.
        Only CPEs marked vulnerable (default true) are included.
        """
        details: list[dict[str, Any]] = []
        for conf in cve.get("configurations") or []:
            for node in (conf.get("nodes") or []):
                for cpe_match in (node.get("cpeMatch") or []):
                    if cpe_match.get("vulnerable") is False:
                        continue
                    cpe = str(cpe_match.get("criteria", "") or "")
                    if not cpe:
                        continue
                    fields = cpe_fields(cpe)
                    details.append({
                        "vendor": fields.get("vendor", ""),
                        "product": fields.get("product", ""),
                        "version": fields.get("version", ""),
                        "range": VersionRange.from_cpe_match(cpe_match),
                    })
        return details


def _tech_pairs(tech_stack: list[str] | dict[str, Any] | None) -> list[tuple[str, str]]:
    """Normalize a tech stack into ``[(name, version), ...]`` pairs.

    Accepts a Wappalyzer-style dict (``{"WordPress": "6.0"}``) or a list of
    ``"Name Version"`` strings (``["WordPress 6.0", "Apache"]``).
    """
    if isinstance(tech_stack, dict):
        return [(str(name), str(ver or "")) for name, ver in tech_stack.items()]
    pairs: list[tuple[str, str]] = []
    for item in (tech_stack or []):
        text = str(item or "").strip()
        if not text:
            continue
        name, _, version = text.rpartition(" ")
        if name and version and any(ch.isdigit() for ch in version):
            pairs.append((name, version))
        else:
            pairs.append((text, ""))
    return pairs


def _tech_label(name: str, version: str) -> str:
    return f"{name} {version}".strip()


def _match_strength(tech_name: str, detail: dict[str, Any]) -> str:
    """Classify name-match strength against one CPE detail entry.

    ``strong`` — product confidently the same product: exact token equality
    or all product tokens contained in the tech name tokens.
    ``weak``  — vendor/partial overlap only (name-level candidate).
    ``""``    — no overlap (CPE mismatch).
    """
    t = name_tokens(tech_name)
    if not t:
        return ""
    product = str(detail.get("product", "") or "")
    vendor = str(detail.get("vendor", "") or "")
    p = name_tokens(product)
    if not p:
        return ""
    if t == p or p <= t:
        return "strong"
    if vendor and vendor in t:
        return "weak"
    if t & p:
        return "weak"
    return ""


def _evaluate_entry(tech_version: str, detail: dict[str, Any]) -> str:
    """Per-entry verdict for a strong match.

    Returns ``affected`` | ``unaffected`` | ``unknown`` | ``candidate``.
    A bare listed version with no numeric bounds never proves a different
    version safe — a mismatch downgrades to ``candidate`` (never excluded).
    """
    if not tech_version:
        return "candidate"
    if parse_version(tech_version) is None:
        return "unknown"
    vrange = detail.get("range")
    verdict = vrange.evaluate(tech_version) if vrange is not None else "unknown"
    if verdict == "unaffected":
        has_bounds = bool(
            getattr(vrange, "start_including", "")
            or getattr(vrange, "start_excluding", "")
            or getattr(vrange, "end_including", "")
            or getattr(vrange, "end_excluding", "")
        )
        return "unaffected" if has_bounds else "candidate"
    return verdict


def _legacy_product_match(tech_name: str, products: list[str]) -> bool:
    """Historical name heuristic for CVEs with no CPE detail entries."""
    t = str(tech_name or "").lower().strip()
    if not t:
        return False
    for product in products or []:
        p_l = str(product).lower()
        if t in p_l or p_l in t or p_l.split(":")[-1] in t:
            return True
    return False


def match_tech_ex(
    cves: list[dict[str, Any]],
    tech_stack: list[str] | dict[str, Any] | None,
) -> tuple[list[tuple[dict[str, Any], list[str]]], dict[str, int]]:
    """Version-aware CVE ↔ tech-stack matching (Pass 3C).

    Returns ``(matches, report)``. *matches* keeps the historical
    ``(cve, matched_techs)`` shape; *report* counts ``affected`` /
    ``unknown`` / ``candidate`` matches plus definitively-``unaffected``
    CVEs that were excluded.

    Each matched CVE dict gains ``applicability`` and ``version_evidence``.
    Name-only matches stay ``candidate`` — never presented as confirmed.
    """
    pairs = _tech_pairs(tech_stack)
    matches: list[tuple[dict[str, Any], list[str]]] = []
    report = {"affected": 0, "unknown": 0, "candidate": 0, "unaffected": 0}

    for cve in cves or []:
        details = cve.get("affected_details") or []
        verdicts: list[str] = []
        matched: list[str] = []
        evidence: list[dict[str, Any]] = []

        for tech_name, tech_version in pairs:
            label = _tech_label(tech_name, tech_version)
            tech_verdicts: list[str] = []
            if not details:
                if _legacy_product_match(tech_name, cve.get("affected_products") or []):
                    tech_verdicts.append("candidate")
                    evidence.append({
                        "tech": label, "verdict": "candidate",
                        "reason": "product-name match only (no CPE version data)",
                    })
            else:
                for detail in details:
                    strength = _match_strength(tech_name, detail)
                    if not strength:
                        continue
                    verdict = (
                        _evaluate_entry(tech_version, detail)
                        if strength == "strong"
                        else "candidate"
                    )
                    tech_verdicts.append(verdict)
                    evidence.append({
                        "tech": label,
                        "vendor": detail.get("vendor", ""),
                        "product": detail.get("product", ""),
                        "detected_version": tech_version,
                        "verdict": verdict,
                        "match": strength,
                    })
            if tech_verdicts:
                verdicts.append(aggregate_status(tech_verdicts))
                matched.append(label)

        if not verdicts:
            continue
        overall = aggregate_status(verdicts)
        if overall == "unaffected":
            report["unaffected"] += 1
            continue
        report[overall] = report.get(overall, 0) + 1
        cve["applicability"] = overall
        cve["version_evidence"] = evidence
        matches.append((cve, matched))
    return matches, report


def match_tech(
    cves: list[dict[str, Any]],
    tech_stack: list[str] | dict[str, Any],
) -> list[tuple[dict[str, Any], list[str]]]:
    """Match CVE affected products against a target's tech stack.

    Version-aware (Pass 3C): definitively-unaffected versions are excluded;
    name-only matches remain candidates. Returns ``(cve, matched_techs)``.
    """
    return match_tech_ex(cves, tech_stack)[0]
