"""Multi-engine dorking module (DISCOVER phase, OSINT extension).

Runs search-engine dork queries through multiple engines to discover
exposed documents, login pages, error pages, and other recon surface
for a target domain. Engines: DuckDuckGo HTML (no API key), Google
(scrape, best-effort), Bing (scrape, best-effort), and GitHub code
search (API when a token is present, HTML otherwise).

All requests go through ``requests`` with timeouts and a standard
User-Agent; results are parsed defensively. This module collects
publicly-indexed surface only — it stores URLs, never content.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote_plus, urlparse, parse_qs

import requests

from lib.logger import get_logger

logger = get_logger("dorker")

_TIMEOUT = (5, 20)
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NEXUS-Recon/1.0"

# Dork templates per intent. {domain} is the target domain.
DORK_TEMPLATES: dict[str, list[str]] = {
    "exposed_docs": [
        "site:{domain} ext:pdf",
        "site:{domain} ext:xls OR ext:xlsx OR ext:csv",
        "site:{domain} ext:doc OR ext:docx",
        "site:{domain} ext:log OR ext:txt OR ext:conf OR ext:env",
    ],
    "login_pages": [
        "site:{domain} inurl:login OR inurl:signin OR inurl:admin",
        'site:{domain} intitle:"login" OR intitle:"sign in"',
    ],
    "error_pages": [
        "site:{domain} inurl:error OR intitle:" + '"error"',
        'site:{domain} "sql syntax" OR "stack trace" OR "warning:"',
    ],
    "backups": [
        "site:{domain} ext:bak OR ext:old OR ext:orig OR ext:swp",
        "site:{domain} inurl:backup OR inurl:dump",
    ],
    "directories": [
        'site:{domain} intitle:"index of"',
        "site:{domain} inurl:wp-config OR inurl:.git",
    ],
    "github_leaks": [
        '"{domain}" password',
        '"{domain}" api_key OR apikey OR secret',
        '"{domain}" BEGIN RSA PRIVATE KEY',
        '"{domain}" filename:.env',
    ],
}

_DDG_RESULT_RE = re.compile(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"', re.IGNORECASE)
_GENERIC_LINK_RE = re.compile(r'<a[^>]+href="(https?://[^"]+)"', re.IGNORECASE)
_GOOGLE_URL_RE = re.compile(r'href="/url\?q=(https?://[^&"]+)')
_GOOGLE_DIRECT_RE = re.compile(r'<a href="(https?://[^"]+)"')
_BING_RESULT_RE = re.compile(r'<h2><a href="(https?://[^"]+)"', re.IGNORECASE)
_GH_CODE_RE = re.compile(r'href="(https?://github\.com/[^"]+/blob/[^"]+)"', re.IGNORECASE)


@dataclass
class DorkResult:
    """One dork query result for one engine."""

    intent: str
    query: str
    engine: str
    urls: list[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent,
            "query": self.query,
            "engine": self.engine,
            "urls": self.urls,
            "error": self.error,
        }


def _ddg_params(url: str) -> str | None:
    """Extract the real target URL from a DuckDuckGo redirect link."""
    if "//duckduckgo.com/l/?uddg=" in url:
        qs = parse_qs(urlparse(url).query)
        if "uddg" in qs and qs["uddg"]:
            return qs["uddg"][0]
    return None


class Dorker:
    """Multi-engine dork runner."""

    def __init__(self, session: requests.Session | None = None, timeout: tuple[int, int] = _TIMEOUT):
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": _UA})
        self.timeout = timeout

    # -- engines ------------------------------------------------------------

    def _search_ddg(self, intent: str, query: str) -> DorkResult:
        """DuckDuckGo HTML endpoint (no key required)."""
        url = "https://html.duckduckgo.com/html/?q=" + quote_plus(query)
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                return DorkResult(intent=intent, query=query, engine="duckduckgo", error=f"HTTP {resp.status_code}")
            urls: list[str] = []
            for raw in _DDG_RESULT_RE.findall(resp.text or ""):
                real = _ddg_params(raw) or raw
                if real.startswith("http") and "duckduckgo.com" not in real:
                    urls.append(real)
            if not urls:
                for raw in _GENERIC_LINK_RE.findall(resp.text or ""):
                    real = _ddg_params(raw) or raw
                    if real.startswith("http") and "duckduckgo.com" not in real:
                        urls.append(real)
            return DorkResult(intent=intent, query=query, engine="duckduckgo", urls=urls[:30])
        except requests.RequestException as exc:
            return DorkResult(intent=intent, query=query, engine="duckduckgo", error=str(exc))

    def _search_google(self, intent: str, query: str) -> DorkResult:
        """Google scrape (best-effort; may be blocked)."""
        url = "https://www.google.com/search?q=" + quote_plus(query) + "&num=30"
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                return DorkResult(intent=intent, query=query, engine="google", error=f"HTTP {resp.status_code}")
            urls = list(_GOOGLE_URL_RE.findall(resp.text or ""))
            for raw in _GOOGLE_DIRECT_RE.findall(resp.text or ""):
                if "google." not in raw:
                    urls.append(raw)
            seen: set[str] = set()
            out: list[str] = []
            for u in urls:
                if u not in seen:
                    seen.add(u)
                    out.append(u)
            return DorkResult(intent=intent, query=query, engine="google", urls=out[:30])
        except requests.RequestException as exc:
            return DorkResult(intent=intent, query=query, engine="google", error=str(exc))

    def _search_bing(self, intent: str, query: str) -> DorkResult:
        """Bing scrape (best-effort)."""
        url = "https://www.bing.com/search?q=" + quote_plus(query)
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code != 200:
                return DorkResult(intent=intent, query=query, engine="bing", error=f"HTTP {resp.status_code}")
            urls: list[str] = []
            for raw in _BING_RESULT_RE.findall(resp.text or ""):
                if "bing.com" not in raw:
                    urls.append(raw)
            seen: set[str] = set()
            out: list[str] = []
            for u in urls:
                if u not in seen:
                    seen.add(u)
                    out.append(u)
            return DorkResult(intent=intent, query=query, engine="bing", urls=out[:30])
        except requests.RequestException as exc:
            return DorkResult(intent=intent, query=query, engine="bing", error=str(exc))

    def _search_github(self, intent: str, query: str, token: str = "") -> DorkResult:
        """GitHub code search (API with token, else HTML search)."""
        if token:
            try:
                resp = self.session.get(
                    "https://api.github.com/search/code",
                    params={"q": query, "per_page": 30},
                    headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}"},
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    items = resp.json().get("items", [])
                    urls = [str(item.get("html_url", "")) for item in items if item.get("html_url")]
                    return DorkResult(intent=intent, query=query, engine="github", urls=urls[:30])
                return DorkResult(intent=intent, query=query, engine="github", error=f"HTTP {resp.status_code}")
            except requests.RequestException as exc:
                return DorkResult(intent=intent, query=query, engine="github", error=str(exc))
        # HTML fallback (no token) — best-effort.
        try:
            resp = self.session.get(
                "https://github.com/search",
                params={"q": query, "type": "code"},
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                return DorkResult(intent=intent, query=query, engine="github", error=f"HTML HTTP {resp.status_code}")
            urls = [u for u in _GH_CODE_RE.findall(resp.text or "")]
            return DorkResult(intent=intent, query=query, engine="github", urls=urls[:30])
        except requests.RequestException as exc:
            return DorkResult(intent=intent, query=query, engine="github", error=str(exc))

    # -- orchestration ------------------------------------------------------

    def run_intents(
        self,
        domain: str,
        intents: list[str] | None = None,
        engines: list[str] | None = None,
        github_token: str = "",
    ) -> list[DorkResult]:
        """Run dork intents across engines; returns all results."""
        intents = intents or list(DORK_TEMPLATES.keys())
        engines = engines or ["duckduckgo", "google", "bing", "github"]
        results: list[DorkResult] = []
        for intent in intents:
            templates = DORK_TEMPLATES.get(intent, [])
            for template in templates:
                query = template.format(domain=domain)
                if "duckduckgo" in engines:
                    results.append(self._search_ddg(intent, query))
                if "google" in engines:
                    results.append(self._search_google(intent, query))
                if "bing" in engines:
                    results.append(self._search_bing(intent, query))
                if "github" in engines and intent == "github_leaks":
                    results.append(self._search_github(intent, query, token=github_token))
        return results

    def run(self, domain: str, github_token: str = "") -> dict[str, Any]:
        """Run all intents on all engines; returns a serializable summary."""
        results = self.run_intents(domain, github_token=github_token)
        all_urls: set[str] = set()
        by_intent: dict[str, list[str]] = {}
        errors = 0
        for r in results:
            if r.error:
                errors += 1
            key = r.intent
            by_intent.setdefault(key, [])
            for u in r.urls:
                all_urls.add(u)
                by_intent[key].append(u)
        summary = {
            "domain": domain,
            "queries_run": len(results),
            "urls_found": len(all_urls),
            "errors": errors,
            "by_intent": {k: sorted(set(v)) for k, v in by_intent.items()},
            "results": [r.to_dict() for r in results],
        }
        logger.info(
            "dorking: %d queries, %d urls, %d engine errors",
            len(results), len(all_urls), errors,
        )
        return summary


def extract_engine_names() -> list[str]:
    """Engines supported by this module (for CLI help)."""
    return ["duckduckgo", "google", "bing", "github"]
