"""Wappalyzer-style tech detection (DISCOVER phase).

Fetches the target homepage (and optional paths) and matches response
headers + body against a built-in technology fingerprint database.
Offline-safe: works on supplied responses when no network is available.
"""
from __future__ import annotations

import re
from typing import Any

import requests

from lib.logger import get_logger

logger = get_logger("wappalyzer_wrapper")

_TIMEOUT = (5, 20)
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NEXUS-Recon/1.0"

# Fingerprint database: tech → list of (header regex, body regex) hints.
# Any hint matches → tech detected. Version capture group = version.
_FINGERPRINTS: dict[str, list[dict[str, str]]] = {
    "WordPress": [
        {"body": r"wp-content|wp-includes"},
        {"header": r"(?i)x-pingback: .*wordpress"},
        {"body": r"(?i)<meta name=\"generator\" content=\"WordPress ([0-9.]+)\""},
    ],
    "Apache": [{"header": r"(?i)server: Apache/([0-9.]+)"}],
    "Nginx": [{"header": r"(?i)server: nginx/([0-9.]+)"}],
    "Microsoft-IIS": [{"header": r"(?i)server: Microsoft-IIS/([0-9.]+)"}],
    "PHP": [
        {"header": r"(?i)x-powered-by: PHP/([0-9.]+)"},
        {"body": r"(?i)<\?php"},
    ],
    "ASP.NET": [
        {"header": r"(?i)x-aspnet-version: ([0-9.]+)"},
        {"header": r"(?i)x-powered-by: ASP\.NET"},
    ],
    "jQuery": [{"body": r"(?i)jquery[.-]?v?([0-9.]+)"}],
    "React": [{"body": r"(?i)react(-dom)?[.-]([0-9.]+)"}],
    "Angular": [{"body": r"(?i)angular[.-]?([0-9.]+)"}],
    "Vue.js": [{"body": r"(?i)vue[.-]?([0-9.]+)"}],
    "Drupal": [{"body": r"(?i)drupal"}],
    "Joomla": [{"body": r"(?i)joomla"}],
    "Tomcat": [{"header": r"(?i)server: Apache-Coyote|Tomcat/([0-9.]+)"}],
    "Jetty": [{"header": r"(?i)server: Jetty\(([0-9.]+)\)"}],
    "Express": [{"header": r"(?i)x-powered-by: Express"}],
    "Next.js": [{"body": r"(?i)__NEXT_DATA__"}],
    "GraphQL": [{"body": r"(?i)graphql"}],
    "Cloudflare": [{"header": r"(?i)server: cloudflare"}],
    "Fastly": [{"header": r"(?i)x-served-by: cache-.*-fastly"}],
}


def detect_from_response(url: str, headers: dict[str, str], body: str) -> dict[str, str]:
    """Match fingerprints against one response; returns {tech: version}."""
    detected: dict[str, str] = {}
    header_blob = "\r\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    for tech, hints in _FINGERPRINTS.items():
        for hint in hints:
            hrx = hint.get("header")
            brx = hint.get("body")
            if hrx:
                m = re.search(hrx, header_blob)
                if m:
                    detected[tech] = (m.group(1) if m.groups() else "") or ""
                    break
            if brx:
                m = re.search(brx, body or "")
                if m:
                    detected[tech] = (m.group(1) if m.groups() else "") or ""
                    break
    return detected


class WappalyzerWrapper:
    """Fetches target pages and detects the tech stack."""

    def __init__(self, session: requests.Session | None = None, timeout: tuple[int, int] = _TIMEOUT):
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": _UA})
        self.timeout = timeout

    def detect(
        self,
        url: str,
        extra_paths: list[str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Detect tech for *url*; returns {'url', 'tech': {name: version}}."""
        aggregate: dict[str, str] = {}
        paths = [""] + list(extra_paths or [])
        for path in paths:
            target = url.rstrip("/") + path
            try:
                resp = self.session.get(target, timeout=self.timeout, headers=headers)
                found = detect_from_response(target, dict(resp.headers), resp.text or "")
                for tech, version in found.items():
                    if tech not in aggregate or (version and not aggregate[tech]):
                        aggregate[tech] = version
            except requests.RequestException as exc:
                logger.debug("tech fetch failed for %s: %s", target, exc)
        return {"url": url, "tech": aggregate}


def detect_tech(
    url: str,
    responses: list[tuple[str, dict[str, str], str]] | None = None,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Convenience entry: detect from live fetch or supplied responses."""
    if responses:
        aggregate: dict[str, str] = {}
        for url_i, headers, body in responses:
            for tech, version in detect_from_response(url_i, headers, body).items():
                if tech not in aggregate or (version and not aggregate[tech]):
                    aggregate[tech] = version
        return {"url": url, "tech": aggregate}
    return WappalyzerWrapper(session=session).detect(url)
