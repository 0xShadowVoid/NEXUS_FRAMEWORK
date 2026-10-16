"""Subdomain takeover detection + domain lifecycle intelligence.

Pipeline (all non-destructive, proof-only):

    DNS/CNAME → provider signature match → resource-state check
              → candidate / probable / confirmed → evidence

SECURITY BOUNDARY: this module *never* registers a domain, never modifies
DNS, and never attempts an actual takeover. Validation is limited to
read-only signals: CNAME resolution, HTTP status of the provider endpoint,
and soft-404 heuristics. Anything stronger is out of scope by design.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lib.config import TargetConfig
from lib.logger import get_logger
from lib.scope_validator import validate_finding_scope
from lib.ssrf_guard import is_safe_url

logger = get_logger("takeover")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# Provider signatures: cname suffix → (provider, fingerprint, status hint).
# The fingerprint is a *read-only* marker that indicates the resource no
# longer exists (dangling), e.g. a "Repository not found" page.
PROVIDER_SIGNATURES: dict[str, dict[str, str]] = {
    "github.io": {
        "provider": "github-pages",
        "fingerprint": "There isn't a GitHub Pages site here",
        "status_hint": "404",
    },
    "herokuapp.com": {
        "provider": "heroku",
        "fingerprint": "No such app",
        "status_hint": "404",
    },
    "s3.amazonaws.com": {
        "provider": "aws-s3",
        "fingerprint": "The specified bucket does not exist",
        "status_hint": "404",
    },
    "blob.core.windows.net": {
        "provider": "azure-blob",
        "fingerprint": "The specified container does not exist",
        "status_hint": "404",
    },
    "storage.googleapis.com": {
        "provider": "gcp-storage",
        "fingerprint": "The specified bucket does not exist",
        "status_hint": "404",
    },
    "cloudfront.net": {
        "provider": "aws-cloudfront",
        "fingerprint": "Bad request",
        "status_hint": "403",
    },
    "azurewebsites.net": {
        "provider": "azure-webapps",
        "fingerprint": "404 Web Site not found",
        "status_hint": "404",
    },
    "trafficmanager.net": {
        "provider": "azure-trafficmanager",
        "fingerprint": "404 Web Site not found",
        "status_hint": "404",
    },
    "elasticbeanstalk.com": {
        "provider": "aws-elasticbeanstalk",
        "fingerprint": "Environment not found",
        "status_hint": "404",
    },
    "fastly.net": {
        "provider": "fastly",
        "fingerprint": "Fastly error: unknown domain",
        "status_hint": "404",
    },
    "pantheon.io": {
        "provider": "pantheon",
        "fingerprint": "The gods are wise",
        "status_hint": "404",
    },
    "tumblr.com": {
        "provider": "tumblr",
        "fingerprint": "Whatever you were looking for doesn't exist",
        "status_hint": "404",
    },
    "wordpress.com": {
        "provider": "wordpress",
        "fingerprint": "doesn't exist",
        "status_hint": "404",
    },
    "surge.sh": {
        "provider": "surge",
        "fingerprint": "project not found",
        "status_hint": "404",
    },
    "netlify.app": {
        "provider": "netlify",
        "fingerprint": "Not Found",
        "status_hint": "404",
    },
    "vercel.app": {
        "provider": "vercel",
        "fingerprint": "The deployment could not be found",
        "status_hint": "404",
    },
}

_SOFT_404_RE = re.compile(r"(?i)(not found|doesn't exist|does not exist|no such|"
                          r"repository not found|page not found|404)")


@dataclass
class TakeoverCandidate:
    subdomain: str
    cname: str = ""
    provider: str = ""
    status: str = "candidate"          # candidate | probable | confirmed | rejected
    evidence: str = ""
    fingerprint: str = ""
    http_status: int = 0
    checks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subdomain": self.subdomain,
            "cname": self.cname,
            "provider": self.provider,
            "status": self.status,
            "evidence": self.evidence,
            "fingerprint": self.fingerprint,
            "http_status": self.http_status,
            "checks": list(self.checks),
        }


def match_provider(cname: str) -> str:
    """Return the logical provider for a CNAME, or '' when unknown."""
    host = (cname or "").lower().rstrip(".")
    if not host:
        return ""
    for suffix, meta in PROVIDER_SIGNATURES.items():
        if host == suffix or host.endswith("." + suffix):
            return meta["provider"]
    return ""


def signature_for(provider: str) -> dict[str, str]:
    for meta in PROVIDER_SIGNATURES.values():
        if meta["provider"] == provider:
            return meta
    return {}


class TakeoverDetector:
    """Read-only dangling-DNS / takeover candidate evaluator."""

    def __init__(self, target_config: TargetConfig, http_get: Any | None = None):
        self.target_config = target_config
        self.http_get = http_get
        self.findings: list[TakeoverCandidate] = []

    # -- steps ---------------------------------------------------------------

    def _safe_fetch(self, url: str) -> tuple[int, str]:
        """Return (status, body) via the injected fetcher, guarded."""
        if self.http_get is None:
            return 0, ""
        safe, _reason = is_safe_url(url)
        if not safe:
            return 0, "ssrf-blocked"
        try:
            body = str(self.http_get(url) or "")
        except Exception as exc:
            return 0, f"error: {exc}"
        return 200, body

    def evaluate(self, subdomain: str, cname: str) -> TakeoverCandidate:
        """One candidate through the pipeline. Never mutates anything."""
        cand = TakeoverCandidate(subdomain=subdomain, cname=cname)
        cand.checks.append("cname-present")

        provider = match_provider(cname)
        if not provider:
            cand.status = "rejected"
            cand.evidence = "CNAME target is not a known takeover-prone provider"
            cand.checks.append("no-provider-signature")
            return cand

        cand.provider = provider
        cand.fingerprint = signature_for(provider).get("fingerprint", "")
        cand.checks.append(f"provider-match:{provider}")

        # Scope gate: the SOURCE subdomain must be in scope. The CNAME
        # destination is a third-party provider by definition, so it is not
        # scope-checked here — only the SSRF guard applies to fetching it.
        source_url = f"https://{subdomain}/"
        if not validate_finding_scope(source_url, self.target_config):
            cand.status = "rejected"
            cand.evidence = "source subdomain out of scope"
            cand.checks.append("scope-rejected")
            return cand

        # Resource-state check: fetch the canonical provider URL read-only.
        url = f"https://{cname.strip('.')}/" if cname else source_url

        status, body = self._safe_fetch(url)
        cand.http_status = status
        cand.checks.append(f"http:{status}")
        if not body or body == "ssrf-blocked":
            # No HTTP evidence → probable (unverified), never confirmed.
            cand.status = "probable"
            cand.evidence = f"CNAME to {provider} with no reachable resource"
            return cand

        if cand.fingerprint and cand.fingerprint.lower() in body.lower():
            cand.status = "confirmed"
            cand.evidence = f"provider fingerprint present: {cand.fingerprint}"
            cand.checks.append("fingerprint-match")
        elif _SOFT_404_RE.search(body):
            cand.status = "probable"
            cand.evidence = "soft-404 marker on provider endpoint"
            cand.checks.append("soft-404")
        else:
            cand.status = "rejected"
            cand.evidence = "provider resource is live (no takeover condition)"
            cand.checks.append("resource-live")

        return cand

    # -- batch ---------------------------------------------------------------

    def run(self, cnames: dict[str, str]) -> list[TakeoverCandidate]:
        """``{subdomain: cname}`` map → evaluated candidates."""
        for subdomain, cname in (cnames or {}).items():
            try:
                self.findings.append(self.evaluate(subdomain, cname))
            except Exception as exc:  # one candidate must never break the cycle
                logger.debug("takeover evaluation failed for %s: %s", subdomain, exc)
        logger.info(
            "takeover: %d candidates (%d probable, %d confirmed)",
            len(self.findings),
            sum(1 for c in self.findings if c.status == "probable"),
            sum(1 for c in self.findings if c.status == "confirmed"),
        )
        return self.findings

    def summary(self) -> dict[str, Any]:
        by_status: dict[str, int] = {}
        for c in self.findings:
            by_status[c.status] = by_status.get(c.status, 0) + 1
        return {
            "total": len(self.findings),
            "by_status": by_status,
            "candidates": [c.to_dict() for c in self.findings],
        }


def run_takeover(
    cfg: Any,
    target_config: TargetConfig,
    results_dir: Path,
    cnames: dict[str, str] | None = None,
    db: Any | None = None,
    scan_id: int | None = None,
    http_get: Any | None = None,
    runner: Any | None = None,
) -> dict[str, Any]:
    """TAKEOVER phase entrypoint (non-destructive, gated)."""
    cnames = cnames or {}
    detector = TakeoverDetector(target_config, http_get=http_get)
    # Optional subdominator-style binary enrichment (kept optional; the
    # detector works purely from CNAME data when the binary is absent).
    if runner is not None and runner.tool_available("subdominator"):
        try:
            result = runner.run(
                "subdominator", ["-d", target_config.domain],
                targets=[target_config.domain],
            )
            if result.ok:
                for line in (result.stdout or "").splitlines():
                    token = line.strip().split()[0] if line.strip() else ""
                    if token and "." in token and token not in cnames:
                        cnames.setdefault(token, "")
        except Exception as exc:  # optional tool, never fatal
            logger.debug("subdominator enrichment failed: %s", exc)

    detector.run(cnames)
    summary = detector.summary()

    # Persist artifacts + graph links.
    try:
        takeover_dir = results_dir / "takeover"
        takeover_dir.mkdir(parents=True, exist_ok=True)
        (takeover_dir / "takeover.json").write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8"
        )
    except OSError:
        pass
    if db is not None and scan_id is not None:
        try:
            from lib.filtration import FiltrationPipeline

            pipeline = FiltrationPipeline(db, target_config, scan_id=scan_id)
            for cand in detector.findings:
                if cand.status in ("probable", "confirmed"):
                    # Ingest first so the asset exists when the evidence is
                    # inserted — the Pass 3C auto-link then links both
                    # without a second manual helper call.
                    pipeline.ingest(
                        "takeover", "takeover", [cand.subdomain], kind="subdomain",
                    )
                    db.insert_evidence(
                        scan_id, url=f"https://{cand.subdomain}/",
                        tool="takeover", source="takeover",
                        status_code=cand.http_status,
                        response_body=cand.evidence,
                    )
        except Exception as exc:  # persistence must never break the cycle
            logger.debug("takeover persistence failed: %s", exc)

    return summary
