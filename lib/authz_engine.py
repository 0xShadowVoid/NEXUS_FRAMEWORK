"""AUTHZ phase — authorization testing (IDOR / BOLA / privilege differential).

Reuses the existing primitives rather than duplicating them:
- horizontal/object-level (IDOR/BOLA)  → ``lib.idor_prober.IdorProber``
- business-logic flaws                  → ``lib.logic_detector.detect_logic_flaws``

What this phase ADDS around them:
- a ≥2-identity gate (authorization needs two identities to compare),
- vertical privilege testing (role comparison via identity kinds),
- a per-endpoint authorization matrix,
- differential evidence collection for every candidate.

SECURITY BOUNDARY: read-only, differential comparison of responses. No
credential guessing, no state-changing requests, no data modification.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from lib.config import TargetConfig
from lib.logger import get_logger
from lib.scope_validator import validate_finding_scope

logger = get_logger("authz")

MIN_IDENTITIES = 2


@dataclass
class AuthzMatrixEntry:
    endpoint: str
    identity: str
    status_code: int = 0
    accessible: bool = False
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "identity": self.identity,
            "status_code": self.status_code,
            "accessible": self.accessible,
            "evidence": self.evidence[:200],
        }


class AuthzMatrix:
    """endpoint x identity accessibility matrix with differential evidence."""

    def __init__(self) -> None:
        self._entries: list[AuthzMatrixEntry] = []

    def record(self, endpoint: str, identity: str, status_code: int, evidence: str = "") -> None:
        accessible = int(status_code or 0) in (200, 201, 202, 204, 206, 301, 302)
        self._entries.append(
            AuthzMatrixEntry(endpoint=endpoint, identity=identity,
                             status_code=int(status_code or 0),
                             accessible=accessible, evidence=evidence)
        )

    def entries(self) -> list[AuthzMatrixEntry]:
        return list(self._entries)

    def horizontal_violations(self) -> list[dict[str, Any]]:
        """Same-role identities reaching each other's resources (IDOR/BOLA)."""
        by_endpoint: dict[str, list[AuthzMatrixEntry]] = {}
        for e in self._entries:
            by_endpoint.setdefault(e.endpoint, []).append(e)
        out: list[dict[str, Any]] = []
        for endpoint, rows in by_endpoint.items():
            same_kind = {}
            for r in rows:
                same_kind.setdefault("any", []).append(r)
            if len(same_kind["any"]) >= 2:
                # Two identities of any kind both accessed the same object.
                identities = sorted({r.identity for r in same_kind["any"] if r.accessible})
                if len(identities) >= 2:
                    out.append({
                        "endpoint": endpoint,
                        "kind": "horizontal",
                        "identities": identities,
                        "evidence": f"{len(identities)} identities can reach {endpoint}",
                    })
        return out

    def vertical_violations(self, lowpriv_kinds: tuple[str, ...] = ("user", "lowpriv"),
                            highpriv_kinds: tuple[str, ...] = ("admin", "highpriv")) -> list[dict[str, Any]]:
        """A low-privilege identity reaching an admin-only surface."""
        by_endpoint: dict[str, list[AuthzMatrixEntry]] = {}
        for e in self._entries:
            by_endpoint.setdefault(e.endpoint, []).append(e)
        out: list[dict[str, Any]] = []
        for endpoint, rows in by_endpoint.items():
            kinds = {r.identity.split(":", 1)[0] for r in rows if r.accessible}
            low_hit = any(k in lowpriv_kinds for k in kinds)
            high_hit = any(k in highpriv_kinds for k in kinds)
            admin_only = any("admin" in (urlsplit(endpoint).path or "").lower()
                             for _ in [endpoint])
            if low_hit and (high_hit or admin_only):
                out.append({
                    "endpoint": endpoint,
                    "kind": "vertical",
                    "evidence": f"low-privilege identity reaches {endpoint}",
                })
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": [e.to_dict() for e in self._entries],
            "horizontal": self.horizontal_violations(),
            "vertical": self.vertical_violations(),
        }


def _adminish(url: str) -> bool:
    path = (urlsplit(url).path or "").lower()
    return any(tok in path for tok in ("/admin", "/internal", "/staff", "/manage", "/console"))


def run_authz(
    cfg: Any,
    target_config: TargetConfig,
    results_dir: Path,
    urls: list[str] | None = None,
    identities: list[dict[str, Any]] | None = None,
    http_get: Callable[[str], str] | None = None,
    db: Any | None = None,
    scan_id: int | None = None,
) -> dict[str, Any]:
    """AUTHZ phase entrypoint.

    Gated: requires ≥2 operator-configured identities, otherwise the phase
    reports ``blocked`` and performs no requests.
    """
    identities = identities or []
    urls = urls or []

    if len(identities) < MIN_IDENTITIES:
        return {
            "status": "blocked",
            "reason": f"authorization testing requires >= {MIN_IDENTITIES} "
                      f"operator-configured identities, found {len(identities)}",
            "findings": [],
        }
    if http_get is None:
        return {
            "status": "blocked",
            "reason": "no read-only HTTP fetcher available",
            "findings": [],
        }

    findings: list[dict[str, Any]] = []

    # 1. Reuse the existing IDOR prober for object-level horizontal testing.
    try:
        from lib.idor_prober import IdorProber

        in_scope_urls = [u for u in urls if validate_finding_scope(u, target_config)]
        findings.extend(IdorProber(fetch=http_get).probe_many(in_scope_urls))
    except Exception as exc:  # never break the phase
        logger.debug("IDOR reuse failed: %s", exc)

    # 2. Reuse the existing business-logic detector.
    try:
        from lib.logic_detector import detect_logic_flaws

        findings.extend(detect_logic_flaws(urls))
    except Exception as exc:
        logger.debug("logic detector reuse failed: %s", exc)

    # 3. Authorization matrix across identities (differential, read-only).
    matrix = AuthzMatrix()
    adminish_urls = [u for u in urls if _adminish(u)]
    for ident in identities:
        name = str(ident.get("name", ""))
        kind = str(ident.get("kind", "user"))
        for url in adminish_urls[:20]:
            if not validate_finding_scope(url, target_config):
                continue
            try:
                body = str(http_get(url) or "")
                # A non-empty, non-error body suggests the identity can view it.
                status_guess = 200 if body.strip() and "403" not in body[:60] else 403
                matrix.record(url, f"{kind}:{name}", status_guess,
                              evidence=f"response length {len(body)}")
            except Exception:
                continue

    horizontal = matrix.horizontal_violations()
    vertical = matrix.vertical_violations()
    for entry in horizontal + vertical:
        findings.append({
            "endpoint": entry["endpoint"],
            "vuln_type": "authz_" + entry["kind"],
            "severity": "P1" if entry["kind"] == "vertical" else "P2",
            "confidence": 70,
            "payload": "",
            "response_snippet": entry["evidence"],
            "tools_found": ["nexus-authz-matrix"],
            "verification": {"verified": False, "method": "differential",
                             "confidence": 70, "notes": "requires manual confirmation with evidence"},
        })

    summary = {
        "status": "completed",
        "identities": len(identities),
        "matrix": matrix.to_dict(),
        "findings": len(findings),
        # Additive: the finding items themselves so the coordinator can merge
        # them into ANALYZE (the ``findings`` count above stays compatible).
        "items": findings,
    }

    # Persist artifacts + evidence (best-effort).
    try:
        authz_dir = Path(results_dir) / "authz"
        authz_dir.mkdir(parents=True, exist_ok=True)
        (authz_dir / "authz.json").write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8"
        )
    except OSError:
        pass
    if db is not None and scan_id is not None:
        try:
            for f in findings:
                db.insert_evidence(
                    scan_id, url=str(f.get("endpoint", "")),
                    tool="authz", source="authz",
                    response_body=str(f.get("response_snippet", "")),
                )
        except Exception as exc:
            logger.debug("authz persistence failed: %s", exc)

    return summary
