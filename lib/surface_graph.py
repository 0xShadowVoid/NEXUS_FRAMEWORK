"""Attack-surface graph — reads and queries over ``assets`` / ``asset_edges``.

The graph is written by :class:`lib.filtration.FiltrationPipeline` (every
discovery cycle) and *read* by orchestration, monitoring, takeover and
reporting. It is not decorative: the queries below drive decisions.

Node kinds: domain, subdomain, host, ip, port, service, technology, url,
endpoint, parameter, file, javascript, api, cloud_asset, certificate,
dns_record, identity, account, finding.

Edge relations: resolved_by, has_cname, hosted_on, serves, uses_technology,
exposes_endpoint, has_param, references, contains_secret, authenticated_by,
affected_by, evidenced_by, has_subdomain, has_port, dns_record_of,
cert_for, monitored_by.
"""
from __future__ import annotations

from typing import Any

from lib.logger import get_logger

logger = get_logger("surface_graph")

NODE_KINDS = (
    "domain", "subdomain", "host", "ip", "asn", "port", "service", "technology",
    "url", "endpoint", "parameter", "file", "javascript", "api", "cloud_asset",
    "certificate", "dns_record", "identity", "account", "finding",
)

EDGE_RELATIONS = (
    "resolved_by", "has_cname", "hosted_on", "serves", "uses_technology",
    "exposes_endpoint", "has_param", "references", "contains_secret",
    "authenticated_by", "affected_by", "evidenced_by", "has_subdomain",
    "has_port", "dns_record_of", "cert_for", "monitored_by", "runs_service",
)


class SurfaceGraph:
    """Read-side queries over the persisted attack-surface graph."""

    def __init__(self, db: Any, scan_id: int | None = None):
        self.db = db
        self.scan_id = scan_id

    # -- nodes ---------------------------------------------------------------

    def count(self, kind: str | None = None) -> int:
        return len(self.db.list_assets(kind=kind, scan_id=self.scan_id))

    def nodes(self, kind: str | None = None, limit: int = 0) -> list[dict[str, Any]]:
        rows = self.db.list_assets(kind=kind, scan_id=self.scan_id)
        return rows[:limit] if limit else rows

    def find(self, kind: str, value: str) -> dict[str, Any] | None:
        from lib.filtration import normalize_asset

        return self.db.get_asset(kind, normalize_asset(kind, value))

    # -- neighbourhood -------------------------------------------------------

    def neighbours(self, asset_id: int, relation: str | None = None) -> list[dict[str, Any]]:
        """Assets directly connected to *asset_id* (either direction)."""
        edges = self.db.list_edges(scan_id=self.scan_id)
        out: list[dict[str, Any]] = []
        for e in edges:
            if relation and e["relation"] != relation:
                continue
            other_id = None
            if e["src_id"] == asset_id:
                other_id = e["dst_id"]
            elif e["dst_id"] == asset_id:
                other_id = e["src_id"]
            if other_id is None:
                continue
            row = self.db.query("SELECT * FROM assets WHERE id = ?", (other_id,))
            if row:
                node = dict(row[0])
                node["relation"] = e["relation"]
                out.append(node)
        return out

    def subdomains_of(self, domain: str) -> list[dict[str, Any]]:
        root = (domain or "").lower().rstrip(".")
        return [
            a for a in self.db.list_assets(kind="subdomain", scan_id=self.scan_id)
            if a["normalized"] == root or a["normalized"].endswith(f".{root}")
        ]

    def endpoints_on(self, host: str) -> list[dict[str, Any]]:
        host_norm = (host or "").lower().rstrip(".")
        return [
            a for a in self.db.list_assets(kind="url", scan_id=self.scan_id)
            if a["normalized"].startswith(host_norm)
        ]

    # -- decision support -----------------------------------------------------

    def has_capability(self, capability: str) -> bool:
        """Does the observed surface contain an asset hinting at *capability*?

        Used by adaptive tool selection (e.g. only run GraphQL tools when a
        GraphQL endpoint exists).
        """
        needle = (capability or "").lower()
        for row in self.db.list_assets(scan_id=self.scan_id):
            hay = f"{row.get('kind','')} {row.get('value','')} {row.get('normalized','')}".lower()
            if needle in hay:
                return True
        return False

    def dangling_cname_candidates(self) -> list[dict[str, Any]]:
        """Subdomains whose CNAME points at a provider with no live host.

        Used by the TAKEOVER cycle: candidates are CNAMEs where the resolved
        host has no live HTTP counterpart (404/NXDOMAIN-style signal stored
        as asset metadata during discovery).
        """
        out: list[dict[str, Any]] = []
        for edge in self.db.list_edges(scan_id=self.scan_id):
            if edge["relation"] != "has_cname":
                continue
            src = self.db.query("SELECT * FROM assets WHERE id = ?", (edge["src_id"],))
            dst = self.db.query("SELECT * FROM assets WHERE id = ?", (edge["dst_id"],))
            if not src or not dst:
                continue
            meta = (dst[0].get("metadata") or "")
            # Metadata recorded by discovery marks provider-host resolution
            # state: "nx", "no-resolve", "404" → dangling candidate.
            if any(tok in meta for tok in ("nx", "no-resolve", "404", "unverified")):
                out.append({"subdomain": src[0]["value"], "cname": dst[0]["value"], "provider_hint": meta})
        return out

    def tech_inventory(self) -> list[str]:
        return sorted(a["value"] for a in self.db.list_assets(kind="technology", scan_id=self.scan_id))

    # -- monitoring / diff ----------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Current surface as a comparable set map (for monitoring diffs)."""
        out: dict[str, set[str]] = {}
        for row in self.db.list_assets(scan_id=None):
            out.setdefault(row["kind"], set()).add(row["normalized"])
        return out

    @staticmethod
    def diff(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, list[str]]:
        """Compute added/removed assets between two snapshots."""
        added: list[str] = []
        removed: list[str] = []
        kinds = set(previous or {}) | set(current or {})
        for kind in kinds:
            prev = {str(v) for v in (previous or {}).get(kind, [])}
            cur = {str(v) for v in (current or {}).get(kind, [])}
            added.extend(f"{kind}:{v}" for v in sorted(cur - prev))
            removed.extend(f"{kind}:{v}" for v in sorted(prev - cur))
        return {"added": added, "removed": removed, "added_count": len(added), "removed_count": len(removed)}
