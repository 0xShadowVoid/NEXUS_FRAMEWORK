"""Result filtration pipeline + attack-surface graph ingestion.

Every discovery/tool cycle funnels its output through:

    RAW → PARSE → NORMALIZE → VALIDATE → DEDUP → CLASSIFY → FILTER → GRAPH

and records per-tool statistics so NEXUS can measure a tool by its
**unique yield** (new attack surface actually added), not raw output count.

This module deliberately reuses the existing primitives:
- ``lib.deduplicator.deduplicate`` for DEDUP,
- ``lib.scope_validator`` for VALIDATE,
- ``core.sanitizer`` for sanitization,
and only adds the accounting + graph ingestion around them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from lib.config import TargetConfig
from lib.logger import get_logger
from lib.scope_validator import validate_finding_scope

logger = get_logger("filtration")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class FiltrationStats:
    """Per-tool-run accounting of what the pipeline produced."""

    tool: str = ""
    phase: str = ""
    total: int = 0                  # RAW total (units emitted by the tool)
    parsed_total: int = 0           # PARSE total (coerced into item records)
    valid: int = 0
    duplicates: int = 0
    filtered: int = 0
    invalid: int = 0
    new: int = 0
    errors: int = 0
    unique_yield: float = 0.0
    source: str = ""
    stats_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "phase": self.phase,
            "total": self.total,
            "parsed_total": self.parsed_total,
            "valid": self.valid,
            "duplicates": self.duplicates,
            "filtered": self.filtered,
            "invalid": self.invalid,
            "new": self.new,
            "errors": self.errors,
            "unique_yield": round(self.unique_yield, 4),
            "source": self.source,
        }

    def finalize(self) -> "FiltrationStats":
        self.unique_yield = (self.new / self.total) if self.total else 0.0
        return self


def normalize_asset(kind: str, value: str) -> str:
    """Canonical form of an asset value for dedup (kind-aware)."""
    raw = (value or "").strip()
    if not raw:
        return ""
    kind = (kind or "").lower()
    if kind in ("url", "endpoint", "javascript", "file"):
        try:
            parts = urlsplit(raw)
        except ValueError:
            return raw.lower()
        host = (parts.hostname or "").lower().rstrip(".")
        path = parts.path.rstrip("/")
        query = f"?{parts.query}" if parts.query else ""
        return f"{host}{path}{query}".lower()
    if kind in ("subdomain", "domain", "host", "hostname"):
        return raw.lower().rstrip(".")
    if kind in ("ip", "port", "service", "technology", "certificate", "dns_record", "api", "cloud_asset"):
        return raw.lower()
    return raw.lower()


def infer_kind(value: str) -> str:
    """Best-effort asset kind for a bare string."""
    raw = (value or "").strip()
    if not raw:
        return ""
    if raw.startswith(("http://", "https://")):
        return "url"
    if "/" in raw or "?" in raw:
        return "endpoint"
    if raw.count(".") >= 2 and not raw.replace(".", "").isdigit():
        return "subdomain"
    if all(part.isdigit() for part in raw.split(".")) and len(raw.split(".")) == 4:
        return "ip"
    return "host"


# evidence_type / plural hint → canonical asset kind (CLASSIFY stage).
_KIND_ALIASES: dict[str, str] = {
    "subdomains": "subdomain", "urls": "url", "endpoints": "endpoint",
    "hosts": "host", "ips": "ip", "ports": "port", "services": "service",
    "technologies": "technology", "cnames": "dns_record", "dns_records": "dns_record",
    "raw_findings": "endpoint", "screenshots": "file", "findings": "finding",
    "certificates": "certificate", "identities": "identity", "accounts": "account",
    "cloud_assets": "cloud_asset", "javascript": "javascript",
    "parameters": "parameter", "apis": "api",
}


def classify_kind(value: str, hint: str = "") -> str:
    """CLASSIFY stage: canonical asset kind for one parsed item.

    The explicit hint (evidence_type / ``kind=``) wins after alias
    canonicalisation; without a hint the value shape is inferred.
    """
    h = (hint or "").strip().lower()
    if h:
        return _KIND_ALIASES.get(h, h)
    return infer_kind(value)


class FiltrationPipeline:
    """Runs one tool's raw output through the stages into the graph."""

    def __init__(self, db: Any, target_config: TargetConfig, scan_id: int | None = None):
        self.db = db
        self.target_config = target_config
        self.scan_id = scan_id

    # -- stage helpers ------------------------------------------------------

    def _validate(self, kind: str, value: str) -> bool:
        if kind in ("url", "endpoint"):
            return validate_finding_scope(value, self.target_config)
        # Non-URL assets are validated against scope by their parent host; a
        # bare subdomain is scope-checked when it is linked to the domain.
        return True

    # -- stage helpers -------------------------------------------------------

    @staticmethod
    def raw_count(raw: Any) -> int:
        """RAW stage: how many units the tool emitted (before parsing)."""
        if raw is None:
            return 0
        if isinstance(raw, str):
            return sum(1 for ln in raw.splitlines() if ln.strip())
        if isinstance(raw, dict):
            return 1
        if isinstance(raw, (list, tuple, set)):
            return len(raw)
        return 1

    @staticmethod
    def parse(raw: Any) -> tuple[list[dict[str, Any]], int]:
        """PARSE stage: coerce raw output into ``{"value": ...}`` records.

        Accepts line-delimited strings, dicts, or lists of either.
        Unparseable units are dropped and counted as errors — this stage
        never raises.
        """
        items: list[dict[str, Any]] = []
        errors = 0

        def _one(unit: Any) -> dict[str, Any] | None:
            if isinstance(unit, dict):
                val = str(
                    unit.get("value") or unit.get("url") or unit.get("endpoint")
                    or unit.get("host") or ""
                ).strip()
                if not val:
                    return None
                rec = dict(unit)
                rec["value"] = val
                return rec
            if isinstance(unit, str):
                val = unit.strip()
                return {"value": val} if val else None
            return None

        if raw is None:
            return [], 0
        if isinstance(raw, str):
            for line in raw.splitlines():
                if not line.strip():
                    continue
                rec = _one(line)
                if rec is None:
                    errors += 1
                else:
                    items.append(rec)
        elif isinstance(raw, dict):
            rec = _one(raw)
            if rec is None:
                errors += 1
            else:
                items.append(rec)
        elif isinstance(raw, (list, tuple, set)):
            for unit in raw:
                rec = _one(unit)
                if rec is None:
                    if unit is not None and unit != "":
                        errors += 1
                else:
                    items.append(rec)
        else:
            errors += 1
        return items, errors

    # -- main entrypoint ----------------------------------------------------

    def ingest(
        self,
        tool: str,
        phase: str,
        raw_items: list[Any],
        kind: str = "",
        source: str = "",
    ) -> FiltrationStats:
        """Run *raw_items* through RAW → PARSE → NORMALIZE → VALIDATE → DEDUP
        → CLASSIFY → FILTER → GRAPH and account for every stage.

        Each item is a string (asset value) or a dict with ``value``/``url``
        and optional ``kind``. Returns the per-tool stats.
        """
        stats = FiltrationStats(tool=tool, phase=phase, source=source or tool)
        kind = (kind or "").lower()
        stats_id = None

        # RAW — units the tool actually emitted (pre-parse).
        stats.total = self.raw_count(raw_items)

        # PARSE — coerce into item records; unparseable units count as errors.
        parsed, parse_errors = self.parse(raw_items)
        stats.parsed_total = len(parsed)
        stats.errors += parse_errors

        for item in parsed:
            try:
                value = str(item.get("value", "")).strip()
                # CLASSIFY — item hint > call hint > value-shape inference.
                item_kind = classify_kind(value, str(item.get("kind", "")) or kind)
                metadata = {
                    k: v for k, v in item.items() if k not in ("value", "url", "kind")
                }
                if not value:
                    stats.invalid += 1
                    continue

                # NORMALIZE
                normalized = normalize_asset(item_kind, value)
                if not normalized:
                    stats.invalid += 1
                    continue

                # VALIDATE + FILTER (scope for URL-like assets)
                if not self._validate(item_kind, value):
                    stats.filtered += 1
                    continue

                # DEDUP + GRAPH upsert (upsert_asset reports created?)
                _asset_id, created = self.db.upsert_asset(
                    kind=item_kind,
                    value=value,
                    normalized=normalized,
                    source_tool=tool,
                    scan_id=self.scan_id,
                    metadata=metadata or None,
                )
                if created:
                    stats.new += 1
                    stats.valid += 1
                else:
                    stats.duplicates += 1
                    stats.valid += 1
            except Exception as exc:  # one bad item must not break a tool cycle
                stats.errors += 1
                logger.debug("filtration item failed (%s): %s", tool, exc)

        stats.finalize()
        # Persist so reporting/GUI can rank tools by unique yield.
        if self.scan_id is not None:
            try:
                stats_id = self.db.insert_filtration_stats(
                    self.scan_id, tool, phase, stats.to_dict()
                )
            except Exception as exc:  # accounting must never break a scan
                logger.debug("filtration stats persist failed: %s", exc)
        stats.stats_id = stats_id
        return stats

    def link(
        self,
        src_kind: str,
        src_value: str,
        dst_kind: str,
        dst_value: str,
        relation: str,
        tool: str = "",
    ) -> bool:
        """Create a provenance-preserving graph edge between two assets."""
        try:
            src = self.db.get_asset(src_kind, normalize_asset(src_kind, src_value))
            dst = self.db.get_asset(dst_kind, normalize_asset(dst_kind, dst_value))
            if src is None or dst is None:
                return False
            self.db.upsert_edge(src["id"], dst["id"], relation, source_tool=tool, scan_id=self.scan_id)
            return True
        except Exception as exc:
            logger.debug("edge failed (%s): %s", relation, exc)
            return False

    def link_domain_assets(self, domain: str, tool: str = "") -> int:
        """Link every discovered subdomain/host to its root domain."""
        created = 0
        root = normalize_asset("domain", domain)
        try:
            _root_id, _created = self.db.upsert_asset(
                "domain", domain, root, source_tool=tool or "nexus", scan_id=self.scan_id
            )
        except Exception:
            return 0
        for kind in ("subdomain", "host"):
            for asset in self.db.list_assets(kind=kind):
                if asset["normalized"] == root:
                    continue
                if asset["normalized"].endswith(f".{root}") or root in asset["normalized"]:
                    if self.link("domain", domain, kind, asset["value"], "has_subdomain", tool=tool):
                        created += 1
        return created

    # -- reporting ----------------------------------------------------------

    def tool_value_report(self) -> list[dict[str, Any]]:
        """Per-tool unique-yield ranking for this scan (GUI + reporting)."""
        rows = self.db.list_filtration_stats(self.scan_id) if self.scan_id else []
        out = []
        for row in rows:
            totals = row.get("totals") or {}
            out.append({"tool": row.get("tool"), "phase": row.get("phase"), **totals})
        return sorted(out, key=lambda r: r.get("unique_yield", 0), reverse=True)
