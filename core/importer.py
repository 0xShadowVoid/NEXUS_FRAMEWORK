"""Import/restore NEXUS exports (zip or json).

Restores findings/chains/scans into the database. With ``merge=True``,
existing rows are kept and only new natural-key rows are inserted;
without merge, a fresh import is performed into the current DB (scan
ids are remapped; the original export file is never modified).
"""
from __future__ import annotations

import io
import json
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from core.database import Database
from lib.logger import get_logger

logger = get_logger("importer")


def _load_payload_from_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "findings" not in data:
        raise ValueError(f"not a NEXUS export: {path}")
    return data


def _load_payload_from_zip(path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        if "findings.json" not in names:
            raise ValueError(f"not a NEXUS export: {path}")
        findings = json.loads(zf.read("findings.json").decode("utf-8"))
        chains = json.loads(zf.read("chains.json").decode("utf-8")) if "chains.json" in names else []
        scans = json.loads(zf.read("scans.json").decode("utf-8")) if "scans.json" in names else []
    return {"findings": findings, "chains": chains, "scans": scans}


def load_payload(path: Path) -> dict[str, Any]:
    """Load an export payload from .json or .zip."""
    suffix = path.suffix.lower()
    if suffix == ".json":
        return _load_payload_from_json(path)
    if suffix == ".zip":
        return _load_payload_from_zip(path)
    raise ValueError(f"unsupported import file type: {path.suffix!r} (expected .json or .zip)")


def _remap_findings(findings: list[dict[str, Any]], scan_id: int) -> list[dict[str, Any]]:
    out = []
    for f in findings:
        row = dict(f)
        row["scan_id"] = scan_id
        out.append(row)
    return out


def import_payload(
    db: Database,
    payload: dict[str, Any],
    target_domain: str = "imported",
    merge: bool = True,
) -> dict[str, Any]:
    """Restore a payload into *db*.

    Returns a summary: {'scans': n, 'findings': n, 'chains': n,
    'merged': bool, 'skipped': n}.
    """
    scans = payload.get("scans", []) or []
    findings = payload.get("findings", []) or []
    chains = payload.get("chains", []) or []

    target_id = db.upsert_target(target_domain)
    scan_id = db.create_scan(target_id, intensity="imported")
    skipped = 0

    existing = {(r.get("endpoint"), r.get("vuln_type")) for r in db.query_findings()} if merge else set()

    rows = _remap_findings(findings, scan_id)
    inserted = 0
    for row in rows:
        key = (row.get("endpoint"), row.get("vuln_type"))
        if merge and key in existing:
            skipped += 1
            continue
        db.insert_finding(
            scan_id=scan_id,
            endpoint=str(row.get("endpoint", "")),
            vuln_type=str(row.get("vuln_type", "")),
            severity=str(row.get("severity", "P4")),
            confidence=int(row.get("confidence", 50) or 0),
            payload=str(row.get("payload", "") or ""),
            response_snippet=str(row.get("response_snippet", "") or ""),
            tools_found=list(row.get("tools_found", []) or []),
            in_scope=bool(row.get("in_scope", True)),
            valid=row.get("valid"),
        )
        inserted += 1

    chain_count = 0
    for c in chains:
        db.insert_chain(
            scan_id=scan_id,
            finding_ids=list(c.get("finding_ids", []) or []),
            chain_type=str(c.get("chain_type", "")),
            impact=str(c.get("impact", "")),
            steps=list(c.get("steps", []) or []),
            combined_severity=str(c.get("combined_severity", "") or ""),
        )
        chain_count += 1

    db.update_scan(
        scan_id,
        status="imported",
        findings_total=inserted,
        findings_valid=len([r for r in rows if r.get("valid") is True]),
        findings_oos=len([r for r in rows if not r.get("in_scope", True)]),
    )

    summary = {
        "scans": 1,
        "findings": inserted,
        "chains": chain_count,
        "merged": merge,
        "skipped": skipped,
    }
    logger.info("import complete: %s", summary)
    return summary


def import_file(db: Database, path: Path, merge: bool = True, target_domain: str = "imported") -> dict[str, Any]:
    """Load + import an export file."""
    payload = load_payload(path)
    return import_payload(db, payload, target_domain=target_domain, merge=merge)
