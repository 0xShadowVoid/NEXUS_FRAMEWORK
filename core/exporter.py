"""Export findings for a target scan.

Formats: zip (default), 7z, json, csv. Every export includes
metadata.json (framework version, target, scan ids, counts,
exported_at). Output naming follows the NEXUS utils conventions into
exports/.
"""
from __future__ import annotations

import csv
import io
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lib.logger import get_logger
from lib.paths import EXPORTS_BASE
from lib.utils import sanitize_path_component

logger = get_logger("exporter")

NEXUS_VERSION = "1.0.0"

_METADATA_NAME = "metadata.json"
_FINDINGS_NAME = "findings.json"
_CHAINS_NAME = "chains.json"


def _export_name(target: str, fmt: str, date: str | None = None) -> str:
    d = date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return f"{sanitize_path_component(target)}-{d}.{fmt}"


def collect_scan_data(
    scan_rows: list[dict[str, Any]],
    findings_rows: list[dict[str, Any]],
    chains_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Bundle scan rows into a serializable export payload."""
    return {
        "scans": scan_rows,
        "findings": findings_rows,
        "chains": chains_rows,
    }


def export_json(payload: dict[str, Any], out_dir: Path, target: str, date: str | None = None) -> Path:
    """Export to a single JSON file."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / _export_name(target, "json", date)
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


def export_csv(findings_rows: list[dict[str, Any]], out_dir: Path, target: str, date: str | None = None) -> Path:
    """Export findings to CSV."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / _export_name(target, "csv", date)
    if findings_rows:
        fieldnames = list(findings_rows[0].keys())
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for row in findings_rows:
                writer.writerow({k: json.dumps(v) if isinstance(v, (dict, list)) else v for k, v in row.items()})
    else:
        path.write_text("", encoding="utf-8")
    return path


def _metadata(target: str, scan_rows: list[dict[str, Any]], findings_rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "framework": "NEXUS",
        "version": NEXUS_VERSION,
        "target": target,
        "scan_ids": [r.get("id") for r in scan_rows],
        "scan_count": len(scan_rows),
        "findings_count": len(findings_rows),
        "exported_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def export_zip(
    payload: dict[str, Any],
    out_dir: Path,
    target: str,
    scan_rows: list[dict[str, Any]],
    findings_rows: list[dict[str, Any]],
    date: str | None = None,
) -> Path:
    """Export to a ZIP archive with metadata."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / _export_name(target, "zip", date)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(_METADATA_NAME, json.dumps(_metadata(target, scan_rows, findings_rows), indent=2))
        zf.writestr(_FINDINGS_NAME, json.dumps(payload.get("findings", []), indent=2, default=str))
        zf.writestr(_CHAINS_NAME, json.dumps(payload.get("chains", []), indent=2, default=str))
        zf.writestr("scans.json", json.dumps(payload.get("scans", []), indent=2, default=str))
    return path


def export_7z(
    payload: dict[str, Any],
    out_dir: Path,
    target: str,
    scan_rows: list[dict[str, Any]],
    findings_rows: list[dict[str, Any]],
    date: str | None = None,
) -> Path:
    """Export to a 7z archive (py7zr) with metadata."""
    import py7zr

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / _export_name(target, "7z", date)
    with py7zr.SevenZipFile(path, "w") as zf:
        zf.writestr(json.dumps(_metadata(target, scan_rows, findings_rows), indent=2), _METADATA_NAME)
        zf.writestr(json.dumps(payload.get("findings", []), default=str), _FINDINGS_NAME)
        zf.writestr(json.dumps(payload.get("chains", []), default=str), _CHAINS_NAME)
        zf.writestr(json.dumps(payload.get("scans", []), default=str), "scans.json")
    return path


def export_html(
    target: str,
    findings_rows: list[dict[str, Any]],
    chains_rows: list[dict[str, Any]],
    metrics: dict[str, Any] | None = None,
    out_base: Path | None = None,
    date: str | None = None,
) -> Path:
    """Export findings to a self-contained HTML file (roadmap F1)."""
    import html as _html

    out_dir = out_base or EXPORTS_BASE
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / _export_name(target, "html", date)
    metrics = metrics or {}

    def esc(value: Any) -> str:
        return _html.escape(str(value if value is not None else ""))

    rows = []
    for i, f in enumerate(findings_rows, start=1):
        rows.append(
            "<tr>"
            f"<td>{i}</td>"
            f"<td>{esc(f.get('severity'))}</td>"
            f"<td>{esc(f.get('vuln_type'))}</td>"
            f"<td class='mono'>{esc(f.get('endpoint'))}</td>"
            f"<td>{esc(f.get('confidence'))}%</td>"
            f"<td>{esc(', '.join(f.get('tools_found') or []))}</td>"
            f"<td class='mono'>{esc(f.get('payload'))}</td>"
            f"<td class='mono'>{esc((str(f.get('response_snippet') or ''))[:200])}</td>"
            "</tr>"
        )
    chain_rows = "".join(
        f"<li><strong>{esc(c.get('chain_type'))}</strong> — {esc(c.get('combined_severity'))}: "
        f"{esc(c.get('impact'))}</li>"
        for c in chains_rows
    ) or "<li>none</li>"

    body_parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f"<title>NEXUS — {esc(target)}</title>",
        "<style>body{font:14px/1.5 system-ui,sans-serif;margin:24px;background:#0f1216;color:#e6edf3}",
        "table{border-collapse:collapse;width:100%}th,td{border:1px solid #242c37;padding:6px 8px;text-align:left}",
        "th{background:#1b222c}.mono{font-family:Consolas,monospace;font-size:12px;word-break:break-all}",
        "h1{font-size:22px}.muted{color:#9aa7b4}</style></head><body>",
        f"<h1>NEXUS Findings — {esc(target)}</h1>",
        '<p class="muted">detection + PoC only · generated by NEXUS</p>',
        "<ul>",
    ]
    for key, value in sorted(metrics.items()):
        if not isinstance(value, (dict, list)):
            body_parts.append(f"<li>{esc(key)}: {esc(value)}</li>")
    body_parts.append("</ul>")
    body_parts.append("<h2>Findings</h2>")
    body_parts.append(
        "<table><thead><tr><th>#</th><th>Sev</th><th>Type</th><th>Endpoint</th>"
        "<th>Conf</th><th>Tools</th><th>Payload</th><th>Evidence</th></tr></thead><tbody>"
    )
    body_parts.append("".join(rows) or '<tr><td colspan="8">no findings</td></tr>')
    body_parts.append("</tbody></table>")
    body_parts.append("<h2>Chains</h2><ul>" + chain_rows + "</ul>")
    body_parts.append("</body></html>")

    path.write_text("\n".join(body_parts), encoding="utf-8")
    return path


def export_sarif(
    target: str,
    findings_rows: list[dict[str, Any]],
    out_base: Path | None = None,
    date: str | None = None,
) -> Path:
    """Export findings as SARIF 2.1.0 JSON (roadmap F2)."""
    out_dir = out_base or EXPORTS_BASE
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / _export_name(target, "sarif", date)
    level_map = {"P1": "error", "P2": "error", "P3": "warning", "P4": "note"}
    results = []
    for f in findings_rows:
        results.append({
            "ruleId": str(f.get("vuln_type") or "finding"),
            "level": level_map.get(str(f.get("severity")), "warning"),
            "message": {"text": (str(f.get("response_snippet") or "") or "")[:500]},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": str(f.get("endpoint") or "")}}
            }],
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "NEXUS", "version": NEXUS_VERSION}},
            "results": results,
        }],
    }
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return path


def export_findings(
    target: str,
    scan_rows: list[dict[str, Any]],
    findings_rows: list[dict[str, Any]],
    chains_rows: list[dict[str, Any]],
    fmt: str = "zip",
    out_base: Path | None = None,
    date: str | None = None,
) -> Path:
    """Export findings in the requested format. Returns the export path."""
    out_dir = out_base or EXPORTS_BASE
    payload = collect_scan_data(scan_rows, findings_rows, chains_rows)
    if fmt == "json":
        return export_json(payload, out_dir, target, date)
    if fmt == "csv":
        return export_csv(findings_rows, out_dir, target, date)
    if fmt == "7z":
        return export_7z(payload, out_dir, target, scan_rows, findings_rows, date)
    if fmt == "zip":
        return export_zip(payload, out_dir, target, scan_rows, findings_rows, date)
    if fmt == "html":
        return export_html(target, findings_rows, chains_rows, out_base=out_dir, date=date)
    if fmt == "sarif":
        return export_sarif(target, findings_rows, out_base=out_dir, date=date)
    raise ValueError(f"unsupported export format: {fmt!r} (expected zip|7z|json|csv|html|sarif)")
