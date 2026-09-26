"""Dalfox runner (PROBE — XSS detection)."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from phases.probe.tool_runner import ToolRunner
from lib.logger import get_logger

logger = get_logger("dalfox_runner")

# Dalfox prints JSON lines with --json (uses "data" object).
_VULN_RE = re.compile(r"\[V\]", re.IGNORECASE)


def parse_dalfox_output(output: str, target: str) -> list[dict[str, Any]]:
    """Parse dalfox output (JSON mode or plain) into raw findings."""
    findings: list[dict[str, Any]] = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                event = json.loads(line)
                data = event.get("data") or event
                if str(event.get("type", "")).lower() != "vuln":
                    continue
                findings.append({
                    "target": target,
                    "endpoint": data.get("pocurl") or target,
                    "vuln_type": "reflected_xss",
                    "severity": "P3",
                    "confidence": 85,
                    "payload": str(data.get("inject") or data.get("param") or ""),
                    "response_snippet": str(data.get("cwe") or "XSS verified by dalfox")[:300],
                    "tools_found": ["dalfox"],
                })
                continue
            except json.JSONDecodeError:
                pass
        if _VULN_RE.search(line):
            # Plain mode: lines like "[V] <url>".
            url = line.split("]", 1)[-1].strip().split(" ")[0]
            findings.append({
                "target": target,
                "endpoint": url or target,
                "vuln_type": "reflected_xss",
                "severity": "P3",
                "confidence": 80,
                "payload": "",
                "response_snippet": "XSS flagged by dalfox plain output",
                "tools_found": ["dalfox"],
            })
    return findings


def run_dalfox(
    target: str,
    urls: list[str],
    runner: ToolRunner,
    results_dir: Path,
    cookie: str = "",
) -> list[dict[str, Any]]:
    """Run dalfox over discovered URLs; returns raw findings."""
    url_list_file = results_dir / "recon" / "urls.txt"
    if not url_list_file.exists():
        url_list_file.parent.mkdir(parents=True, exist_ok=True)
        url_list_file.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")

    args = ["file", str(url_list_file), "--json", "--silent", "-o", str(results_dir / "scans" / "dalfox_results.json")]
    if cookie:
        args.extend(["--cookie", cookie])

    result = runner.run("dalfox", args)
    if result.status in ("not_found", "skipped"):
        logger.info("dalfox not available; skipping (%s)", result.status)
        return []
    findings = parse_dalfox_output(result.stdout, target)
    logger.info("dalfox: %d raw findings", len(findings))
    return findings
