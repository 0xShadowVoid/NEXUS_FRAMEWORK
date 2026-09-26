"""Nuclei orchestrator (PROBE phase) with smart template selection.

Wappalyzer tech from DISCOVER selects ONLY matching nuclei template
directories (e.g. WordPress 6.0 → ``wordpress/`` templates, skip
``java/``, ``asp/``). Findings are parsed from nuclei JSON output.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from phases.probe.tool_runner import ToolRunner
from lib.logger import get_logger

logger = get_logger("nuclei_orchestrator")

# tech (lowercase) → nuclei template directory.
TECH_TEMPLATE_DIRS = {
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "php": "php",
    "asp.net": "asp",
    "apache": "apache",
    "nginx": "nginx",
    "tomcat": "tomcat",
    "jetty": "jetty",
    "graphql": "api",
    "react": "javascript",
    "angular": "javascript",
    "vue.js": "javascript",
    "next.js": "javascript",
    "express": "nodejs",
    "microsoft-iis": "iis",
}

# Always-loaded generic template sets.
BASE_TEMPLATE_DIRS = ["exposures", "misconfiguration", "unnecessary-technologies"]

# nuclei severity → NEXUS severity.
_SEVERITY_MAP = {
    "critical": "P1",
    "high": "P1",
    "medium": "P2",
    "low": "P3",
    "info": "P4",
    "unknown": "P4",
}


def select_template_dirs(tech: dict[str, str]) -> list[str]:
    """Map detected tech to nuclei template directories (smart selection)."""
    dirs = list(BASE_TEMPLATE_DIRS)
    for tech_name in tech:
        mapped = TECH_TEMPLATE_DIRS.get(tech_name.lower())
        if mapped and mapped not in dirs:
            dirs.append(mapped)
    return dirs


def parse_nuclei_output(output: str, target: str) -> list[dict[str, Any]]:
    """Parse nuclei JSONL output into raw findings."""
    findings: list[dict[str, Any]] = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = event.get("info") or {}
        severity_raw = str(info.get("severity", "unknown")).lower()
        findings.append({
            "target": target,
            "endpoint": event.get("matched-at") or event.get("host") or target,
            "vuln_type": str(info.get("name") or "nuclei-finding").lower().replace(" ", "_"),
            "severity": _SEVERITY_MAP.get(severity_raw, "P4"),
            "confidence": 80 if severity_raw in ("critical", "high") else 60,
            "payload": str((info.get("reference") or [""])[0]),
            "response_snippet": str(event.get("extracted-results") or "")[:300],
            "tools_found": ["nuclei"],
            "template_id": info.get("template-id"),
        })
    return findings


def run_nuclei(
    target: str,
    urls: list[str],
    tech: dict[str, str],
    runner: ToolRunner,
    results_dir: Path,
    severity_filter: str = "medium,high,critical",
) -> list[dict[str, Any]]:
    """Run nuclei with tech-matched templates; returns raw findings."""
    template_dirs = select_template_dirs(tech)
    template_args: list[str] = []
    for d in template_dirs:
        template_args.extend(["-t", f"{d}/"])

    url_list_file = results_dir / "recon" / "urls.txt"
    url_list_file.parent.mkdir(parents=True, exist_ok=True)
    url_list_file.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")

    args = [
        "-l", str(url_list_file),
        *template_args,
        "-severity", severity_filter,
        "-jsonl",
        "-silent",
    ]
    result = runner.run("nuclei", args)
    findings: list[dict[str, Any]] = []
    if result.status in ("not_found", "skipped"):
        logger.info("nuclei not available; skipping (%s)", result.status)
        return findings
    findings = parse_nuclei_output(result.stdout, target)
    out_file = results_dir / "scans" / "nuclei_results.jsonl"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(result.stdout, encoding="utf-8", errors="replace")
    logger.info("nuclei: %d raw findings (templates=%s)", len(findings), ",".join(template_dirs))
    return findings
