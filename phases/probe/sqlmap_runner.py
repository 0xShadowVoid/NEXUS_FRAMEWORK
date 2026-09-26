"""SQLmap runner (PROBE — light mode default: risk=1, level=1).

Heavy-tool gating per spec: sqlmap runs ONLY on 200 auth-keyword
endpoints, 401/403 bypass candidates, or user-chosen endpoints. In
light mode it is skipped entirely unless explicit endpoints are given;
in deep mode it runs against gated candidates only. All invocations
are boundary-checked (read-only detection flags).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from phases.probe.tool_runner import ToolRunner
from lib.logger import get_logger
from lib.status_detector import is_heavy_tool_candidate

logger = get_logger("sqlmap_runner")


def gate_endpoints(
    responses: list[dict[str, Any]],
    user_chosen: list[str] | None = None,
) -> list[str]:
    """Select endpoints heavy tools may target.

    A response is {url, status_code, body}. Gates: 200+auth keywords,
    401/403, or explicitly user-chosen URLs.
    """
    chosen = set(user_chosen or [])
    out: list[str] = []
    for r in responses or []:
        url = str(r.get("url", ""))
        if not url:
            continue
        if url in chosen or is_heavy_tool_candidate(
            int(r.get("status_code", 0) or 0), str(r.get("body", "") or "")
        ):
            out.append(url)
    return out


def parse_sqlmap_output(output: str, target: str) -> list[dict[str, Any]]:
    """Parse sqlmap console output for confirmed injection points."""
    findings: list[dict[str, Any]] = []
    current_url = ""
    for line in (output or "").splitlines():
        m = re.search(r"GET parameter[^\n]*\b(\w+)\b[^\n]*is vulnerable", line, re.IGNORECASE)
        url_m = re.search(r"\[(https?://[^\]]+)\]", line)
        if url_m:
            current_url = url_m.group(1)
        if m:
            param = m.group(1)
            findings.append({
                "target": target,
                "endpoint": current_url or target,
                "vuln_type": "sqli",
                "severity": "P1",
                "confidence": 90,
                "payload": f"parameter: {param}",
                "response_snippet": "sqlmap reported injectable parameter (detection only)",
                "tools_found": ["sqlmap"],
                "notes": f"GET param {param}",
            })
        if re.search(r"the back-end DBMS is", line, re.IGNORECASE):
            # Enrich the latest finding with DBMS info.
            if findings:
                findings[-1]["response_snippet"] += f" | {line.strip()[:120]}"
    return findings


def run_sqlmap(
    target: str,
    responses: list[dict[str, Any]],
    runner: ToolRunner,
    results_dir: Path,
    deep: bool = False,
    user_chosen: list[str] | None = None,
    cookie: str = "",
) -> list[dict[str, Any]]:
    """Run sqlmap (light mode by default: --risk=1 --level=1)."""
    candidates = gate_endpoints(responses, user_chosen)
    if not candidates:
        logger.info("sqlmap: no gated endpoints; skipping (boundary gate)")
        return []
    if not deep and not user_chosen:
        # Light mode: only user-chosen endpoints get sqlmap.
        logger.info("sqlmap: light mode without user-chosen endpoints; skipping")
        return []

    findings: list[dict[str, Any]] = []
    out_dir = results_dir / "scans" / "sqlmap"
    out_dir.mkdir(parents=True, exist_ok=True)
    for url in candidates:
        args = [
            "-u", url,
            "--batch",
            "--risk=1", "--level=1",       # light default per spec
            "--technique=BT",              # boolean/time-based detection only
            "--flush-session",
            "--output-dir", str(out_dir),
        ]
        if deep:
            args = ["-u", url, "--batch", "--risk=2", "--level=3",
                    "--flush-session", "--output-dir", str(out_dir)]
        if cookie:
            args.extend(["--cookie", cookie])
        result = runner.run("sqlmap", args)
        if result.status in ("not_found", "skipped"):
            logger.info("sqlmap not available; skipping (%s)", result.status)
            return []
        findings.extend(parse_sqlmap_output(result.stdout + "\n" + result.stderr, target))
    logger.info("sqlmap: %d raw findings", len(findings))
    return findings
