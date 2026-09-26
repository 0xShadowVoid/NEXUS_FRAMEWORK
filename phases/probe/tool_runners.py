"""Generic tool runners for the remaining PROBE tools.

Wraps commix, ghauri, jwt-tool, lfihunt, graphql-cop, waf-probe,
nomore403, arjun (light), and the cloud scanners with boundary-checked
invocations and per-tool output parsing into raw findings.
"""
from __future__ import annotations

import re
from typing import Any

from phases.probe.tool_runner import ToolRunner
from lib.logger import get_logger
from lib.status_detector import is_heavy_tool_candidate

logger = get_logger("tool_runners")


def _mk(url: str, vtype: str, sev: str, conf: int, tool: str, evidence: str) -> dict[str, Any]:
    return {
        "endpoint": url,
        "vuln_type": vtype,
        "severity": sev,
        "confidence": conf,
        "payload": "",
        "response_snippet": evidence[:300],
        "tools_found": [tool],
    }


def run_commix(target: str, responses: list[dict[str, Any]], runner: ToolRunner, deep: bool, cookie: str = "") -> list[dict[str, Any]]:
    """Command-injection detection (deep mode; heavy-tool gated)."""
    if not deep:
        return []
    candidates = [r.get("url", "") for r in responses if is_heavy_tool_candidate(
        int(r.get("status_code", 0) or 0), str(r.get("body", "") or ""))]
    findings = []
    for url in candidates:
        args = ["-u", url, "--batch", "--level=1"]
        if cookie:
            args.extend(["--cookie", cookie])
        result = runner.run("commix", args)
        if result.status in ("not_found", "skipped"):
            return []
        if re.search(r"(?i)the target.*is vulnerable", result.stdout):
            findings.append(_mk(url, "rce", "P1", 85, "commix", "command injection confirmed (detection only)"))
    return findings


def run_ghauri(target: str, urls: list[str], runner: ToolRunner, deep: bool) -> list[dict[str, Any]]:
    """Blind SQLi detection (deep mode)."""
    if not deep:
        return []
    findings = []
    for url in urls[:50]:
        result = runner.run("ghauri", ["-u", url, "--batch", "--dbs=0"])
        if result.status in ("not_found", "skipped"):
            return []
        if re.search(r"(?i)vulnerable", result.stdout):
            findings.append(_mk(url, "sqli", "P1", 88, "ghauri", "blind SQLi confirmed (detection only)"))
    return findings


def run_jwt_tool(target: str, urls: list[str], runner: ToolRunner) -> list[dict[str, Any]]:
    """JWT analysis over URLs that look token-bearing."""
    findings = []
    for url in urls:
        if not re.search(r"(?i)(jwt|token|auth|session)", url):
            continue
        result = runner.run("jwt-tool", [url])
        if result.status in ("not_found", "skipped"):
            return []
        for line in result.stdout.splitlines():
            if re.search(r"(?i)(weak secret|none algorithm|expired)", line):
                findings.append(_mk(url, "jwt_weakness", "P2", 75, "jwt-tool", line.strip()))
                break
    return findings


def run_lfihunt(target: str, urls: list[str], runner: ToolRunner) -> list[dict[str, Any]]:
    """LFI detection."""
    findings = []
    for url in urls:
        if not re.search(r"(?i)(file|path|page|include|load|doc|download|cat|dir|view)", url):
            continue
        result = runner.run("lfihunt", ["-u", url])
        if result.status in ("not_found", "skipped"):
            return []
        if re.search(r"(?i)(passwd|root:|boot loader)", result.stdout):
            findings.append(_mk(url, "lfi", "P2", 82, "lfihunt", "file content marker in response (detection only)"))
    return findings


def run_graphql_cop(target: str, urls: list[str], runner: ToolRunner) -> list[dict[str, Any]]:
    """GraphQL vulnerability scanning."""
    findings = []
    for url in urls:
        if "graphql" not in url.lower():
            continue
        result = runner.run("graphql-cop", ["-t", url])
        if result.status in ("not_found", "skipped"):
            return []
        for m in re.finditer(r"(?im)^\[.*?\]\s+(.*?)\s*$", result.stdout):
            issue = m.group(1).strip()
            if issue:
                findings.append(_mk(url, "graphql_misconfig", "P3", 70, "graphql-cop", issue))
    return findings


def run_waf_probe(target: str, runner: ToolRunner) -> list[dict[str, Any]]:
    """WAF detection (informational)."""
    result = runner.run("waf-probe", ["-u", f"https://{target}"])
    if result.status in ("not_found", "skipped"):
        return []
    if result.stdout.strip():
        return [_mk(f"https://{target}", "info", "P4", 60, "waf-probe", result.stdout[:200])]
    return []


def run_nomore403(target: str, urls: list[str], runner: ToolRunner) -> list[dict[str, Any]]:
    """401/403 bypass testing (detection only)."""
    findings = []
    for r_dict in urls:
        url = r_dict if isinstance(r_dict, str) else str(r_dict.get("url", ""))
        result = runner.run("nomore403", ["-u", url])
        if result.status in ("not_found", "skipped"):
            return []
        if re.search(r"(?i)(bypass|200 ok)", result.stdout):
            findings.append(_mk(url, "auth_bypass", "P1", 80, "nomore403", "403 bypass achieved (detection only)"))
    return findings


def run_arjun(target: str, urls: list[str], runner: ToolRunner) -> list[dict[str, Any]]:
    """Hidden-parameter discovery (light scan allowed per spec)."""
    findings = []
    for url in urls[:100]:
        result = runner.run("arjun", ["-u", url])
        if result.status in ("not_found", "skipped"):
            return []
        for m in re.finditer(r"(?i)parameter\s+[:=]\s+(\w+)", result.stdout):
            findings.append(_mk(url, "info", "P4", 55, "arjun", f"hidden parameter: {m.group(1)}"))
    return findings


def run_cloudenum(target: str, runner: ToolRunner) -> list[dict[str, Any]]:
    """Cloud asset enumeration (S3/Azure/GCP buckets)."""
    result = runner.run("cloudenum", ["-k", target])
    if result.status in ("not_found", "skipped"):
        return []
    findings = []
    for m in re.finditer(r"(?im)^\s*(https?://\S+|s3:::\S+)\s*$", result.stdout):
        findings.append(_mk(m.group(1), "info", "P4", 50, "cloudenum", "public cloud asset identified"))
    return findings


def run_s3scanner(target: str, runner: ToolRunner) -> list[dict[str, Any]]:
    """S3 bucket scanning."""
    result = runner.run("s3scanner", ["scan", "--bucket-file", "-"])
    if result.status in ("not_found", "skipped"):
        return []
    findings = []
    for line in result.stdout.splitlines():
        if re.search(r"(?i)(public|readable|writable)", line):
            findings.append(_mk(line.split()[0] if line.split() else target, "info", "P4", 60, "s3scanner", line.strip()))
    return findings


def run_prowler(target: str, runner: ToolRunner) -> list[dict[str, Any]]:
    """Cloud posture scanning (master account, informational)."""
    result = runner.run("prowler", ["-g", "quick"])
    if result.status in ("not_found", "skipped"):
        return []
    findings = []
    for line in result.stdout.splitlines():
        m = re.search(r"(?i)(critical|high)\s+\|\s+(.*)", line)
        if m:
            findings.append(_mk(target, "cloud_misconfig", "P2", 70, "prowler", m.group(2)[:200]))
    return findings


def run_all_light(target: str, urls: list[str], runner: ToolRunner) -> list[dict[str, Any]]:
    """Run the light-mode tool set; returns raw findings."""
    findings: list[dict[str, Any]] = []
    findings.extend(run_arjun(target, urls, runner))
    findings.extend(run_jwt_tool(target, urls, runner))
    findings.extend(run_lfihunt(target, urls, runner))
    findings.extend(run_graphql_cop(target, urls, runner))
    findings.extend(run_waf_probe(target, runner))
    findings.extend(run_cloudenum(target, runner))
    return findings


def run_all_light_parallel(
    target: str,
    urls: list[str],
    runner: ToolRunner,
    max_workers: int = 2,
) -> list[dict[str, Any]]:
    """Run the independent light tools concurrently (roadmap D4)."""
    from concurrent.futures import ThreadPoolExecutor

    jobs = [run_arjun, run_jwt_tool, run_lfihunt, run_graphql_cop, run_waf_probe, run_cloudenum]
    findings: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(fn, target, urls, runner) for fn in jobs]
        for future in futures:
            try:
                findings.extend(future.result())
            except Exception as exc:  # one failing tool must not break the phase
                logger.warning("parallel light tool failed: %s", exc)
    return findings


def run_all_deep(target: str, urls: list[str], responses: list[dict[str, Any]], runner: ToolRunner, cookie: str = "") -> list[dict[str, Any]]:
    """Run the deep-mode tool set (includes light set)."""
    findings = run_all_light(target, urls, runner)
    findings.extend(run_commix(target, responses, runner, deep=True, cookie=cookie))
    findings.extend(run_ghauri(target, urls, runner, deep=True))
    findings.extend(run_nomore403(target, urls, runner))
    findings.extend(run_s3scanner(target, runner))
    findings.extend(run_prowler(target, runner))
    return findings
