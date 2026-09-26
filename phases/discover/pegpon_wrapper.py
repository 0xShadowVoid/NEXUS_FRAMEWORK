"""Pegpon wrapper — 15 light recon tools (DISCOVER phase).

Runs the Pegpon light set against the target, parses subdomain/URL
output, and stores recon artifacts under the scan's ``recon/``
directory. Every tool invocation goes through the boundary-checked
ToolRunner. Missing tools degrade per mode (light: skip + continue).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from phases.probe.tool_runner import ToolRunner
from lib.logger import get_logger

logger = get_logger("pegpon_wrapper")

# The 15 Pegpon light tools (spec Part 2).
PEGPON_TOOLS = [
    "subfinder", "assetfinder", "httpx", "ffuf", "katana", "waybackurls",
    "gau", "findomain", "chaos", "github-subdomains", "dnsx", "nuclei",
    "jsluice", "crt.sh", "securitytrails",
]


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def run_pegpon(
    domain: str,
    runner: ToolRunner,
    results_dir: Path,
    with_subdomains: bool = True,
) -> dict[str, Any]:
    """Run the Pegpon light tool set; returns recon summary dict.

    Summary: {'subdomains': [...], 'urls': [...], 'tools_run': [...],
    'tools_skipped': [...], 'tools_failed': [...]}.
    """
    recon_dir = results_dir / "recon"
    recon_dir.mkdir(parents=True, exist_ok=True)

    subdomains: set[str] = set()
    urls: set[str] = set()
    tools_run: list[str] = []
    tools_skipped: list[str] = []
    tools_failed: list[str] = []

    def absorb_subdomains(stdout: str) -> None:
        for line in (stdout or "").splitlines():
            token = line.strip().split()[0] if line.strip() else ""
            if token and "." in token and " " not in token:
                subdomains.add(token.lower().rstrip("."))

    def absorb_urls(stdout: str) -> None:
        for line in (stdout or "").splitlines():
            token = line.strip()
            if token.startswith(("http://", "https://")):
                urls.add(token)

    # --- subdomain enumeration (always, when with_subdomains) ---
    for tool in ("subfinder", "assetfinder", "findomain", "chaos", "github-subdomains"):
        if not with_subdomains:
            break
        result = runner.run(tool, ["-d", domain])
        if result.status == "not_found":
            tools_skipped.append(tool)
            continue
        if result.status == "skipped":
            tools_skipped.append(tool)
            continue
        tools_run.append(tool)
        if not result.ok:
            tools_failed.append(tool)
        absorb_subdomains(result.stdout)

    subdomains.add(domain.lower())

    # --- URL / endpoint discovery ---
    url_tools = {
        "waybackurls": [domain],
        "gau": [domain],
        "katana": ["-u", f"https://{domain}", "-d", "3"],
        "httpx": ["-l", str(recon_dir / "domains.txt"), "-silent"],
        "jsluice": ["urls", f"https://{domain}"],
    }
    # Write domains first so httpx -l has input.
    _write_lines(recon_dir / "domains.txt", sorted(subdomains))
    for tool, args in url_tools.items():
        if tool == "httpx" and not subdomains:
            continue
        result = runner.run(tool, args)
        if result.status in ("not_found", "skipped"):
            tools_skipped.append(tool)
            continue
        tools_run.append(tool)
        if not result.ok:
            tools_failed.append(tool)
        absorb_urls(result.stdout)
        absorb_subdomains(result.stdout)

    # --- content discovery (ffuf) ---
    result = runner.run(
        "ffuf",
        ["-u", f"https://{domain}/FUZZ", "-w", "wordlists/custom/common.txt", "-mc", "all", "-t", "25"],
    )
    if result.status in ("not_found", "skipped"):
        tools_skipped.append("ffuf")
    else:
        tools_run.append("ffuf")
        if not result.ok:
            tools_failed.append("ffuf")

    # --- DNS / cert / OSINT (dnsx, crt.sh, securitytrails) ---
    result = runner.run("dnsx", ["-l", str(recon_dir / "domains.txt"), "-silent"])
    if result.status in ("not_found", "skipped"):
        tools_skipped.append("dnsx")
    else:
        tools_run.append("dnsx")
        if not result.ok:
            tools_failed.append("dnsx")
        absorb_subdomains(result.stdout)

    # crt.sh and securitytrails are HTTP APIs surfaced as pseudo-tools.
    for pseudo in ("crt.sh", "securitytrails"):
        tools_skipped.append(pseudo)  # API-based; handled by dorker/OSINT path

    # Persist artifacts.
    _write_lines(recon_dir / "domains.txt", sorted(subdomains))
    _write_lines(recon_dir / "urls_wayback.txt", sorted(urls))
    endpoints = [{"url": u} for u in sorted(urls)]
    (recon_dir / "endpoints.json").write_text(
        json.dumps(endpoints, indent=2), encoding="utf-8"
    )

    summary = {
        "subdomains": sorted(subdomains),
        "urls": sorted(urls),
        "tools_run": tools_run,
        "tools_skipped": tools_skipped,
        "tools_failed": tools_failed,
    }
    logger.info(
        "pegpon: %d subdomains, %d urls (run=%d skipped=%d failed=%d)",
        len(subdomains), len(urls), len(tools_run), len(tools_skipped), len(tools_failed),
    )
    return summary
