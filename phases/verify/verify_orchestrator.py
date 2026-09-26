"""VERIFY phase orchestrator (roadmap A1/A2).

Runs deterministic verification over raw probe findings between PROBE
and ANALYZE. Findings that evidence actively contradicts are marked
invalid; everything else keeps its verification record so ANALYZE can
require confirmation (or multi-tool corroboration) for high-value
submission.
"""
from __future__ import annotations

from typing import Any, Callable

from lib.logger import get_logger
from lib.verifier import verification_dict, verify_finding

logger = get_logger("verify_orchestrator")


def run_verify(
    findings: list[dict[str, Any]],
    http_probe: Callable[[str], str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Annotate findings with verification results; returns (findings, summary)."""
    verified = unverified = disproved = 0

    for f in findings:
        result = verify_finding(f, http_probe=http_probe)
        f["verification"] = verification_dict(result)
        if result.disproved:
            disproved += 1
            f["valid"] = False
            f["validity_reason"] = f"verification disproved: {result.notes}"
        elif result.verified:
            verified += 1
            f["verified"] = True
        else:
            unverified += 1
            f["verified"] = False

    summary = {
        "total": len(findings),
        "verified": verified,
        "unverified": unverified,
        "disproved": disproved,
    }
    logger.info(
        "verify: %d verified, %d unverified, %d disproved",
        verified, unverified, disproved,
    )
    return findings, summary
