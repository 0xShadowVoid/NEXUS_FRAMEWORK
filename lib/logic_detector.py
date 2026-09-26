"""Business-logic flaw detection (roadmap J2).

Heuristic, detection-only: flags suspicious parameter patterns that
commonly indicate logic flaws, without performing harmful actions.
Results are always marked POTENTIAL — a human (or AI triage) must
confirm before anything is treated as valid.
"""
from __future__ import annotations

import re
from typing import Any

from lib.logger import get_logger

logger = get_logger("logic_detector")

_LOGIC_PATTERNS = [
    ("price_manipulation", re.compile(r"(?i)(price|amount|cost|total|balance|fee|credit)="), "P2",
     "price/amount parameter present — test negative/zero/overflow values"),
    ("role_escalation", re.compile(r"(?i)(role|is_admin|isadmin|admin|privilege|permission|is_staff)="), "P1",
     "role/privilege parameter present — test escalation values"),
    ("mass_assignment", re.compile(r"(?i)(role|is_admin|email|password|credit|balance)"), "P2",
     "potential mass-assignment surface — test add/overwrite of sensitive fields"),
    ("id_confusion", re.compile(r"(?i)(user_id|account_id|uid|owner_id)="), "P2",
     "identity parameter — test horizontal access (see IDOR prober)"),
    ("currency_rounding", re.compile(r"(?i)(discount|percent|rate|coupon|voucher)="), "P3",
     "discount/rate parameter — test 100%+ / negative discounts"),
    ("bulk_operation", re.compile(r"(?i)(bulk|batch|all|select_all|delete_all)="), "P2",
     "bulk action parameter — verify authorization boundaries"),
]


def detect_logic_flaws(urls: list[str]) -> list[dict[str, Any]]:
    """Scan URLs for logic-flaw parameter patterns; returns POTENTIAL findings."""
    findings: list[dict[str, Any]] = []
    for url in (urls or []):
        for flaw_id, pattern, severity, note in _LOGIC_PATTERNS:
            if pattern.search(url or ""):
                findings.append({
                    "endpoint": url,
                    "vuln_type": "business_logic",
                    "severity": severity,
                    "confidence": 45,
                    "payload": f"logic pattern: {flaw_id}",
                    "response_snippet": "",
                    "tools_found": ["nexus-logic-detector"],
                    "valid": None,            # POTENTIAL only — never auto-valid
                    "notes": note,
                })
                break  # one primary pattern per URL
    logger.info("logic detector: %d potential flaw(s)", len(findings))
    return findings


def detect_from_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Re-scan existing findings' endpoints for logic patterns (deduped)."""
    urls = {str(f.get("endpoint", "")) for f in (findings or []) if f.get("endpoint")}
    return detect_logic_flaws(sorted(urls))
