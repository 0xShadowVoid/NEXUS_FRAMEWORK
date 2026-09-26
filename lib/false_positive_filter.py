"""Per-type false-positive filtering.

Strictness semantics (from the build spec):

- ``aggressive``: enforce the confidence threshold strictly AND drop
  findings matching ``auto_filter`` patterns. Below-threshold findings
  are marked FALSE_POSITIVE.
- ``conservative``: only drop clear ``auto_filter`` matches; below
  threshold findings are kept as POTENTIAL (not dropped).

Output states: VALID / FALSE_POSITIVE / POTENTIAL (with reasons).
"""
from __future__ import annotations

import re
from typing import Any

STATES = ("VALID", "FALSE_POSITIVE", "POTENTIAL")


def _compile_patterns(patterns: list[str]) -> list[re.Pattern[str]]:
    out = []
    for p in patterns or []:
        try:
            out.append(re.compile(re.escape(p), re.IGNORECASE))
        except re.error:
            continue
    return out


def _finding_text(finding: dict[str, Any]) -> str:
    return " ".join(
        str(finding.get(k, "") or "") for k in ("endpoint", "payload", "response_snippet", "notes")
    )


class FalsePositiveFilter:
    """Applies per-type strictness rules to scored findings."""

    def __init__(self, filters_config: dict[str, Any]):
        self.rules: dict[str, dict[str, Any]] = {}
        filters = filters_config.get("filters", {}) or {}
        for ftype, rule in filters.items():
            self.rules[ftype] = {
                "strictness": str(rule.get("strictness", "conservative")).lower(),
                "threshold": int(rule.get("confidence_threshold", 0) or 0),
                "patterns": _compile_patterns(list(rule.get("auto_filter", []) or [])),
            }

    def learn_from_review(self, finding: dict[str, Any], verdict: str) -> dict[str, Any] | None:
        """Learn from a human review decision (real-reports/skills feedback loop).

        verdict: 'FP' (false positive) or 'TP' (true positive). Adds a durable
        auto_filter pattern derived from the finding's own evidence so the same
        pattern stops being reported next run. Returns the learned rule update.
        """
        vt = str(finding.get("vuln_type", "")).lower().strip()
        matched = self.rule_for(vt)
        if matched is None:
            return None
        key, rule = matched
        marker = ""
        snippet = str(finding.get("response_snippet", "") or "")
        payload = str(finding.get("payload", "") or "")
        if verdict.upper() == "FP" and snippet.strip():
            # Use a compact, distinctive fragment of the response as the pattern.
            words = [w for w in snippet.split() if len(w) >= 6]
            marker = (words[0] if words else snippet[:40]).strip()
        elif verdict.upper() == "FP" and payload.strip():
            marker = payload.strip()
        if not marker:
            return None
        if marker not in [p.pattern for p in rule["patterns"]]:
            rule["patterns"].append(re.compile(re.escape(marker), re.IGNORECASE))
            return {"type": vt, "learned_pattern": marker, "source": "human review"}
        return None

    def rule_for(self, finding_type: str) -> tuple[str, dict[str, Any]] | None:
        """Resolve the rule for a finding type (exact then substring)."""
        vt = str(finding_type).lower().strip()
        if vt in self.rules:
            return vt, self.rules[vt]
        for key in self.rules:
            if key in vt or vt in key:
                return key, self.rules[key]
        return None

    def classify(self, finding: dict[str, Any]) -> tuple[str, str]:
        """Classify a finding → (state, reason)."""
        vt = str(finding.get("vuln_type", "")).lower().strip()
        confidence = int(finding.get("confidence", 50))
        matched = self.rule_for(vt)
        if matched is None:
            return ("VALID", "no rule for type; default valid")

        key, rule = matched
        text = _finding_text(finding)

        # auto_filter patterns always drop (both strictness levels).
        for pat in rule["patterns"]:
            if pat.search(text):
                return ("FALSE_POSITIVE", f"matched auto_filter pattern of {key}")

        strictness = rule["strictness"]
        threshold = rule["threshold"]

        if strictness == "aggressive":
            if confidence < threshold:
                return ("FALSE_POSITIVE", f"confidence {confidence} below {key} threshold {threshold} (aggressive)")
            return ("VALID", f"confidence {confidence} >= threshold {threshold} (aggressive)")
        # conservative
        if confidence < threshold:
            return ("POTENTIAL", f"confidence {confidence} below {key} threshold {threshold} (conservative: kept as potential)")
        return ("VALID", f"confidence {confidence} >= threshold {threshold} (conservative)")


def classify_finding(finding: dict[str, Any], filters_config: dict[str, Any]) -> tuple[str, str]:
    """Functional wrapper (module-level)."""
    return FalsePositiveFilter(filters_config).classify(finding)
