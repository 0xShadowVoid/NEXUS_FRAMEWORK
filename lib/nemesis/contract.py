"""NEMESIS completion contract (Phase G).

A lightweight, structured completion record for agent tasks. It does not
replace the existing NEXUS reporting system — it integrates with it:
the loop's report embeds this contract alongside the existing outputs.

Required blocks (uppercase keys in ``to_dict``): WHAT_CHANGED,
WHAT_WAS_OBSERVED, WHAT_WAS_VERIFIED, EVIDENCE, REMAINING_UNCERTAINTY,
NEXT_STATE.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

REQUIRED_BLOCKS = (
    "WHAT_CHANGED", "WHAT_WAS_OBSERVED", "WHAT_WAS_VERIFIED",
    "EVIDENCE", "REMAINING_UNCERTAINTY", "NEXT_STATE",
)


@dataclass
class CompletionContract:
    """Structured completion record for one agent task."""

    objective: str = ""
    what_changed: list[str] = field(default_factory=list)
    what_was_observed: list[str] = field(default_factory=list)
    what_was_verified: list[str] = field(default_factory=list)
    evidence: list[Any] = field(default_factory=list)
    remaining_uncertainty: list[str] = field(default_factory=list)
    next_state: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective": self.objective,
            "WHAT_CHANGED": list(self.what_changed),
            "WHAT_WAS_OBSERVED": list(self.what_was_observed),
            "WHAT_WAS_VERIFIED": list(self.what_was_verified),
            "EVIDENCE": list(self.evidence),
            "REMAINING_UNCERTAINTY": list(self.remaining_uncertainty),
            "NEXT_STATE": self.next_state,
        }

    def check(self) -> tuple[bool, list[str]]:
        """Validate the contract. Returns ``(ok, issues)``.

        Rules:
        - observations must be recorded;
        - verification claims require evidence references;
        - remaining uncertainty must be explicitly recorded (use a
          placeholder entry like "none known" when truly none);
        - next state must be recorded.
        """
        issues: list[str] = []
        if not self.what_was_observed:
            issues.append("no observations recorded")
        if self.what_was_verified and not self.evidence:
            issues.append("verification claims without evidence references")
        if not self.remaining_uncertainty:
            issues.append("remaining_uncertainty must be explicitly recorded (use 'none known')")
        if not str(self.next_state or "").strip():
            issues.append("next_state not recorded")
        return (not issues, issues)


def build_from_run(
    objective: str,
    observations: list[dict[str, Any]],
    errors: list[str] | None = None,
) -> CompletionContract:
    """Build a contract from raw loop observations (helper for the loop)."""
    changed: list[str] = []
    observed: list[str] = []
    verified: list[str] = []
    evidence: list[Any] = []
    for obs in observations or []:
        action = str(obs.get("action", "?"))
        status = str(obs.get("status", "?"))
        observed.append(f"{action}: {status}")
        result = obs.get("result")
        if isinstance(result, dict):
            for ref in result.get("evidence_refs", []) or []:
                evidence.append(ref)
            if result.get("changed"):
                changed.append(str(result.get("changed")))
            if status == "ok" and result.get("verified"):
                verified.append(action)
    uncertainty = list(errors or [])
    if not uncertainty:
        uncertainty = ["none known"]
    return CompletionContract(
        objective=objective,
        what_changed=changed,
        what_was_observed=observed,
        what_was_verified=verified,
        evidence=evidence,
        remaining_uncertainty=uncertainty,
        next_state="completed" if observations else "not-started",
    )
