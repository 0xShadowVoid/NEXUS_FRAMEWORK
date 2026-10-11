"""NEMESIS multi-agent validation coordinator (Phase D).

A minimal coordinator for specialized roles:

    Recon/Context ─┐
    Security Analysis ─┤→ Validation (sequential) → Evidence Merge → Reporter
                   ┘

CRITICAL invariants (enforced by code, not just documentation):

- AI agents cannot independently promote findings to ``validated`` — the
  finding lifecycle requires supporting evidence and refuses AI actors;
- out-of-scope findings cannot become validated (lifecycle rule);
- the coordinator never fabricates evidence or assets (merge only links
  what callers actually provide).
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from core import lifecycle
from lib.logger import get_logger

logger = get_logger("nemesis.team")

INDEPENDENT_ROLES = ("recon", "analysis")
ALL_ROLES = ("recon", "analysis", "validation", "reporting")


class NemesisTeam:
    """Sequential/parallel coordinator over the four base roles."""

    def __init__(
        self,
        db: Any,
        roles: dict[str, Callable[..., Any]] | None = None,
        parallel: bool = False,
    ):
        unknown = set(roles or {}) - set(ALL_ROLES)
        if unknown:
            raise ValueError(f"unknown team role(s): {sorted(unknown)}")
        self.db = db
        self.roles = dict(roles or {})
        self.parallel = bool(parallel)

    # -- stages ----------------------------------------------------------------

    def _run_independent(self, task: dict[str, Any], ctx: dict[str, Any]) -> dict[str, list]:
        selected = {n: self.roles[n] for n in INDEPENDENT_ROLES if n in self.roles}
        results: dict[str, list] = {}
        if self.parallel and len(selected) > 1:
            with ThreadPoolExecutor(max_workers=len(selected)) as pool:
                futures = {pool.submit(work, task, ctx): name for name, work in selected.items()}
                for future in as_completed(futures):
                    name = futures[future]
                    results[name] = list(future.result() or [])
            return results
        for name, work in selected.items():
            results[name] = list(work(task, ctx) or [])
        return results

    def _validate(self, items: list[dict], ctx: dict[str, Any]) -> tuple[list[dict], list[dict]]:
        """Apply validation verdicts THROUGH the lifecycle (never around it)."""
        validated: list[dict] = []
        held: list[dict] = []
        validator = self.roles.get("validation")
        if validator is None:
            return validated, held
        for item in items or []:
            verdict = validator(item, ctx) or {}
            finding_id = verdict.get("finding_id")
            state = str(verdict.get("verdict", ""))
            if not finding_id or state not in ("validated", "rejected"):
                held.append({"finding_id": finding_id, "reason": "no lifecycle verdict produced"})
                continue
            try:
                if state == "validated":
                    result = lifecycle.transition(
                        self.db, int(finding_id), "validated",
                        actor="verifier", evidence_id=verdict.get("evidence_id"),
                        reason="team validation",
                    )
                else:
                    result = lifecycle.transition(
                        self.db, int(finding_id), "rejected",
                        actor="filter", reason=str(verdict.get("reason") or "team rejection"),
                    )
                validated.append({"finding_id": finding_id, "state": result["to_state"]})
            except lifecycle.InvalidTransition as exc:
                # Missing evidence / scope violations land here — never promoted.
                held.append({"finding_id": finding_id, "error": str(exc)})
        return validated, held

    def _merge_evidence(self, items: list[dict]) -> int:
        """Link evidence references to findings (only when both provided)."""
        merged = 0
        for item in items or []:
            fid = item.get("finding_id")
            eid = item.get("evidence_id")
            if fid and eid:
                try:
                    if self.db.set_evidence_finding(int(eid), int(fid)):
                        merged += 1
                except Exception as exc:  # merge must never break the run
                    logger.debug("evidence merge skipped: %s", exc)
        return merged

    # -- entrypoint ---------------------------------------------------------------

    def run(self, task: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
        ctx = dict(context or {})
        if self.db is not None:
            try:
                self.db.insert_audit_event(
                    actor=str(ctx.get("actor", "team")), action="nemesis.team.run",
                    category="nemesis", detail=json.dumps(task, default=str)[:300],
                )
            except Exception:  # audit must never break the run
                pass

        results = self._run_independent(task, ctx)
        validated, held = self._validate(results.get("analysis", []), ctx)
        merged = self._merge_evidence(results.get("analysis", []) + results.get("recon", []))

        reporter = self.roles.get("reporting")
        if reporter is not None:
            report = reporter(
                {"task": task, "results": results, "validated": validated, "held": held}, ctx
            )
        else:
            report = {
                "summary": "no reporting role configured",
                "counts": {
                    role: len(items) for role, items in sorted(results.items())
                },
                "validated": len(validated),
                "held": len(held),
            }

        return {
            "roles": sorted(self.roles),
            "parallel": self.parallel,
            "results": results,
            "validated": validated,
            "held": held,
            "merged_evidence": merged,
            "report": report,
        }
