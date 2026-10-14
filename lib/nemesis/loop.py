"""NEMESIS plan → act → observe → verify loop (Phase C).

Strengthens the existing agent loop (``lib/agent.NexusAgent``) with:

- **understand** — engagement memory + guard status before planning;
- **act** — the same whitelisted action map the CLI uses (audited);
- **observe** — structured observations + memory journaling;
- **verify** — a completion contract check (Phase G);
- **report** — structured result, persisted as a resumable session (Phase H).

NEMESIS never bypasses NEXUS safety boundaries: the kill switch and
request budget are honored, actions keep their own scope checks, AI
output stays advisory (it can plan, never validate findings), and every
step keeps flowing through the existing audit trail.
"""
from __future__ import annotations

from typing import Any, Callable

from lib.config import Config
from lib.logger import get_logger
from lib.ops_guard import KillSwitch, requests_remaining
from lib.nemesis.contract import build_from_run
from lib.nemesis.memory import EngagementMemory
from lib.nemesis.session import NemesisSession, load_session, save_session

logger = get_logger("nemesis.loop")

DEFAULT_MAX_STEPS = 5


def _clip(value: Any, limit: int = 500) -> Any:
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, dict):
        return {k: _clip(v, limit) for k, v in list(value.items())[:20]}
    if isinstance(value, list):
        return [_clip(v, limit) for v in value[:20]]
    return value


class NemesisLoop:
    """Bounded understand → plan → act → observe → verify → report cycle."""

    def __init__(
        self,
        cfg: Config,
        db: Any = None,
        agent: Any = None,
        actions: dict[str, Callable[[dict[str, Any]], Any]] | None = None,
        max_steps: int = DEFAULT_MAX_STEPS,
        killswitch: KillSwitch | None = None,
    ):
        from lib.agent import NexusAgent

        self.cfg = cfg
        self.db = db
        self.actions = actions or {}
        self.agent = agent or NexusAgent(cfg=cfg, actions=self.actions)
        self.max_steps = int(max_steps)
        self.killswitch = killswitch or KillSwitch()

    # -- stages --------------------------------------------------------------

    def memory(self, engagement: str) -> EngagementMemory | None:
        if self.db is None:
            return None
        return EngagementMemory(self.db, engagement)

    def guard_status(self) -> dict[str, Any]:
        return {"killed": self.killswitch.killed(), "requests_remaining": requests_remaining()}

    def understand(self, objective: str, engagement: str) -> dict[str, Any]:
        mem = self.memory(engagement)
        return {
            "objective": objective,
            "engagement": engagement,
            "memory": mem.context_summary() if mem else {},
            "guards": self.guard_status(),
        }

    def run_cycle(self, objective: str, engagement: str, dry_run: bool = False) -> dict[str, Any]:
        """Run one bounded cycle; returns the structured report."""
        guards = self.guard_status()
        if guards["killed"]:
            logger.warning("kill switch engaged; refusing to run")
            return {"status": "blocked", "reason": "kill switch engaged", "objective": objective}

        understanding = self.understand(objective, engagement)
        session: NemesisSession | None = load_session(self.db, engagement) if self.db else None
        if session is None and self.db is not None:
            session = NemesisSession(engagement=engagement)
        if session is not None:
            session.phase = "plan"

        steps = self.agent.plan(objective)
        if session is not None and session.completed_actions:
            done = set(session.completed_actions)
            steps = [s for s in steps if NemesisSession.action_sig(s) not in done]
        steps = steps[: self.max_steps]

        if session is not None and not dry_run:
            session.plan = steps
            session.pending_actions = [NemesisSession.action_sig(s) for s in steps]
            save_session(self.db, session)

        observations: list[dict[str, Any]] = []
        errors: list[str] = []
        mem = self.memory(engagement)

        for step in steps:
            if self.killswitch.killed():
                errors.append("kill switch engaged mid-run; aborting")
                break
            outcome = self.agent.act(step, dry_run=dry_run)
            observations.append(outcome)
            sig = NemesisSession.action_sig(step)
            if outcome.get("status") == "ok" and not dry_run:
                if session is not None:
                    session.completed_actions.append(sig)
                    session.pending_actions = [s for s in session.pending_actions if s != sig]
                if mem is not None:
                    try:
                        mem.remember(
                            "tool_results", sig,
                            {"status": outcome.get("status"), "result": _clip(outcome.get("result"))},
                        )
                    except Exception as exc:  # memory must never break the loop
                        logger.debug("memory journaling skipped: %s", exc)
            elif outcome.get("status") == "error":
                errors.append(f"{sig}: {outcome.get('error', '')}")
                if session is not None:
                    session.previous_errors.append(errors[-1])
            if session is not None and not dry_run:
                save_session(self.db, session)

        session.phase = "report"
        contract = build_from_run(objective, observations, errors)
        contract_ok, contract_issues = contract.check()
        if session is not None:
            session.state = "completed" if contract_ok else "partial"
            if not dry_run:
                save_session(self.db, session)

        report = {
            "status": "ok",
            "objective": objective,
            "engagement": engagement,
            "dry_run": dry_run,
            "understanding": understanding,
            "observations": observations,
            "contract": contract.to_dict(),
            "contract_ok": contract_ok,
            "contract_issues": contract_issues,
            "session": session.to_dict() if session is not None else None,
        }
        logger.info(
            "nemesis cycle: %d step(s), contract_ok=%s (engagement=%s)",
            len(observations), contract_ok, engagement,
        )
        return report
