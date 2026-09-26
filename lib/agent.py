"""NEXUS agent loop (roadmap C1).

Contract-bounded: plan → act → observe, over a **whitelisted** action
map and a skills registry. The planner uses the configured AI provider
when available and falls back to deterministic heuristics otherwise, so
the agent works offline too. Every step is audited.

Guardrails: bounded step count, whitelisted actions only, no shell,
scope validation happens inside the actions themselves.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from lib.config import Config
from lib.logger import get_logger
from lib.paths import REPO_ROOT

logger = get_logger("agent")

SKILLS_DIR = REPO_ROOT / "skills"
DEFAULT_MAX_STEPS = 5

# Actions the agent may invoke (whitelist).
ALLOWED_ACTIONS = {
    "scan", "discover", "dork", "cve-update", "status", "report", "schedules", "verify",
}

_HEURISTICS = [
    (("recon", "subdomain", "discover", "enumerate"), "discover"),
    (("cve", "cve-update", "zero-day", "kev"), "cve-update"),
    (("dork", "google", "github leak", "osint"), "dork"),
    (("report", "write-up", "summary"), "report"),
    (("status", "state", "health"), "status"),
    (("scan", "hunt", "test", "probe"), "scan"),
]


@dataclass
class Skill:
    """A reusable capability the agent can plan against."""

    name: str
    description: str = ""
    prompt: str = ""
    tools: list[str] = field(default_factory=list)
    guardrails: list[str] = field(default_factory=list)


def load_skills(directory: Path | None = None) -> dict[str, Skill]:
    """Load ``skills/*.yaml`` into Skill objects."""
    path = Path(directory) if directory else SKILLS_DIR
    skills: dict[str, Skill] = {}
    if not path.exists():
        return skills
    for file in sorted(path.glob("*.yaml")):
        try:
            data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            logger.warning("skill %s invalid: %s", file.name, exc)
            continue
        name = str(data.get("name") or file.stem)
        skills[name] = Skill(
            name=name,
            description=str(data.get("description", "")),
            prompt=str(data.get("prompt", "")),
            tools=list(data.get("tools", []) or []),
            guardrails=list(data.get("guardrails", []) or []),
        )
    return skills


class NexusAgent:
    """Bounded plan→act→observe agent."""

    def __init__(
        self,
        cfg: Config,
        ai: Any = None,
        actions: dict[str, Callable[[dict[str, Any]], Any]] | None = None,
        skills: dict[str, Skill] | None = None,
        audit_path: Path | None = None,
    ):
        self.cfg = cfg
        self.ai = ai
        self.actions = actions or {}
        self.skills = skills if skills is not None else load_skills()
        self.audit_path = audit_path or (REPO_ROOT / "logs" / "agent_audit.log")

    # -- planning ----------------------------------------------------------

    def plan(self, objective: str) -> list[dict[str, Any]]:
        """Produce a step list (AI first, heuristic fallback)."""
        steps: list[dict[str, Any]] = []
        if self.ai is not None and hasattr(self.ai, "plan_steps"):
            try:
                suggestion = self.ai.plan_steps(objective, list(self.skills.values()))
                if suggestion and isinstance(suggestion.get("steps"), list):
                    steps = suggestion["steps"]
            except Exception as exc:  # AI must never break planning
                logger.warning("AI planning failed, using heuristics: %s", exc)
        if not steps:
            steps = self._heuristic_plan(objective)
        # Whitelist + shape validation.
        clean: list[dict[str, Any]] = []
        for step in steps:
            action = str(step.get("action", "")).strip()
            if action in ALLOWED_ACTIONS or action in self.actions:
                clean.append({"action": action,
                              "target": str(step.get("target", "") or ""),
                              "why": str(step.get("why", "") or "")})
        return clean

    @staticmethod
    def _heuristic_plan(objective: str) -> list[dict[str, Any]]:
        text = (objective or "").lower()
        for keywords, action in _HEURISTICS:
            if any(k in text for k in keywords):
                target = ""
                for token in objective.split():
                    if "." in token and not token.startswith("http"):
                        target = token.strip(",.()")
                        break
                return [{"action": action, "target": target, "why": f"matched '{action}' intent"}]
        return [{"action": "status", "target": "", "why": "no specific intent found"}]

    # -- execution ---------------------------------------------------------

    def _audit(self, record: dict[str, Any]) -> None:
        try:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            record = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), **record}
            with self.audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except OSError as exc:
            logger.debug("agent audit failed: %s", exc)

    def act(self, step: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
        """Execute one step through the whitelisted action map."""
        action = step.get("action", "")
        if dry_run:
            return {"action": action, "target": step.get("target", ""), "status": "dry-run"}
        handler = self.actions.get(action)
        if handler is None:
            return {"action": action, "status": "no-handler"}
        try:
            result = handler(step)
            return {"action": action, "status": "ok", "result": result}
        except Exception as exc:
            logger.warning("agent step %s failed: %s", action, exc)
            return {"action": action, "status": "error", "error": str(exc)}

    def run(self, objective: str, max_steps: int = DEFAULT_MAX_STEPS, dry_run: bool = False) -> dict[str, Any]:
        """Plan and execute up to *max_steps* steps; returns a run report."""
        steps = self.plan(objective)[:max_steps]
        observations: list[dict[str, Any]] = []
        for step in steps:
            outcome = self.act(step, dry_run=dry_run)
            observations.append(outcome)
            self._audit({"objective": objective, "step": step, "outcome": outcome})
        report = {
            "objective": objective,
            "planned": len(steps),
            "executed": len(observations),
            "dry_run": dry_run,
            "skills_available": sorted(self.skills),
            "observations": observations,
        }
        logger.info("agent: %d step(s) executed (dry_run=%s)", len(observations), dry_run)
        return report
