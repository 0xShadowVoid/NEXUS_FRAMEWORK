"""NEMESIS security skills (Phase B) — the methodology layer above tools.

A Skill is decision logic, not a shell command: purpose, prerequisites,
inputs, candidate tools, execution strategy, evidence/validation
requirements, completion criteria and safety constraints.

Skills are discoverable and configurable and gated by scope; none are
enabled automatically (``nemesis.skills.enabled`` lists the active ones).
Tool references are validated against the existing ToolRegistry — skills
never duplicate tool implementations.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from lib.logger import get_logger
from lib.paths import REPO_ROOT
from lib.tool_registry import ToolRegistry, get_registry

logger = get_logger("nemesis.skills")

SKILLS_DIR = REPO_ROOT / "skills"


@dataclass
class SecuritySkill:
    """One methodology skill (superset of the legacy agent Skill shape)."""

    name: str
    purpose: str = ""
    description: str = ""
    prompt: str = ""
    prerequisites: list[str] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)
    candidate_tools: list[str] = field(default_factory=list)
    execution_strategy: list[str] = field(default_factory=list)
    evidence_requirements: list[str] = field(default_factory=list)
    validation_requirements: list[str] = field(default_factory=list)
    completion_criteria: list[str] = field(default_factory=list)
    safety_constraints: list[str] = field(default_factory=list)
    scope_required: bool = True
    enabled: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "purpose": self.purpose,
            "prerequisites": list(self.prerequisites),
            "inputs": list(self.inputs),
            "candidate_tools": list(self.candidate_tools),
            "execution_strategy": list(self.execution_strategy),
            "evidence_requirements": list(self.evidence_requirements),
            "validation_requirements": list(self.validation_requirements),
            "completion_criteria": list(self.completion_criteria),
            "safety_constraints": list(self.safety_constraints),
            "scope_required": self.scope_required,
            "enabled": self.enabled,
        }


def _as_list(value: Any) -> list[str]:
    return [str(v) for v in (value or [])]


def load_security_skills(directory: Path | None = None) -> dict[str, SecuritySkill]:
    """Load ``skills/*.yaml`` into SecuritySkill objects (legacy keys ok)."""
    path = Path(directory) if directory else SKILLS_DIR
    skills: dict[str, SecuritySkill] = {}
    if not path.exists():
        return skills
    for file in sorted(path.glob("*.yaml")):
        try:
            data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            logger.warning("skill %s invalid: %s", file.name, exc)
            continue
        if not isinstance(data, dict):
            continue
        name = str(data.get("name") or file.stem)
        skills[name] = SecuritySkill(
            name=name,
            purpose=str(data.get("purpose") or data.get("description", "")),
            description=str(data.get("description", "")),
            prompt=str(data.get("prompt", "")),
            prerequisites=_as_list(data.get("prerequisites")),
            inputs=_as_list(data.get("inputs")),
            candidate_tools=_as_list(data.get("candidate_tools") or data.get("tools")),
            execution_strategy=_as_list(data.get("execution_strategy")),
            evidence_requirements=_as_list(data.get("evidence_requirements")),
            validation_requirements=_as_list(data.get("validation_requirements")),
            completion_criteria=_as_list(data.get("completion_criteria")),
            safety_constraints=_as_list(data.get("safety_constraints") or data.get("guardrails")),
            scope_required=bool(data.get("scope_required", True)),
            enabled=False,  # never enabled by definition file alone
        )
    return skills


def validate_skill_tools(skill: SecuritySkill, registry: ToolRegistry | None = None) -> dict[str, list[str]]:
    """Split a skill's tool references into known/unknown registry names."""
    reg = registry or get_registry()
    known = [t for t in skill.candidate_tools if t in reg]
    unknown = [t for t in skill.candidate_tools if t not in reg]
    return {"known": known, "unknown": unknown}


class SecuritySkillRegistry:
    """Discoverable, configurable, scope-gated skill registry."""

    def __init__(self, directory: Path | None = None, tool_registry: ToolRegistry | None = None):
        self.skills = load_security_skills(directory)
        self.tool_registry = tool_registry or get_registry()

    def names(self) -> list[str]:
        return sorted(self.skills)

    def get(self, name: str) -> SecuritySkill | None:
        return self.skills.get(str(name))

    def enabled_names(self, cfg: Any) -> list[str]:
        section = getattr(cfg, "nemesis", {}) or {}
        skills_cfg = section.get("skills", {}) or {}
        return [str(s) for s in (skills_cfg.get("enabled") or [])]

    def enabled(self, cfg: Any) -> list[SecuritySkill]:
        enabled = set(self.enabled_names(cfg))
        return [s for s in self.skills.values() if s.name in enabled]

    def gate(self, name: str, cfg: Any, target_config: Any = None) -> tuple[bool, str]:
        """Gate a skill: must be explicitly enabled; scope-required skills
        additionally need a scope-checked target context.
        """
        skill = self.get(name)
        if skill is None:
            return False, f"unknown skill: {name}"
        if skill.name not in self.enabled_names(cfg):
            return False, f"skill not enabled: {name}"
        if skill.scope_required and target_config is None:
            return False, f"skill {name} requires a scope-checked target"
        return True, "ok"

    def validate_all(self) -> dict[str, dict[str, list[str]]]:
        return {
            name: validate_skill_tools(skill, self.tool_registry)
            for name, skill in sorted(self.skills.items())
        }
