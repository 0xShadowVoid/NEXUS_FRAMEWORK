"""NEMESIS layer — security reasoning, planning, coordination, skills.

Principle (from the architecture rule):

    NEXUS executes.  NEMESIS reasons.  Help Me Learn explains.

Everything in this package is additive: it reuses NEXUS primitives
(scope validation, ToolRegistry, evidence, finding lifecycle, audit,
checkpoint/recovery) and never bypasses a security boundary.
Optional capabilities (browser, MCP) are OFF by default.
"""
from __future__ import annotations

__all__ = [
    "memory",
    "skills",
    "contract",
    "session",
    "loop",
    "team",
    "browser",
    "mcp",
]
