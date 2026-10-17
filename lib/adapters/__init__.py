"""Security-tool adapter framework (see :mod:`lib.adapters.base`).

Public surface:

    base      — adapter contract, value objects, policy guard, ingestion
    registry  — name → factory registration (pluggable integrations)
    zap       — OWASP ZAP adapter (+ offline mock)
"""
from __future__ import annotations

__all__ = ["base", "registry", "zap"]
