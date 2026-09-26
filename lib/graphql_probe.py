"""GraphQL introspection analysis (roadmap K2).

Parses a GraphQL introspection result and flags common misconfigurations
(introspection enabled, sensitive type names, deprecated fields, exposed
admin/mutation surfaces). Read-only; purely analytical.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from lib.logger import get_logger

logger = get_logger("graphql_probe")

_SENSITIVE_NAMES = ("password", "token", "secret", "api_key", "apikey", "private",
                    "internal", "admin", "credit", "ssn", "social")
_DEPRECATED_MARKER = "deprecated"


def analyze_introspection(introspection: dict[str, Any]) -> list[dict[str, Any]]:
    """Return findings for a GraphQL introspection payload."""
    findings: list[dict[str, Any]] = []
    data = introspection.get("data") or introspection
    schema = data.get("__schema") or {}
    types = schema.get("types") or []

    # 1. Introspection itself is enabled (surface disclosure).
    findings.append({
        "vuln_type": "graphql_misconfig",
        "severity": "P4",
        "confidence": 80,
        "payload": "introspection enabled",
        "response_snippet": "GraphQL introspection returned the full schema",
        "tools_found": ["nexus-graphql-probe"],
    })

    sensitive: list[str] = []
    deprecated_count = 0
    mutation_types: list[str] = []
    for t in types:
        name = str(t.get("name", ""))
        if any(s in name.lower() for s in _SENSITIVE_NAMES):
            sensitive.append(name)
        for f in (t.get("fields") or []):
            if f.get("isDeprecated"):
                deprecated_count += 1
            if _DEPRECATED_MARKER in str(f.get("deprecationReason", "")).lower():
                deprecated_count += 1
    for t in types:
        if str(t.get("name", "")) in ("Mutation", "RootMutation") and (t.get("fields") or []):
            mutation_types = [f.get("name") for f in t["fields"]]

    if sensitive:
        findings.append({
            "vuln_type": "info_disclosure",
            "severity": "P3",
            "confidence": 55,
            "payload": "sensitive type names",
            "response_snippet": f"sensitive types exposed: {', '.join(sorted(set(sensitive))[:15])}",
            "tools_found": ["nexus-graphql-probe"],
        })
    if mutation_types:
        findings.append({
            "vuln_type": "business_logic",
            "severity": "P3",
            "confidence": 45,
            "payload": "mutation surface",
            "response_snippet": f"mutation fields: {', '.join(mutation_types[:15])}",
            "tools_found": ["nexus-graphql-probe"],
            "valid": None,
        })
    if deprecated_count:
        findings.append({
            "vuln_type": "info_disclosure",
            "severity": "P4",
            "confidence": 50,
            "payload": "deprecated fields",
            "response_snippet": f"{deprecated_count} deprecated field(s) present",
            "tools_found": ["nexus-graphql-probe"],
        })

    logger.info("graphql probe: %d finding(s)", len(findings))
    return findings


def analyze_introspection_file(path: Path | str) -> list[dict[str, Any]]:
    import json

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return analyze_introspection(payload)
