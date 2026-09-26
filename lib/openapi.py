"""OpenAPI/Swagger ingestion (roadmap K1).

Parses an OpenAPI 3.x / Swagger 2.0 JSON spec into concrete endpoints
(method + path + parameters), so API surface can be discovered and
handed to the probe phase. Read-only, offline-testable.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from lib.logger import get_logger

logger = get_logger("openapi")

_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")


def parse_openapi(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract endpoints from an OpenAPI/Swagger spec dict."""
    endpoints: list[dict[str, Any]] = []
    paths = spec.get("paths") or {}
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method in _METHODS:
            op = methods.get(method)
            if not isinstance(op, dict):
                continue
            params = []
            for p in (op.get("parameters") or []):
                if isinstance(p, dict):
                    params.append({
                        "name": p.get("name", ""),
                        "in": p.get("in", ""),
                        "required": bool(p.get("required", False)),
                    })
            endpoints.append({
                "method": method.upper(),
                "path": path,
                "parameters": params,
                "operation_id": op.get("operationId", ""),
            })
    logger.info("openapi: %d endpoints parsed", len(endpoints))
    return endpoints


def endpoints_from_file(path: Path | str) -> list[dict[str, Any]]:
    """Load + parse an OpenAPI JSON/YAML file."""
    import json

    import yaml

    p = Path(path)
    text = p.read_text(encoding="utf-8")
    try:
        spec = json.loads(text)
    except json.JSONDecodeError:
        spec = yaml.safe_load(text) or {}
    return parse_openapi(spec)


def endpoints_to_urls(base_url: str, endpoints: list[dict[str, Any]]) -> list[str]:
    """Materialise endpoints into full URLs against *base_url*."""
    base = base_url.rstrip("/")
    out = []
    for ep in endpoints:
        path = ep["path"].lstrip("/")
        url = f"{base}/{path}"
        # Replace {param} placeholders with a benign value for discovery.
        url = _fill_path_params(url, ep.get("parameters") or [])
        out.append(url)
    return out


def _fill_path_params(url: str, params: list[dict[str, Any]]) -> str:
    import re

    for p in params:
        if p.get("in") == "path":
            url = re.sub(r"\{[^}]*\}", str(p.get("name", "x")) or "x", url, count=1)
    url = re.sub(r"\{[^}]*\}", "1", url)  # any remaining placeholders
    return url
