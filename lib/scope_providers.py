"""Scope providers (roadmap E1: scope auto-sync).

Fetches a bug-bounty program's *published* in/out-of-scope from a platform's
API and normalizes it into the document shape consumed by
:mod:`lib.scope_sync` (``parse_h1_program`` / ``parse_bugcrowd_program``).

Conventions mirror the HUNT phase's ``api_fetcher``:

* a fixed destination allowlist checked by the SSRF guard before every send;
* an injectable ``requests`` session so the whole path is offline-testable;
* credentials are read from the environment by **name** only and are never
  logged or echoed back in a report.

Unlike the best-effort listing fetch, a scope sync must not silently write an
empty scope, so failures raise :class:`ScopeProviderError` and the caller
reports the program as *skipped*.
"""
from __future__ import annotations

from typing import Any, Callable
from urllib.parse import quote

import requests

from lib.logger import get_logger
from lib.ssrf_guard import is_safe_url

logger = get_logger("scope_providers")

_TIMEOUT = (10, 30)

H1_BASE = "https://api.hackerone.com/v1/hackers/programs"
BUGCROWD_BASE = "https://api.bugcrowd.com/programs"

# Fixed, operator-independent destinations (SSRF guard allowlist).
_SSRF_ALLOW = {"api.hackerone.com", "api.bugcrowd.com"}

# Default environment variable *names* per platform (never values).
DEFAULT_CRED_ENV = {
    "hackerone": {"username": "H1_API_USER", "token": "H1_API_TOKEN"},
    "bugcrowd": {"token": "BUGCROWD_API_TOKEN"},
}


class ScopeProviderError(RuntimeError):
    """A scope fetch failed (auth, not found, transport, malformed)."""


def _checked(url: str) -> None:
    safe, reason = is_safe_url(url, allow=_SSRF_ALLOW)
    if not safe:
        raise ScopeProviderError(f"ssrf guard blocked {url}: {reason}")


def _handle(value: str) -> str:
    handle = str(value or "").strip().strip("/")
    if not handle:
        raise ScopeProviderError("program handle is required")
    return quote(handle, safe="")


def _get(session: requests.Session | None, url: str, **kwargs: Any) -> requests.Response:
    _checked(url)
    sess = session or requests
    try:
        return sess.get(url, timeout=_TIMEOUT, **kwargs)
    except requests.RequestException as exc:
        raise ScopeProviderError(f"request failed: {exc.__class__.__name__}") from exc


def _json(resp: requests.Response, platform: str) -> Any:
    if resp.status_code in (401, 403):
        raise ScopeProviderError(f"{platform} authentication failed")
    if resp.status_code == 404:
        raise ScopeProviderError(f"{platform} program not found")
    if resp.status_code != 200:
        raise ScopeProviderError(f"{platform} HTTP {resp.status_code}")
    try:
        return resp.json()
    except ValueError as exc:
        raise ScopeProviderError(f"{platform} returned malformed JSON") from exc


def _jsonapi_node(data: Any) -> dict[str, Any]:
    """Unwrap a JSON:API single-resource envelope to the resource node."""
    node = data
    if isinstance(node, dict) and isinstance(node.get("data"), list):
        node = node["data"][0] if node["data"] else {}
    elif isinstance(node, dict) and isinstance(node.get("data"), dict):
        node = node["data"]
    return node if isinstance(node, dict) else {}


def _h1_to_program(node: dict[str, Any], handle: str) -> dict[str, Any]:
    """Convert an H1 program resource into ``parse_h1_program`` input."""
    attrs = node.get("attributes") or {}
    rel = node.get("relationships") or {}
    structured = rel.get("structured_scopes") or {}
    raw_list = structured.get("data") if isinstance(structured, dict) else None

    items: list[dict[str, Any]] = []
    if isinstance(raw_list, list):
        for scope in raw_list:
            item = (scope.get("attributes") if isinstance(scope, dict) else None) or scope
            if isinstance(item, dict) and item.get("asset_identifier"):
                items.append(item)
    if not items:  # fall back to an embedded list when present
        embedded = (attrs.get("scope") or {}).get("list") if isinstance(attrs.get("scope"), dict) else attrs.get("scope")
        if isinstance(embedded, list):
            items = [i for i in embedded if isinstance(i, dict)]

    return {
        "name": attrs.get("name") or node.get("id") or handle,
        "attributes": {"scope": {"list": items}},
    }


def _bugcrowd_to_program(node: dict[str, Any], handle: str) -> dict[str, Any]:
    """Convert a Bugcrowd engagement resource into ``parse_bugcrowd_program`` input."""
    targets = node.get("targets") or {}
    in_scope: list[dict[str, Any]] = []
    out_of_scope: list[dict[str, Any]] = []
    if isinstance(targets, dict):
        for item in targets.get("in_scope") or []:
            if isinstance(item, dict):
                in_scope.append({"target": item.get("target") or item.get("name") or ""})
        for item in targets.get("out_of_scope") or []:
            if isinstance(item, dict):
                out_of_scope.append({"target": item.get("target") or item.get("name") or ""})
    return {
        "name": node.get("name") or handle,
        "targets": {"in_scope": in_scope, "out_of_scope": out_of_scope},
    }


def fetch_h1_program(
    handle: str,
    *,
    username: str,
    api_token: str,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Fetch one HackerOne program's published scope (HTTP basic auth)."""
    if not username or not api_token:
        raise ScopeProviderError("hackerone credentials are not configured")
    url = f"{H1_BASE}/{_handle(handle)}"
    resp = _get(session, url, auth=(username, api_token), headers={"Accept": "application/json"})
    return _h1_to_program(_jsonapi_node(_json(resp, "hackerone")), handle)


def fetch_bugcrowd_program(
    handle: str,
    *,
    api_key: str,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Fetch one Bugcrowd program's published scope (token auth)."""
    if not api_key:
        raise ScopeProviderError("bugcrowd credentials are not configured")
    url = f"{BUGCROWD_BASE}/{_handle(handle)}"
    resp = _get(session, url, headers={"Authorization": f"Token {api_key}", "Accept": "application/json"})
    return _bugcrowd_to_program(_jsonapi_node(_json(resp, "bugcrowd")), handle)


PROVIDERS: dict[str, Callable[..., dict[str, Any]]] = {
    "hackerone": fetch_h1_program,
    "bugcrowd": fetch_bugcrowd_program,
}


def fetch_program(
    platform: str,
    handle: str,
    *,
    env: dict[str, Any] | None = None,
    session: requests.Session | None = None,
    username_env: str = "",
    token_env: str = "",
) -> dict[str, Any]:
    """Fetch *handle*'s scope from *platform*, resolving creds from *env* names.

    ``env`` maps environment variable names to values (e.g.
    ``Config.env``). Credential *names* may be overridden per program.
    """
    env = env or {}
    platform = str(platform or "").strip().lower()
    names = DEFAULT_CRED_ENV.get(platform)
    if names is None:
        raise ScopeProviderError(f"unsupported platform: {platform!r}")
    if platform == "hackerone":
        user_name = username_env or names["username"]
        token_name = token_env or names["token"]
        return fetch_h1_program(
            handle,
            username=str(env.get(user_name, "") or ""),
            api_token=str(env.get(token_name, "") or ""),
            session=session,
        )
    token_name = token_env or names["token"]
    return fetch_bugcrowd_program(
        handle,
        api_key=str(env.get(token_name, "") or ""),
        session=session,
    )
