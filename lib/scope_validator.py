"""Scope validation — NEXUS security boundary enforcement.

Blocks out-of-scope targets before scanning starts and out-of-scope
findings before they reach reports or submissions. Wildcard entries
(``*.api.paypal.com``) are supported; explicit out-of-scope entries
always override in-scope entries.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from urllib.parse import urlparse

from lib.config import TargetConfig
from lib.exceptions import ScopeException

_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$", re.IGNORECASE)

# Cloud asset patterns (validated only when scope explicitly covers them).
_S3_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", re.IGNORECASE)
_CLOUD_ARNG_RE = re.compile(r"^(arn:aws|arn:azure|arn:gcp):", re.IGNORECASE)
_CLOUD_PREFIX_RE = re.compile(
    r"^(s3:::|https?://s3\.|https?://[a-z0-9-]+\.blob\.core\.windows\.net/)",
    re.IGNORECASE,
)

CLOUD_SCHEME_PREFIXES = ("s3:::", "arn:", "azure::", "gcp::", "cloud:")


def _extract_host(endpoint_or_host: str) -> str:
    """Extract a comparable host from a URL, host, or bare endpoint string."""
    raw = (endpoint_or_host or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        return (urlparse(raw).hostname or "").lower()
    # Bare path like "/api/users" has no host.
    if raw.startswith("/"):
        return ""
    # host:port without scheme
    candidate = raw.split("/")[0]
    if ":" in candidate:
        host, port = candidate.rsplit(":", 1)
        if port.isdigit():
            candidate = host
    return candidate.lower()


def _matches_scope_entry(host: str, entry: str) -> bool:
    """Check whether *host* matches a single scope entry (wildcard-aware)."""
    entry = (entry or "").strip().lower()
    if not entry:
        return False
    if entry.startswith("*."):
        # *.api.paypal.com matches x.api.paypal.com AND api.paypal.com itself
        suffix = entry[2:]
        return host.endswith("." + suffix) or host == suffix
    if "*" in entry or "?" in entry:
        return fnmatch.fnmatch(host, entry)
    return host == entry


def validate_target_scope(target: str, target_config: TargetConfig) -> bool:
    """Return True when *target* is inside the configured scope.

    Raises :class:`ScopeException` when the target is out of scope —
    callers must call this BEFORE any scan activity.
    """
    host = _extract_host(target)
    if not host:
        raise ScopeException(f"invalid target format: {target!r}")

    oos = [e for e in target_config.out_of_scope]
    for entry in oos:
        if _matches_scope_entry(host, entry):
            raise ScopeException(
                f"{target} is explicitly out of scope (matched OOS entry {entry!r})"
            )

    in_sc = list(target_config.in_scope) or [target_config.domain.lower()]
    for entry in in_sc:
        if _matches_scope_entry(host, entry):
            return True

    raise ScopeException(
        f"{target} is out of scope (not matched by any in-scope entry)"
    )


def validate_finding_scope(endpoint_or_host: str, target_config: TargetConfig) -> bool:
    """Return True when a finding's endpoint/host is in scope.

    Never raises for OOS — returns False so findings can be marked
    OUT_OF_SCOPE instead of submitted.
    """
    try:
        return validate_target_scope(endpoint_or_host, target_config)
    except ScopeException:
        return False


def is_cloud_asset(value: str) -> bool:
    """Heuristic: does *value* look like a cloud resource identifier?"""
    v = (value or "").strip()
    if not v:
        return False
    if _CLOUD_ARNG_RE.match(v):
        return True
    if v.lower().startswith(CLOUD_SCHEME_PREFIXES):
        return True
    if _CLOUD_PREFIX_RE.match(v):
        return True
    return False


def validate_cloud_target(value: str, target_config: TargetConfig) -> bool:
    """Cloud targets are scannable only when scope explicitly covers them.

    An explicit in-scope entry must name the asset/prefix (e.g.
    ``s3:::example-bucket`` or ``cloud:aws``) — cloud assets are never
    implicitly in scope via domain wildcards.
    """
    if not is_cloud_asset(value):
        return False
    v = value.strip().lower()
    for entry in target_config.in_scope:
        e = (entry or "").strip().lower()
        if not e:
            continue
        if v == e or v.startswith(e + "/") or e == v.split("/", 1)[0]:
            return True
        if fnmatch.fnmatch(v, e):
            return True
    return False


def validate_scan_targets(targets: list[str], target_config: TargetConfig) -> list[str]:
    """Validate a batch of targets, returning only the in-scope ones.

    Raises ScopeException on the first OOS target so the caller can
    abort before any traffic is sent.
    """
    validated: list[str] = []
    for t in targets:
        validate_target_scope(t, target_config)
        validated.append(t)
    return validated
