"""SSRF guard for NEXUS HTTP fetching.

Blocks requests to private, loopback, link-local and cloud-metadata
endpoints before any connection is opened. The framework fetches many URLs
that come from *recon output* (i.e. attacker-influenced data), so every
generic HTTP consumer must resolve the host and ask this module first.

Allowlist: ``SSRF_ALLOW`` env / ``scanning.ssrf_allow`` config may add
explicitly permitted hosts (e.g. an internal test box). Loopback is never
allowed for target-derived URLs, but the local Ollama/AI endpoints are
hard-exempted (they are configured by the operator, not by recon data).
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlsplit

from lib.logger import get_logger

logger = get_logger("ssrf_guard")

# Never reachable from target-derived URLs.
_BLOCKED_PREFIXES = (
    "169.254.169.254",       # AWS / GCP / Azure metadata
    "metadata.google.internal",
    "100.100.100.200",       # Alibaba metadata
    "metadata.azure.com",
)

# Operator-configured local endpoints (never derived from recon output).
_LOCAL_EXEMPT = {"localhost", "127.0.0.1", "::1", "ollama", "api.openai.com"}

_METADATA_PATHS = ("/latest/meta-data/", "/computeMetadata/v1/", "/metadata/instance")


def _env_allow() -> set[str]:
    """Operator-level allowlist from the ``SSRF_ALLOW`` env var (comma-separated)."""
    raw = os.environ.get("SSRF_ALLOW", "")
    return {h.strip().lower().rstrip(".") for h in raw.split(",") if h.strip()}


def _is_blocked_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unresolvable / weird → block
    if (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified):
        return True
    # IPv4-mapped IPv6 of a private address.
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return _is_blocked_ip(str(addr.ipv4_mapped))
    return False


def resolve_host(host: str) -> str:
    """Resolve a hostname to its first A/AAAA address ('' on failure)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError, UnicodeError):
        return ""
    for info in infos:
        addr = info[4][0]
        try:
            ipaddress.ip_address(addr)
            return addr
        except ValueError:
            continue
    return ""


def is_safe_url(url: str, allow: set[str] | None = None, local_ok: bool = False) -> tuple[bool, str]:
    """Validate *url* for outbound fetching. Returns (safe, reason).

    ``local_ok`` must be set only for operator-configured endpoints, never
    for URLs derived from scan/recon output.
    """
    raw = (url or "").strip()
    if not raw:
        return False, "empty url"
    try:
        parts = urlsplit(raw)
    except ValueError:
        return False, "unparseable url"
    scheme = (parts.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, f"scheme not allowed: {scheme or 'none'}"
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return False, "no host"

    # Explicit allowlist: caller-provided entries plus the operator
    # ``SSRF_ALLOW`` env var (comma-separated hostnames), as documented
    # at the top of this module.
    allow = set(allow or set()) | _env_allow()
    if host in allow:
        return True, "explicitly allowed"

    if local_ok and host in _LOCAL_EXEMPT:
        return True, "local endpoint (operator-configured)"

    # Metadata hostnames are always blocked.
    for bad in _BLOCKED_PREFIXES:
        if host == bad:
            return False, f"cloud metadata endpoint blocked: {host}"

    # Path-level metadata probes on any host are blocked.
    path = parts.path or ""
    if any(path.startswith(p) for p in _METADATA_PATHS):
        return False, "cloud metadata path blocked"

    # Resolve and check the IP (DNS rebinding defence: check the resolved IP,
    # not just the printed hostname).
    ip = resolve_host(host)
    if not ip:
        return False, f"unresolvable host: {host}"
    if not local_ok and _is_blocked_ip(ip):
        return False, f"private/loopback address blocked: {host} -> {ip}"
    return True, "ok"


def assert_safe_url(url: str, allow: set[str] | None = None, local_ok: bool = False) -> None:
    safe, reason = is_safe_url(url, allow=allow, local_ok=local_ok)
    if not safe:
        from lib.exceptions import NexusError

        raise NexusError(f"SSRF guard blocked {url!r}: {reason}")
