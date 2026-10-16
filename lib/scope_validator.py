"""Scope validation — NEXUS security boundary enforcement.

Blocks out-of-scope targets before scanning starts, before any handoff to an
external tool, and flags out-of-scope findings (marked ``OUT_OF_SCOPE`` and
excluded from submissions, alerts, and chains).

Scope semantics (authoritative — do not broaden implicitly):

- **Exact host** — ``in_scope: [example.com]`` authorizes ``example.com`` only.
  Subdomains are **not** implied; ``a.example.com`` is out of scope.
- **Subdomains / wildcard** — ``*.example.com`` authorizes ``example.com`` and
  every strict subdomain (``a.example.com``, ``x.y.example.com``) but never
  ``example.com.attacker.test`` (a deceptive suffix) or ``evilexample.com``.
- **Ports** — ports are ignored for host matching; a host is authorized (or
  not) regardless of port. Restrict ports separately via the network phase.
- **IP literals** — an IP target is in scope only when an explicit ``in_scope``
  entry equals it or is a CIDR network containing it (e.g. ``10.0.0.0/24``).
  ``out_of_scope`` CIDRs always win. Unlisted IPs are out of scope (fail
  closed). Private/loopback/metadata addresses additionally require the network
  phase's explicit grants via :func:`ip_allowed_for_target`.
- **Malformed input** — empty/space-bearing/backslash/userinfo-only or
  otherwise unparseable targets are rejected (fail closed), never treated as a
  match.
- **Redirects** — handled on the HTTP path by the SSRF guard, which re-checks
  every hop (:mod:`lib.ssrf_guard`).

Explicit ``out_of_scope`` entries always override ``in_scope`` entries.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from urllib.parse import urlsplit

from lib.config import TargetConfig
from lib.exceptions import ScopeException
from lib.logger import get_logger

logger = get_logger("scope")

_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$", re.IGNORECASE)
# Permissive-but-bounded character set for a cleaned host token (hostnames,
# IPv4, and IPv6 hex/colon forms). Anything else is rejected as malformed.
_HOST_CHARS_RE = re.compile(r"^[A-Za-z0-9._:-]+$")

# Cloud asset patterns (validated only when scope explicitly covers them).
_S3_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", re.IGNORECASE)
_CLOUD_ARNG_RE = re.compile(r"^(arn:aws|arn:azure|arn:gcp):", re.IGNORECASE)
_CLOUD_PREFIX_RE = re.compile(
    r"^(s3:::|https?://s3\.|https?://[a-z0-9-]+\.blob\.core\.windows\.net/)",
    re.IGNORECASE,
)

CLOUD_SCHEME_PREFIXES = ("s3:::", "arn:", "azure::", "gcp::", "cloud:")


def _clean_host(host: str) -> str:
    """Normalize a host token; return "" when it is malformed / unparseable."""
    h = (host or "").strip().lower()
    if not h:
        return ""
    # Strip IPv6 brackets if present.
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    # Split off userinfo (bare ``user@host`` form; urlsplit handles URLs).
    if "@" in h:
        h = h.rsplit("@", 1)[1]
    # Drop a single ``:port`` suffix for non-IPv6 forms.
    if h.count(":") == 1:
        name, port = h.rsplit(":", 1)
        if port.isdigit():
            h = name
    # Root FQDN trailing dot is not significant.
    h = h.rstrip(".")
    if not h or not _HOST_CHARS_RE.match(h):
        return ""
    return h


def extract_host(endpoint_or_host: str) -> str:
    """Extract a comparable host from a URL, host, or bare endpoint string.

    Returns "" for malformed input (empty, embedded whitespace/control chars,
    backslashes, bare paths, userinfo-only strings, …) so callers fail closed.
    """
    raw = (endpoint_or_host or "").strip()
    if not raw:
        return ""
    # Hosts/URLs never contain whitespace or control characters; rejecting
    # them defeats "example.com /evil" style parser-confusion tricks.
    if any(c.isspace() or ord(c) < 0x20 for c in raw):
        return ""
    if "\\" in raw:
        return ""
    if "://" in raw:
        try:
            parts = urlsplit(raw)
        except ValueError:
            return ""
        return _clean_host(parts.hostname or "")
    # Bare path like "/api/users" has no host.
    if raw.startswith("/"):
        return ""
    # Strip query/fragment, take the authority component.
    candidate = re.split(r"[/?#]", raw, maxsplit=1)[0]
    return _clean_host(candidate)


# Backwards-compatible private alias (older callers/tests may reference it).
_extract_host = extract_host


def _matches_scope_entry(host: str, entry: str) -> bool:
    """Check whether *host* matches a single scope entry (wildcard-aware).

    Wildcards are anchored: ``*.example.com`` requires a literal ``.`` boundary
    so ``example.com.attacker.test`` and ``evilexample.com`` never match.
    """
    entry = (entry or "").strip().lower().rstrip(".")
    if not entry:
        return False
    if entry.startswith("*."):
        suffix = entry[2:]
        if not suffix:
            return False
        # *.example.com matches x.example.com AND example.com itself.
        return host.endswith("." + suffix) or host == suffix
    if "*" in entry or "?" in entry:
        return fnmatch.fnmatch(host, entry)
    return host == entry


def _entry_as_network(entry: str):
    """Return an ``ip_network`` for a CIDR/bare-IP entry, else None."""
    e = (entry or "").strip()
    if not e or "/" not in e and _canonical_ip(e) is None:
        return None
    try:
        return ipaddress.ip_network(e, strict=False)
    except ValueError:
        return None


def _host_denied_by_entries(host: str, entries: list[str]) -> bool:
    """True when *host* is matched by any deny (out-of-scope) entry."""
    ip = _canonical_ip(host)
    for entry in entries or []:
        e = (entry or "").strip()
        if not e:
            continue
        if _matches_scope_entry(host, e):
            return True
        if ip is not None:
            net = _entry_as_network(e)
            if net is not None and ip in net:
                return True
    return False


def _ip_literal_granted(host: str, entries: list[str]) -> bool:
    """True when an explicit in-scope entry covers the IP *host*."""
    ip = _canonical_ip(host)
    if ip is None:
        return False
    for entry in entries or []:
        e = (entry or "").strip()
        if not e:
            continue
        if _matches_scope_entry(host, e):
            return True
        net = _entry_as_network(e)
        if net is not None and ip in net:
            return True
    return False


def host_in_scope(host: str, target_config: TargetConfig) -> bool:
    """Return True when *host* is inside the configured scope (no raise).

    Accepts either a bare host or a full URL (the host is extracted first).
    Implements the documented semantics: out-of-scope wins; exact host only
    (no implicit subdomains); ``*.`` wildcards anchored; IP literals require an
    explicit exact/CIDR grant; malformed hosts are out of scope.
    """
    h = extract_host(host)
    if not h:
        return False

    if _host_denied_by_entries(h, list(target_config.out_of_scope)):
        return False

    if _canonical_ip(h) is not None:
        return _ip_literal_granted(h, list(target_config.in_scope))

    in_sc = list(target_config.in_scope) or [str(target_config.domain or "").lower()]
    return any(_matches_scope_entry(h, e) for e in in_sc)


def validate_target_scope(target: str, target_config: TargetConfig) -> bool:
    """Return True when *target* is inside the configured scope.

    Raises :class:`ScopeException` when the target is out of scope or
    malformed — callers must call this BEFORE any scan activity or external
    tool handoff.
    """
    host = extract_host(target)
    if not host:
        raise ScopeException(f"invalid target format: {target!r}")
    if host_in_scope(host, target_config):
        return True
    if _host_denied_by_entries(host, list(target_config.out_of_scope)):
        raise ScopeException(f"{target} is explicitly out of scope")
    raise ScopeException(
        f"{target} is out of scope (not matched by any in-scope entry)"
    )


def filter_targets(
    targets: list[str] | None,
    target_config: TargetConfig,
    *,
    context: str = "",
) -> list[str]:
    """Return only the in-scope targets, logging what was dropped (audit).

    Used at every external-tool handoff so OOS/malformed URLs discovered by
    recon never reach a third-party binary. Logs host names only (never full
    URLs) to avoid leaking query-string secrets.
    """
    kept: list[str] = []
    dropped: list[str] = []
    for t in targets or []:
        host = extract_host(t)
        if host and host_in_scope(host, target_config):
            kept.append(t)
        else:
            dropped.append(host or "<malformed>")
    if dropped:
        sample = ", ".join(sorted(set(dropped))[:5])
        logger.info(
            "scope: dropped %d out-of-scope target(s)%s: %s",
            len(dropped), f" during {context}" if context else "", sample,
        )
    return kept


def iter_handoff_targets(args: list[str] | None):
    """Yield URL-looking tokens from a tool argument vector (defense in depth).

    Only unambiguous ``scheme://...`` tokens are considered so flag values and
    file paths are never mistaken for targets. Bare-host handoffs are covered
    by the explicit ``targets=`` passed at each call site.
    """
    for a in args or []:
        s = str(a)
        if "://" in s:
            yield s


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


# ---------------------------------------------------------------------------
# Pass 5 — IP / CIDR authorization helpers (network phase scope gate)
# ---------------------------------------------------------------------------

_METADATA_ADDRESSES = frozenset({"169.254.169.254", "fd00:ec2::254"})
_FORBIDDEN_IP_CLASSES = frozenset({"private", "loopback", "link_local", "metadata"})


def _canonical_ip(value: str):
    """Parse an IP, normalizing IPv4-mapped IPv6 to IPv4. None if invalid."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if ip.version == 6 and getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return ip


def is_ip_literal(value: str) -> bool:
    return _canonical_ip(str(value).split("/")[0]) is not None


def classify_ip(value: str) -> str:
    """public|private|loopback|link_local|metadata|multicast|reserved|unspecified|invalid."""
    ip = _canonical_ip(str(value).split("/")[0])
    if ip is None:
        return "invalid"
    if str(ip) in _METADATA_ADDRESSES:
        return "metadata"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_private:
        return "private"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_reserved:
        return "reserved"
    return "public"


def explicit_ip_grant(value: str, target_config: TargetConfig) -> str:
    """Return the in-scope ip/CIDR entry covering *value* ("" if none)."""
    ip = _canonical_ip(str(value).split("/")[0])
    if ip is None:
        return ""
    for entry in target_config.in_scope:
        e = (entry or "").strip()
        if not e:
            continue
        try:
            network = ipaddress.ip_network(e, strict=False)
        except ValueError:
            continue
        if ip in network:
            return e
    return ""


def ip_allowed_for_target(
    ip_value: str,
    target_config: TargetConfig,
    *,
    allow_private: bool = False,
    require_grant: bool = False,
) -> tuple[bool, str]:
    """Engagement-policy gate for one target IP (explicit authorization only).

    - loopback / link-local / private / metadata addresses require an EXPLICIT
      in-scope ip/CIDR grant AND ``allow_private`` (two-key authorization);
    - IP-literal targets additionally require a grant (``require_grant``);
    - multicast / reserved / unspecified are never scannable;
    - explicit out-of-scope networks always win.
    """
    ip = _canonical_ip(str(ip_value).split("/")[0])
    if ip is None:
        return False, "not an IP address"
    for entry in target_config.out_of_scope:
        e = (entry or "").strip()
        if not e:
            continue
        try:
            if ip in ipaddress.ip_network(e, strict=False):
                return False, f"explicitly out of scope ({e})"
        except ValueError:
            continue
    category = classify_ip(str(ip))
    grant = explicit_ip_grant(str(ip), target_config)
    if category in _FORBIDDEN_IP_CLASSES:
        if not (grant and allow_private):
            return False, (
                f"{category} address requires an explicit in-scope ip/CIDR grant "
                "plus allow_private"
            )
        return True, f"explicitly authorized ({grant})"
    if category in ("multicast", "reserved", "unspecified"):
        return False, f"{category} address is not scannable"
    if require_grant and not grant:
        return False, "IP-literal target requires an explicit in-scope ip/CIDR entry"
    return True, f"explicitly authorized ({grant})" if grant else "public address of in-scope host"
