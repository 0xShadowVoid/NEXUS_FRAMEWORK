"""Vulnerability chain detection over dependency graphs.

Chains combine individual findings into higher-impact attack paths:
stored XSS on an admin surface → admin session hijack → RCE-like
impact; IDOR + write surface → account takeover; SQLi + auth bypass →
full database access; SSRF + internal service → internal access;
open redirect + OAuth flow → token theft.

Chain severity is escalated to at least the maximum member severity and
frequently one level higher (chain impact exceeds the sum of parts).
"""
from __future__ import annotations

from typing import Any

from lib.severity_scorer import severity_rank

_SEVERITY_ORDER = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}
_RANK_TO_SEVERITY = {v: k for k, v in _SEVERITY_ORDER.items()}

_ADMIN_SURFACE = ("admin", "administrator", "dashboard", "panel", "cms")
_WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
_AUTH_CONTEXT = ("login", "auth", "session", "signin", "password")
_INTERNAL_HINTS = ("internal", "127.0.0.1", "localhost", "169.254.169.254", "metadata")
_OAUTH_HINTS = ("oauth", "token", "callback", "redirect_uri", "authorization-code")


def _escalate(severities: list[str], extra: int = 1) -> str:
    """Escalate the worst member severity by *extra* levels (capped at P1)."""
    worst = min(severity_rank(s) for s in severities) if severities else 4
    return _RANK_TO_SEVERITY[max(1, worst - extra)]


def _finding_text(f: dict[str, Any]) -> str:
    return " ".join(
        str(f.get(k, "")).lower() for k in ("endpoint", "payload", "response_snippet", "notes", "title")
    )


class ChainDetector:
    """Detects vulnerability chains across a finding set."""

    def __init__(self, min_members: int = 1):
        self.min_members = min_members

    def detect(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return chain records built from *findings*.

        Each chain: {chain_type, finding_ids, steps, combined_severity,
        impact, members: [endpoint...]}.
        """
        chains: list[dict[str, Any]] = []
        if len(findings) < self.min_members:
            return chains

        by_type = self._group_by_type(findings)
        used: set[int] = set()

        chains.extend(self._xss_to_rce(by_type, findings, used))
        chains.extend(self._idor_to_ato(by_type, findings, used))
        chains.extend(self._sqli_to_db(by_type, findings, used))
        chains.extend(self._ssrf_to_internal(by_type, findings, used))
        chains.extend(self._redirect_to_token_theft(by_type, findings, used))
        return chains

    # -- grouping ----------------------------------------------------------

    @staticmethod
    def _group_by_type(findings: list[dict[str, Any]]) -> dict[str, list[int]]:
        groups: dict[str, list[int]] = {}
        for idx, f in enumerate(findings):
            vt = str(f.get("vuln_type", "")).lower()
            if "stored" in vt and "xss" in vt:
                groups.setdefault("stored_xss", []).append(idx)
            elif "xss" in vt:
                groups.setdefault("xss", []).append(idx)
            elif "sqli" in vt:
                groups.setdefault("sqli", []).append(idx)
            elif "idor" in vt or "bola" in vt:
                groups.setdefault("idor", []).append(idx)
            elif "ssrf" in vt:
                groups.setdefault("ssrf", []).append(idx)
            elif "redirect" in vt:
                groups.setdefault("redirect", []).append(idx)
            elif "auth" in vt and "bypass" in vt:
                groups.setdefault("auth_bypass", []).append(idx)
            elif "rce" in vt or "command_injection" in vt:
                groups.setdefault("rce", []).append(idx)
        return groups

    # -- chain rules -------------------------------------------------------

    def _build(self, chain_type: str, members: list[dict[str, Any]], impact: str, escalate: int = 1) -> dict[str, Any]:
        severities = [str(m.get("severity", "P4")) for m in members]
        steps = [
            f"{i}. {m.get('vuln_type')} at {m.get('endpoint')} ({m.get('severity')})"
            for i, m in enumerate(members, start=1)
        ]
        return {
            "chain_type": chain_type,
            "finding_ids": [m.get("id") for m in members],
            "steps": steps,
            "combined_severity": _escalate(severities, escalate),
            "impact": impact,
            "members": [m.get("endpoint") for m in members],
        }

    def _xss_to_rce(self, by_type, findings, used) -> list[dict[str, Any]]:
        out = []
        for idx in by_type.get("stored_xss", []):
            f = findings[idx]
            text = _finding_text(f)
            if any(s in text for s in _ADMIN_SURFACE):
                out.append(self._build(
                    "xss_to_rce",
                    [f],
                    "Stored XSS on an admin surface enables session hijack of "
                    "administrators; admin actions can achieve code execution "
                    "or equivalent system compromise.",
                    escalate=2,
                ))
                used.add(idx)
        return out

    def _idor_to_ato(self, by_type, findings, used) -> list[dict[str, Any]]:
        out = []
        for idx in by_type.get("idor", []):
            f = findings[idx]
            text = _finding_text(f)
            method = str(f.get("method", "GET")).upper()
            write_surface = method in _WRITE_METHODS or any(
                w in text for w in ("update", "edit", "profile", "password", "email")
            )
            if write_surface:
                out.append(self._build(
                    "idor_to_ato",
                    [f],
                    "IDOR on a write endpoint allows modifying other users' data "
                    "(email/password), enabling full account takeover.",
                    escalate=1,
                ))
                used.add(idx)
        return out

    def _sqli_to_db(self, by_type, findings, used) -> list[dict[str, Any]]:
        out = []
        sqli_idxs = by_type.get("sqli", [])
        auth_bypass_idxs = by_type.get("auth_bypass", [])
        # SQLi alone with auth context → full DB access path.
        for idx in sqli_idxs:
            f = findings[idx]
            if any(k in _finding_text(f) for k in _AUTH_CONTEXT):
                out.append(self._build(
                    "sqli_to_db_access",
                    [f],
                    "SQL injection on an authentication surface enables auth "
                    "bypass and full database access.",
                    escalate=0,
                ))
                used.add(idx)
        # SQLi + separate auth bypass finding → combined chain.
        if sqli_idxs and auth_bypass_idxs:
            members = [findings[sqli_idxs[0]], findings[auth_bypass_idxs[0]]]
            out.append(self._build(
                "sqli_to_db_access",
                members,
                "SQL injection combined with authentication bypass yields "
                "unauthenticated full database access.",
                escalate=0,
            ))
        return out

    def _ssrf_to_internal(self, by_type, findings, used) -> list[dict[str, Any]]:
        out = []
        for idx in by_type.get("ssrf", []):
            f = findings[idx]
            if any(h in _finding_text(f) for h in _INTERNAL_HINTS):
                out.append(self._build(
                    "ssrf_to_internal",
                    [f],
                    "SSRF reaches internal services/metadata endpoints, "
                    "enabling internal network access and credential theft "
                    "from cloud metadata.",
                    escalate=1,
                ))
                used.add(idx)
        return out

    def _redirect_to_token_theft(self, by_type, findings, used) -> list[dict[str, Any]]:
        out = []
        for idx in by_type.get("redirect", []):
            f = findings[idx]
            if any(h in _finding_text(f) for h in _OAUTH_HINTS):
                out.append(self._build(
                    "redirect_to_token_theft",
                    [f],
                    "Open redirect within an OAuth/token flow enables "
                    "authorization-code or token theft.",
                    escalate=2,
                ))
                used.add(idx)
        return out


def detect_chains(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Functional wrapper around :class:`ChainDetector`."""
    return ChainDetector().detect(findings)
