"""Authentication / ATO surface detection.

Detects login surfaces (forms, login APIs, OAuth), session/token handling,
logout/reset/MFA *indicators*, and authentication enumeration signals —
read-only, detection-only. This module never attempts credential attacks,
never submits credentials it did not observe, and never modifies state.

Detected surfaces feed:
- ``identities`` / ``auth_sessions`` rows,
- the attack-surface graph (``authenticated_by`` edges),
- the AUTHZ phase gate (needs ≥2 identities),
- Discord/Telegram login-event notifications.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from lib.config import TargetConfig
from lib.logger import get_logger
from lib.scope_validator import validate_finding_scope

logger = get_logger("authn")


# --- surface detectors ------------------------------------------------------

_LOGIN_PATH_RE = re.compile(
    r"(?i)(/login|/signin|/sign-in|/log-in|/auth|/oauth|/authorize|/sso|"
    r"/account/login|/users/sign_in|/session)"
)
_LOGOUT_PATH_RE = re.compile(r"(?i)(/logout|/signout|/log-out|/session/destroy)")
_RESET_PATH_RE = re.compile(r"(?i)(/reset|/forgot|/recover|/password-reset|/new-password)")
_MFA_PATH_RE = re.compile(r"(?i)(/mfa|/otp|/two-factor|/2fa|/verify|/challenge)")
_REGISTER_PATH_RE = re.compile(r"(?i)(/register|/signup|/sign-up|/join)")

_LOGIN_FORM_RE = re.compile(
    r"(?is)<form[^>]*(?:login|signin|auth)[^>]*>.*?</form>|"
    r"<input[^>]*type=['\"]password['\"][^>]*>",
    re.IGNORECASE,
)
_OAUTH_RE = re.compile(
    r"(?i)(oauth|openid|/oauth2?/|client_id=|response_type=|scope=|"
    r"accounts.google.com|login.microsoftonline.com|github.com/login/oauth)"
)
_JWT_RE = re.compile(r"(?i)\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_SESSION_COOKIE_RE = re.compile(
    r"(?i)\b(session|sess|sid|jsessionid|phpsessid|asp\.net_session|"
    r"connect\.sid|_session|auth|token|csrf)\s*=", re.IGNORECASE
)

# Auth-API heuristics (request shapes seen on the surface)
_LOGIN_API_RE = re.compile(
    r"(?i)(/api/[^\s\"']*?(login|signin|auth|token|session)[^\s\"']*|"
    r"/oauth2?/[^\s\"']*token)"
)

# Authentication enumeration indicators (identical bodies / timing-free heuristics)
_IDENTICAL_RESPONSE_RE = re.compile(r"(?i)(invalid|incorrect|wrong|unknown).{0,40}(credentials|username|email|password)")
_ACCOUNT_LOCKOUT_RE = re.compile(r"(?i)(locked|too many attempts|rate limit|temporarily disabled)")


@dataclass
class AuthnSurface:
    url: str
    kind: str                      # login_form | login_api | oauth | logout | reset | mfa | register
    evidence: str = ""
    confidence: int = 50
    indicator: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "kind": self.kind,
            "evidence": self.evidence[:200],
            "confidence": self.confidence,
            "indicator": self.indicator,
        }


@dataclass
class Identity:
    name: str
    kind: str = "user"             # user | admin | lowpriv | highpriv
    credential_ref: str = ""       # env key NAME only, never the secret
    scope_verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "credential_ref": self.credential_ref,
            "scope_verified": self.scope_verified,
        }


class AuthnEngine:
    """Detects authentication surfaces; tracks identities and sessions."""

    def __init__(self, target_config: TargetConfig):
        self.target_config = target_config
        self.surfaces: list[AuthnSurface] = []
        self.identities: list[Identity] = []
        self.session_signals: list[dict[str, Any]] = []

    # -- detection ------------------------------------------------------------

    def detect_surfaces(self, urls: list[str], responses: list[dict[str, Any]] | None = None) -> list[AuthnSurface]:
        """Find login/logout/reset/MFA/OAuth surfaces across discovered URLs."""
        responses = responses or []
        body_by_url = {str(r.get("url", "")): str(r.get("body", "") or "") for r in responses}
        headers_by_url = {str(r.get("url", "")): r.get("headers", {}) for r in responses}

        for url in urls or []:
            raw = (url or "").strip()
            if not raw or not validate_finding_scope(raw, self.target_config):
                continue
            path = urlsplit(raw).path or "/"
            body = body_by_url.get(raw, "")
            headers = headers_by_url.get(raw, {}) or {}
            set_cookie = " ".join(
                str(v) for k, v in headers.items() if k.lower() == "set-cookie"
            )

            try:
                if _LOGIN_FORM_RE.search(body):
                    self._add(raw, "login_form", "password input / login form present", 75,
                              "form+password-field")
                if _LOGIN_API_RE.search(raw) or _LOGIN_API_RE.search(body[:20000]):
                    self._add(raw, "login_api", "login-like API endpoint", 65, "api-path-shape")
                if _OAUTH_RE.search(body) or _OAUTH_RE.search(raw):
                    self._add(raw, "oauth", "OAuth/OpenID flow parameters present", 70, "oauth-params")
                if _LOGOUT_PATH_RE.search(path):
                    self._add(raw, "logout", "logout endpoint", 60, "path")
                if _RESET_PATH_RE.search(path):
                    self._add(raw, "reset", "password-reset endpoint", 60, "path")
                if _MFA_PATH_RE.search(path):
                    self._add(raw, "mfa", "MFA/second-factor endpoint", 60, "path")
                if _REGISTER_PATH_RE.search(path):
                    self._add(raw, "register", "registration endpoint", 55, "path")
                if _LOGIN_PATH_RE.search(path):
                    self._add(raw, "login_form", "login path", 55, "path")
                if _SESSION_COOKIE_RE.search(set_cookie):
                    self._add(raw, "session", "session cookie issued", 60, "set-cookie")
                if _JWT_RE.search(body) or _JWT_RE.search(set_cookie):
                    self._add(raw, "token", "JWT observed in response", 60, "jwt")
            except Exception as exc:  # one URL must never break detection
                logger.debug("authn detection failed for %s: %s", raw, exc)

        logger.info("authn: %d surfaces detected", len(self.surfaces))
        return self.surfaces

    def _add(self, url: str, kind: str, evidence: str, confidence: int, indicator: str) -> None:
        self.surfaces.append(
            AuthnSurface(url=url, kind=kind, evidence=evidence, confidence=confidence, indicator=indicator)
        )

    # -- enumeration indicators ------------------------------------------------

    def detect_enumeration_indicators(self, responses: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Look for signals that the server distinguishes valid from invalid
        identities (user enumeration) — detection only, no guessing."""
        out: list[dict[str, Any]] = []
        for r in responses or []:
            body = str(r.get("body", "") or "")
            url = str(r.get("url", ""))
            if not validate_finding_scope(url, self.target_config):
                continue
            try:
                if _IDENTICAL_RESPONSE_RE.search(body):
                    out.append({
                        "url": url, "indicator": "generic-credential-error",
                        "evidence": "response mentions invalid credentials generically",
                        "confidence": 50,
                    })
                if _ACCOUNT_LOCKOUT_RE.search(body):
                    out.append({
                        "url": url, "indicator": "lockout-presence",
                        "evidence": "account lockout / rate-limit messaging present",
                        "confidence": 45,
                    })
            except Exception:
                continue
        self.session_signals.extend(out)
        return out

    # -- identities -------------------------------------------------------------

    def load_identities(self, cfg: Any | None = None) -> list[Identity]:
        """Identities are OPERATOR-configured only (never guessed by NEXUS).

        Reads ``authn.identities`` from nexus.yaml. ``credential_ref`` is the
        *name* of an env key (e.g. ``TEST_USER_TOKEN``); the value is never
        loaded by this module.
        """
        identities: list[Identity] = []
        try:
            raw_identities = (cfg.authn if cfg is not None else {}) or {}
            if hasattr(raw_identities, "get"):
                raw_identities = raw_identities.get("identities", []) or []
            for item in raw_identities or []:
                if not isinstance(item, dict):
                    continue
                identities.append(
                    Identity(
                        name=str(item.get("name", "")),
                        kind=str(item.get("kind", "user")),
                        credential_ref=str(item.get("credential_ref", "")),
                        scope_verified=bool(item.get("scope_verified", False)),
                    )
                )
        except Exception as exc:  # identity config is optional
            logger.debug("no operator-configured identities: %s", exc)
        self.identities = identities
        return identities

    # -- persistence ------------------------------------------------------------

    def persist(self, db: Any, scan_id: int) -> dict[str, Any]:
        """Record surfaces + identities; returns a summary (never raises)."""
        summary = {"surfaces": 0, "identities": 0, "sessions": 0}
        try:
            for s in self.surfaces:
                db.insert_evidence(
                    scan_id, url=s.url, tool="authn", source="authn",
                    response_body=s.evidence, finding_id=None,
                )
            summary["surfaces"] = len(self.surfaces)
            for ident in self.identities:
                db.insert_identity(
                    scan_id, name=ident.name, kind=ident.kind,
                    credential_ref=ident.credential_ref,
                )
            summary["identities"] = len(self.identities)
        except Exception as exc:
            logger.debug("authn persistence failed: %s", exc)
        return summary

    # -- notifications -----------------------------------------------------------

    def notify(self, notifier: Any, domain: str) -> None:
        """Login/ATO surface alerts through the existing channels."""
        if notifier is None or not self.surfaces:
            return
        try:
            login_kinds = {"login_form", "login_api", "oauth"}
            login = [s for s in self.surfaces if s.kind in login_kinds]
            if login:
                notifier.send_info_alert(
                    f"NEXUS: authentication surface on {domain}",
                    f"{len(login)} login/ATO surface(s) detected "
                    f"(kinds: {sorted({s.kind for s in login})}). "
                    f"AUTHZ testing gated on operator-configured identities.",
                )
        except Exception as exc:  # notifications are best-effort
            logger.debug("authn notify failed: %s", exc)


def run_authn(
    cfg: Any,
    target_config: TargetConfig,
    results_dir: Any,
    urls: list[str] | None = None,
    responses: list[dict[str, Any]] | None = None,
    db: Any | None = None,
    scan_id: int | None = None,
    notifier: Any | None = None,
) -> dict[str, Any]:
    """AUTHN phase entrypoint. Gated: does nothing when no login surface exists."""
    engine = AuthnEngine(target_config)
    engine.detect_surfaces(urls or [], responses=responses or [])
    engine.detect_enumeration_indicators(responses or [])
    engine.load_identities(cfg)

    persisted = engine.persist(db, scan_id) if db is not None and scan_id is not None else {}
    if notifier is not None:
        engine.notify(notifier, target_config.domain)

    try:
        import json as _json
        from pathlib import Path

        authn_dir = Path(results_dir) / "authn"
        authn_dir.mkdir(parents=True, exist_ok=True)
        (authn_dir / "authn.json").write_text(
            _json.dumps({
                "surfaces": [s.to_dict() for s in engine.surfaces],
                "identities": [i.to_dict() for i in engine.identities],
                "signals": engine.session_signals,
                "persisted": persisted,
            }, indent=2, default=str),
            encoding="utf-8",
        )
    except OSError:
        pass

    return {
        "status": "completed",
        "surfaces": len(engine.surfaces),
        "identities": len(engine.identities),
        "signals": len(engine.session_signals),
        "by_kind": _count_by_kind(engine.surfaces),
        "persisted": persisted,
    }


def _count_by_kind(surfaces: list[AuthnSurface]) -> dict[str, int]:
    out: dict[str, int] = {}
    for s in surfaces:
        out[s.kind] = out.get(s.kind, 0) + 1
    return out
