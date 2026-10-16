"""Centralized secret redaction for logs and error messages.

Single source of truth so every logger, notification provider and error
message scrubs credentials consistently instead of relying on one call
site. Covers the secret shapes this codebase actually handles:

- Discord webhook URLs (all discord hosts/subdomains) and their tokens;
- Telegram bot tokens (plain or embedded in ``/bot<token>/`` URLs);
- OpenAI/GitHub/Google/AWS/Slack API keys, JWTs and PEM private keys;
- ``Authorization: Bearer/Basic`` headers and other credential headers;
- query-string credentials (masked by parameter *name*, so percent-encoded
  values are removed too) and URL userinfo (``user:pass@host``).

``redact_text`` is safe to call on arbitrary text (log messages, exception
strings, HTTP errors). ``redact_url`` keeps the scheme and host for
diagnostics while dropping everything that can carry a secret.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

REDACTED = "***REDACTED***"

# -- secret value shapes (highest specificity first) -----------------------

_SIGNATURE_PATTERNS: list[re.Pattern[str]] = [
    # Discord webhook URLs (any subdomain, incl. canary./ptb.).
    re.compile(r"https?://(?:[\w-]+\.)*discord(?:app)?\.com/api/webhooks/\S+", re.IGNORECASE),
    # Telegram bot token, including the ``bot<token>`` URL form (the leading
    # verb is irrelevant, so no word boundary before the digits).
    re.compile(r"(?<!\d)\d{8,12}:[A-Za-z0-9_-]{30,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),                      # OpenAI-style
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),                 # GitHub
    re.compile(r"AKIA[0-9A-Z]{16}"),                           # AWS access key id
    re.compile(r"AIza[0-9A-Za-z_-]{30,}"),                     # Google API key
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),               # Slack
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),  # JWT
    re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        r"[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ),
]

# Authorization / credential headers.
_AUTH_RE = re.compile(r"(?i)\b(authorization\s*[:=]\s*)(?:bearer|basic|token)?\s*\S+")

# Names that mark a value as secret (JSON/YAML/query ``key=value`` pairs).
_SECRET_KEY_WORDS = (
    r"authorization|proxy-authorization|cookie|set-cookie|"
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"api[_-]?key|apikey|client[_-]?secret|secret|"
    r"password|passwd|passphrase|pwd|pass|"
    r"token|signature|session[_-]?id|sessionid|session|jwt|bearer|webhook|auth|key"
)
_KV_RE = re.compile(rf"(?i)\b({_SECRET_KEY_WORDS})\b(\s*[=:]\s*)(\S+)")

# A key name is "secret-looking" when it contains one of these tokens
# (used for dict keys and URL query parameter names).
SECRET_KEY_RE = re.compile(
    r"(token|secret|password|passwd|pwd|api[_-]?key|apikey|credential|"
    r"webhook|auth|cookie|session|signature|private)",
    re.IGNORECASE,
)
_SECRET_PARAM_RE = re.compile(rf"(?i)^({_SECRET_KEY_WORDS}|code)$")

# Bare http(s) URLs inside free text (stop before quotes/brackets/common prose).
_URL_RE = re.compile(r"https?://[^\s'\"<>()\[\]]+")
# Telegram ``/bot<id>`` path segment (token, or token in an exception that
# prints only the path).
_BOT_PATH_RE = re.compile(r"(?i)/bot\d")


def _is_secret_query(query: str) -> bool:
    for pair in query.split("&"):
        if not pair:
            continue
        name = pair.partition("=")[0]
        if _SECRET_PARAM_RE.search(name):
            return True
    return False


def redact_url(url: str) -> str:
    """Return *url* with credentials removed, keeping scheme+host for context.

    Drops the whole path/query/fragment when it may carry a secret (Discord
    webhook, Telegram ``/bot<token>``, secret query parameter, or userinfo);
    otherwise returns the URL unchanged after masking secret query values.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return REDACTED
    host = parts.hostname
    if not host:
        return redact_text(url)
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = host if port is None else f"{host}:{port}"
    path = parts.path or ""

    if parts.username is not None or "/api/webhooks/" in path or _BOT_PATH_RE.match(path):
        return f"{parts.scheme}://{netloc}/{REDACTED}"

    if parts.query and _is_secret_query(parts.query):
        tail = f"?{REDACTED}"
        if parts.fragment:
            tail += f"#{REDACTED}"
        return f"{parts.scheme}://{netloc}{path}{tail}"
    return url


def redact_text(value: Any) -> str:
    """Redact every recognizable secret from *value* (coerced to ``str``)."""
    out = value if isinstance(value, str) else str(value)
    if not out:
        return out
    for pattern in _SIGNATURE_PATTERNS:
        out = pattern.sub(REDACTED, out)
    out = _AUTH_RE.sub(lambda m: f"{m.group(1)}{REDACTED}", out)
    out = _URL_RE.sub(lambda m: redact_url(m.group(0)), out)
    out = _KV_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", out)
    return out


def redact(value: Any) -> Any:
    """Recursively redact secret-looking values from dicts/lists/strings."""
    if isinstance(value, dict):
        return {
            k: (REDACTED if SECRET_KEY_RE.search(str(k)) else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
