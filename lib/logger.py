"""Structured logging for NEXUS with secret redaction.

Console + rotating file output under ``logs/``. Values that look like
secrets (tokens, keys, passwords, webhook URLs) are redacted before
formatting so they never land in log files.
"""
from __future__ import annotations

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from lib.paths import LOGS_DIR

_MAX_BYTES = 5 * 1024 * 1024   # 5 MB per file
_BACKUP_COUNT = 5              # keep 5 rotated files

# Values for keys that look secret are masked in logs.
SECRET_KEY_RE = re.compile(r"(token|key|pass|secret|webhook|authorization)", re.IGNORECASE)
_REDACTED = "***REDACTED***"

# Webhook URLs are secrets themselves.
WEBHOOK_URL_RE_LOG = re.compile(r"https://(discord|discordapp)\.com/api/webhooks/\S+")
TELEGRAM_TOKEN_RE_LOG = re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b")

_configured = False


def redact(value: Any) -> Any:
    """Recursively redact secret-looking values from dicts/lists/strings."""
    if isinstance(value, dict):
        return {
            k: (_REDACTED if SECRET_KEY_RE.search(str(k)) else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        out = WEBHOOK_URL_RE_LOG.sub(_REDACTED, value)
        out = TELEGRAM_TOKEN_RE_LOG.sub(_REDACTED, out)
        return out
    return value


class RedactingFormatter(logging.Formatter):
    """Log formatter that redacts secrets from the final message."""

    _SENSITIVE_ARGS = ("token", "key", "pass", "secret", "webhook", "cookie", "authorization")

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        msg = WEBHOOK_URL_RE_LOG.sub(_REDACTED, msg)
        msg = TELEGRAM_TOKEN_RE_LOG.sub(_REDACTED, msg)
        # Redact key=value pairs for sensitive keys.
        for word in self._SENSITIVE_ARGS:
            msg = re.sub(
                rf"(?i)(\b{word}\s*[=:]\s*)(\S+)",
                lambda m: m.group(1) + _REDACTED,
                msg,
            )
        return msg


def setup_logging(level: int = logging.INFO, logs_dir: Path | None = None) -> None:
    """Configure root 'nexus' logger with console + rotating file handlers."""
    global _configured
    root = logging.getLogger("nexus")
    if _configured:
        root.setLevel(level)
        return

    logs = logs_dir or LOGS_DIR
    logs.mkdir(parents=True, exist_ok=True)

    fmt = RedactingFormatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console = logging.StreamHandler()
    console.setFormatter(fmt)

    file_handler = RotatingFileHandler(
        logs / "nexus.log", maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)

    root.setLevel(level)
    root.addHandler(console)
    root.addHandler(file_handler)
    root.propagate = False
    _configured = True


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """Return a namespaced logger under the 'nexus' root."""
    setup_logging(level=level)
    if not name.startswith("nexus."):
        name = f"nexus.{name}"
    return logging.getLogger(name)
