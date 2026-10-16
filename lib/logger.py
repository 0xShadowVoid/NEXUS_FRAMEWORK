"""Structured logging for NEXUS with secret redaction.

Console + rotating file output under ``logs/``. Every formatted record is
passed through :func:`lib.redaction.redact_text` so tokens, keys, webhook
URLs and query-string credentials never land in log files. The redaction
rules live in :mod:`lib.redaction` (single source of truth).

``redact`` and ``RedactingFormatter`` are kept here for backwards
compatibility; they delegate to the shared implementation.
"""
from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from lib.paths import LOGS_DIR
from lib.redaction import REDACTED as _REDACTED
from lib.redaction import SECRET_KEY_RE, redact, redact_text

_MAX_BYTES = 5 * 1024 * 1024   # 5 MB per file
_BACKUP_COUNT = 5              # keep 5 rotated files

_configured = False


class RedactingFormatter(logging.Formatter):
    """Log formatter that redacts secrets from the final message."""

    def format(self, record: logging.LogRecord) -> str:
        return redact_text(super().format(record))


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
