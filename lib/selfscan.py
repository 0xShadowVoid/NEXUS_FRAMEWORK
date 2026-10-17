"""Self secret-scan (roadmap H1).

Scans the repository tree for accidentally committed secrets before you
push. Pure-regex, offline, no dependencies. Test fixtures and example
files are allowlisted by default so the framework's own suite stays clean.
"""
from __future__ import annotations

import re
from pathlib import Path

from lib.logger import get_logger

logger = get_logger("selfscan")

SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("discord_webhook", re.compile(r"https://(?:discord|discordapp)\.com/api/webhooks/\d+/[\w.-]{10,}")),
    ("telegram_bot_token", re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("generic_bearer", re.compile(r"(?i)\bauthorization:\s*bearer\s+[A-Za-z0-9._~+/=-]{20,}")),
]

# Paths never scanned (fixtures/examples legitimately contain fake markers).
ALLOWLIST_PARTS = {"__pycache__", ".git", ".pytest_cache", "node_modules", ".venv", "venv"}
ALLOWLIST_NAME_HINTS = ("example", "sample", "placeholder", "template")
ALLOWLIST_DIRS = {"tests", "test", "fixtures"}
MAX_FILE_BYTES = 2 * 1024 * 1024   # skip very large/binary-ish files
MAX_LINE_CHARS = 2000              # skip absurdly long (often minified/binary) lines
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".7z", ".db", ".pyc"}


def is_allowlisted(path: Path, root: Path) -> bool:
    """True when *path* is a fixture/example the tree scan skips by policy."""
    rel = path.relative_to(root)
    parts = {p.lower() for p in rel.parts}
    if parts & {p.lower() for p in ALLOWLIST_PARTS}:
        return True
    if parts & {p.lower() for p in ALLOWLIST_DIRS}:
        return True
    name = path.name.lower()
    return any(hint in name for hint in ALLOWLIST_NAME_HINTS)


# Backwards-compatible alias (older callers/tests used the private name).
_is_allowlisted = is_allowlisted


def scan_text(text: str, *, path: str = "") -> list[dict]:
    """Scan one text blob and return masked findings.

    Shared by the working-tree scan (``scan_tree``), the staged-index scan and
    the history scan (``lib.secretscan``). Findings never contain a raw secret:
    the *detail* is always masked by :func:`_mask`.
    """
    findings: list[dict] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > MAX_LINE_CHARS:
            continue
        for kind, pattern in SIGNATURES:
            if pattern.search(line):
                findings.append({
                    "file": path,
                    "line": lineno,
                    "kind": kind,
                    "detail": _mask(line.strip()[:120]),
                })
    return findings


def scan_tree(root: Path, include_allowlisted: bool = False) -> list[dict]:
    """Scan *root* for secret-like strings; returns findings."""
    root = Path(root)
    findings: list[dict] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.name == ".keys.env":
            findings.append({"file": str(path), "line": 0, "kind": "keys_file_present",
                             "detail": ".keys.env exists on disk (must stay git-ignored)"})
        if not include_allowlisted and is_allowlisted(path, root):
            continue
        if path.suffix.lower() in BINARY_SUFFIXES:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(scan_text(text, path=str(path)))
    logger.info("self-scan: %d potential secret(s)", len(findings))
    return findings


def _mask(text: str) -> str:
    """Mask the tail of a suspicious line for safe reporting."""
    if len(text) <= 16:
        return "*" * len(text)
    return text[:12] + "…" + "*" * 6
