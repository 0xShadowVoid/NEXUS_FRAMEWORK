"""Payload guard — NEXUS security boundary enforcement.

Validates payloads BEFORE they are sent to any tool runner. Destructive
SQL, reverse/bind shells, download-and-execute chains, filesystem
destruction and webshell planting are blocked. Detection payloads
(alert-boxes, time-based blind probes, error-based probes, traversal
probes) are allowed.

This module is enforcement code, not decoration: tool runners must call
:func:`validate_payload` (or :func:`assert_payload_allowed`) before
building any tool command line.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from lib.exceptions import PayloadGuardError
from lib.paths import REPO_ROOT

_PAYLOAD_GUARD_AUDIT = REPO_ROOT / "logs" / "payload_guard_audit.log"


def _audit_blocked(category: str, detail: str) -> None:
    """Append a masked record of a blocked payload/command (roadmap H4)."""
    try:
        _PAYLOAD_GUARD_AUDIT.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "category": category,
            "detail": (detail or "")[:200],
        }
        with _PAYLOAD_GUARD_AUDIT.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass


# --------------------------------------------------------------------------
# BLOCKED patterns
# --------------------------------------------------------------------------

_DESTRUCTIVE_SQL_RE = re.compile(
    r"(?is)\b(drop\s+(table|database|schema|index|view)|"
    r"truncate\s+(table\s+)?[\w.]+|"
    r"delete\s+from\s+[\w.\"'`\[\]]+|"
    r"update\s+[\w.\"'`\[\]]+\s+set\b|"
    r"insert\s+into\s+[\w.\"'`\[\]]+|"
    r"alter\s+(table|database|user)\b|"
    r"create\s+(table|database|user)\b|"
    r"grant\s+(all|select|insert|update|delete)\b|"
    r"revoke\b)"
)

_SHELL_PAYLOAD_RES = [
    # reverse / bind shells
    re.compile(r"(?i)\bnc(\.exe)?\s+(-e|-c)\b"),
    re.compile(r"(?i)\bn?cat\s+(-e|--exec)\b"),
    re.compile(r"(?i)bash\s+-i\s+.*>&"),
    re.compile(r"(?i)bash\s+-i\s+>&\s*/dev/tcp/"),
    re.compile(r"(?i)/dev/tcp/"),
    re.compile(r"(?i)mkfifo\b.*\b(nc|ncat|netcat)\b"),
    re.compile(r"(?i)\bsocat\b.*\bexec:?"),
    re.compile(r"(?i)powercat\b"),
    re.compile(r"(?i)msfvenom\b"),
    re.compile(r"(?i)\bmeterpreter\b"),
    # download-and-execute
    re.compile(r"(?i)\bwget\b[^|;&]*\|\s*(ba|z|)sh\b"),
    re.compile(r"(?i)\bcurl\b[^|;&]*\|\s*(ba|z|)sh\b"),
    re.compile(r"(?i)\bwget\b[^|;&]*\|\s*powershell\b"),
    re.compile(r"(?i)\bcurl\b[^|;&]*\|\s*powershell\b"),
    re.compile(r"(?i)\bcertutil\b.*\b-?urlcache\b.*\|"),
    re.compile(r"(?i)\bpowershell\b.*\s-(enc|encodedcommand|e)\b"),
    re.compile(r"(?i)\bpowershell\b.*\bdownloadstring\b"),
    re.compile(r"(?i)\biex(\s|\()'"),
    re.compile(r"(?i)\binvoke-expression\b"),
    # filesystem destruction
    re.compile(r"(?i)\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|--recursive)\b"),
    re.compile(r"(?i)\brmdir\s+/s\b"),
    re.compile(r"(?i)\bdel\s+(/[sq]\s+)+"),
    re.compile(r"(?i)\bformat\s+[a-z]:"),
    re.compile(r"(?i)\bshred\b"),
    re.compile(r"(?i)\bmkfs(\.\w+)?\b"),
    # webshell / backdoor planting
    re.compile(r"(?i)<\?php.*\b(system|exec|shell_exec|passthru|eval)\s*\("),
    re.compile(r"(?i)<%.*\b(Runtime\.getRuntime|ProcessBuilder)\b"),
    re.compile(r"(?i)\bc99\b.*\br57\b"),
    re.compile(r"(?i)\bwebshell\b"),
    re.compile(r"(?i)\bbackdoor\b"),
    re.compile(r"(?i)\bchmod\s+[0-7]*[67][0-7]{2}\b.*(\.sh|/tmp)"),
    re.compile(r"(?i)\bcrontab\b"),
    re.compile(r"(?i)\b(scheduled\s*tasks?|schtasks)\b.*\bcreate\b"),
]

# Patterns allowed for detection (documented, evaluated first).
_ALLOWED_DETECTION_HINTS = [
    re.compile(r"(?i)alert\(\s*\d+\s*\)"),
    re.compile(r"(?i)print\(\s*\d+\s*\)"),
    re.compile(r"(?i)confirm\(\s*\d+\s*\)"),
    re.compile(r"(?i)prompt\(\s*\d+\s*\)"),
    re.compile(r"(?i)dnslog|interact\.sh|oast\.pro|burpcollaborator"),
    re.compile(r"(?i)\bbenchmark\s*\(\s*\d+"),
    re.compile(r"(?i)\bsleep\s*\(\s*\d+\s*\)"),
    re.compile(r"(?i)\bpg_sleep\s*\(\s*\d+"),
    re.compile(r"(?i)\bwaitfor\s+delay\b"),
    re.compile(r"(?i)\$\(\s*sleep\s+\d+\s*\)"),
    re.compile(r"(?i)\{\{\s*\d+\s*[*x]\s*\d+\s*\}\}"),
    re.compile(r"(?i)<!--"),
]


def is_destructive_sql(payload: str) -> bool:
    """True when payload contains destructive/modifying SQL verbs."""
    return bool(_DESTRUCTIVE_SQL_RE.search(payload or ""))


def is_shell_payload(payload: str) -> bool:
    """True when payload attempts shell/implant/download-execute behavior."""
    return any(rx.search(payload or "") for rx in _SHELL_PAYLOAD_RES)


def _is_pure_detection(payload: str) -> bool:
    """Payload matches a known-detection pattern and contains no blocked verb."""
    if is_destructive_sql(payload) or is_shell_payload(payload):
        return False
    return any(rx.search(payload) for rx in _ALLOWED_DETECTION_HINTS)


def validate_payload(payload: str) -> tuple[bool, str]:
    """Validate a payload against the security boundary.

    Returns ``(allowed, reason)``. A short reason is returned even on
    success for logging.
    """
    p = payload or ""
    if not p.strip():
        return True, "empty payload"

    if is_destructive_sql(p):
        _audit_blocked("payload_sql", p)
        return False, "destructive SQL (drop/delete/update/insert/alter/create/grant/revoke/truncate)"

    if is_shell_payload(p):
        _audit_blocked("payload_shell", p)
        return False, "shell/implant/download-execute payload (reverse shell, wget|sh, encoded powershell, webshell, destructive fs)"

    return True, "detection payload within boundary"


def assert_payload_allowed(payload: str) -> None:
    """Raise :class:`PayloadGuardError` when *payload* violates the boundary."""
    allowed, reason = validate_payload(payload)
    if not allowed:
        raise PayloadGuardError(f"payload blocked by security boundary: {reason}")


def validate_tool_command(cmd: list[str]) -> tuple[bool, str]:
    """Validate a tool command line before execution.

    Blocks obviously harmful invocations (rm, del, format, mkfs, nc -e,
    curl|sh, wget|sh, encoded PowerShell) regardless of tool name, and
    interactive interpreters used as wrappers. Commands are lists —
    never strings — so the guard sees real argv semantics.
    """
    if not cmd:
        return False, "empty command"
    if isinstance(cmd, str):
        return False, "command must be a list, not a string"

    joined = " ".join(str(a) for a in cmd)

    # Block interpreters as command wrappers.
    if len(cmd) >= 2 and str(cmd[0]).lower() in ("bash", "sh", "zsh", "cmd.exe", "cmd", "powershell", "pwsh"):
        # Only whitelisted, generated detection PoCs may run via interpreter.
        if not str(cmd[1]).endswith(".nexus-poc.sh"):
            return False, "interpreter wrapper commands are blocked"
    if len(cmd) == 1 and str(cmd[0]).lower() in ("bash", "sh", "zsh", "cmd.exe", "cmd", "powershell", "pwsh"):
        return False, "interpreter wrapper commands are blocked"

    # Block file/host destructive binaries regardless of args.
    first = str(cmd[0]).lower()
    if first in ("rm", "del", "rmdir", "format", "mkfs", "shred", "fdisk", "dd"):
        return False, f"destructive binary not allowed: {first}"

    # Block netcat bind/reverse shells.
    if first in ("nc", "ncat", "netcat") and any(a.lower() in ("-e", "-c") for a in cmd[1:]):
        return False, "netcat exec mode blocked"

    joined_rx = re.compile(
        r"(?i)(\bwget\b[^|]*\|\s*(ba|z|)sh\b|\bcurl\b[^|]*\|\s*(ba|z|)sh\b"
        r"|\bpowershell\b.*\s-(enc|encodedcommand)\b)"
    )
    if joined_rx.search(joined):
        return False, "download-and-execute chain blocked"

    return True, "tool command within boundary"
