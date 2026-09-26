"""Property-style fuzzing of the security boundary (roadmap H3).

Randomised but deterministic (seeded). Asserts the boundary functions
never raise and always return well-typed results on adversarial input.
"""
from __future__ import annotations

import random
import string

from lib.config import TargetConfig
from lib.payload_guard import validate_payload, validate_tool_command
from lib.scope_validator import validate_finding_scope


def _rand_str(n: int) -> str:
    return "".join(random.choices(string.printable, k=n))


def test_fuzz_payloads_never_raise_and_typed():
    random.seed(42)
    for _ in range(800):
        payload = _rand_str(random.randint(0, 60))
        allowed, reason = validate_payload(payload)
        assert isinstance(allowed, bool)
        assert isinstance(reason, str)
        # Blocked payloads must be flagged by at least one detector when relevant.
        if not allowed:
            assert reason


def test_fuzz_tool_commands_never_raise():
    random.seed(7)
    for _ in range(400):
        cmd = [_rand_str(random.randint(1, 10)) for _ in range(random.randint(0, 5))]
        allowed, reason = validate_tool_command(cmd)
        assert isinstance(allowed, bool)
        assert isinstance(reason, str)


def test_fuzz_scope_never_raises():
    random.seed(13)
    tc = TargetConfig(domain="x.com", in_scope=["*.x.com"], out_of_scope=[])
    for _ in range(500):
        host = _rand_str(random.randint(1, 30)).replace(" ", "").replace("\\", "")
        result = validate_finding_scope(host, tc)
        assert isinstance(result, bool)


def test_known_bad_still_blocked_after_fuzz_seed():
    """Sanity: the blocklist still works independent of fuzz seeding."""
    assert validate_payload("'; DROP TABLE users;--")[0] is False
    assert validate_tool_command(["rm", "-rf", "/"])[0] is False
