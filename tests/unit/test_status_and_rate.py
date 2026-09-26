"""Unit tests for status detection and rate limiting."""
from __future__ import annotations

import pytest

from lib.rate_limiter import RateLimiter, parse_rate
from lib.status_detector import (
    classify_status,
    has_error_keywords,
    is_heavy_tool_candidate,
)


def test_classify_auth_candidate_200():
    assert classify_status(200, "Please login to continue") == "auth_candidate_200"


def test_classify_plain_200():
    assert classify_status(200, "welcome to our shop") == "ok_plain_200"


def test_classify_bypass_candidates():
    assert classify_status(401) == "bypass_candidate_401_403"
    assert classify_status(403) == "bypass_candidate_401_403"


def test_classify_404_and_5xx():
    assert classify_status(404) == "not_found_404"
    assert classify_status(502) == "server_error_5xx"


def test_heavy_tool_gate():
    assert is_heavy_tool_candidate(200, "sign in with password") is True
    assert is_heavy_tool_candidate(403, "") is True
    assert is_heavy_tool_candidate(200, "nothing here") is False
    assert is_heavy_tool_candidate(404, "") is False


def test_error_keywords():
    assert has_error_keywords("SQL syntax error near ...") is True
    assert has_error_keywords("all good") is False


def test_parse_rate():
    assert parse_rate("50/minute") == (50, 60)
    assert parse_rate("10/second") == (10, 1)
    assert parse_rate("5/hour") == (5, 3600)


def test_parse_rate_invalid():
    with pytest.raises(ValueError):
        parse_rate("fast")
    with pytest.raises(ValueError):
        parse_rate("0/minute")


def test_rate_limiter_allows_within_limit():
    rl = RateLimiter()
    rl.configure("t", "100/minute")
    assert rl.acquire("t") == 0.0
    assert rl.try_acquire("t") is True


def test_rate_limiter_blocks_over_limit():
    rl = RateLimiter()
    rl.configure("k", "2/minute")
    assert rl.try_acquire("k") is True
    assert rl.try_acquire("k") is True
    assert rl.try_acquire("k") is False


def test_rate_limiter_unconfigured_is_unlimited():
    rl = RateLimiter()
    assert rl.acquire("unknown") == 0.0
