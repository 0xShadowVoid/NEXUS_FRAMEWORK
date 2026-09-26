"""Unit tests for the scope validator (security boundary)."""
from __future__ import annotations

import pytest

from lib.config import TargetConfig
from lib.exceptions import ScopeException
from lib.scope_validator import (
    is_cloud_asset,
    validate_cloud_target,
    validate_finding_scope,
    validate_scan_targets,
    validate_target_scope,
)


def _tc(in_scope, out_of_scope=None) -> TargetConfig:
    return TargetConfig(
        domain="paypal.com",
        in_scope=list(in_scope),
        out_of_scope=list(out_of_scope or []),
    )


def test_single_domain_in_scope():
    tc = _tc(["paypal.com"])
    assert validate_target_scope("paypal.com", tc) is True
    assert validate_target_scope("https://paypal.com/login", tc) is True


def test_wildcard_matches_subdomains():
    tc = _tc(["paypal.com", "*.api.paypal.com"])
    assert validate_target_scope("a.api.paypal.com", tc) is True
    assert validate_target_scope("deep.sub.api.paypal.com", tc) is True
    assert validate_target_scope("api.paypal.com", tc) is True


def test_out_of_scope_blocked():
    tc = _tc(["paypal.com"], ["blog.paypal.com"])
    with pytest.raises(ScopeException):
        validate_target_scope("blog.paypal.com", tc)


def test_out_of_scope_overrides_in_scope():
    tc = _tc(["*.paypal.com"], ["admin.paypal.com"])
    assert validate_target_scope("api.paypal.com", tc) is True
    with pytest.raises(ScopeException):
        validate_target_scope("admin.paypal.com", tc)


def test_not_in_scope_raises():
    tc = _tc(["paypal.com"])
    with pytest.raises(ScopeException):
        validate_target_scope("evil.com", tc)


def test_finding_scope_never_raises():
    tc = _tc(["paypal.com"])
    assert validate_finding_scope("https://paypal.com/x", tc) is True
    assert validate_finding_scope("https://evil.com/x", tc) is False


def test_invalid_target_format_raises():
    tc = _tc(["paypal.com"])
    with pytest.raises(ScopeException):
        validate_target_scope("/just/a/path", tc)


def test_validate_scan_targets_aborts_on_oos():
    tc = _tc(["paypal.com"])
    assert validate_scan_targets(["paypal.com"], tc) == ["paypal.com"]
    with pytest.raises(ScopeException):
        validate_scan_targets(["paypal.com", "evil.com"], tc)


def test_cloud_asset_detection_and_validation():
    assert is_cloud_asset("arn:aws:s3:::my-bucket") is True
    assert is_cloud_asset("https://s3.amazonaws.com/x") is True
    assert is_cloud_asset("paypal.com") is False

    tc = _tc(["arn:aws:s3:::my-bucket"])
    assert validate_cloud_target("arn:aws:s3:::my-bucket", tc) is True
    # Cloud assets are never implicitly in scope via domain wildcards.
    tc2 = _tc(["*.paypal.com"])
    assert validate_cloud_target("arn:aws:s3:::someone-else", tc2) is False
