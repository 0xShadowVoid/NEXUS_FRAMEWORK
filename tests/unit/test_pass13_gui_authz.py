"""GUI authorization / scope-boundary regression tests (Pass 13).

Verified properties:
- the GUI authorization boundary comes **only** from the configured
  ``targets:`` scope — a request can never authorize itself;
- authorized targets are accepted and reach the scanner;
- unauthorized targets are rejected and never reach the scanner / HTTP client
  / external-tool executor;
- missing, empty or malformed scope configuration fails closed;
- wildcard, exact-host, IP/CIDR and ``out_of_scope`` semantics follow the
  shared validator;
- every scan-triggering route enforces the boundary, and authentication
  failure stays distinct from scope failure.

All targets are config-local fixtures; no public host is ever contacted.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
import requests
import yaml
from fastapi.testclient import TestClient

import core.gui as gui
from core.gui import app
from lib.config import load_config
from lib.exceptions import ConfigError

USER = "operator"
PASS = "s3cret-pass!"

CLIENT = TestClient(app)

# FastAPI's built-in documentation routes are not part of the NEXUS surface.
_DOC_PATHS = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}


# -- fixtures / helpers ----------------------------------------------------


def _write_cfg(tmp_path: Path, targets: dict) -> Path:
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    (cfg_dir / "nexus.yaml").write_text(
        yaml.safe_dump({"targets": targets}, sort_keys=False), encoding="utf-8"
    )
    (cfg_dir / "false_positive_filters.yaml").write_text("filters: {}\n", encoding="utf-8")
    return cfg_dir


def _use_config(monkeypatch, cfg_dir: Path) -> None:
    monkeypatch.setattr(gui, "load_config", lambda: load_config(cfg_dir))


def _install_coordinator(monkeypatch) -> list:
    """Replace the Coordinator with a recorder; returns created instances."""
    created: list = []

    class FakeCoordinator:
        def __init__(self, cfg):
            self.cfg = cfg
            self.scans: list = []
            created.append(self)

        def run_scan(self, options):
            self.scans.append(options)
            return {"target": options.target, "phases": {"discover": "ok"}, "findings_total": 0}

    monkeypatch.setattr(gui, "Coordinator", FakeCoordinator)
    return created


def _forbid_network_and_subprocess(monkeypatch) -> None:
    def _boom(*_a, **_k):
        raise AssertionError("network/subprocess access attempted for a rejected request")

    monkeypatch.setattr(requests.sessions.Session, "request", _boom)
    monkeypatch.setattr(subprocess, "Popen", _boom)
    monkeypatch.setattr(subprocess, "run", _boom)


@pytest.fixture
def creds(monkeypatch):
    monkeypatch.setenv("NEXUS_GUI_USER", USER)
    monkeypatch.setenv("NEXUS_GUI_PASS", PASS)
    return (USER, PASS)


# -- trusted scope source --------------------------------------------------


def test_trusted_scope_is_config_only(tmp_path):
    cfg_dir = _write_cfg(tmp_path, {"paypal.com": {"in_scope": ["paypal.com", "*.paypal.com"]}})
    scope = gui._trusted_scope(load_config(cfg_dir))
    assert scope.domain == ""
    assert scope.in_scope == ["paypal.com", "*.paypal.com"]


def test_trusted_scope_empty_when_no_targets_configured(tmp_path):
    scope = gui._trusted_scope(load_config(_write_cfg(tmp_path, {})))
    assert scope.in_scope == []
    assert scope.domain == ""


# -- accept / reject -------------------------------------------------------


def test_authorized_target_is_accepted(tmp_path, monkeypatch, creds):
    _use_config(monkeypatch, _write_cfg(tmp_path, {"paypal.com": {"in_scope": ["paypal.com", "*.paypal.com"]}}))
    created = _install_coordinator(monkeypatch)
    resp = CLIENT.post(
        "/api/scan",
        json={"target": "api.paypal.com", "intensity": "quick-scan", "confirm": True},
        auth=creds,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "success"
    assert len(created) == 1 and created[0].scans[0].target == "api.paypal.com"


def test_unauthorized_target_is_rejected(tmp_path, monkeypatch, creds):
    _use_config(monkeypatch, _write_cfg(tmp_path, {"paypal.com": {"in_scope": ["paypal.com"]}}))
    created = _install_coordinator(monkeypatch)
    resp = CLIENT.post(
        "/api/scan",
        json={"target": "attacker.example.com", "confirm": True},
        auth=creds,
    )
    assert resp.status_code == 403
    assert created == []


def test_request_cannot_authorize_itself(tmp_path, monkeypatch, creds):
    _use_config(monkeypatch, _write_cfg(tmp_path, {"paypal.com": {"in_scope": ["paypal.com"]}}))
    created = _install_coordinator(monkeypatch)
    for target in ("evil.com", "self-authorizing.test", "127.0.0.1", "169.254.169.254"):
        resp = CLIENT.post(
            "/api/scan",
            json={"target": target, "confirm": True, "scope_kind": "private", "cookie": "x=1"},
            auth=creds,
        )
        assert resp.status_code == 403, f"{target} was not rejected: {resp.text}"
    assert created == []


def test_confirmation_required_before_any_scope_or_scan(monkeypatch, creds):
    created = _install_coordinator(monkeypatch)
    resp = CLIENT.post("/api/scan", json={"target": "paypal.com", "confirm": False}, auth=creds)
    assert resp.status_code == 400
    assert created == []


# -- fail closed -----------------------------------------------------------


def test_missing_scope_fails_closed(tmp_path, monkeypatch, creds):
    _use_config(monkeypatch, _write_cfg(tmp_path, {}))
    created = _install_coordinator(monkeypatch)
    resp = CLIENT.post("/api/scan", json={"target": "paypal.com", "confirm": True}, auth=creds)
    assert resp.status_code == 403
    assert "fail closed" in resp.json()["detail"].lower()
    assert created == []


def test_config_error_fails_closed(monkeypatch, creds):
    def _boom():
        raise ConfigError("main config not found")

    monkeypatch.setattr(gui, "load_config", _boom)
    created = _install_coordinator(monkeypatch)
    resp = CLIENT.post("/api/scan", json={"target": "paypal.com", "confirm": True}, auth=creds)
    assert resp.status_code == 503
    assert created == []


def test_malformed_scope_config_fails_closed(tmp_path, monkeypatch, creds):
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    (cfg_dir / "nexus.yaml").write_text("targets:\n  broken: not-a-mapping\n", encoding="utf-8")
    (cfg_dir / "false_positive_filters.yaml").write_text("filters: {}\n", encoding="utf-8")
    _use_config(monkeypatch, cfg_dir)
    created = _install_coordinator(monkeypatch)
    resp = CLIENT.post("/api/scan", json={"target": "paypal.com", "confirm": True}, auth=creds)
    assert resp.status_code == 503
    assert created == []


# -- validator semantics preserved -----------------------------------------


def test_wildcard_allows_subdomains_rejects_deceptive_suffix(tmp_path, monkeypatch, creds):
    _use_config(monkeypatch, _write_cfg(tmp_path, {"example.com": {"in_scope": ["*.example.com"]}}))
    _install_coordinator(monkeypatch)
    for target in ("example.com", "api.example.com", "a.b.example.com"):
        resp = CLIENT.post("/api/scan", json={"target": target, "confirm": True}, auth=creds)
        assert resp.status_code == 200, f"{target}: {resp.text}"
    for target in ("example.com.attacker.test", "evilexample.com", "notexample.com"):
        resp = CLIENT.post("/api/scan", json={"target": target, "confirm": True}, auth=creds)
        assert resp.status_code == 403, f"{target} should be out of scope"


def test_ip_and_cidr_scope(tmp_path, monkeypatch, creds):
    _use_config(monkeypatch, _write_cfg(tmp_path, {"net": {"in_scope": ["10.0.0.0/24"]}}))
    _install_coordinator(monkeypatch)
    for target in ("10.0.0.5", "10.0.0.0"):
        resp = CLIENT.post("/api/scan", json={"target": target, "confirm": True}, auth=creds)
        assert resp.status_code == 200, f"{target}: {resp.text}"
    for target in ("10.0.1.5", "192.168.1.1", "8.8.8.8"):
        resp = CLIENT.post("/api/scan", json={"target": target, "confirm": True}, auth=creds)
        assert resp.status_code == 403, f"{target} should be out of scope"


def test_out_of_scope_wins(tmp_path, monkeypatch, creds):
    _use_config(
        monkeypatch,
        _write_cfg(
            tmp_path,
            {"example.com": {"in_scope": ["*.example.com"], "out_of_scope": ["admin.example.com"]}},
        ),
    )
    _install_coordinator(monkeypatch)
    ok = CLIENT.post("/api/scan", json={"target": "www.example.com", "confirm": True}, auth=creds)
    assert ok.status_code == 200, ok.text
    blocked = CLIENT.post("/api/scan", json={"target": "admin.example.com", "confirm": True}, auth=creds)
    assert blocked.status_code == 403


# -- isolation: rejected requests touch nothing ----------------------------


def test_rejected_request_reaches_no_scanner_http_or_subprocess(tmp_path, monkeypatch, creds):
    _use_config(monkeypatch, _write_cfg(tmp_path, {"paypal.com": {"in_scope": ["paypal.com"]}}))
    created = _install_coordinator(monkeypatch)
    _forbid_network_and_subprocess(monkeypatch)
    resp = CLIENT.post("/api/scan", json={"target": "evil.example.com", "confirm": True}, auth=creds)
    assert resp.status_code == 403
    assert created == []


# -- auth vs scope are distinct --------------------------------------------


def test_authentication_and_scope_failures_are_distinct(tmp_path, monkeypatch):
    _use_config(monkeypatch, _write_cfg(tmp_path, {"paypal.com": {"in_scope": ["paypal.com"]}}))
    created = _install_coordinator(monkeypatch)
    body = {"target": "paypal.com", "confirm": True}

    # No Authorization header at all -> 401 (Basic scheme challenge).
    r = CLIENT.post("/api/scan", json=body)
    assert r.status_code == 401

    # Header present but credentials unconfigured -> 503 (fail closed).
    monkeypatch.delenv("NEXUS_GUI_USER", raising=False)
    monkeypatch.delenv("NEXUS_GUI_PASS", raising=False)
    r = CLIENT.post("/api/scan", json=body, auth=("x", "y"))
    assert r.status_code == 503

    # Wrong password -> 401.
    monkeypatch.setenv("NEXUS_GUI_USER", USER)
    monkeypatch.setenv("NEXUS_GUI_PASS", PASS)
    r = CLIENT.post("/api/scan", json=body, auth=(USER, "wrong"))
    assert r.status_code == 401

    # Correct credentials, out-of-scope target -> 403 (scope, not auth).
    r = CLIENT.post("/api/scan", json={"target": "evil.com", "confirm": True}, auth=(USER, PASS))
    assert r.status_code == 403
    assert created == []


# -- route coverage --------------------------------------------------------


def test_every_scan_route_enforces_the_boundary(tmp_path, monkeypatch, creds):
    post_routes = sorted(
        {r.path for r in app.routes if getattr(r, "methods", None) and "POST" in r.methods}
    )
    assert post_routes == ["/api/scan"], "unexpected POST routes may bypass the scope gate"

    _use_config(monkeypatch, _write_cfg(tmp_path, {"paypal.com": {"in_scope": ["paypal.com"]}}))
    created = _install_coordinator(monkeypatch)
    for path in post_routes:
        # No credentials -> rejected before any scope/scan work.
        assert CLIENT.post(path, json={"target": "paypal.com", "confirm": True}).status_code == 401
        # Authorized credentials + out-of-scope target -> rejected, no scan.
        r = CLIENT.post(path, json={"target": "evil.com", "confirm": True}, auth=creds)
        assert r.status_code == 403
    assert created == []


def test_protected_routes_require_authentication():
    protected = [
        r.path
        for r in app.routes
        if getattr(r, "methods", None) and r.path not in _DOC_PATHS and r.path != "/health"
    ]
    assert "/api/scan" in protected
    for path in protected:
        methods = next(r for r in app.routes if getattr(r, "methods", None) and r.path == path).methods
        method = "POST" if "POST" in methods else "GET"
        resp = CLIENT.request(method, path)
        assert resp.status_code == 401, f"{method} {path} is not protected"
