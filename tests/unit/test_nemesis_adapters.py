"""NEMESIS Alpha — browser adapter (Phase E) + MCP gateway (Phase F) tests."""
from __future__ import annotations

import pytest

from lib.config import load_config
from lib.paths import CONFIG_DIR
from lib.nemesis.browser import (
    BrowserUnavailable,
    MockBrowserAdapter,
    PlaywrightBrowserAdapter,
    browser_enabled,
    build_browser_evidence,
    record_browser_evidence,
)
from lib.nemesis.mcp import McpGateway, McpTool


# --- browser ---------------------------------------------------------------------

def test_browser_disabled_by_default():
    cfg = load_config(CONFIG_DIR)
    assert browser_enabled(cfg) is False
    cfg._main["nemesis"] = {"browser": {"enabled": True}}
    assert browser_enabled(cfg) is True


def test_mock_browser_flow_and_evidence(db):
    sid = db.create_scan(db.upsert_target("example.com"))
    adapter = MockBrowserAdapter()
    adapter.start()
    obs = adapter.navigate("https://example.com/login")
    dom = adapter.inspect_dom()
    shot = adapter.screenshot()
    adapter.observe()
    assert "mock page" in dom
    assert shot.startswith("mock://")
    assert adapter.actions  # every action recorded

    obs.dom_summary = dom
    obs.screenshot_ref = shot
    schema = build_browser_evidence(obs, phase="browser")
    assert schema["trusted"] is False
    assert schema["phase"] == "browser"
    assert schema["url"] == "https://example.com/login"
    assert schema["screenshot_reference"] == shot

    eid = record_browser_evidence(db, obs, scan_id=sid)
    row = [r for r in db.query_evidence(scan_id=sid) if r["id"] == eid][0]
    assert row["source"] == "browser" and row["tool"] == "browser"
    assert row["screenshot_path"] == shot
    assert "mock page" in row["response_body"]  # sanitized, kept for proof


def test_playwright_adapter_degrades_cleanly():
    try:
        import playwright  # noqa: F401
        available = True
    except Exception:
        available = False
    if available:  # pragma: no cover - environment dependent
        pytest.skip("playwright installed; degradation path not applicable")
    with pytest.raises(BrowserUnavailable):
        PlaywrightBrowserAdapter()


# --- MCP gateway ------------------------------------------------------------------

def _target_cfg():
    return load_config(CONFIG_DIR).target("example.com")


def _gw(db=None):
    gw = McpGateway(db=db, target_config=_target_cfg())
    gw.register(
        McpTool(name="safe_read", handler=lambda args: {"ok": args},
                scope_target_key="target"),
        enabled=True,
    )
    gw.register(
        McpTool(name="agent_tool", handler=lambda args: "done",
                allow_agent=True, scope_target_key="target"),
        enabled=True,
    )
    return gw


def test_mcp_denies_unknown_and_disabled(db):
    gw = _gw(db)
    assert gw.call("nope", {})["status"] == "denied"
    gw.register(McpTool(name="off", handler=lambda a: 1), enabled=False)
    assert gw.call("off", {})["status"] == "denied"


def test_mcp_denies_agent_when_not_allowed(db):
    gw = _gw(db)
    out = gw.call("safe_read", {"target": "example.com"}, actor="agent")
    assert out["status"] == "denied" and "authorization" in out["reason"]


def test_mcp_scope_enforced(db):
    gw = _gw(db)
    out = gw.call("agent_tool", {"target": "not-example.com"}, actor="agent")
    assert out["status"] == "denied" and "scope" in out["reason"]
    ok = gw.call("agent_tool", {"target": "example.com"}, actor="agent")
    assert ok["status"] == "ok" and ok["result"] == "done"


def test_mcp_safety_payload_guard(db):
    gw = _gw(db)
    out = gw.call("safe_read", {"target": "example.com", "payload": "rm -rf /"}, actor="operator")
    assert out["status"] == "denied" and "safety" in out["reason"]


def test_mcp_auth_required(db):
    gw = _gw(db)
    out = gw.call("safe_read", {"target": "example.com"}, actor="")
    assert out["status"] == "denied" and "authentication" in out["reason"]


def test_mcp_audits_calls(db):
    gw = _gw(db)
    gw.call("agent_tool", {"target": "example.com"}, actor="agent")
    events = db.list_audit_events(category="mcp")
    assert events and events[0]["action"] == "mcp.agent_tool"
