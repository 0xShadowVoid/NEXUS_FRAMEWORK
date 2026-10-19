"""Pass 4 — guarded browser layer unit tests (deterministic, mock-based)."""
from __future__ import annotations

import pytest

from core import lifecycle
from lib.config import load_config
from lib.paths import CONFIG_DIR
from lib.nemesis.browser import (
    BrowserObservation,
    BrowserPolicy,
    BrowserPolicyError,
    BrowserStep,
    GuardedBrowser,
    MockBrowserAdapter,
    _safe_download_target,
    build_browser_evidence,
    playwright_available,
    run_browser_task,
)
from lib.nemesis.session import load_session


class _FakeAdapter(MockBrowserAdapter):
    """Mock with programmable failures / redirect simulation."""

    def __init__(self, final_url: str | None = None, fail_on_action: str = ""):
        super().__init__()
        self.final_url = final_url
        self.fail_on_action = fail_on_action

    def navigate(self, url: str) -> BrowserObservation:
        if self.fail_on_action == "navigate":
            raise TimeoutError("navigation timed out")
        obs = super().navigate(url)
        if self.final_url:
            obs.url = self.final_url
        return obs

    def click(self, selector: str) -> BrowserObservation:
        if self.fail_on_action == "click":
            raise TimeoutError("click timed out")
        return super().click(selector)


def _policy(**overrides) -> BrowserPolicy:
    cfg = load_config(CONFIG_DIR)
    defaults = dict(
        target_config=cfg.target("example.com"),
        ssrf_allow={"example.com"},
        download_dir=None,
        db=None,
    )
    defaults.update(overrides)
    return BrowserPolicy(**defaults)


# --- destination validation ----------------------------------------------------

def test_guard_blocks_metadata_and_private_via_ssrf():
    policy = BrowserPolicy(target_config=None, ssrf_allow=set())
    for bad in ("http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1/", "http://10.0.0.5/"):
        ok, reason = policy.check_url(bad)
        assert not ok and reason.startswith("ssrf"), (bad, reason)


def test_guard_enforces_scope():
    policy = _policy()
    ok, reason = policy.check_url("https://evil-other.com/x")
    assert not ok and "scope" in reason
    ok2, _ = policy.check_url("https://example.com/x")
    assert ok2


def test_navigate_blocked_pre_action_never_hits_adapter():
    adapter = MockBrowserAdapter()
    gb = GuardedBrowser(adapter, _policy(ssrf_allow=set()))
    with pytest.raises(BrowserPolicyError):
        gb.navigate("http://169.254.169.254/")
    assert adapter.actions == []          # nothing was executed


def test_redirect_final_destination_revalidated():
    adapter = _FakeAdapter(final_url="http://169.254.169.254/redirected")
    gb = GuardedBrowser(adapter, _policy())
    with pytest.raises(BrowserPolicyError):
        gb.navigate("https://example.com/go")


def test_state_changing_requires_explicit_authorization():
    adapter = MockBrowserAdapter()
    policy = _policy()
    gb = GuardedBrowser(adapter, policy)
    with pytest.raises(BrowserPolicyError):
        gb.click("#login")
    policy.authorize_state_changes(note="operator approved test login")
    obs = gb.click("#login")
    assert obs.action == "click" and adapter.actions


def test_download_target_stays_in_sandbox(tmp_path):
    target = _safe_download_target(tmp_path, "../../evil.sh")
    assert str(target).startswith(str(tmp_path.resolve()))
    target2 = _safe_download_target(tmp_path, "report.pdf")
    assert str(target2).startswith(str(tmp_path.resolve()))


def test_playwright_available_flag_shape():
    assert isinstance(playwright_available(), bool)


# --- task runner: evidence + session + secrets ------------------------------------

def test_run_browser_task_records_evidence_and_session(db, tmp_path):
    sid = db.create_scan(db.upsert_target("example.com"))
    policy = _policy(download_dir=tmp_path, db=db)
    gb = GuardedBrowser(MockBrowserAdapter(), policy)
    steps = [
        BrowserStep(action="navigate", url="https://example.com/"),
        BrowserStep(action="observe"),
        BrowserStep(action="screenshot"),
    ]
    out = run_browser_task(db, gb, steps, engagement="example.com", scan_id=sid)
    assert out["state"] == "completed" and not out["pending"]
    assert len(out["evidence_ids"]) == 3
    rows = db.query_evidence(scan_id=sid)
    assert {r["source"] for r in rows} == {"browser"}
    session = load_session(db, "example.com")
    assert session.completed_actions == [s.signature() for s in steps]


def test_run_browser_task_interrupted_then_resumed(db, tmp_path):
    sid = db.create_scan(db.upsert_target("example.com"))
    policy = _policy(download_dir=tmp_path, db=db)
    policy.authorize_state_changes()
    gb = GuardedBrowser(_FakeAdapter(fail_on_action="click"), policy)
    steps = [
        BrowserStep(action="navigate", url="https://example.com/"),
        BrowserStep(action="click", selector="#x"),
        BrowserStep(action="screenshot"),
    ]
    first = run_browser_task(db, gb, steps, engagement="example.com", scan_id=sid)
    assert first["state"] == "partial" and first["errors"]
    assert first["completed"] == [steps[0].signature()]
    assert first["pending"] == [steps[1].signature(), steps[2].signature()]

    # resume with a healthy adapter — completed step is skipped
    gb2 = GuardedBrowser(MockBrowserAdapter(), policy)
    second = run_browser_task(db, gb2, steps, engagement="example.com", scan_id=sid)
    assert second["state"] == "completed" and not second["pending"]
    assert second["completed"] == [steps[1].signature(), steps[2].signature()]


def test_fill_values_never_persisted(db, tmp_path):
    sid = db.create_scan(db.upsert_target("example.com"))
    policy = _policy(download_dir=tmp_path, db=db)
    policy.authorize_state_changes()
    gb = GuardedBrowser(MockBrowserAdapter(), policy)
    steps = [BrowserStep(action="fill", selector="#pw", value="hunter2-secret")]
    run_browser_task(db, gb, steps, engagement="example.com", scan_id=sid)
    session = load_session(db, "example.com")
    blob = str(session.to_dict())
    assert "hunter2-secret" not in blob
    assert "len=" in session.completed_actions[0]
    events = db.list_audit_events(category="nemesis")
    assert events and all("hunter2-secret" not in str(e) for e in events)


def test_ai_cannot_validate_after_browser_evidence(db, tmp_path):
    sid = db.create_scan(db.upsert_target("example.com"))
    fid = db.insert_finding(sid, "https://example.com/a", "xss", "P2", 90)
    gb = GuardedBrowser(MockBrowserAdapter(), _policy(download_dir=tmp_path, db=db))
    run_browser_task(db, gb, [BrowserStep(action="navigate", url="https://example.com/")],
                     engagement="example.com", scan_id=sid, finding_ref=fid)
    assert lifecycle.current_state(db, fid) == "candidate"
    with pytest.raises(lifecycle.InvalidTransition):
        lifecycle.transition(db, fid, "validated", actor="ai_browser_agent")


def test_evidence_schema_carries_engagement_and_phase():
    obs = BrowserObservation(url="https://example.com/", action="navigate", dom_summary="…")
    schema = build_browser_evidence(obs, phase="browser", engagement="example.com")
    assert schema["engagement"] == "example.com"
    assert schema["phase"] == "browser"
    assert schema["trusted"] is False


# --- redirect watchdog (browserless unit coverage) -------------------------------

def _bare_adapter():
    from lib.nemesis.browser import PlaywrightBrowserAdapter

    adapter = PlaywrightBrowserAdapter.__new__(PlaywrightBrowserAdapter)
    adapter.request_guard = lambda url: ("169.254" not in url, "scope")
    adapter._blocked_requests = []
    adapter._policy_violation = None
    adapter._blocked_navigations = 0
    return adapter


def test_watchdog_closes_page_on_disallowed_navigation():
    adapter = _bare_adapter()
    closed = []

    class _Page:
        def close(self):
            closed.append(True)

    class _Req:
        url = "http://169.254.169.254/latest/meta-data/"

        @staticmethod
        def is_navigation_request():
            return True

    adapter._page = _Page()
    adapter._on_request_watch(_Req())
    assert closed
    assert adapter._blocked_requests == ["http://169.254.169.254/latest/meta-data/"]
    assert adapter._policy_violation


def test_watchdog_records_but_keeps_page_for_subresources():
    adapter = _bare_adapter()
    closed = []

    class _Page:
        def close(self):
            closed.append(True)

    class _Req:
        url = "http://169.254.169.254/pixel.png"

        @staticmethod
        def is_navigation_request():
            return False

    adapter._page = _Page()
    adapter._on_request_watch(_Req())
    assert not closed                      # route layer blocks subresources pre-fetch
    assert adapter._blocked_requests


# --- redirect-chain validation (browserless unit coverage) -----------------------

def _bare_chain_adapter():
    from lib.nemesis.browser import PlaywrightBrowserAdapter

    adapter = PlaywrightBrowserAdapter.__new__(PlaywrightBrowserAdapter)
    adapter.request_guard = lambda url: ("canary" not in url, "scope")
    adapter.max_redirect_hops = 10
    adapter._blocked_requests = []
    adapter._policy_violation = None
    return adapter


class _FakeResp:
    def __init__(self, status, location=""):
        self.status = status
        self.headers = {"location": location} if location else {}


def test_chain_validation_blocks_before_fetching_prohibited():
    adapter = _bare_chain_adapter()
    fetched = []

    def fetch_next(url):
        fetched.append(url)
        return _FakeResp(200)

    ok, blocked = adapter._validate_redirect_chain(
        "https://example.com/a", _FakeResp(302, "http://canary.example/x"), fetch_next=fetch_next
    )
    assert not ok and "canary" in blocked
    assert fetched == []          # prohibited destination was never fetched


def test_chain_validation_follows_allowed_hops_to_final():
    adapter = _bare_chain_adapter()

    def fetch_next(url):
        if url.endswith("/b"):
            return _FakeResp(302, "https://example.com/c")
        return _FakeResp(200)

    ok, blocked = adapter._validate_redirect_chain(
        "https://example.com/a", _FakeResp(302, "https://example.com/b"), fetch_next=fetch_next
    )
    assert ok and blocked == ""


def test_chain_validation_detects_redirect_loop():
    adapter = _bare_chain_adapter()

    def fetch_next(url):
        return _FakeResp(302, "https://example.com/a")   # loops back to the start

    ok, blocked = adapter._validate_redirect_chain(
        "https://example.com/a", _FakeResp(302, "https://example.com/b"), fetch_next=fetch_next
    )
    assert not ok and "loop" in blocked


# --- capability probe: package present but browser not usable ---------------------

def _install_fake_playwright(monkeypatch, *, executable_path=None, start_raises=False):
    """Inject a fake ``playwright`` package so the probe can be tested offline."""
    import sys
    import types

    pkg = types.ModuleType("playwright")
    sync = types.ModuleType("playwright.sync_api")

    class _Chromium:
        def __init__(self, path):
            self.executable_path = path

    class _Playwright:
        def __init__(self, path):
            self.chromium = _Chromium(path)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def _sync_playwright():
        if start_raises:
            raise RuntimeError("driver unavailable")
        return _Playwright(executable_path)

    sync.sync_playwright = _sync_playwright
    monkeypatch.setitem(sys.modules, "playwright", pkg)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync)


def test_playwright_available_false_when_package_missing(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "playwright", None)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    assert playwright_available() is False


def test_playwright_available_true_when_browser_installed(tmp_path, monkeypatch):
    exe = tmp_path / "chromium"
    exe.write_text("x", encoding="utf-8")
    _install_fake_playwright(monkeypatch, executable_path=str(exe))
    assert playwright_available() is True


def test_playwright_available_false_when_browser_missing(tmp_path, monkeypatch):
    _install_fake_playwright(monkeypatch, executable_path=str(tmp_path / "not-installed"))
    assert playwright_available() is False


def test_playwright_available_false_when_driver_start_fails(monkeypatch):
    _install_fake_playwright(monkeypatch, executable_path="whatever", start_raises=True)
    assert playwright_available() is False


# --- request gate (browserless coverage of the route layer) -----------------------

class _FakeRoute:
    def __init__(self, url, resource_type, fetch_response=None, fetch_raises=False):
        import types

        self.request = types.SimpleNamespace(url=url, resource_type=resource_type)
        self.calls = []
        self._fetch_response = fetch_response
        self._fetch_raises = fetch_raises

    def abort(self):
        self.calls.append("abort")

    def continue_(self):
        self.calls.append("continue")

    def fetch(self, max_redirects=0):
        self.calls.append(("fetch", max_redirects))
        if self._fetch_raises:
            raise RuntimeError("route.fetch unavailable")
        return self._fetch_response

    def fulfill(self, response=None):
        self.calls.append("fulfill")


def test_route_gate_aborts_disallowed_document():
    adapter = _bare_adapter()
    route = _FakeRoute("http://169.254.169.254/latest/meta-data/", "document")
    adapter._route_handler(route)
    assert "abort" in route.calls
    assert adapter._blocked_navigations == 1
    assert adapter._blocked_requests == ["http://169.254.169.254/latest/meta-data/"]


def test_route_gate_allows_and_continues_plain_subresource():
    adapter = _bare_adapter()
    route = _FakeRoute("https://example.com/pixel.png", "image")
    adapter._route_handler(route)
    assert route.calls == ["continue"]


def test_route_gate_validates_document_chain_then_fulfills():
    adapter = _bare_adapter()
    adapter.max_redirect_hops = 10
    route = _FakeRoute("https://example.com/ok", "document", fetch_response=_FakeResp(200))
    adapter._route_handler(route)
    assert ("fetch", 0) in route.calls          # chain validated out-of-browser
    assert "fulfill" in route.calls
    assert adapter._blocked_requests == []


def test_route_gate_falls_back_to_continue_when_fetch_unavailable():
    adapter = _bare_adapter()
    route = _FakeRoute("https://example.com/ok", "document", fetch_raises=True)
    adapter._route_handler(route)
    assert route.calls == [("fetch", 0), "continue"]


# --- redirect-chain bounds (fail-closed envelope) ---------------------------------

def test_chain_validation_without_guard_is_permissive():
    adapter = _bare_chain_adapter()
    adapter.request_guard = None
    ok, reason = adapter._validate_redirect_chain(
        "https://example.com/a", _FakeResp(302, "https://example.com/b")
    )
    assert ok and reason == ""


def test_chain_validation_missing_location_stops():
    adapter = _bare_chain_adapter()
    ok, reason = adapter._validate_redirect_chain("https://example.com/a", _FakeResp(302))
    assert ok and reason == ""


def test_chain_validation_fetch_failure_fails_open_for_watchdog():
    adapter = _bare_chain_adapter()

    def fetch_next(url):
        raise RuntimeError("hop unavailable")

    ok, reason = adapter._validate_redirect_chain(
        "https://example.com/a", _FakeResp(302, "https://example.com/b"), fetch_next=fetch_next
    )
    assert ok and reason == ""


def test_chain_validation_bounds_too_many_redirects():
    adapter = _bare_chain_adapter()
    adapter.max_redirect_hops = 2
    nxt = {
        "https://example.com/b": "https://example.com/c",
        "https://example.com/c": "https://example.com/d",
    }

    def fetch_next(url):
        return _FakeResp(302, nxt[url])

    ok, reason = adapter._validate_redirect_chain(
        "https://example.com/a", _FakeResp(302, "https://example.com/b"), fetch_next=fetch_next
    )
    assert not ok and "too many redirects" in reason


# --- cancellation, download sandbox, guarded wiring -------------------------------

def test_bare_adapter_cancel_sets_flag_and_check_raises():
    adapter = _bare_adapter()
    adapter._cancelled = False
    adapter._page = None
    adapter.cancel()
    assert adapter._cancelled is True
    with pytest.raises(BrowserPolicyError):
        adapter._check_cancelled()


def test_download_escape_guard_blocks_when_sanitizer_fails(tmp_path, monkeypatch):
    import lib.nemesis.browser as browser_mod

    monkeypatch.setattr(browser_mod, "sanitize_path_component", lambda _v: "../escape.bin")
    with pytest.raises(BrowserPolicyError):
        browser_mod._safe_download_target(tmp_path, "anything")


def test_guarded_start_stop_delegate_to_adapter():
    adapter = MockBrowserAdapter()
    gb = GuardedBrowser(adapter, _policy())
    gb.start()
    gb.stop()
    assert [a["action"] for a in adapter.actions] == ["start", "stop"]


def test_guarded_open_tab_is_gated_and_fill_requires_authorization():
    adapter = MockBrowserAdapter()
    policy = _policy()
    gb = GuardedBrowser(adapter, policy)
    with pytest.raises(BrowserPolicyError):
        gb.open_tab("http://169.254.169.254/")
    assert adapter.actions == []                       # gated before the adapter
    with pytest.raises(BrowserPolicyError):
        gb.fill_form("#pw", "secret")
    assert adapter.actions == []
    policy.authorize_state_changes()
    obs = gb.open_tab("https://example.com/")
    assert obs.action == "navigate"


def test_guarded_browser_wires_request_guard_for_playwright_adapter():
    from lib.nemesis.browser import PlaywrightBrowserAdapter

    adapter = PlaywrightBrowserAdapter.__new__(PlaywrightBrowserAdapter)
    adapter.request_guard = None
    policy = _policy()
    GuardedBrowser(adapter, policy)
    assert adapter.request_guard == policy.check_url
