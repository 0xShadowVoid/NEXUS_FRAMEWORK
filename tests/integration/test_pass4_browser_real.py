"""Pass 4 — real browser integration + end-to-end demonstration (local app).

These tests exercise the REAL Playwright driver against controlled LOCAL
servers only (no public websites are contacted). They are skipped when
Playwright is unavailable; the report distinguishes executed vs skipped.

Security matrix covered: direct scope rejection, same-host and cross-host
redirects, redirects to link-local/metadata, multi-hop chains, redirect
loops, disallowed subresources, navigation timeouts, cancellation — with
canary hit-counters proving whether prohibited destinations were contacted.
"""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from core.database import Database
from lib.config import load_config
from lib.paths import CONFIG_DIR
from lib.nemesis.browser import (
    BrowserPolicy,
    BrowserPolicyError,
    BrowserStep,
    GuardedBrowser,
    PlaywrightBrowserAdapter,
    playwright_available,
    run_browser_task,
)

pytestmark = pytest.mark.skipif(not playwright_available(), reason="playwright not installed")

_HTML = """<html><head><title>Nexus Test App</title></head>
<body><h1>Hello NEXUS</h1>
<form action="/login" method="post">
<input id="user" name="user"/><input id="pass" name="pass" type="password"/>
<button id="go">Go</button></form>
</body></html>"""

CANARY_HITS: list[str] = []


class _CanaryHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        CANARY_HITS.append(self.path)
        body = b"canary"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _AppHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _send_html(self, html: str) -> None:
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass  # client aborted (e.g. route.fetch handling) — benign in tests

    def do_GET(self):
        canary_port = getattr(self.server, "canary_port", 0)
        app_port = self.server.server_port
        if self.path == "/redirect-bad":
            self._redirect("http://169.254.169.254/latest/meta-data/")
            return
        if self.path == "/redir-cross":
            self._redirect(f"http://localhost:{canary_port}/canary")
            return
        if self.path == "/redir-ok":
            self._redirect(f"http://127.0.0.1:{app_port}/hop-final")
            return
        if self.path == "/redir-chain":
            self._redirect(f"http://127.0.0.1:{app_port}/hopbad")
            return
        if self.path == "/hopbad":
            self._redirect(f"http://localhost:{canary_port}/canary")
            return
        if self.path == "/loop-a":
            self._redirect(f"http://127.0.0.1:{app_port}/loop-b")
            return
        if self.path == "/loop-b":
            self._redirect(f"http://127.0.0.1:{app_port}/loop-a")
            return
        if self.path == "/slow":
            time.sleep(2)
            self._send_html(_HTML)
            return
        if self.path == "/img-page":
            self._send_html(
                f'<html><title>img</title><img src="http://localhost:{canary_port}/pixel.png"/></html>'
            )
            return
        self._send_html(_HTML)


@pytest.fixture()
def servers():
    CANARY_HITS.clear()
    canary = ThreadingHTTPServer(("127.0.0.1", 0), _CanaryHandler)
    threading.Thread(target=canary.serve_forever, daemon=True).start()
    app = ThreadingHTTPServer(("127.0.0.1", 0), _AppHandler)
    app.canary_port = canary.server_port
    threading.Thread(target=app.serve_forever, daemon=True).start()
    yield {"app": f"http://127.0.0.1:{app.server_port}", "canary_port": canary.server_port}
    app.shutdown()
    canary.shutdown()


@pytest.fixture()
def pdb(tmp_path):
    db = Database(tmp_path / "p4.db")
    yield db
    db.close()


def _local_target():
    cfg = load_config(CONFIG_DIR)
    tcfg = cfg.target("127.0.0.1")
    tcfg.in_scope = ["127.0.0.1"]
    return tcfg


def _local_policy(db, tmp_path):
    return BrowserPolicy(
        target_config=_local_target(),
        ssrf_allow={"127.0.0.1"},
        download_dir=tmp_path,
        db=db,
    )


def _guarded(pdb, tmp_path):
    policy = _local_policy(pdb, tmp_path)
    adapter = PlaywrightBrowserAdapter(headless=True)
    guarded = GuardedBrowser(adapter, policy)
    return guarded, adapter, policy


# --- core path ---------------------------------------------------------------------

def test_real_launch_navigate_dom_screenshot_evidence(pdb, tmp_path, servers):
    guarded, adapter, _policy = _guarded(pdb, tmp_path)
    guarded.start()
    try:
        obs = guarded.navigate(servers["app"] + "/ok")
        assert obs.url.endswith("/ok")
        assert "Nexus Test App" in (obs.state.get("title") or "")
        dom = guarded.inspect_dom()
        assert "Hello NEXUS" in dom
        shot = guarded.screenshot()
        assert Path(shot).exists() and Path(shot).stat().st_size > 100

        sid = pdb.create_scan(pdb.upsert_target("127.0.0.1"))
        out = run_browser_task(
            pdb, guarded, [BrowserStep(action="observe")],
            engagement="127.0.0.1", scan_id=sid,
        )
        assert out["state"] == "completed" and out["evidence_ids"]
    finally:
        guarded.stop()


def test_real_scope_rejection(pdb, tmp_path, servers):
    guarded, adapter, _policy = _guarded(pdb, tmp_path)
    with pytest.raises(BrowserPolicyError):
        guarded.navigate("http://out-of-scope.invalid/")  # pre-gate; never contacted


# --- redirect security matrix -------------------------------------------------------

def test_redirect_to_metadata_blocked(pdb, tmp_path, servers):
    guarded, adapter, _policy = _guarded(pdb, tmp_path)
    guarded.start()
    try:
        with pytest.raises(BrowserPolicyError):
            guarded.navigate(servers["app"] + "/redirect-bad")
        assert any("169.254.169.254" in u for u in adapter._blocked_requests)
    finally:
        guarded.stop()


def test_first_hop_redirect_to_prohibited_zero_contact(pdb, tmp_path, servers):
    guarded, adapter, _policy = _guarded(pdb, tmp_path)
    guarded.start()
    try:
        with pytest.raises(BrowserPolicyError):
            guarded.navigate(servers["app"] + "/redir-cross")
        assert any("canary" in u for u in adapter._blocked_requests)
        assert CANARY_HITS == []          # strict pre-fetch: zero contact
    finally:
        guarded.stop()


def test_allowed_same_host_redirect_completes(pdb, tmp_path, servers):
    guarded, adapter, _policy = _guarded(pdb, tmp_path)
    guarded.start()
    try:
        obs = guarded.navigate(servers["app"] + "/redir-ok")
        assert obs.url.endswith("/hop-final")
        assert adapter._blocked_requests == []
        assert CANARY_HITS == []
    finally:
        guarded.stop()


def test_redirect_chain_blocked_at_second_hop_zero_contact(pdb, tmp_path, servers):
    guarded, adapter, _policy = _guarded(pdb, tmp_path)
    guarded.start()
    try:
        with pytest.raises(BrowserPolicyError):
            guarded.navigate(servers["app"] + "/redir-chain")
        assert any("canary" in u for u in adapter._blocked_requests)
        assert CANARY_HITS == []          # chain validated out-of-browser
    finally:
        guarded.stop()


def test_redirect_loop_bounded(pdb, tmp_path, servers):
    guarded, adapter, _policy = _guarded(pdb, tmp_path)
    guarded.start()
    try:
        with pytest.raises(BrowserPolicyError) as exc:
            guarded.navigate(servers["app"] + "/loop-a")
        assert "loop" in str(exc.value).lower()
    finally:
        guarded.stop()


def test_navigation_timeout_bounded(pdb, tmp_path, servers):
    guarded, adapter, _policy = _guarded(pdb, tmp_path)
    guarded.start()
    try:
        with pytest.raises(Exception):
            adapter.navigate(servers["app"] + "/slow", timeout_ms=600)
    finally:
        guarded.stop()  # clean shutdown after timeout


def test_disallowed_subresource_blocked_prefetch(pdb, tmp_path, servers):
    guarded, adapter, _policy = _guarded(pdb, tmp_path)
    guarded.start()
    try:
        obs = guarded.navigate(servers["app"] + "/img-page")
        assert obs.url.endswith("/img-page")          # navigation itself allowed
        assert any("pixel.png" in u for u in adapter._blocked_requests)
        assert CANARY_HITS == []                      # subresource blocked pre-fetch
        assert guarded.observe().dom_summary          # page remains usable
    finally:
        guarded.stop()


def test_cancellation_stops_session(pdb, tmp_path, servers):
    guarded, adapter, _policy = _guarded(pdb, tmp_path)
    guarded.start()
    try:
        guarded.cancel()
        with pytest.raises(BrowserPolicyError):
            guarded.navigate(servers["app"] + "/ok")
    finally:
        guarded.stop()


# --- end-to-end demonstration --------------------------------------------------------

def test_e2e_demo_plan_authorize_navigate_observe_capture_verify_report(pdb, tmp_path, servers):
    """PLAN → AUTHORIZE → NAVIGATE → OBSERVE → CAPTURE EVIDENCE → VERIFY → REPORT."""
    host = "127.0.0.1"
    sid = pdb.create_scan(pdb.upsert_target(host))
    guarded, _adapter, policy = _guarded(pdb, tmp_path)

    # PLAN
    steps = [
        BrowserStep(action="navigate", url=servers["app"] + "/ok"),
        BrowserStep(action="observe"),
        BrowserStep(action="screenshot"),
    ]
    # AUTHORIZE (explicit; audited)
    policy.authorize_state_changes(note="pass4 e2e demonstration")

    guarded.start()
    try:
        outcome = run_browser_task(pdb, guarded, steps, engagement=host, scan_id=sid)
    finally:
        guarded.stop()

    # VERIFY
    assert outcome["state"] == "completed" and not outcome["pending"]
    evidence = pdb.query_evidence(scan_id=sid)
    assert len(evidence) == 3
    assert all(e["source"] == "browser" for e in evidence)
    shots = [e for e in evidence if e.get("screenshot_path")]
    assert shots and Path(shots[0]["screenshot_path"]).exists()

    # REPORT (existing contract machinery; does not replace NEXUS reporting)
    from lib.nemesis.contract import build_from_run

    contract = build_from_run(
        "pass4 e2e browser demonstration",
        [{"action": "browser", "status": "ok",
          "result": {"evidence_refs": [e["id"] for e in evidence]}}],
    )
    ok, issues = contract.check()
    assert ok, issues
    assert contract.to_dict()["EVIDENCE"]
