"""Pass 3B — focused SSRF-guard tests for each protected request path.

Every test here is offline by design:
- blocked destinations are IP literals or metadata hostnames (no DNS);
- allowlisted destinations short-circuit the guard before resolution;
- sessions are doubles that record / refuse wire calls.
"""
from __future__ import annotations

from lib import ssrf_guard


class _RefuseSession:
    """Session double that fails the test if any request reaches the wire."""

    def __init__(self):
        self.calls = []
        self.headers = {}

    def get(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("network call attempted")


class _Resp:
    def __init__(self, status_code=200, payload=None, text="", headers=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text
        self.headers = headers or {}

    def json(self):
        return self._payload


# ---------------------------------------------------------------------------
# Guard core: blocked classes need no DNS; env allowlist short-circuits.
# ---------------------------------------------------------------------------

def test_guard_blocks_loopback_private_linklocal_and_metadata():
    for bad in (
        "http://127.0.0.1/hook",
        "http://10.0.0.8/hook",
        "http://192.168.1.1/hook",
        "http://172.16.4.5/hook",
        "http://[::1]/hook",
        "http://0.0.0.0/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "ftp://example.com/file",
    ):
        safe, _reason = ssrf_guard.is_safe_url(bad)
        assert not safe, bad


def test_guard_blocks_metadata_paths_without_dns():
    safe, reason = ssrf_guard.is_safe_url("https://cdn.example.com/latest/meta-data/")
    assert not safe and "metadata path" in reason


def test_guard_env_allowlist_short_circuits(monkeypatch):
    monkeypatch.setenv("SSRF_ALLOW", "internal.example.test")
    safe, reason = ssrf_guard.is_safe_url("http://internal.example.test/x")
    assert safe and reason == "explicitly allowed"


# ---------------------------------------------------------------------------
# phases/hunt/api_fetcher.py — four platform API paths
# ---------------------------------------------------------------------------

def test_api_fetcher_blocks_blocked_destinations(monkeypatch):
    from phases.hunt import api_fetcher as af

    session = _RefuseSession()
    monkeypatch.setattr(af, "H1_ENDPOINT", "http://127.0.0.1:8080/programs")
    assert af.fetch_hackerone_programs("u", "t", session=session) == []
    monkeypatch.setattr(af, "BUGCROWD_ENDPOINT", "http://169.254.169.254/programs")
    assert af.fetch_bugcrowd_programs("k", session=session) == []
    monkeypatch.setattr(af, "INTIGRITI_ENDPOINT", "http://10.0.0.9/programs")
    assert af.fetch_intigriti_programs("k", session=session) == []
    monkeypatch.setattr(af, "YESWEHACK_ENDPOINT", "http://192.168.7.7/programs")
    assert af.fetch_yeswehack_programs("k", session=session) == []
    assert session.calls == []


def test_api_fetcher_allows_fixed_public_endpoints(monkeypatch):
    from phases.hunt import api_fetcher as af

    class _Sess:
        def __init__(self):
            self.urls = []

        def get(self, url, **kwargs):
            self.urls.append(url)
            return _Resp(200, {"data": [], "programs": []})

    sess = _Sess()
    assert af.fetch_hackerone_programs("u", "t", session=sess) == []
    assert af.fetch_bugcrowd_programs("k", session=sess) == []
    assert len(sess.urls) == 2
    assert all(u.startswith("https://") for u in sess.urls)


# ---------------------------------------------------------------------------
# phases/discover/dorker.py — five engine paths
# ---------------------------------------------------------------------------

def test_dorker_blocks_blocked_engines(monkeypatch):
    from phases.discover import dorker as dk

    def _boom(*a, **k):
        raise AssertionError("network call attempted")

    def _new():
        d = dk.Dorker()
        monkeypatch.setattr(d.session, "get", _boom)
        return d

    monkeypatch.setattr(dk, "_DDG_URL", "http://127.0.0.1:81/html/")
    assert "ssrf blocked" in _new()._search_ddg("exposed_docs", "site:x ext:pdf").error

    monkeypatch.setattr(dk, "_GOOGLE_URL", "http://10.0.0.4/search")
    assert "ssrf blocked" in _new()._search_google("login_pages", "site:x").error

    monkeypatch.setattr(dk, "_BING_URL", "http://192.168.5.5/search")
    assert "ssrf blocked" in _new()._search_bing("login_pages", "site:x").error

    monkeypatch.setattr(dk, "_GITHUB_API_URL", "http://169.254.169.254/search/code")
    assert "ssrf blocked" in _new()._search_github("github_leaks", "q", token="t").error

    monkeypatch.setattr(dk, "_GITHUB_HTML_URL", "http://127.0.0.2/search")
    assert "ssrf blocked" in _new()._search_github("github_leaks", "q", token="").error


# ---------------------------------------------------------------------------
# phases/discover/wappalyzer_wrapper.py — target fetch path
# ---------------------------------------------------------------------------

def test_wappalyzer_blocks_blocked_targets(monkeypatch):
    from phases.discover import wappalyzer_wrapper as ww

    session = _RefuseSession()
    out = ww.WappalyzerWrapper(session=session).detect("http://169.254.169.254/")
    assert out["tech"] == {}
    out = ww.WappalyzerWrapper(session=session).detect(
        "http://127.0.0.1:8500/", extra_paths=["/login", "/admin"]
    )
    assert out["tech"] == {}
    assert session.calls == []


def test_wappalyzer_allowlisted_target_fetches():
    from phases.discover import wappalyzer_wrapper as ww

    class _Sess:
        def __init__(self):
            self.headers = {}
            self.urls = []

        def get(self, url, **kwargs):
            self.urls.append(url)
            return _Resp(200, text="", headers={"Server": "nginx/1.24.0"})

    sess = _Sess()
    out = ww.WappalyzerWrapper(session=sess, ssrf_allow={"internal.example.test"}).detect(
        "https://internal.example.test"
    )
    assert out["tech"].get("Nginx") == "1.24.0"
    assert sess.urls == ["https://internal.example.test"]


# ---------------------------------------------------------------------------
# lib/threat_feeds.py — KEV / EPSS / GHSA paths
# ---------------------------------------------------------------------------

def test_threat_feeds_blocks_blocked_destinations(monkeypatch):
    from lib import threat_feeds as tf

    session = _RefuseSession()
    monkeypatch.setattr(tf, "KEV_URL", "http://192.168.0.9/kev.json")
    assert tf.ThreatFeeds(session=session).fetch_kev() == set()
    monkeypatch.setattr(tf, "EPSS_URL", "http://169.254.169.254/epss")
    assert tf.ThreatFeeds(session=session).fetch_epss(["CVE-1"]) == {}
    monkeypatch.setattr(tf, "GHSA_URL", "http://127.0.0.1/advisories")
    assert tf.ThreatFeeds(session=session).fetch_ghsa() == []
    assert session.calls == []


# ---------------------------------------------------------------------------
# lib/cve_fetcher.py — NVD path
# ---------------------------------------------------------------------------

def test_cve_fetcher_blocks_blocked_destination(monkeypatch):
    from lib import cve_fetcher as cf

    session = _RefuseSession()
    monkeypatch.setattr(cf, "NVD_API_URL", "http://10.255.255.1/rest/json/cves/2.0")
    assert cf.CVEFetcher(session=session).fetch_recent() == []
    assert session.calls == []


# ---------------------------------------------------------------------------
# lib/notifications.py — webhook / bot alert paths
# ---------------------------------------------------------------------------

def test_notifications_block_private_and_metadata_webhooks(monkeypatch):
    from lib import notifications as nt

    def _boom(*a, **k):
        raise AssertionError("network call attempted")

    monkeypatch.setattr(nt.requests, "post", _boom)
    assert nt._post_with_retry("http://127.0.0.1:9000/hook", {}) is False
    assert nt._post_with_retry("http://169.254.169.254/hook", {}) is False

    class _Cfg:
        email = {}

        def webhook(self, kind):
            return "http://10.0.0.3/hook"

        def telegram(self):
            return ("111:token", "42")

    assert nt.Notifier(_Cfg()).send_finding({"vuln_type": "xss", "severity": "P1"}) is False


# ---------------------------------------------------------------------------
# phases/control/telegram_c2.py — send + poll paths
# ---------------------------------------------------------------------------

def test_telegram_c2_blocks_non_allowlisted_base(monkeypatch):
    from phases.control import telegram_c2 as tc

    def _boom(*a, **k):
        raise AssertionError("network call attempted")

    monkeypatch.setattr(tc, "_API_BASE", "http://127.0.0.1:9001/bot{token}")
    monkeypatch.setattr(tc.requests, "post", _boom)
    monkeypatch.setattr(tc.requests, "get", _boom)

    class _Router:
        pass

    c2 = tc.TelegramC2(_Router(), bot_token="t", chat_id="c")
    c2._stop.set()  # make any back-off immediate
    assert c2._send("hello") is False
    assert c2._poll_once(0) == 0


# ---------------------------------------------------------------------------
# lib/ai_analyzer.py — provider call path (metadata stays blocked)
# ---------------------------------------------------------------------------

def test_ai_analyzer_blocks_metadata_endpoint(monkeypatch):
    from lib.ai_analyzer import AIAnalyzer

    calls = []
    monkeypatch.setattr("lib.ai_analyzer.requests.post", lambda *a, **k: calls.append(a))

    analyzer = AIAnalyzer(
        env={"OPENAI_API_KEY": "k"},
        providers=["openai"],
        base_urls={"openai": "http://169.254.169.254/v1"},
    )
    assert analyzer.categorize_finding({"vuln_type": "xss"}) is None
    assert calls == []


# ---------------------------------------------------------------------------
# Redirect-hop hardening (recon-derived fetches)
# ---------------------------------------------------------------------------

def test_collector_blocks_redirect_to_blocked_hop(monkeypatch):
    from lib import http_collector as hc

    calls = []

    class _Resp:
        def __init__(self, status, location=""):
            self.status_code = status
            self.headers = {"Location": location} if location else {}
            self.text = ""

    def fake_get(url, **kwargs):
        calls.append((url, kwargs.get("allow_redirects")))
        if url.endswith("/start"):
            return _Resp(302, "http://169.254.169.254/latest/meta-data/")
        return _Resp(200)

    monkeypatch.setattr(hc.requests, "get", fake_get)
    monkeypatch.setattr(hc, "validate_finding_scope", lambda url, cfg: True)

    class _CfgT:
        domain = "example.com"

    collector = hc.HttpCollector(_CfgT(), ssrf_allow={"example.com"})
    out = collector.fetch("https://example.com/start")
    assert "ssrf blocked on redirect" in out.error
    assert all("169.254.169.254" not in u for u, _ in calls)
    assert calls[0][1] is False  # no unguarded auto-follow


def test_collector_follows_allowlisted_redirect_hop(monkeypatch):
    from lib import http_collector as hc

    class _Resp:
        def __init__(self, status, location="", text=""):
            self.status_code = status
            self.headers = {"Location": location} if location else {}
            self.text = text

    def fake_get(url, **kwargs):
        if url == "https://example.com/start":
            return _Resp(302, "https://second.example/final")
        return _Resp(200, text="final-page")

    monkeypatch.setattr(hc.requests, "get", fake_get)
    monkeypatch.setattr(hc, "validate_finding_scope", lambda url, cfg: True)

    class _CfgT:
        domain = "example.com"

    collector = hc.HttpCollector(_CfgT(), ssrf_allow={"example.com", "second.example"})
    out = collector.fetch("https://example.com/start")
    assert out.status_code == 200 and "final-page" in out.body


def test_wappalyzer_blocks_redirect_to_blocked_hop():
    from phases.discover import wappalyzer_wrapper as ww

    class _Sess:
        def __init__(self):
            self.headers = {}
            self.calls = []

        def get(self, url, **kwargs):
            self.calls.append((url, kwargs.get("allow_redirects")))

            class _R:
                status_code = 302
                headers = {"Location": "http://127.0.0.1:9000/"}
                text = ""

            return _R()

    sess = _Sess()
    out = ww.WappalyzerWrapper(session=sess, ssrf_allow={"example.com"}).detect("https://example.com/")
    assert out["tech"] == {}
    assert all("127.0.0.1" not in u for u, _ in sess.calls)
    assert sess.calls and sess.calls[0][1] is False
