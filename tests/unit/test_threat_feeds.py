"""Unit tests for threat-intel feeds (KEV + EPSS) — offline."""
from __future__ import annotations

import requests

from lib.threat_feeds import (
    ThreatFeeds,
    enrich_cves,
    epss_interesting_count,
    sort_by_priority,
)

KEV_FIXTURE = {
    "vulnerabilities": [
        {"cveID": "CVE-2026-0001", "vendorProject": "Acme"},
        {"cveID": "CVE-2026-0002", "vendorProject": "Globex"},
    ]
}

EPSS_FIXTURE = {
    "data": [
        {"cve": "CVE-2026-0001", "epss": "0.91"},
        {"cve": "CVE-2026-0003", "epss": "0.12"},
    ]
}


class _Resp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _Session:
    def __init__(self, kev=None, epss=None, fail=()):
        self.kev = kev or KEV_FIXTURE
        self.epss = epss or EPSS_FIXTURE
        self.fail = set(fail)
        self.calls = []

    def get(self, url, params=None, timeout=None):
        self.calls.append((url, params))
        if "kev" in url or "known_exploited" in url:
            if "kev" in self.fail:
                return _Resp(500, {})
            return _Resp(200, self.kev)
        if "epss" in url:
            if "epss" in self.fail:
                raise requests.RequestException("blocked")
            return _Resp(200, self.epss)
        return _Resp(404, {})


def test_fetch_kev_parses_fixture():
    feeds = ThreatFeeds(session=_Session())
    ids = feeds.fetch_kev()
    assert ids == {"CVE-2026-0001", "CVE-2026-0002"}


def test_fetch_kev_http_error_returns_empty():
    feeds = ThreatFeeds(session=_Session(fail=("kev",)))
    assert feeds.fetch_kev() == set()


def test_fetch_epss_parses_fixture():
    feeds = ThreatFeeds(session=_Session())
    scores = feeds.fetch_epss(["CVE-2026-0001", "CVE-2026-0003"])
    assert scores["CVE-2026-0001"] == 0.91
    assert scores["CVE-2026-0003"] == 0.12


def test_fetch_epss_transport_error_returns_empty():
    feeds = ThreatFeeds(session=_Session(fail=("epss",)))
    assert feeds.fetch_epss(["CVE-2026-0001"]) == {}


def test_fetch_epss_malformed_json_returns_empty():
    class _Bad(_Session):
        def get(self, url, params=None, timeout=None):
            if "epss" in url:
                raise ValueError("bad json")
            return super().get(url, params, timeout)

    assert ThreatFeeds(session=_Bad()).fetch_epss(["CVE-1"]) == {}


def test_enrich_cves_sets_kev_epss_priority():
    cves = [
        {"cve_id": "CVE-2026-0001"},   # KEV + high EPSS
        {"cve_id": "CVE-2026-0003"},   # not KEV, medium EPSS
        {"cve_id": "CVE-2026-9999"},   # unknown
    ]
    out = enrich_cves(cves, feeds=ThreatFeeds(session=_Session()))
    assert out[0]["kev"] is True and out[0]["priority"] == 0
    assert out[0]["epss"] == 0.91
    assert out[1]["kev"] is False and out[1]["priority"] == 1
    assert out[2]["epss"] == 0.0


def test_sort_by_priority_kev_first_then_epss():
    cves = [
        {"cve_id": "A", "priority": 1, "epss": 0.9},
        {"cve_id": "B", "priority": 0, "epss": 0.1},
        {"cve_id": "C", "priority": 1, "epss": 0.95},
    ]
    ordered = [c["cve_id"] for c in sort_by_priority(cves)]
    assert ordered[0] == "B"           # KEV wins regardless of EPSS
    assert ordered[1:] == ["C", "A"]   # then EPSS desc


def test_epss_interesting_count():
    cves = [{"epss": 0.9}, {"epss": 0.5}, {"epss": 0.1}]
    assert epss_interesting_count(cves) == 2
