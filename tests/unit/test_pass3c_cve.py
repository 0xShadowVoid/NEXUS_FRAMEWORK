"""Pass 3C — CVE version-range matching tests (offline)."""
from __future__ import annotations

from lib.cve_fetcher import CVEFetcher, match_tech, match_tech_ex
from lib.versioning import (
    VersionRange,
    aggregate_status,
    compare_versions,
    parse_version,
)


def _detail(product="server", vendor="acme", version="", **bounds):
    # Mirror the production extraction (VersionRange.from_cpe_match):
    # a bare criteria version becomes the range's ``exact`` bound.
    has_bounds = any(bounds.values())
    exact = "" if (has_bounds or version in ("", "*", "-")) else version
    return {
        "vendor": vendor,
        "product": product,
        "version": version,
        "range": VersionRange(exact=exact, **bounds),
    }


def _cve(details=None, products=None, **extra):
    cve = {
        "cve_id": "CVE-2026-0001",
        "severity": "high",
        "affected_products": products if products is not None else ["acme:server"],
        "affected_details": details or [],
    }
    cve.update(extra)
    return cve


# --- versioning core ----------------------------------------------------------

def test_parse_version_basic():
    assert parse_version("6.0") == ([6, 0], "")
    assert parse_version("v1.2.3-rc1") == ([1, 2, 3], "rc1")
    assert parse_version("not-a-version") is None
    assert parse_version("") is None


def test_compare_versions_ordering():
    assert compare_versions("1.2.3", "1.2.3") == 0
    assert compare_versions("1.2.3", "1.2.4") < 0
    assert compare_versions("1.10", "1.9") > 0          # numeric, not lexical
    assert compare_versions("2.0", "2") == 0            # zero padding
    assert compare_versions("1.0", "1.0-rc1") > 0       # release > prerelease
    assert compare_versions("bad", "1.0") is None


def test_range_inclusive_exclusive_bounds():
    inc = VersionRange(start_including="1.0", end_including="2.0")
    assert inc.evaluate("1.0") == "affected"
    assert inc.evaluate("1.5") == "affected"
    assert inc.evaluate("2.0") == "affected"
    assert inc.evaluate("2.1") == "unaffected"
    exc = VersionRange(start_excluding="1.0", end_excluding="2.0")
    assert exc.evaluate("1.0") == "unaffected"
    assert exc.evaluate("1.5") == "affected"
    assert exc.evaluate("2.0") == "unaffected"


def test_range_single_bounds():
    lower = VersionRange(start_including="1.5")
    assert lower.evaluate("1.5") == "affected"
    assert lower.evaluate("9.9") == "affected"
    assert lower.evaluate("1.4") == "unaffected"
    upper = VersionRange(end_excluding="3.0")
    assert upper.evaluate("2.9") == "affected"
    assert upper.evaluate("3.0") == "unaffected"


def test_range_unknown_and_malformed():
    assert VersionRange().evaluate("1.0") == "unknown"
    assert VersionRange(start_including="1.0").evaluate("junk") == "unknown"
    assert VersionRange(start_including="junk").evaluate("1.0") == "unknown"


def test_aggregate_status_precedence():
    assert aggregate_status(["unaffected", "affected"]) == "affected"
    assert aggregate_status(["unaffected", "unknown"]) == "unknown"
    assert aggregate_status(["candidate", "unaffected"]) == "candidate"
    assert aggregate_status(["unaffected", "unaffected"]) == "unaffected"
    assert aggregate_status([]) == "candidate"


# --- matcher behavior ----------------------------------------------------------

def test_exact_affected_version():
    cve = _cve(details=[_detail(version="1.0")])
    matches, report = match_tech_ex([cve], {"Acme Server": "1.0"})
    assert len(matches) == 1
    assert report["affected"] == 1
    assert cve["applicability"] == "affected"
    assert cve["version_evidence"][0]["verdict"] == "affected"


def test_exact_unaffected_version_excluded():
    cve = _cve(details=[_detail(start_including="1.0", end_including="1.9")])
    matches, report = match_tech_ex([cve], {"Acme Server": "2.0"})
    assert matches == []
    assert report["unaffected"] == 1


def test_bare_version_mismatch_stays_candidate():
    cve = _cve(details=[_detail(version="1.0")])
    matches, report = match_tech_ex([cve], {"Acme Server": "2.0"})
    assert len(matches) == 1
    assert cve["applicability"] == "candidate"
    assert report["candidate"] == 1


def test_multiple_affected_ranges():
    details = [
        _detail(start_including="1.0", end_including="1.9"),
        _detail(start_including="2.5", end_including="2.9"),
    ]
    in_range = _cve(details=details)
    out_of_range = _cve(details=details)
    assert len(match_tech([in_range], {"Acme Server": "2.7"})) == 1
    assert in_range["applicability"] == "affected"
    assert match_tech([out_of_range], {"Acme Server": "2.2"}) == []


def test_unknown_and_malformed_versions():
    cve_unknown = _cve(details=[_detail(start_including="1.0")])
    matches, _report = match_tech_ex([cve_unknown], {"Acme Server": "x.y.z"})
    assert len(matches) == 1 and cve_unknown["applicability"] == "unknown"

    cve_noversion = _cve(details=[_detail(start_including="1.0")])
    matches2, _ = match_tech_ex([cve_noversion], {"Acme Server": ""})
    assert len(matches2) == 1 and cve_noversion["applicability"] == "candidate"


def test_product_name_only_match_is_candidate():
    cve = _cve(details=[], products=["acme:server"])
    matches, report = match_tech_ex([cve], {"Acme": "1.0"})
    assert len(matches) == 1
    assert cve["applicability"] == "candidate"
    assert report["candidate"] == 1


def test_cpe_mismatch_no_match():
    cve = _cve(details=[_detail(product="nginx", vendor="nginx", start_including="1.0")])
    assert match_tech([cve], {"Apache Server": "2.4.1"}) == []


def test_legacy_product_list_still_matches():
    cve = {"cve_id": "CVE-1", "affected_products": ["wordpress:wp_plugin"], "severity": "critical"}
    matches = match_tech([cve], {"WordPress": "6.0"})
    assert matches and matches[0][0]["cve_id"] == "CVE-1"
    assert match_tech([cve], {"Nginx": "1.0"}) == []


def test_cve_fetcher_extracts_version_details():
    payload = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2026-4242",
                "published": "2026-09-25T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Acme server flaw."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}}]},
                "configurations": [{"nodes": [{"cpeMatch": [{
                    "criteria": "cpe:2.3:a:acme:server:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "1.0",
                    "versionEndExcluding": "2.0",
                    "vulnerable": True,
                }]}]}],
            }
        }]
    }

    class _Sess:
        headers: dict = {}

        def get(self, url, params=None, headers=None, timeout=None):
            class _R:
                status_code = 200

                @staticmethod
                def json():
                    return payload

            return _R()

    cves = CVEFetcher(session=_Sess()).fetch_recent(hours=24, min_severity="high")
    assert len(cves) == 1
    details = cves[0]["affected_details"]
    assert details and details[0]["product"] == "server"
    assert details[0]["range"].evaluate("1.5") == "affected"
    assert details[0]["range"].evaluate("2.0") == "unaffected"

    matches, report = match_tech_ex(cves, {"Acme Server": "1.5"})
    assert len(matches) == 1 and report["affected"] == 1
    assert match_tech(cves, {"Acme Server": "3.0"}) == []


def test_prioritization_preserved_through_matching():
    cve_kev = _cve(cve_id="CVE-2026-1000", details=[_detail(start_including="1.0")],
                   kev=True, priority=0, epss=0.9)
    cve_plain = _cve(cve_id="CVE-2026-1001", details=[_detail(start_including="1.0")],
                     kev=False, priority=1, epss=0.1)
    matches, _report = match_tech_ex([cve_plain, cve_kev], {"Acme Server": "1.5"})
    ordered = sorted(
        matches,
        key=lambda pair: (int(pair[0].get("priority", 1)), -float(pair[0].get("epss", 0.0))),
    )
    assert [m[0]["cve_id"] for m in ordered] == ["CVE-2026-1000", "CVE-2026-1001"]
    assert ordered[0][0]["kev"] is True and ordered[0][0]["epss"] == 0.9
