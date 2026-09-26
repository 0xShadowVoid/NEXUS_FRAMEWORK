"""Tests for Wave-2 additions: IDOR prober, logic detector, ops guard,
OpenAPI ingestion, SARIF export, platform fetchers, digest, serve."""
from __future__ import annotations

import json
from pathlib import Path

import nexus
from core.exporter import export_findings, export_sarif
from lib.idor_prober import IdorProber
from lib.logic_detector import detect_logic_flaws
from lib.ops_guard import KillSwitch, set_request_budget, spend_requests
from lib.openapi import endpoints_from_file, endpoints_to_urls, parse_openapi
from phases.hunt.api_fetcher import fetch_intigriti_programs, fetch_yeswehack_programs


# --- IDOR prober ----------------------------------------------------------


def test_idor_candidate_ids_path_and_query():
    prober = IdorProber(fetch=lambda u: "")
    assert prober._candidate_ids("https://x/api/users/5/profile") == [
        "https://x/api/users/6/profile",
        "https://x/api/users/4/profile",
    ]
    ids = prober._candidate_ids("https://x/item?id=10")
    assert "id=11" in ids[0]


def test_idor_probe_same_shape_yields_finding():
    def fetch(url):
        return '{"name":"user","email":"a@b.com"}'

    prober = IdorProber(fetch=fetch)
    finding = prober.probe("https://x/api/users/1/profile")
    assert finding and finding["vuln_type"] == "idor"
    assert finding["verification"]["verified"] is True


def test_idor_probe_different_shape_no_finding():
    def fetch(url):
        return '{"name":"user"}' if "1/" in url else '{"error":"not found"}'

    prober = IdorProber(fetch=fetch)
    assert prober.probe("https://x/api/users/1/profile") is None


# --- logic detector -------------------------------------------------------


def test_logic_detector_flags_price_param():
    findings = detect_logic_flaws(["https://x/checkout?price=100&item=1"])
    assert findings and findings[0]["payload"] == "logic pattern: price_manipulation"
    assert findings[0]["valid"] is None  # POTENTIAL only


def test_logic_detector_role_escalation():
    findings = detect_logic_flaws(["https://x/profile?role=admin"])
    assert findings[0]["severity"] == "P1"


def test_logic_detector_empty():
    assert detect_logic_flaws(["https://x/about"]) == []


# --- ops guard ------------------------------------------------------------


def test_request_budget_enforced():
    set_request_budget(2)
    assert spend_requests() is True
    assert spend_requests() is True
    assert spend_requests() is False
    set_request_budget(None)  # reset


def test_killswitch(tmp_path):
    ks = KillSwitch(tmp_path)
    assert ks.killed() is False
    ks.kill()
    assert ks.killed() is True
    ks.resume()
    assert ks.killed() is False


# --- OpenAPI --------------------------------------------------------------


def test_openapi_parse_and_urls(tmp_path):
    spec = {
        "paths": {
            "/users/{id}": {
                "get": {"operationId": "getUser", "parameters": [
                    {"name": "id", "in": "path", "required": True},
                ]},
                "post": {"operationId": "createUser", "parameters": []},
            }
        }
    }
    eps = parse_openapi(spec)
    assert len(eps) == 2
    urls = endpoints_to_urls("https://api.example.com", eps)
    assert any(u.startswith("https://api.example.com/users/") for u in urls)


def test_openapi_from_file(tmp_path):
    f = tmp_path / "swagger.json"
    f.write_text(json.dumps({"paths": {"/ping": {"get": {}}}}), encoding="utf-8")
    assert len(endpoints_from_file(f)) == 1


# --- SARIF -----------------------------------------------------------------


def test_export_sarif(tmp_path):
    findings = [{"vuln_type": "xss", "severity": "P2", "endpoint": "https://x/a",
                 "response_snippet": "proof"}]
    path = export_sarif("example.com", findings, out_base=tmp_path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["ruleId"] == "xss"
    assert doc["runs"][0]["results"][0]["level"] == "error"


def test_export_findings_sarif_via_router(tmp_path):
    from core.database import Database

    db = Database(tmp_path / "s.db")
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid)
    db.insert_finding(sid, "https://example.com/a", "xss", "P2", 90, valid=True)
    path = export_findings(
        "example.com", db.list_scans(target_id=tid), db.query_findings(scan_id=sid), [],
        fmt="sarif", out_base=tmp_path,
    )
    assert path.suffix == ".sarif"


# --- platform fetchers ------------------------------------------------------


def test_intigriti_fetcher_parses():
    class _Session:
        def get(self, url, params=None, headers=None, timeout=None):
            class _R:
                status_code = 200

                @staticmethod
                def json():
                    return [{"name": "Acme", "maxBounty": 1000, "domains": [{"endpoint": "acme.com"}]}]
            return _R()

    programs = fetch_intigriti_programs("key", session=_Session())
    assert programs and programs[0]["platform"] == "intigriti"
    assert programs[0]["type"] == "bb"
    assert programs[0]["in_scope"] == ["acme.com"]


def test_yeswehack_fetcher_parses():
    class _Session:
        def get(self, url, params=None, headers=None, timeout=None):
            class _R:
                status_code = 200

                @staticmethod
                def json():
                    return {"items": [{"title": "T", "bounty_reward": True,
                                       "scopes": [{"scope": "t.com"}]}]}
            return _R()

    programs = fetch_yeswehack_programs("key", session=_Session())
    assert programs and programs[0]["platform"] == "yeswehack"
    assert programs[0]["type"] == "bb"


def test_fetchers_skip_without_key():
    assert fetch_intigriti_programs("") == []
    assert fetch_yeswehack_programs("") == []


# --- serve -----------------------------------------------------------------


def test_serve_once_runs(tmp_path, monkeypatch):
    from lib.config import load_config

    cfg = load_config(Path(__file__).resolve().parent.parent.parent / "config")
    cfg._main["database"] = {"path": str(tmp_path / "s.db")}
    monkeypatch.setattr("nexus.load_config", lambda *a, **k: cfg)
    assert nexus.main(["serve", "--once"]) == 0
