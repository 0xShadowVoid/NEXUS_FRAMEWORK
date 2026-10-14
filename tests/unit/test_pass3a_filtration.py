"""PASS 3A focused tests: filtration pipeline stages + probe ingestion."""
from __future__ import annotations

import json
from pathlib import Path

from core.coordinator import Coordinator, ScanOptions
from core.database import Database
from lib.config import load_config
from lib.filtration import FiltrationPipeline, classify_kind

CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"


def _pipeline(db, domain="example.com", scan_id=None):
    cfg = load_config(CONFIG_DIR)
    tc = cfg.target(domain)
    return FiltrationPipeline(db, tc, scan_id=scan_id)


# -- stages -------------------------------------------------------------------

def test_raw_count_and_parse_stages():
    assert FiltrationPipeline.raw_count(None) == 0
    assert FiltrationPipeline.raw_count("a.example.com\n\nb.example.com\n") == 2
    assert FiltrationPipeline.raw_count(["a", "b", ""]) == 3
    assert FiltrationPipeline.raw_count({"value": "x.example.com"}) == 1

    items, errors = FiltrationPipeline.parse("a.example.com\n\nb.example.com\n")
    assert [i["value"] for i in items] == ["a.example.com", "b.example.com"]
    assert errors == 0

    items, errors = FiltrationPipeline.parse(
        ["ok.example.com", None, 123, {"url": "https://ok.example.com/x"}]
    )
    # None is silently dropped; non-str/dict units count as parse errors.
    assert [i["value"] for i in items] == ["ok.example.com", "https://ok.example.com/x"]
    assert errors == 1

    items, errors = FiltrationPipeline.parse({"endpoint": "https://ok.example.com/y"})
    assert items[0]["value"] == "https://ok.example.com/y"
    assert errors == 0


def test_classify_kind_aliases_and_inference():
    assert classify_kind("https://x.example.com/", "urls") == "url"
    assert classify_kind("a.example.com", "subdomains") == "subdomain"
    assert classify_kind("https://x.example.com/api", "raw_findings") == "endpoint"
    assert classify_kind("a.example.com") == "subdomain"          # inferred
    assert classify_kind("1.2.3.4") == "ip"                      # inferred
    assert classify_kind("anything", "customkind") == "customkind"


# -- ingest -------------------------------------------------------------------

def test_ingest_accounts_every_stage_and_persists(db):
    pipe = _pipeline(db, scan_id=None)
    raw = [
        "https://example.com/login",        # new (in scope)
        "https://example.com/login",        # duplicate of the first
        "https://OTHER.com/x",              # out of scope → filtered
        {"url": "https://example.com/api"}, # dict form → new
    ]
    stats = pipe.ingest("toolx", "discover", raw, kind="url")
    d = stats.to_dict()
    assert d["total"] == 4 and d["parsed_total"] == 4
    assert d["new"] == 2 and d["duplicates"] == 1 and d["filtered"] == 1
    assert d["valid"] == 3 and d["errors"] == 0
    assert d["source"] == "toolx"
    assert 0.0 < d["unique_yield"] <= 1.0


def test_ingest_parses_line_string_with_errors(db):
    pipe = _pipeline(db)
    stats = pipe.ingest("dnstool", "discover", ["a.example.com", 123], kind="subdomain")
    d = stats.to_dict()
    assert d["total"] == 2        # RAW units
    assert d["parsed_total"] == 1 # one coerced into an item record
    assert d["errors"] == 1       # unparseable unit counted, never raised
    assert d["new"] == 1


def test_ingest_persists_stats_and_graph(db):
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid)
    pipe = _pipeline(db, scan_id=sid)
    stats = pipe.ingest("tooly", "probe", ["https://example.com/a"], kind="endpoint")
    assert stats.stats_id is not None
    rows = db.list_filtration_stats(sid)
    assert rows and rows[-1]["tool"] == "tooly"
    assert rows[-1]["totals"]["parsed_total"] == 1
    # graph got the asset with provenance
    asset = db.get_asset("endpoint", "example.com/a")
    assert asset is not None and asset["source_tool"] == "tooly"


# -- dorking ingestion fix (recon) --------------------------------------------

def test_dork_ingest_uses_urls_not_intent_keys(tmp_path, monkeypatch):
    cfg = load_config(CONFIG_DIR)
    db = Database(tmp_path / "dork.db")
    from phases.discover import recon_orchestrator

    def fake_pegpon(domain, runner, results_dir, with_subdomains=True):
        return {"subdomains": [domain], "urls": [], "tools_run": [],
                "tools_skipped": [], "tools_failed": []}

    class _FakeDorker:
        def run(self, domain, github_token="", engines=None):
            return {
                "by_intent": {"login_pages": [f"https://{domain}/login"]},
                "urls_found": 1, "queries_run": 1, "errors": 0,
            }

    class _FakeWapp:
        def detect(self, url, **kw):
            return {"url": url, "tech": {}}

    monkeypatch.setattr("phases.discover.recon_orchestrator.run_pegpon", fake_pegpon)
    monkeypatch.setattr("phases.discover.recon_orchestrator.Dorker", _FakeDorker)
    monkeypatch.setattr("phases.discover.recon_orchestrator.WappalyzerWrapper", _FakeWapp)

    summary = recon_orchestrator.run_discover(
        cfg, cfg.target("example.com"), tmp_path / "out", deep=False,
        dorking=True, db=db, scan_id=None,
    )
    # The URL itself was ingested …
    assert db.get_asset("url", "example.com/login") is not None
    # … and the intent KEY was NOT mistaken for a URL.
    assert db.get_asset("url", "login_pages") is None
    assert any(s["tool"] == "dorker" for s in summary["filtration"])
    db.close()
