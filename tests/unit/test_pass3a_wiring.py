"""PASS 3A focused tests: PhaseRegistry → Coordinator wiring (fully offline).

Covers the audit gaps: registry selection, gate(), load_runner(),
with_optional(), the 8-state lifecycle (start/pause/resume/retry/stop/
checkpoint/recover) and the coordinator's optional-phase dispatch —
authn wiring, truthful blocking, intel opt-in, report state.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.coordinator import Coordinator, ScanOptions
from core.database import Database
from core.phase_registry import (
    PhaseRecord,
    PhaseRegistry,
    PhaseStateError,
    PhaseStateMachine,
)
from lib.config import load_config

CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"


# -- registry composition -----------------------------------------------------

def _registry() -> PhaseRegistry:
    return PhaseRegistry().with_optional()


def test_with_optional_keeps_core_then_adds_optional():
    names = [r.name for r in _registry().all_phases()]
    assert names[:4] == ["discover", "probe", "verify", "analyze"]
    for opt in ("authn", "authz", "takeover", "network", "cloud", "intel", "report"):
        assert opt in names


def test_intel_is_opt_in_by_default():
    cfg = load_config(CONFIG_DIR)
    enabled = {r.name for r in _registry().enabled_phases(cfg)}
    assert "intel" not in enabled  # per-scan NVD fetch must be explicit

    class _Cfg:
        phases = {"intel": {"enabled": True}}

    assert "intel" in {r.name for r in _registry().enabled_phases(_Cfg())}


def test_phase_can_be_disabled_via_config():
    class _Cfg:
        phases = {"authn": {"enabled": False}}

    enabled = {r.name for r in _registry().enabled_phases(_Cfg())}
    assert "authn" not in enabled
    assert "probe" in enabled


# -- gates --------------------------------------------------------------------

def test_gate_scope_profile_identity_capability():
    reg = _registry()
    rec = {r.name: r for r in reg.all_phases()}

    ok, reason = reg.gate(rec["network"], scope_kind="public", profile="deep")
    assert not ok and "ip" in reason
    ok, _ = reg.gate(rec["network"], scope_kind="ip", profile="deep")
    assert ok

    ok, reason = reg.gate(rec["cloud"], scope_kind="public")
    assert not ok and "cloud" in reason
    ok, _ = reg.gate(rec["cloud"], scope_kind="cloud")
    assert ok

    ok, reason = reg.gate(rec["takeover"], profile="standard")
    assert not ok and "profile" in reason
    ok, _ = reg.gate(rec["takeover"], profile="deep")
    assert ok

    ok, reason = reg.gate(rec["authz"], identities=1)
    assert not ok and "identities" in reason
    ok, _ = reg.gate(rec["authz"], identities=2)
    assert ok

    class _G:
        def __init__(self, caps):
            self.caps = caps

        def has_capability(self, c):
            return c in self.caps

    ok, reason = reg.gate(rec["authn"], graph=_G(set()))
    assert not ok and "capability" in reason
    ok, _ = reg.gate(rec["authn"], graph=_G({"login"}))
    assert ok


def test_load_runner_returns_real_callables():
    reg = _registry()
    rec = {r.name: r for r in reg.all_phases()}
    for name in ("authn", "authz", "takeover", "intel"):
        assert callable(reg.load_runner(rec[name])), name
    # network/cloud runners may still be absent → None (blocked truthfully)
    for name in ("network", "cloud"):
        runner = reg.load_runner(rec[name])
        assert runner is None or callable(runner)


def test_load_runner_unknown_module_returns_none():
    reg = _registry()
    assert reg.load_runner(PhaseRecord(name="ghost", runner="no.such.mod:fn")) is None


# -- lifecycle ----------------------------------------------------------------

def test_phase_state_machine_full_lifecycle(tmp_path):
    db = Database(tmp_path / "life.db")
    tid = db.upsert_target("example.com")
    sid = db.create_scan(tid)

    m = PhaseStateMachine(db, sid, PhaseRecord(name="authn"))
    assert m.state == "pending"
    m.start()
    assert m.state == "running"
    with pytest.raises(PhaseStateError):
        m.start()  # double start is illegal
    m.pause()
    assert m.state == "paused"
    with pytest.raises(PhaseStateError):
        m.complete()  # cannot complete from paused
    m.resume()
    assert m.state == "running"
    m.checkpoint({"step": 1})  # never raises
    m.complete()
    assert m.state == "completed"
    with pytest.raises(PhaseStateError):
        m.start()  # terminal states are final

    m2 = PhaseStateMachine(db, sid, PhaseRecord(name="authz"))
    m2.block("needs >=2 identities")
    assert m2.state == "blocked"
    m2.start()  # blocked phases are re-runnable once the gate opens
    m2.stop("boom")
    assert m2.state == "failed"
    m2.retry()
    assert m2.state == "running"
    m2.complete(partial=True)
    assert m2.state == "partial"

    # recover(): a row left `running` (crash) becomes `failed`
    m3 = PhaseStateMachine(db, sid, PhaseRecord(name="takeover"))
    m3.start()
    m4 = PhaseStateMachine.recover(db, sid, PhaseRecord(name="takeover"))
    assert m4.state == "failed"
    db.close()


# -- coordinator integration --------------------------------------------------

def _patch_offline(monkeypatch):
    """Deterministic discover/probe doubles + zero network in the collector."""

    def fake_discover(cfg, target_config, results_dir, db=None, scan_id=None, **kwargs):
        from lib.filtration import FiltrationPipeline

        (results_dir / "recon").mkdir(parents=True, exist_ok=True)
        urls = [
            f"https://{target_config.domain}/",
            f"https://{target_config.domain}/login",
        ]
        summary = {
            "domain": target_config.domain,
            "urls": urls,
            "pegpon": {"subdomains": [target_config.domain]},
            "wappalyzer": {"tech": {"WordPress": "6.0"}},
        }
        (results_dir / "recon" / "summary.json").write_text(
            json.dumps(summary), encoding="utf-8"
        )
        if db is not None and scan_id is not None:
            # Real graph ingestion so AUTHN's capability gate is observable.
            FiltrationPipeline(db, target_config, scan_id=scan_id).ingest(
                "fake-discover", "discover", urls, kind="url"
            )
        return summary

    def fake_probe(cfg, target_config, results_dir, urls, tech, **kwargs):
        (results_dir / "scans").mkdir(parents=True, exist_ok=True)
        findings: list = []
        (results_dir / "scans" / "raw_findings.json").write_text(
            json.dumps(findings), encoding="utf-8"
        )
        return findings

    monkeypatch.setattr("phases.discover.recon_orchestrator.run_discover", fake_discover)
    monkeypatch.setattr("phases.probe.probe_orchestrator.run_probe", fake_probe)
    # Offline: never actually fetch the fake URLs.
    monkeypatch.setattr(
        "lib.http_collector.HttpCollector.collect", lambda self, urls: []
    )


def _coord(tmp_path):
    cfg = load_config(CONFIG_DIR)
    db = Database(tmp_path / "p3a.db")
    return cfg, db, Coordinator(cfg, db=db, results_base=tmp_path / "results")


def test_optional_phases_gated_and_authn_wired(tmp_path, monkeypatch):
    _patch_offline(monkeypatch)
    cfg, db, coord = _coord(tmp_path)
    result = coord.run_scan(ScanOptions(target="example.com"))
    assert result["status"] == "completed", result.get("error")

    states = result["phase_states"]
    # authn ran for real (login URL observed on the graph) …
    assert states["authn"] == "completed"
    assert result["phases"]["authn"]["surfaces"] >= 1
    # … every other optional cycle was truthfully gated off …
    assert states["authz"] == "blocked"
    assert states["takeover"] == "blocked"
    assert states["network"] == "blocked"
    assert states["cloud"] == "blocked"
    # intel stays opt-in (no NVD traffic on the default path)
    assert "intel" not in states
    # the report phase row reflects the real report write
    assert states["report"] == "completed"
    assert Path(result["report"]).exists()

    # persistence: phase_runs + authn evidence + artifacts
    assert db.get_phase_run(result["scan_id"], "authn")["state"] == "completed"
    results_dir = Path(result["results_dir"])
    assert (results_dir / "authn" / "authn.json").exists()
    evidence = db.query_evidence(scan_id=result["scan_id"])
    assert any(e.get("tool") == "authn" for e in evidence)
    db.close()


def test_intel_opt_in_dispatch(tmp_path, monkeypatch):
    _patch_offline(monkeypatch)
    called: dict = {}

    def fake_cve_scan(cfg, db, target, tech_stack=None, **kwargs):
        called["target"] = target
        return {"target": target, "candidates": 0, "matches": []}

    monkeypatch.setattr("lib.cve_workflow.run_cve_scan", fake_cve_scan)

    cfg, db, coord = _coord(tmp_path)
    cfg._main.setdefault("phases", {})["intel"] = {"enabled": True}
    result = coord.run_scan(ScanOptions(target="example.com"))
    assert result["status"] == "completed", result.get("error")
    assert result["phase_states"]["intel"] == "completed"
    assert called.get("target") == "example.com"
    db.close()


def test_takeover_runs_on_deep_profile(tmp_path, monkeypatch):
    _patch_offline(monkeypatch)
    cfg, db, coord = _coord(tmp_path)
    result = coord.run_scan(ScanOptions(target="example.com", intensity="full-scan"))
    assert result["status"] == "completed", result.get("error")
    # profile deep → takeover gate opens; no CNAME data → engine reports empty
    assert result["phase_states"]["takeover"] == "completed"
    assert result["phases"]["takeover"]["total"] == 0
    results_dir = Path(result["results_dir"])
    assert (results_dir / "takeover" / "takeover.json").exists()
    # network/cloud still demand explicit ip/cloud scope even in deep mode
    assert result["phase_states"]["network"] == "blocked"
    assert result["phase_states"]["cloud"] == "blocked"
    db.close()

