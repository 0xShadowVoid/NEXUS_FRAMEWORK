"""Pass 5 â€” network engine unit tests (deterministic, offline)."""
from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from lib.config import load_config
from lib.paths import CONFIG_DIR
from lib.scope_validator import (
    classify_ip,
    explicit_ip_grant,
    ip_allowed_for_target,
    is_ip_literal,
)
from phases.network import net_orchestrator as no
from phases.network.engine import NetSettings, NetworkEngine, PortResult, parse_ports


def _tcfg(**overrides):
    cfg = load_config(CONFIG_DIR)
    tcfg = cfg.target("example.com")
    for key, value in overrides.items():
        setattr(tcfg, key, value)
    return tcfg


# --- IP / CIDR scope -----------------------------------------------------------------

def test_classify_ip_categories():
    assert classify_ip("8.8.8.8") == "public"
    assert classify_ip("10.0.0.5") == "private"
    assert classify_ip("127.0.0.1") == "loopback"
    assert classify_ip("169.254.169.254") == "metadata"
    assert classify_ip("169.254.1.10") == "link_local"
    assert classify_ip("::1") == "loopback"
    assert classify_ip("::ffff:10.0.0.1") == "private"      # v4-mapped normalised
    assert classify_ip("junk") == "invalid"
    assert is_ip_literal("10.1.2.3") and not is_ip_literal("example.com")


def test_cidr_grant_boundaries_and_two_key_rule():
    tcfg = _tcfg(in_scope=["10.20.30.0/24"], out_of_scope=[])
    assert explicit_ip_grant("10.20.30.5", tcfg) == "10.20.30.0/24"
    assert explicit_ip_grant("10.20.31.5", tcfg) == ""       # boundary outside
    ok, _ = ip_allowed_for_target("10.20.30.5", tcfg, allow_private=True)
    assert ok
    ok2, why2 = ip_allowed_for_target("10.20.30.5", tcfg, allow_private=False)
    assert not ok2 and "allow_private" in why2               # two-key rule
    ok3, _ = ip_allowed_for_target("10.20.31.5", tcfg, allow_private=True)
    assert not ok3                                            # no grant


def test_forbidden_classes_need_explicit_grant():
    tcfg = _tcfg(in_scope=["example.com"], out_of_scope=[])
    for bad in ("127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1", "::1"):
        ok, why = ip_allowed_for_target(bad, tcfg, allow_private=True)
        assert not ok and "grant" in why, bad


def test_metadata_and_loopback_with_grant_still_need_allow_private():
    tcfg = _tcfg(in_scope=["127.0.0.1"], out_of_scope=[])
    ok, _ = ip_allowed_for_target("127.0.0.1", tcfg, allow_private=False)
    assert not ok
    ok2, _ = ip_allowed_for_target("127.0.0.1", tcfg, allow_private=True)
    assert ok2


def test_oos_network_wins_over_grant():
    tcfg = _tcfg(in_scope=["10.0.0.0/8"], out_of_scope=["10.9.0.0/16"])
    ok, why = ip_allowed_for_target("10.9.1.1", tcfg, allow_private=True)
    assert not ok and "out of scope" in why
    ok2, _ = ip_allowed_for_target("10.8.1.1", tcfg, allow_private=True)
    assert ok2


def test_ipv6_grant():
    tcfg = _tcfg(in_scope=["fd12:3456::/32"], out_of_scope=[])
    assert explicit_ip_grant("fd12:3456::5", tcfg) == "fd12:3456::/32"
    ok, _ = ip_allowed_for_target("fd12:3456::5", tcfg, allow_private=True)
    assert ok
    ok2, why2 = ip_allowed_for_target("fd99::5", tcfg, allow_private=True)
    assert not ok2 and "grant" in why2
    assert explicit_ip_grant("2001:db9::5", _tcfg(in_scope=["2001:db8::/32"])) == ""


def test_ip_literal_target_requires_grant():
    tcfg = _tcfg(in_scope=["example.com"], out_of_scope=[])
    ok, why = ip_allowed_for_target("93.184.216.34", tcfg, require_grant=True)
    assert not ok and "explicit" in why


# --- port plan ------------------------------------------------------------------------

def test_parse_ports_defaults_ranges_and_cap():
    ports, over = parse_ports([], 512)
    assert ports == sorted(set(ports)) and len(ports) > 10 and over == 0
    ports2, _ = parse_ports(["80", "443", "8000-8002", "bad", 70000], 512)
    assert ports2 == [80, 443, 8000, 8001, 8002]
    ports3, over3 = parse_ports(["1-100"], 10)
    assert len(ports3) == 10 and over3 == 90


# --- engine ---------------------------------------------------------------------------

def _engine(connect=None, cancel_event=None, **kw):
    settings = NetSettings(
        ports=(80, 443), concurrency=4, connect_timeout=0.01, probe_timeout=0.01, **kw
    )
    return NetworkEngine(settings, connect=connect, cancel_event=cancel_event)


def test_engine_connect_state_mapping():
    def fake_connect(ip, port, timeout):
        return {80: "open", 443: "closed"}[port]

    results = _engine(fake_connect).scan("10.0.0.5", [80, 443])
    assert [r.state for r in results] == ["open", "closed"]


def test_engine_connect_exception_is_filtered():
    def fake_connect(ip, port, timeout):
        raise TimeoutError("no response")

    results = _engine(fake_connect).scan("10.0.0.5", [80, 443])
    assert {r.state for r in results} == {"filtered"}


def test_engine_budget_exhaustion_marks_skipped(monkeypatch):
    from lib import ops_guard

    ops_guard.set_request_budget(1)
    try:
        calls = []

        def fake_connect(ip, port, timeout):
            calls.append(port)
            return "open"

        results = _engine(fake_connect).scan("10.0.0.5", [80, 443])
        assert sorted(r.state for r in results) == ["open", "skipped"]
        assert len(calls) == 1
    finally:
        ops_guard.set_request_budget(None)


def test_engine_cancellation_leaves_untested():
    cancel = threading.Event()
    cancel.set()
    results = _engine(lambda ip, port, t: "open", cancel_event=cancel).scan("10.0.0.5", [80, 443])
    assert {r.state for r in results} == {"untested"}


def test_engine_per_task_check_rejection_is_skipped():
    results = _engine(lambda ip, port, t: "open").scan(
        "10.0.0.5", [80, 443], per_task_check=lambda ip, port: False
    )
    assert {r.state for r in results} == {"skipped"}


def test_engine_concurrency_cap_honored():
    active = {"now": 0, "max": 0}
    lock = threading.Lock()

    def fake_connect(ip, port, timeout):
        with lock:
            active["now"] += 1
            active["max"] = max(active["max"], active["now"])
        time.sleep(0.02)
        with lock:
            active["now"] -= 1
        return "open"

    settings = NetSettings(ports=tuple(range(1, 13)), concurrency=3,
                           connect_timeout=0.01, probe_timeout=0.01)
    engine = NetworkEngine(settings, connect=fake_connect)
    results = engine.scan("10.0.0.5", list(range(1, 13)))
    assert len(results) == 12
    assert active["max"] <= 3


# --- service identification -------------------------------------------------------------

def test_service_identification_banner_and_malformed(monkeypatch):
    engine = _engine()
    res = PortResult("10.0.0.5", 22, "open")
    monkeypatch.setattr(engine, "_read_banner", lambda ip, port: "SSH-2.0-OpenSSH_9.2")
    assert engine.identify(res).service == "ssh"

    res2 = PortResult("10.0.0.5", 25, "open")
    monkeypatch.setattr(engine, "_read_banner", lambda ip, port: "\x00\xff garbage")
    out2 = engine.identify(res2)
    assert out2.service  # never raises on malformed input

    res3 = PortResult("10.0.0.5", 21, "open")

    def _boom(ip, port):
        raise RuntimeError("connection died")

    monkeypatch.setattr(engine, "_read_banner", _boom)
    assert engine.identify(res3).service == "unknown"


def test_service_identification_http_probe(monkeypatch):
    engine = _engine()
    res = PortResult("10.0.0.5", 8080, "open")
    monkeypatch.setattr(
        engine, "_http_probe",
        lambda ip, port, tls=False: {"status": "HTTP/1.1 200 OK", "server": "nginx/1.24"},
    )
    out = engine.identify(res)
    assert out.service == "http" and "nginx" in out.banner


def test_legacy_tls_flagged(monkeypatch):
    engine = _engine()
    res = PortResult("10.0.0.5", 443, "open")
    monkeypatch.setattr(engine, "_tls_meta", lambda ip, port: {"protocol": "TLSv1"})
    monkeypatch.setattr(engine, "_http_probe", lambda ip, port, tls=False: {})
    out = engine.identify(res)
    assert out.meta.get("legacy_tls") is True


# --- orchestrator wiring -------------------------------------------------------------------

def _prep(monkeypatch, *, in_scope, allow_private, ports=None):
    cfg = load_config(CONFIG_DIR)
    cfg._main.setdefault("phases", {})["network"] = {
        "enabled": True,
        "ports": ports or ["80", "443"],
        "concurrency": 4,
        "connect_timeout": 0.01,
        "probe_timeout": 0.01,
        "max_ports": 512,
        "allow_private": allow_private,
    }
    tcfg = cfg.target("example.com")
    tcfg.in_scope = in_scope
    return cfg, tcfg


def _run(cfg, tcfg, db, tmp_path, sid=None):
    if sid is None:
        sid = db.create_scan(db.upsert_target("example.com"))
    return no.run_network(cfg, tcfg, tmp_path / "results", db=db, scan_id=sid), sid


def test_orchestrator_out_of_scope_blocked(db, tmp_path, monkeypatch):
    cfg, tcfg = _prep(monkeypatch, in_scope=["other-domain.com"], allow_private=False)
    out, _sid = _run(cfg, tcfg, db, tmp_path)
    assert out["status"] == "blocked" and out["phase_state"] == "blocked"


def test_orchestrator_private_rejected_without_grant(db, tmp_path, monkeypatch):
    cfg, tcfg = _prep(monkeypatch, in_scope=["example.com"], allow_private=True)
    monkeypatch.setattr(no, "_resolve_ips", lambda host: ["10.0.0.5"])
    out, _sid = _run(cfg, tcfg, db, tmp_path)
    assert out["status"] == "blocked"
    assert any("10.0.0.5" in r for r in out["rejected"])


def test_orchestrator_full_flow_with_grant(db, tmp_path, monkeypatch):
    def fake_connect(self, ip, port, timeout):
        return "open" if port == 80 else "closed"

    cfg, tcfg = _prep(monkeypatch, in_scope=["example.com", "10.0.0.5"], allow_private=True)
    monkeypatch.setattr(no, "_resolve_ips", lambda host: ["10.0.0.5"])
    monkeypatch.setattr(no.NetworkEngine, "_tcp_state", fake_connect)
    out, sid = _run(cfg, tcfg, db, tmp_path)

    assert out["status"] == "completed"
    assert out["ports"]["open"] == 1 and out["ports"]["closed"] == 1
    assert out["ports"]["checked"] == 2
    assert out["ports"]["checked"] + out["ports"]["skipped"] + out["ports"]["untested"] == 2

    rows = db.query_evidence(scan_id=sid)
    assert rows and all(r["source"] == "network" for r in rows)
    links = db.query("SELECT * FROM evidence_assets")
    assert links  # evidence â†’ ip asset linkage
    assert db.get_asset("ip", "10.0.0.5")
    assert Path(out["snapshot"]).exists()


def test_orchestrator_phase_attribution_roundtrip_includes_network(db):
    from core.database import EVIDENCE_PHASES

    assert "network" in EVIDENCE_PHASES


def test_orchestrator_partial_when_killed(db, tmp_path, monkeypatch):
    class _K:
        def killed(self):
            return True

    monkeypatch.setattr(no, "KillSwitch", lambda: _K())
    cfg, tcfg = _prep(monkeypatch, in_scope=["example.com", "10.0.0.5"], allow_private=True)
    monkeypatch.setattr(no, "_resolve_ips", lambda host: ["10.0.0.5"])
    out, _sid = _run(cfg, tcfg, db, tmp_path)
    assert out["phase_state"] == "partial"
    assert out["ports"]["untested"] == 2


def test_orchestrator_resume_skips_completed_ports(db, tmp_path, monkeypatch):
    calls = {"n": 0}

    def fake_connect(self, ip, port, timeout):
        calls["n"] += 1
        return "closed"

    cfg, tcfg = _prep(monkeypatch, in_scope=["example.com", "10.0.0.5"], allow_private=True)
    monkeypatch.setattr(no, "_resolve_ips", lambda host: ["10.0.0.5"])
    monkeypatch.setattr(no.NetworkEngine, "_tcp_state", fake_connect)

    out1, sid = _run(cfg, tcfg, db, tmp_path)
    assert calls["n"] == 2
    out2, _ = _run(cfg, tcfg, db, tmp_path, sid=sid)   # resume on same scan
    assert calls["n"] == 2                              # nothing re-scanned
    assert out2["ports"]["checked"] == 2


def test_orchestrator_ai_unavailable_deterministic(db, tmp_path, monkeypatch):
    # No AI provider is configured anywhere in these paths â€” deterministic checks run.
    cfg, tcfg = _prep(monkeypatch, in_scope=["example.com", "10.0.0.5"], allow_private=True)
    monkeypatch.setattr(no, "_resolve_ips", lambda host: ["10.0.0.5"])
    monkeypatch.setattr(no.NetworkEngine, "_tcp_state", lambda self, ip, port, t: "open")
    out, _sid = _run(cfg, tcfg, db, tmp_path)
    assert out["status"] == "completed"


def test_ai_cannot_validate_network_finding(db, tmp_path, monkeypatch):
    from core import lifecycle

    def fake_tls(self, ip, port):
        return {"protocol": "TLSv1"}

    cfg, tcfg = _prep(monkeypatch, in_scope=["example.com", "10.0.0.5"],
                      allow_private=True, ports=["443"])
    monkeypatch.setattr(no, "_resolve_ips", lambda host: ["10.0.0.5"])
    monkeypatch.setattr(no.NetworkEngine, "_tcp_state", lambda self, ip, port, t: "open")
    monkeypatch.setattr(no.NetworkEngine, "_tls_meta", fake_tls)
    monkeypatch.setattr(no.NetworkEngine, "_http_probe", lambda self, ip, port, tls=False: {})
    out, sid = _run(cfg, tcfg, db, tmp_path)
    assert out["findings"] == 1
    fid = db.query_findings(scan_id=sid)[0]["id"]
    assert lifecycle.current_state(db, fid) in ("probable", "candidate")
    with pytest.raises(lifecycle.InvalidTransition):
        lifecycle.transition(db, fid, "validated", actor="ai_network_agent")
