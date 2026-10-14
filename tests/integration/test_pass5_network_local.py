"""Pass 5 — local-server integration for the network phase (no external scanning).

Only loopback test servers are used; authorization for 127.0.0.1 is granted
explicitly through the engagement policy (in_scope + allow_private).
"""
from __future__ import annotations

import socket
import socketserver
import threading
from pathlib import Path

import pytest

from core.database import Database
from lib.config import load_config
from lib.paths import CONFIG_DIR
from phases.network import net_orchestrator as no


class _BannerServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _BannerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.sendall(b"SSH-2.0-Pass5TestBanner\r\n")
        except OSError:
            pass


class _SilentHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(0.5)
            self.request.recv(16)
        except OSError:
            pass


@pytest.fixture()
def local_ports():
    banner = _BannerServer(("127.0.0.1", 0), _BannerHandler)
    threading.Thread(target=banner.serve_forever, daemon=True).start()
    silent = _BannerServer(("127.0.0.1", 0), _SilentHandler)
    threading.Thread(target=silent.serve_forever, daemon=True).start()
    # find a definitely-closed port: bind then release
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()
    yield {"banner": banner.server_address[1], "silent": silent.server_address[1],
           "closed": closed_port}
    banner.shutdown()
    silent.shutdown()


@pytest.fixture()
def pdb(tmp_path):
    db = Database(tmp_path / "p5.db")
    yield db
    db.close()


def _cfg_for_localhost(ports):
    cfg = load_config(CONFIG_DIR)
    cfg._main.setdefault("phases", {})["network"] = {
        "enabled": True,
        "ports": [str(p) for p in ports],
        "concurrency": 4,
        "connect_timeout": 0.8,
        "probe_timeout": 0.8,
        "max_ports": 512,
        "allow_private": True,
    }
    tcfg = cfg.target("127.0.0.1")
    tcfg.in_scope = ["127.0.0.1"]
    return cfg, tcfg


def _load_snapshot(out):
    import json

    return json.loads(Path(out["snapshot"]).read_text(encoding="utf-8"))


def test_local_port_states_banner_and_accounting(pdb, tmp_path, local_ports):
    ports = [local_ports["banner"], local_ports["silent"], local_ports["closed"]]
    cfg, tcfg = _cfg_for_localhost(ports)
    sid = pdb.create_scan(pdb.upsert_target("127.0.0.1"))
    out = no.run_network(cfg, tcfg, tmp_path / "results", db=pdb, scan_id=sid)

    assert out["status"] in ("completed", "partial")
    amounts = out["ports"]
    assert amounts["open"] == 2          # banner + silent listeners
    # On this environment a released loopback port shows as filtered (SYN drop)
    # rather than closed (RST) depending on the local firewall behaviour.
    assert amounts["closed"] + amounts["filtered"] == 1
    assert amounts["checked"] == 3
    assert amounts["checked"] + amounts["skipped"] + amounts["untested"] == 3

    by_port = {r["port"]: r for r in _load_snapshot(out)["ports"]}
    banner_row = by_port[local_ports["banner"]]
    assert banner_row["service"] == "ssh"
    assert "Pass5TestBanner" in banner_row["banner"]

    # evidence + asset linkage + phase attribution
    rows = pdb.query_evidence(scan_id=sid)
    assert rows and all(r["source"] == "network" for r in rows)
    assert pdb.query("SELECT * FROM evidence_assets")
    assert pdb.get_asset("ip", "127.0.0.1")

    # snapshot artifact
    assert Path(out["snapshot"]).exists()


def test_local_resume_second_run_keeps_states(pdb, tmp_path, local_ports):
    ports = [local_ports["banner"], local_ports["closed"]]
    cfg, tcfg = _cfg_for_localhost(ports)
    sid = pdb.create_scan(pdb.upsert_target("127.0.0.1"))
    first = no.run_network(cfg, tcfg, tmp_path / "results", db=pdb, scan_id=sid)
    second = no.run_network(cfg, tcfg, tmp_path / "results", db=pdb, scan_id=sid)
    assert first["ports"]["checked"] == 2
    assert second["ports"]["checked"] == 2        # resumed from checkpoint
    assert second["status"] in ("completed", "partial")


def test_local_out_of_scope_hostname_blocked(pdb, tmp_path, local_ports):
    cfg, tcfg = _cfg_for_localhost([local_ports["banner"]])
    tcfg.domain = "out-of-scope.example"
    tcfg.in_scope = ["other-domain.example"]      # no ip/CIDR grants either
    out = no.run_network(cfg, tcfg, tmp_path / "results", db=pdb,
                         scan_id=pdb.create_scan(pdb.upsert_target("127.0.0.1")))
    assert out["status"] == "blocked"
