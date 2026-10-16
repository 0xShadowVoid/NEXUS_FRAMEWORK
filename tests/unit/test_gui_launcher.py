"""Tests for the ``nexus gui`` launcher (loopback default, credential gate)."""

import argparse

import nexus


def _args(**over):
    base = {"host": "127.0.0.1", "port": 8080, "allow_remote": False, "log_level": "info"}
    base.update(over)
    return argparse.Namespace(**base)


def test_gui_command_registered():
    parser = nexus.build_parser()
    ns = parser.parse_args(["gui"])
    assert ns.func is nexus.cmd_gui
    assert ns.host == "127.0.0.1"
    assert ns.port == 8080


def test_gui_requires_credentials(monkeypatch):
    monkeypatch.delenv("NEXUS_GUI_USER", raising=False)
    monkeypatch.delenv("NEXUS_GUI_PASS", raising=False)
    assert nexus.cmd_gui(_args()) == 2


def test_gui_refuses_non_loopback(monkeypatch):
    monkeypatch.setenv("NEXUS_GUI_USER", "operator")
    monkeypatch.setenv("NEXUS_GUI_PASS", "s3cret")
    assert nexus.cmd_gui(_args(host="0.0.0.0")) == 2


def test_gui_runs_loopback(monkeypatch):
    monkeypatch.setenv("NEXUS_GUI_USER", "operator")
    monkeypatch.setenv("NEXUS_GUI_PASS", "s3cret")

    import uvicorn

    captured = {}

    def fake_run(app, **kwargs):
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(uvicorn, "run", fake_run)
    assert nexus.cmd_gui(_args(port=9099)) == 0
    assert captured["app"] == "core.gui:app"
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 9099
