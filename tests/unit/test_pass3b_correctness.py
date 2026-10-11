"""Pass 3B — correctness fixes (single-source version, C2 frontends)."""
from __future__ import annotations

import json

from lib.paths import REPO_ROOT
from lib.version import framework_version


def test_version_single_source():
    assert (REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip() == "2.0.0"
    assert framework_version() == "2.0.0"


def test_exporter_uses_framework_version(tmp_path):
    from core import exporter

    assert exporter.NEXUS_VERSION == framework_version()
    meta = exporter._metadata("example.com", [{"id": 1}], [{"id": 1}, {"id": 2}])
    assert meta["version"] == "2.0.0"

    path = exporter.export_sarif(
        "example.com", [{"vuln_type": "xss", "severity": "P2"}], out_base=tmp_path
    )
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["runs"][0]["tool"]["driver"]["version"] == "2.0.0"


def test_cli_version_string(capsys):
    import pytest
    import nexus

    with pytest.raises(SystemExit) as exc:
        nexus.main(["--version"])
    assert exc.value.code == 0
    assert "NEXUS 2.0.0" in capsys.readouterr().out


def test_c2_frontends_import_and_default_routers():
    from phases.control.c2_commands import default_logs_handler
    from phases.control.discord_c2 import build_default_router as build_discord
    from phases.control.telegram_c2 import build_default_router as build_telegram

    for build in (build_discord, build_telegram):
        router = build("OWNER")
        ok = router.handle("OWNER", "/nexus hunt acme.com")
        assert ok.ok is True and "acme.com" in ok.output
        denied = router.handle("INTRUDER", "/nexus hunt acme.com")
        assert denied.ok is False
    assert isinstance(default_logs_handler(), str)
