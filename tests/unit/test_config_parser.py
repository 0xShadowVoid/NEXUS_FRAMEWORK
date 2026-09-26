"""Unit tests for lib.config."""
from __future__ import annotations

from pathlib import Path

import pytest

from lib.config import Config, load_config, validate_keys
from lib.exceptions import ConfigError


def test_loads_repo_config(cfg: Config):
    assert cfg.scanning["default_intensity"] == "quick-scan"
    assert cfg.phases["probe"]["default_tools"] == ["nuclei", "dalfox"]
    assert cfg.tool_timeout() > 0


def test_env_substitution(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DISCORD_FINDINGS_WEBHOOK", "https://discord.com/api/webhooks/123/abc")
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    (cfg_dir / "nexus.yaml").write_text(
        "webhooks:\n  discord:\n    findings: ${DISCORD_FINDINGS_WEBHOOK}\n", encoding="utf-8"
    )
    (cfg_dir / "false_positive_filters.yaml").write_text("filters: {}\n", encoding="utf-8")
    cfg = load_config(cfg_dir)
    assert cfg.webhook("findings") == "https://discord.com/api/webhooks/123/abc"


def test_missing_config_raises(tmp_path: Path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope")


def test_target_overrides(tmp_cfg: Config):
    tc = tmp_cfg.target("example.com")
    assert tc.intensity == "full-scan"
    assert tc.tools == ["nuclei", "dalfox", "sqlmap"]
    assert tc.rate_limit == "100/minute"
    # Unknown target falls back to defaults.
    other = tmp_cfg.target("unknown.com")
    assert other.intensity == "quick-scan"
    assert other.in_scope == ["unknown.com"]


def test_validate_keys_reports_missing(cfg: Config):
    report = validate_keys(cfg)
    assert "missing" in report and isinstance(report["missing"], list)
    assert report["valid"] is True


def test_validate_keys_flags_bad_webhook(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DISCORD_CVE_WEBHOOK", "http://not-a-discord-url")
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    (cfg_dir / "nexus.yaml").write_text(
        "webhooks:\n  discord:\n    cve: ${DISCORD_CVE_WEBHOOK}\n", encoding="utf-8"
    )
    (cfg_dir / "false_positive_filters.yaml").write_text("filters: {}\n", encoding="utf-8")
    cfg = load_config(cfg_dir)
    report = validate_keys(cfg)
    assert report["valid"] is False
    assert "DISCORD_CVE_WEBHOOK" in report["invalid"]


def test_database_path_is_absolute(cfg: Config):
    assert cfg.database_path.is_absolute()
