"""Unit tests for automatic scope sync (roadmap E1).

Fully offline: platform APIs are exercised through an injected fake
``requests`` session, so no live H1/Bugcrowd call is ever made.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import requests
import yaml

from lib.scope_providers import (
    ScopeProviderError,
    fetch_bugcrowd_program,
    fetch_h1_program,
    fetch_program,
)
from lib.scope_sync import (
    diff_scope,
    is_changed,
    normalize_scope,
    parse_bugcrowd_program,
    parse_h1_program,
    read_config_target_scope,
    sync_program,
    sync_targets,
)


# --- fakes ----------------------------------------------------------------


class FakeResponse:
    def __init__(self, status_code: int = 200, payload=None, bad_json: bool = False):
        self.status_code = status_code
        self._payload = payload
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise ValueError("not json")
        return self._payload


class FakeSession:
    def __init__(self, response: FakeResponse | None = None, exc: Exception | None = None):
        self.response = response
        self.exc = exc
        self.calls: list[tuple[str, dict]] = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.exc is not None:
            raise self.exc
        return self.response


class FakeCfg:
    def __init__(self, targets: dict, env: dict | None = None):
        self.targets_section = targets
        self.env = env or {}

    def sync_target_names(self):
        return [d for d, raw in self.targets_section.items() if raw.get("sync")]


def _h1_jsonapi_scopes() -> dict:
    return {
        "data": {
            "id": "acme",
            "type": "program",
            "attributes": {"name": "Acme"},
            "relationships": {
                "structured_scopes": {
                    "data": [
                        {"attributes": {"asset_identifier": "acme.com", "eligible_for_submission": True}},
                        {"attributes": {"asset_identifier": "https://blog.acme.com", "eligible_for_submission": False}},
                        {"attributes": {"asset_identifier": "api.acme.com", "eligible_for_submission": True}},
                    ]
                }
            },
        }
    }


def _write_cfg(tmp_path: Path, targets: dict) -> Path:
    path = tmp_path / "nexus.yaml"
    path.write_text(yaml.safe_dump({"targets": targets}, sort_keys=False), encoding="utf-8")
    return path


# --- providers: hackerone -------------------------------------------------


def test_fetch_h1_program_normalizes_structured_scopes():
    session = FakeSession(FakeResponse(payload=_h1_jsonapi_scopes()))
    doc = fetch_h1_program("acme", username="u", api_token="t", session=session)
    parsed = parse_h1_program(doc)
    assert parsed["in_scope"] == ["acme.com", "api.acme.com"]
    assert parsed["out_of_scope"] == ["blog.acme.com"]
    assert parsed["name"] == "Acme"


def test_fetch_h1_program_uses_basic_auth_and_official_host():
    session = FakeSession(FakeResponse(payload=_h1_jsonapi_scopes()))
    fetch_h1_program("acme", username="user-x", api_token="tok-y", session=session)
    url, kwargs = session.calls[0]
    assert url == "https://api.hackerone.com/v1/hackers/programs/acme"
    assert kwargs["auth"] == ("user-x", "tok-y")


def test_fetch_h1_program_requires_credentials():
    with pytest.raises(ScopeProviderError, match="credentials"):
        fetch_h1_program("acme", username="", api_token="", session=FakeSession(FakeResponse()))


@pytest.mark.parametrize("status", [401, 403])
def test_fetch_h1_program_auth_failure(status):
    with pytest.raises(ScopeProviderError, match="authentication"):
        fetch_h1_program("acme", username="u", api_token="t",
                         session=FakeSession(FakeResponse(status_code=status)))


def test_fetch_h1_program_not_found():
    with pytest.raises(ScopeProviderError, match="not found"):
        fetch_h1_program("acme", username="u", api_token="t",
                         session=FakeSession(FakeResponse(status_code=404)))


def test_fetch_h1_program_malformed_json():
    with pytest.raises(ScopeProviderError, match="malformed"):
        fetch_h1_program("acme", username="u", api_token="t",
                         session=FakeSession(FakeResponse(bad_json=True)))


def test_fetch_h1_program_transport_error_does_not_leak_token(caplog):
    caplog.set_level("DEBUG")
    session = FakeSession(exc=requests.ConnectionError("boom"))
    with pytest.raises(ScopeProviderError):
        fetch_h1_program("acme", username="u", api_token="super-secret-token", session=session)
    assert "super-secret-token" not in caplog.text


def test_fetch_h1_program_ssrf_guard_blocks(monkeypatch):
    monkeypatch.setattr("lib.scope_providers.is_safe_url", lambda *a, **k: (False, "nope"))
    with pytest.raises(ScopeProviderError, match="ssrf"):
        fetch_h1_program("acme", username="u", api_token="t", session=FakeSession(FakeResponse()))


def test_fetch_h1_program_requires_handle():
    with pytest.raises(ScopeProviderError, match="handle"):
        fetch_h1_program("   ", username="u", api_token="t", session=FakeSession(FakeResponse()))


# --- providers: bugcrowd / dispatch ---------------------------------------


def test_fetch_bugcrowd_program_token_header():
    payload = {"data": {"name": "Globex", "targets": {
        "in_scope": [{"target": "globex.com"}],
        "out_of_scope": [{"target": "internal.globex.com"}],
    }}}
    session = FakeSession(FakeResponse(payload=payload))
    doc = fetch_bugcrowd_program("globex", api_key="tok", session=session)
    url, kwargs = session.calls[0]
    assert url == "https://api.bugcrowd.com/programs/globex"
    assert kwargs["headers"]["Authorization"] == "Token tok"
    parsed = parse_bugcrowd_program(doc)
    assert parsed["in_scope"] == ["globex.com"]
    assert parsed["out_of_scope"] == ["internal.globex.com"]


def test_fetch_program_dispatch_and_env_names():
    session = FakeSession(FakeResponse(payload=_h1_jsonapi_scopes()))
    doc = fetch_program("hackerone", "acme", env={"MY_USER": "u", "MY_TOK": "t"},
                        session=session, username_env="MY_USER", token_env="MY_TOK")
    assert parse_h1_program(doc)["in_scope"]
    assert session.calls[0][1]["auth"] == ("u", "t")


def test_fetch_program_missing_env_credentials_skips():
    with pytest.raises(ScopeProviderError, match="credentials"):
        fetch_program("hackerone", "acme", env={}, session=FakeSession(FakeResponse()))


def test_fetch_program_unknown_platform():
    with pytest.raises(ScopeProviderError, match="unsupported platform"):
        fetch_program("shady", "acme", env={}, session=FakeSession(FakeResponse()))


# --- diff / normalize -----------------------------------------------------


def test_normalize_scope_cleans_dedupes_sorts():
    assert normalize_scope(["HTTPS://WWW.Acme.com/", "acme.com", "b.acme.com", ""]) == [
        "acme.com", "b.acme.com"]


def test_diff_scope_added_and_removed():
    drift = diff_scope(["acme.com", "old.acme.com"], ["x.acme.com"],
                       ["acme.com", "new.acme.com"], ["x.acme.com", "y.acme.com"])
    assert drift == {
        "added_in_scope": ["new.acme.com"],
        "removed_in_scope": ["old.acme.com"],
        "added_out_of_scope": ["y.acme.com"],
        "removed_out_of_scope": [],
    }
    assert is_changed(drift) is True
    assert is_changed(diff_scope(["a.com"], [], ["a.com"], [])) is False


def test_read_config_target_scope(tmp_path):
    path = _write_cfg(tmp_path, {"acme.com": {"in_scope": ["acme.com"], "out_of_scope": ["x.acme.com"]}})
    assert read_config_target_scope("acme.com", path) == (["acme.com"], ["x.acme.com"])
    assert read_config_target_scope("nope.com", path) == ([], [])


# --- sync_program ---------------------------------------------------------


def test_sync_program_applies_on_change(tmp_path):
    path = _write_cfg(tmp_path, {})
    session = FakeSession(FakeResponse(payload=_h1_jsonapi_scopes()))
    report = sync_program("acme.com", platform="hackerone", handle="acme", env={"H1_API_USER": "u", "H1_API_TOKEN": "t"},
                          session=session, config_path=path)
    assert report["applied"] is True and report["changed"] is True
    assert report["in_scope"] == ["acme.com", "api.acme.com"]
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["targets"]["acme.com"]["in_scope"] == ["acme.com", "api.acme.com"]
    assert data["targets"]["acme.com"]["out_of_scope"] == ["blog.acme.com"]
    assert (tmp_path / "nexus.yaml.bak").exists()


def test_sync_program_no_write_when_unchanged(tmp_path):
    path = _write_cfg(tmp_path, {"acme.com": {
        "in_scope": ["acme.com", "api.acme.com"], "out_of_scope": ["blog.acme.com"]}})
    before = path.read_text(encoding="utf-8")
    session = FakeSession(FakeResponse(payload=_h1_jsonapi_scopes()))
    report = sync_program("acme.com", platform="hackerone", handle="acme",
                          env={"H1_API_USER": "u", "H1_API_TOKEN": "t"}, session=session, config_path=path)
    assert report["changed"] is False and report["applied"] is False
    assert path.read_text(encoding="utf-8") == before
    assert not (tmp_path / "nexus.yaml.bak").exists()


def test_sync_program_dry_run_does_not_write(tmp_path):
    path = _write_cfg(tmp_path, {})
    before = path.read_text(encoding="utf-8")
    session = FakeSession(FakeResponse(payload=_h1_jsonapi_scopes()))
    report = sync_program("acme.com", platform="hackerone", handle="acme",
                          env={"H1_API_USER": "u", "H1_API_TOKEN": "t"}, session=session,
                          config_path=path, apply=False)
    assert report["changed"] is True and report["applied"] is False
    assert path.read_text(encoding="utf-8") == before


def test_sync_program_skips_on_provider_error(tmp_path):
    path = _write_cfg(tmp_path, {})
    before = path.read_text(encoding="utf-8")
    report = sync_program("acme.com", platform="hackerone", handle="acme", env={},
                          session=FakeSession(FakeResponse()), config_path=path)
    assert report["skipped"] is True
    assert "credentials" in report["error"]
    assert path.read_text(encoding="utf-8") == before


def test_sync_program_reports_removed_scope(tmp_path):
    path = _write_cfg(tmp_path, {"acme.com": {
        "in_scope": ["acme.com", "api.acme.com", "gone.acme.com"], "out_of_scope": []}})
    session = FakeSession(FakeResponse(payload=_h1_jsonapi_scopes()))
    report = sync_program("acme.com", platform="hackerone", handle="acme",
                          env={"H1_API_USER": "u", "H1_API_TOKEN": "t"}, session=session, config_path=path)
    assert report["drift"]["removed_in_scope"] == ["gone.acme.com"]
    assert report["applied"] is True


# --- sync_targets ---------------------------------------------------------


def test_sync_targets_reports_summary(tmp_path):
    path = _write_cfg(tmp_path, {"acme.com": {"sync": {"platform": "bugcrowd", "handle": "acme"}}})
    cfg = FakeCfg({"acme.com": {"sync": {"platform": "bugcrowd", "handle": "acme"}}},
                  env={"BUGCROWD_API_TOKEN": "tok"})
    payload = {"data": {"name": "Acme", "targets": {"in_scope": [{"target": "acme.com"}], "out_of_scope": []}}}
    result = sync_targets(["acme.com"], config=cfg, config_path=path,
                          session=FakeSession(FakeResponse(payload=payload)))
    assert (result["count"], result["applied"], result["changed"], result["skipped"]) == (1, 1, 1, 0)
    assert result["programs"][0]["applied"] is True


def test_sync_targets_skips_unconfigured_and_errors(tmp_path):
    path = _write_cfg(tmp_path, {})
    cfg = FakeCfg({"nosync.com": {"intensity": "quick-scan"}, "acme.com": {"sync": {"platform": "hackerone"}}})
    result = sync_targets(["nosync.com", "acme.com"], config=cfg, config_path=path,
                          session=FakeSession(FakeResponse(payload=_h1_jsonapi_scopes())))
    assert result["count"] == 2 and result["skipped"] == 2
    assert result["programs"][0]["error"] == "no sync block configured"
    assert "credentials" in result["programs"][1]["error"]


def test_sync_targets_reports_no_secret(tmp_path):
    path = _write_cfg(tmp_path, {"acme.com": {"sync": {"platform": "hackerone"}}})
    cfg = FakeCfg({"acme.com": {"sync": {"platform": "hackerone"}}},
                  env={"H1_API_USER": "u", "H1_API_TOKEN": "top-secret-token"})
    result = sync_targets(["acme.com"], config=cfg, config_path=path,
                          session=FakeSession(exc=requests.ConnectionError("x")))
    assert "top-secret-token" not in json.dumps(result)


# --- CLI ------------------------------------------------------------------


def _cli_args(**kwargs):
    import argparse
    base = {"domain": None, "file": None, "platform": "hackerone",
            "program": None, "all": False, "config": None, "dry_run": False}
    base.update(kwargs)
    return argparse.Namespace(**base)


def test_cmd_scope_sync_all_when_nothing_configured(tmp_path, monkeypatch, capsys):
    import nexus

    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: FakeCfg({}))
    rc = nexus.cmd_scope_sync(_cli_args(all=True))
    assert rc == 0
    assert "no targets carry a sync block" in capsys.readouterr().out


def test_cmd_scope_sync_all_dry_run(tmp_path, monkeypatch, capsys):
    import nexus

    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: FakeCfg({"acme.com": {"sync": {"platform": "hackerone"}}}))
    monkeypatch.setattr("lib.scope_providers.fetch_program",
                        lambda *a, **k: {"name": "Acme", "attributes": {"scope": {"list": [
                            {"asset_identifier": "acme.com", "eligible_for_submission": True}]}}})
    rc = nexus.cmd_scope_sync(_cli_args(all=True, dry_run=True))
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["count"] == 1 and out["programs"][0]["changed"] is True


def test_cmd_scope_sync_legacy_file(tmp_path, monkeypatch, capsys):
    import nexus

    cfg_path = _write_cfg(tmp_path, {})
    program_file = tmp_path / "program.json"
    program_file.write_text(json.dumps({
        "name": "Acme",
        "attributes": {"scope": {"list": [
            {"asset_identifier": "acme.com", "eligible_for_submission": True}]}},
    }), encoding="utf-8")
    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: FakeCfg({}))
    rc = nexus.cmd_scope_sync(_cli_args(domain="acme.com", file=str(program_file), config=str(cfg_path)))
    assert rc == 0
    data = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert data["targets"]["acme.com"]["in_scope"] == ["acme.com"]


def test_cmd_scope_sync_requires_domain_or_file(capsys):
    import nexus

    assert nexus.cmd_scope_sync(_cli_args()) == 2
    assert "provide" in capsys.readouterr().err
