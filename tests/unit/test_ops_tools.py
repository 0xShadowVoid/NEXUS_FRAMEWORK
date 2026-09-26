"""Unit tests for self-scan, doctor, delta and scope-sync."""
from __future__ import annotations

from pathlib import Path

import yaml

from lib.delta import ReconState, compute_delta, filter_new_urls
from lib.doctor import run_doctor
from lib.scope_sync import (
    apply_scope_to_config,
    parse_bugcrowd_program,
    parse_h1_program,
)
from lib.selfscan import scan_tree


# --- self-scan ------------------------------------------------------------


def test_selfscan_detects_webhook(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        'HOOK = "https://discord.com/api/webhooks/123456789/abcdefghijklmnop"\n', encoding="utf-8"
    )
    findings = scan_tree(tmp_path)
    assert any(f["kind"] == "discord_webhook" for f in findings)


def test_selfscan_ignores_tests_dir(tmp_path: Path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_x.py").write_text('key = "sk-abcdefghijklmnopqrstuvwxyz0123"\n', encoding="utf-8")
    assert scan_tree(tmp_path) == []


def test_selfscan_short_fake_not_flagged(tmp_path: Path):
    (tmp_path / "a.py").write_text('x = "sk-short"\n', encoding="utf-8")
    assert scan_tree(tmp_path) == []


def test_selfscan_detects_private_key(tmp_path: Path):
    (tmp_path / "id_rsa").write_text("-----BEGIN RSA PRIVATE KEY-----\nAAA\n", encoding="utf-8")
    findings = scan_tree(tmp_path)
    assert any(f["kind"] == "private_key" for f in findings)


def test_selfscan_masks_detail(tmp_path: Path):
    secret = "https://discord.com/api/webhooks/123456789/supersecretvalue123"
    (tmp_path / "s.py").write_text(f'U = "{secret}"\n', encoding="utf-8")
    finding = scan_tree(tmp_path)[0]
    assert "supersecretvalue123" not in finding["detail"]


# --- doctor ---------------------------------------------------------------


def test_doctor_reports_structure():
    report = run_doctor()
    assert "ok" in report and isinstance(report["ok"], bool)
    assert any(c["check"] == "python>=3.11" for c in report["checks"])
    assert any(c["check"].startswith("dep:") for c in report["checks"])


def test_doctor_fails_without_config(tmp_path: Path):
    report = run_doctor(root=tmp_path, cfg=None)
    # config load will fail against the tmp root's (missing) config
    assert any(c["check"] == "config:nexus.yaml" for c in report["checks"])


# --- delta ----------------------------------------------------------------


def test_compute_delta_new_and_removed():
    prev = {"subdomains": ["a.com", "b.com"], "urls": ["https://a.com/1"]}
    cur = {"subdomains": ["b.com", "c.com"], "urls": ["https://a.com/1", "https://c.com/2"]}
    delta = compute_delta(prev, cur)
    assert delta["new_subdomains"] == ["c.com"]
    assert delta["removed_subdomains"] == ["a.com"]
    assert delta["new_urls"] == ["https://c.com/2"]


def test_filter_new_urls_first_run_returns_all():
    assert filter_new_urls(["u1", "u2"], []) == ["u1", "u2"]
    assert filter_new_urls(["u1", "u2"], ["u1"]) == ["u2"]


def test_recon_state_roundtrip(tmp_path: Path):
    state = ReconState(tmp_path, "example.com")
    assert state.load() == {}
    state.save({"subdomains": ["a.com"], "urls": ["https://a.com/"]})
    assert state.load()["subdomains"] == ["a.com"]


# --- scope-sync -----------------------------------------------------------


def test_parse_h1_program():
    program = {
        "name": "Acme",
        "attributes": {"scope": {"list": [
            {"asset_identifier": "acme.com", "eligible_for_submission": True},
            {"asset_identifier": "https://blog.acme.com", "eligible_for_submission": False},
        ]}},
    }
    parsed = parse_h1_program(program)
    assert parsed["in_scope"] == ["acme.com"]
    assert parsed["out_of_scope"] == ["blog.acme.com"]


def test_parse_bugcrowd_program():
    program = {"name": "Globex", "targets": {
        "in_scope": [{"target": "globex.com"}],
        "out_of_scope": [{"target": "internal.globex.com"}],
    }}
    parsed = parse_bugcrowd_program(program)
    assert parsed["in_scope"] == ["globex.com"]
    assert parsed["out_of_scope"] == ["internal.globex.com"]


def test_apply_scope_to_config_writes_yaml_and_backup(tmp_path: Path):
    cfg_path = tmp_path / "nexus.yaml"
    cfg_path.write_text(yaml.safe_dump({"targets": {}}), encoding="utf-8")
    result = apply_scope_to_config("acme.com", ["acme.com"], ["blog.acme.com"], config_path=cfg_path)
    data = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert data["targets"]["acme.com"]["in_scope"] == ["acme.com"]
    assert data["targets"]["acme.com"]["out_of_scope"] == ["blog.acme.com"]
    assert (tmp_path / "nexus.yaml.bak").exists()
    assert result["domain"] == "acme.com"
