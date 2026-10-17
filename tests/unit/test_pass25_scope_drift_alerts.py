"""Unit tests for scope-drift alerting (roadmap E3).

Fully offline: notifications are exercised through a fake notifier, so no
webhook, Telegram or SMTP call is ever made.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from lib import scope_drift
from lib.scope_drift import (
    alert_on_result,
    build_events,
    dispatch,
    drift_signature,
    filter_new,
    format_event,
    load_state,
    save_state,
)


# --- fakes ----------------------------------------------------------------


class FakeNotifier:
    def __init__(self, ok: bool = True, raise_on: str = ""):
        self.ok = ok
        self.raise_on = raise_on
        self.discord: list[tuple[str, str]] = []
        self.telegram: list[tuple[str, str]] = []

    def send_info_alert(self, title: str, body: str) -> bool:
        if self.raise_on == "discord":
            raise RuntimeError("discord exploded")
        self.discord.append((title, body))
        return self.ok

    def send_info_telegram(self, title: str, body: str) -> bool:
        if self.raise_on == "telegram":
            raise RuntimeError("telegram exploded")
        self.telegram.append((title, body))
        return self.ok


class FakeEmail:
    def __init__(self, ok: bool = True):
        self.ok = ok
        self.sent: list[tuple[str, str]] = []

    def send(self, subject: str, body: str) -> bool:
        self.sent.append((subject, body))
        return self.ok


class FakeCfg:
    def __init__(self, targets: dict | None = None, env: dict | None = None,
                 notify: dict | None = None, db_path: Path | None = None):
        self.targets_section = targets or {}
        self.env = env or {}
        self._notify = notify or {}
        self._db_path = db_path or Path("nexus.db")
        self.email: dict = {}

    def sync_target_names(self):
        return [d for d, raw in self.targets_section.items() if raw.get("sync")]

    def scope_notify(self):
        return self._notify

    @property
    def database_path(self):
        return self._db_path

    def webhook(self, kind: str) -> str:
        return ""

    def telegram(self):
        return ("", "")


def _program(domain="acme.com", *, added_in=(), removed_in=(), changed=True,
             skipped=False, applied=True):
    drift = {
        "added_in_scope": list(added_in),
        "removed_in_scope": list(removed_in),
        "added_out_of_scope": [],
        "removed_out_of_scope": [],
    }
    return {
        "domain": domain, "platform": "hackerone", "name": "Acme",
        "changed": changed, "drift": drift, "applied": applied,
        **({"skipped": True, "error": "boom"} if skipped else {}),
    }


def _result(*programs):
    return {"programs": list(programs), "count": len(programs),
            "applied": sum(1 for p in programs if p.get("applied")),
            "changed": sum(1 for p in programs if p.get("changed")),
            "skipped": sum(1 for p in programs if p.get("skipped"))}


# --- structured events ----------------------------------------------------


def test_build_events_added_direction():
    events = build_events(_result(_program(added_in=["new.acme.com"])))
    assert len(events) == 1
    event = events[0]
    assert event["event"] == "scope_drift"
    assert event["target"] == "acme.com" and event["provider"] == "hackerone"
    assert event["direction"] == "added"
    assert event["added"]["added_in_scope"] == ["new.acme.com"]
    assert event["counts"] == {"added": 1, "removed": 0}
    assert event["timestamp"]


def test_build_events_removed_and_mixed_directions():
    removed = build_events(_result(_program(removed_in=["gone.acme.com"])))[0]
    assert removed["direction"] == "removed"
    assert removed["removed"]["removed_in_scope"] == ["gone.acme.com"]
    mixed = build_events(_result(_program(added_in=["a.acme.com"], removed_in=["b.acme.com"])))[0]
    assert mixed["direction"] == "mixed"
    assert mixed["counts"] == {"added": 1, "removed": 1}


def test_build_events_single_program_result():
    events = build_events(_program(added_in=["new.acme.com"]))
    assert len(events) == 1 and events[0]["target"] == "acme.com"


def test_build_events_skips_unchanged_and_skipped():
    assert build_events(_result(_program(changed=False))) == []
    assert build_events(_result(_program(skipped=True, changed=False))) == []
    # A provider failure must never surface as a removal.
    assert build_events(_result(_program(skipped=True))) == []
    assert build_events({}) == []


def test_events_distinguish_in_and_out_of_scope():
    program = _program()
    program["drift"]["added_out_of_scope"] = ["blog.acme.com"]
    program["drift"]["removed_out_of_scope"] = ["old.acme.com"]
    event = build_events(_result(program))[0]
    assert event["added"]["added_out_of_scope"] == ["blog.acme.com"]
    assert event["removed"]["removed_out_of_scope"] == ["old.acme.com"]


# --- signatures / dedupe --------------------------------------------------


def test_signature_ignores_timestamp_and_applied():
    a = build_events(_result(_program(added_in=["x.acme.com"], applied=True)))[0]
    b = dict(build_events(_result(_program(added_in=["x.acme.com"], applied=False)))[0])
    b["timestamp"] = "1999-01-01T00:00:00+00:00"
    assert drift_signature(a) == drift_signature(b)
    changed = dict(a)
    changed["added"] = {"added_in_scope": ["y.acme.com"],
                        "added_out_of_scope": [], "removed_in_scope": [],
                        "removed_out_of_scope": []}
    assert drift_signature(a) != drift_signature(changed)


def test_filter_new_dedupes_identical_drift():
    events = build_events(_result(_program(added_in=["x.acme.com"])))
    fresh, state = filter_new(events, {})
    assert len(fresh) == 1
    again, state2 = filter_new(events, state)
    assert again == [] and state2 == state


def test_filter_new_reports_changed_drift_again():
    first = build_events(_result(_program(added_in=["x.acme.com"])))
    _fresh, state = filter_new(first, {})
    second = build_events(_result(_program(added_in=["y.acme.com"])))
    fresh, _state = filter_new(second, state)
    assert len(fresh) == 1 and fresh[0]["added"]["added_in_scope"] == ["y.acme.com"]


def test_state_roundtrip_and_corruption(tmp_path):
    assert save_state({"acme.com": "sig"}, tmp_path) is True
    assert load_state(tmp_path) == {"acme.com": "sig"}
    (tmp_path / scope_drift.DEFAULT_STATE_NAME).write_text("{not json", encoding="utf-8")
    assert load_state(tmp_path) == {}
    assert load_state(tmp_path / "missing") == {}


# --- formatting / redaction ----------------------------------------------


def test_format_event_lists_changes():
    event = build_events(_result(_program(added_in=["new.acme.com"], removed_in=["old.acme.com"])))[0]
    title, body = format_event(event)
    assert "acme.com" in title and "mixed" in title
    assert "+ added_in_scope: new.acme.com" in body
    assert "- removed_in_scope: old.acme.com" in body
    assert "never broadened" in body


def test_format_event_redacts_secrets():
    secret = "https://discord.com/api/webhooks/123456789/abcdefSECRETtokenshouldvanish"
    title, body = format_event(_program_event_with(secret))
    assert "SECRETtokenshouldvanish" not in title + body
    assert "***REDACTED***" in body or "***REDACTED***" in title


def _program_event_with(entry: str) -> dict:
    return build_events(_result(_program(added_in=[entry])))[0]


# --- dispatch -------------------------------------------------------------


def test_dispatch_delivers_via_discord_and_telegram():
    events = build_events(_result(_program(added_in=["x.acme.com"])))
    notifier = FakeNotifier()
    report = dispatch(events, notifier=notifier)
    assert report["sent"] == 1 and report["failed"] == 0
    assert report["channels"] == {"discord": 1, "telegram": 1, "email": 0}
    assert report["delivered_targets"]["acme.com"] == drift_signature(events[0])


def test_dispatch_isolates_channel_failure():
    events = build_events(_result(_program(added_in=["x.acme.com"])))
    notifier = FakeNotifier(raise_on="discord")
    report = dispatch(events, notifier=notifier)
    # Discord raised, Telegram still delivered: reported separately, no raise.
    assert report["channels"]["discord"] == 0 and report["channels"]["telegram"] == 1
    assert report["sent"] == 1 and report["failed"] == 0


def test_dispatch_all_channels_fail_reports_failure():
    events = build_events(_result(_program(added_in=["x.acme.com"])))
    report = dispatch(events, notifier=FakeNotifier(ok=False))
    assert report["sent"] == 0 and report["failed"] == 1
    assert report["delivered_targets"] == {}


def test_dispatch_email_channel_gated_and_used():
    events = build_events(_result(_program(added_in=["x.acme.com"])))
    email = FakeEmail()
    gated = dispatch(events, notifier=FakeNotifier(), channels={"discord": False,
                                                                "telegram": False,
                                                                "email": True})
    assert gated["sent"] == 0 and gated["failed"] == 1  # no alerter injected
    report = dispatch(events, notifier=FakeNotifier(),
                      channels={"discord": False, "telegram": False, "email": True,
                                "_email_alerter": email})
    assert report["channels"]["email"] == 1 and email.sent


# --- orchestration --------------------------------------------------------


def test_alert_on_result_disabled_by_default(tmp_path):
    notifier = FakeNotifier()
    report = alert_on_result(_result(_program(added_in=["x.acme.com"])),
                             cfg=FakeCfg(), notifier=notifier, results_base=tmp_path)
    assert report["enabled"] is False and report["sent"] == 0
    assert notifier.discord == [] and notifier.telegram == []
    assert load_state(tmp_path) == {}


def test_alert_on_result_fires_when_enabled(tmp_path):
    notifier = FakeNotifier()
    cfg = FakeCfg(notify={"enabled": True, "discord": True, "telegram": True})
    report = alert_on_result(_result(_program(added_in=["x.acme.com"])),
                             cfg=cfg, notifier=notifier, results_base=tmp_path)
    assert report == {"enabled": True, "events": 1, "new_events": 1, "sent": 1, "failed": 0}
    assert notifier.discord and notifier.telegram
    assert load_state(tmp_path)["acme.com"]


def test_alert_on_result_notify_flag_forces_send(tmp_path):
    notifier = FakeNotifier()
    report = alert_on_result(_result(_program(added_in=["x.acme.com"])),
                             cfg=FakeCfg(), notify=True, notifier=notifier,
                             results_base=tmp_path)
    assert report["enabled"] is True and report["sent"] == 1


def test_alert_on_result_dry_run_previews_only(tmp_path):
    notifier = FakeNotifier()
    report = alert_on_result(_result(_program(added_in=["x.acme.com"])),
                             cfg=FakeCfg(notify={"enabled": True}), dry_run=True,
                             notifier=notifier, results_base=tmp_path)
    assert report["dry_run"] is True and report["events"] == 1
    assert report["sent"] == 0 and notifier.discord == []
    assert load_state(tmp_path) == {}


def test_alert_on_result_duplicate_suppressed(tmp_path):
    notifier = FakeNotifier()
    cfg = FakeCfg(notify={"enabled": True})
    first = alert_on_result(_result(_program(added_in=["x.acme.com"])),
                            cfg=cfg, notifier=notifier, results_base=tmp_path)
    second = alert_on_result(_result(_program(added_in=["x.acme.com"])),
                             cfg=cfg, notifier=notifier, results_base=tmp_path)
    assert first["sent"] == 1
    assert second["new_events"] == 0 and second["sent"] == 0
    assert len(notifier.discord) == 1


def test_alert_on_result_provider_error_no_alert(tmp_path):
    notifier = FakeNotifier()
    cfg = FakeCfg(notify={"enabled": True})
    report = alert_on_result(_result(_program(skipped=True)),
                             cfg=cfg, notifier=notifier, results_base=tmp_path)
    assert report["events"] == 0 and report["sent"] == 0
    assert notifier.discord == []


def test_alert_on_result_failure_does_not_change_result(tmp_path):
    result = _result(_program(added_in=["x.acme.com"]))
    snapshot = json.loads(json.dumps(result))
    cfg = FakeCfg(notify={"enabled": True})
    report = alert_on_result(result, cfg=cfg, notifier=FakeNotifier(ok=False),
                             results_base=tmp_path)
    assert report["failed"] == 1
    # The authoritative sync result is untouched by delivery outcome.
    assert result == snapshot
    # Failed delivery is not recorded, so it retries instead of silently dropping.
    assert load_state(tmp_path) == {}


def test_alert_on_result_missing_notifier_reports_failure(tmp_path):
    cfg = FakeCfg(notify={"enabled": True})
    report = alert_on_result(_result(_program(added_in=["x.acme.com"])),
                             cfg=cfg, notifier=None, results_base=tmp_path)
    # Building the real Notifier from a fake cfg succeeds; sending is a no-op
    # (no endpoints) and reported as a failure rather than raising.
    assert report["enabled"] is True and report["failed"] == 1


# --- config ---------------------------------------------------------------


def test_config_scope_notify_reads_yaml(tmp_path):
    from lib.config import Config

    path = tmp_path / "nexus.yaml"
    path.write_text("scope_sync:\n  notify:\n    enabled: true\n    email: true\n", encoding="utf-8")
    import yaml

    cfg = Config(yaml.safe_load(path.read_text(encoding="utf-8")) or {}, {}, {})
    assert cfg.scope_notify() == {"enabled": True, "email": True}
    assert Config({}, {}, {}).scope_notify() == {}


# --- CLI ------------------------------------------------------------------


def _cli_args(**kwargs):
    import argparse
    base = {"domain": None, "file": None, "platform": "hackerone",
            "program": None, "all": False, "config": None, "dry_run": False,
            "notify": False}
    base.update(kwargs)
    return argparse.Namespace(**base)


def _monkey_config(monkeypatch, tmp_path, targets, notify=None, env=None):
    import nexus

    cfg = FakeCfg(targets, env=env, notify=notify or {}, db_path=tmp_path / "nexus.db")
    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: cfg)
    monkeypatch.setattr("lib.scope_providers.fetch_program",
                        lambda *a, **k: {"name": "Acme", "attributes": {"scope": {"list": [
                            {"asset_identifier": "acme.com", "eligible_for_submission": True}]}}})
    monkeypatch.setattr(scope_drift, "RESULTS_BASE", tmp_path)
    # Isolated config so a non-dry run never rewrites the repo's nexus.yaml.
    cfg_path = tmp_path / "nexus.yaml"
    cfg_path.write_text(yaml.safe_dump({"targets": targets}), encoding="utf-8")
    return cfg_path


def test_cmd_scope_sync_dry_run_previews_events_without_notify(monkeypatch, capsys, tmp_path):
    import nexus

    cfg_path = _monkey_config(monkeypatch, tmp_path, {"acme.com": {"sync": {"platform": "hackerone"}}})
    rc = nexus.cmd_scope_sync(_cli_args(all=True, dry_run=True, config=str(cfg_path)))
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["drift_events"][0]["direction"] == "added"
    assert "notifications" not in out
    assert not (tmp_path / scope_drift.DEFAULT_STATE_NAME).exists()


def test_cmd_scope_sync_no_notify_writes_no_state(monkeypatch, capsys, tmp_path):
    import nexus

    cfg_path = _monkey_config(monkeypatch, tmp_path, {"acme.com": {"sync": {"platform": "hackerone"}}})
    rc = nexus.cmd_scope_sync(_cli_args(all=True, config=str(cfg_path)))
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["notifications"]["enabled"] is False
    assert not (tmp_path / scope_drift.DEFAULT_STATE_NAME).exists()


def test_cmd_scope_sync_notify_sends_and_reports(monkeypatch, capsys, tmp_path):
    import nexus
    from lib import notifications

    cfg_path = _monkey_config(monkeypatch, tmp_path,
                              {"acme.com": {"sync": {"platform": "hackerone"}}},
                              notify={"enabled": True, "discord": True, "telegram": True})
    monkeypatch.setattr(notifications.Notifier, "send_info_alert", lambda self, t, b: True)
    monkeypatch.setattr(notifications.Notifier, "send_info_telegram", lambda self, t, b: True)
    rc = nexus.cmd_scope_sync(_cli_args(all=True, notify=True, config=str(cfg_path)))
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["notifications"]["sent"] == 1 and out["notifications"]["new_events"] == 1
    assert load_state(tmp_path)["acme.com"]


def test_cmd_scope_sync_legacy_file_unchanged(monkeypatch, capsys, tmp_path):
    import nexus

    cfg_path = tmp_path / "nexus.yaml"
    cfg_path.write_text("targets: {}\n", encoding="utf-8")
    program_file = tmp_path / "program.json"
    program_file.write_text(json.dumps({
        "name": "Acme",
        "attributes": {"scope": {"list": [
            {"asset_identifier": "acme.com", "eligible_for_submission": True}]}},
    }), encoding="utf-8")
    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: FakeCfg({}))
    rc = nexus.cmd_scope_sync(_cli_args(domain="acme.com", file=str(program_file),
                                        config=str(cfg_path)))
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and "notifications" not in out and "drift_events" not in out
