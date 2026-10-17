"""Pass 22 — OWASP ZAP adapter (Task 14), mocked/offline only."""
from __future__ import annotations

import json

import pytest

from lib.adapters.base import (
    KIND_ACTIVE,
    KIND_PASSIVE,
    STATUS_COMPLETED,
    STATUS_RUNNING,
    STATUS_TIMEOUT,
    AdapterAuthError,
    AdapterPolicy,
    AdapterPolicyError,
    AdapterProtocolError,
    AdapterTimeout,
    AdapterUnavailable,
    GuardedAdapter,
    JobHandle,
    JobSpec,
    ingest_findings,
)
from lib.adapters.zap import (
    DEFAULT_BASE_URL,
    FakeZapBackend,
    MockZapAdapter,
    ZapAdapter,
    build_zap,
    default_alert,
)
from lib.ops_guard import KillSwitch


def _adapter(backend: FakeZapBackend | None = None, **kwargs) -> ZapAdapter:
    return MockZapAdapter(backend=backend or FakeZapBackend(), **kwargs)


# --- health + capability discovery -------------------------------------------


def test_default_base_url_is_loopback():
    assert DEFAULT_BASE_URL.startswith("http://127.0.0.1")


def test_health_reports_version():
    health = _adapter().health()
    assert health.reachable is True
    assert health.version == "2.15.0"
    assert health.mode == "standard"


def test_health_auth_failure_is_reported_not_raised():
    health = _adapter(FakeZapBackend(fail="auth")).health()
    assert health.reachable is False
    assert "auth" in health.error.lower()


def test_health_unreachable_is_reported_not_raised():
    health = _adapter(FakeZapBackend(fail="unreachable")).health()
    assert health.reachable is False
    assert "unreachable" in health.error.lower()


def test_health_malformed_is_reported_not_raised():
    health = _adapter(FakeZapBackend(fail="malformed")).health()
    assert health.reachable is False


def test_capabilities_discovered():
    names = {c.name for c in _adapter().capabilities()}
    assert names == {"passive-scan", "spider", "active-scan", "alert-retrieval"}
    active = {c.name for c in _adapter().capabilities() if c.active}
    assert active == {"active-scan"}


def test_validate_config_flags_missing_base_url():
    assert ZapAdapter(base_url="ftp://nope").validate_config()


# --- job lifecycle ------------------------------------------------------------


def test_passive_job_then_completes():
    adapter = _adapter(FakeZapBackend(status_seq=[100]))
    handle = adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_PASSIVE))
    assert handle.status == STATUS_RUNNING
    handle = adapter.job_status(handle)
    assert handle.status == STATUS_COMPLETED
    assert handle.progress == 100


def test_active_job_uses_ascan_component():
    adapter = _adapter()
    handle = adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_ACTIVE,
                                       authorized=True))
    assert handle.raw["component"] == "ascan"


def test_wait_polls_until_terminal():
    adapter = _adapter(FakeZapBackend(status_seq=[25, 60, 100]))
    handle = adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_PASSIVE))
    out = adapter.wait(handle, poll_interval=0, sleep=lambda _s: None)
    assert out.status == STATUS_COMPLETED


def test_wait_times_out_without_completion():
    adapter = _adapter(FakeZapBackend(status_seq=[10]))
    handle = adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_PASSIVE))
    out = adapter.wait(handle, timeout=0.001, poll_interval=0, sleep=lambda _s: None)
    assert out.status == STATUS_TIMEOUT


def test_cancel_job_accepted():
    adapter = _adapter()
    handle = adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_PASSIVE))
    assert adapter.cancel_job(handle) is True
    assert handle.status == "cancelled"


def test_unsupported_job_kind_rejected():
    from lib.adapters.base import AdapterError

    with pytest.raises(AdapterError):
        _adapter().start_job(JobSpec(target="http://example.com/", kind="teleport"))


# --- alerts / evidence --------------------------------------------------------


def test_collect_normalizes_alert():
    findings = _adapter().collect(JobHandle(job_id="0", adapter="zap",
                                            target="http://example.com/", raw={"target": "http://example.com/"}))
    assert len(findings) == 1
    f = findings[0]
    assert f.adapter == "zap" and f.source == "zap"
    assert f.severity == "P3" and f.confidence == 90
    assert f.plugin_id == "10038" and f.cwe_id == "693"


def test_collect_sanitizes_untrusted_alert_fields():
    alert = dict(default_alert())
    alert["evidence"] = "Authorization: Bearer sk-abcdefghijklmnop1234567890"
    alert["otherinfo"] = "token=topsecretvalue123456"
    adapter = _adapter(FakeZapBackend(alerts=[alert]))
    f = adapter.collect(JobHandle(job_id="0", adapter="zap", raw={"target": "http://example.com/"}))[0]
    assert "sk-abcdefghijklmnop1234567890" not in f.evidence
    assert "topsecretvalue123456" not in f.other_info


def test_collect_malformed_alerts_raises_protocol_error():
    def transport(url: str):
        if url.endswith("/JSON/core/view/alerts/"):
            return 200, json.dumps({"alerts": "not-a-list"})
        return 200, json.dumps({"version": "2.15.0"})

    adapter = ZapAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    with pytest.raises(AdapterProtocolError):
        adapter.collect(JobHandle(job_id="0", adapter="zap", raw={"target": "http://x/"}))


# --- normalized errors --------------------------------------------------------


def test_start_job_auth_error():
    adapter = _adapter(FakeZapBackend(fail="auth"))
    with pytest.raises(AdapterAuthError):
        adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_PASSIVE))


def test_start_job_connection_failure():
    def transport(url: str):
        raise ConnectionError("connection refused")

    adapter = ZapAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    with pytest.raises(AdapterUnavailable):
        adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_PASSIVE))


def test_transport_timeout_normalized():
    def transport(url: str):
        raise TimeoutError("slow")

    adapter = ZapAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    with pytest.raises(AdapterTimeout):
        adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_PASSIVE))


def test_malformed_status_raises_protocol_error():
    def transport(url: str):
        if "/view/status/" in url:
            return 200, json.dumps({"status": "not-a-number"})
        return 200, json.dumps({"scan": "0"})

    adapter = ZapAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    handle = adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_PASSIVE))
    with pytest.raises(AdapterProtocolError):
        adapter.job_status(handle)


def test_server_error_raised_on_start():
    # a 500 on the scan action must raise (not silently return a handle)
    def transport(url: str):
        if "/action/scan/" in url:
            return 500, "boom"
        return 200, json.dumps({"version": "2.15.0"})

    adapter = ZapAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    with pytest.raises(AdapterProtocolError):
        adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_PASSIVE))


def test_api_key_attached_to_requests():
    seen: list[str] = []

    def transport(url: str):
        seen.append(url)
        return 200, json.dumps({"scan": "0"})

    adapter = ZapAdapter(base_url=DEFAULT_BASE_URL, api_key="KEYXYZ", transport=transport)
    adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_PASSIVE))
    assert any("apikey=KEYXYZ" in u for u in seen)


# --- scope / authorization through the guard ---------------------------------


def _policy(cfg, **overrides) -> AdapterPolicy:
    defaults = dict(target_config=cfg.target("example.com"), ssrf_allow={"example.com"})
    defaults.update(overrides)
    return AdapterPolicy(**defaults)


def test_guarded_zap_rejects_out_of_scope(cfg):
    guarded = GuardedAdapter(_adapter(), _policy(cfg, ssrf_allow={"evil.test"}))
    with pytest.raises(AdapterPolicyError):
        guarded.start_job(JobSpec(target="https://evil.test/", kind=KIND_PASSIVE))


def test_guarded_zap_active_requires_authorization(cfg):
    guarded = GuardedAdapter(_adapter(), _policy(cfg, allow_active=False))
    with pytest.raises(AdapterPolicyError):
        guarded.start_job(JobSpec(target="https://example.com/", kind=KIND_ACTIVE, authorized=True))


def test_guarded_zap_passive_allowed_and_collects(cfg, db, tmp_path):
    guarded = GuardedAdapter(_adapter(), _policy(cfg, db=db, killswitch=KillSwitch(tmp_path)))
    handle = guarded.start_job(JobSpec(target="https://example.com/", kind=KIND_PASSIVE))
    handle = guarded.wait(handle, poll_interval=0, sleep=lambda _s: None)
    findings = guarded.collect(handle)
    assert findings and handle.status == STATUS_COMPLETED
    events = db.query("SELECT action FROM audit_events WHERE category = 'adapter'")
    actions = {e["action"] for e in events}
    assert "adapter.zap.start" in actions and "adapter.zap.collect" in actions


# --- end-to-end import into a scan -------------------------------------------


def test_zap_findings_import_with_provenance(cfg, db, tmp_path):
    tid = db.upsert_target("example.com")
    scan_id = db.create_scan(tid)
    guarded = GuardedAdapter(_adapter(), _policy(cfg, db=db, killswitch=KillSwitch(tmp_path)))
    handle = guarded.start_job(JobSpec(target="https://example.com/", kind=KIND_PASSIVE))
    findings = guarded.collect(guarded.wait(handle, poll_interval=0, sleep=lambda _s: None))
    report = ingest_findings(db, scan_id, findings, cfg.target("example.com"), phase="zap")
    assert report["finding_ids"]
    row = db.query_findings(scan_id=scan_id)[0]
    assert "zap" in row["tools_found"]
    evidence = db.query_evidence(scan_id=scan_id)
    assert evidence[0]["tool"] == "zap" and evidence[0]["source"] == "zap"
    assert "10038" in evidence[0]["response_body"]   # plugin id provenance preserved


def test_build_zap_reads_config(monkeypatch):
    monkeypatch.setenv("ZAP_API_KEY", "envkey")
    adapter = build_zap({"base_url": "http://zap.local:9000", "api_key_env": "ZAP_API_KEY",
                         "timeout_seconds": 15})
    assert adapter.base_url == "http://zap.local:9000"
    assert adapter.api_key == "envkey"
