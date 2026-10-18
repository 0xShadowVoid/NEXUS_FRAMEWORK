"""Pass 26 — Burp Suite Professional adapter (Task 18), mocked/offline only.

No licensed Burp instance is required: every call goes through an injected
deterministic transport.
"""
from __future__ import annotations

import json

import pytest

from lib.adapters.base import (
    KIND_ACTIVE,
    KIND_PASSIVE,
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_RUNNING,
    STATUS_TIMEOUT,
    AdapterAuthError,
    AdapterError,
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
from lib.adapters.burp import (
    DEFAULT_BASE_URL,
    BurpAdapter,
    FakeBurpBackend,
    MockBurpAdapter,
    _endpoint_label,
    build_burp,
    default_issue,
    existing_scan_handle,
)
from lib.adapters.registry import adapter_names, build_adapter, has_adapter
from lib.config import Config
from lib.ops_guard import KillSwitch


def _adapter(backend: FakeBurpBackend | None = None, **kwargs) -> BurpAdapter:
    return MockBurpAdapter(backend=backend or FakeBurpBackend(), **kwargs)


# --- health + capability discovery -------------------------------------------


def test_default_base_url_is_loopback_pro():
    assert DEFAULT_BASE_URL == "http://127.0.0.1:1337"


def test_health_ok_reports_issue_definitions():
    health = _adapter().health()
    assert health.reachable is True
    assert health.details["issue_definition_count"] == 3
    assert "Burp Suite Professional REST API" in health.details["api"]
    assert health.version == ""          # the REST API exposes no version string


def test_health_auth_failure_is_reported_not_raised():
    health = _adapter(FakeBurpBackend(fail="auth")).health()
    assert health.reachable is False
    assert "auth" in health.error.lower()


def test_health_unreachable_is_reported_not_raised():
    health = _adapter(FakeBurpBackend(fail="unreachable")).health()
    assert health.reachable is False
    assert "unreachable" in health.error.lower()


def test_health_malformed_is_reported_not_raised():
    health = _adapter(FakeBurpBackend(fail="malformed")).health()
    assert health.reachable is False


def test_capabilities_discovered():
    caps = _adapter().capabilities()
    assert {c.name for c in caps} == {
        "health", "capability-discovery", "active-scan", "issue-retrieval"}
    assert {c.name for c in caps if c.active} == {"active-scan"}


def test_issue_definitions_live_discovery():
    defs = _adapter().issue_definitions()
    assert len(defs) == 3
    assert any(d["name"] == "SQL injection" for d in defs)


def test_validate_config_flags_bad_base_url():
    assert BurpAdapter(base_url="ftp://nope").validate_config()


# --- job lifecycle ------------------------------------------------------------


def test_start_scan_returns_running_handle():
    handle = _adapter().start_job(JobSpec(target="http://example.com/", kind=KIND_ACTIVE,
                                          authorized=True))
    assert handle.status == STATUS_RUNNING
    assert handle.adapter == "burp"
    assert handle.raw["scan_id"] == "42"


def test_unsupported_job_kind_rejected():
    with pytest.raises(AdapterError, match="unsupported job kind"):
        _adapter().start_job(JobSpec(target="http://example.com/", kind=KIND_PASSIVE))


def test_job_status_maps_running_then_succeeded():
    adapter = _adapter(FakeBurpBackend(status_seq=["running", "succeeded"]))
    handle = adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_ACTIVE))
    handle = adapter.job_status(handle)
    assert handle.status == STATUS_RUNNING
    assert handle.progress == 50          # audit_queue 5/(5+5)
    handle = adapter.job_status(handle)
    assert handle.status == STATUS_COMPLETED and handle.progress == 100


def test_job_status_pending_and_failed():
    scheduled = _adapter(FakeBurpBackend(scan_status="scheduled")).start_job(
        JobSpec(target="http://example.com/", kind=KIND_ACTIVE))
    assert _adapter(FakeBurpBackend(scan_status="scheduled")).job_status(scheduled).status == STATUS_PENDING
    failed = _adapter(FakeBurpBackend(scan_status="failed")).job_status(
        JobHandle(job_id="42", adapter="burp", raw={"scan_id": "42"}))
    assert failed.status == STATUS_FAILED


def test_job_status_unknown_metrics_yields_zero_progress():
    def transport(method: str, url: str, body: str):
        return 200, json.dumps({"scan_status": "running"})

    adapter = BurpAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    handle = adapter.job_status(JobHandle(job_id="42", adapter="burp", raw={"scan_id": "42"}))
    assert handle.status == STATUS_RUNNING and handle.progress == 0


def test_wait_polls_until_terminal():
    adapter = _adapter(FakeBurpBackend(status_seq=["running", "succeeded"]))
    handle = adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_ACTIVE))
    out = adapter.wait(handle, poll_interval=0, sleep=lambda _s: None)
    assert out.status == STATUS_COMPLETED


def test_wait_timeout_does_not_claim_burp_stopped():
    adapter = _adapter(FakeBurpBackend(status_seq=["running"]))
    handle = adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_ACTIVE))
    out = adapter.wait(handle, timeout=0.001, poll_interval=0, sleep=lambda _s: None)
    assert out.status == STATUS_TIMEOUT
    assert out.raw["burp_may_still_be_running"] is True
    assert "may still be scanning" in out.message


def test_wait_kill_switch_does_not_claim_burp_stopped(tmp_path):
    adapter = _adapter(FakeBurpBackend(status_seq=["running"]))
    handle = adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_ACTIVE))
    out = adapter.wait(handle, poll_interval=0, sleep=lambda _s: None,
                       should_stop=lambda: "kill switch engaged")
    assert out.status == STATUS_CANCELLED
    assert out.raw["burp_may_still_be_running"] is True


def test_cancel_job_unsupported_returns_false():
    handle = _adapter().start_job(JobSpec(target="http://example.com/", kind=KIND_ACTIVE))
    assert _adapter().cancel_job(handle) is False


# --- findings / evidence ------------------------------------------------------


def test_collect_normalizes_issue():
    findings = _adapter().collect(JobHandle(job_id="42", adapter="burp", raw={"scan_id": "42"}))
    assert len(findings) == 1
    f = findings[0]
    assert f.adapter == "burp" and f.source == "burp"
    assert f.name == "SQL injection"
    assert f.severity == "P2" and f.confidence == 95          # high / certain
    assert f.endpoint == "http://example.com/login"
    assert f.method == "POST" and f.param == "username"
    assert f.plugin_id == "1049088" and f.alert_id == "1"
    assert f.extra["burp_confidence"] == "certain"


def test_collect_sanitizes_untrusted_evidence():
    issue = dict(default_issue())
    issue["evidence"] = [{"request": "Authorization: Bearer ghp_" + "A" * 24,
                          "response": "HTTP/1.1 200"}]
    issue["issue_detail"] = "token=supersecretvalue1234567890"
    adapter = _adapter(FakeBurpBackend(issues=[issue]))
    f = adapter.collect(JobHandle(job_id="42", adapter="burp", raw={"scan_id": "42"}))[0]
    assert "ghp_" + "A" * 24 not in f.evidence
    assert "supersecretvalue1234567890" not in f.other_info


def test_collect_malformed_issue_events_raises():
    def transport(method: str, url: str, body: str):
        return 200, json.dumps({"scan_status": "succeeded", "issue_events": "nope"})

    adapter = BurpAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    with pytest.raises(AdapterProtocolError):
        adapter.collect(JobHandle(job_id="42", adapter="burp", raw={"scan_id": "42"}))


def test_collect_missing_issues_collection_raises():
    def transport(method: str, url: str, body: str):
        return 200, json.dumps({"scan_status": "succeeded"})

    adapter = BurpAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    with pytest.raises(AdapterProtocolError):
        adapter.collect(JobHandle(job_id="42", adapter="burp", raw={"scan_id": "42"}))


def test_collect_accepts_issues_key():
    def transport(method: str, url: str, body: str):
        return 200, json.dumps({"scan_status": "succeeded", "issues": [default_issue()]})

    adapter = BurpAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    assert len(adapter.collect(JobHandle(job_id="42", adapter="burp", raw={"scan_id": "42"}))) == 1


# --- normalized errors --------------------------------------------------------


def test_start_job_auth_error():
    with pytest.raises(AdapterAuthError):
        _adapter(FakeBurpBackend(fail="auth")).start_job(
            JobSpec(target="http://example.com/", kind=KIND_ACTIVE))


def test_start_job_connection_failure():
    def transport(method: str, url: str, body: str):
        raise ConnectionError("connection refused")

    adapter = BurpAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    with pytest.raises(AdapterUnavailable):
        adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_ACTIVE))


def test_transport_timeout_normalized():
    def transport(method: str, url: str, body: str):
        raise TimeoutError("slow")

    adapter = BurpAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    with pytest.raises(AdapterTimeout):
        adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_ACTIVE))


def test_server_error_on_scan_raises():
    def transport(method: str, url: str, body: str):
        return 500, "boom"

    adapter = BurpAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    with pytest.raises(AdapterProtocolError):
        adapter.job_status(JobHandle(job_id="42", adapter="burp", raw={"scan_id": "42"}))


def test_malformed_json_raises_protocol_error():
    def transport(method: str, url: str, body: str):
        return 200, "<html>not json</html>"

    adapter = BurpAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    with pytest.raises(AdapterProtocolError):
        adapter.issue_definitions()


# --- secret redaction ---------------------------------------------------------


def test_api_key_is_in_the_path_but_never_logged():
    seen: list[str] = []

    def transport(method: str, url: str, body: str):
        seen.append(url)
        return 200, json.dumps({"scan": "42", "scan_id": "42"})

    adapter = BurpAdapter(base_url=DEFAULT_BASE_URL, api_key="KEYXYZ", transport=transport)
    adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_ACTIVE))
    assert any("/KEYXYZ/v0.1/scan" in url for url in seen)
    # The host-only label never carries the secret path segment.
    assert "KEYXYZ" not in _endpoint_label(seen[0])


def test_auth_error_never_leaks_the_api_key():
    adapter = _adapter(FakeBurpBackend(fail="auth"), api_key="SUPERSECRETKEY")
    with pytest.raises(AdapterAuthError) as excinfo:
        adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_ACTIVE))
    assert "SUPERSECRETKEY" not in str(excinfo.value)


def test_keyless_access_omits_the_key_segment():
    seen: list[str] = []

    def transport(method: str, url: str, body: str):
        seen.append(url)
        return 200, json.dumps({"scan_id": "42"})

    adapter = BurpAdapter(base_url=DEFAULT_BASE_URL, api_key="", transport=transport)
    adapter.start_job(JobSpec(target="http://example.com/", kind=KIND_ACTIVE))
    assert any(url.endswith("/v0.1/scan") for url in seen)
    assert "//v0.1" not in seen[0]


# --- scope / authorization through the guard ---------------------------------


def _policy(cfg, **overrides) -> AdapterPolicy:
    defaults = dict(target_config=cfg.target("example.com"), ssrf_allow={"example.com"})
    defaults.update(overrides)
    return AdapterPolicy(**defaults)


def test_guarded_burp_rejects_out_of_scope(cfg):
    guarded = GuardedAdapter(_adapter(), _policy(cfg, ssrf_allow={"evil.test"}))
    with pytest.raises(AdapterPolicyError):
        guarded.start_job(JobSpec(target="https://evil.test/", kind=KIND_ACTIVE, authorized=True))


def test_guarded_burp_scan_requires_authorization(cfg):
    guarded = GuardedAdapter(_adapter(), _policy(cfg, allow_active=False))
    with pytest.raises(AdapterPolicyError):
        guarded.start_job(JobSpec(target="https://example.com/", kind=KIND_ACTIVE, authorized=True))


def test_guarded_burp_scan_requires_per_run_flag(cfg):
    guarded = GuardedAdapter(_adapter(), _policy(cfg, allow_active=True))
    with pytest.raises(AdapterPolicyError):
        guarded.start_job(JobSpec(target="https://example.com/", kind=KIND_ACTIVE, authorized=False))


def test_guarded_burp_active_allowed_and_collects(cfg, db, tmp_path):
    guarded = GuardedAdapter(_adapter(), _policy(cfg, allow_active=True, db=db,
                                                  killswitch=KillSwitch(tmp_path)))
    handle = guarded.start_job(JobSpec(target="https://example.com/", kind=KIND_ACTIVE,
                                       authorized=True))
    handle = guarded.wait(handle, poll_interval=0, sleep=lambda _s: None)
    findings = guarded.collect(handle)
    assert findings and handle.status == STATUS_COMPLETED
    actions = {e["action"] for e in db.query(
        "SELECT action FROM audit_events WHERE category = 'adapter'")}
    assert "adapter.burp.start" in actions and "adapter.burp.collect" in actions


# --- read-only retrieval + end-to-end import ---------------------------------


def test_existing_scan_handle_is_read_only_metadata():
    handle = existing_scan_handle(42)
    assert handle.job_id == "42" and handle.adapter == "burp"
    assert handle.raw["scan_id"] == "42"


def test_read_only_retrieval_from_existing_scan():
    adapter = _adapter()
    handle = adapter.job_status(existing_scan_handle(42))
    assert handle.status == STATUS_COMPLETED
    findings = adapter.collect(handle)
    assert findings and findings[0].adapter == "burp"


def test_burp_findings_import_with_provenance(cfg, db, tmp_path):
    tid = db.upsert_target("example.com")
    scan_id = db.create_scan(tid)
    guarded = GuardedAdapter(_adapter(), _policy(cfg, allow_active=True, db=db,
                                                 killswitch=KillSwitch(tmp_path)))
    handle = guarded.start_job(JobSpec(target="https://example.com/", kind=KIND_ACTIVE,
                                       authorized=True))
    findings = guarded.collect(guarded.wait(handle, poll_interval=0, sleep=lambda _s: None))
    report = ingest_findings(db, scan_id, findings, cfg.target("example.com"), phase="burp")
    assert report["finding_ids"]
    row = db.query_findings(scan_id=scan_id)[0]
    assert "burp" in row["tools_found"]
    evidence = db.query_evidence(scan_id=scan_id)
    assert evidence[0]["tool"] == "burp" and evidence[0]["source"] == "burp"
    assert "1049088" in evidence[0]["response_body"]   # plugin id provenance preserved


def test_build_burp_reads_config(monkeypatch):
    monkeypatch.setenv("BURP_API_KEY", "envkey")
    adapter = build_burp({"base_url": "http://burp.local:1337", "api_key_env": "BURP_API_KEY",
                          "timeout_seconds": 15})
    assert adapter.base_url == "http://burp.local:1337"
    assert adapter.api_key == "envkey"


# --- compatibility with ZAP + the generic registry ---------------------------


def test_registry_exposes_both_adapters():
    names = adapter_names()
    assert "zap" in names and "burp" in names
    assert has_adapter("burp") and has_adapter("zap")


def test_both_adapters_build_from_config(cfg):
    assert isinstance(build_adapter("zap", cfg), object)
    assert build_adapter("zap", cfg).name == "zap"
    assert build_adapter("burp", cfg).name == "burp"


def test_burp_evidence_is_untrusted_and_provenance_preserved(db):
    from lib.adapters.base import build_adapter_evidence

    tid = db.upsert_target("example.com")
    scan_id = db.create_scan(tid)
    finding = _adapter().collect(JobHandle(job_id="42", adapter="burp", raw={"scan_id": "42"}))[0]
    record = build_adapter_evidence(finding, phase="burp", scan_id=scan_id)
    assert record["trusted"] is False
    assert record["detection"]["plugin_id"] == "1049088"
    assert record["tool"] == "burp"


# --- CLI -----------------------------------------------------------------------


def _cli_args(**kwargs):
    import argparse
    base = {"health": False, "capabilities": False, "issue_definitions": False,
            "active": "", "authorize_active": False, "scan_id": None, "domain": "",
            "import_scan": 0, "collect": False, "timeout": 0.0, "poll": 1.0, "mock": False}
    base.update(kwargs)
    return argparse.Namespace(**base)


def _cli_cfg(enabled: bool = True) -> Config:
    """An offline config: example.com is in scope and SSRF-allowlisted (no DNS)."""
    return Config({
        "scanning": {"default_intensity": "quick-scan"},
        "targets": {"example.com": {"in_scope": ["example.com"]}},
        "integrations": {"burp": {"enabled": enabled, "base_url": DEFAULT_BASE_URL,
                                  "ssrf_allow": ["example.com"]}},
    }, {}, {})


def test_cmd_burp_disabled_without_mock(monkeypatch, capsys):
    import nexus

    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: _cli_cfg(enabled=False))
    rc = nexus.cmd_burp(_cli_args())
    assert rc == 1
    assert "disabled" in capsys.readouterr().err


def test_cmd_burp_mock_health(monkeypatch, capsys):
    import nexus

    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: _cli_cfg())
    rc = nexus.cmd_burp(_cli_args(mock=True, health=True))
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["reachable"] is True


def test_cmd_burp_mock_scan_requires_authorization(monkeypatch, capsys):
    import nexus

    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: _cli_cfg())
    rc = nexus.cmd_burp(_cli_args(mock=True, active="http://example.com/"))
    assert rc == 1
    assert "authorize" in capsys.readouterr().err


def test_cmd_burp_mock_active_scan_runs(monkeypatch, capsys):
    import nexus

    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: _cli_cfg())
    rc = nexus.cmd_burp(_cli_args(mock=True, active="http://example.com/",
                                  authorize_active=True, domain="example.com"))
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["job"]["status"] == STATUS_COMPLETED
    assert out["finding_count"] == 1


def test_cmd_burp_mock_scan_id_read_only(monkeypatch, capsys):
    import nexus

    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: _cli_cfg())
    rc = nexus.cmd_burp(_cli_args(mock=True, scan_id="42"))
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["finding_count"] == 1
    assert "authorize" not in out


def test_cmd_burp_out_of_scope_scan_rejected(monkeypatch, capsys):
    import nexus

    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: _cli_cfg())
    rc = nexus.cmd_burp(_cli_args(mock=True, active="http://evil.test/",
                                  authorize_active=True, domain="example.com"))
    assert rc == 1
    assert "blocked" in capsys.readouterr().err.lower()


def test_cmd_burp_spec_authorized_follows_flag(monkeypatch, capsys):
    """Regression: the JobSpec must carry the explicit authorization flag.

    Previously the Burp path hard-coded ``authorized=True``, bypassing the
    per-job gate in ``GuardedAdapter`` even when the flag was absent.
    """
    import nexus
    from lib.adapters import base as abase

    captured: dict = {}
    real_start = abase.GuardedAdapter.start_job

    def spy(self, job):
        captured["authorized"] = job.authorized
        return real_start(self, job)

    monkeypatch.setattr(abase.GuardedAdapter, "start_job", spy)
    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: _cli_cfg())
    rc = nexus.cmd_burp(_cli_args(mock=True, active="http://example.com/",
                                  authorize_active=True, domain="example.com"))
    assert rc == 0
    assert captured["authorized"] is True
