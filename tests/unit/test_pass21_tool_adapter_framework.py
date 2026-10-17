"""Pass 21 — security-tool adapter framework (Task 14), deterministic/offline."""
from __future__ import annotations

import pytest

from lib.adapters.base import (
    KIND_ACTIVE,
    KIND_PASSIVE,
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_RUNNING,
    AdapterCapability,
    AdapterHealth,
    AdapterPolicy,
    AdapterPolicyError,
    GuardedAdapter,
    JobHandle,
    JobSpec,
    RawFinding,
    SecurityToolAdapter,
    build_adapter_evidence,
    confidence_from_word,
    ingest_findings,
    severity_from_risk,
)
from lib.adapters.registry import adapter_names, api_key_for, build_adapter, has_adapter
from lib.exceptions import NexusError
from lib.ops_guard import KillSwitch, set_request_budget


class FakeAdapter(SecurityToolAdapter):
    """Minimal in-memory adapter for framework tests."""

    name = "fake"

    def __init__(self, alerts: list[RawFinding] | None = None):
        self.alerts = alerts or []
        self.started: list[JobSpec] = []
        self._cancelled = False

    def capabilities(self):
        return [AdapterCapability("passive-scan", active=False),
                AdapterCapability("active-scan", active=True)]

    def health(self):
        return AdapterHealth(name=self.name, reachable=True, version="1.0")

    def start_job(self, job: JobSpec) -> JobHandle:
        self.started.append(job)
        return JobHandle(job_id="j1", adapter=self.name, target=job.target,
                         kind=job.kind, status=STATUS_RUNNING)

    def job_status(self, handle: JobHandle) -> JobHandle:
        handle.status = STATUS_COMPLETED
        handle.progress = 100
        return handle

    def cancel_job(self, handle: JobHandle) -> bool:
        self._cancelled = True
        handle.status = STATUS_CANCELLED
        return True

    def collect(self, handle: JobHandle):
        return list(self.alerts)


def _policy(cfg, **overrides) -> AdapterPolicy:
    defaults = dict(target_config=cfg.target("example.com"), ssrf_allow={"example.com"})
    defaults.update(overrides)
    return AdapterPolicy(**defaults)


# --- severity / confidence helpers --------------------------------------------


def test_severity_from_risk_mapping():
    assert severity_from_risk("High") == "P2"
    assert severity_from_risk("medium") == "P3"
    assert severity_from_risk("Informational") == "P4"
    assert severity_from_risk("P1") == "P1"
    assert severity_from_risk(None) == "P4"


def test_confidence_from_word_mapping():
    assert confidence_from_word("High") == 90
    assert confidence_from_word("70") == 70
    assert confidence_from_word(33) == 33
    assert confidence_from_word("bogus") == 50


# --- policy guard -------------------------------------------------------------


def test_guard_rejects_out_of_scope_target(cfg):
    guarded = GuardedAdapter(FakeAdapter(), _policy(cfg, ssrf_allow={"evil.test"}))
    with pytest.raises(AdapterPolicyError):
        guarded.start_job(JobSpec(target="https://evil.test/", kind=KIND_PASSIVE))


def test_guard_allows_in_scope_target(cfg):
    adapter = FakeAdapter()
    guarded = GuardedAdapter(adapter, _policy(cfg))
    handle = guarded.start_job(JobSpec(target="https://example.com/", kind=KIND_PASSIVE))
    assert handle.status == STATUS_RUNNING
    assert adapter.started and adapter.started[0].target == "https://example.com/"


def test_guard_blocks_active_without_policy_allow(cfg):
    guarded = GuardedAdapter(FakeAdapter(), _policy(cfg, allow_active=False))
    with pytest.raises(AdapterPolicyError):
        guarded.start_job(JobSpec(target="https://example.com/", kind=KIND_ACTIVE, authorized=True))


def test_guard_blocks_active_without_run_authorization(cfg):
    guarded = GuardedAdapter(FakeAdapter(), _policy(cfg, allow_active=True))
    with pytest.raises(AdapterPolicyError):
        guarded.start_job(JobSpec(target="https://example.com/", kind=KIND_ACTIVE, authorized=False))


def test_guard_allows_active_when_both_granted(cfg):
    guarded = GuardedAdapter(FakeAdapter(), _policy(cfg, allow_active=True))
    handle = guarded.start_job(JobSpec(target="https://example.com/", kind=KIND_ACTIVE, authorized=True))
    assert handle.kind == KIND_ACTIVE


def test_guard_honors_kill_switch(cfg, tmp_path):
    ks = KillSwitch(tmp_path)
    ks.kill()
    guarded = GuardedAdapter(FakeAdapter(), _policy(cfg, killswitch=ks))
    with pytest.raises(AdapterPolicyError):
        guarded.start_job(JobSpec(target="https://example.com/", kind=KIND_PASSIVE))


def test_guard_enforces_request_budget(cfg):
    set_request_budget(0)
    try:
        guarded = GuardedAdapter(FakeAdapter(), _policy(cfg))
        with pytest.raises(AdapterPolicyError):
            guarded.start_job(JobSpec(target="https://example.com/", kind=KIND_PASSIVE))
    finally:
        set_request_budget(None)


def test_guard_requires_target(cfg):
    guarded = GuardedAdapter(FakeAdapter(), _policy(cfg))
    with pytest.raises(AdapterPolicyError):
        guarded.start_job(JobSpec(target="", kind=KIND_PASSIVE))


def test_guard_writes_audit_events(cfg, db):
    guarded = GuardedAdapter(FakeAdapter(), _policy(cfg, db=db))
    guarded.start_job(JobSpec(target="https://example.com/", kind=KIND_PASSIVE))
    events = db.query("SELECT action FROM audit_events WHERE category = 'adapter'")
    assert "adapter.fake.start" in {e["action"] for e in events}


def test_guard_wait_returns_on_kill_switch(cfg, tmp_path):
    ks = KillSwitch(tmp_path)
    guarded = GuardedAdapter(FakeAdapter(), _policy(cfg, killswitch=ks))
    handle = JobHandle(job_id="j1", adapter="fake", target="https://example.com/",
                       kind=KIND_PASSIVE, status=STATUS_RUNNING)
    ks.kill()
    out = guarded.wait(handle, poll_interval=0, sleep=lambda _s: None)
    assert out.status == STATUS_CANCELLED


# --- ingestion / provenance ---------------------------------------------------


def _scan(db) -> int:
    tid = db.upsert_target("example.com")
    return db.create_scan(tid)


def test_ingest_findings_provenance_and_scope(cfg, db):
    scan_id = _scan(db)
    findings = [
        RawFinding(adapter="fake", source="fake", name="SQLi", severity="P1", confidence=90,
                   endpoint="https://example.com/a?q=1", method="POST", plugin_id="40018",
                   alert_id="7", evidence="payload reflected", other_info="ctx"),
        RawFinding(adapter="fake", source="fake", name="XSS", severity="P3", confidence=70,
                   endpoint="https://evil.test/x"),
    ]
    result = ingest_findings(db, scan_id, findings, cfg.target("example.com"), phase="fake")
    assert len(result["finding_ids"]) == 2
    assert len(result["evidence_ids"]) == 2
    assert result["out_of_scope"] == 1

    rows = {r["vuln_type"]: r for r in db.query_findings(scan_id=scan_id)}
    assert rows["SQLi"]["in_scope"] == 1
    assert rows["XSS"]["in_scope"] == 0
    assert "fake" in rows["SQLi"]["tools_found"]

    evidence = db.query_evidence(scan_id=scan_id)
    assert all(e["tool"] == "fake" for e in evidence)
    assert all(e["source"] == "fake" for e in evidence)


def test_ingest_sanitizes_untrusted_evidence(cfg, db):
    scan_id = _scan(db)
    finding = RawFinding(
        adapter="fake", source="fake", name="Leak", endpoint="https://example.com/",
        evidence="Authorization: Bearer sk-abcdefghijklmnop1234567890",
        other_info="token=supersecretvalue12345",
    )
    result = ingest_findings(db, scan_id, [finding], cfg.target("example.com"))
    rows = db.query_evidence(scan_id=scan_id)
    body = rows[0]["response_body"]
    assert "sk-abcdefghijklmnop1234567890" not in body
    assert "supersecretvalue12345" not in body
    assert result["evidence_ids"]


def test_build_adapter_evidence_schema():
    finding = RawFinding(adapter="zap", source="zap", name="CSP", plugin_id="10038",
                         alert_id="1", cwe_id="693", endpoint="http://x/")
    record = build_adapter_evidence(finding, phase="zap", finding_ref=5, scan_id=9)
    assert record["trusted"] is False
    assert record["detection"]["plugin_id"] == "10038"
    assert record["finding_reference"] == 5
    assert record["scan_id"] == 9


# --- registry -----------------------------------------------------------------


def test_registry_lists_zap():
    assert "zap" in adapter_names()
    assert has_adapter("zap")


def test_registry_build_from_config(cfg):
    adapter = build_adapter("zap", cfg)
    assert adapter.name == "zap"
    assert adapter.base_url.startswith("http")


def test_registry_unknown_adapter_raises(cfg):
    with pytest.raises(NexusError):
        build_adapter("does-not-exist", cfg)


def test_api_key_read_from_env(monkeypatch):
    monkeypatch.setenv("ZAP_API_KEY", "s3cr3t-key")
    assert api_key_for({"api_key_env": "ZAP_API_KEY"}) == "s3cr3t-key"
    assert api_key_for({}) == ""


# --- backward compatibility ---------------------------------------------------


def test_existing_tool_execution_unaffected():
    from lib.tool_registry import get_registry
    from phases.probe.tool_runner import TOOL_CATALOG, ToolResult, ToolRunner

    assert "nuclei" in TOOL_CATALOG
    assert get_registry().get("nuclei") is not None
    assert ToolRunner is not None and ToolResult(tool="x", cmd=[], returncode=0).ok
