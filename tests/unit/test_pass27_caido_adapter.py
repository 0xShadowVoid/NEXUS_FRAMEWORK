"""Pass 27 — Caido adapter (Task 19), mocked/offline only.

No live Caido instance is required: every call goes through an injected
deterministic transport. Caido's instance GraphQL API is read-only for us (no
documented remote scan/job API), so the tests focus on retrieval, normalization,
provenance, redaction, and the scope/SSRF gates.
"""
from __future__ import annotations

import json

import pytest

from core.database import Database
from lib.adapters.base import (
    KIND_ACTIVE,
    STATUS_COMPLETED,
    AdapterAuthError,
    AdapterError,
    AdapterPolicy,
    AdapterPolicyError,
    AdapterProtocolError,
    AdapterTimeout,
    AdapterUnavailable,
    GuardedAdapter,
    JobSpec,
    ingest_findings,
)
from lib.adapters.burp import MockBurpAdapter
from lib.adapters.caido import (
    DEFAULT_BASE_URL,
    CaidoAdapter,
    FakeCaidoBackend,
    MockCaidoAdapter,
    _requests_query,
    build_caido,
    default_finding,
    default_request,
    read_handle,
)
from lib.adapters.registry import adapter_names, build_adapter, has_adapter
from lib.adapters.zap import MockZapAdapter
from lib.config import Config


def _adapter(backend: FakeCaidoBackend | None = None, **kwargs) -> MockCaidoAdapter:
    return MockCaidoAdapter(backend=backend or FakeCaidoBackend(), **kwargs)


# --- health + capability discovery -------------------------------------------


def test_default_base_url_is_loopback():
    assert DEFAULT_BASE_URL == "http://127.0.0.1:8080"


def test_health_ok():
    health = _adapter().health()
    assert health.reachable is True
    assert health.details["api"] == "Caido instance GraphQL API"
    assert health.details["auth"] == "bearer"
    assert health.details["viewer"] == "CloudUser"


def test_health_auth_failure_is_reported_not_raised():
    health = _adapter(FakeCaidoBackend(fail="auth")).health()
    assert health.reachable is False
    assert "authentication" in health.error.lower()


def test_health_unreachable_is_reported_not_raised():
    health = _adapter(FakeCaidoBackend(fail="unreachable")).health()
    assert health.reachable is False
    assert "unreachable" in health.error.lower()


def test_health_malformed_is_reported_not_raised():
    health = _adapter(FakeCaidoBackend(fail="malformed")).health()
    assert health.reachable is False


def test_health_graphql_error_is_reported_not_raised():
    health = _adapter(FakeCaidoBackend(fail="gql")).health()
    assert health.reachable is False
    assert "graphql error" in health.error.lower()


def test_capabilities_are_read_only():
    caps = _adapter().capabilities()
    names = {c.name for c in caps}
    assert names == {"health", "capability-discovery", "finding-retrieval", "request-retrieval"}
    assert not any(c.active for c in caps)


def test_introspect_live_discovery():
    fields = _adapter().introspect()
    assert "findings" in fields and "requests" in fields


def test_introspect_malformed_schema_raises():
    def transport(method, url, headers, body):
        return 200, json.dumps({"data": {"__schema": {}}})

    adapter = CaidoAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    with pytest.raises(AdapterProtocolError):
        adapter.introspect()


def test_finding_reporters():
    assert _adapter().finding_reporters() == ["nexus-plugin"]


def test_validate_config_flags_bad_base_url():
    assert CaidoAdapter(base_url="ftp://nope").validate_config()


# --- retrieval / normalization -----------------------------------------------


def test_findings_normalized():
    findings = _adapter().findings()
    assert len(findings) == 1
    f = findings[0]
    assert f.adapter == "caido" and f.source == "caido"
    assert f.name == "SQL injection"
    assert f.severity == "P4" and f.confidence == 50
    assert f.endpoint == "https://example.com/item"
    assert f.plugin_id == "nexus-plugin"            # reporter as provenance
    assert f.alert_id == "1"
    assert f.extra["request_id"] == "7"
    assert f.evidence == "request_id=7 reporter=nexus-plugin"


def test_finding_endpoint_keeps_explicit_scheme():
    node = dict(default_finding()); node["host"] = "http://insecure.test"
    f = _adapter().normalize_finding(node)
    assert f.endpoint == "http://insecure.test/item"


def test_findings_reporter_filter_in_query():
    backend = FakeCaidoBackend()
    _adapter(backend).findings(reporter="aucun-plugin")
    assert "aucun-plugin" in backend.calls[-1][3]


def test_findings_malformed_edges_raises():
    def transport(method, url, headers, body):
        return 200, json.dumps({"data": {"findings": {"edges": "nope"}}})

    adapter = CaidoAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    with pytest.raises(AdapterProtocolError):
        adapter.findings()


def test_findings_missing_collection_raises():
    def transport(method, url, headers, body):
        return 200, json.dumps({"data": {}})

    adapter = CaidoAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    with pytest.raises(AdapterProtocolError):
        adapter.findings()


def test_requests_normalized():
    rows = _adapter().requests()
    assert rows == [{
        "id": "7", "method": "POST", "host": "example.com", "path": "/item",
        "query": "id=1", "created_at": "1700000000", "status_code": 500, "length": 1234,
    }]


def test_requests_query_contains_httpql():
    q = _requests_query(50, None, "resp.code.gte:400")
    assert "resp.code.gte:400" in q


# --- untrusted content + redaction -------------------------------------------


def test_finding_description_and_dedupe_are_sanitized():
    node = dict(default_finding())
    node["description"] = "Authorization: Bearer ghp_" + "A" * 24
    node["dedupeKey"] = "token=supersecretvalue1234567890"
    f = _adapter().normalize_finding(node)
    assert "ghp_" + "A" * 24 not in f.description
    assert "supersecretvalue1234567890" not in f.other_info


def test_request_metadata_is_sanitized():
    req = dict(default_request()); req["path"] = "/?token=supersecretvalue1234567890"
    row = _adapter().normalize_request(req)
    assert "supersecretvalue1234567890" not in row["path"]


def test_token_is_sent_as_bearer_header():
    backend = FakeCaidoBackend()
    _adapter(backend, token="caido_MOCKTOKEN").findings()
    assert backend.calls[-1][2].get("Authorization") == "Bearer caido_MOCKTOKEN"


def test_auth_error_never_leaks_the_token():
    adapter = _adapter(FakeCaidoBackend(fail="auth"), token="caido_SUPERSECRET")
    with pytest.raises(AdapterAuthError) as excinfo:
        adapter.findings()
    assert "caido_SUPERSECRET" not in str(excinfo.value)


def test_health_error_never_leaks_the_token():
    adapter = _adapter(FakeCaidoBackend(fail="auth"), token="caido_SUPERSECRET")
    assert "caido_SUPERSECRET" not in adapter.health().error


def test_keyless_access_omits_authorization_header():
    backend = FakeCaidoBackend()
    _adapter(backend, token="").findings()
    assert "Authorization" not in backend.calls[-1][2]


# --- normalized errors / timeouts --------------------------------------------


def test_transport_timeout_normalized():
    def transport(method, url, headers, body):
        raise TimeoutError("slow")

    adapter = CaidoAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    with pytest.raises(AdapterTimeout):
        adapter.findings()


def test_connection_failure_normalized():
    def transport(method, url, headers, body):
        raise ConnectionError("refused")

    adapter = CaidoAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    with pytest.raises(AdapterUnavailable):
        adapter.findings()


def test_server_error_normalized():
    def transport(method, url, headers, body):
        return 500, "boom"

    adapter = CaidoAdapter(base_url=DEFAULT_BASE_URL, transport=transport)
    with pytest.raises(AdapterProtocolError):
        adapter.findings()


def test_no_data_normalized():
    adapter = _adapter(FakeCaidoBackend(fail="no_data"))
    with pytest.raises(AdapterProtocolError):
        adapter.findings()


# --- SSRF protection of the connection endpoint ------------------------------


def test_metadata_endpoint_blocked_by_ssrf():
    adapter = CaidoAdapter(base_url="http://169.254.169.254")
    health = adapter.health()
    assert health.reachable is False
    assert "ssrf" in health.error.lower()


def test_metadata_endpoint_raises_on_retrieval():
    adapter = CaidoAdapter(base_url="http://169.254.169.254")
    with pytest.raises(AdapterError, match="SSRF"):
        adapter.findings()


# --- unsupported operations (no remote scan API) -----------------------------


def test_start_job_unsupported_for_every_kind():
    adapter = _adapter()
    with pytest.raises(AdapterError, match="unsupported operation"):
        adapter.start_job(JobSpec(target="https://example.com/", kind=KIND_ACTIVE, authorized=True))


def test_cancel_job_returns_false():
    assert _adapter().cancel_job(read_handle()) is False


def test_read_handle_is_terminal_and_has_no_scan():
    handle = read_handle(reporter="nexus-plugin")
    assert handle.raw["reporter"] == "nexus-plugin"
    assert _adapter().job_status(handle).status == STATUS_COMPLETED


def test_collect_uses_read_handle():
    findings = _adapter().collect(read_handle(reporter="nexus-plugin"))
    assert len(findings) == 1 and findings[0].adapter == "caido"


# --- scope / authorization via the guard (defence in depth) ------------------


def _policy(cfg, **overrides) -> AdapterPolicy:
    defaults = dict(target_config=cfg.target("example.com"), ssrf_allow={"example.com"})
    defaults.update(overrides)
    return AdapterPolicy(**defaults)


def test_guarded_rejects_out_of_scope_target(cfg):
    guarded = GuardedAdapter(_adapter(), _policy(cfg, ssrf_allow={"evil.test"}))
    with pytest.raises(AdapterPolicyError, match="scope"):
        guarded.start_job(JobSpec(target="https://evil.test/", kind=KIND_ACTIVE, authorized=True))


def test_guarded_in_scope_active_still_hits_unsupported_op(cfg):
    guarded = GuardedAdapter(_adapter(), _policy(cfg, allow_active=True))
    with pytest.raises(AdapterError, match="unsupported operation"):
        guarded.start_job(JobSpec(target="https://example.com/", kind=KIND_ACTIVE, authorized=True))


# --- import / evidence provenance --------------------------------------------


def test_findings_import_with_provenance(cfg, db):
    sid = db.create_scan(db.upsert_target("example.com"))
    findings = _adapter().findings()
    report = ingest_findings(db, sid, findings, cfg.target("example.com"), phase="caido")
    assert report["finding_ids"] and report["out_of_scope"] == 0
    row = db.query_findings(scan_id=sid)[0]
    assert "caido" in row["tools_found"]
    evidence = db.query_evidence(scan_id=sid)[0]
    assert evidence["tool"] == "caido" and evidence["source"] == "caido"
    assert "nexus-plugin" in evidence["response_body"]      # reporter provenance
    assert "request_id=7" in evidence["response_body"]       # request provenance


def test_out_of_scope_finding_marked_not_in_scope(cfg, db):
    sid = db.create_scan(db.upsert_target("example.com"))
    node = dict(default_finding()); node["host"] = "evil.test"
    findings = [_adapter().normalize_finding(node)]
    report = ingest_findings(db, sid, findings, cfg.target("example.com"), phase="caido")
    assert report["out_of_scope"] == 1
    assert db.query_findings(scan_id=sid)[0]["in_scope"] in (0, False)


def test_build_caido_reads_token_from_env(monkeypatch):
    monkeypatch.setenv("CAIDO_PAT", "caido_envtoken")
    adapter = build_caido({"base_url": "http://caido.internal:8080",
                           "api_key_env": "CAIDO_PAT", "timeout_seconds": 15})
    assert adapter.base_url == "http://caido.internal:8080"
    assert adapter.token == "caido_envtoken"


# --- registry + cross-adapter compatibility ----------------------------------


def test_registry_exposes_all_three_adapters():
    names = adapter_names()
    assert {"zap", "burp", "caido"}.issubset(set(names))
    assert has_adapter("caido")


def test_all_adapters_build_from_config(cfg):
    assert build_adapter("zap", cfg).name == "zap"
    assert build_adapter("burp", cfg).name == "burp"
    assert build_adapter("caido", cfg).name == "caido"


def test_adapters_share_the_same_contract():
    for adapter in (MockZapAdapter(), MockBurpAdapter(), MockCaidoAdapter()):
        assert adapter.capabilities()          # all implement capability discovery
        assert adapter.health() is not None    # and health
        assert adapter.name in {"zap", "burp", "caido"}


# --- CLI -----------------------------------------------------------------------


def _cli_args(**kwargs):
    import argparse
    base = {"health": False, "capabilities": False, "introspect": False, "findings": False,
            "requests": False, "reporter": "", "httpql": "", "limit": 0, "import_scan": 0,
            "domain": "", "timeout": 0.0, "mock": False}
    base.update(kwargs)
    return argparse.Namespace(**base)


def _cli_cfg(enabled: bool = True, db_path=None) -> Config:
    main = {
        "scanning": {"default_intensity": "quick-scan"},
        "targets": {"example.com": {"in_scope": ["example.com"]}},
        "integrations": {"caido": {"enabled": enabled, "base_url": DEFAULT_BASE_URL}},
    }
    if db_path is not None:
        main["database"] = {"path": str(db_path)}
    return Config(main, {}, {})


def test_cmd_caido_disabled_without_mock(monkeypatch, capsys):
    import nexus

    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: _cli_cfg(enabled=False))
    rc = nexus.cmd_caido(_cli_args())
    assert rc == 1
    assert "disabled" in capsys.readouterr().err


def test_cmd_caido_mock_health(monkeypatch, capsys):
    import nexus

    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: _cli_cfg())
    rc = nexus.cmd_caido(_cli_args(mock=True, health=True))
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["reachable"] is True


def test_cmd_caido_mock_findings(monkeypatch, capsys):
    import nexus

    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: _cli_cfg())
    rc = nexus.cmd_caido(_cli_args(mock=True, findings=True))
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["finding_count"] == 1 and out["findings"][0]["adapter"] == "caido"


def test_cmd_caido_mock_requests(monkeypatch, capsys):
    import nexus

    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: _cli_cfg())
    rc = nexus.cmd_caido(_cli_args(mock=True, requests=True))
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["request_count"] == 1
    assert "findings" not in out


def test_cmd_caido_import_findings(monkeypatch, capsys, tmp_path):
    import nexus

    db_path = tmp_path / "nexus.db"
    seed = Database(str(db_path))
    sid = seed.create_scan(seed.upsert_target("example.com"))
    seed.close()

    monkeypatch.setattr(nexus, "load_config", lambda *a, **k: _cli_cfg(db_path=db_path))
    rc = nexus.cmd_caido(_cli_args(mock=True, findings=True, import_scan=sid, domain="example.com"))
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["import"]["finding_ids"]

    check = Database(str(db_path))
    assert len(check.query_findings(scan_id=sid)) == 1
    check.close()
