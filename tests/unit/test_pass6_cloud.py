"""Pass 6 â€” cloud posture tests (deterministic; fakes only, no real credentials).

Mocks/fixtures only: no cloud credentials, no cloud resources, no network.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from core import lifecycle
from lib.config import load_config
from lib.paths import CONFIG_DIR
from phases.cloud import cloud_orchestrator as co
from phases.cloud.engine import FORBIDDEN_METHOD_RE, redact
from phases.cloud.providers import AwsProvider

_ALLOWED_LOCAL_SETTERS = ("set_evidence_asset", "set_evidence_finding")


class NoCredentialsError(Exception):
    pass


class AccessDenied(Exception):
    pass


class _Fake:
    """Recording fake client. ``responses`` maps method â†’ value/callable/exception."""

    def __init__(self, responses=None, log=None):
        self.responses = responses or {}
        self.log = log if log is not None else []

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)

        def call(*args, **kwargs):
            self.log.append(name)
            value = self.responses.get(name)
            if isinstance(value, BaseException):
                raise value
            if callable(value):
                return value(*args, **kwargs)
            if value is None:
                raise RuntimeError(f"no fake response for {name}")
            return value

        return call


def _aws_fakes(overrides=None):
    log: list[str] = []
    sts = _Fake({"get_caller_identity": {"Account": "123456789012",
                                         "Arn": "arn:aws:iam::123456789012:user/t"}}, log)
    s3 = _Fake({
        "list_buckets": {"Buckets": [{"Name": "pub-bucket"}, {"Name": "priv-bucket"}]},
        "get_bucket_acl": lambda Bucket=None: {"Grants": (
            [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]
            if Bucket == "pub-bucket" else []
        )},
        "get_public_access_block": lambda Bucket=None: {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": Bucket != "pub-bucket",
            "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        }},
        "get_bucket_encryption": lambda Bucket=None: {"ServerSideEncryptionConfiguration": {}},
        "get_bucket_versioning": lambda Bucket=None: {"Status": "Enabled"},
    }, log)
    ec2 = _Fake({"describe_security_groups": {"SecurityGroups": [
        {"GroupName": "web", "IpPermissions": [
            {"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 22, "ToPort": 22,
             "IpProtocol": "tcp"},
        ]},
    ]}}, log)
    iam = _Fake({"get_account_summary": {"SummaryMap": {
        "AccountMFAEnabled": 0, "AccountAccessKeysPresent": 0}}}, log)
    ct = _Fake({"describe_trails": {"trailList": []}}, log)
    clients = {"sts": sts, "s3": s3, "ec2": ec2, "iam": iam, "cloudtrail": ct}
    if overrides:
        clients.update(overrides)
    return clients, log


def _prep(*, providers, accounts, in_scope=None, cloud_block_extra=None):
    cfg = load_config(CONFIG_DIR)
    block = {"enabled": True, "providers": providers, "accounts": accounts,
             "max_resources": 50}
    block.update(cloud_block_extra or {})
    cfg._main.setdefault("phases", {})["cloud"] = block
    tcfg = cfg.target("example.com")
    tcfg.in_scope = in_scope if in_scope is not None else ["example.com"]
    tcfg.scope_kind = "cloud"
    return cfg, tcfg


def _run(cfg, tcfg, db, tmp_path, clients=None, cancel=None):
    sid = db.create_scan(db.upsert_target("example.com"))
    out = co.run_cloud(cfg, tcfg, tmp_path / "results", db=db, scan_id=sid,
                       clients=clients, cancel_event=cancel)
    return out, sid


# --- provider selection / identity / scope ------------------------------------------

def test_provider_selection_only_selected_runs(db, tmp_path):
    clients, log = _aws_fakes()
    azure_log = []
    cfg, tcfg = _prep(providers=["aws"], accounts={"aws": ["123456789012"]})
    out, _ = _run(cfg, tcfg, db, tmp_path,
                  clients={"aws": clients, "azure": {"subscription": _Fake({}, azure_log)}})
    assert [p["provider"] for p in out["providers"]] == ["aws"]
    assert azure_log == []          # unselected provider never touched


def test_identity_not_allowlisted_blocked(db, tmp_path):
    clients, log = _aws_fakes()
    cfg, tcfg = _prep(providers=["aws"], accounts={"aws": ["999999999999"]})
    out, _ = _run(cfg, tcfg, db, tmp_path, clients={"aws": clients})
    assert out["status"] == "blocked"
    assert out["providers"][0]["status"] == "blocked"
    assert log == ["get_caller_identity"]      # stopped right after identity; nothing else


def test_missing_allowlist_fails_closed(db, tmp_path):
    clients, log = _aws_fakes()
    cfg, tcfg = _prep(providers=["aws"], accounts={})
    out, _ = _run(cfg, tcfg, db, tmp_path, clients={"aws": clients})
    assert out["status"] == "blocked"
    assert "allowlist" in out["providers"][0]["reason"]
    assert log == []                            # not a single API call


def test_cloud_scope_entry_mismatch_blocks(db, tmp_path):
    clients, log = _aws_fakes()
    cfg, tcfg = _prep(providers=["aws"], accounts={"aws": ["123456789012"]},
                      in_scope=["example.com", "cloud:azure"])
    out, _ = _run(cfg, tcfg, db, tmp_path, clients={"aws": clients})
    assert out["providers"][0]["status"] == "blocked"
    assert log == []


def test_missing_sdk_skipped_non_crashing(db, tmp_path, monkeypatch):
    monkeypatch.setattr(AwsProvider, "sdk_available", classmethod(lambda cls: False))
    cfg, tcfg = _prep(providers=["aws"], accounts={"aws": ["123456789012"]})
    out, _ = _run(cfg, tcfg, db, tmp_path, clients=None)
    assert out["status"] == "skipped" and out["phase_state"] == "skipped"
    assert "SDK" in out["providers"][0]["reason"]


def test_all_sdks_missing_skips_whole_phase(db, tmp_path, monkeypatch):
    for cls in (AwsProvider,):
        monkeypatch.setattr(cls, "sdk_available", classmethod(lambda c: False))
    cfg, tcfg = _prep(providers=["aws"], accounts={"aws": ["123456789012"]})
    out, _ = _run(cfg, tcfg, db, tmp_path)
    assert out["status"] == "skipped"


def test_azure_ambiguous_identity_fails_closed(db, tmp_path):
    class _Sub:
        def __init__(self, sid):
            self.subscription_id = sid

    class _List:
        def list(self):
            return [_Sub("sub-1"), _Sub("sub-2")]

    class _Subs:
        subscriptions = _List()

    cfg, tcfg = _prep(providers=["azure"], accounts={"azure": ["sub-1", "sub-2"]})
    out, _ = _run(cfg, tcfg, db, tmp_path,
                  clients={"azure": {"subscription": _Subs()}})
    assert out["providers"][0]["status"] == "failed"
    assert "ambiguous" in out["providers"][0]["reason"]


# --- statuses: credentials vs permissions vs errors -----------------------------------

def test_missing_credentials_status_not_conflated(db, tmp_path):
    sts = _Fake({"get_caller_identity": NoCredentialsError("no credentials found")})
    clients, _ = _aws_fakes(overrides={"sts": sts})
    cfg, tcfg = _prep(providers=["aws"], accounts={"aws": ["123456789012"]})
    out, _ = _run(cfg, tcfg, db, tmp_path, clients={"aws": clients})
    assert out["providers"][0]["status"] == "failed"    # identity unverifiable â†’ fail closed
    assert "identity" in out["providers"][0]["reason"]


def test_insufficient_permissions_distinguished_from_issue(db, tmp_path):
    ec2 = _Fake({"describe_security_groups": AccessDenied("not authorized")})
    clients, _ = _aws_fakes(overrides={"ec2": ec2})
    cfg, tcfg = _prep(providers=["aws"], accounts={"aws": ["123456789012"]})
    out, _ = _run(cfg, tcfg, db, tmp_path, clients={"aws": clients})
    assert out["providers"][0]["status"] == "partial"
    checks = json.loads(Path(out["snapshot"]).read_text(encoding="utf-8"))["checks"]
    network_review = [c for c in checks if c["check"] == "network_review"][0]
    assert network_review["status"] == "insufficient_permissions"


def test_api_error_yields_partial_with_other_checks(db, tmp_path):
    ct = _Fake({"describe_trails": RuntimeError("boom")})
    clients, _ = _aws_fakes(overrides={"cloudtrail": ct})
    cfg, tcfg = _prep(providers=["aws"], accounts={"aws": ["123456789012"]})
    out, _ = _run(cfg, tcfg, db, tmp_path, clients={"aws": clients})
    assert out["providers"][0]["status"] == "partial"
    snapshot = json.loads(Path(out["snapshot"]).read_text(encoding="utf-8"))
    logs = [c for c in snapshot["checks"] if c["check"] == "logging_review"][0]
    assert logs["status"] == "error"
    assert any(c["status"] == "issue" for c in snapshot["checks"])  # others still ran


# --- representative checks -----------------------------------------------------------

def test_public_exposure_and_posture_checks(db, tmp_path):
    clients, _ = _aws_fakes()
    cfg, tcfg = _prep(providers=["aws"], accounts={"aws": ["123456789012"]})
    out, sid = _run(cfg, tcfg, db, tmp_path, clients={"aws": clients})
    snapshot = json.loads(Path(out["snapshot"]).read_text(encoding="utf-8"))
    names = {c["check"]: c for c in snapshot["checks"]}
    assert names["storage_public_exposure"]["status"] == "issue"
    assert names["storage_public_exposure"]["severity"] == "P1"
    assert names["storage_public_access_block"]["status"] == "issue"
    assert names["network_open_ingress"]["status"] == "issue"
    assert names["network_open_ingress"]["severity"] == "P1"     # port 22 exposed
    assert names["iam_account_mfa"]["status"] == "issue"
    assert names["logging_audit_disabled"]["status"] == "issue"


def test_storage_encryption_and_versioning(db, tmp_path):
    s3 = _Fake({
        "list_buckets": {"Buckets": [{"Name": "enc-off"}, {"Name": "ver-off"}]},
        "get_bucket_acl": lambda Bucket=None: {"Grants": []},
        "get_public_access_block": lambda Bucket=None: {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True}},
        "get_bucket_encryption": lambda Bucket=None: (
            (_ for _ in ()).throw(Exception("ServerSideEncryptionConfigurationNotFoundError"))
            if Bucket == "enc-off" else {"ServerSideEncryptionConfiguration": {}}
        ),
        "get_bucket_versioning": lambda Bucket=None: {"Status": "Enabled" if Bucket == "enc-off" else ""},
    })
    clients, _ = _aws_fakes(overrides={"s3": s3})
    cfg, tcfg = _prep(providers=["aws"], accounts={"aws": ["123456789012"]})
    out, _ = _run(cfg, tcfg, db, tmp_path, clients={"aws": clients})
    snapshot = json.loads(Path(out["snapshot"]).read_text(encoding="utf-8"))
    names = {c["check"]: c for c in snapshot["checks"]}
    assert names["storage_encryption"]["status"] == "issue"
    assert names["storage_versioning"]["status"] == "issue"


# --- secret handling -----------------------------------------------------------------

def test_redaction_direct():
    token = "sk-" + "abc" + "0123456789abcdef"      # constructed at runtime
    data = {"secret_access_key": "SECRET123", "note": f"Bearer {token}",
            "nested": [{"password": "hunter2"}]}
    out = redact(data)
    assert out["secret_access_key"] == "[REDACTED]"
    assert out["nested"][0]["password"] == "[REDACTED]"
    dump = json.dumps(out)
    assert token not in dump
    assert "hunter2" not in dump


def test_secrets_never_persisted_end_to_end(db, tmp_path):
    leaky_token = "sk-" + "live" + "0123456789abcdef"   # constructed at runtime
    s3 = _Fake({
        "list_buckets": {"Buckets": [{"Name": leaky_token}]},
        "get_bucket_acl": lambda Bucket=None: {"Grants": [
            {"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
             "SecretAccessKey": "SECRETRAWSECRET"},
        ]},
        "get_public_access_block": lambda Bucket=None: {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": False, "IgnorePublicAcls": False,
            "BlockPublicPolicy": False, "RestrictPublicBuckets": False}},
        "get_bucket_encryption": lambda Bucket=None: {"ServerSideEncryptionConfiguration": {}},
        "get_bucket_versioning": lambda Bucket=None: {"Status": "Enabled"},
    })
    clients, _ = _aws_fakes(overrides={"s3": s3})
    cfg, tcfg = _prep(providers=["aws"], accounts={"aws": ["123456789012"]})
    out, sid = _run(cfg, tcfg, db, tmp_path, clients={"aws": clients})
    blob = json.dumps([dict(r) for r in db.query_evidence(scan_id=sid)], default=str)
    snapshot = Path(out["snapshot"]).read_text(encoding="utf-8")
    # a key-shaped token coming from the cloud API is redacted before persistence
    assert leaky_token not in blob
    assert leaky_token not in snapshot
    assert "[REDACTED-KEY]" in blob or "[REDACTED-KEY]" in snapshot


# --- linkage / lifecycle / budgets / cancellation ------------------------------------

def test_evidence_asset_linkage_and_phase(db, tmp_path):
    clients, _ = _aws_fakes()
    cfg, tcfg = _prep(providers=["aws"], accounts={"aws": ["123456789012"]})
    out, sid = _run(cfg, tcfg, db, tmp_path, clients={"aws": clients})
    rows = db.query_evidence(scan_id=sid)
    assert rows and all(r["source"] == "cloud" for r in rows)
    assert db.query("SELECT * FROM evidence_assets")
    from core.database import EVIDENCE_PHASES

    assert "cloud" in EVIDENCE_PHASES


def test_findings_seeded_and_ai_cannot_validate(db, tmp_path):
    clients, _ = _aws_fakes()
    cfg, tcfg = _prep(providers=["aws"], accounts={"aws": ["123456789012"]})
    out, sid = _run(cfg, tcfg, db, tmp_path, clients={"aws": clients})
    assert out["findings"] >= 1
    fid = db.query_findings(scan_id=sid)[0]["id"]
    assert lifecycle.current_state(db, fid) in ("probable", "candidate")
    with pytest.raises(lifecycle.InvalidTransition):
        lifecycle.transition(db, fid, "validated", actor="ai_cloud_agent")


def test_budget_exhaustion_skips_without_crash(db, tmp_path):
    from lib import ops_guard

    clients, _ = _aws_fakes()
    ops_guard.set_request_budget(1)
    try:
        cfg, tcfg = _prep(providers=["aws"], accounts={"aws": ["123456789012"]})
        out, _ = _run(cfg, tcfg, db, tmp_path, clients={"aws": clients})
        assert out["status"] in ("partial", "failed", "skipped")
    finally:
        ops_guard.set_request_budget(None)


def test_cancellation_yields_partial(db, tmp_path):
    clients, _ = _aws_fakes()
    cancel = threading.Event()
    cancel.set()
    cfg, tcfg = _prep(providers=["aws"], accounts={"aws": ["123456789012"]})
    out, _ = _run(cfg, tcfg, db, tmp_path, clients={"aws": clients}, cancel=cancel)
    assert out["phase_state"] in ("partial", "skipped")
    assert out["status"] != "completed"


def test_read_only_static_proof():
    import re

    offenders: list[str] = []
    for path in sorted(Path("phases/cloud").glob("*.py")):
        source = path.read_text(encoding="utf-8")
        for match in re.finditer(FORBIDDEN_METHOD_RE, source):
            fragment = source[max(0, match.start() - 80): match.end() + 40]
            if any(local in fragment for local in _ALLOWED_LOCAL_SETTERS):
                continue
            offenders.append(f"{path.name}: {match.group(0)}")
    assert offenders == []


def test_read_only_runtime_proof(db, tmp_path):
    clients, log = _aws_fakes()
    cfg, tcfg = _prep(providers=["aws"], accounts={"aws": ["123456789012"]})
    _run(cfg, tcfg, db, tmp_path, clients={"aws": clients})
    assert log and all(
        name.split(".")[-1].split("_")[0] in ("get", "list", "describe")
        for name in log
    )


def test_gcp_flow_representative(db, tmp_path):
    class _Bucket:
        name = "gcp-bucket"
        versioning_enabled = True

        def get_iam_policy(self, requested_policy_version=1):
            return {"bindings": [{"members": ["allUsers"]}]}

    class _Storage:
        def list_buckets(self):
            return [_Bucket()]

    class _Firewalls:
        def list(self):
            return [{"name": "fw-open", "sourceRanges": ["0.0.0.0/0"],
                     "allowed": [{"ports": ["22"]}]}]

    class _Compute:
        def firewalls(self):
            return _Firewalls()

    class _Project:
        project_id = "demo-proj"

    class _AuditConfigs:
        def get(self, name=None):
            return {}

    class _Projects:
        audit_configs = _AuditConfigs()

        def get(self, name=None):
            return _Project()

    cfg, tcfg = _prep(providers=["gcp"], accounts={"gcp": ["demo-proj"]})
    out, _ = _run(cfg, tcfg, db, tmp_path,
                  clients={"gcp": {"projects": _Projects(), "storage": _Storage(),
                                    "compute": _Compute()}})
    snapshot = json.loads(Path(out["snapshot"]).read_text(encoding="utf-8"))
    names = {c["check"]: c for c in snapshot["checks"]}
    assert names["storage_public_exposure"]["status"] == "issue"
    assert names["network_open_ingress"]["status"] == "issue"
    assert names["logging_audit_disabled"]["status"] == "issue"
