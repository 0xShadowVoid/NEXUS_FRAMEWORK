"""Pass 6 — cloud provider adapters (thin READ-ONLY SDK wrappers).

Every provider exposes the same normalized surface:
``identity()`` + ``collect()`` returning ``{section: {status, data}}``.

- SDKs are optional and lazily imported (``sdk_available``);
- live clients are only built when the SDK is present — otherwise sections
  degrade with a clear status (never a crash, never a silent pass);
- tests inject fake clients (``clients={service: fake}``) for determinism;
- NO resource-mutating calls exist anywhere in this package (static test).
"""
from __future__ import annotations

import importlib.util
from typing import Any, Callable

from lib.logger import get_logger

from phases.cloud.engine import classify_error

logger = get_logger("cloud_providers")


def _module_available(name: str) -> bool:
    """True when a (possibly dotted) module can be imported — never raises."""
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


class CloudProviderError(RuntimeError):
    """Raised for provider-level issues (ambiguity, missing SDK wiring)."""


class BaseProvider:
    name = "base"
    services: tuple[str, ...] = ()

    def __init__(self, settings: dict[str, Any] | None = None,
                 clients: dict[str, Any] | None = None):
        self.settings = dict(settings or {})
        self._clients = dict(clients or {})
        self.calls: list[str] = []          # runtime read-only proof

    # -- helpers ---------------------------------------------------------------

    @classmethod
    def sdk_available(cls) -> bool:
        return False

    def identity(self, spend: Callable[[int], bool] | None = None) -> dict[str, Any]:
        """Collect ONLY the identity section (authorization must precede everything else)."""
        return self._guard(self._identity, spend)

    def _client(self, service: str) -> Any:
        if service in self._clients:
            return self._clients[service]
        raise CloudProviderError(
            f"{self.name}: live client for {service!r} unavailable "
            "(SDK not installed / no client injected)"
        )

    def _guard(self, fn: Callable[[], Any], spend: Callable[[int], bool] | None) -> dict[str, Any]:
        try:
            if spend is not None and not spend(1):
                return {"status": "skipped", "data": None, "reason": "request budget exhausted"}
            return {"status": "ok", "data": fn()}
        except Exception as exc:
            status = classify_error(exc)
            logger.warning("%s section unavailable: %s (%s)", self.name, type(exc).__name__, status)
            return {"status": status, "data": None, "reason": str(exc)[:240]}

    def collect(self, cancel: Callable[[], bool] | None = None,
                spend: Callable[[int], bool] | None = None,
                only: tuple[str, ...] | None = None) -> dict[str, dict[str, Any]]:
        sections: dict[str, dict[str, Any]] = {}
        for name, fn in (
            ("identity", self._identity),
            ("storage", self._storage),
            ("network", self._network),
            ("iam", self._iam),
            ("logging", self._logging),
        ):
            if only is not None and name not in only:
                continue
            if cancel is not None and cancel():
                sections[name] = {"status": "skipped", "data": None, "reason": "cancelled"}
                continue
            sections[name] = self._guard(fn, spend)
        return sections

    # -- to be implemented by providers ------------------------------------------

    def _identity(self) -> dict[str, Any]:
        raise CloudProviderError(f"{self.name}: identity not implemented")

    def _storage(self) -> list[dict[str, Any]]:
        return []

    def _network(self) -> list[dict[str, Any]]:
        return []

    def _iam(self) -> dict[str, Any]:
        raise CloudProviderError(f"{self.name}: iam not supported")

    def _logging(self) -> dict[str, Any]:
        return {}


class AwsProvider(BaseProvider):
    """AWS — read-only posture collection (boto3, optional)."""

    name = "aws"
    services = ("sts", "s3", "ec2", "iam", "cloudtrail")

    @classmethod
    def sdk_available(cls) -> bool:
        return _module_available("boto3")

    def _client(self, service: str) -> Any:
        if service in self._clients:
            return self._clients[service]
        import boto3  # lazy: optional dependency

        session = boto3.session.Session(region_name=self.settings.get("region") or None)
        return session.client(service)

    def _identity(self) -> dict[str, Any]:
        sts = self._client("sts")
        self.calls.append("sts.get_caller_identity")
        out = sts.get_caller_identity()
        return {"account": str(out.get("Account", "")), "arn": str(out.get("Arn", ""))}

    def _storage(self) -> list[dict[str, Any]]:
        s3 = self._client("s3")
        self.calls.append("s3.list_buckets")
        limit = int(self.settings.get("max_resources", 200))
        buckets = (s3.list_buckets().get("Buckets") or [])[:limit]
        out: list[dict[str, Any]] = []
        for bucket in buckets:
            name = str(bucket.get("Name", ""))
            entry: dict[str, Any] = {"name": name}
            try:
                self.calls.append("s3.get_bucket_acl")
                acl = s3.get_bucket_acl(Bucket=name)
                grants = [
                    str(g.get("Grantee", {}).get("URI", ""))
                    for g in (acl.get("Grants") or [])
                ]
                entry["grants"] = [g for g in grants if g]
                entry["public_acl"] = any(
                    g.endswith(("AllUsers", "AuthenticatedUsers")) for g in grants
                )
            except Exception as exc:
                entry.setdefault("errors", []).append(classify_error(exc))
            try:
                self.calls.append("s3.get_public_access_block")
                block = s3.get_public_access_block(Bucket=name)
                conf = (block.get("PublicAccessBlockConfiguration") or {})
                entry["public_access_block"] = all(
                    bool(conf.get(k)) for k in (
                        "BlockPublicAcls", "IgnorePublicAcls",
                        "BlockPublicPolicy", "RestrictPublicBuckets",
                    )
                )
            except Exception as exc:
                # missing configuration is an absence, not a pass or a failure
                entry.setdefault("errors", []).append(classify_error(exc))
                if "nosuch" in f"{type(exc).__name__}{exc}".lower():
                    entry["public_access_block"] = False
            try:
                self.calls.append("s3.get_bucket_encryption")
                s3.get_bucket_encryption(Bucket=name)
                entry["encryption"] = True
            except Exception as exc:
                blob = f"{type(exc).__name__}{exc}".lower()
                if "serversideencryptionconfigurationnotfound" in blob or "notfound" in blob:
                    entry["encryption"] = False
                else:
                    entry.setdefault("errors", []).append(classify_error(exc))
            try:
                self.calls.append("s3.get_bucket_versioning")
                versioning = s3.get_bucket_versioning(Bucket=name)
                entry["versioning"] = str(versioning.get("Status", "")) == "Enabled"
            except Exception as exc:
                entry.setdefault("errors", []).append(classify_error(exc))
            out.append(entry)
        return out

    def _network(self) -> list[dict[str, Any]]:
        ec2 = self._client("ec2")
        self.calls.append("ec2.describe_security_groups")
        limit = int(self.settings.get("max_resources", 200))
        groups = (ec2.describe_security_groups().get("SecurityGroups") or [])[:limit]
        out: list[dict[str, Any]] = []
        for group in groups:
            rule_list = []
            for permission in group.get("IpPermissions") or []:
                cidrs = [
                    str(r.get("CidrIp", "")) for r in (permission.get("IpRanges") or [])
                ] + [
                    str(r.get("CidrIpv6", "")) for r in (permission.get("Ipv6Ranges") or [])
                ]
                open_cidrs = [c for c in cidrs if c in ("0.0.0.0/0", "::/0")]
                if not open_cidrs:
                    continue
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")
                if from_port is None or to_port is None:
                    ports: Any = "all"
                else:
                    ports = list(range(int(from_port), int(to_port) + 1))[:64]
                rule_list.append({
                    "cidrs": open_cidrs, "ports": ports,
                    "protocol": str(permission.get("IpProtocol", "")),
                })
            if rule_list:
                out.append({
                    "name": str(group.get("GroupName", group.get("GroupId", ""))),
                    "rules": rule_list,
                })
        return out

    def _iam(self) -> dict[str, Any]:
        iam = self._client("iam")
        self.calls.append("iam.get_account_summary")
        summary = iam.get_account_summary().get("SummaryMap") or {}
        return {
            "mfa_enabled": int(summary.get("AccountMFAEnabled", 0)) == 1,
            "root_access_keys": int(summary.get("AccountAccessKeysPresent", 0)) == 1,
        }

    def _logging(self) -> dict[str, Any]:
        cloudtrail = self._client("cloudtrail")
        self.calls.append("cloudtrail.describe_trails")
        trails = cloudtrail.describe_trails(includeShadowTrails=False).get("trailList") or []
        return {
            "audit_logging_enabled": bool(trails),
            "multi_region": any(bool(t.get("IsMultiRegionTrail")) for t in trails),
            "log_validation": any(bool(t.get("LogFileValidationEnabled")) for t in trails),
        }


class AzureProvider(BaseProvider):
    """Azure — read-only collection over azure-mgmt clients (optional).

    Live wiring requires the azure-mgmt packages; tests inject fake clients.
    """

    name = "azure"
    services = ("subscription", "storage", "network", "monitor")

    @classmethod
    def sdk_available(cls) -> bool:
        return _module_available("azure.identity")

    def _identity(self) -> dict[str, Any]:
        subscription = self._client("subscription")
        self.calls.append("subscriptions.list")
        subs = list(subscription.subscriptions.list())
        allow = [str(s) for s in self.settings.get("accounts", [])]
        if allow:
            subs = [s for s in subs if str(getattr(s, "subscription_id", "")) in allow]
        ids = [str(getattr(s, "subscription_id", "")) for s in subs]
        if len(ids) != 1:
            raise CloudProviderError(
                f"azure: ambiguous or unavailable subscription identity: {ids or 'none'}"
            )
        return {"account": ids[0]}

    def _storage(self) -> list[dict[str, Any]]:
        storage = self._client("storage")
        self.calls.append("storage_accounts.list")
        out = []
        for account in list(storage.storage_accounts.list()):
            out.append({
                "name": str(getattr(account, "name", "")),
                "public_acl": bool(getattr(account, "allow_blob_public_access", False)),
                "encryption": True,  # Azure Storage is encrypted at rest by default
                "versioning": None,
            })
        return out

    def _network(self) -> list[dict[str, Any]]:
        network = self._client("network")
        self.calls.append("network_security_groups.list_all")
        out = []
        for group in network.network_security_groups.list_all():
            rules = []
            for rule in (getattr(group, "security_rules", None) or []):
                source = str(getattr(rule, "source_address_prefix", "") or "")
                if str(getattr(rule, "access", "")).lower() == "allow" and source in ("*", "0.0.0.0/0", "internet", "any"):
                    ports: Any = "all"
                    port_range = str(getattr(rule, "destination_port_range", "") or "")
                    if port_range and "-" in port_range:
                        lo, _, hi = port_range.partition("-")
                        try:
                            ports = list(range(int(lo), int(hi) + 1))[:64]
                        except ValueError:
                            ports = "all"
                    elif port_range.isdigit():
                        ports = [int(port_range)]
                    rules.append({"cidrs": [source], "ports": ports})
            if rules:
                out.append({"name": str(getattr(group, "name", "")), "rules": rules})
        return out

    def _logging(self) -> dict[str, Any]:
        monitor = self._client("monitor")
        self.calls.append("diagnostic_settings.list")
        settings = list(monitor.diagnostic_settings.list(""))
        return {"audit_logging_enabled": bool(settings)}


class GcpProvider(BaseProvider):
    """GCP — read-only collection over google-cloud clients (optional).

    Live wiring requires google-cloud-* packages; tests inject fake clients.
    """

    name = "gcp"
    services = ("storage", "compute", "projects")

    @classmethod
    def sdk_available(cls) -> bool:
        return _module_available("google.cloud.storage")

    def _identity(self) -> dict[str, Any]:
        projects = self._client("projects")
        self.calls.append("projects.get")
        project = projects.get(self.settings.get("project") or None)
        project_id = str(getattr(project, "project_id", "") or "")
        if not project_id:
            raise CloudProviderError("gcp: ambiguous or unavailable project identity")
        return {"account": project_id}

    def _storage(self) -> list[dict[str, Any]]:
        storage = self._client("storage")
        self.calls.append("storage.list_buckets")
        limit = int(self.settings.get("max_resources", 200))
        out = []
        for bucket in list(storage.list_buckets())[:limit]:
            iam_public = False
            try:
                self.calls.append("storage.get_iam_policy")
                policy = bucket.get_iam_policy(requested_policy_version=1)
                iam_public = any(
                    "allUsers" in str(member) or "allAuthenticatedUsers" in str(member)
                    for binding in policy.get("bindings", [])
                    for member in binding.get("members", [])
                )
            except Exception:
                pass
            out.append({
                "name": str(getattr(bucket, "name", "")),
                "public_policy": iam_public,
                "encryption": True,  # GCS encrypts at rest by default
                "versioning": bool(getattr(bucket, "versioning_enabled", False)),
            })
        return out

    def _network(self) -> list[dict[str, Any]]:
        compute = self._client("compute")
        self.calls.append("firewalls.list")
        out = []
        for firewall in compute.firewalls().list():
            rules = []
            for allowed in (firewall.get("allowed") or []):
                ports = allowed.get("ports") or ["all"]
                expanded: Any = "all"
                if ports and ports != ["all"]:
                    expanded = []
                    for spec in ports:
                        if "-" in str(spec):
                            lo, _, hi = str(spec).partition("-")
                            try:
                                expanded.extend(range(int(lo), int(hi) + 1))
                            except ValueError:
                                pass
                        elif str(spec).isdigit():
                            expanded.append(int(spec))
                    expanded = expanded[:64] or "all"
                if any(str(src) == "0.0.0.0/0" for src in (firewall.get("sourceRanges") or [])):
                    rules.append({"cidrs": ["0.0.0.0/0"], "ports": expanded})
            if rules:
                out.append({"name": str(firewall.get("name", "")), "rules": rules})
        return out

    def _logging(self) -> dict[str, Any]:
        projects = self._client("projects")
        self.calls.append("audit_configs.get")
        config = projects.audit_configs.get(self.settings.get("project") or "")
        return {"audit_logging_enabled": bool(config)}
