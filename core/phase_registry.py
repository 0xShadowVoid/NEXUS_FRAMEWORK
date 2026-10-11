"""Phase registry + lifecycle state machine.

NEXUS runs an ordered set of phases per scan. Historically the pipeline was
hard-coded (``PHASES_IN_ORDER``); this module makes phases self-describing,
individually enable/disable-able, and gives each one a real lifecycle:

    pending → running → (paused ⇄ running) → completed | failed | skipped | blocked | partial

Operations: start, pause, resume, retry, stop, checkpoint, recovery.

Backward compatibility: the default plan reproduces the historical
DISCOVER → PROBE → VERIFY → ANALYZE order, and the existing
``scans.checkpoint`` JSON keeps its ``phases_done`` / ``probe_steps`` keys
(new keys are additive).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from lib.logger import get_logger

logger = get_logger("phase_registry")

# Lifecycle states.
PENDING = "pending"
RUNNING = "running"
PAUSED = "paused"
COMPLETED = "completed"
FAILED = "failed"
SKIPPED = "skipped"
BLOCKED = "blocked"
PARTIAL = "partial"

TERMINAL = frozenset({COMPLETED, FAILED, SKIPPED, BLOCKED, PARTIAL})
ACTIVE = frozenset({RUNNING, PAUSED})

# Domains.
WEB = "web"
NETWORK = "network"
CLOUD = "cloud"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class PhaseRecord:
    """Declarative description of one phase/cycle."""

    name: str
    domain: str = WEB
    group: str = "core"                       # core | optional | intel | control
    order: int = 100
    enabled_by_default: bool = True
    # capability gate: only run if the attack-surface graph has this hint
    requires_capability: str = ""
    # profile gate: only run when these profiles are active
    requires_profiles: tuple[str, ...] = ()
    # authorization gate: needs ≥2 configured identities
    requires_identities: bool = False
    # scope gate: needs explicit IP/ASN/cloud scope
    requires_scope_kind: str = ""             # ip | asn | cloud
    description: str = ""
    runner: str = ""                          # module:function phase entrypoint

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "domain": self.domain,
            "group": self.group,
            "order": self.order,
            "enabled_by_default": self.enabled_by_default,
            "requires_capability": self.requires_capability,
            "requires_profiles": list(self.requires_profiles),
            "requires_identities": self.requires_identities,
            "requires_scope_kind": self.requires_scope_kind,
            "description": self.description,
            "runner": self.runner,
        }


# The historical core pipeline (unchanged behaviour).
DEFAULT_PLAN: list[PhaseRecord] = [
    PhaseRecord(name="discover", order=10, description="Reconnaissance + attack-surface discovery",
                runner="phases.discover.recon_orchestrator:run_discover"),
    PhaseRecord(name="probe", order=20, description="Vulnerability testing (web)",
                runner="phases.probe.probe_orchestrator:run_probe"),
    PhaseRecord(name="verify", order=30, description="Deterministic finding verification",
                runner="phases.verify.verify_orchestrator:run_verify"),
    PhaseRecord(name="analyze", order=40, description="Dedup, severity, FP, chains, persistence",
                runner="phases.analyze.analyze_orchestrator:run_analyze"),
]

# Optional/new cycles: gated, never in the default quick path.
OPTIONAL_PLAN: list[PhaseRecord] = [
    PhaseRecord(name="authn", domain=WEB, group="optional", order=50,
                requires_capability="login",
                description="Authentication/ATO surface detection",
                runner="phases.auth.authn_orchestrator:run_authn"),
    PhaseRecord(name="authz", domain=WEB, group="optional", order=55,
                requires_identities=True,
                description="Authorization / IDOR / BOLA differential testing",
                runner="phases.auth.authz_orchestrator:run_authz"),
    PhaseRecord(name="takeover", domain=NETWORK, group="optional", order=60,
                requires_profiles=("extended", "deep"),
                description="Subdomain takeover / domain lifecycle intelligence",
                runner="phases.takeover.takeover_orchestrator:run_takeover"),
    PhaseRecord(name="network", domain=NETWORK, group="optional", order=65,
                requires_profiles=("extended", "deep"), requires_scope_kind="ip",
                description="Port + service discovery (nmap/naabu)",
                runner="phases.network.net_orchestrator:run_network"),
    PhaseRecord(name="cloud", domain=CLOUD, group="optional", order=70,
                requires_scope_kind="cloud",
                description="Cloud asset discovery + exposure checks",
                runner="phases.cloud.cloud_orchestrator:run_cloud"),
    PhaseRecord(name="intel", group="intel", order=75,
                # Opt-in: runs NVD fetches per scan, so it must not be part of
                # the default quick path. Enable with ``phases.intel.enabled``.
                enabled_by_default=False,
                description="CVE/GHSA/CPE enrichment for detected technologies",
                runner="lib.cve_workflow:run_cve_scan"),
    PhaseRecord(name="report", group="core", order=90,
                description="Report + export generation",
                runner="core.reporter:write_report"),
]


class PhaseStateError(Exception):
    """Raised on an illegal lifecycle transition."""


class PhaseStateMachine:
    """Per-scan lifecycle for one phase, persisted in ``phase_runs``."""

    def __init__(self, db: Any, scan_id: int, record: PhaseRecord):
        self.db = db
        self.scan_id = scan_id
        self.record = record
        row = db.get_phase_run(scan_id, record.name)
        self.state = (row or {}).get("state") or PENDING
        self.attempts = int((row or {}).get("attempts") or 0)
        self._run_id = (row or {}).get("id")

    # -- transitions ---------------------------------------------------------

    def _set(self, state: str, error: str | None = None, checkpoint: str | None = None) -> None:
        self.state = state
        self._run_id = self.db.upsert_phase_run(
            self.scan_id, self.record.name, state,
            ended_at=_now() if state in TERMINAL else None,
            attempts=self.attempts if state != RUNNING else self.attempts,
            checkpoint=checkpoint, error=error,
        )

    def start(self) -> None:
        if self.state == RUNNING:
            raise PhaseStateError(f"{self.record.name}: already running — use pause/resume")
        if self.state in TERMINAL and self.state not in (BLOCKED, SKIPPED):
            raise PhaseStateError(f"{self.record.name}: cannot start from {self.state}")
        if self.state == PAUSED:
            raise PhaseStateError(f"{self.record.name}: paused — use resume()")
        self.attempts += 1
        self._set(RUNNING)

    def pause(self, checkpoint: str | None = None) -> None:
        if self.state != RUNNING:
            raise PhaseStateError(f"{self.record.name}: can only pause a running phase")
        self._set(PAUSED, checkpoint=checkpoint)

    def resume(self) -> None:
        if self.state != PAUSED:
            raise PhaseStateError(f"{self.record.name}: can only resume a paused phase")
        self.attempts += 1
        self._set(RUNNING)

    def retry(self) -> None:
        if self.state not in (FAILED, PARTIAL):
            raise PhaseStateError(f"{self.record.name}: can only retry failed/partial phases")
        self.attempts += 1
        self._set(RUNNING)

    def stop(self, error: str = "stopped by operator") -> None:
        if self.state not in ACTIVE:
            raise PhaseStateError(f"{self.record.name}: can only stop an active phase")
        self._set(FAILED, error=error)

    def complete(self, partial: bool = False) -> None:
        if self.state != RUNNING:
            raise PhaseStateError(f"{self.record.name}: complete requires running state")
        self._set(PARTIAL if partial else COMPLETED)

    def skip(self, reason: str = "") -> None:
        self._set(SKIPPED, error=reason or None)

    def block(self, reason: str = "") -> None:
        self._set(BLOCKED, error=reason or None)

    def checkpoint(self, payload: dict[str, Any]) -> None:
        """Persist phase-local recovery state (never raises)."""
        try:
            self.db.upsert_phase_run(
                self.scan_id, self.record.name, self.state, checkpoint=json.dumps(payload)
            )
        except Exception as exc:  # checkpoint must never kill a scan
            logger.debug("checkpoint write failed for %s: %s", self.record.name, exc)

    # -- recovery ------------------------------------------------------------

    @classmethod
    def recover(cls, db: Any, scan_id: int, record: PhaseRecord) -> "PhaseStateMachine":
        """Rebuild the machine from persisted state after a crash/restart.

        A phase found ``running`` (process died mid-phase) is moved to
        ``failed`` so the next run can retry it deterministically.
        """
        machine = cls(db, scan_id, record)
        if machine.state == RUNNING:
            machine._set(FAILED, error="process interrupted; recovered on restart")
        return machine


class PhaseRegistry:
    """Ordered set of phases for a scan, with gating."""

    def __init__(self, records: list[PhaseRecord] | None = None):
        self.records = list(records) if records is not None else list(DEFAULT_PLAN)

    def all_phases(self) -> list[PhaseRecord]:
        return sorted(self.records, key=lambda r: r.order)

    def enabled_phases(self, cfg: Any | None = None) -> list[PhaseRecord]:
        """Phases enabled for this run, honoring config + gates."""
        phases_cfg: dict[str, Any] = (cfg.phases if cfg is not None else {}) or {}
        out: list[PhaseRecord] = []
        for record in self.all_phases():
            section = phases_cfg.get(record.name, {})
            if isinstance(section, dict) and section.get("enabled") is False:
                continue
            if not record.enabled_by_default and not (
                isinstance(section, dict) and section.get("enabled") is True
            ):
                continue
            out.append(record)
        return out

    def with_optional(self) -> "PhaseRegistry":
        return PhaseRegistry(self.all_phases() + [r for r in OPTIONAL_PLAN if r not in self.records])

    def gate(
        self,
        record: PhaseRecord,
        graph: Any | None = None,
        identities: int = 0,
        scope_kind: str = "",
        profile: str = "",
    ) -> tuple[bool, str]:
        """Evaluate a phase's applicability gate. Returns (allowed, reason)."""
        if record.requires_capability and graph is not None:
            if not graph.has_capability(record.requires_capability):
                return False, f"capability '{record.requires_capability}' not present on surface"
        if record.requires_identities and identities < 2:
            return False, f"requires ≥2 configured identities, found {identities}"
        if record.requires_scope_kind and record.requires_scope_kind not in (scope_kind or ""):
            return False, f"requires explicit {record.requires_scope_kind} scope"
        if record.requires_profiles and profile not in record.requires_profiles:
            return False, f"profile '{profile}' not in {list(record.requires_profiles)}"
        return True, ""

    def load_runner(self, record: PhaseRecord) -> Callable[..., Any] | None:
        if not record.runner or ":" not in record.runner:
            return None
        from importlib import import_module

        module_name, func_name = record.runner.split(":", 1)
        try:
            return getattr(import_module(module_name), func_name)
        except (ImportError, AttributeError) as exc:
            logger.debug("phase runner %s unavailable: %s", record.runner, exc)
            return None
