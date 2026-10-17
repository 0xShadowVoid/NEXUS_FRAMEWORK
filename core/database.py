"""SQLite persistence layer for NEXUS.

Schema per BUILD_SPEC Part 5 (targets, scans, findings, chains,
schedules, high_value_alerts, screenshots) plus an eighth ``cves``
table for the CVE workflow (documented addition — see
BUILD_DECISIONS.md).

SECURITY BOUNDARY: this module deliberately exposes NO delete/drop
APIs for findings/targets — data is mutated only through narrow,
audited update methods (status flags, checkpoints). All queries use
parameterized statements.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from lib.logger import get_logger
from lib.utils import utc_timestamp
from core.sanitizer import sanitize_evidence_record

logger = get_logger("database")

SCHEMA_VERSION = 4

# Canonical evidence phase attribution (Pass 3C §3): ``evidence.source``
# carries the producing PHASE (e.g. "probe", "authn", "authz", "takeover")
# and ``evidence.tool`` names the producing tool — the existing schema
# represents phase attribution safely without a new column.
EVIDENCE_PHASES = (
    "discover", "probe", "verify", "analyze", "hunt", "control",
    "authn", "authz", "takeover", "intel", "report", "manual", "browser", "network", "cloud",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
  id INTEGER PRIMARY KEY,
  domain TEXT UNIQUE,
  platform TEXT,
  type TEXT,
  scope TEXT,
  in_scope TEXT,
  out_of_scope TEXT,
  config TEXT,
  created_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY,
  target_id INTEGER,
  scan_date TIMESTAMP,
  intensity TEXT,
  duration_seconds INTEGER,
  findings_total INTEGER,
  findings_valid INTEGER,
  findings_oos INTEGER,
  status TEXT,
  checkpoint TEXT,
  created_at TIMESTAMP,
  FOREIGN KEY(target_id) REFERENCES targets(id)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER,
  endpoint TEXT,
  vuln_type TEXT,
  severity TEXT,
  confidence INTEGER,
  payload TEXT,
  response_snippet TEXT,
  tools_found TEXT,
  in_scope INTEGER,
  valid INTEGER,
  reviewed INTEGER,
  created_at TIMESTAMP,
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS chains (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER,
  finding_ids TEXT,
  chain_type TEXT,
  impact TEXT,
  steps TEXT,
  created_at TIMESTAMP,
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS schedules (
  id INTEGER PRIMARY KEY,
  name TEXT UNIQUE,
  target_id INTEGER,
  frequency TEXT,
  cron_expression TEXT,
  intensity TEXT,
  enabled INTEGER,
  last_run TIMESTAMP,
  next_run TIMESTAMP,
  created_at TIMESTAMP,
  FOREIGN KEY(target_id) REFERENCES targets(id)
);
CREATE TABLE IF NOT EXISTS high_value_alerts (
  id INTEGER PRIMARY KEY,
  finding_id INTEGER,
  alert_type TEXT,
  sent_to TEXT,
  created_at TIMESTAMP,
  FOREIGN KEY(finding_id) REFERENCES findings(id)
);
CREATE TABLE IF NOT EXISTS screenshots (
  id INTEGER PRIMARY KEY,
  finding_id INTEGER,
  path TEXT,
  uploaded INTEGER,
  created_at TIMESTAMP,
  FOREIGN KEY(finding_id) REFERENCES findings(id)
);
CREATE TABLE IF NOT EXISTS cves (
  id INTEGER PRIMARY KEY,
  cve_id TEXT UNIQUE,
  severity TEXT,
  description TEXT,
  published TEXT,
  tech_matched TEXT,
  poc_generated INTEGER,
  alerted_at TIMESTAMP,
  created_at TIMESTAMP
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    """NEXUS persistence layer. Read/insert/update only — no deletes."""

    def __init__(self, path: str | Path = "nexus.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        # check_same_thread=False + an explicit lock makes the layer safe
        # for concurrent batch scans (ThreadPoolExecutor).
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute("PRAGMA journal_mode=WAL;")
        except sqlite3.DatabaseError:  # pragma: no cover - exotic filesystems
            pass
        # Bounded wait on cross-connection/process write contention: SQLite
        # retries with backoff up to 5s instead of failing immediately with
        # "database is locked".
        self.conn.execute("PRAGMA busy_timeout=5000;")
        self.conn.executescript(_SCHEMA)
        self.conn.commit()
        # Additive migrations: upgrade an existing nexus.db in place.
        # Never drops/alters existing tables (see core/migrations.py).
        from core import migrations as migrations_mod

        self.schema_version = migrations_mod.migrate(self.conn)
        logger.debug("database ready at %s (schema v%d)", self.path, self.schema_version)

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # -- guards ------------------------------------------------------------

    @staticmethod
    def _assert_no_destructive(sql: str) -> None:
        lowered = sql.strip().lower()
        for bad in ("drop table", "drop database", "delete from", "alter table"):
            if bad in lowered:
                raise sqlite3.ProgrammingError(
                    f"destructive SQL blocked by NEXUS security boundary: {bad!r}"
                )

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """Parameterized execute with a destructive-SQL guard (thread-safe)."""
        self._assert_no_destructive(sql)
        with self._lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur

    def query(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        """Parameterized read query returning list[dict] (thread-safe)."""
        with self._lock:
            cur = self.conn.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]

    # -- targets -----------------------------------------------------------

    def upsert_target(
        self,
        domain: str,
        platform: str = "generic",
        program_type: str = "bb",
        scope_kind: str = "public",
        in_scope: list[str] | None = None,
        out_of_scope: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> int:
        """Insert a target if absent; returns its id (first write wins).

        Conflict-safe ``INSERT ... ON CONFLICT(domain) DO NOTHING`` closes the
        previous read-then-write window, so concurrent upserts of the same
        domain can no longer create duplicate rows or raise ``IntegrityError``
        (``targets.domain`` is ``UNIQUE``). An existing target keeps its
        original platform/scope/config — its id is returned unchanged, exactly
        like the former insert-only path.
        """
        cur = self.execute(
            "INSERT INTO targets (domain, platform, type, scope, in_scope, out_of_scope,"
            " config, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(domain) DO NOTHING",
            (
                domain,
                platform,
                program_type,
                scope_kind,
                json.dumps(in_scope or [domain]),
                json.dumps(out_of_scope or []),
                json.dumps(config or {}),
                _now(),
            ),
        )
        if cur.rowcount == 1:
            return int(cur.lastrowid)
        row = self.query("SELECT id FROM targets WHERE domain = ?", (domain,))
        return int(row[0]["id"])

    def get_target(self, domain: str) -> dict[str, Any] | None:
        rows = self.query("SELECT * FROM targets WHERE domain = ?", (domain,))
        return rows[0] if rows else None

    def list_targets(self) -> list[dict[str, Any]]:
        return self.query("SELECT * FROM targets ORDER BY domain")

    def find_target_id(self, domain: str) -> int | None:
        rows = self.query("SELECT id FROM targets WHERE domain = ?", (domain,))
        return int(rows[0]["id"]) if rows else None

    def update_target_config(self, domain: str, patch: dict[str, Any]) -> bool:
        """Merge *patch* into a target's config JSON (no deletion semantics)."""
        rows = self.query("SELECT id, config FROM targets WHERE domain = ?", (domain,))
        if not rows:
            return False
        try:
            current = json.loads(rows[0].get("config") or "{}")
        except (json.JSONDecodeError, TypeError):
            current = {}
        current.update(patch)
        self.execute(
            "UPDATE targets SET config = ? WHERE id = ?",
            (json.dumps(current), rows[0]["id"]),
        )
        return True

    def set_target_disabled(self, domain: str, disabled: bool = True) -> bool:
        return self.update_target_config(domain, {"disabled": bool(disabled)})

    def find_schedule_id(self, name: str) -> int | None:
        rows = self.query("SELECT id FROM schedules WHERE name = ?", (name,))
        return int(rows[0]["id"]) if rows else None

    def set_schedule_enabled(self, name: str, enabled: bool) -> bool:
        sid = self.find_schedule_id(name)
        if sid is None:
            return False
        self.execute("UPDATE schedules SET enabled = ? WHERE id = ?", (1 if enabled else 0, sid))
        return True

    # -- scans -------------------------------------------------------------

    def create_scan(self, target_id: int, intensity: str = "quick-scan") -> int:
        cur = self.execute(
            "INSERT INTO scans (target_id, scan_date, intensity, status, created_at)"
            " VALUES (?, ?, ?, 'running', ?)",
            (target_id, _now(), intensity, _now()),
        )
        return int(cur.lastrowid)

    def update_scan(
        self,
        scan_id: int,
        *,
        status: str | None = None,
        checkpoint: str | None = None,
        duration_seconds: int | None = None,
        findings_total: int | None = None,
        findings_valid: int | None = None,
        findings_oos: int | None = None,
    ) -> None:
        """Narrow, audited mutation path for scan bookkeeping."""
        sets: list[str] = []
        params: list[Any] = []
        if status is not None:
            sets.append("status = ?")
            params.append(status)
        if checkpoint is not None:
            sets.append("checkpoint = ?")
            params.append(checkpoint)
        if duration_seconds is not None:
            sets.append("duration_seconds = ?")
            params.append(duration_seconds)
        if findings_total is not None:
            sets.append("findings_total = ?")
            params.append(findings_total)
        if findings_valid is not None:
            sets.append("findings_valid = ?")
            params.append(findings_valid)
        if findings_oos is not None:
            sets.append("findings_oos = ?")
            params.append(findings_oos)
        if not sets:
            return
        params.append(scan_id)
        self.execute(f"UPDATE scans SET {', '.join(sets)} WHERE id = ?", tuple(params))

    def get_scan(self, scan_id: int) -> dict[str, Any] | None:
        rows = self.query("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return rows[0] if rows else None

    def latest_scan_for_target(self, target_id: int) -> dict[str, Any] | None:
        rows = self.query(
            "SELECT * FROM scans WHERE target_id = ? ORDER BY id DESC LIMIT 1",
            (target_id,),
        )
        return rows[0] if rows else None

    def list_scans(self, target_id: int | None = None) -> list[dict[str, Any]]:
        if target_id is None:
            return self.query("SELECT * FROM scans ORDER BY id DESC")
        return self.query(
            "SELECT * FROM scans WHERE target_id = ? ORDER BY id DESC", (target_id,)
        )

    # -- findings ----------------------------------------------------------

    def insert_finding(
        self,
        scan_id: int,
        endpoint: str,
        vuln_type: str,
        severity: str,
        confidence: int,
        payload: str = "",
        response_snippet: str = "",
        tools_found: list[str] | None = None,
        in_scope: bool = True,
        valid: bool | None = None,
    ) -> int:
        cur = self.execute(
            "INSERT INTO findings (scan_id, endpoint, vuln_type, severity, confidence,"
            " payload, response_snippet, tools_found, in_scope, valid, reviewed, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
            (
                scan_id,
                endpoint,
                vuln_type,
                severity,
                int(confidence),
                payload,
                response_snippet,
                json.dumps(tools_found or []),
                1 if in_scope else 0,
                None if valid is None else (1 if valid else 0),
                _now(),
            ),
        )
        return int(cur.lastrowid)

    def insert_findings(self, scan_id: int, findings: list[dict[str, Any]]) -> list[int]:
        ids: list[int] = []
        for f in findings:
            ids.append(
                self.insert_finding(
                    scan_id=scan_id,
                    endpoint=str(f.get("endpoint", "")),
                    vuln_type=str(f.get("vuln_type", "")),
                    severity=str(f.get("severity", "P4")),
                    confidence=int(f.get("confidence", 50)),
                    payload=str(f.get("payload", "")),
                    response_snippet=str(f.get("response_snippet", "")),
                    tools_found=list(f.get("tools_found", []) or []),
                    in_scope=bool(f.get("in_scope", True)),
                    valid=f.get("valid"),
                )
            )
        return ids

    def query_findings(
        self,
        scan_id: int | None = None,
        severity: str | None = None,
        valid: bool | None = None,
        min_confidence: int | None = None,
    ) -> list[dict[str, Any]]:
        """Query findings with optional filters."""
        sql = "SELECT * FROM findings WHERE 1=1"
        params: list[Any] = []
        if scan_id is not None:
            sql += " AND scan_id = ?"
            params.append(scan_id)
        if severity is not None:
            sql += " AND severity = ?"
            params.append(severity)
        if valid is not None:
            sql += " AND valid = ?"
            params.append(1 if valid else 0)
        if min_confidence is not None:
            sql += " AND confidence >= ?"
            params.append(min_confidence)
        sql += " ORDER BY id"
        rows = self.query(sql, tuple(params))
        for r in rows:
            r["tools_found"] = json.loads(r.get("tools_found") or "[]")
        return rows

    def mark_finding_validity(self, finding_id: int, valid: bool) -> None:
        self.execute(
            "UPDATE findings SET valid = ? WHERE id = ?", (1 if valid else 0, finding_id)
        )

    def mark_finding_reviewed(self, finding_id: int, reviewed: bool = True) -> None:
        self.execute(
            "UPDATE findings SET reviewed = ? WHERE id = ?", (1 if reviewed else 0, finding_id)
        )

    # -- chains ------------------------------------------------------------

    def insert_chain(
        self,
        scan_id: int,
        finding_ids: list[int],
        chain_type: str,
        impact: str,
        steps: list[str],
        combined_severity: str = "",
    ) -> int:
        cur = self.execute(
            "INSERT INTO chains (scan_id, finding_ids, chain_type, impact, steps, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                json.dumps(finding_ids),
                chain_type,
                impact,
                json.dumps({"steps": steps, "combined_severity": combined_severity}),
                _now(),
            ),
        )
        return int(cur.lastrowid)

    def query_chains(self, scan_id: int) -> list[dict[str, Any]]:
        rows = self.query("SELECT * FROM chains WHERE scan_id = ?", (scan_id,))
        for r in rows:
            r["finding_ids"] = json.loads(r.get("finding_ids") or "[]")
            payload = json.loads(r.get("steps") or "{}")
            r["steps"] = payload.get("steps", [])
            r["combined_severity"] = payload.get("combined_severity", "")
        return rows

    # -- schedules ---------------------------------------------------------

    def upsert_schedule(
        self,
        name: str,
        target_id: int,
        frequency: str = "custom",
        cron_expression: str = "",
        intensity: str = "quick-scan",
        enabled: bool = True,
        next_run: str | None = None,
    ) -> int:
        """Insert or update a schedule by name; returns its id.

        Conflict-safe single statement: ``ON CONFLICT(name) DO UPDATE`` rewrites
        exactly the fields the previous UPDATE path did (``target_id``,
        ``frequency``, ``cron_expression``, ``intensity``, ``enabled``) and
        leaves ``next_run``/``created_at``/``last_run`` untouched, so behavior
        is unchanged while the read-then-write race is gone (``schedules.name``
        is ``UNIQUE``).
        """
        self.execute(
            "INSERT INTO schedules (name, target_id, frequency, cron_expression, intensity,"
            " enabled, next_run, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(name) DO UPDATE SET"
            " target_id = excluded.target_id,"
            " frequency = excluded.frequency,"
            " cron_expression = excluded.cron_expression,"
            " intensity = excluded.intensity,"
            " enabled = excluded.enabled",
            (name, target_id, frequency, cron_expression, intensity, 1 if enabled else 0, next_run, _now()),
        )
        row = self.query("SELECT id FROM schedules WHERE name = ?", (name,))
        return int(row[0]["id"])

    def list_schedules(self, enabled_only: bool = False) -> list[dict[str, Any]]:
        if enabled_only:
            return self.query("SELECT * FROM schedules WHERE enabled = 1 ORDER BY name")
        return self.query("SELECT * FROM schedules ORDER BY name")

    def mark_schedule_run(self, schedule_id: int, last_run: str, next_run: str) -> None:
        self.execute(
            "UPDATE schedules SET last_run = ?, next_run = ? WHERE id = ?",
            (last_run, next_run, schedule_id),
        )

    # -- alerts / screenshots ----------------------------------------------

    def record_alert(self, finding_id: int, alert_type: str, sent_to: list[str]) -> int:
        cur = self.execute(
            "INSERT INTO high_value_alerts (finding_id, alert_type, sent_to, created_at)"
            " VALUES (?, ?, ?, ?)",
            (finding_id, alert_type, json.dumps(sent_to), _now()),
        )
        return int(cur.lastrowid)

    def record_screenshot(self, finding_id: int, path: str) -> int:
        cur = self.execute(
            "INSERT INTO screenshots (finding_id, path, uploaded, created_at)"
            " VALUES (?, ?, 0, ?)",
            (finding_id, path, _now()),
        )
        return int(cur.lastrowid)

    # -- cves --------------------------------------------------------------

    def get_or_create_cve(
        self,
        cve_id: str,
        severity: str = "",
        description: str = "",
        published: str = "",
        tech_matched: str = "",
    ) -> tuple[int, bool]:
        """Returns (id, created?) — dedup guard for the CVE workflow.

        Conflict-safe ``INSERT ... ON CONFLICT(cve_id) DO NOTHING`` closes the
        previous read-then-write window, so concurrent creation of the same CVE
        can no longer raise ``IntegrityError`` (``cves.cve_id`` is ``UNIQUE``).
        An existing record is never modified — matching the former behavior,
        which treated an already-known CVE purely as a dedup hit and returned
        its id with ``created=False``.
        """
        cur = self.execute(
            "INSERT INTO cves (cve_id, severity, description, published, tech_matched,"
            " poc_generated, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)"
            " ON CONFLICT(cve_id) DO NOTHING",
            (cve_id, severity, description, published, tech_matched, _now()),
        )
        if cur.rowcount == 1:
            return int(cur.lastrowid), True
        row = self.query("SELECT id FROM cves WHERE cve_id = ?", (cve_id,))
        return int(row[0]["id"]), False

    def mark_cve_poc_generated(self, cve_row_id: int) -> None:
        self.execute("UPDATE cves SET poc_generated = 1 WHERE id = ?", (cve_row_id,))

    def mark_cve_alerted(self, cve_row_id: int) -> None:
        self.execute("UPDATE cves SET alerted_at = ? WHERE id = ?", (_now(), cve_row_id))

    def list_cves(self, severity: str | None = None) -> list[dict[str, Any]]:
        if severity:
            return self.query(
                "SELECT * FROM cves WHERE severity = ? ORDER BY id DESC", (severity,)
            )
        return self.query("SELECT * FROM cves ORDER BY id DESC")

    # -- stats -------------------------------------------------------------

    def scan_stats(self, scan_id: int) -> dict[str, Any]:
        rows = self.query("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
        by_sev: dict[str, int] = {}
        valid_count = oos_count = 0
        for r in rows:
            by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
            if r["in_scope"] == 0:
                oos_count += 1
            if r["valid"] == 1:
                valid_count += 1
        return {
            "findings_total": len(rows),
            "findings_valid": valid_count,
            "findings_oos": oos_count,
            "by_severity": by_sev,
        }

    # -- phase runs (v2) ----------------------------------------------------

    def upsert_phase_run(
        self,
        scan_id: int,
        phase: str,
        state: str,
        started_at: str | None = None,
        ended_at: str | None = None,
        attempts: int | None = None,
        checkpoint: str | None = None,
        error: str | None = None,
    ) -> int:
        """Insert or update the lifecycle row for one phase of one scan.

        ``phase_runs`` has no ``UNIQUE(scan_id, phase)`` constraint, and an
        additive-only migration cannot safely add one once duplicate rows may
        already exist — so the read-then-write is serialized inside the
        connection lock instead. Holding ``self._lock`` across the lookup and
        the insert/update closes the window where two threads could both miss
        the row and insert duplicates. ``_lock`` is reentrant, so the nested
        ``query``/``execute`` calls are safe.
        """
        sets = ["state = ?"]
        params: list[Any] = [state]
        if started_at is not None:
            sets.append("started_at = ?")
            params.append(started_at)
        if ended_at is not None:
            sets.append("ended_at = ?")
            params.append(ended_at)
        if attempts is not None:
            sets.append("attempts = ?")
            params.append(attempts)
        if checkpoint is not None:
            sets.append("checkpoint = ?")
            params.append(checkpoint)
        if error is not None:
            sets.append("error = ?")
            params.append(error)
        with self._lock:
            rows = self.query(
                "SELECT id FROM phase_runs WHERE scan_id = ? AND phase = ?", (scan_id, phase)
            )
            if rows:
                params.append(rows[0]["id"])
                self.execute(
                    f"UPDATE phase_runs SET {', '.join(sets)} WHERE id = ?", tuple(params)
                )
                return int(rows[0]["id"])
            cur = self.execute(
                "INSERT INTO phase_runs (scan_id, phase, state, started_at, ended_at,"
                " attempts, checkpoint, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (scan_id, phase, state, started_at or _now(), ended_at, attempts or 0,
                 checkpoint, error),
            )
            return int(cur.lastrowid)

    def list_phase_runs(self, scan_id: int) -> list[dict[str, Any]]:
        return self.query(
            "SELECT * FROM phase_runs WHERE scan_id = ? ORDER BY id", (scan_id,)
        )

    def get_phase_run(self, scan_id: int, phase: str) -> dict[str, Any] | None:
        rows = self.query(
            "SELECT * FROM phase_runs WHERE scan_id = ? AND phase = ?", (scan_id, phase)
        )
        return rows[0] if rows else None

    # -- tool runs (v2) -----------------------------------------------------

    def record_tool_run(
        self,
        scan_id: int,
        phase: str,
        tool: str,
        status: str,
        duration_ms: int = 0,
        returncode: int | None = None,
        output_path: str = "",
        filtration_stats_id: int | None = None,
    ) -> int:
        cur = self.execute(
            "INSERT INTO tool_runs (scan_id, phase, tool, status, duration_ms,"
            " returncode, output_path, filtration_stats_id, started_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, phase, tool, status, int(duration_ms), returncode, output_path,
             filtration_stats_id, _now()),
        )
        return int(cur.lastrowid)

    def list_tool_runs(self, scan_id: int, phase: str | None = None) -> list[dict[str, Any]]:
        if phase is None:
            return self.query(
                "SELECT * FROM tool_runs WHERE scan_id = ? ORDER BY id", (scan_id,)
            )
        return self.query(
            "SELECT * FROM tool_runs WHERE scan_id = ? AND phase = ? ORDER BY id",
            (scan_id, phase),
        )

    # -- attack-surface graph (v2) -------------------------------------------

    def upsert_asset(
        self,
        kind: str,
        value: str,
        normalized: str,
        source_tool: str = "",
        scan_id: int | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[int, bool]:
        """Atomically insert an asset if new, else refresh ``last_seen``.

        Returns ``(id, created?)``. The canonical identity is ``(kind,
        normalized)`` — the ``assets`` table has ``UNIQUE(kind, normalized)``.
        A single conflict-safe ``INSERT`` closes the previous read-then-write
        window, so concurrent upserts of the same asset can no longer create
        duplicate rows or raise ``IntegrityError`` under concurrent scans.
        Existing ``value``/``source_tool``/``scan_id``/``metadata`` are
        preserved (first write wins); only ``last_seen`` advances.
        """
        now = _now()
        cur = self.execute(
            "INSERT INTO assets (scan_id, kind, value, normalized, source_tool,"
            " first_seen, last_seen, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(kind, normalized) DO NOTHING",
            (scan_id, kind, value, normalized, source_tool, now, now,
             json.dumps(metadata or {})),
        )
        if cur.rowcount == 1:
            return int(cur.lastrowid), True
        # Already present (possibly just created by a concurrent upsert).
        self.execute(
            "UPDATE assets SET last_seen = ? WHERE kind = ? AND normalized = ?",
            (now, kind, normalized),
        )
        row = self.query(
            "SELECT id FROM assets WHERE kind = ? AND normalized = ?", (kind, normalized)
        )
        return int(row[0]["id"]), False

    def get_asset(self, kind: str, normalized: str) -> dict[str, Any] | None:
        rows = self.query(
            "SELECT * FROM assets WHERE kind = ? AND normalized = ?", (kind, normalized)
        )
        return rows[0] if rows else None

    def list_assets(self, kind: str | None = None, scan_id: int | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM assets WHERE 1=1"
        params: list[Any] = []
        if kind is not None:
            sql += " AND kind = ?"
            params.append(kind)
        if scan_id is not None:
            sql += " AND scan_id = ?"
            params.append(scan_id)
        return self.query(sql + " ORDER BY id", tuple(params))

    def upsert_edge(
        self,
        src_id: int,
        dst_id: int,
        relation: str,
        source_tool: str = "",
        scan_id: int | None = None,
    ) -> tuple[int, bool]:
        """Atomically insert a graph edge if new (``UNIQUE(src_id,dst_id,relation)``).

        Same conflict-safe pattern as :meth:`upsert_asset`: concurrent creation
        of the same relationship yields a single row and no ``IntegrityError``.
        """
        cur = self.execute(
            "INSERT INTO asset_edges (scan_id, src_id, dst_id, relation, source_tool,"
            " first_seen) VALUES (?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(src_id, dst_id, relation) DO NOTHING",
            (scan_id, src_id, dst_id, relation, source_tool, _now()),
        )
        if cur.rowcount == 1:
            return int(cur.lastrowid), True
        rows = self.query(
            "SELECT id FROM asset_edges WHERE src_id = ? AND dst_id = ? AND relation = ?",
            (src_id, dst_id, relation),
        )
        return int(rows[0]["id"]), False

    def list_edges(self, scan_id: int | None = None) -> list[dict[str, Any]]:
        if scan_id is None:
            return self.query("SELECT * FROM asset_edges ORDER BY id")
        return self.query(
            "SELECT * FROM asset_edges WHERE scan_id = ? ORDER BY id", (scan_id,)
        )

    # -- evidence (v2) -------------------------------------------------------

    def insert_evidence(
        self,
        scan_id: int,
        url: str,
        method: str = "GET",
        request_headers: dict[str, str] | None = None,
        request_body: str = "",
        status_code: int | None = None,
        response_headers: dict[str, str] | None = None,
        response_body: str = "",
        tool: str = "",
        source: str = "",
        finding_id: int | None = None,
        screenshot_path: str = "",
        sanitized: bool = False,
    ) -> int:
        """Persist one evidence record (sanitized; auto asset-link best-effort).

        ``source`` is the canonical phase attribution (see ``EVIDENCE_PHASES``);
        ``tool`` names the producing tool.
        """
        # SECURITY BOUNDARY (Pass 3B §4): evidence is sanitized HERE, before
        # persistence — no caller can store raw credentials. The stored
        # ``sanitized`` flag records that this enforcement ran.
        req_h, req_b, resp_h, resp_b = sanitize_evidence_record(
            request_headers, request_body, response_headers, response_body
        )
        cur = self.execute(
            "INSERT INTO evidence (scan_id, finding_id, url, method, request_headers,"
            " request_body, status_code, response_headers, response_body, timestamp,"
            " tool, source, screenshot_path, sanitized) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id, finding_id, url, method,
                json.dumps(req_h), req_b,
                status_code, json.dumps(resp_h), resp_b,
                _now(), tool, source, screenshot_path, 1,
            ),
        )
        evidence_id = int(cur.lastrowid)
        # Pass 3C §2: best-effort auto-link to an ALREADY-KNOWN asset.
        self._auto_link_evidence_asset(evidence_id, url)
        return evidence_id

    def query_evidence(self, scan_id: int | None = None, finding_id: int | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM evidence WHERE 1=1"
        params: list[Any] = []
        if scan_id is not None:
            sql += " AND scan_id = ?"
            params.append(scan_id)
        if finding_id is not None:
            sql += " AND finding_id = ?"
            params.append(finding_id)
        rows = self.query(sql + " ORDER BY id", tuple(params))
        for r in rows:
            r["request_headers"] = json.loads(r.get("request_headers") or "{}")
            r["response_headers"] = json.loads(r.get("response_headers") or "{}")
        return rows

    def set_evidence_finding(self, evidence_id: int, finding_id: int) -> bool:
        """Link stored evidence to a finding (Pass 3B §3, linkage only)."""
        cur = self.execute(
            "UPDATE evidence SET finding_id = ? WHERE id = ?", (finding_id, evidence_id)
        )
        return cur.rowcount > 0

    def set_evidence_asset(self, evidence_id: int, asset_id: int, relation: str = "observed-on") -> int:
        """Link stored evidence to an attack-surface asset (Pass 3B §3)."""
        cur = self.execute(
            "INSERT INTO evidence_assets (evidence_id, asset_id, relation, created_at)"
            " VALUES (?, ?, ?, ?)",
            (evidence_id, asset_id, relation, _now()),
        )
        return int(cur.lastrowid)

    def _auto_link_evidence_asset(self, evidence_id: int, url: str) -> None:
        """Best-effort Pass 3C §2: link evidence to an already-known asset.

        Never creates assets (no fabrication) and skips duplicates.
        Lookup priority: exact ``url`` asset → ``subdomain`` → ``host``.
        """
        try:
            from lib.filtration import normalize_asset

            candidates: list[tuple[str, str]] = []
            raw = str(url or "").strip()
            if raw:
                candidates.append(("url", normalize_asset("url", raw)))
                try:
                    host = urlsplit(raw).hostname or ""
                except ValueError:
                    host = ""
                if not host:
                    host = raw.split("/")[0].split(":")[0]
                if host:
                    candidates.append(("subdomain", normalize_asset("subdomain", host)))
                    candidates.append(("host", normalize_asset("host", host)))
            for kind, normalized in candidates:
                if not normalized:
                    continue
                asset = self.get_asset(kind, normalized)
                if asset is None:
                    continue
                dup = self.query(
                    "SELECT id FROM evidence_assets WHERE evidence_id = ? AND asset_id = ?",
                    (evidence_id, asset["id"]),
                )
                if dup:
                    return
                self.set_evidence_asset(evidence_id, int(asset["id"]))
                return
        except Exception as exc:  # linkage must never break insertion
            logger.debug("evidence asset auto-link skipped: %s", exc)

    # -- identities / sessions (v2) -------------------------------------------

    def insert_identity(
        self,
        scan_id: int,
        name: str,
        kind: str = "user",
        credential_ref: str = "",
    ) -> int:
        cur = self.execute(
            "INSERT INTO identities (scan_id, name, kind, credential_ref, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (scan_id, name, kind, credential_ref, _now()),
        )
        return int(cur.lastrowid)

    def list_identities(self, scan_id: int) -> list[dict[str, Any]]:
        return self.query(
            "SELECT * FROM identities WHERE scan_id = ? ORDER BY id", (scan_id,)
        )

    def insert_auth_session(
        self,
        identity_id: int,
        token_kind: str = "cookie",
        state: str = "observed",
        evidence_id: int | None = None,
    ) -> int:
        cur = self.execute(
            "INSERT INTO auth_sessions (identity_id, token_kind, obtained_at, state,"
            " evidence_id) VALUES (?, ?, ?, ?, ?)",
            (identity_id, token_kind, _now(), state, evidence_id),
        )
        return int(cur.lastrowid)

    # -- filtration stats (v2) -------------------------------------------------

    def insert_filtration_stats(
        self,
        scan_id: int,
        tool: str,
        phase: str,
        totals: dict[str, Any],
        tool_run_id: int | None = None,
    ) -> int:
        cur = self.execute(
            "INSERT INTO filtration_stats (scan_id, tool_run_id, tool, phase, totals,"
            " created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, tool_run_id, tool, phase, json.dumps(totals), _now()),
        )
        return int(cur.lastrowid)

    def list_filtration_stats(self, scan_id: int) -> list[dict[str, Any]]:
        rows = self.query(
            "SELECT * FROM filtration_stats WHERE scan_id = ? ORDER BY id", (scan_id,)
        )
        for r in rows:
            r["totals"] = json.loads(r.get("totals") or "{}")
        return rows

    # -- monitoring snapshots (v2) ---------------------------------------------

    def insert_monitoring_snapshot(
        self,
        kind: str,
        snapshot: dict[str, Any],
        diff: dict[str, Any] | None = None,
        schedule_id: int | None = None,
    ) -> int:
        cur = self.execute(
            "INSERT INTO monitoring_snapshots (schedule_id, kind, taken_at, snapshot,"
            " diff) VALUES (?, ?, ?, ?, ?)",
            (schedule_id, kind, _now(), json.dumps(snapshot), json.dumps(diff or {})),
        )
        return int(cur.lastrowid)

    def latest_monitoring_snapshot(self, kind: str) -> dict[str, Any] | None:
        rows = self.query(
            "SELECT * FROM monitoring_snapshots WHERE kind = ? ORDER BY id DESC LIMIT 1",
            (kind,),
        )
        if not rows:
            return None
        row = rows[0]
        row["snapshot"] = json.loads(row.get("snapshot") or "{}")
        row["diff"] = json.loads(row.get("diff") or "{}")
        return row

    def backup_to(self, backup_path: str | Path) -> None:
        """Backup the SQLite database using SQLite's online backup API."""
        backup_path = Path(backup_path)
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(backup_path)) as dest_conn:
            with self._lock:
                self.conn.backup(dest_conn)
        logger.info("database backed up successfully to %s", backup_path)

    def restore_from(self, backup_path: str | Path) -> None:
        """Restore the SQLite database from a backup file using SQLite's online backup API."""
        backup_path = Path(backup_path)
        if not backup_path.exists():
            raise FileNotFoundError(f"Backup file not found: {backup_path}")
        # Verify backup integrity first by connecting
        try:
            with sqlite3.connect(str(backup_path)) as src_conn:
                src_conn.execute("PRAGMA integrity_check;")
        except Exception as exc:
            raise ValueError(f"Invalid or corrupted SQLite backup file: {exc}") from exc

        with sqlite3.connect(str(backup_path)) as src_conn:
            with self._lock:
                src_conn.backup(self.conn)
        logger.info("database restored successfully from %s", backup_path)

    def insert_audit_event(
        self,
        actor: str,
        action: str,
        category: str = "system",
        detail: str = "",
    ) -> int:
        cur = self.execute(
            "INSERT INTO audit_events (ts, actor, action, category, detail)"
            " VALUES (?, ?, ?, ?, ?)",
            (_now(), actor, action, category, detail[:300]),
        )
        return int(cur.lastrowid)

    def list_audit_events(self, limit: int = 100, category: str | None = None) -> list[dict[str, Any]]:
        if category is None:
            return self.query(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (int(limit),)
            )
        return self.query(
            "SELECT * FROM audit_events WHERE category = ? ORDER BY id DESC LIMIT ?",
            (category, int(limit)),
        )
