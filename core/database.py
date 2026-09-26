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

from lib.logger import get_logger
from lib.utils import utc_timestamp

logger = get_logger("database")

SCHEMA_VERSION = 1

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
        self.conn.executescript(_SCHEMA)
        self.conn.commit()
        logger.debug("database ready at %s", self.path)

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
        """Insert or update a target; returns the target id."""
        row = self.query("SELECT id FROM targets WHERE domain = ?", (domain,))
        if row:
            return int(row[0]["id"])
        cur = self.execute(
            "INSERT INTO targets (domain, platform, type, scope, in_scope, out_of_scope,"
            " config, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
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
        return int(cur.lastrowid)

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
        existing = self.query("SELECT id FROM schedules WHERE name = ?", (name,))
        if existing:
            self.execute(
                "UPDATE schedules SET target_id = ?, frequency = ?, cron_expression = ?,"
                " intensity = ?, enabled = ? WHERE id = ?",
                (target_id, frequency, cron_expression, intensity, 1 if enabled else 0, existing[0]["id"]),
            )
            return int(existing[0]["id"])
        cur = self.execute(
            "INSERT INTO schedules (name, target_id, frequency, cron_expression, intensity,"
            " enabled, next_run, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (name, target_id, frequency, cron_expression, intensity, 1 if enabled else 0, next_run, _now()),
        )
        return int(cur.lastrowid)

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
        """Returns (id, created?) — dedup guard for the CVE workflow."""
        rows = self.query("SELECT id FROM cves WHERE cve_id = ?", (cve_id,))
        if rows:
            return int(rows[0]["id"]), False
        cur = self.execute(
            "INSERT INTO cves (cve_id, severity, description, published, tech_matched,"
            " poc_generated, created_at) VALUES (?, ?, ?, ?, ?, 0, ?)",
            (cve_id, severity, description, published, tech_matched, _now()),
        )
        return int(cur.lastrowid), True

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
