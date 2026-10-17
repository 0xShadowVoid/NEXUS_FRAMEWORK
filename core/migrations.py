"""Additive-only SQLite schema migrations for NEXUS.

SECURITY BOUNDARY: migrations never DROP, DELETE, ALTER or rename existing
columns/tables. Every step is strictly additive (``CREATE TABLE IF NOT
EXISTS`` / ``ADD COLUMN``-free additive table creation), so an existing
``nexus.db`` from any prior version keeps all its data and is upgraded in
place on first connect.

The version is stored in the ``schema_version`` meta table; a database is
considered current when ``schema_version == TARGET``.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from lib.logger import get_logger

logger = get_logger("migrations")

TARGET = 5

_META = """
CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER PRIMARY KEY,
  applied_at TEXT
)
"""

# v2: phase lifecycle, tool runs, attack-surface graph, structured evidence,
# identities/sessions, filtration metrics, monitoring snapshots, audit events.
_V2 = """
CREATE TABLE IF NOT EXISTS phase_runs (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER,
  phase TEXT,
  state TEXT,
  started_at TEXT,
  ended_at TEXT,
  attempts INTEGER DEFAULT 0,
  checkpoint TEXT,
  error TEXT,
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS tool_runs (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER,
  phase TEXT,
  tool TEXT,
  status TEXT,
  duration_ms INTEGER,
  returncode INTEGER,
  output_path TEXT,
  filtration_stats_id INTEGER,
  started_at TEXT,
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER,
  kind TEXT,
  value TEXT,
  normalized TEXT,
  source_tool TEXT,
  first_seen TEXT,
  last_seen TEXT,
  metadata TEXT,
  UNIQUE(kind, normalized)
);
CREATE TABLE IF NOT EXISTS asset_edges (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER,
  src_id INTEGER,
  dst_id INTEGER,
  relation TEXT,
  source_tool TEXT,
  first_seen TEXT,
  UNIQUE(src_id, dst_id, relation)
);
CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER,
  finding_id INTEGER,
  url TEXT,
  method TEXT,
  request_headers TEXT,
  request_body TEXT,
  status_code INTEGER,
  response_headers TEXT,
  response_body TEXT,
  timestamp TEXT,
  tool TEXT,
  source TEXT,
  screenshot_path TEXT,
  sanitized INTEGER DEFAULT 0,
  FOREIGN KEY(scan_id) REFERENCES scans(id),
  FOREIGN KEY(finding_id) REFERENCES findings(id)
);
CREATE TABLE IF NOT EXISTS identities (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER,
  name TEXT,
  kind TEXT,
  credential_ref TEXT,
  created_at TEXT,
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS auth_sessions (
  id INTEGER PRIMARY KEY,
  identity_id INTEGER,
  token_kind TEXT,
  obtained_at TEXT,
  state TEXT,
  evidence_id INTEGER,
  FOREIGN KEY(identity_id) REFERENCES identities(id),
  FOREIGN KEY(evidence_id) REFERENCES evidence(id)
);
CREATE TABLE IF NOT EXISTS filtration_stats (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER,
  tool_run_id INTEGER,
  tool TEXT,
  phase TEXT,
  totals TEXT,
  created_at TEXT,
  FOREIGN KEY(scan_id) REFERENCES scans(id),
  FOREIGN KEY(tool_run_id) REFERENCES tool_runs(id)
);
CREATE TABLE IF NOT EXISTS monitoring_snapshots (
  id INTEGER PRIMARY KEY,
  schedule_id INTEGER,
  kind TEXT,
  taken_at TEXT,
  snapshot TEXT,
  diff TEXT,
  FOREIGN KEY(schedule_id) REFERENCES schedules(id)
);
CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY,
  ts TEXT,
  actor TEXT,
  action TEXT,
  category TEXT,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_phase_runs_scan ON phase_runs(scan_id, phase);
CREATE INDEX IF NOT EXISTS idx_tool_runs_scan ON tool_runs(scan_id, tool);
CREATE INDEX IF NOT EXISTS idx_assets_kind_norm ON assets(kind, normalized);
CREATE INDEX IF NOT EXISTS idx_asset_edges_src ON asset_edges(src_id);
CREATE INDEX IF NOT EXISTS idx_evidence_scan ON evidence(scan_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_filtration_scan ON filtration_stats(scan_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
"""

# v3: finding lifecycle — single authoritative transitions + evidence links
# (evidence → finding via FK, evidence → asset via the link table below).
_V3 = """
CREATE TABLE IF NOT EXISTS finding_transitions (
  id INTEGER PRIMARY KEY,
  finding_id INTEGER,
  from_state TEXT,
  to_state TEXT,
  actor TEXT,
  reason TEXT,
  evidence_id INTEGER,
  ts TEXT,
  FOREIGN KEY(finding_id) REFERENCES findings(id),
  FOREIGN KEY(evidence_id) REFERENCES evidence(id)
);
CREATE INDEX IF NOT EXISTS idx_finding_transitions_finding ON finding_transitions(finding_id);
CREATE TABLE IF NOT EXISTS evidence_assets (
  id INTEGER PRIMARY KEY,
  evidence_id INTEGER,
  asset_id INTEGER,
  relation TEXT,
  created_at TEXT,
  FOREIGN KEY(evidence_id) REFERENCES evidence(id),
  FOREIGN KEY(asset_id) REFERENCES assets(id)
);
CREATE INDEX IF NOT EXISTS idx_evidence_assets_evidence ON evidence_assets(evidence_id);
"""

# v4: NEMESIS layer — engagement memory + resumable agent sessions.
_V4 = """
CREATE TABLE IF NOT EXISTS engagement_memory (
  id INTEGER PRIMARY KEY,
  engagement TEXT,
  category TEXT,
  key TEXT,
  value TEXT,
  evidence_id INTEGER,
  created_at TEXT,
  updated_at TEXT,
  UNIQUE(engagement, category, key)
);
CREATE INDEX IF NOT EXISTS idx_engmem_engagement ON engagement_memory(engagement, category);
CREATE TABLE IF NOT EXISTS nemesis_sessions (
  id INTEGER PRIMARY KEY,
  engagement TEXT UNIQUE,
  scan_id INTEGER,
  phase TEXT,
  state TEXT,
  plan TEXT,
  completed TEXT,
  pending TEXT,
  evidence_refs TEXT,
  findings_refs TEXT,
  errors TEXT,
  updated_at TEXT
);
"""

# v5: bounded multi-agent runtime — per-task state for resume + provenance.
_V5 = """
CREATE TABLE IF NOT EXISTS nemesis_tasks (
  id INTEGER PRIMARY KEY,
  plan_id TEXT,
  engagement TEXT,
  task_id TEXT,
  role TEXT,
  action TEXT,
  target TEXT,
  status TEXT,
  attempts INTEGER DEFAULT 0,
  failure_class TEXT,
  result TEXT,
  error TEXT,
  depends_on TEXT,
  evidence_refs TEXT,
  findings_refs TEXT,
  started_at TEXT,
  ended_at TEXT,
  updated_at TEXT,
  UNIQUE(plan_id, task_id)
);
CREATE INDEX IF NOT EXISTS idx_nemesis_tasks_plan ON nemesis_tasks(plan_id);
"""

_STEPS: dict[int, str] = {2: _V2, 3: _V3, 4: _V4, 5: _V5}


def current_version(conn: sqlite3.Connection) -> int:
    conn.execute(_META)
    conn.commit()
    try:
        row = conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
        return int((row or (None,))[0] or 1)
    except sqlite3.DatabaseError:  # pragma: no cover - exotic corruption
        return 1


def migrate(conn: sqlite3.Connection, target: int = TARGET) -> int:
    """Apply additive migrations up to *target*; returns the new version.

    Never raises on an individual step being already applied
    (``IF NOT EXISTS`` everywhere). A failure inside a step rolls back only
    that step and is logged — an existing database is never left unusable.
    """
    version = current_version(conn)
    if version >= target:
        return version
    for step in range(version + 1, target + 1):
        script = _STEPS.get(step)
        if not script:
            continue
        try:
            conn.executescript(script)
            conn.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                (step, _now()),
            )
            conn.commit()
            logger.info("schema migrated to v%d", step)
        except sqlite3.DatabaseError as exc:  # pragma: no cover
            logger.error("schema migration v%d failed: %s", step, exc)
            conn.rollback()
            break
    return current_version(conn)


def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def schema_version(db: Any) -> int:
    """Read the applied schema version through a Database-like object."""
    try:
        rows = db.query("SELECT MAX(version) AS v FROM schema_version")
        return int((rows[0] if rows else {}).get("v") or 1)
    except Exception:  # pragma: no cover - pre-meta databases
        return 1
