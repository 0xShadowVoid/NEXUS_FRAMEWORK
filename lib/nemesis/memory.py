"""NEMESIS engagement memory (Phase A).

Lightweight, SQLite-backed, engagement-scoped memory that survives
restart (it lives in ``nexus.db`` next to the checkpoint state, and the
session table references scan ids instead of duplicating checkpoints).

Isolation rule: everything is scoped by engagement/target and the store
refuses to exist without an engagement — memories never mix.

Secret rule: values are sanitized and sensitive keys are redacted
BEFORE persistence. Plaintext passwords, API keys, cookies, bearer
tokens and similar are never stored; use evidence references instead.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from core.sanitizer import sanitize_evidence
from lib.logger import get_logger

logger = get_logger("nemesis.memory")

CATEGORIES = (
    "technologies", "endpoints", "auth", "hypotheses", "rejected_hypotheses",
    "validated_findings", "false_positives", "tool_results", "decisions",
    "evidence_refs", "phase_context",
)

_BANNED_KEYS = (
    "password", "passwd", "pwd", "api_key", "apikey", "token", "secret",
    "cookie", "authorization", "session_id", "credential",
)


def _scrub(value: Any, depth: int = 0) -> Any:
    """Redact sensitive keys + sanitize strings; structural + bounded."""
    if depth > 6:
        return "[depth-limit]"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in list(value.items())[:100]:
            ks = str(k).lower()
            if any(b in ks for b in _BANNED_KEYS):
                out[str(k)] = "[REDACTED]"
            else:
                out[str(k)] = _scrub(v, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [_scrub(v, depth + 1) for v in list(value)[:100]]
    if isinstance(value, str):
        return sanitize_evidence(value, max_length=2000)
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class EngagementMemory:
    """Engagement-scoped memory store (never mixes engagements)."""

    def __init__(self, db: Any, engagement: str):
        if not str(engagement or "").strip():
            raise ValueError("engagement is required (memory must never be unscoped)")
        self.db = db
        self.engagement = str(engagement).strip().lower()

    # -- writes --------------------------------------------------------------

    def remember(
        self, category: str, key: str, value: Any, evidence_id: int | None = None
    ) -> int:
        """Insert or update one memory entry (sanitized before persistence)."""
        cat = str(category or "").strip().lower()
        if cat not in CATEGORIES:
            raise ValueError(f"unknown memory category: {category!r}")
        key_s = str(key or "").strip()[:200]
        payload = json.dumps(_scrub(value), default=str)
        now = _now()
        row = self.db.query(
            "SELECT id FROM engagement_memory WHERE engagement = ? AND category = ? AND key = ?",
            (self.engagement, cat, key_s),
        )
        if row:
            self.db.execute(
                "UPDATE engagement_memory SET value = ?, evidence_id = ?, updated_at = ? WHERE id = ?",
                (payload, evidence_id, now, row[0]["id"]),
            )
            return int(row[0]["id"])
        cur = self.db.execute(
            "INSERT INTO engagement_memory (engagement, category, key, value,"
            " evidence_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (self.engagement, cat, key_s, payload, evidence_id, now, now),
        )
        return int(cur.lastrowid)

    def reject_hypothesis(self, key: str, reason: str = "") -> None:
        """Record a rejected hypothesis (kept — never deleted)."""
        self.remember("rejected_hypotheses", key, {"reason": reason})

    # -- reads ---------------------------------------------------------------

    def recall(self, category: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql = "SELECT * FROM engagement_memory WHERE engagement = ?"
        params: list[Any] = [self.engagement]
        if category:
            sql += " AND category = ?"
            params.append(str(category).lower())
        sql += " ORDER BY id LIMIT ?"
        params.append(int(limit))
        rows = self.db.query(sql, tuple(params))
        for r in rows:
            try:
                r["value"] = json.loads(r.get("value") or "null")
            except (TypeError, ValueError):  # pragma: no cover - defensive
                pass
        return rows

    def get(self, category: str, key: str) -> Any | None:
        rows = self.db.query(
            "SELECT value FROM engagement_memory WHERE engagement = ? AND category = ? AND key = ?",
            (self.engagement, str(category).lower(), str(key or "").strip()[:200]),
        )
        if not rows:
            return None
        try:
            return json.loads(rows[0]["value"] or "null")
        except (TypeError, ValueError):  # pragma: no cover - defensive
            return None

    def hypotheses(self) -> list[dict[str, Any]]:
        """Open hypotheses (rejected ones are filtered out)."""
        rejected = {r["key"] for r in self.recall("rejected_hypotheses", limit=500)}
        return [h for h in self.recall("hypotheses", limit=500) if h["key"] not in rejected]

    def context_summary(self) -> dict[str, Any]:
        """Compact context map for agent prompts / resumed sessions."""
        out: dict[str, Any] = {}
        for cat in CATEGORIES:
            rows = self.recall(cat, limit=50)
            if rows:
                out[cat] = [{"key": r["key"], "value": r["value"]} for r in rows]
        return out
