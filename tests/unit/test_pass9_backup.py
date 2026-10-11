"""Unit tests for SQLite online backup and restore functionality."""
from __future__ import annotations

import tempfile
from pathlib import Path
import pytest
import sqlite3
from core.database import Database

def test_database_backup_and_restore(tmp_path: Path):
    db_path = tmp_path / "nexus_test.db"
    backup_path = tmp_path / "nexus_backup.db"
    
    db = Database(db_path)
    # Insert a test target
    target_id = db.upsert_target(domain="example.com", platform="generic", program_type="bb", scope_kind="public")
    assert target_id > 0
    
    # Perform backup
    db.backup_to(backup_path)
    assert backup_path.exists()
    
    # Create a new database and restore from backup
    restored_db_path = tmp_path / "nexus_restored.db"
    restored_db = Database(restored_db_path)
    restored_db.restore_from(backup_path)
    
    targets = restored_db.list_targets()
    assert len(targets) == 1
    assert targets[0]["domain"] == "example.com"

def test_database_restore_invalid_backup(tmp_path: Path):
    db_path = tmp_path / "nexus_test.db"
    invalid_backup = tmp_path / "invalid.db"
    invalid_backup.write_text("not a sqlite database")
    
    db = Database(db_path)
    with pytest.raises(ValueError, match="Invalid or corrupted SQLite backup file"):
        db.restore_from(invalid_backup)
