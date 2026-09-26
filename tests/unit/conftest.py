"""Shared DB fixture for unit tests."""
from __future__ import annotations

import pytest

from core.database import Database


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "test.db")
    yield database
    database.close()
