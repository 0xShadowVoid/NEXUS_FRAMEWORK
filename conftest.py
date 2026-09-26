"""Pytest bootstrap: ensure repo root is importable as `lib` / `core` / `phases`."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
