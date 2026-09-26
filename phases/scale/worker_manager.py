"""SCALE phase — worker manager (functional local workers)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from lib.logger import get_logger
from phases.scale.master_coordinator import WorkerSpec

logger = get_logger("worker_manager")

PHASE_STATUS = "local"


@dataclass
class WorkerHealth:
    worker_id: str
    alive: bool = False
    last_seen: str = ""
    load: float = 0.0


class WorkerManager:
    """Manages worker specs and executes tasks through a scan function."""

    def __init__(self, scan_fn: Callable[[dict[str, Any]], Any] | None = None):
        self._workers: dict[str, WorkerSpec] = {}
        self._scan_fn = scan_fn or (lambda task: {"task": task})

    def add(self, spec: WorkerSpec) -> None:
        self._workers[spec.worker_id] = spec

    def health(self) -> list[WorkerHealth]:
        return [WorkerHealth(worker_id=w.worker_id) for w in self._workers.values()]

    def execute(self, task: dict[str, Any]) -> Any:
        """Execute a single task locally via the configured scan function."""
        try:
            return self._scan_fn(task)
        except Exception as exc:
            logger.warning("worker task failed: %s", exc)
            return {"status": "error", "error": str(exc)}

    def status(self) -> dict[str, Any]:
        return {"phase": "scale", "status": PHASE_STATUS, "workers": len(self._workers)}
