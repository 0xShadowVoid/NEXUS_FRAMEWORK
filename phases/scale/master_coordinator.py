"""SCALE phase — functional local master coordinator (roadmap D8).

Turns the scaffold into a working single-host parallel executor: submit
tasks to a queue and run them concurrently across a worker pool. The
scan function is injected, so it is fully offline-testable. Remote /
multi-host distribution (SSH/Redis) remains the next increment and is
flagged via ``dispatch_remote``.
"""
from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable

from lib.logger import get_logger

logger = get_logger("master_coordinator")

PHASE_STATUS = "local"


@dataclass
class WorkerSpec:
    """A (future) worker VPS instance; local workers are implicit."""

    worker_id: str
    host: str = ""
    capacity: int = 1


@dataclass
class TaskQueue:
    """A thread-safe task queue."""

    pending: list[dict[str, Any]] = field(default_factory=list)
    running: dict[str, dict[str, Any]] = field(default_factory=dict)
    completed: list[dict[str, Any]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)


class MasterCoordinator:
    """Coordinator that distributes scan tasks across a local worker pool."""

    def __init__(
        self,
        workers: list[WorkerSpec] | None = None,
        scan_fn: Callable[[dict[str, Any]], Any] | None = None,
    ):
        self.workers = workers or []
        self.scan_fn = scan_fn or (lambda task: {"task": task, "status": "noop"})
        self.queue = TaskQueue()

    def register_worker(self, worker: WorkerSpec) -> None:
        self.workers.append(worker)

    def submit(self, task: dict[str, Any]) -> str:
        """Enqueue a scan task; returns its task id."""
        task_id = uuid.uuid4().hex[:8]
        task = dict(task)
        task["_id"] = task_id
        with self.queue._lock:
            self.queue.pending.append(task)
        logger.debug("task %s enqueued", task_id)
        return task_id

    def run_local(self, max_workers: int = 2) -> dict[str, Any]:
        """Run all pending tasks across a local thread pool and aggregate."""
        with self.queue._lock:
            pending = list(self.queue.pending)
            self.queue.pending.clear()
        if not pending:
            return self.aggregate()

        def _run(task: dict[str, Any]) -> dict[str, Any]:
            try:
                result = self.scan_fn(task)
            except Exception as exc:  # one failing task must not kill the pool
                result = {"task_id": task.get("_id"), "status": "error", "error": str(exc)}
            with self.queue._lock:
                self.queue.completed.append(result)
            return result

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            list(pool.map(_run, pending))
        logger.info("scale: %d task(s) completed", len(pending))
        return self.aggregate()

    def aggregate(self) -> dict[str, Any]:
        with self.queue._lock:
            completed = list(self.queue.completed)
        return {
            "phase": "scale",
            "workers": len(self.workers),
            "completed": len(completed),
            "results": completed,
        }

    def dispatch_remote(self, task: dict[str, Any]) -> None:
        """Multi-host dispatch — not yet implemented (next increment)."""
        raise NotImplementedError(
            "multi-host SCALE dispatch (SSH/Redis) is not implemented; "
            "use run_local() for single-host parallelism"
        )

    def status(self) -> dict[str, Any]:
        with self.queue._lock:
            return {
                "phase": "scale",
                "status": PHASE_STATUS,
                "workers": len(self.workers),
                "pending": len(self.queue.pending),
                "completed": len(self.queue.completed),
            }
