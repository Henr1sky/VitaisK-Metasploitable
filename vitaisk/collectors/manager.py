"""Orchestrator: instantiates, starts, and stops all enabled collectors."""
from __future__ import annotations

import threading
from typing import Iterator, Optional

from ..events import Event
from ..utils import eprint
from .base import Collector, EventQueue


class CollectorManager:
    """Builds collectors from config, runs them in threads, exposes one event stream."""

    def __init__(self, config, queue: Optional[EventQueue] = None, *, build=None):
        from . import build_collectors  # local import avoids circular import
        self.config = config
        self.queue = queue or EventQueue(maxsize=config.max_events_in_memory)
        self.stop_event = threading.Event()
        self.collectors: list[Collector] = (build or build_collectors)(
            config, self.queue, self.stop_event,
        )

    # ── lifecycle ──────────────────────────────────────────────
    def start(self) -> None:
        for c in self.collectors:
            try:
                c.start()
            except Exception as e:
                eprint(f"[manager] could not start {c.name}: {e}")

    def stop(self, timeout: float = 3.0) -> None:
        self.stop_event.set()
        for c in self.collectors:
            try:
                c.stop(timeout=timeout)
            except Exception as e:
                eprint(f"[manager] error stopping {c.name}: {e}")
        self.queue.close()

    # ── event consumption ─────────────────────────────────────
    def events(self, timeout: float = 0.5) -> Iterator[Event]:
        """Yield events from the shared queue until all collectors are done."""
        while not self.stop_event.is_set():
            ev = self.queue.get(timeout=timeout)
            if ev is not None:
                yield ev
                continue
            if self.queue.closed and self.queue.qsize() == 0:
                break
        # Drain any remaining events after stop
        while True:
            ev = self.queue.get(timeout=0.1)
            if ev is None:
                break
            yield ev

    # ── introspection ─────────────────────────────────────────
    def stats(self) -> dict:
        return {
            "queue": self.queue.stats(),
            "collectors": [
                {
                    "name": c.name,
                    "alive": c.is_alive(),
                    "events": c.events_emitted,
                    "uptime": round(c.uptime, 1),
                    "error": str(c.error) if c.error else None,
                    "rejected": getattr(c, "rejected", 0),
                }
                for c in self.collectors
            ],
        }

    def running(self) -> list[str]:
        return [c.name for c in self.collectors if c.is_alive()]