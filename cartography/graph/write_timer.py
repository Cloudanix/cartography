"""
Thread-local accumulator that separates time spent talking to Neo4j from time spent
calling cloud APIs inside a service sync.

cartography.graph.session.Session feeds this on every run/execute_write/execute_read;
provider timing blocks snapshot total() around a service_func call and emit the delta
as graph_write_seconds next to duration_seconds (perf plan Phase 3.0.2).

Each sync worker thread owns one Session, so a plain thread-local monotonic counter is
enough: callers measure deltas, never reset.
"""
import threading
import time
from contextlib import contextmanager
from typing import Iterator

_local = threading.local()


def add(seconds: float) -> None:
    _local.total = getattr(_local, "total", 0.0) + seconds


def total() -> float:
    """Monotonic per-thread total of seconds spent in Neo4j calls."""
    return getattr(_local, "total", 0.0)


@contextmanager
def timed() -> Iterator[None]:
    t0 = time.perf_counter()
    try:
        yield
    finally:
        add(time.perf_counter() - t0)
