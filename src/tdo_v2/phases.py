"""Per-phase measurement of an analysis run (docs 25.30 K2), opt-in with
TDO_V2_PHASES=1 (resolved once per run). Disabled: ``phase(name)`` returns one
preallocated null context -- no environment read, no allocation, no clock,
no /proc read; ``count`` returns at once. Enabled: per phase name, the number
of invocations, aborted ones (an exception passed through), inclusive and
exclusive wall time (perf_counter), inclusive and exclusive logical work
(``resource_limits.logical_work``: the run ledger plus pending units; not
charged while reporting), and named counters; a sampler thread reads the
process RSS (/proc/self/statm) every ``SAMPLE_SECONDS`` and attributes the
sample to the innermost TOP-LEVEL phase active (max per phase; sample count
and observed gaps recorded; a phase never sampled has no memory figure).

The active phase stack is module state written only by the analysis thread
and read by the sampler (no context variables). Analyses are serial.
``begin(run)`` / ``end()`` are called by resource_limits' run scope; the
finished table is ``resource_limits.last_run().phases``."""

from __future__ import annotations

import os
import threading
import time

SAMPLE_SECONDS = 0.05
TOP_LEVEL = frozenset({
    "admission", "scoping", "linker", "analyze_units", "normalize", "summarize", "indirect_targets",
    "program_checks", "binding", "roots", "reporting",
})


class _Null:
    __slots__ = ()

    def __enter__(self):
        return None

    def __exit__(self, kind, value, traceback):
        return False


_NULL = _Null()


class _Table:
    def __init__(self, work) -> None:
        self.work = work                # () -> logical work units
        self.rows: dict = {}            # name -> dict
        self.stack: list = []           # [name, start time, start work, child time, child work]
        self.top: str | None = None     # innermost top-level phase (read by the sampler)
        self.samples = 0
        self.gaps: list = []
        self.started = time.perf_counter()

    def row(self, name):
        found = self.rows.get(name)
        if found is None:
            found = self.rows[name] = {"count": 0, "aborted": 0, "time": 0.0, "time_exclusive": 0.0,
                                       "work": 0, "work_exclusive": 0, "rss_max_mb": None, "counters": {}}
        return found


_TABLE: _Table | None = None
# called with ("enter" | "exit", name) at every TOP-LEVEL phase transition when
# set (the bench's telemetry); only while enabled
LISTENER = None
_SAMPLER: threading.Thread | None = None
_STOP = threading.Event()


class _Phase:
    __slots__ = ("name", "table")

    def __init__(self, name, table) -> None:
        self.name, self.table = name, table

    def __enter__(self):
        table = self.table
        table.stack.append([self.name, time.perf_counter(), table.work(), 0.0, 0, table.top])
        if self.name in TOP_LEVEL:
            table.top = self.name
            if LISTENER is not None:
                LISTENER("enter", self.name)
        return None

    def __exit__(self, kind, value, traceback):
        table = self.table
        name, start, work, child_time, child_work, outer_top = table.stack.pop()
        elapsed = time.perf_counter() - start
        done = table.work() - work
        row = table.row(name)
        row["count"] += 1
        if kind is not None:
            row["aborted"] += 1
        row["time"] += elapsed
        row["time_exclusive"] += elapsed - child_time
        row["work"] += done
        row["work_exclusive"] += done - child_work
        if table.stack:
            table.stack[-1][3] += elapsed
            table.stack[-1][4] += done
        table.top = outer_top
        if name in TOP_LEVEL and LISTENER is not None:
            LISTENER("exit", name)
        return False


def enabled() -> bool:
    return _TABLE is not None


def phase(name: str):
    """``with phase("memory_ssa"):`` -- a measured phase (a no-op when off)."""
    table = _TABLE
    if table is None:
        return _NULL
    return _Phase(name, table)


def measured(name: str):
    """Decorator: the function is the phase ``name`` (one global check when
    off; never on recursive functions -- one frame per call)."""
    import functools

    def wrap(function):
        @functools.wraps(function)
        def inner(*args, **kwargs):
            table = _TABLE
            if table is None:
                return function(*args, **kwargs)
            with _Phase(name, table):
                return function(*args, **kwargs)

        return inner

    return wrap


def count(name: str, value: int, phase_name: str | None = None) -> None:
    """Add ``value`` to a named counter of ``phase_name`` (default: the
    innermost active phase); only already-known lengths are passed."""
    table = _TABLE
    if table is None:
        return
    target = phase_name or (table.stack[-1][0] if table.stack else "run")
    counters = table.row(target)["counters"]
    counters[name] = counters.get(name, 0) + value


def _rss_mb() -> float:
    with open("/proc/self/statm", "rb") as handle:
        return int(handle.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / (1 << 20)


def _sample(table: _Table) -> None:
    last = time.perf_counter()
    while not _STOP.wait(SAMPLE_SECONDS):
        now = time.perf_counter()
        if now - last > 2 * SAMPLE_SECONDS:
            table.gaps.append(round(now - last, 3))
        last = now
        try:
            rss = _rss_mb()
        except OSError:
            continue
        table.samples += 1
        name = table.top or "run"
        row = table.row(name)
        if row["rss_max_mb"] is None or rss > row["rss_max_mb"]:
            row["rss_max_mb"] = round(rss, 1)


def begin(work) -> None:
    """At an outer run's start (resource_limits): enable when TDO_V2_PHASES=1."""
    global _TABLE, _SAMPLER
    if os.environ.get("TDO_V2_PHASES") != "1":
        _TABLE = None
        return
    _TABLE = _Table(work)
    _STOP.clear()
    if os.path.exists("/proc/self/statm"):
        _SAMPLER = threading.Thread(target=_sample, args=(_TABLE,), name="tdo-phase-sampler", daemon=True)
        _SAMPLER.start()


def end() -> dict | None:
    """At the outer run's end: the sampler stopped and joined first, then the
    table frozen into plain data (None when off)."""
    global _TABLE, _SAMPLER
    table = _TABLE
    if table is None:
        return None
    _STOP.set()
    if _SAMPLER is not None:
        _SAMPLER.join()
    _SAMPLER = None
    _TABLE = None
    return {"phases": table.rows, "samples": table.samples, "sample_seconds": SAMPLE_SECONDS,
            "gaps": table.gaps[:100], "gap_count": len(table.gaps),
            "wall": round(time.perf_counter() - table.started, 3),
            "open": [row[0] for row in table.stack]}
