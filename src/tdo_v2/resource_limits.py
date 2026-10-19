"""Resource limits of an analysis (docs 25.30, step A-5 K1).

* ``RESOURCE_FAILURES``: the exceptions that mean "this analysis ran out of a
  resource" -- Python's recursion bound (and CPython 3.14's C-stack guard,
  both ``RecursionError``), ``MemoryError`` and ``AnalysisBudgetExceeded``.
  Code that turns arbitrary exceptions into evidence verdicts ("incomplete
  memory", "invalid observation" ...) re-raises these first: a resource
  failure is never mistaken for a property of the input.
* ``run_analysis``: runs an analysis entry point on a dedicated worker thread
  with a large stack and a recursion limit sized to it (qualified on
  WSL / Linux CPython >= 3.14, where the interpreter checks the real C stack;
  elsewhere -- and with TDO_V2_ANALYSIS_WORKER=0 -- the entry runs inline
  with the default limits). Nested entries already on the worker run inline.
  The caller's context variables are copied into the worker once; results
  and exceptions (any BaseException, with its traceback) come back. Ctrl-C
  (SIGINT) is recorded, never raised, for the whole worker lifecycle -- from
  before the thread is created until it has ended (a thread cannot be
  stopped safely; an interrupt at ``start`` / ``join`` must not release the
  lock or restore the limits under a live worker) -- and delivered to the
  previous handler afterwards (KeyboardInterrupt by default). The
  process-wide recursion limit is raised for the worker's lifetime:
  analyses are serial (one reentrant lock, inline runs included); other
  threads of the process see the raised limit (and a thread started in the
  start window the large stack size) meanwhile -- the engine starts no other
  threads.
"""

from __future__ import annotations

import contextvars
import os
import signal
import sys
import threading


class AnalysisBudgetExceeded(Exception):
    """A budget ran out: ``scope`` "function" (that function fails:
    ``ANALYSIS_BUDGET``) or "run" (finalization: ``ANALYSIS_RUN_BUDGET``),
    ``kind`` "work" / "time" / "rss" / "structure"."""

    def __init__(self, kind: str, detail: str = "", scope: str = "function") -> None:
        super().__init__(f"{scope} {kind} budget exceeded{': ' + detail if detail else ''}")
        self.kind = kind
        self.scope = scope


RESOURCE_FAILURES = (RecursionError, MemoryError, AnalysisBudgetExceeded)

DEFAULT_STACK_MB = 1024
MIN_STACK_MB = 64
MAX_STACK_MB = 16384
# Python frames per MiB of worker stack the recursion limit allows (3.14's
# Python-to-Python calls use no C stack; C-level recursion is checked against
# the real stack by the interpreter): measured 60,000 dependent values
# analyze with 2 GiB and 400,000
FRAMES_PER_MB = 200

_LOCK = threading.RLock()
_WORKERS: set[int] = set()


def worker_supported() -> bool:
    """The large-stack worker is used (qualified platforms only)."""
    if os.environ.get("TDO_V2_ANALYSIS_WORKER") == "0":
        return False
    return sys.platform.startswith("linux") and sys.version_info >= (3, 14)


def stack_megabytes() -> int:
    """TDO_V2_ANALYSIS_STACK_MB, validated (an infrastructure error when
    malformed or out of range -- never silently replaced)."""
    raw = os.environ.get("TDO_V2_ANALYSIS_STACK_MB")
    if raw is None:
        return DEFAULT_STACK_MB
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"TDO_V2_ANALYSIS_STACK_MB must be an integer, got {raw!r}") from None
    if not MIN_STACK_MB <= value <= MAX_STACK_MB:
        raise ValueError(f"TDO_V2_ANALYSIS_STACK_MB must be in [{MIN_STACK_MB}, {MAX_STACK_MB}], got {value}")
    return value


def on_worker() -> bool:
    return threading.get_ident() in _WORKERS


def _defer_interrupts(received: list):
    """Record SIGINT in ``received`` instead of raising (the main thread only:
    other threads never receive signals); the previous handler, or None. With
    the default handler a SIGINT also cancels the analysis (the worker stops at
    its next check: ``AnalysisCancelled``); SIG_IGN: not intercepted at all; a
    custom handler: delivered after the worker ends, no cancellation."""
    if threading.current_thread() is not threading.main_thread():
        return None
    previous = signal.getsignal(signal.SIGINT)
    if previous == signal.SIG_IGN:
        return None
    cancels = previous is signal.default_int_handler

    def record(signum, frame):
        received.append(signum)
        if cancels:
            _CANCEL.set()

    return signal.signal(signal.SIGINT, record)


def _deliver_interrupt(previous) -> None:
    """A recorded SIGINT, delivered as the previous handler would have."""
    if callable(previous):
        previous(signal.SIGINT, None)   # default_int_handler: KeyboardInterrupt
    elif previous != signal.SIG_IGN:
        raise KeyboardInterrupt


def run_analysis(function, *args, **kwargs):
    """``function(*args, **kwargs)`` on the analysis worker (see the module)."""
    if on_worker():
        token = _begin_run()   # (nested: inherits the run's budget)
        try:
            return function(*args, **kwargs)
        finally:
            _end_run(token)
    megabytes = stack_megabytes()
    if not worker_supported():
        with _LOCK:   # (serial inline runs: process-wide limits and diagnostics)
            token = _begin_run()
            try:
                return function(*args, **kwargs)
            finally:
                _end_run(token)
    with _LOCK:
        token = _begin_run()
        context = contextvars.copy_context()
        box: dict = {}

        def body() -> None:
            _WORKERS.add(threading.get_ident())
            try:
                box["result"] = context.run(function, *args, **kwargs)
            except BaseException as error:  # transported to the caller, traceback kept
                box["error"] = error
            finally:
                _WORKERS.discard(threading.get_ident())

        received: list = []
        previous_handler = _defer_interrupts(received)
        previous_limit = sys.getrecursionlimit()
        try:
            sys.setrecursionlimit(max(previous_limit, megabytes * FRAMES_PER_MB))
            previous_size = threading.stack_size(megabytes << 20)
            try:
                worker = threading.Thread(target=body, name="tdo-analysis")
                worker.start()
            finally:
                threading.stack_size(previous_size)
            worker.join()
        finally:
            sys.setrecursionlimit(previous_limit)
            if previous_handler is not None:
                signal.signal(signal.SIGINT, previous_handler)
            _end_run(token)
            _CANCEL.clear()
        if isinstance(box.get("error"), AnalysisCancelled):
            box.clear()
            raise KeyboardInterrupt
        if received:
            # a handler that returns (SIG_IGN, a custom one) keeps the outcome
            # (Astra K1a round 2, P2-1); one that raises releases it first
            try:
                _deliver_interrupt(previous_handler)
            except BaseException:
                box.clear()
                raise
        if "error" in box:
            error = box.pop("error")
            try:
                raise error
            finally:
                del error   # (frame <-> traceback cycle: the worker's frames are freed at once)
        return box.pop("result")


def analysis_entry(function):
    """Decorator: the entry point runs through ``run_analysis`` (its signature
    is kept: ``inspect.signature`` follows ``__wrapped__``)."""
    import functools

    @functools.wraps(function)
    def entry(*args, **kwargs):
        return run_analysis(function, *args, **kwargs)

    return entry




# ---------------------------------------------------------------- budgets (K1c)
# docs 25.30 K1c: one cumulative ledger per function (keyed by its scope
# identity: addresses repeat across nested library runs) and one per run,
# work charged exactly (``step``), sampled clock / RSS / cancellation checks
# every QUANTUM units and at activation boundaries; every limit is off unless
# configured (TDO_V2_FUNCTION_WORK, TDO_V2_FUNCTION_SECONDS, TDO_V2_RUN_WORK,
# TDO_V2_RUN_SECONDS, TDO_V2_RUN_RSS_MB, TDO_V2_REPORTING_SECONDS,
# TDO_V2_LIMIT_<STRUCTURE>). Analyses are serial (``_LOCK``): the fast
# counter is module state.

QUANTUM = 4096
DEFAULT_REPORTING_SECONDS = 60.0
STRUCTURES = ("graph_nodes", "graph_edges", "memory_definitions", "fact_members", "summary_runs",
              "output_items")


class AnalysisCancelled(BaseException):
    """Ctrl-C during an analysis (a BaseException: no per-function containment
    catches it); ``run_analysis`` turns it into KeyboardInterrupt."""


class AnalysisReportingFailed(Exception):
    """The bounded reporting phase after a run exhaustion did not finish: the
    run fails (never a partial inventory without its failures)."""


def _positive(name, cast):
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return None
    try:
        value = cast(raw)
    except ValueError:
        raise ValueError(f"{name} must be a number, got {raw!r}") from None
    if not value > 0:
        raise ValueError(f"{name} must be positive, got {raw!r}")
    return value


class Limits:
    """The configured limits (None: off)."""

    __slots__ = ("function_work", "function_seconds", "run_work", "run_seconds", "run_rss_mb",
                 "reporting_seconds", "structures")

    def __init__(self, function_work=None, function_seconds=None, run_work=None, run_seconds=None,
                 run_rss_mb=None, reporting_seconds=DEFAULT_REPORTING_SECONDS, structures=None):
        self.function_work, self.function_seconds = function_work, function_seconds
        self.run_work, self.run_seconds, self.run_rss_mb = run_work, run_seconds, run_rss_mb
        self.reporting_seconds = reporting_seconds
        self.structures = dict(structures or {})

    @classmethod
    def from_environment(cls) -> "Limits":
        return cls(_positive("TDO_V2_FUNCTION_WORK", int), _positive("TDO_V2_FUNCTION_SECONDS", float),
                   _positive("TDO_V2_RUN_WORK", int), _positive("TDO_V2_RUN_SECONDS", float),
                   _positive("TDO_V2_RUN_RSS_MB", int),
                   _positive("TDO_V2_REPORTING_SECONDS", float) or DEFAULT_REPORTING_SECONDS,
                   {name: value for name in STRUCTURES
                    if (value := _positive(f"TDO_V2_LIMIT_{name.upper()}", int)) is not None})


class _Ledger:
    __slots__ = ("work", "seconds")

    def __init__(self) -> None:
        self.work = 0
        self.seconds = 0.0


class RunBudget:
    """The run's ledger and its functions' ledgers (``exhausted``: the latched
    run-scope kind, e.g. "work"; ``reporting``: the bounded reporting phase)."""

    def __init__(self, limits: Limits) -> None:
        import time

        self.limits = limits
        self.started = time.monotonic()
        self.deadline = None if limits.run_seconds is None else self.started + limits.run_seconds
        self.work = 0
        self.ledgers: dict = {}
        self.exhausted: str | None = None
        self.reporting = False
        self.reporting_deadline = None

    def ledger(self, key) -> _Ledger:
        if key not in self.ledgers:
            self.ledgers[key] = _Ledger()
        return self.ledgers[key]


_RUN: contextvars.ContextVar = contextvars.ContextVar("tdo_v2_run_budget", default=None)
_CANCEL = threading.Event()
_left = QUANTUM          # units until the next slow path
_quantum = QUANTUM       # the units the current quantum started with
_active: _Ledger | None = None
_active_since = 0.0


def current_run() -> RunBudget | None:
    return _RUN.get()


_LAST: RunBudget | None = None


def last_run() -> RunBudget | None:
    """The most recently finished outer run (its ledgers, work and ``phases``
    table: docs 25.30 K2) -- kept after the run context is reset."""
    return _LAST


def logical_work() -> int:
    """The run's work so far INCLUDING the pending units of the current
    quantum -- read-only: no flush, no rearm, no check (docs 25.30 K2). Work
    is not charged while reporting."""
    run = _RUN.get()
    if run is None:
        return 0
    if run.reporting:
        return run.work
    return run.work + (_quantum - _left)


def run_exhausted() -> bool:
    run = _RUN.get()
    return run is not None and run.exhausted is not None


def step(n: int = 1) -> None:
    """Charge ``n`` units of work (a leaf call: no frame stays on the stack)."""
    global _left
    _left -= n
    if _left <= 0:
        _slow()


def checkpoint() -> None:
    """A forced check (activation boundaries, before / after expensive work)."""
    _slow()


def charge(n: int) -> None:
    """A pre-allocation charge: debited in full and checked BEFORE the caller
    allocates."""
    global _left
    _left -= n
    _slow()


def limit(name: str, count: int) -> None:
    """A structural limit of the active function (AnalysisBudgetExceeded
    "structure" when ``count`` exceeds a configured ``name``)."""
    run = _RUN.get()
    if run is None:
        return
    bound = run.limits.structures.get(name)
    if bound is not None and count > bound and not run.reporting:
        raise AnalysisBudgetExceeded("structure", f"{name} {count} > {bound}", scope="function")


def _flush(run) -> None:
    """Pending units into the active function's and the run's ledgers (exactly
    once: the quantum restarts from what is left)."""
    global _quantum
    consumed = _quantum - _left
    _quantum = _left
    if consumed and run is not None and not run.reporting:
        run.work += consumed
        if _active is not None:
            _active.work += consumed


def _rearm(run) -> None:
    """The next quantum, clamped so a work limit trips at the exact unit."""
    global _left, _quantum
    size = QUANTUM
    if run is not None and not run.reporting:
        limits = run.limits
        if limits.run_work is not None:
            size = min(size, max(1, limits.run_work - run.work + 1))
        if limits.function_work is not None and _active is not None:
            size = min(size, max(1, limits.function_work - _active.work + 1))
    _left = _quantum = size


def _rss_mb() -> float:
    with open("/proc/self/statm", "rb") as handle:
        return int(handle.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / (1 << 20)


def _slow() -> None:
    import time

    run = _RUN.get()
    _flush(run)
    _rearm(run)
    if _CANCEL.is_set():
        raise AnalysisCancelled()
    if run is None:
        return
    limits = run.limits
    if run.reporting:
        if time.monotonic() > run.reporting_deadline:
            raise AnalysisReportingFailed(f"reporting exceeded {limits.reporting_seconds} s")
        return
    # run scope first: latched even when a function limit trips on the same charge
    if run.exhausted is None:
        if limits.run_work is not None and run.work > limits.run_work:
            run.exhausted = "work"
        elif run.deadline is not None and time.monotonic() > run.deadline:
            run.exhausted = "time"
        elif limits.run_rss_mb is not None and _rss_mb() > limits.run_rss_mb:
            run.exhausted = "rss"
    if run.exhausted is not None:
        raise AnalysisBudgetExceeded(run.exhausted, scope="run")
    if _active is not None:
        if limits.function_work is not None and _active.work > limits.function_work:
            raise AnalysisBudgetExceeded("work", scope="function")
        if limits.function_seconds is not None \
                and _active.seconds + (time.monotonic() - _active_since) > limits.function_seconds:
            raise AnalysisBudgetExceeded("time", scope="function")


class activation:
    """``with activation(key):`` -- the function ``key``'s ledger is active
    (cumulative across activations; an outer activation pauses meanwhile);
    a forced check on entry; the pending units flushed exactly once on exit
    (never raising there: an exception in flight is never replaced)."""

    __slots__ = ("key", "ledger", "previous", "run")

    def __init__(self, key) -> None:
        self.key = key

    def __enter__(self):
        import time

        global _active, _active_since
        self.run = _RUN.get()
        if self.run is None or self.run.reporting:
            self.ledger = None
            return None
        _flush(self.run)
        now = time.monotonic()
        if _active is not None:
            _active.seconds += now - _active_since
        self.previous = _active
        self.ledger = self.run.ledger(self.key)
        _active, _active_since = self.ledger, now
        global _left
        _left -= 1   # (one unit per activation)
        try:
            _slow()
        except BaseException:
            self.__exit__(None, None, None)
            raise
        return self.ledger

    def __exit__(self, kind, value, traceback) -> bool:
        import time

        global _active, _active_since
        if self.ledger is None:
            return False
        _flush(self.run)
        now = time.monotonic()
        self.ledger.seconds += now - _active_since
        _active, _active_since = self.previous, now
        _rearm(self.run)
        self.ledger = None
        return False


class reporting:
    """``with reporting():`` -- the bounded reporting phase after a run
    exhaustion: analysis budgets suspended, its own deadline (entry +
    TDO_V2_REPORTING_SECONDS), cancellation still checked; analysis entries
    refuse meanwhile."""

    def __enter__(self):
        import time

        self.run = run = _RUN.get()
        self.entered = run is not None and not run.reporting
        if self.entered:
            _flush(run)
            run.reporting = True
            run.reporting_deadline = time.monotonic() + run.limits.reporting_seconds
            _rearm(run)
        return run

    def __exit__(self, kind, value, traceback) -> bool:
        if self.entered:
            _flush(self.run)
            self.run.reporting = False
            self.run.reporting_deadline = None
            _rearm(self.run)
        return False


def _begin_run():
    """A new run budget for an outer entry (None when one is active: nested
    entries inherit it); the context token to reset."""
    global _active, _active_since
    run = _RUN.get()
    if run is not None:
        if run.reporting:
            raise AnalysisReportingFailed("an analysis entry during the reporting phase")
        return None
    _CANCEL.clear()
    _active, _active_since = None, 0.0
    run = RunBudget(Limits.from_environment())
    run.phases = None
    token = _RUN.set(run)
    _rearm(run)
    from . import phases

    phases.begin(logical_work)
    return token


def _end_run(token) -> None:
    global _active, _LAST
    if token is not None:
        run = _RUN.get()
        _flush(run)   # (the last pending units; never raises)
        from . import phases

        run.phases = phases.end()   # (the sampler stopped and joined first)
        _LAST = run
        _RUN.reset(token)
        _active = None
        _rearm(None)


__all__ = ("AnalysisBudgetExceeded", "AnalysisCancelled", "AnalysisReportingFailed", "Limits", "QUANTUM",
           "RESOURCE_FAILURES", "RunBudget", "activation", "analysis_entry", "charge", "checkpoint", "current_run",
           "DEFAULT_STACK_MB", "limit", "on_worker", "reporting", "run_analysis", "run_exhausted",
           "stack_megabytes", "step", "worker_supported")
