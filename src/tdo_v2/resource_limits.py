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
    """A per-function or per-run budget ran out (``kind``: "time", "memory",
    "work" ...): the function (or run) is reported incomplete."""

    def __init__(self, kind: str, detail: str = "") -> None:
        super().__init__(f"{kind} budget exceeded{': ' + detail if detail else ''}")
        self.kind = kind


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
    other threads never receive signals); the previous handler, or None."""
    if threading.current_thread() is not threading.main_thread():
        return None
    return signal.signal(signal.SIGINT, lambda signum, frame: received.append(signum))


def _deliver_interrupt(previous) -> None:
    """A recorded SIGINT, delivered as the previous handler would have."""
    if callable(previous):
        previous(signal.SIGINT, None)   # default_int_handler: KeyboardInterrupt
    elif previous != signal.SIG_IGN:
        raise KeyboardInterrupt


def run_analysis(function, *args, **kwargs):
    """``function(*args, **kwargs)`` on the analysis worker (see the module)."""
    if on_worker():
        return function(*args, **kwargs)
    megabytes = stack_megabytes()
    if not worker_supported():
        with _LOCK:   # (serial inline runs: process-wide limits and diagnostics)
            return function(*args, **kwargs)
    with _LOCK:
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


__all__ = ("AnalysisBudgetExceeded", "analysis_entry", "DEFAULT_STACK_MB", "RESOURCE_FAILURES", "on_worker", "run_analysis",
           "stack_megabytes", "worker_supported")
