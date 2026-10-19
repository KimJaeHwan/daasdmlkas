"""Resource limits (docs 25.30, step A-5 K1a): the large-stack analysis worker
(``resource_limits.run_analysis``), resource failures that fail one function
alone and stick for the run (``ANALYSIS_DEPTH`` / ``ANALYSIS_BUDGET``),
per-function checks that fail closed, broad handlers that never turn a
resource failure into a verdict, and the summary engine's failure roots
(``EngineRun.failed_functions``)."""

import contextvars
import inspect
import sys
import threading
from pathlib import Path

import pytest

from synthetic import RAX, FunctionBuilder, add, const, program_units, reg
from tdo_v2 import interprocedural, resource_limits
from tdo_v2.interprocedural import analyze_units, program_switches_stack
from tdo_v2.normalize import FunctionNormalizer, NormalizationFailureReason, NormalizedFunction
from tdo_v2.resource_limits import AnalysisBudgetExceeded, analysis_entry, run_analysis, worker_supported

REPO = Path(__file__).resolve().parents[2]
needs_worker = pytest.mark.skipif(not worker_supported(), reason="worker qualified on Linux CPython >= 3.14")


def _wide_chain(per, count, entry=0x1000):
    builder = FunctionBuilder(entry=entry)
    for _ in range(count):
        builder.ins(*[add(reg(RAX), reg(RAX), const(1)) for _ in range(per)])
    return builder.ret()


# -- the worker -------------------------------------------------------------------

@needs_worker
def test_an_entry_runs_on_the_worker_with_a_raised_limit_restored_after():
    previous = sys.getrecursionlimit()
    seen = {}

    @analysis_entry
    def entry():
        seen.update(name=threading.current_thread().name, worker=resource_limits.on_worker(),
                    limit=sys.getrecursionlimit())
        return 7

    assert entry() == 7
    assert seen == {"name": "tdo-analysis", "worker": True,
                    "limit": max(previous, resource_limits.DEFAULT_STACK_MB * resource_limits.FRAMES_PER_MB)}
    assert sys.getrecursionlimit() == previous and not resource_limits.on_worker()


@needs_worker
def test_nested_entries_run_inline_on_the_same_worker():
    idents = []

    @analysis_entry
    def inner():
        idents.append(threading.get_ident())

    @analysis_entry
    def outer():
        idents.append(threading.get_ident())
        inner()

    outer()
    assert len(idents) == 2 and idents[0] == idents[1] != threading.get_ident()


@needs_worker
def test_exceptions_come_back_with_their_traceback():
    def fails():
        raise LookupError("inside")

    with pytest.raises(LookupError, match="inside") as caught:
        run_analysis(fails)
    assert any(frame.name == "fails" for frame in caught.traceback)


@needs_worker
def test_context_variables_are_copied_in_and_do_not_leak_out():
    variable = contextvars.ContextVar("probe", default="unset")
    token = variable.set("caller")
    try:
        def body():
            seen = variable.get()
            variable.set("worker")
            return seen

        assert run_analysis(body) == "caller"
        assert variable.get() == "caller"
    finally:
        variable.reset(token)


@needs_worker
def test_ctrl_c_is_deferred_until_the_worker_ends():
    """SIGINT anywhere in the lifecycle is recorded, then delivered: the worker
    finished, the lock free, the limit restored (round 1: Astra P1-1, agy P1-3)."""
    import signal
    import time

    previous = sys.getrecursionlimit()
    finished = []

    def body():
        signal.raise_signal(signal.SIGINT)   # handled on the main thread meanwhile
        time.sleep(0.3)
        finished.append(True)
        return 1

    with pytest.raises(KeyboardInterrupt):
        run_analysis(body)
    assert finished == [True] and sys.getrecursionlimit() == previous
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler
    assert resource_limits._LOCK.acquire(blocking=False)
    resource_limits._LOCK.release()


@needs_worker
@pytest.mark.parametrize("handler", ["ignore", "returns"])
def test_a_handler_that_returns_keeps_the_outcome(handler):
    """SIG_IGN / a custom handler that returns: the worker's result (or its
    exception) still comes back (Astra K1a round 2, P2-1)."""
    import signal

    seen = []
    installed = signal.SIG_IGN if handler == "ignore" else (lambda signum, frame: seen.append(signum))
    previous = signal.signal(signal.SIGINT, installed)
    try:
        def body():
            signal.raise_signal(signal.SIGINT)
            return 42

        def failing():
            signal.raise_signal(signal.SIGINT)
            raise LookupError("kept")

        assert run_analysis(body) == 42
        with pytest.raises(LookupError, match="kept"):
            run_analysis(failing)
        assert signal.getsignal(signal.SIGINT) is installed
        assert seen == ([] if handler == "ignore" else [signal.SIGINT, signal.SIGINT])
    finally:
        signal.signal(signal.SIGINT, previous)


def test_inline_runs_validate_the_stack_size_too(monkeypatch):
    monkeypatch.setenv("TDO_V2_ANALYSIS_WORKER", "0")
    monkeypatch.setenv("TDO_V2_ANALYSIS_STACK_MB", "bad")
    with pytest.raises(ValueError, match="TDO_V2_ANALYSIS_STACK_MB"):
        run_analysis(int)


def test_the_worker_can_be_switched_off(monkeypatch):
    monkeypatch.setenv("TDO_V2_ANALYSIS_WORKER", "0")
    assert not worker_supported()
    assert run_analysis(threading.get_ident) == threading.get_ident()


@pytest.mark.parametrize("raw", ["abc", "1.5", str(resource_limits.MIN_STACK_MB - 1),
                                 str(resource_limits.MAX_STACK_MB + 1)])
def test_a_malformed_stack_size_is_an_error_never_replaced(monkeypatch, raw):
    monkeypatch.setenv("TDO_V2_ANALYSIS_STACK_MB", raw)
    with pytest.raises(ValueError, match="TDO_V2_ANALYSIS_STACK_MB"):
        resource_limits.stack_megabytes()


def test_entry_signatures_are_kept():
    from tdo_v2.engine import analyze_frozen_bundle
    from tdo_v2.summary_engine import analyze_frozen_bundle_with_summaries

    assert "assume_import_slots_hold_exports" in inspect.signature(analyze_units).parameters
    assert "linker" in inspect.signature(analyze_frozen_bundle_with_summaries).parameters
    assert "include_explanations" in inspect.signature(analyze_frozen_bundle).parameters


@needs_worker
def test_ten_thousand_dependent_values_analyze_on_the_worker():
    """Beyond the main thread's bound (``test_analysis_depth``)."""
    result = analyze_units(program_units(_wide_chain(10, 1000)))["1:1000"]
    assert type(result.normalized) is NormalizedFunction and result.summary is not None


# -- failures of one function ---------------------------------------------------

def _failing(monkeypatch, entry, error):
    """FunctionNormalizer.normalize raising ``error`` for the function at
    ``entry``; returns the list of its attempts."""
    original = FunctionNormalizer.normalize
    attempts = []

    def normalize(self, unit, *args, **kwargs):
        if unit.scopes.function.entry.byte_offset == entry:
            attempts.append(1)
            raise error
        return original(self, unit, *args, **kwargs)

    monkeypatch.setattr(FunctionNormalizer, "normalize", normalize)
    return attempts


def test_a_budget_failure_is_typed_and_sticky_across_recursion_rounds(monkeypatch):
    """A and B call each other: the SCC is solved in rounds; B's failure is
    reported once and never retried (its callers see an opaque call)."""
    attempts = _failing(monkeypatch, 0x1800, AnalysisBudgetExceeded("work", "test"))
    a = FunctionBuilder().sub_rsp(0x28).call(0x1800).add_rsp(0x28).ret()
    b = FunctionBuilder(entry=0x1800).sub_rsp(0x28).call(0x1000).add_rsp(0x28).ret()
    results = analyze_units(program_units(a, b))
    assert results["1:1800"].normalized.reason is NormalizationFailureReason.ANALYSIS_BUDGET
    assert results["1:1800"].summary is None
    assert type(results["1:1000"].normalized) is NormalizedFunction and not results["1:1000"].proven
    assert len(attempts) == 1


def test_a_recursion_failure_is_analysis_depth(monkeypatch):
    _failing(monkeypatch, 0x1000, RecursionError("test"))
    result = analyze_units(program_units(_wide_chain(1, 3)))["1:1000"]
    assert result.normalized.reason is NormalizationFailureReason.ANALYSIS_DEPTH


def test_memory_errors_fail_the_run(monkeypatch):
    _failing(monkeypatch, 0x1000, MemoryError())
    with pytest.raises(MemoryError):
        analyze_units(program_units(_wide_chain(1, 3)))


def test_a_stack_switch_check_out_of_resources_is_unchecked(monkeypatch):
    from tdo_v2 import may_alias

    def fails(*args, **kwargs):
        raise RecursionError("test")

    monkeypatch.setattr(may_alias, "stack_switches", fails)
    assert program_switches_stack(program_units(_wide_chain(1, 3))) == {"1:1000": ("unchecked",)}


def test_an_indirect_target_check_out_of_resources_fails_its_function(monkeypatch):
    """Never "no targets" silently (agy K1a round 1, P1-1): the function is a
    failed function of the run, its callers see an opaque call."""
    calls = []

    def fails(item, functions):
        calls.append(item.key)
        if item.key == "1:1800":
            raise AnalysisBudgetExceeded("time")
        return {}

    monkeypatch.setattr(interprocedural, "_indirect_targets", fails)
    caller = FunctionBuilder().sub_rsp(0x28).call(0x1800).add_rsp(0x28).ret()
    results = analyze_units(program_units(caller, _wide_chain(1, 3, 0x1800)))
    assert results["1:1800"].normalized.reason is NormalizationFailureReason.ANALYSIS_BUDGET
    assert type(results["1:1000"].normalized) is NormalizedFunction and not results["1:1000"].proven
    assert calls.count("1:1800") == 1   # sticky: never checked again


def test_a_state_proof_out_of_resources_fails_the_function_needing_it(monkeypatch):
    """Never a silent "no proof" (agy K1a round 1, P1-2)."""
    proofs = []

    def fails(unit, normalized):
        proofs.append(unit.scopes.function.entry.byte_offset)
        raise RecursionError("test")

    monkeypatch.setattr(interprocedural, "_state_proof", fails)
    caller = FunctionBuilder().sub_rsp(0x28).call(0x1800).add_rsp(0x28).ret()
    results = analyze_units(program_units(caller, FunctionBuilder(entry=0x1800).ret()))
    if not proofs:
        pytest.skip("no call here takes a state proof")
    assert results["1:1000"].normalized.reason is NormalizationFailureReason.ANALYSIS_DEPTH
    assert proofs == [0x1800]   # computed once


# -- broad handlers ---------------------------------------------------------------

@pytest.mark.parametrize("error", [RecursionError("deep"), MemoryError(), AnalysisBudgetExceeded("time")])
def test_a_resource_failure_is_never_an_incomplete_memory_verdict(error):
    from tdo_v2._scope_memory import _consume_positioned

    def chunks():
        raise error
        yield

    with pytest.raises(type(error)):
        list(_consume_positioned(chunks(), 0, 1))


def test_other_errors_still_are_incomplete_memory():
    from tdo_v2._scope_memory import _consume_positioned, _MemoryCommitmentError

    def chunks():
        raise OSError("disk")
        yield

    with pytest.raises(_MemoryCommitmentError):
        list(_consume_positioned(chunks(), 0, 1))


# -- the summary engine's failure roots -------------------------------------------

def _generation():
    root = Path("/root/tdo_bundles/v2-win-release")
    found = sorted(path for path in root.glob("*/") if path.is_dir()) if root.is_dir() else []
    return found[0] if found else None


@pytest.mark.skipif(_generation() is None, reason="v2-win-release Bundle not exported here")
def test_a_failed_function_keeps_its_sink_occurrences_as_incomplete_roots(monkeypatch):
    sys.path.insert(0, str(REPO / "tools" / "bundle_export"))
    import run_dfbench
    from tdo_v2 import summary_engine

    generation = _generation()

    def run():
        return summary_engine.analyze_frozen_bundle_with_summaries(
            generation, naming_exporter_source=REPO / "ghidra" / "GhidraV2CallNaming.java",
            boundary_provider=run_dfbench.boundary_provider(False, run_dfbench.abi_of(generation)),
            pcodeop_models=run_dfbench.pcodeop_models())

    before = run()
    assert before.failed_functions == ()
    own: dict = {}
    for root in before.roots:
        own.setdefault(root.function_byte_offset, set()).add((root.label, root.occurrence_ordinal))
    target = max(own, key=lambda offset: len(own[offset]))
    _failing(monkeypatch, target, AnalysisBudgetExceeded("work", "test"))
    after = run()
    key = next(name for name, _, _ in after.failed_functions)
    assert after.failed_functions == ((key, "analysis_budget", "function:work"),) and key.endswith(f":{target:x}")
    failed = [root for root in after.roots if root.function_byte_offset == target]
    # every own (syntactic) sink occurrence, under the same occurrence numbers
    occurrences = {(root.label, root.occurrence_ordinal) for root in failed}
    assert occurrences and occurrences <= own[target]
    assert all(root.root_nodes == () and root.explanation == {"failure": "analysis_budget"}
               and not root.is_locally_complete and not root.is_effectively_complete
               and root.reached_origin_labels == () for root in failed)


# -- derived templates ------------------------------------------------------------

@pytest.mark.parametrize("failing", [0x1000, 0x1800])
def test_a_template_resting_on_a_resource_failure_is_a_transient_refusal(monkeypatch, failing):
    """The export itself or a callee in its closure ran out: retried next run
    (linking never stores a "transient" refusal), not a semantic verdict."""
    from tdo_v2.summary_templates import TemplateRefused, export_summary

    _failing(monkeypatch, failing, AnalysisBudgetExceeded("work", "test"))
    caller = FunctionBuilder().sub_rsp(0x28).call(0x1800).add_rsp(0x28).ret()
    results = analyze_units(program_units(caller, _wide_chain(1, 3, 0x1800)))
    with pytest.raises(TemplateRefused, match="analysis_budget") as caught:
        export_summary(results["1:1000"], results, set())
    assert caught.value.kind == "transient"


# -- dependents of a late failure ---------------------------------------------------

def test_roots_projected_through_a_late_failed_callee_become_incomplete():
    """A projects B's sink demand; B fails afterwards (sink binding / slicing):
    A's projected root is incomplete and names B (Astra K1a round 1, P1-2);
    A's own roots and roots through other callees are kept."""
    from types import SimpleNamespace

    from tdo_v2.engine import RootSlice
    from tdo_v2.normalize import NormalizationFailureReason
    from tdo_v2.query_contracts import LocalCompleteness
    from tdo_v2.summary_engine import _dependents_incomplete

    complete = LocalCompleteness(True, 0, 0)

    def root(offset, occurrence):
        return RootSlice(1, offset, "sink", occurrence, (5,), (), (), {}, complete, complete)

    # A: 1 call site, no tails -> projected occurrences start at 1
    by_key = {"1:a": SimpleNamespace(seeds=SimpleNamespace(callsites=[0]), tails=())}
    results = {
        "1:a": SimpleNamespace(calls={"c1": "1:b", "c2": "1:c"}, projected_sinks=[
            ("c1", 0, "sink", (5,), True), ("c2", 0, "sink", (5,), True)]),
        "1:b": SimpleNamespace(calls={}, projected_sinks=[]),
        "1:c": SimpleNamespace(calls={}, projected_sinks=[]),
    }
    found = _dependents_incomplete([root(0xa, 0), root(0xa, 1), root(0xa, 2)],
                                   {"1:b": NormalizationFailureReason.ANALYSIS_BUDGET}, results, by_key)
    assert [item.is_locally_complete for item in found] == [True, False, True]
    assert not found[1].is_effectively_complete and found[1].explanation["rests_on_failed"] == ["1:b"]


def test_only_late_failures_take_dependents_with_them():
    """A callee that failed in the analysis was opaque to its callers already:
    a projected root through a function merely reaching it stays as it is
    (agy K1a round 2, P2-3) -- ``failed`` holds the late failures only."""
    from types import SimpleNamespace

    from tdo_v2.engine import RootSlice
    from tdo_v2.query_contracts import LocalCompleteness
    from tdo_v2.summary_engine import _dependents_incomplete

    complete = LocalCompleteness(True, 0, 0)
    by_key = {"1:a": SimpleNamespace(seeds=SimpleNamespace(callsites=[0]), tails=())}
    results = {"1:a": SimpleNamespace(calls={"c1": "1:b"}, projected_sinks=[("c1", 0, "sink", (5,), True)]),
               "1:b": SimpleNamespace(calls={"c9": "1:c"}, projected_sinks=[]),
               "1:c": SimpleNamespace(calls={}, projected_sinks=[])}
    (kept,) = _dependents_incomplete([RootSlice(1, 0xa, "sink", 1, (5,), (), (), {}, complete, complete)],
                                     set(), results, by_key)
    assert kept.is_locally_complete
    (marked,) = _dependents_incomplete([kept], {"1:c"}, results, by_key)
    assert not marked.is_locally_complete and marked.explanation["rests_on_failed"] == ["1:c"]


# -- the legacy engine (K1b: run-level, typed) ------------------------------------

def _legacy(generation):
    sys.path.insert(0, str(REPO / "tools" / "bundle_export"))
    import run_dfbench
    from tdo_v2 import engine

    return engine.analyze_frozen_bundle(
        generation, naming_exporter_source=REPO / "ghidra" / "GhidraV2CallNaming.java",
        boundary_provider=run_dfbench.boundary_provider(False, run_dfbench.abi_of(generation)),
        include_explanations=False)


@pytest.mark.skipif(_generation() is None, reason="v2-win-release Bundle not exported here")
def test_the_legacy_engine_fails_the_run_with_the_typed_reason(monkeypatch):
    from tdo_v2.engine import UnresolvedBundleFunctionError

    generation = _generation()
    first = _legacy(generation).roots[0].function_byte_offset
    _failing(monkeypatch, first, AnalysisBudgetExceeded("work", "test"))
    with pytest.raises(UnresolvedBundleFunctionError) as caught:
        _legacy(generation)
    assert caught.value.reason is NormalizationFailureReason.ANALYSIS_BUDGET
    assert caught.value.entry.byte_offset == first


@pytest.mark.skipif(_generation() is None, reason="v2-win-release Bundle not exported here")
def test_a_legacy_whole_program_resource_failure_returns_no_roots(monkeypatch):
    from tdo_v2 import engine

    def fails(*args, **kwargs):
        raise RecursionError("whole program")

    monkeypatch.setattr(engine, "complete_configured_interprocedural_slices", fails)
    with pytest.raises(RecursionError, match="whole program"):
        _legacy(_generation())



# -- typed refusals fail one function (K1c item 7) --------------------------------

@pytest.mark.skipif(_generation() is None, reason="v2-win-release Bundle not exported here")
def test_an_unsupported_function_fails_alone_with_its_reason(monkeypatch):
    """A typed normalization refusal no longer aborts the run: listed, its sink
    occurrences failure roots, the rest analysed."""
    sys.path.insert(0, str(REPO / "tools" / "bundle_export"))
    import run_dfbench
    from tdo_v2 import summary_engine
    from tdo_v2.normalize import UnresolvedNormalizedFunction

    generation = _generation()

    def run():
        return summary_engine.analyze_frozen_bundle_with_summaries(
            generation, naming_exporter_source=REPO / "ghidra" / "GhidraV2CallNaming.java",
            boundary_provider=run_dfbench.boundary_provider(False, run_dfbench.abi_of(generation)),
            pcodeop_models=run_dfbench.pcodeop_models())

    before = run()
    target = before.roots[0].function_byte_offset
    original = FunctionNormalizer.normalize

    def normalize(self, unit, *args, **kwargs):
        if unit.scopes.function.entry.byte_offset == target:
            return UnresolvedNormalizedFunction(unit.scopes,
                                                NormalizationFailureReason.UNSUPPORTED_INTRA_INSTRUCTION_FLOW)
        return original(self, unit, *args, **kwargs)

    monkeypatch.setattr(FunctionNormalizer, "normalize", normalize)
    after = run()
    assert [(key.endswith(f":{target:x}"), reason, detail) for key, reason, detail in after.failed_functions] ==         [(True, "unsupported_intra_instruction_flow", "")]
    failed = [root for root in after.roots if root.function_byte_offset == target]
    assert failed and all(root.explanation == {"failure": "unsupported_intra_instruction_flow"}
                          and not root.is_locally_complete for root in failed)
    assert any(root.function_byte_offset != target for root in after.roots)


def test_a_stack_switch_check_without_the_entry_is_unchecked():
    from tdo_v2.may_alias import _coefficient_switches

    (unit,) = program_units(_wide_chain(1, 3))
    observation = unit.observation
    assert _coefficient_switches(observation, 1, 0x20, 8, "not-the-entry") == ("unchecked",)



def test_the_public_stack_check_without_the_entry_is_unchecked():
    """Before any fast path: an empty observation, or one missing the entry,
    with or without registers (Astra K1b/K1c-1 implementation round 1, P1-1)."""
    from types import SimpleNamespace

    from tdo_v2.may_alias import stack_switches

    (unit,) = program_units(_wide_chain(1, 3))
    stub = SimpleNamespace(entry_block_key="not-the-entry")
    assert stack_switches(stub, unit.observation, None, None) == ("unchecked",)
    assert stack_switches(stub, SimpleNamespace(instructions=()), None, None) == ("unchecked",)


def test_a_template_over_a_refused_callee_is_refused(monkeypatch):
    """A calls B, B is refused (an unsupported shape): A's export is a semantic
    refusal, never a template with B's call left opaque."""
    from tdo_v2.normalize import UnresolvedNormalizedFunction
    from tdo_v2.summary_templates import TemplateRefused, export_summary

    original = FunctionNormalizer.normalize

    def normalize(self, unit, *args, **kwargs):
        if unit.scopes.function.entry.byte_offset == 0x1800:
            return UnresolvedNormalizedFunction(unit.scopes,
                                                NormalizationFailureReason.UNSUPPORTED_INTRA_INSTRUCTION_FLOW)
        return original(self, unit, *args, **kwargs)

    monkeypatch.setattr(FunctionNormalizer, "normalize", normalize)
    caller = FunctionBuilder().sub_rsp(0x28).call(0x1800).add_rsp(0x28).ret()
    results = analyze_units(program_units(caller, _wide_chain(1, 3, 0x1800)))
    assert results["1:1000"].summary is not None
    with pytest.raises(TemplateRefused, match="unsupported_intra_instruction_flow") as caught:
        export_summary(results["1:1000"], results, set())
    assert caught.value.kind == "semantic"
