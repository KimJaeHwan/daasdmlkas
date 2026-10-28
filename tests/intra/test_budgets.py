"""Budgets (docs 25.30 K1c-2..4): the cumulative per-function and run ledgers,
exact work charging, structural limits, run exhaustion as finalization (only
verified results published, then a bounded reporting phase), and Ctrl-C as
cancellation."""

import sys
import threading
from pathlib import Path

import pytest

from synthetic import RAX, FunctionBuilder, add, const, program_units, reg
from tdo_v2 import interprocedural, resource_limits
from tdo_v2.interprocedural import analyze_units
from tdo_v2.normalize import FunctionNormalizer, NormalizationFailureReason, NormalizedFunction
from tdo_v2.resource_limits import (
    AnalysisBudgetExceeded, AnalysisReportingFailed, activation, charge, checkpoint, current_run, limit,
    reporting, run_analysis, run_exhausted, step, worker_supported,
)

REPO = Path(__file__).resolve().parents[2]
needs_worker = pytest.mark.skipif(not worker_supported(), reason="worker qualified on Linux CPython >= 3.14")
LIMIT_VARIABLES = ("TDO_V2_FUNCTION_WORK", "TDO_V2_FUNCTION_SECONDS", "TDO_V2_RUN_WORK", "TDO_V2_RUN_SECONDS",
                   "TDO_V2_RUN_RSS_MB", "TDO_V2_REPORTING_SECONDS",
                   *(f"TDO_V2_LIMIT_{name.upper()}" for name in resource_limits.STRUCTURES))


@pytest.fixture(autouse=True)
def _no_limits(monkeypatch):
    for name in LIMIT_VARIABLES:
        monkeypatch.delenv(name, raising=False)


def _chain(count, entry=0x1000):
    builder = FunctionBuilder(entry=entry)
    for _ in range(count):
        builder.ins(add(reg(RAX), reg(RAX), const(1)))
    return builder.ret()


def _caller(target, entry=0x1000):
    return FunctionBuilder(entry=entry).sub_rsp(0x28).call(target).add_rsp(0x28).ret()


# -- the ledger ---------------------------------------------------------------------

def test_steps_outside_a_run_cost_nothing():
    for _ in range(3 * resource_limits.QUANTUM):
        step()
    checkpoint()
    assert current_run() is None and not run_exhausted()


def _steps_until_exceeded(monkeypatch, plan, **limits):
    """Run ``plan`` (a list of (key, steps)) as activations; the step at which
    a budget ran out: (activation index, step index, exception)."""
    for name, value in limits.items():
        monkeypatch.setenv(name, str(value))
    found = []

    def body():
        try:
            for index, (key, count) in enumerate(plan):
                with activation(key):
                    for position in range(count):
                        found[:] = [(index, position, None)]
                        step()
        except AnalysisBudgetExceeded as error:
            found[0] = (*found[0][:2], error)

    run_analysis(body)
    return found[0]


def test_a_function_work_limit_trips_at_the_exact_unit(monkeypatch):
    index, position, error = _steps_until_exceeded(monkeypatch, [("a", 100)], TDO_V2_FUNCTION_WORK=10)
    # (the activation itself is one unit: 1 + 10 steps is the 11th unit)
    assert (index, position) == (0, 9) and error.scope == "function" and error.kind == "work"


def test_a_function_ledger_is_cumulative_across_activations(monkeypatch):
    index, position, error = _steps_until_exceeded(monkeypatch, [("a", 6), ("b", 3), ("a", 100)],
                                                   TDO_V2_FUNCTION_WORK=10)
    # a: 1 + 6, again 1 + 3 more -> the 11th unit
    assert (index, position) == (2, 2) and error.scope == "function"


def test_a_nested_activation_pauses_the_outer_ledger(monkeypatch):
    monkeypatch.setenv("TDO_V2_FUNCTION_WORK", "12")

    def body():
        with activation("outer"):
            for _ in range(5):
                step()
            with activation("inner"):
                for _ in range(8):
                    step()
            for _ in range(5):
                step()
        ledgers = current_run().ledgers
        return ledgers["outer"].work, ledgers["inner"].work

    assert run_analysis(body) == (11, 9)   # 1 + 5 + 5 and 1 + 8: the inner units are its own


def test_run_exhaustion_is_latched(monkeypatch):
    monkeypatch.setenv("TDO_V2_RUN_WORK", "20")
    seen = []

    def body():
        try:
            with activation("a"):
                for _ in range(100):
                    step()
        except AnalysisBudgetExceeded as error:
            seen.append((error.scope, error.kind, run_exhausted()))
        try:
            with activation("b"):   # a later function fails at its first check
                pass
        except AnalysisBudgetExceeded as error:
            seen.append((error.scope, error.kind))

    run_analysis(body)
    assert seen == [("run", "work", True), ("run", "work")]


def test_a_preallocation_charge_is_rejected_before_allocating(monkeypatch):
    monkeypatch.setenv("TDO_V2_FUNCTION_WORK", "1000")

    def body():
        with activation("a"):
            charge(5000)
            return "allocated"

    with pytest.raises(AnalysisBudgetExceeded):
        run_analysis(body)


def test_a_structural_limit_fails_the_function(monkeypatch):
    monkeypatch.setenv("TDO_V2_LIMIT_GRAPH_NODES", "5")
    result = analyze_units(program_units(_chain(20)))["1:1000"]
    assert result.normalized.reason is NormalizationFailureReason.ANALYSIS_BUDGET
    assert result.failure_detail == "function:structure"


def test_a_function_work_budget_in_the_engine(monkeypatch):
    monkeypatch.setenv("TDO_V2_FUNCTION_WORK", "50")
    results = analyze_units(program_units(_caller(0x1800), _chain(400, 0x1800)))
    assert results["1:1800"].normalized.reason is NormalizationFailureReason.ANALYSIS_BUDGET
    assert results["1:1800"].failure_detail == "function:work"


def test_limits_off_change_nothing():
    assert analyze_units(program_units(_chain(50)))["1:1000"].summary is not None


@pytest.mark.parametrize("value", ["0", "-3", "x"])
def test_a_malformed_limit_is_an_error(monkeypatch, value):
    monkeypatch.setenv("TDO_V2_RUN_WORK", value)
    with pytest.raises(ValueError, match="TDO_V2_RUN_WORK"):
        run_analysis(int)


# -- finalization -------------------------------------------------------------------

def _exhaust_in(monkeypatch, entry):
    """The run's work budget runs out while normalizing the function at ``entry``."""
    monkeypatch.setenv("TDO_V2_RUN_WORK", str(10 ** 12))
    original = FunctionNormalizer.normalize

    def normalize(self, unit, *args, **kwargs):
        if unit.scopes.function.entry.byte_offset == entry:
            charge(10 ** 13)
        return original(self, unit, *args, **kwargs)

    monkeypatch.setattr(FunctionNormalizer, "normalize", normalize)


def test_completed_callees_are_published_and_the_rest_is_run_budget(monkeypatch):
    _exhaust_in(monkeypatch, 0x1000)
    results = analyze_units(program_units(_caller(0x1800), _chain(3, 0x1800)))
    assert type(results["1:1800"].normalized) is NormalizedFunction      # finished before
    assert results["1:1000"].normalized.reason is NormalizationFailureReason.ANALYSIS_RUN_BUDGET
    assert results["1:1000"].failure_detail == "run:work"


def test_an_interrupted_recursive_component_publishes_none_of_its_members(monkeypatch):
    """A <-> B; A is analysed first (its result rests on B's optimistic
    hypothesis), B exhausts the run: neither is published; C (calling A) after."""
    _exhaust_in(monkeypatch, 0x1800)
    a = _caller(0x1800, 0x1000)
    b = _caller(0x1000, 0x1800)
    c = _caller(0x1000, 0x1c00)
    results = analyze_units(program_units(a, b, c))
    assert {key: item.normalized.reason for key, item in results.items()
            if type(item.normalized) is not NormalizedFunction} == {
        "1:1000": NormalizationFailureReason.ANALYSIS_RUN_BUDGET,
        "1:1800": NormalizationFailureReason.ANALYSIS_RUN_BUDGET,
        "1:1c00": NormalizationFailureReason.ANALYSIS_RUN_BUDGET,
    }


def test_exhaustion_in_the_indirect_target_check_publishes_round_one(monkeypatch):
    monkeypatch.setenv("TDO_V2_RUN_WORK", str(10 ** 12))

    def exhausts(item, functions):
        charge(10 ** 13)

    monkeypatch.setattr(interprocedural, "_indirect_targets", exhausts)
    results = analyze_units(program_units(_caller(0x1800), _chain(3, 0x1800)))
    assert all(type(item.normalized) is NormalizedFunction for item in results.values())


def test_an_already_exhausted_run_analyses_nothing(monkeypatch):
    monkeypatch.setenv("TDO_V2_RUN_WORK", "1")

    def body():
        with pytest.raises(AnalysisBudgetExceeded):
            charge(10)   # exhausted before analyze_units (e.g. by a linker derivation)
        return analyze_units(program_units(_chain(3)))

    results = run_analysis(body)
    assert results["1:1000"].normalized.reason is NormalizationFailureReason.ANALYSIS_RUN_BUDGET


def test_the_reporting_phase_is_bounded(monkeypatch):
    monkeypatch.setenv("TDO_V2_REPORTING_SECONDS", "0.000001")

    def body():
        with reporting():
            import time

            time.sleep(0.01)
            checkpoint()

    with pytest.raises(AnalysisReportingFailed):
        run_analysis(body)


def test_no_analysis_entry_while_reporting():
    def body():
        with reporting():
            analyze_units(program_units(_chain(3)))

    with pytest.raises(AnalysisReportingFailed):
        run_analysis(body)


# -- cancellation -------------------------------------------------------------------

@needs_worker
def test_ctrl_c_cancels_a_running_analysis():
    import signal

    def body():
        signal.raise_signal(signal.SIGINT)
        for _ in range(10 ** 9):   # stops at a check, long before this ends
            step()
        return "finished"

    with pytest.raises(KeyboardInterrupt):
        run_analysis(body)
    assert not resource_limits._CANCEL.is_set()


# -- the summary engine on a real Bundle ---------------------------------------------

def _generation():
    root = Path("/root/tdo_bundles/v2-win-release")
    found = sorted(path for path in root.glob("*/") if path.is_dir()) if root.is_dir() else []
    return found[0] if found else None


@pytest.mark.skipif(_generation() is None, reason="v2-win-release Bundle not exported here")
def test_a_run_budget_in_the_summary_engine_reports_every_unfinished_function(monkeypatch):
    sys.path.insert(0, str(REPO / "tools" / "bundle_export"))
    import run_dfbench
    from tdo_v2 import summary_engine

    generation = _generation()
    runs = []
    original = summary_engine.analyze_units

    def capture(*args, **kwargs):
        runs.append(current_run())
        return original(*args, **kwargs)

    def run():
        return summary_engine.analyze_frozen_bundle_with_summaries(
            generation, naming_exporter_source=REPO / "ghidra" / "GhidraV2CallNaming.java",
            boundary_provider=run_dfbench.boundary_provider(False, run_dfbench.abi_of(generation)),
            pcodeop_models=run_dfbench.pcodeop_models())

    monkeypatch.setattr(summary_engine, "analyze_units", capture)
    full = run()
    total = runs[0].work
    assert full.failed_functions == () and total > 0
    monkeypatch.setenv("TDO_V2_RUN_WORK", str(total // 2))
    half = run()
    reasons = {reason for _, reason, _ in half.failed_functions}
    assert reasons == {"analysis_run_budget"}
    assert all(detail == "run:work" for _, _, detail in half.failed_functions)
    failed = {int(key.split(":")[1], 16) for key, _, _ in half.failed_functions}
    by_root = {(root.function_byte_offset, root.label, root.occurrence_ordinal): root for root in full.roots}
    for root in half.roots:
        if root.function_byte_offset in failed:
            assert root.explanation["failure"] == "analysis_run_budget" and not root.is_locally_complete
            continue
        same = by_root[(root.function_byte_offset, root.label, root.occurrence_ordinal)]
        # a published root is the full run's, or marked incomplete
        assert root.reached_origin_labels == same.reached_origin_labels or not root.is_effectively_complete



# -- implementation review round 1 (Astra) ------------------------------------------

def test_function_failures_survive_the_round_one_fallback(monkeypatch):
    """A's indirect check fails (sticky) in round 1; B exhausts the run in round
    2: round 1 is published, A still reported failed (Astra K1c impl. P1-1)."""
    monkeypatch.setenv("TDO_V2_RUN_WORK", str(10 ** 12))
    checks = []

    def targets(item, functions):
        checks.append(item.key)
        if item.key == "1:1000":
            raise RecursionError("indirect")
        return {}

    monkeypatch.setattr(interprocedural, "_indirect_targets", targets)
    original = FunctionNormalizer.normalize
    seen = []

    def normalize(self, unit, *args, **kwargs):
        if unit.scopes.function.entry.byte_offset == 0x1800:
            seen.append(1)
            if len(seen) == 2:
                charge(10 ** 13)   # round 2
        return original(self, unit, *args, **kwargs)

    monkeypatch.setattr(FunctionNormalizer, "normalize", normalize)
    results = analyze_units(program_units(_chain(3), _chain(3, 0x1800)))
    assert results["1:1000"].normalized.reason is NormalizationFailureReason.ANALYSIS_DEPTH
    assert results["1:1000"].failure_detail == "function:depth"
    assert type(results["1:1800"].normalized) is NormalizedFunction


def test_the_indirect_check_is_charged_to_its_function(monkeypatch):
    monkeypatch.setenv("TDO_V2_FUNCTION_WORK", str(10 ** 6))

    def targets(item, functions):
        charge(10 ** 7)
        return {}

    monkeypatch.setattr(interprocedural, "_indirect_targets", targets)
    result = analyze_units(program_units(_chain(3)))["1:1000"]
    assert result.normalized.reason is NormalizationFailureReason.ANALYSIS_BUDGET
    assert result.failure_detail == "function:work"


def test_a_time_limit_is_checked_before_a_result_is_published(monkeypatch):
    import time

    monkeypatch.setenv("TDO_V2_FUNCTION_SECONDS", "0.001")
    original = FunctionNormalizer.normalize

    def slow(self, unit, *args, **kwargs):
        time.sleep(0.05)   # (fewer units than one quantum)
        return original(self, unit, *args, **kwargs)

    monkeypatch.setattr(FunctionNormalizer, "normalize", slow)
    result = analyze_units(program_units(_chain(3)))["1:1000"]
    assert result.normalized.reason is NormalizationFailureReason.ANALYSIS_BUDGET
    assert result.failure_detail == "function:time"


def test_the_last_pending_units_reach_the_run_ledger():
    runs = []

    def body():
        runs.append(current_run())
        for _ in range(17):
            step()

    run_analysis(body)
    assert runs[0].work == 17


@pytest.mark.skipif(_generation() is None, reason="v2-win-release Bundle not exported here")
def test_a_report_is_never_returned_after_its_deadline(monkeypatch):
    import time

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

    target = run().roots[0].function_byte_offset
    original = FunctionNormalizer.normalize

    def normalize(self, unit, *args, **kwargs):
        if unit.scopes.function.entry.byte_offset == target:
            return UnresolvedNormalizedFunction(unit.scopes,
                                                NormalizationFailureReason.UNSUPPORTED_INTRA_INSTRUCTION_FLOW)
        return original(self, unit, *args, **kwargs)

    slow_roots = summary_engine._failure_roots

    def slow(*args, **kwargs):
        time.sleep(0.05)
        return slow_roots(*args, **kwargs)

    monkeypatch.setattr(FunctionNormalizer, "normalize", normalize)
    monkeypatch.setattr(summary_engine, "_failure_roots", slow)
    monkeypatch.setenv("TDO_V2_REPORTING_SECONDS", "0.001")
    with pytest.raises(AnalysisReportingFailed):
        run()



def test_a_refused_function_takes_no_indirect_check(monkeypatch):
    """A refused function is not checked for indirect targets (no activation,
    no spurious budget failure replacing its reason: Astra K1c impl. round 2)."""
    from tdo_v2.normalize import UnresolvedNormalizedFunction

    checked = []
    monkeypatch.setattr(interprocedural, "_indirect_targets",
                        lambda item, functions: checked.append(item.key) or {})
    original = FunctionNormalizer.normalize

    def normalize(self, unit, *args, **kwargs):
        if unit.scopes.function.entry.byte_offset == 0x1000:
            return UnresolvedNormalizedFunction(unit.scopes,
                                                NormalizationFailureReason.UNSUPPORTED_INTRA_INSTRUCTION_FLOW)
        return original(self, unit, *args, **kwargs)

    monkeypatch.setattr(FunctionNormalizer, "normalize", normalize)
    result = analyze_units(program_units(_chain(3)))["1:1000"]
    assert result.normalized.reason is NormalizationFailureReason.UNSUPPORTED_INTRA_INSTRUCTION_FLOW
    assert result.failure_detail == "" and "1:1000" not in checked


def test_a_superseded_round_one_result_keeps_its_assumptions(monkeypatch):
    """The failure published over a round-1 result keeps that result
    (``superseded``): its callers used its summary, so its assumptions stay the
    run's (agy K1c impl. round 2, P1-1)."""
    from tdo_v2.summary_engine import run_assumptions

    monkeypatch.setenv("TDO_V2_RUN_WORK", str(10 ** 12))

    def targets(item, functions):
        if item.key == "1:1000":
            raise RecursionError("indirect")
        return {}

    monkeypatch.setattr(interprocedural, "_indirect_targets", targets)
    original = FunctionNormalizer.normalize
    seen = []

    def normalize(self, unit, *args, **kwargs):
        if unit.scopes.function.entry.byte_offset == 0x1800:
            seen.append(1)
            if len(seen) == 2:
                charge(10 ** 13)
        return original(self, unit, *args, **kwargs)

    monkeypatch.setattr(FunctionNormalizer, "normalize", normalize)
    results = analyze_units(program_units(_chain(3), _chain(3, 0x1800)))
    replaced = results["1:1000"].superseded
    assert type(replaced.normalized) is NormalizedFunction
    assert set(run_assumptions({"1:1000": replaced})) <= set(run_assumptions(results))


# -- an engine's own bound (docs 25.83 D5') ------------------------------------------

def test_a_bound_trips_at_its_exact_unit_without_a_run():
    from tdo_v2.resource_limits import BoundExceeded, bounded

    counted = []
    with pytest.raises(BoundExceeded) as caught:
        with bounded("demo", 10):
            for position in range(100):
                counted.append(position)
                step()
    assert len(counted) == 11 and caught.value.name == "demo" and caught.value.scope == "function"
    step()   # (closed: the bound is gone)


def test_a_bounds_units_are_the_runs_and_the_functions_too():
    from tdo_v2.resource_limits import bounded, last_run

    found = {}

    def body():
        with activation("a"):
            for _ in range(5):
                step()
            with bounded("demo", 100) as bound:
                for _ in range(7):
                    step()
            found["bound"] = bound.work

    run_analysis(body)
    run = last_run()
    assert found["bound"] == 7 and run.work == 1 + 5 + 7 and run.ledgers["a"].work == 1 + 5 + 7


def test_a_function_limit_inside_a_bound_is_the_functions(monkeypatch):
    from tdo_v2.resource_limits import BoundExceeded, bounded

    monkeypatch.setenv("TDO_V2_FUNCTION_WORK", "10")
    found = []

    def body():
        with activation("a"):
            try:
                with bounded("demo", 1000):
                    for _ in range(100):
                        step()
            except AnalysisBudgetExceeded as error:
                found.append(error)

    run_analysis(body)
    assert type(found[0]) is AnalysisBudgetExceeded and not isinstance(found[0], BoundExceeded)


def test_diagnostic_units_do_not_count_against_a_bound():
    from tdo_v2.resource_limits import bounded, diagnostic

    found = {}

    def body():
        with bounded("demo", 10) as bound:
            with diagnostic():
                for _ in range(100):
                    step()
            found["bound"] = bound.work

    run_analysis(body)
    assert found["bound"] == 0


def test_bounds_do_not_nest():
    from tdo_v2.resource_limits import bounded

    with bounded("outer", 10):
        with pytest.raises(RuntimeError):
            with bounded("inner", 10):
                pass
    with pytest.raises(ValueError):
        bounded("zero", 0)
