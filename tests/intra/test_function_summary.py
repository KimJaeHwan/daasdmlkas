"""S0: function summaries read off the intra graph (docs/interprocedural_design.md).

The summary must cover every concrete run: dynamic ⊆ static
(``summary_oracle.check_summary``), on targeted shapes and random functions,
and the checker must reject wrong summaries.
"""

import dataclasses
import random

import pytest

import test_graph_fidelity
import test_robustness
from summary_oracle import check_summary
from synthetic import (
    CODE_BASE, RAX, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const, copy,
    load, normalize_with_observation, reg, store,
)
from tdo_v2.function_summary import SummaryKind, summarize_function
from tdo_v2.span_geometry import StorageObjectKind


def _register_run(summary, offset):
    (exit_summary,) = summary.exits
    return next(run for run in exit_summary.runs
                if run.span.object_id.kind is StorageObjectKind.REGISTER_FILE
                and run.span.start <= offset < run.span.end)


def _summary(builder):
    function, observation = normalize_with_observation(builder)
    return summarize_function(function, observation), observation


def test_computed_identity_and_sources():
    summary, _ = _summary(FunctionBuilder().ins(add(reg(RAX), reg(RDI), const(1))).ret())
    rax = _register_run(summary, RAX)
    assert rax.kind is SummaryKind.COMPUTED
    assert {(s.start, s.size) for s in rax.sources if s.object_id.kind is StorageObjectKind.REGISTER_FILE} == {(RDI, 8)}
    assert _register_run(summary, RDI).kind is SummaryKind.IDENTITY  # read, never written


def test_value_crossing_a_call_is_unknown():
    summary, _ = _summary(FunctionBuilder().ins(copy(reg(RAX), reg(RDI))).call(CODE_BASE + 0x800).ret())
    rax = _register_run(summary, RAX)
    assert rax.kind is SummaryKind.UNKNOWN
    assert any(label.startswith("call:") for label in rax.crossed)


def test_store_through_pointer_depends_on_value_and_address():
    summary, _ = _summary(FunctionBuilder().ins(store(reg(RSI), reg(RDX))).ret())
    (exit_summary,) = summary.exits
    written = [run for run in exit_summary.runs if run.writers]
    assert written and all(run.kind is SummaryKind.COMPUTED for run in written)
    registers = {s.start for run in written for s in run.sources
                 if s.object_id.kind is StorageObjectKind.REGISTER_FILE}
    assert {RSI, RDX} <= registers


def test_uncertain_address_write_cannot_erase_an_earlier_write():
    """*(*rsi) = rdx; *rdi = rcx; *(*rsi) = rbx: the second load of *rsi may see
    the aliasing write to *rdi, so the last store may land elsewhere."""
    builder = (
        FunctionBuilder()
        .ins(load(reg(RAX), reg(RSI)), store(reg(RAX), reg(RDX)))
        .ins(store(reg(RDI), reg(RCX)))
        .ins(load(reg(RAX), reg(RSI)), store(reg(RAX), reg(RBX)))
        .ret()
    )
    summary, observation = _summary(builder)
    assert summary.unknown_writers
    pools = lambda seed: {RSI: 0x2000, RDI: (0x2000, 0x3000)[seed % 2], RSP: 0x7000_0000}
    report = check_summary(summary, observation, seeds=range(8), register_pools=pools)
    assert report.runs == 8 and report.violations == []


@pytest.mark.parametrize("chunk", range(4))
def test_dynamic_runs_are_within_the_summary(chunk):
    violations, runs = [], 0
    for seed in range(chunk * 75, (chunk + 1) * 75):
        for generate, base, pools, havoc in (
            (test_graph_fidelity._random_function, 50_000, test_graph_fidelity._inputs_with_bounded_loop, None),
            (test_robustness._random_function, 0, None, (REG, RSP, 8)),
        ):
            try:
                function, observation = normalize_with_observation(generate(random.Random(base + seed)))
            except AssertionError:
                continue
            report = check_summary(summarize_function(function, observation), observation,
                                   seeds=range(6), register_pools=pools, havoc_calls=havoc)
            runs += report.runs
            violations += [(seed, item) for item in report.violations]
    assert runs > 0
    assert violations == [], violations[:3]


def test_checker_rejects_wrong_summaries():
    def claim_identity(summary):
        return dataclasses.replace(summary, exits=tuple(
            dataclasses.replace(item, runs=tuple(
                dataclasses.replace(run, kind=SummaryKind.IDENTITY)
                if run.kind is SummaryKind.COMPUTED else run for run in item.runs))
            for item in summary.exits))

    caught = 0
    for seed in range(40):
        try:
            function, observation = normalize_with_observation(
                test_graph_fidelity._random_function(random.Random(50_000 + seed)))
        except AssertionError:
            continue
        report = check_summary(claim_identity(summarize_function(function, observation)), observation,
                               seeds=range(6), register_pools=test_graph_fidelity._inputs_with_bounded_loop)
        caught += bool(report.violations)
    assert caught > 20


def test_global_write_after_home_space_store_under_the_assumption():
    """*(RSP+8) = RCX (caller home space); *(global) = RDX: without the
    assumption the global write may alias the slot (UNKNOWN at the exit);
    with it the slot is computed from RCX."""
    from synthetic import DATA_BASE, program_units, tmp
    from tdo_v2.normalize import FunctionNormalizer

    T = tmp(0x100)
    builder = (FunctionBuilder()
               .ins(add(T, reg(RSP), const(8)), store(T, reg(RCX)))
               .ins(store(const(DATA_BASE + 0x10), reg(RDX)))
               .ret())
    kinds = {}
    for assume in (False, True):
        (unit,) = program_units(builder)
        function = FunctionNormalizer().normalize(unit, assume_globals_disjoint_from_stack=assume)
        summary = summarize_function(function, unit.observation)
        (exit_summary,) = summary.exits
        (slot,) = [run for run in exit_summary.runs
                   if run.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE and run.writers
                   and run.span.size == 8]
        kinds[assume] = slot.kind
    assert kinds == {False: SummaryKind.UNKNOWN, True: SummaryKind.COMPUTED}
