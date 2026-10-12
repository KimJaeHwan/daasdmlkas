"""Alias conditions a function cannot decide pass to its callers (BUG-5,
run pairs only): helper(rcx, rdx): *rcx = rbx; *rdx = rsi; r9 = *rcx --
r9 = rbx only if [rcx] and [rdx] do not overlap. wrapper(rcx, rdx) calls
helper and returns r9 in rax: the pair is open there (two entry pointers),
so the wrapper's summary carries it and the root decides it."""

import pytest

import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    CODE_BASE, R9, RAX, RBX, RCX, RDX, REG, RSI, RSP, FunctionBuilder, add, const, copy, load,
    operation_node_at, program_units, reg, slice_from, store,
)
from tdo_v2.interprocedural import analyze_units

HELPER, WRAPPER = CODE_BASE + 0x800, CODE_BASE + 0xA00


def _program(same):
    helper = (FunctionBuilder(entry=HELPER)
              .ins(store(reg(RCX), reg(RBX)))
              .ins(store(reg(RDX), reg(RSI)))
              .ins(load(reg(R9), reg(RCX)))
              .ret())
    wrapper = (FunctionBuilder(entry=WRAPPER).sub_rsp(0x28)
               .call(HELPER)
               .ins(copy(reg(RAX), reg(R9)))
               .add_rsp(0x28).ret())
    caller = (FunctionBuilder().sub_rsp(0x48)
              .ins(add(reg(RCX), reg(RSP), const(0x20)))
              .ins(add(reg(RDX), reg(RSP), const(0x20 if same else 0x30)))
              .call(WRAPPER)
              .ins(copy(reg(R9), reg(RAX)))                                                  # instruction 4
              .add_rsp(0x48).ret())
    return caller, wrapper, helper


def _run(same):
    units = program_units(*_program(same))
    results = analyze_units(units)
    analyzed = results["1:1000"]
    function = analyzed.normalized
    reload = slice_from(function, operation_node_at(function, 4, 0))
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    report = check_program(function, analyzed.unit.observation, program, seeds=range(6), register_pools=pools,
                           havoc_calls=(REG, RSP, 8))
    return reload, report, results


def test_an_open_pair_is_carried_by_the_wrapper():
    _, _, results = _run(same=False)
    wrapper = results[f"1:{WRAPPER:x}"]
    runs = [run for exit_summary in wrapper.summary.exits for run in exit_summary.runs
            if run.span.object_id.kind.value == "register_file" and run.span.start <= RAX < run.span.end]
    assert runs and all(run.conditions for run in runs)
    assert any(graph_label == "open_condition" for graph_label in (
        wrapper.normalized.dependencies.node(node).label for node, _ in wrapper.normalized.open_nodes))


def test_disjoint_arguments_decide_it_at_the_root():
    reload, report, _ = _run(same=False)
    assert reload.is_complete and set(range(RBX, RBX + 8)) <= reload.register_bytes
    assert not set(range(RSI, RSI + 8)) & reload.register_bytes
    assert report.runs and report.silent == []


def test_overlapping_arguments_are_never_sure():
    reload, report, _ = _run(same=True)
    assert set(range(RSI, RSI + 8)) <= reload.register_bytes or not reload.is_complete
    assert report.runs and report.silent == []


def test_the_wrapper_root_itself_is_unsure():
    """At the wrapper (no caller decides there) the value is not sure."""
    _, _, results = _run(same=False)
    wrapper = results[f"1:{WRAPPER:x}"].normalized
    reload = slice_from(wrapper, operation_node_at(wrapper, 2, 0, entry=WRAPPER))
    assert not reload.is_complete


def test_a_store_through_a_conditionally_returned_pointer_is_guarded():
    """getter(rcx, rdx): *rdx = rsi; rax = *rcx -- rax is the slot's entry
    value only if the pair holds. user(rcx, rdx): a = rbx; p = getter(); *p =
    r8; rax = a. Root: rcx = rdx = &slot, rsi = &a (user's frame): p == &a and
    user returns r8 (Astra's design-consult case)."""
    from synthetic import R8

    getter = (FunctionBuilder(entry=HELPER)
              .ins(store(reg(RDX), reg(RSI)))
              .ins(load(reg(RAX), reg(RCX)))
              .ret())
    from synthetic import tmp

    t = tmp(0x100)
    user = (FunctionBuilder(entry=WRAPPER).sub_rsp(0x28)
            .ins(add(t, reg(RSP), const(0x20)), store(t, reg(RBX)))
            .call(HELPER)
            .ins(store(reg(RAX), reg(R8)))
            .ins(add(t, reg(RSP), const(0x20)), load(reg(RAX), t))
            .add_rsp(0x28).ret())
    local = 0x7000_0000 - 0x48 - 8 - 0x28 + 0x20
    caller = (FunctionBuilder().sub_rsp(0x48)
              .ins(add(reg(RCX), reg(RSP), const(0x30)))
              .ins(copy(reg(RDX), reg(RCX)))
              .ins(copy(reg(RSI), const(local)))
              .call(WRAPPER)
              .ins(copy(reg(R9), reg(RAX)))                                                  # instruction 5
              .add_rsp(0x48).ret())
    units = program_units(caller, user, getter)
    analyzed = analyze_units(units)["1:1000"]
    function = analyzed.normalized
    reload = slice_from(function, operation_node_at(function, 5, 0))
    assert set(range(R8, R8 + 8)) <= reload.register_bytes or not reload.is_complete
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    report = check_program(function, analyzed.unit.observation, program, seeds=range(6), register_pools=pools,
                           havoc_calls=(REG, RSP, 8))
    assert report.runs and report.silent == []


def test_a_pair_on_objects_the_wrapper_never_touches_is_decided():
    """helper(p = rcx, q = rdx, value = r8): saved = *q; *q = value; rax = *p;
    *q = saved -- rax = *p only if p, q are disjoint. wrapper only calls it:
    the pair's objects are known to the wrapper only through the condition
    (Astra, review round 1). Root: p = &a (= rbx), q = &b."""
    from synthetic import R8, tmp

    saved = tmp(0x300)
    helper = (FunctionBuilder(entry=HELPER)
              .ins(load(saved, reg(RDX)))
              .ins(store(reg(RDX), reg(R8)))
              .ins(load(reg(RAX), reg(RCX)))
              .ins(store(reg(RDX), saved))
              .ret())
    wrapper = FunctionBuilder(entry=WRAPPER).sub_rsp(0x28).call(HELPER).add_rsp(0x28).ret()
    t = tmp(0x100)
    caller = (FunctionBuilder().sub_rsp(0x48)
              .ins(add(t, reg(RSP), const(0x20)), store(t, reg(RBX)))
              .ins(add(reg(RCX), reg(RSP), const(0x20)))
              .ins(add(reg(RDX), reg(RSP), const(0x30)))
              .call(WRAPPER)
              .ins(copy(reg(R9), reg(RAX)))                                                  # instruction 5
              .add_rsp(0x48).ret())
    units = program_units(caller, wrapper, helper)
    analyzed = analyze_units(units)["1:1000"]
    function = analyzed.normalized
    reload = slice_from(function, operation_node_at(function, 5, 0))
    assert reload.is_complete and set(range(RBX, RBX + 8)) <= reload.register_bytes
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    report = check_program(function, analyzed.unit.observation, program, seeds=range(6), register_pools=pools,
                           havoc_calls=(REG, RSP, 8))
    assert report.runs and report.silent == []
