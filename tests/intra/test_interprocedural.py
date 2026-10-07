"""Interprocedural S1a: callee summaries as proven register effects at call sites.

Checked against concrete runs that execute the callees for real
(``program_oracle.check_program``): every def->use read by the caller is a
graph path, values computed inside a call reach their caller-level inputs,
and nothing is silently missed.
"""

import random

import pytest

import test_graph_fidelity as fidelity
from program_oracle import check_program, check_sink_demands
from synthetic import (
    CODE_BASE, R8, R9, RAX, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const,
    copy, load, program_units, reg, slice_from, slice_op, store, tmp,
)
from tdo_v2.interprocedural import analyze_units

LEAF, MIDDLE = CODE_BASE + 0x800, CODE_BASE + 0x600
HAVOC = (REG, RSP, 8)


def _analyze(*functions):
    units = program_units(*functions)
    results = analyze_units(units)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units
               if hasattr(unit.scopes.function, "entry")}
    return results, program


def _check(results, program, key="1:1000", seeds=range(6), pools=None):
    analyzed = results[key]
    pools = pools or (lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000})
    return check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=seeds,
                         register_pools=pools, havoc_calls=HAVOC)


def _entry_registers(function, opcode, index=0):
    return slice_op(function, opcode, index).register_bytes


def test_value_flows_through_a_call_and_preserved_registers_stay_exact():
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    caller = (FunctionBuilder().ins(copy(reg(RDI), reg(RSI))).call(LEAF)
              .ins(copy(reg(RCX), reg(RAX))).ins(copy(reg(R9), reg(RBX))).ret())
    results, program = _analyze(caller, leaf)
    function = results["1:1000"].normalized
    assert set(range(RSI, RSI + 8)) <= _entry_registers(function, "COPY", 2)  # rcx <- rax <- rdi <- rsi
    r9 = _entry_registers(function, "COPY", 3)
    assert set(range(RBX, RBX + 8)) <= r9
    assert not [row for row in function.call_clobber_reads  # registers: no call debt left
                if any(span.object_id.kind.value == "register_file" for span in row.spans)]
    report = _check(results, program)
    assert report.runs and report.through_calls and report.silent == []


def test_selected_argument_only():
    """dfb_returns_third(x, y, z): the result depends on the third argument only."""
    leaf = FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), reg(RDX))).ins(copy(reg(RCX), reg(RDI))).ret()
    caller = FunctionBuilder().call(LEAF).ins(copy(reg(R9), reg(RAX))).ret()
    results, _ = _analyze(caller, leaf)
    sources = _entry_registers(results["1:1000"].normalized, "COPY", 1)
    assert set(range(RDX, RDX + 8)) <= sources and not sources & set(range(RDI, RDI + 8))


def test_opaque_call_inside_the_callee_stays_debt():
    leaf = FunctionBuilder(entry=LEAF).call(CODE_BASE + 0x4000).ret()  # unknown target
    caller = FunctionBuilder().call(LEAF).ins(copy(reg(R9), reg(RAX))).ret()
    results, program = _analyze(caller, leaf)
    assert results["1:1000"].normalized.call_clobber_reads
    assert _check(results, program).silent == []


def test_nested_calls_compose():
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(R8), const(2))).ret()
    middle = FunctionBuilder(entry=MIDDLE).ins(copy(reg(R8), reg(RDI))).call(LEAF).ret()
    caller = FunctionBuilder().ins(copy(reg(RDI), reg(RSI))).call(MIDDLE).ins(copy(reg(R9), reg(RAX))).ret()
    results, program = _analyze(caller, middle, leaf)
    assert set(range(RSI, RSI + 8)) <= _entry_registers(results["1:1000"].normalized, "COPY", 2)
    report = _check(results, program)
    assert report.through_calls and report.silent == []


def _random_body(rng, builder, calls=(), stack_ops=True):
    """``stack_ops``: free push/pop. Callees keep the stack balanced: the call
    shape assumes the callee restores the stack pointer (checking that is the
    S2 stack-pointer summary)."""
    labels = []
    for index in range(rng.randint(2, 10)):
        if index and rng.random() < 0.15:
            labels.append(f"L{index}")
            builder.label(labels[-1])
        kind = rng.random()
        if calls and kind < 0.2:
            builder.call(rng.choice(calls))
        elif kind < 0.55:
            builder.ins(fidelity._random_value_op(rng))
        elif kind < 0.85:
            builder.ins(*fidelity._random_memory_ops(rng))
        elif kind < 0.9:
            builder.ins(*fidelity._cmov(rng))
        elif stack_ops:
            builder.push(rng.choice(fidelity.REGS)) if rng.random() < 0.5 else builder.pop(
                rng.choice(fidelity.REGS))
        else:
            builder.ins(fidelity._random_value_op(rng))
    if labels and rng.random() < 0.4:
        builder.cbranch(rng.choice(labels), reg(rng.choice((fidelity.ZF, fidelity.CF)), 1))
    return builder.ret(realistic=True)


@pytest.mark.parametrize("chunk", range(4))
def test_random_programs_have_no_silent_misses(chunk):
    silent, through, runs = [], 0, 0
    for seed in range(chunk * 40, (chunk + 1) * 40):
        rng = random.Random(90_000 + seed)
        leaf = _random_body(rng, FunctionBuilder(entry=LEAF), stack_ops=False)
        middle = _random_body(rng, FunctionBuilder(entry=MIDDLE), calls=(LEAF,), stack_ops=False)
        caller = _random_body(rng, FunctionBuilder(), calls=(LEAF, MIDDLE))
        try:
            results, program = _analyze(caller, middle, leaf)
        except AssertionError:
            continue
        for key in ("1:1000", f"1:{MIDDLE:x}"):
            if type(results[key].normalized).__name__ != "NormalizedFunction":
                continue
            report = _check(results, program, key=key)
            runs += report.runs
            through += report.through_calls
            silent += [(seed, key, item) for item in report.silent]
    assert runs > 0 and through > 0
    assert silent == [], silent[:3]


# -- S1b: memory through pointers -------------------------------------------------

def _stack_local_call(leaf, after):
    """caller: rdi = rsp (a local), rsi = rdx, call leaf, then ``after`` ops."""
    return (FunctionBuilder().sub_rsp(0x20).ins(add(reg(RDI), reg(RSP), const(0)))
            .ins(copy(reg(RSI), reg(RDX))).call(LEAF).ins(*after).add_rsp(0x20).ret())


def test_outparam_written_by_the_callee():
    """leaf: *(rdi + 8) = rsi; the caller reads its local back: origin is its rdx."""
    from synthetic import load, store, tmp
    leaf = FunctionBuilder(entry=LEAF).ins(add(tmp(0x100), reg(RDI), const(8)), store(tmp(0x100), reg(RSI))).ret()
    caller = _stack_local_call(leaf, [add(tmp(0x100), reg(RSP), const(8)), load(reg(RAX), tmp(0x100))])
    results, program = _analyze(caller, leaf)
    effect = next(iter(results["1:1000"].proven.values()))
    assert effect.memory_runs and effect.preserves_memory
    loaded = slice_op(results["1:1000"].normalized, "LOAD", 4)
    assert set(range(RDX, RDX + 8)) <= loaded.register_bytes and loaded.result.is_complete
    report = _check(results, program)
    assert report.through_calls and report.silent == []


def test_swap_through_two_pointers():
    """dfb_swap(&x, &y): x gets y's old value."""
    from synthetic import load, store
    leaf = (FunctionBuilder(entry=LEAF).ins(load(reg(RAX), reg(RDI))).ins(load(reg(RCX), reg(RSI)))
            .ins(store(reg(RDI), reg(RCX))).ins(store(reg(RSI), reg(RAX))).ret())
    caller = (FunctionBuilder().sub_rsp(0x20)
              .ins(store(reg(RSP), reg(RDX)))                                   # x = rdx
              .ins(add(reg(R8), reg(RSP), const(8)), store(reg(R8), reg(R9)))   # y = r9
              .ins(copy(reg(RDI), reg(RSP))).ins(copy(reg(RSI), reg(R8)))
              .call(LEAF).ins(load(reg(RBX), reg(RSP))).add_rsp(0x20).ret())
    results, program = _analyze(caller, leaf)
    report = _check(results, program, pools=lambda seed: {RSP: 0x7000_0000})
    assert report.through_calls and report.silent == []


def test_callee_frame_and_pointer_loaded_from_memory():
    """A balanced push/pop frame is bound to the caller's stack; a store through
    a pointer the callee loads from memory has no anchor: memory stays debt."""
    from synthetic import load, store, tmp
    leaf = (FunctionBuilder(entry=LEAF).push(RBX).ins(load(tmp(0x110), reg(RDI)), store(tmp(0x110), reg(RSI)))
            .pop(RBX).ret())
    caller = _stack_local_call(leaf, [load(reg(RAX), reg(RSP))])
    results, program = _analyze(caller, leaf)
    effect = next(iter(results["1:1000"].proven.values()))
    assert not effect.preserves_memory
    assert results["1:1000"].normalized.call_clobber_reads
    assert _check(results, program).silent == []


def test_global_written_by_the_callee():
    from synthetic import DATA_BASE, load, store
    leaf = FunctionBuilder(entry=LEAF).ins(store(const(DATA_BASE + 0x20), reg(RDI))).ret()
    caller = (FunctionBuilder().ins(copy(reg(RDI), reg(RSI))).call(LEAF)
              .ins(load(reg(RAX), const(DATA_BASE + 0x20))).ret())
    results, program = _analyze(caller, leaf)
    loaded = slice_op(results["1:1000"].normalized, "LOAD", 2)
    assert set(range(RSI, RSI + 8)) <= loaded.register_bytes
    assert _check(results, program).silent == []


def test_one_object_passed_twice_is_not_trusted():
    """swap(&x, &x): the callee assumed two distinct objects; the caller binds
    both to the same bytes, so those writes stay unresolved (no silent miss)."""
    from synthetic import load, store
    leaf = (FunctionBuilder(entry=LEAF).ins(load(reg(RAX), reg(RDI))).ins(store(reg(RDI), reg(RCX)))
            .ins(store(reg(RSI), reg(RAX))).ret())
    caller = (FunctionBuilder().sub_rsp(0x20).ins(store(reg(RSP), reg(RDX)))
              .ins(copy(reg(RDI), reg(RSP))).ins(copy(reg(RSI), reg(RSP)))
              .call(LEAF).ins(load(reg(RBX), reg(RSP))).add_rsp(0x20).ret())
    results, program = _analyze(caller, leaf)
    report = _check(results, program, pools=lambda seed: {RSP: 0x7000_0000})
    assert report.silent == []
    assert not slice_op(results["1:1000"].normalized, "LOAD", 5).result.is_complete


# -- sink demand projection ---------------------------------------------------

SINK = CODE_BASE + 0xF00    # no function of the program there: an opaque sink call
SINK_USE = 0x300            # unique slot the test sink root reads RCX into


def _sink_roots(key, unit, normalized):
    """Test boundary: every ``copy(tmp(SINK_USE), RCX)`` is a sink root."""
    found = []
    for row in unit.observation.instructions:
        for ordinal, operation in enumerate(row.operations):
            if (operation.opcode == "COPY" and operation.output is not None
                    and operation.output.coordinate.byte_offset == SINK_USE
                    and operation.output.kind.name == "UNIQUE"):
                op_key = f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:COPY"
                found.append(("sink", (normalized.dependencies.node_for_key(f"op:{op_key}"),), True))
    return found


def _sink(builder):
    return builder.ins(copy(tmp(SINK_USE), reg(RCX))).call(SINK)


def _analyze_sinks(*functions):
    units = program_units(*functions)
    results = analyze_units(units, sink_roots=_sink_roots)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    return results, program


def _check_sinks(results, program, key="1:1000", seeds=range(6)):
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    return check_sink_demands(results[key], program, ({(1, SINK)}, ((RCX, 8),)), seeds=seeds,
                              register_pools=pools, havoc_calls=HAVOC)


def test_sink_wrapper_projects_to_the_caller():
    """leaf(x) { sink(x + 1) }; caller: rcx = rsi; leaf(): the caller root reaches RSI."""
    leaf = _sink(FunctionBuilder(entry=LEAF).ins(add(reg(RCX), reg(RCX), const(1)))).ret()
    caller = FunctionBuilder().ins(copy(reg(RCX), reg(RSI))).call(LEAF).ret()
    results, program = _analyze_sinks(caller, leaf)
    ((_, _, label, nodes, complete),) = results["1:1000"].projected_sinks
    assert label == "sink" and nodes and complete
    assert set(range(RSI, RSI + 8)) <= slice_from(results["1:1000"].normalized, nodes[0]).register_bytes
    report = _check_sinks(results, program)
    assert report.through_calls and report.silent == [] and report.covered_by_debt == []


def test_sink_through_a_pointer_and_two_levels():
    """leaf(p) { sink(*p) }; middle(p) { leaf(p) }; caller: *(rsp) = rdx; middle(rsp)."""
    leaf = _sink(FunctionBuilder(entry=LEAF).ins(load(reg(RCX), reg(RCX)))).ret()
    middle = FunctionBuilder(entry=MIDDLE).call(LEAF).ret()
    caller = (FunctionBuilder().sub_rsp(0x20).ins(store(reg(RSP), reg(RDX)))
              .ins(add(reg(RCX), reg(RSP), const(0))).call(MIDDLE).add_rsp(0x20).ret())
    results, program = _analyze_sinks(caller, middle, leaf)
    ((_, _, _, nodes, complete),) = results["1:1000"].projected_sinks
    assert complete
    assert set(range(RDX, RDX + 8)) <= slice_from(results["1:1000"].normalized, nodes[0]).register_bytes
    report = _check_sinks(results, program)
    assert report.through_calls and report.silent == []


def test_sink_in_a_callee_that_never_returns_is_kept():
    leaf = _sink(FunctionBuilder(entry=LEAF)).tail_call(CODE_BASE + 0xF80)
    caller = FunctionBuilder().ins(copy(reg(RCX), reg(RSI))).call(LEAF).ret()
    results, _ = _analyze_sinks(caller, leaf)
    assert [row[2] for row in results["1:1000"].projected_sinks] == ["sink"]


def _random_prefix(rng, builder):
    for _ in range(rng.randint(0, 4)):
        if rng.random() < 0.5:
            builder.ins(fidelity._random_value_op(rng))
        else:
            builder.ins(*fidelity._random_memory_ops(rng))


@pytest.mark.parametrize("chunk", range(4))
def test_random_sink_wrappers_have_no_silent_misses(chunk):
    silent, through, runs = [], 0, 0
    for seed in range(chunk * 40, (chunk + 1) * 40):
        rng = random.Random(70_000 + seed)
        leaf = FunctionBuilder(entry=LEAF)
        _random_prefix(rng, leaf)
        leaf = _random_body(rng, _sink(leaf), stack_ops=False)
        middle = FunctionBuilder(entry=MIDDLE)
        _random_prefix(rng, middle)
        if rng.random() < 0.5:
            _sink(middle)
        middle = _random_body(rng, middle, calls=(LEAF,), stack_ops=False)
        caller = _random_body(rng, FunctionBuilder(), calls=(LEAF, MIDDLE))
        try:
            results, program = _analyze_sinks(caller, middle, leaf)
        except AssertionError:
            continue
        for key in ("1:1000", f"1:{MIDDLE:x}"):
            if type(results[key].normalized).__name__ != "NormalizedFunction":
                continue
            report = _check_sinks(results, program, key=key)
            runs += report.runs
            through += report.through_calls
            silent += [(seed, key, item) for item in report.silent]
    assert runs > 0 and through > 0
    assert silent == [], silent[:3]


# -- S2: the callee's stack pointer (AFFINE) ------------------------------------

def _ret_popping(builder, extra):
    """``ret extra``: RIP = *(RSP); RSP += 8 + extra; RETURN RIP."""
    from synthetic import RIP, _Instruction, op
    builder._rows.append(_Instruction([
        load(reg(RIP), reg(RSP)),
        add(reg(RSP), reg(RSP), const(8 + extra)),
        op("RETURN", [reg(RIP)]),
    ], "return"))
    return builder


def test_callee_restoring_the_stack_pointer_is_proven():
    leaf = FunctionBuilder(entry=LEAF).push(RBX).pop(RBX).ret()
    caller = FunctionBuilder().call(LEAF).ins(copy(reg(R9), reg(RSP))).ret()
    results, _ = _analyze(caller, leaf)
    assert dict(results[f"1:{LEAF:x}"].summary.register_deltas)[(RSP, 8)] == 8
    (effect,) = results["1:1000"].proven.values()
    assert effect.restores_stack
    function = results["1:1000"].normalized
    assert not [row for row in function.call_clobber_reads
                if any(span.start == RSP for span in row.spans)]


def test_callee_popping_its_arguments_is_not_trusted():
    """stdcall-like ``ret 8``: after the call RSP is 8 higher than the call shape
    assumes, so the caller's later stack accesses must carry debt."""
    leaf = _ret_popping(FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), reg(RDI))), 8)
    caller = (FunctionBuilder().sub_rsp(0x20).ins(add(tmp(0x100), reg(RSP), const(8)),
                                                  store(tmp(0x100), reg(RDX)))
              .call(LEAF).ins(add(tmp(0x100), reg(RSP), const(8)), load(reg(R9), tmp(0x100)))
              .add_rsp(0x20).ret())
    results, program = _analyze(caller, leaf)
    assert dict(results[f"1:{LEAF:x}"].summary.register_deltas)[(RSP, 8)] == 16
    (effect,) = results["1:1000"].proven.values()
    assert not effect.restores_stack
    function = results["1:1000"].normalized
    assert [row for row in function.call_clobber_reads if any(span.start == RSP for span in row.spans)]
    from synthetic import operation_node_at
    reload = slice_from(function, operation_node_at(function, 3, 1))  # the LOAD after the call
    assert not reload.is_complete


@pytest.mark.parametrize("chunk", range(4))
def test_random_programs_with_unbalanced_callees(chunk):
    """Callees push/pop freely, so some return with a moved stack pointer: the
    summary must not prove a restore it cannot (S2), and nothing is missed."""
    silent, through, runs, unrestored = [], 0, 0, 0
    for seed in range(chunk * 40, (chunk + 1) * 40):
        rng = random.Random(95_000 + seed)
        leaf = _random_body(rng, FunctionBuilder(entry=LEAF))
        middle = _random_body(rng, FunctionBuilder(entry=MIDDLE), calls=(LEAF,))
        caller = _random_body(rng, FunctionBuilder(), calls=(LEAF, MIDDLE))
        try:
            results, program = _analyze(caller, middle, leaf)
        except AssertionError:
            continue
        for key in ("1:1000", f"1:{MIDDLE:x}"):
            if type(results[key].normalized).__name__ != "NormalizedFunction":
                continue
            unrestored += sum(not effect.restores_stack for effect in results[key].proven.values())
            report = _check(results, program, key=key)
            runs += report.runs
            through += report.through_calls
            silent += [(seed, key, item) for item in report.silent]
    assert runs > 0 and through > 0 and unrestored > 0
    assert silent == [], silent[:3]


# -- S2: tail jumps composed with the target's summary --------------------------

def test_tail_jump_composes_with_the_target():
    """middle: rdi = rsi; jmp leaf; leaf: rax = rdi + 1; ret -- calling middle
    computes rax from the caller's rsi, and the stack pointer is restored."""
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    middle = FunctionBuilder(entry=MIDDLE).ins(copy(reg(RDI), reg(RSI))).tail_call(LEAF)
    caller = FunctionBuilder().call(MIDDLE).ins(copy(reg(R9), reg(RAX))).ret()
    results, program = _analyze(caller, middle, leaf)
    summary = results[f"1:{MIDDLE:x}"].summary
    assert summary.tail_exits == ()
    assert dict(summary.register_deltas)[(RSP, 8)] == 8
    (effect,) = results["1:1000"].proven.values()
    assert effect.restores_stack
    assert set(range(RSI, RSI + 8)) <= _entry_registers(results["1:1000"].normalized, "COPY", 1)
    report = _check(results, program)
    assert report.through_calls and report.silent == []


def test_tail_jump_to_an_unsummarized_target_stays_opaque():
    middle = FunctionBuilder(entry=MIDDLE).ins(copy(reg(RDI), reg(RSI))).tail_call(CODE_BASE + 0xF00)
    caller = FunctionBuilder().call(MIDDLE).ins(copy(reg(R9), reg(RAX))).ret()
    results, _ = _analyze(caller, middle)
    assert results[f"1:{MIDDLE:x}"].summary.tail_exits
    assert not results["1:1000"].proven


@pytest.mark.parametrize("chunk", range(4))
def test_random_programs_with_tail_jumps(chunk):
    silent, through, runs, composed = [], 0, 0, 0
    for seed in range(chunk * 40, (chunk + 1) * 40):
        rng = random.Random(97_000 + seed)
        leaf = _random_body(rng, FunctionBuilder(entry=LEAF), stack_ops=rng.random() < 0.3)
        middle = FunctionBuilder(entry=MIDDLE)
        _random_prefix(rng, middle)
        if rng.random() < 0.3:
            middle.push(RBX).pop(RBX)
        middle.tail_call(LEAF)
        caller = _random_body(rng, FunctionBuilder(), calls=(LEAF, MIDDLE))
        try:
            results, program = _analyze(caller, middle, leaf)
        except AssertionError:
            continue
        if type(results["1:1000"].normalized).__name__ != "NormalizedFunction":
            continue
        composed += sum(1 for key in results[f"1:{MIDDLE:x}"].proven if key.endswith(":BRANCH"))
        report = _check(results, program)
        runs += report.runs
        through += report.through_calls
        silent += [(seed, item) for item in report.silent]
    assert runs > 0 and through > 0 and composed > 0
    assert silent == [], silent[:3]


def test_tail_jump_to_a_callee_popping_its_arguments_is_not_trusted():
    """middle: jmp leaf; leaf: ret 8 -- calling middle moves RSP by 8 more than
    the call shape assumes: the thunk's summary composes the target's c."""
    leaf = _ret_popping(FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), reg(RDI))), 8)
    middle = FunctionBuilder(entry=MIDDLE).tail_call(LEAF)
    caller = FunctionBuilder().call(MIDDLE).ins(copy(reg(R9), reg(RAX))).ret()
    results, _ = _analyze(caller, middle, leaf)
    assert dict(results[f"1:{MIDDLE:x}"].summary.register_deltas)[(RSP, 8)] == 16
    (effect,) = results["1:1000"].proven.values()
    assert not effect.restores_stack


# -- indirect calls with a constant target --------------------------------------

def test_indirect_call_through_a_constant_is_a_direct_call():
    """rdx = &leaf; call rdx (DFB073 shape): the call is summarized."""
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    caller = (FunctionBuilder().ins(copy(reg(RDX), const(LEAF))).ins(copy(reg(RDI), reg(RSI)))
              .call_indirect(RDX).ins(copy(reg(R9), reg(RAX))).ret())
    results, program = _analyze(caller, leaf)
    ((call, effect),) = results["1:1000"].proven.items()
    assert call.endswith(":CALLIND") and effect.callee == f"1:{LEAF:x}"
    assert set(range(RSI, RSI + 8)) <= _entry_registers(results["1:1000"].normalized, "COPY", 3)
    report = _check(results, program)
    assert report.through_calls and report.silent == []


def test_indirect_call_through_an_entry_register_stays_opaque():
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    caller = FunctionBuilder().call_indirect(RDX).ins(copy(reg(R9), reg(RAX))).ret()
    results, _ = _analyze(caller, leaf)
    assert not results["1:1000"].proven


def test_indirect_target_reloaded_after_an_opaque_call_stays_opaque():
    """*(rsp) = &leaf; opaque call (may rewrite the slot); rdx = *(rsp); call rdx."""
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    caller = (FunctionBuilder().sub_rsp(0x20).ins(store(reg(RSP), const(LEAF))).call(CODE_BASE + 0xF00)
              .ins(load(reg(RDX), reg(RSP))).call_indirect(RDX).add_rsp(0x20).ret())
    results, _ = _analyze(caller, leaf)
    assert not any(key.endswith(":CALLIND") for key in results["1:1000"].proven)
