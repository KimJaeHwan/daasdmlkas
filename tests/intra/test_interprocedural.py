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
    CODE_BASE, DATA_BASE, R8, R9, RAX, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const,
    copy, load, program_units, reg, slice_from, slice_op, store, sub, tmp,
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
    a pointer the callee loads from memory (*(rdi)) is anchored on that slot
    and bound at the call to whatever the caller's slot holds."""
    from synthetic import load, store, tmp
    leaf = (FunctionBuilder(entry=LEAF).push(RBX).ins(load(tmp(0x110), reg(RDI)), store(tmp(0x110), reg(RSI)))
            .pop(RBX).ret())
    caller = _stack_local_call(leaf, [load(reg(RAX), reg(RSP))])
    results, program = _analyze(caller, leaf)
    effect = next(iter(results["1:1000"].proven.values()))
    assert any(run.write.pointer is not None for run in effect.memory_runs)
    assert _check(results, program).silent == []


def test_double_pointer_outparam():
    """DFB023: **pp = value; the caller's p = &local, pp = &p: local = value."""
    from synthetic import load, store, tmp
    t = tmp(0x100)
    leaf = FunctionBuilder(entry=LEAF).ins(load(tmp(0x110), reg(RCX)), store(tmp(0x110), reg(RDX))).ret()
    caller = (FunctionBuilder().sub_rsp(0x40)
              .ins(add(t, reg(RSP), const(0x28)), add(tmp(0x118), reg(RSP), const(0x20)), store(t, tmp(0x118)))
              .ins(add(reg(RCX), reg(RSP), const(0x28))).ins(copy(reg(RDX), reg(RSI)))
              .call(LEAF).ins(add(t, reg(RSP), const(0x20)), load(reg(R9), t)).add_rsp(0x40).ret())
    results, program = _analyze(caller, leaf)
    function = results["1:1000"].normalized
    from synthetic import operation_node_at
    reload = slice_from(function, operation_node_at(function, 5, 1))
    assert set(range(RSI, RSI + 8)) <= reload.register_bytes
    assert _check(results, program).silent == []


def test_one_object_passed_twice_leaves_other_memory_exact():
    """swap(&x, &x) as above, and the caller reads a global it stored before
    the call: the two writes land on x (the place is known, the value left
    there is not -- an opaque-write debt on both rows), so the global read
    stays exact; formerly both writes stayed address-unresolved and dirtied
    every byte of every object (docs 25.73, cleanup 3C)."""
    from synthetic import DATA_BASE, load, store
    leaf = (FunctionBuilder(entry=LEAF).ins(load(reg(RAX), reg(RDI))).ins(store(reg(RDI), reg(RCX)))
            .ins(store(reg(RSI), reg(RAX))).ret())
    caller = (FunctionBuilder().sub_rsp(0x20).ins(store(reg(RSP), reg(RDX)))
              .ins(store(const(DATA_BASE + 0x40), reg(R8)))
              .ins(copy(reg(RDI), reg(RSP))).ins(copy(reg(RSI), reg(RSP)))
              .call(LEAF).ins(load(reg(RBX), reg(RSP))).ins(load(reg(RAX), const(DATA_BASE + 0x40)))
              .add_rsp(0x20).ret())
    # (globals-disjoint-from-stack: the call receives the stack address, so
    # without it the frame writes reach the global by the ordinary may-alias
    # rule; an address-unresolved write reaches it either way)
    units = program_units(caller, leaf)
    results = analyze_units(units, assume_globals_disjoint_from_stack=True)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    report = _check(results, program, pools=lambda seed: {RSP: 0x7000_0000})
    assert report.silent == []
    item = results["1:1000"]
    if not item.activations:
        assert not slice_op(item.normalized, "LOAD", 6).result.is_complete   # x: the unknown value
    found = slice_op(item.normalized, "LOAD", 7)
    assert found.result.is_complete and set(range(R8, R8 + 8)) <= found.register_bytes


def test_one_object_passed_twice_through_a_tail_call_is_not_trusted():
    """The same through a wrapper that tail-calls the writer (``rsi = rdi;
    jmp leaf``): the wrapper's tail-call rows overlap too (Astra, cleanup 3C:
    they were missed, a silent miss)."""
    from synthetic import load, store
    leaf = FunctionBuilder(entry=LEAF).ins(store(reg(RSI), reg(RDX))).ins(store(reg(RDI), reg(RCX))).ret()
    middle = FunctionBuilder(entry=MIDDLE).ins(copy(reg(RSI), reg(RDI))).tail_call(LEAF)
    caller = (FunctionBuilder().sub_rsp(0x20).ins(copy(reg(RDI), reg(RSP)))
              .call(MIDDLE).ins(load(reg(RBX), reg(RSP))).add_rsp(0x20).ret())
    results, program = _analyze(caller, middle, leaf)
    assert _check(results, program, pools=lambda seed: {RSP: 0x7000_0000}).silent == []
    assert _check(results, program, key=f"1:{MIDDLE:x}", pools=lambda seed: {RSP: 0x7000_0000}).silent == []


def test_overlapping_literal_writes_state_no_value():
    """The callee writes two constants through two pointers the caller makes
    equal: which one is left is not known -- the shared bytes are a ``~ov``
    row's (docs 25.82), whose value is no row's literal (a forward address
    through it would be exact and wrong -- Astra, cleanup 3C); the caller's
    read is incomplete and nothing is silent."""
    from synthetic import load, store
    leaf = (FunctionBuilder(entry=LEAF).ins(store(reg(RDI), const(DATA_BASE + 0x100)))
            .ins(store(reg(RSI), const(DATA_BASE + 0x200))).ret())
    caller = (FunctionBuilder().sub_rsp(0x20).ins(copy(reg(RDI), reg(RSP))).ins(copy(reg(RSI), reg(RSP)))
              .call(LEAF).ins(load(reg(RAX), reg(RSP))).ins(load(reg(RBX), reg(RAX))).add_rsp(0x20).ret())
    results, program = _analyze(caller, leaf)
    item = results["1:1000"]
    function = item.normalized
    call = next(key for key in item.proven)
    literals = {row[2] for key, row in function.pointer_rows if key.startswith(call + "~")
                and key != call + "~push" and row[0] == "const"}
    if item.activations:
        # the callee analysed with RDI == RSI: its own order decides -- the
        # last store's value, exactly
        assert literals <= {DATA_BASE + 0x200}
    else:
        assert not slice_op(function, "LOAD", 4).result.is_complete
    assert _check(results, program, pools=lambda seed: {RSP: 0x7000_0000}).silent == []


def test_overlap_found_on_an_earlier_pass_keeps_its_debt():
    """Call A writes &g through two pointers to one slot x; call B gets
    ``rdi = x`` and ``rsi = &g`` and writes through both (``*rsi = rcx;
    *rdi = rdx``). With A's literal B's rows overlap; once A's value is
    dropped they no longer resolve onto each other, but their debt must stay
    (Astra, cleanup 3C round 2: the read of g was complete and missed rdx)."""
    from synthetic import DATA_BASE, RCX, RDX, load, store
    leaf = (FunctionBuilder(entry=LEAF).ins(store(reg(RDI), const(DATA_BASE + 0x40)))
            .ins(store(reg(RSI), const(DATA_BASE + 0x40))).ret())
    middle = FunctionBuilder(entry=MIDDLE).ins(store(reg(RSI), reg(RCX))).ins(store(reg(RDI), reg(RDX))).ret()
    caller = (FunctionBuilder().sub_rsp(0x20).ins(copy(reg(RDI), reg(RSP))).ins(copy(reg(RSI), reg(RSP)))
              .call(LEAF).ins(load(reg(RDI), reg(RSP))).ins(copy(reg(RSI), const(DATA_BASE + 0x40)))
              .call(MIDDLE).ins(load(reg(RAX), const(DATA_BASE + 0x40))).add_rsp(0x20).ret())
    results, program = _analyze(caller, leaf, middle)
    found = slice_op(results["1:1000"].normalized, "LOAD", 7)
    assert not found.result.is_complete or set(range(RDX, RDX + 8)) <= found.register_bytes
    assert _check(results, program, pools=lambda seed: {RSP: 0x7000_0000}).silent == []


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
    loaded = slice_op(results["1:1000"].normalized, "LOAD", 5)
    if results["1:1000"].activations:
        # Context SSA merges the identical pointers and executes both stores
        # in order: the original local value is written back, not RCX.
        assert loaded.result.is_complete and set(range(RDX, RDX + 8)) <= loaded.register_bytes
    else:
        assert not loaded.result.is_complete


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


def test_falling_out_through_an_instruction_without_pcode_is_a_tail_exit():
    """The last instruction has no p-code (release builds: padding after a
    noreturn call): the exit is not a RETURN, so the summary is not trusted."""
    class Padded(FunctionBuilder):
        def to_json(self):
            raw = super().to_json()
            last = raw["instructions"][-1]   # the ret becomes a nop falling out
            last["operations"] = []
            last["flow_type"] = {key: key in ("is_flow", "has_fallthrough", "is_unconditional")
                                 for key in last["flow_type"]}
            last["fallthrough_present"] = True
            last["fallthrough"] = {**last["address"], "byte_offset": last["address"]["byte_offset"] + 4}
            return raw

    middle = Padded(entry=MIDDLE).ins(copy(reg(RDI), reg(RSI))).ret()
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


# -- S3: callee may-alias debt decided at the call site --------------------------

def _home_space_wrapper(field):
    """func1(v) in MSVC debug style: spill RCX to the home space, reload it to
    write v->field = rdx, reload it again and pass it on (DFB055)."""
    t, u = tmp(0x100), tmp(0x108)
    return (FunctionBuilder(entry=MIDDLE)
            .ins(add(t, reg(RSP), const(8)), store(t, reg(RCX)))
            .ins(add(t, reg(RSP), const(8)), load(reg(RAX), t))
            .ins(add(u, reg(RAX), const(field)), store(u, reg(RDX)))
            .ins(add(t, reg(RSP), const(8)), load(reg(RCX), t))
            .call(LEAF).ret())


def _deep_sink_leaf():
    return _sink(FunctionBuilder(entry=LEAF).ins(load(reg(RCX), reg(RCX)))).ret()


def _home_space_caller(displacement):
    """s.aaa = rbx at [rsp + displacement]; func1(&s)."""
    t = tmp(0x100)
    return (FunctionBuilder().sub_rsp(0x40)
            .ins(add(t, reg(RSP), const(displacement & 0xFFFFFFFFFFFFFFFF)), store(t, reg(RBX)))
            .ins(add(reg(RCX), reg(RSP), const(displacement & 0xFFFFFFFFFFFFFFFF)))
            .call(MIDDLE).add_rsp(0x40).ret())


def test_home_space_alias_is_discharged_by_the_caller():
    results, program = _analyze_sinks(_home_space_caller(0x20), _home_space_wrapper(4), _deep_sink_leaf())
    (demand,) = results[f"1:{MIDDLE:x}"].summary.sink_demands
    assert demand.conditions  # the callee alone cannot tell
    ((_, _, _, nodes, complete),) = results["1:1000"].projected_sinks
    assert complete
    assert set(range(RBX, RBX + 8)) <= slice_from(results["1:1000"].normalized, nodes[0]).register_bytes
    report = _check_sinks(results, program)
    assert report.through_calls and report.silent == []


def test_overlapping_home_space_stays_incomplete():
    """v + 12 is the callee's home slot: the reload really is clobbered."""
    results, program = _analyze_sinks(_home_space_caller(-12), _home_space_wrapper(12), _deep_sink_leaf())
    ((_, _, _, _, complete),) = results["1:1000"].projected_sinks
    assert not complete
    report = _check_sinks(results, program)
    assert report.silent == []


@pytest.mark.parametrize("displacement", [-16, -12, -8, -4, 0, 4, 8, 0x20])
@pytest.mark.parametrize("field", [0, 4, 8, 12])
def test_home_space_alias_any_layout(displacement, field):
    results, program = _analyze_sinks(
        _home_space_caller(displacement), _home_space_wrapper(field), _deep_sink_leaf())
    report = _check_sinks(results, program)
    assert report.silent == [], report.silent[:2]


def _field_getter(field):
    """int get(const S *v) { return v->field; } in MSVC debug style (spill/reload)."""
    t, u = tmp(0x100), tmp(0x108)
    return (FunctionBuilder(entry=LEAF)
            .ins(add(t, reg(RSP), const(8)), store(t, reg(RCX)))
            .ins(add(t, reg(RSP), const(8)), load(reg(RAX), t))
            .ins(add(u, reg(RAX), const(field)), load(reg(RAX), u))
            .ret())


def _getter_caller(displacement, field):
    """s.field = rbx at [rsp + displacement + field]; r9 = get(&s)."""
    t = tmp(0x100)
    return (FunctionBuilder().sub_rsp(0x40)
            .ins(add(t, reg(RSP), const((displacement + field) & 0xFFFFFFFFFFFFFFFF)), store(t, reg(RBX)))
            .ins(add(reg(RCX), reg(RSP), const(displacement & 0xFFFFFFFFFFFFFFFF)))
            .call(LEAF).ins(copy(reg(R9), reg(RAX))).add_rsp(0x40).ret())


def test_conditional_return_value_is_proven_in_context():
    """DFB057: the callee's v->field read may alias its home-space spill; the
    caller knows &s is elsewhere, so RAX = s.field (from RBX)."""
    results, program = _analyze(_getter_caller(0x20, 4), _field_getter(4))
    (run,) = [r for r in results[f"1:{LEAF:x}"].summary.exits[0].runs if r.span.start == RAX]
    assert run.conditions and not run.debts
    (effect,) = results["1:1000"].proven.values()
    assert any(r.writes[0].start == RAX for r in effect.runs)
    assert set(range(RBX, RBX + 8)) <= _entry_registers(results["1:1000"].normalized, "COPY", 4)
    report = _check(results, program)
    assert report.through_calls and report.silent == []


@pytest.mark.parametrize("displacement", [-16, -12, -8, -4, 0, 4, 0x20])
@pytest.mark.parametrize("field", [0, 4, 8])
def test_conditional_return_value_any_layout(displacement, field):
    results, program = _analyze(_getter_caller(displacement, field), _field_getter(field))
    report = _check(results, program)
    assert report.silent == [], report.silent[:2]


def _home_space_initializer(first, second):
    """UE DebugGame constructor shape: spill this (RCX) to the home space and
    reload it before each field write: v->first = rdx; v->second = r8. The
    second write's address may see the first write (v + first could be the
    home slot): a writer condition the caller decides."""
    t, u = tmp(0x100), tmp(0x108)
    return (FunctionBuilder(entry=LEAF)
            .ins(add(t, reg(RSP), const(8)), store(t, reg(RCX)))
            .ins(add(t, reg(RSP), const(8)), load(reg(RAX), t))
            .ins(add(u, reg(RAX), const(first)), store(u, reg(RDX)))
            .ins(add(t, reg(RSP), const(8)), load(reg(RAX), t))
            .ins(add(u, reg(RAX), const(second)), store(u, reg(R8)))
            .ret())


def _initializer_caller(displacement, second):
    """kept = rbx at [rsp+0x30]; s.second = rdi; init(&s at rsp + displacement);
    r9 = s.second; rsi = kept (memory the call must be proven to keep). When
    the second write misses s, r9 is still rdi."""
    t = tmp(0x100)
    return (FunctionBuilder().sub_rsp(0x40)
            .ins(add(t, reg(RSP), const(0x30)), store(t, reg(RBX)))
            .ins(add(t, reg(RSP), const((displacement + second) & 0xFFFFFFFFFFFFFFFF)), store(t, reg(RDI)))
            .ins(add(reg(RCX), reg(RSP), const(displacement & 0xFFFFFFFFFFFFFFFF)))
            .call(LEAF)
            .ins(add(t, reg(RSP), const((displacement + second) & 0xFFFFFFFFFFFFFFFF)), load(reg(R9), t))
            .ins(add(t, reg(RSP), const(0x30)), load(reg(RSI), t))
            .add_rsp(0x40).ret())


def test_conditional_writer_keeps_memory_in_context():
    results, program = _analyze(_initializer_caller(0x10, 8), _home_space_initializer(0, 8))
    summary = results[f"1:{LEAF:x}"].summary
    assert summary.writer_conditions and not summary.unknown_writers
    (effect,) = results["1:1000"].proven.values()
    assert effect.preserves_memory and effect.restores_stack
    from synthetic import operation_node_at
    function = results["1:1000"].normalized
    reload = slice_from(function, operation_node_at(function, 5, 1))
    assert reload.is_complete and set(range(R8, R8 + 8)) <= reload.register_bytes
    assert not reload.register_bytes & set(range(RDI, RDI + 8))
    kept = slice_from(function, operation_node_at(function, 6, 1))
    assert kept.is_complete and set(range(RBX, RBX + 8)) <= kept.register_bytes
    report = _check(results, program)
    assert report.through_calls and report.silent == []


def test_failing_writer_condition_proves_nothing():
    """&s + 0 is the callee's home slot (the caller's stack pointer at the
    call): the reloaded pointer is RDX, so the second write lands elsewhere."""
    results, program = _analyze(_initializer_caller(0, 8), _home_space_initializer(0, 8))
    effect = results["1:1000"].proven.get(next(iter(results["1:1000"].calls)))
    if results["1:1000"].activations:
        # The failed generic condition is not reused: context SSA resolves
        # the reload to RDX and exports the actual second store at RDX+8.
        assert effect.preserves_memory
        assert any(run.write.anchor is not None and run.write.anchor.start == RDX
                   and run.write.displacement == 8 and run.write.size == 8 for run in effect.memory_runs)
    else:
        assert effect is None or not effect.preserves_memory
    assert _check(results, program).silent == []


@pytest.mark.parametrize("displacement", [-16, -12, -8, -4, 0, 8, 0x10])
@pytest.mark.parametrize("first, second", [(0, 8), (4, 0), (8, 4), (0, 0), (0, 16)])
def test_conditional_writer_any_layout(displacement, first, second):
    results, program = _analyze(_initializer_caller(displacement, second), _home_space_initializer(first, second))
    report = _check(results, program)
    assert report.silent == [], report.silent[:2]


def _reloading_writer():
    """*rdi = rcx; *(*rsi) = rbx: the pointer is loaded after a write that may
    alias its slot -- a writer condition ([rsi], [rdi]) no other mechanism of
    the caller catches (the two writes land on different caller bytes)."""
    return (FunctionBuilder(entry=LEAF)
            .ins(store(reg(RDI), reg(RCX)))
            .ins(load(reg(RAX), reg(RSI)), store(reg(RAX), reg(RBX)))
            .ret())


def _reloading_caller(same_slot):
    """slot = &s; s = rdx; leaf(rsi = &slot, rdi = &slot or &other); r9 = s."""
    t = tmp(0x100)
    return (FunctionBuilder().sub_rsp(0x40)
            .ins(add(t, reg(RSP), const(0x20)), store(t, reg(RDX)))
            .ins(add(reg(RAX), reg(RSP), const(0x20)), add(t, reg(RSP), const(0x28)), store(t, reg(RAX)))
            .ins(add(reg(RSI), reg(RSP), const(0x28)))
            .ins(add(reg(RDI), reg(RSP), const(0x28 if same_slot else 0x30)))
            .call(LEAF)
            .ins(add(t, reg(RSP), const(0x20)), load(reg(R9), t))
            .add_rsp(0x40).ret())


@pytest.mark.parametrize("same_slot", [False, True])
def test_writer_condition_decided_per_call(same_slot):
    results, program = _analyze(_reloading_caller(same_slot), _reloading_writer())
    assert results[f"1:{LEAF:x}"].summary.writer_conditions
    (effect,) = results["1:1000"].proven.values()
    contextual = bool(results["1:1000"].activations)
    if contextual and same_slot:
        # The first store overwrites the saved pointer with RCX. The second
        # store is therefore explicitly exported at RCX, without assuming
        # the generic nonalias writer condition.
        assert effect.preserves_memory
        assert any(run.write.anchor is not None and run.write.anchor.start == RCX
                   and run.write.displacement == 0 for run in effect.memory_runs)
    else:
        assert effect.preserves_memory is not same_slot
    report = _check(results, program)
    # a failing condition proves nothing through the call (the mutation that
    # trusts conditional writers misses r9's real writer here)
    assert bool(report.through_calls) is not same_slot and report.silent == []


def test_private_frame_writes_do_not_disturb_entry_pointer_objects():
    """leaf spills rdx to its own frame (private: nothing escapes) and reads
    *rcx: its summary keeps *rcx, so the call keeps the caller's local."""
    t = tmp(0x100)
    leaf = (FunctionBuilder(entry=LEAF).sub_rsp(0x28)
            .ins(add(t, reg(RSP), const(0x20)), store(t, reg(RDX)))
            .ins(load(reg(RAX), reg(RCX)))
            .add_rsp(0x28).ret())
    caller = (FunctionBuilder().sub_rsp(0x40)
              .ins(add(t, reg(RSP), const(0x20)), store(t, reg(RBX)))
              .ins(add(reg(RCX), reg(RSP), const(0x20)))
              .call(LEAF)
              .ins(add(t, reg(RSP), const(0x20)), load(reg(R9), t))
              .add_rsp(0x40).ret())
    results, program = _analyze(caller, leaf)
    (effect,) = results["1:1000"].proven.values()
    assert effect.preserves_memory
    from synthetic import operation_node_at
    function = results["1:1000"].normalized
    reload = slice_from(function, operation_node_at(function, 4, 1))
    assert reload.is_complete and set(range(RBX, RBX + 8)) <= reload.register_bytes
    assert _check(results, program).silent == []


def _clobbering_getter(write_field, read_field):
    """spill rcx; v->write_field = rdx; return reload(v)->read_field: if the
    caller's v + write_field is the home slot, the reloaded pointer (and so
    the result) depends on RDX."""
    t, u = tmp(0x100), tmp(0x108)
    return (FunctionBuilder(entry=LEAF)
            .ins(add(t, reg(RSP), const(8)), store(t, reg(RCX)))
            .ins(add(t, reg(RSP), const(8)), load(reg(RAX), t))
            .ins(add(u, reg(RAX), const(write_field)), store(u, reg(RDX)))
            .ins(add(t, reg(RSP), const(8)), load(reg(RAX), t))
            .ins(add(u, reg(RAX), const(read_field)), load(reg(RAX), u))
            .ret())


def _clobber_caller(displacement):
    """*(rdx) = r8 (memory the clobbered pointer will reach), s = rbx at
    [rsp + displacement], r9 = get(&s)."""
    t = tmp(0x100)
    return (FunctionBuilder().sub_rsp(0x40)
            .ins(copy(reg(RDX), const(DATA_BASE + 0x40)), store(const(DATA_BASE + 0x4C), reg(R8)))
            .ins(add(t, reg(RSP), const(displacement & 0xFFFFFFFFFFFFFFFF)), store(t, reg(RBX)))
            .ins(add(reg(RCX), reg(RSP), const(displacement & 0xFFFFFFFFFFFFFFFF)))
            .call(LEAF).ins(copy(reg(R9), reg(RAX))).add_rsp(0x40).ret())


@pytest.mark.parametrize("displacement", [-16, -12, -8, -4, 0, 4, 0x20])
@pytest.mark.parametrize("write_field", [0, 4, 8])
def test_clobbered_pointer_reload_is_never_silent(displacement, write_field):
    """Where v + write_field is the home slot, the result is *(rdx + 12): a
    caller-written global the static value must reach, or stay unsure."""
    units = program_units(_clobber_caller(displacement), _clobbering_getter(write_field, 12))
    results = analyze_units(units, assume_globals_disjoint_from_stack=True)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    report = _check(results, program)
    assert report.silent == [], report.silent[:2]



@pytest.mark.parametrize("chunk", range(2))
def test_random_pointers_passed_in_memory(chunk):
    """caller: local = rbx; slot = &local + d; leaf(&slot); r9 = local.
    leaf: p = *slot; random reads/writes at p + k. Pointer anchors must bind
    the right caller bytes (a wrong displacement shows as a silent miss)."""
    silent, through, runs = [], 0, 0
    t, u = tmp(0x100), tmp(0x118)
    for seed in range(chunk * 30, (chunk + 1) * 30):
        rng = random.Random(41_000 + seed)
        d = rng.choice((0, 4, 8))
        leaf = FunctionBuilder(entry=LEAF).ins(load(tmp(0x110), reg(RCX)))
        for _ in range(rng.randint(1, 3)):
            k = rng.choice((0, 4, 8, 12))
            if rng.random() < 0.6:
                leaf.ins(add(u, tmp(0x110), const(k)), store(u, reg(rng.choice((RDX, R8)), rng.choice((4, 8)))))
            else:
                leaf.ins(add(u, tmp(0x110), const(k)), load(reg(RAX), u))
        leaf = leaf.ret()
        caller = (FunctionBuilder().sub_rsp(0x60)
                  .ins(add(t, reg(RSP), const(0x30)), store(t, reg(RBX)))
                  .ins(add(t, reg(RSP), const(0x38)), store(t, reg(RSI)))
                  .ins(add(t, reg(RSP), const(0x20)), add(u, reg(RSP), const(0x30 + d)), store(t, u))
                  .ins(add(reg(RCX), reg(RSP), const(0x20)))
                  .call(LEAF)
                  .ins(add(t, reg(RSP), const(0x30)), load(reg(R9), t))
                  .ins(add(t, reg(RSP), const(0x38)), load(reg(R10 if False else RDI), t))
                  .add_rsp(0x60).ret())
        results, program = _analyze(caller, leaf)
        report = _check(results, program)
        runs += report.runs
        through += report.through_calls
        silent += [(seed, item) for item in report.silent]
    assert runs and through
    assert silent == [], silent[:3]



# -- S5: recursion through a verified fixpoint ----------------------------------

def _recursive_body(rng, entry, callee):
    """if (r9 == 0) { base } else { r9--; ...; callee(); ... } -- bounded by r9;
    sometimes a callee-saved register is pushed around the recursive call."""
    from synthetic import ZF, op, sub
    builder = FunctionBuilder(entry=entry)
    builder.cbranch("base", reg(ZF, 1), op("INT_EQUAL", [reg(R9), const(0)], reg(ZF, 1)))
    _random_prefix(rng, builder)
    pushed = rng.random() < 0.3
    if pushed:
        builder.push(RBX)
    builder.ins(sub(reg(R9), reg(R9), const(1)))
    builder.call(callee)
    _random_prefix(rng, builder)
    if pushed:
        builder.pop(RBX)
    builder.ret()
    builder.label("base")
    _random_prefix(rng, builder)
    return builder.ret()


@pytest.mark.parametrize("chunk", range(4))
def test_random_recursion_has_no_silent_misses(chunk):
    silent, through, runs, recursive = [], 0, 0, 0
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000, R9: seed % 4}
    for seed in range(chunk * 40, (chunk + 1) * 40):
        rng = random.Random(61_000 + seed)
        mutual = rng.random() < 0.4
        leaf = _recursive_body(rng, LEAF, MIDDLE if mutual else LEAF)
        functions = [leaf]
        if mutual:
            functions.append(_recursive_body(rng, MIDDLE, LEAF))
        caller = _random_body(rng, FunctionBuilder(), calls=(LEAF,))
        try:
            results, program = _analyze(caller, *functions)
        except AssertionError:
            continue
        recursive += sum(1 for key, item in results.items()
                         for call, callee in item.calls.items() if call in item.proven and key != "1:1000")
        for key in ("1:1000", f"1:{LEAF:x}"):
            if type(results[key].normalized).__name__ != "NormalizedFunction":
                continue
            analyzed = results[key]
            report = check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=range(4),
                                   register_pools=pools, havoc_calls=HAVOC)
            runs += report.runs
            through += report.through_calls
            silent += [(seed, key, item) for item in report.silent]
    assert runs and through and recursive
    assert silent == [], silent[:3]


def test_stack_below_the_call_is_clobbered_and_the_rest_kept():
    """leaf pushes rdx (its own frame: the caller's stack below its call-time
    pointer). The caller's slot below its stack pointer is clobbered; its
    slot above stays exact (the leaf keeps every other byte)."""
    t = tmp(0x100)
    leaf = FunctionBuilder(entry=LEAF).push(RDX).pop(RCX).ret()
    caller = (FunctionBuilder()
              .ins(sub(t, reg(RSP), const(16)), store(t, reg(RBX)))      # below the call-time SP
              .ins(add(t, reg(RSP), const(8)), store(t, reg(RSI)))       # caller's own home slot
              .call(LEAF)
              .ins(sub(t, reg(RSP), const(16)), load(reg(R8), t))
              .ins(add(t, reg(RSP), const(8)), load(reg(R9), t))
              .ret())
    results, program = _analyze(caller, leaf)
    (effect,) = results["1:1000"].proven.values()
    assert effect.preserves_memory and effect.clobbers_below
    function = results["1:1000"].normalized
    from synthetic import operation_node_at
    below = slice_from(function, operation_node_at(function, 3, 1))
    above = slice_from(function, operation_node_at(function, 4, 1))
    assert not below.is_complete
    assert above.is_complete and set(range(RSI, RSI + 8)) <= above.register_bytes
    assert _check(results, program).silent == []


# -- TEST-ONLY declared boundaries as call effects --------------------------------

def test_declared_boundary_is_a_call_effect():
    """A TEST-ONLY declared source writes only RAX and keeps everything else:
    the same kind of call effect as a summary or a model, labelled."""
    from tdo_v2.assumed_call_effects import AssumedCallEffect
    from tdo_v2.physical_state import PhysicalRegisterSlice
    caller = (FunctionBuilder().ins(copy(reg(RBX), reg(RSI))).call(CODE_BASE + 0xF00)
              .ins(copy(reg(R9), reg(RAX))).ins(copy(reg(R8), reg(RBX))).ret())
    units = program_units(caller)
    call = "1:1004:2:CALL"
    results = analyze_units(units, declared_boundaries={"1:1000": {
        call: AssumedCallEffect("src.ret", (PhysicalRegisterSlice(RAX, 8),))}})
    item = results["1:1000"]
    effect = item.proven[call]
    assert item.declared[call] == "test-only-boundary:src.ret"
    assert [run.writes[0].start for run in effect.runs] == [RAX]
    assert effect.preserves_memory and not effect.observes_registers and not effect.clobbers_below
    function = item.normalized
    kept = slice_from(function, operation_node_at_index(function, 3))
    assert kept.is_complete and set(range(RSI, RSI + 8)) <= kept.register_bytes
    assert not function.call_clobber_reads


def operation_node_at_index(function, index):
    from synthetic import operation_node_at
    return operation_node_at(function, index)
