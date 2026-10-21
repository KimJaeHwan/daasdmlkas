"""Forward value facts, F0 (docs 25.33): the transfer rules are sound against
concrete evaluation, and every fact holds on concrete runs (the p-code
interpreter, ``forward_oracle``); nothing in the engine reads them yet."""

import random
from dataclasses import replace

import pytest

import test_graph_fidelity as fidelity
from forward_oracle import check_forward
from synthetic import (
    CODE_BASE, RAX, RBX, RCX, RDX, RSP, FunctionBuilder, add, const, copy, load, op, program_units, reg, store, tmp,
)
from tdo_v2.forward import Interval, Value, _transfer, concretizes, forward_facts, join
from tdo_v2.interprocedural import analyze_units
from tdo_v2.operation_records import _compute

ROOT = "1:1000"
OPS = ("INT_ADD", "INT_SUB", "INT_MULT", "INT_AND", "INT_OR", "INT_LEFT", "INT_RIGHT", "INT_ZEXT", "INT_SEXT",
       "SUBPIECE", "INT_EQUAL", "INT_LESS", "INT_SLESS", "INT_REM", "INT_DIV", "COPY", "POPCOUNT", "INT_NEGATE")


def _interval(rng, bits):
    top = (1 << bits) - 1
    lo = rng.randrange(top + 1) if rng.random() < 0.5 else rng.randrange(min(top, 64) + 1)
    if rng.random() < 0.3:
        return Interval.const(lo, bits)
    hi = min(top, lo + rng.randrange(1, 200))
    stride = rng.choice((1, 1, 2, 4, 8))
    hi = lo + (hi - lo) // stride * stride
    return Interval(lo, hi, stride, bits) if hi > lo else Interval.const(lo, bits)


def _members(rng, interval, count=6):
    if interval.single:
        return [interval.lo]
    steps = (interval.hi - interval.lo) // interval.stride
    return [interval.lo, interval.hi] + [interval.lo + interval.stride * rng.randrange(steps + 1) for _ in range(count)]


@pytest.mark.parametrize("opcode", OPS)
def test_numeric_transfer_is_sound(opcode):
    rng = random.Random(hash(opcode) & 0xFFFF)
    for _ in range(300):
        size = rng.choice((1, 2, 4, 8))
        out = size
        if opcode in ("INT_ZEXT", "INT_SEXT"):
            out = rng.choice([s for s in (2, 4, 8) if s > size] or [8])
        if opcode in ("INT_EQUAL", "INT_LESS", "INT_SLESS"):
            out = 1
        if opcode == "POPCOUNT":
            out = rng.choice((1, 4))
        a = _interval(rng, 8 * size)
        if opcode in ("INT_ZEXT", "INT_SEXT", "COPY", "POPCOUNT", "INT_NEGATE"):
            inputs, widths = [Value(8 * size, (( ("abs",), a),))], [size]
        elif opcode == "SUBPIECE":
            out = rng.choice([s for s in (1, 2, 4) if s < size] or [1]) if size > 1 else 1
            inputs, widths = [Value(8 * size, ((("abs",), a),)), Value.number(0, 32)], [size, 4]
        else:
            second = Interval.const(rng.randrange(1, 9) if opcode in ("INT_LEFT", "INT_RIGHT") else
                                    rng.randrange(1, 1 << min(16, 8 * size)), 8 * size) \
                if rng.random() < 0.7 else _interval(rng, 8 * size)
            inputs = [Value(8 * size, ((("abs",), a),)), Value(8 * size, ((("abs",), second),))]
            widths = [size, size]
        result = _transfer(opcode, inputs, widths, out)
        if result.is_top:
            continue
        for x in _members(rng, a):
            others = [] if len(inputs) == 1 else _members(rng, inputs[1].items[0][1], 3)
            for y in (others or [None]):
                values = [x] if y is None else [x, y]
                if opcode in ("INT_REM", "INT_DIV") and y == 0:
                    continue
                concrete = _compute(opcode, values, widths, out) & ((1 << (8 * out)) - 1)
                assert concretizes(result, concrete, lambda *_: 0), (opcode, a, values, result)


def test_based_values_keep_their_base_only_through_add_and_sub():
    pointer = Value(64, ((("entry", RCX, 8), Interval.offset(0, 64)),))
    moved = _transfer("INT_ADD", [pointer, Value.number(16, 64)], [8, 8], 8)
    assert moved.items == ((("entry", RCX, 8), Interval.offset(16, 64)),)
    assert _transfer("INT_SUB", [moved, Value.number(8, 64)], [8, 8], 8).items[0][1] == Interval.offset(8, 64)
    for opcode in ("INT_AND", "INT_OR", "INT_LEFT", "INT_MULT"):
        assert _transfer(opcode, [pointer, Value.number(3, 64)], [8, 8], 8).is_top, opcode
    assert _transfer("INT_ADD", [pointer, pointer], [8, 8], 8).is_top


def test_join_and_widening_cover_both_sides():
    rng = random.Random(7)
    for _ in range(200):
        a, b = _interval(rng, 32), _interval(rng, 32)
        left, right = Value(32, ((("abs",), a),)), Value(32, ((("abs",), b),))
        for joined in (join(left, right), join(left, right, widen=True)):
            for member in _members(rng, a) + _members(rng, b):
                assert concretizes(joined, member, lambda *_: 0)


def _facts(*functions, **options):
    results = analyze_units(program_units(*functions), **options)
    item = results[ROOT]
    return item, forward_facts(item.normalized, item.unit)


def _pools(seed):
    return {**fidelity._register_inputs(seed), RSP: 0x7000_0000}


def _holds(item, facts, seeds=range(8)):
    report = check_forward(item.unit, facts, seeds=seeds, register_pools=_pools)
    assert report.failures == [], report.failures
    return report


def test_a_constant_target_and_stack_addresses():
    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(copy(reg(RAX), const(CODE_BASE + 0x800)), add(t, reg(RSP), const(0x10)),
                    store(t, reg(RAX)), add(t, reg(RSP), const(0x10)), load(reg(RDX), t))
               .call_indirect(RDX).add_rsp(0x28).ret())
    item, facts = _facts(builder, FunctionBuilder(entry=CODE_BASE + 0x800).ret())
    by_opcode = {}
    operations = {f"{i.address.space_id:x}:{i.address.byte_offset:x}:{n}:{o.opcode}": o
                  for i in item.unit.observation.instructions for n, o in enumerate(i.operations)}
    for fact in facts:
        by_opcode.setdefault(operations[fact.operation].opcode, []).append(fact)
    (target,) = by_opcode["CALLIND"]
    assert target.claim.single_number() == CODE_BASE + 0x800   # through the stack slot
    stores = by_opcode["STORE"]
    assert stores and all(fact.claim.items[0][0] == ("entry", RSP, 8) for fact in stores)
    assert _holds(item, facts).checked


def test_a_loop_counter_widens_and_holds():
    flag = tmp(0x300, 1)
    t = tmp(0x100)
    builder = (FunctionBuilder().ins(copy(reg(RBX), const(0)))
               .label("loop")
               .ins(add(t, reg(RCX), reg(RBX)), load(reg(RAX), t), add(reg(RBX), reg(RBX), const(4)))
               .cbranch("loop", flag, op("INT_LESS", [reg(RBX), const(64)], flag))
               .ret())
    item, facts = _facts(builder)
    assert facts and not any(fact.claim.is_top for fact in facts)
    _holds(item, facts)


def test_entry_pointer_offsets_hold():
    t = tmp(0x100)
    builder = FunctionBuilder().ins(add(t, reg(RCX), const(8)), load(reg(RAX), t), store(reg(RDX), reg(RAX))).ret()
    item, facts = _facts(builder)
    # (and the return's load of [rsp])
    assert {fact.claim.items[0][0] for fact in facts} == {("entry", RCX, 8), ("entry", RDX, 8), ("entry", RSP, 8)}
    _holds(item, facts)


def test_the_oracle_rejects_a_shrunk_fact():
    t = tmp(0x100)
    builder = FunctionBuilder().ins(add(t, reg(RCX), const(8)), load(reg(RAX), t)).ret()
    item, facts = _facts(builder)
    (fact,) = [fact for fact in facts if fact.claim.items[0][0] == ("entry", RCX, 8)]
    wrong = replace(fact, claim=Value(64, ((("entry", RCX, 8), Interval.offset(16, 64)),)))
    report = check_forward(item.unit, [wrong], seeds=range(4), register_pools=_pools)
    assert report.failures


@pytest.mark.parametrize("chunk", range(4))
def test_random_programs_hold(chunk):
    from test_interprocedural import _random_body

    checked = 0
    for seed in range(chunk * 40, chunk * 40 + 40):
        rng = random.Random(91_000 + seed)
        builder = _random_body(rng, FunctionBuilder())
        item, facts = _facts(builder)
        report = check_forward(item.unit, facts, seeds=range(4), register_pools=_pools)
        assert report.failures == [], (seed, report.failures)
        checked += report.checked
    assert checked


def test_a_load_through_a_clobbered_address_is_not_a_value():
    """p = A; an opaque call (p may change); [A] = 0x2000; q = [p]; [q]: the
    SSA keeps p = A, but p's read carries the call-clobber debt -- the load
    through it must not take [A]'s value (Astra F0 review)."""
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(copy(reg(RBX), const(0x40_0000)))
               .call(CODE_BASE + 0x900)
               .ins(store(const(0x40_0000), const(0x2000)), load(reg(RCX), reg(RBX)), load(reg(RDX), reg(RCX)))
               .add_rsp(0x28).ret())
    item, facts = _facts(builder)
    assert not any(fact.claim.single_number() == 0x2000 for fact in facts)


def test_widening_keeps_a_based_offset_signed():
    pointer = Value(64, ((("entry", RCX, 8), Interval.offset(0, 64)),))
    widened = join(Value.number(1, 64), pointer, widen=True)
    below = join(widened, Value(64, ((("entry", RCX, 8), Interval.offset(-1, 64)),)))
    assert concretizes(below, 0x1000 - 1, lambda offset, size: 0x1000)


def test_facts_carry_the_function_assumptions():
    t = tmp(0x100)
    builder = FunctionBuilder().ins(add(t, reg(RCX), const(8)), load(reg(RAX), t)).ret()
    results = analyze_units(program_units(builder))
    item = results[ROOT]
    facts = forward_facts(item.normalized, item.unit, assumptions=("external-model:x/y@v1",))
    assert facts and all("external-model:x/y@v1" in fact.requires for fact in facts)


def test_facts_carry_the_run_assumptions():
    """The caller passes the run's assumptions (EngineRun.assumptions): every
    fact lists them, the engine-level ones included."""
    from tdo_v2.summary_engine import run_assumptions

    builder = FunctionBuilder().sub_rsp(0x28).call(CODE_BASE + 0x900).ins(load(reg(RAX), reg(RSP))).add_rsp(0x28).ret()
    results = analyze_units(program_units(builder))
    labels = run_assumptions(results)
    assert "opaque-callees-restore-stack-pointer" in labels
    item = results[ROOT]
    facts = forward_facts(item.normalized, item.unit, assumptions=labels)
    assert facts and all("opaque-callees-restore-stack-pointer" in fact.requires for fact in facts)


def test_the_oracle_checks_call_instructions_too():
    """A false CALLIND target fact is rejected (the call instruction runs
    after the interpreter entered the callee's activation)."""
    callee = CODE_BASE + 0x800
    builder = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RAX), const(callee))).call_indirect(RAX)
               .add_rsp(0x28).ret())
    results = analyze_units(program_units(builder, FunctionBuilder(entry=callee).ret()))
    item = results[ROOT]
    facts = forward_facts(item.normalized, item.unit)
    calls = [fact for fact in facts if fact.operation.endswith(":CALLIND")]
    assert calls and calls[0].claim.single_number() == callee
    wrong = replace(calls[0], claim=Value.number(callee + 4, 64))
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation
               for unit in program_units(builder, FunctionBuilder(entry=callee).ret())}
    report = check_forward(item.unit, [wrong], seeds=range(2), register_pools=_pools, program=program)
    assert report.failures, report


def test_taint_that_arrives_late_still_reaches_the_loads():
    """Blocks in backward order: the taint of rbx (clobbered by an opaque
    call) reaches the load through q only after the values are stable; the
    fixpoint waits for it (Astra F0 round 2: a false 0x2000 address)."""
    from synthetic import REG

    p, q, z = tmp(0x500), tmp(0x600), tmp(0x700)
    builder = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), const(0x4000))).call(0x1900)
               .ins(op("INT_XOR", [reg(RSP), reg(RSP)], z), store(const(0x4000), z), store(const(0), const(0x2000)))
               .branch("source").label("sink").ins(load(reg(RAX), q), load(reg(RDX), reg(RAX))).add_rsp(0x28).ret()
               .label("middle").ins(load(q, p)).branch("sink").label("source").ins(copy(p, reg(RBX))).branch("middle"))
    results = analyze_units(program_units(builder))
    item = results[ROOT]
    facts = forward_facts(item.normalized, item.unit)
    assert not any(fact.claim.single_number() == 0x2000 for fact in facts)
    report = check_forward(item.unit, facts, seeds=range(2), register_pools=lambda seed: {RSP: 0x7000_0000},
                           havoc_calls=(REG, RSP, 8))
    assert report.failures == []
