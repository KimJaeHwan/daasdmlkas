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
from tdo_v2.forward import Interval, Value, _transfer, concretizes, context_facts, forward_facts, join, substitute
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
    for opcode in ("INT_OR", "INT_LEFT", "INT_MULT"):
        assert _transfer(opcode, [pointer, Value.number(3, 64)], [8, 8], 8).is_top, opcode
    # a mask keeps no base, only the mask's range
    assert _transfer("INT_AND", [pointer, Value.number(3, 64)], [8, 8], 8).items == (
        (("abs",), Interval(0, 3, 1, 64)),)
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


# -- F4a: reads at ranged addresses (docs 25.33) ------------------------------------

A_TARGET, B_TARGET = CODE_BASE + 0x800, CODE_BASE + 0x900


def _table(*between, slot_b=0x28):
    """table[0] = A at [rsp+0x20], table[1] = B at [rsp+slot_b]; i = rcx & 1;
    call table[i] -- the 09 testbed's DFB072 shape."""
    t, u, i = tmp(0x100), tmp(0x180), tmp(0x200)
    return (FunctionBuilder().sub_rsp(0x48)
            .ins(add(t, reg(RSP), const(0x20)), store(t, const(A_TARGET)),
                 add(u, reg(RSP), const(slot_b)), store(u, const(B_TARGET)))
            .ins(*between)
            .ins(op("INT_AND", [reg(RCX), const(1)], i), op("INT_MULT", [i, const(8)], i),
                 add(i, i, reg(RSP)), add(i, i, const(0x20)), load(reg(RAX), i))
            .call_indirect(RAX).add_rsp(0x48).ret())


def _forward_facts(monkeypatch, *functions):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    results = analyze_units(program_units(*functions))
    item = results[ROOT]
    assert item.normalized.forward_inputs is not None
    return item, forward_facts(item.normalized, item.unit)


def _target(facts):
    return next((fact.claim for fact in facts if fact.operation.endswith(":CALLIND")), None)


def _targets(claim):
    ((base, interval),) = claim.items
    assert base == ("abs",)
    return {value for value in range(interval.lo, interval.hi + 1, interval.stride or 1) if interval.contains(value)}


def test_a_table_read_by_a_ranged_index_gives_both_targets(monkeypatch):
    callees = (FunctionBuilder(entry=A_TARGET).ret(), FunctionBuilder(entry=B_TARGET).ret())
    item, facts = _forward_facts(monkeypatch, _table(), *callees)
    claim = _target(facts)
    assert claim is not None and _targets(claim) == {A_TARGET, B_TARGET}
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation
               for unit in program_units(_table(), *callees)}
    report = check_forward(item.unit, facts, seeds=range(6), register_pools=_pools, program=program)
    assert report.failures == [] and report.checked


def test_an_opaque_call_between_the_stores_and_the_read_gives_no_target(monkeypatch):
    builder = (FunctionBuilder().sub_rsp(0x48)
               .ins(add(tmp(0x100), reg(RSP), const(0x20)), store(tmp(0x100), const(A_TARGET)),
                    add(tmp(0x180), reg(RSP), const(0x28)), store(tmp(0x180), const(B_TARGET)))
               .call(CODE_BASE + 0xA00)
               .ins(op("INT_AND", [reg(RCX), const(1)], tmp(0x200)), op("INT_MULT", [tmp(0x200), const(8)], tmp(0x200)),
                    add(tmp(0x200), tmp(0x200), reg(RSP)), add(tmp(0x200), tmp(0x200), const(0x20)),
                    load(reg(RAX), tmp(0x200)))
               .call_indirect(RAX).add_rsp(0x48).ret())
    _, facts = _forward_facts(monkeypatch, builder)
    assert _target(facts) is None


def test_a_partial_overwrite_of_one_slot_gives_no_target(monkeypatch):
    _, facts = _forward_facts(monkeypatch, _table(add(tmp(0x300), reg(RSP), const(0x2C)),
                                                  store(tmp(0x300), const(0x77, 1))))
    claim = _target(facts)
    assert claim is None or B_TARGET not in _targets(claim)


def test_forward_off_builds_no_inputs(monkeypatch):
    monkeypatch.delenv("TDO_V2_FORWARD", raising=False)
    results = analyze_units(program_units(_table()))
    assert results[ROOT].normalized.forward_inputs is None


def test_the_probe_keeps_the_configured_frame_policy(monkeypatch):
    """With entry-values-do-not-address-the-new-frame OFF, an entry pointer
    (rdx) may address the table: its store reaches a slot, so no {A, B}
    (Astra F4a round 1, reproduced)."""
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    builder = _table(store(reg(RDX), const(0x1A00)))
    results = analyze_units(program_units(builder), assume_entry_values_not_frame=False)
    item = results[ROOT]
    claim = _target(forward_facts(item.normalized, item.unit))
    assert claim is None or 0x1A00 in _targets(claim) or not _targets(claim) <= {A_TARGET, B_TARGET}


def test_a_probe_resting_on_an_assumption_reports_it(monkeypatch):
    """Default policies; the stack address escapes after the read, so the
    normalization itself rests on no private-frame assumption -- only the probe
    does (it decides the rdx store cannot reach a table slot). Every fact then
    lists entry-values-do-not-address-the-new-frame (Astra F4a round 2)."""
    i = tmp(0x200)
    builder = (FunctionBuilder().sub_rsp(0x48)
               .ins(add(tmp(0x100), reg(RSP), const(0x20)), store(tmp(0x100), const(A_TARGET)),
                    add(tmp(0x180), reg(RSP), const(0x28)), store(tmp(0x180), const(B_TARGET)))
               .ins(store(reg(RDX), const(0x1A00)))
               .ins(op("INT_AND", [reg(RCX), const(1)], i), op("INT_MULT", [i, const(8)], i),
                    add(i, i, reg(RSP)), add(i, i, const(0x20)), load(reg(RAX), i))
               .ins(store(const(0x5000), reg(RSP)))
               .call_indirect(RAX).add_rsp(0x48).ret())
    item, facts = _forward_facts(monkeypatch, builder)
    assert not item.normalized.assumes_entry_values_not_frame
    assert _targets(_target(facts)) == {A_TARGET, B_TARGET}
    assert facts and all("entry-values-do-not-address-the-new-frame" in fact.requires for fact in facts)


# -- F2a: call contexts by substitution (docs 25.33) --------------------------------

CALLEE, OPAQUE = CODE_BASE + 0xA00, CODE_BASE + 0xC00


def _calls_rcx():
    """callee(rcx): call rcx."""
    return FunctionBuilder(entry=CALLEE).sub_rsp(0x18).call_indirect(RCX).add_rsp(0x18).ret()


def _context_run(monkeypatch, caller, *others):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    functions = (caller, _calls_rcx(), FunctionBuilder(entry=A_TARGET).ret(), FunctionBuilder(entry=B_TARGET).ret(),
                 *others)
    results = analyze_units(program_units(*functions))
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in program_units(*functions)}
    return results, context_facts(results), program


def _context_targets(facts):
    return {fact.context: _targets(fact.claim) for fact in facts if fact.operation.endswith(":CALLIND")}


def test_substitution_moves_offsets_onto_the_binding():
    claim = Value(64, ((("entry", RCX, 8), Interval.offset(8, 64)), (("abs",), Interval.const(3, 64))))
    bound = substitute(claim, {("entry", RCX, 8): Value.number(0x1000, 64)})
    assert bound.numeric() == Interval(3, 0x1008, 0x1005, 64)
    assert substitute(claim, {}).is_top
    assert substitute(claim, {("entry", RCX, 8): Value.top(64)}).is_top
    stack = substitute(Value(64, ((("entry", RSP, 8), Interval(-16, -8, 8, 64, True)),)),
                       {("entry", RSP, 8): Value(64, ((("entry", RSP, 8), Interval.offset(-0x30, 64)),))})
    assert stack == Value(64, ((("entry", RSP, 8), Interval(-0x40, -0x38, 8, 64, True)),))


def test_two_call_sites_bind_their_own_targets(monkeypatch):
    caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), const(A_TARGET))).call(CALLEE)
              .ins(copy(reg(RCX), const(B_TARGET))).call(CALLEE).add_rsp(0x28).ret())
    results, facts, program = _context_run(monkeypatch, caller)
    targets = _context_targets(facts)
    assert sorted(targets.values(), key=sorted) == [{A_TARGET}, {B_TARGET}]
    assert len(targets) == 2 and all(context[0] == ROOT for context in targets)
    callee_fact = next(fact for fact in forward_facts(results[f"1:{CALLEE:x}"].normalized, results[f"1:{CALLEE:x}"].unit)
                       if fact.operation.endswith(":CALLIND"))
    assert callee_fact.claim.items[0][0] == ("entry", RCX, 8)   # (the generic fact stays parametric)
    item = results[ROOT]
    report = check_forward(item.unit, facts, seeds=range(4), register_pools=_pools, program=program)
    assert report.failures == [] and report.checked and report.unexercised == 0


def test_the_stack_pointer_is_bound_once_through_the_call_shape(monkeypatch):
    caller = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), const(A_TARGET))).call(CALLEE).add_rsp(0x28).ret()
    results, facts, program = _context_run(monkeypatch, caller)
    # the callee's return reads [its entry rsp] = the caller's entry rsp - 0x28 - 8
    (ret,) = [fact for fact in facts if fact.operation.endswith(":LOAD")
              and fact.claim.items[0][0] == ("entry", RSP, 8)]
    assert ret.claim.items[0][1] == Interval.offset(-0x30, 64)
    report = check_forward(results[ROOT].unit, facts, seeds=range(4), register_pools=_pools, program=program)
    assert report.failures == [] and report.checked


def test_a_clobbered_binding_gives_no_context_target(monkeypatch):
    caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), const(A_TARGET))).call(OPAQUE).call(CALLEE)
              .add_rsp(0x28).ret())
    _, facts, _ = _context_run(monkeypatch, caller)
    assert _context_targets(facts) == {}


def test_repeated_activations_from_one_site_hold(monkeypatch):
    flag = tmp(0x300, 1)
    caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), const(0)))
              .label("loop").ins(copy(reg(RCX), const(A_TARGET))).call(CALLEE)
              .ins(add(reg(RBX), reg(RBX), const(1)))
              .cbranch("loop", flag, op("INT_LESS", [reg(RBX), const(3)], flag))
              .add_rsp(0x28).ret())
    results, facts, program = _context_run(monkeypatch, caller)
    report = check_forward(results[ROOT].unit, facts, seeds=range(3), register_pools=_pools, program=program)
    assert report.failures == [] and report.checked
    assert list(_context_targets(facts).values()) == [{A_TARGET}]


def test_context_facts_carry_both_sides_requires(monkeypatch):
    caller = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), const(A_TARGET))).call(CALLEE).add_rsp(0x28).ret()
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    functions = (caller, _calls_rcx(), FunctionBuilder(entry=A_TARGET).ret())
    results = analyze_units(program_units(*functions))
    facts = context_facts(results, assumptions=lambda key, item: (f"side-{key}",))
    assert facts and all({"side-1:1000", f"side-1:{CALLEE:x}"} <= set(fact.requires) for fact in facts)


def test_the_oracle_rejects_a_wrong_context_target(monkeypatch):
    caller = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), const(A_TARGET))).call(CALLEE).add_rsp(0x28).ret()
    results, facts, program = _context_run(monkeypatch, caller)
    wrong = [replace(fact, claim=Value.number(B_TARGET, 64)) if fact.operation.endswith(":CALLIND") else fact
             for fact in facts]
    report = check_forward(results[ROOT].unit, wrong, seeds=range(2), register_pools=_pools, program=program)
    assert report.failures


def test_forward_off_gives_no_context_facts(monkeypatch):
    monkeypatch.delenv("TDO_V2_FORWARD", raising=False)
    caller = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), const(A_TARGET))).call(CALLEE).add_rsp(0x28).ret()
    results = analyze_units(program_units(caller, _calls_rcx(), FunctionBuilder(entry=A_TARGET).ret()))
    assert context_facts(results) == ()


def test_a_register_written_after_the_projected_push_binds_to_top(monkeypatch):
    """call shape ``rsp -= 8; [rsp] = ret; rcx = rsp; CALL`` -- the projection
    removes the push, so rcx is not the pre-call value the binding reads
    (Astra F2a round 1, reproduced): no context fact rests on it."""
    from synthetic import _Instruction, ram, sub

    caller = FunctionBuilder().sub_rsp(0x28)
    after = caller._address(len(caller._rows) + 1)   # (the return address: the shape is projected)
    caller._rows.append(_Instruction([sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), const(after)),
                                      copy(reg(RCX), reg(RSP)), op("CALL", [ram(CALLEE)])], "call", call_target=CALLEE))
    caller = caller.add_rsp(0x28).ret()
    callee = FunctionBuilder(entry=CALLEE).ins(load(reg(RAX), reg(RCX))).ret()
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    functions = (caller, callee)
    results = analyze_units(program_units(*functions))
    facts = context_facts(results)
    assert not any(fact.operation.startswith(f"1:{CALLEE:x}:0:") for fact in facts)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in program_units(*functions)}
    report = check_forward(results[ROOT].unit, facts, seeds=range(3), register_pools=_pools, program=program)
    assert report.failures == []


def test_the_oracle_checks_a_recursive_callees_own_call_instruction():
    """At depth 2 the call's own address is the callee's call instruction
    (recursion): checked; at depth 1 it is the caller's (Astra F2a round 1)."""
    import pcode_interpreter
    from forward_oracle import _Recording

    recording = _Recording.__new__(_Recording)
    recording.contexts, recording.subjects, recording.seen = {("1:1008:2:CALL", "1:1008:0:LOAD"): 1}, {}, {}
    recording._subject_value = lambda varnode: 7
    operation = type("Op", (), {"inputs": (None, None)})()
    original = pcode_interpreter.Interpreter._execute
    pcode_interpreter.Interpreter._execute = lambda self, key, operation, run: None
    try:
        recording._activations = [(0, "1:1008:2:CALL"), (0, "1:1008:2:CALL")]
        recording._execute("1:1008:0:LOAD", operation, None)
        assert recording.seen == {("1:1008:2:CALL", "1:1008:0:LOAD"): [7]}
        recording.seen = {}
        recording._activations = [(0, "1:1008:2:CALL")]
        recording._execute("1:1008:0:LOAD", operation, None)
        assert recording.seen == {}
    finally:
        pcode_interpreter.Interpreter._execute = original


def test_a_pass_through_is_a_context_fact(monkeypatch):
    """caller passes its own entry rcx on: the context claim reads the same
    but belongs to the caller's activation (Fable F2a round 1)."""
    caller = FunctionBuilder().sub_rsp(0x28).call(CALLEE).add_rsp(0x28).ret()
    _, facts, _ = _context_run(monkeypatch, caller)
    ((context, targets),) = [(fact.context, fact.claim) for fact in facts if fact.operation.endswith(":CALLIND")]
    assert context[0] == ROOT and targets.items[0][0] == ("entry", RCX, 8)


def test_a_projection_sensitive_caller_gets_no_facts(monkeypatch):
    """``rsp -= 8; [rsp] = ret; rcx = rsp; CALL A`` then ``CALL B`` with B
    loading [rcx]: the projected push makes the caller's own SSA value of rcx
    wrong, so it leaks into later bindings (Astra F2a round 2, reproduced):
    the caller gets no forward facts and binds nothing."""
    from synthetic import _Instruction, ram, sub

    other = CODE_BASE + 0xE00
    caller = FunctionBuilder().sub_rsp(0x28)
    after = caller._address(len(caller._rows) + 1)
    caller._rows.append(_Instruction([sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), const(after)),
                                      copy(reg(RCX), reg(RSP)), op("CALL", [ram(A_TARGET)])], "call", call_target=A_TARGET))
    caller = caller.call(other).add_rsp(0x28).ret()
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    functions = (caller, FunctionBuilder(entry=A_TARGET).ret(),
                 FunctionBuilder(entry=other).ins(load(reg(RAX), reg(RCX))).ret())
    results = analyze_units(program_units(*functions))
    assert forward_facts(results[ROOT].normalized, results[ROOT].unit) == ()
    assert not [fact for fact in context_facts(results) if fact.context[0] == ROOT]
