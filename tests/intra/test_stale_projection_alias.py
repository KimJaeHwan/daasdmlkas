"""A value read from memory feeds an address or a rep count only if it holds
on the final state (census round 2, Astra's round-2 counterexamples): here
the slot is rewritten through q = *(rdi*rdi), a pointer with no address
expression -- its write gets a definition atom (a wild object), so it is no
longer pending, yet it may land on the slot. The slot read carries that
alias debt, so the store through its value is an uncertain-address writer
(``function_summary.uncertain_writers_of``) and every later read it may
reach carries debt (``may_alias`` ``uncertain_writers``). A rep count with
debt is refused instead (``normalize`` validation). Concrete runs: rdi*rdi
points at the slot."""

import random

from graph_oracle import check
from synthetic import (
    R8, R9, RAX, RBX, RCX, RDI, RDX, RSI, RSP, FunctionBuilder, add, const, copy, load, op, operation_node_at,
    program_units, reg, slice_from, store, tmp,
)
from test_rep_strings import DF, _rep
from tdo_v2.normalize import FunctionNormalizer

STACK = 0x7000_0000
SLOT = STACK - 0x80 + 0x20     # [rsp+0x20] after sub rsp, 0x80
POINTER = 0x1_0000_0000        # rdi * rdi with rdi = 0x10000


def _image(space, address):
    if POINTER <= address < POINTER + 8:
        return (SLOT >> (8 * (address - POINTER))) & 0xFF
    return None


def _pools(seed):
    rng = random.Random(seed)
    return {RSP: STACK, RDI: 0x10000, RBX: rng.getrandbits(64), RSI: rng.getrandbits(64)}


def _slot_rewritten(builder, value):
    t, u = tmp(0x100), tmp(0x200)
    return (builder
            .ins(op("INT_MULT", [reg(RDI), reg(RDI)], u), load(reg(RAX), u))          # q = *(rdi*rdi)
            .ins(*value(t), store(reg(RAX), t)))                                      # *q = value


def _pointer_program():
    """slot = &x; *q = &y (q == &slot); y = rbx; p = slot; *p = rsi; r9 = y."""
    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x80)
               .ins(add(t, reg(RSP), const(0x20)), add(tmp(0x200), reg(RSP), const(0x40)),
                    store(t, tmp(0x200))))
    _slot_rewritten(builder, lambda t: [add(t, reg(RSP), const(0x48))])
    return (builder
            .ins(add(t, reg(RSP), const(0x48)), store(t, reg(RBX)))
            .ins(add(t, reg(RSP), const(0x20)), load(reg(RCX), t))
            .ins(store(reg(RCX), reg(RSI)))
            .ins(add(t, reg(RSP), const(0x48)), load(reg(R9), t))                     # instruction 7
            .add_rsp(0x80).ret())


def _count_program():
    """count = 1; *q = 2 (q == &count); dst[0..8) = rbx; rep stosb (count, al = sil); r9b = dst[1]."""
    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x80)
               .ins(add(t, reg(RSP), const(0x20)), store(t, const(1))))
    _slot_rewritten(builder, lambda t: [copy(t, const(2))])
    builder = (builder
               .ins(add(t, reg(RSP), const(0x40)), store(t, reg(RBX)))
               .ins(add(t, reg(RSP), const(0x20)), load(reg(RCX), t))
               .ins(add(reg(RDI), reg(RSP), const(0x40)))
               .ins(copy(reg(RAX), reg(RSI)))
               .ins(copy(reg(DF, 1), const(0, 1))))
    index = len(builder._rows)
    builder.ins(*_rep(index, "stos"))
    builder.ins(add(t, reg(RSP), const(0x41)), load(reg(R9, 1), t))
    return builder.add_rsp(0x80).ret(), index + 1


def _run(builder, instruction):
    (unit,) = program_units(builder)
    function = FunctionNormalizer().normalize(unit)
    reload = slice_from(function, operation_node_at(function, instruction, 1))
    report = check(function, unit.observation, seeds=range(6), register_pools=_pools, image=_image)
    return reload, report


def test_a_slot_rewritten_through_a_wild_pointer_is_not_used():
    reload, report = _run(_pointer_program(), 7)
    assert set(range(RSI, RSI + 8)) <= reload.register_bytes or not reload.is_complete
    assert report.runs and report.silent == []


def test_a_rep_count_rewritten_through_a_wild_pointer_is_not_used():
    builder, instruction = _count_program()
    reload, report = _run(builder, instruction)
    assert RSI in reload.register_bytes or not reload.is_complete
    assert report.runs and report.silent == []


def test_an_uncertain_write_inside_a_callee_is_seen():
    """As above, but *p = rsi happens in helper(p): the call's memory row is an
    anchored write whose anchor (rcx = p) rests on the slot read."""
    from program_oracle import check_program
    from synthetic import CODE_BASE, REG
    from tdo_v2.interprocedural import analyze_units

    helper_entry = CODE_BASE + 0x800
    helper = FunctionBuilder(entry=helper_entry).ins(store(reg(RCX), reg(RSI))).ret()
    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x80)
               .ins(add(t, reg(RSP), const(0x20)), add(tmp(0x200), reg(RSP), const(0x40)),
                    store(t, tmp(0x200))))
    _slot_rewritten(builder, lambda t: [add(t, reg(RSP), const(0x48))])
    (builder
     .ins(add(t, reg(RSP), const(0x48)), store(t, reg(RBX)))
     .ins(add(t, reg(RSP), const(0x20)), load(reg(RCX), t))
     .call(helper_entry)
     .ins(add(t, reg(RSP), const(0x48)), load(reg(R9), t))                            # instruction 7
     .add_rsp(0x80).ret())
    units = program_units(builder, helper)
    analyzed = analyze_units(units)["1:1000"]
    function = analyzed.normalized
    reload = slice_from(function, operation_node_at(function, 7, 1))
    assert set(range(RSI, RSI + 8)) <= reload.register_bytes or not reload.is_complete
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    report = check_program(function, analyzed.unit.observation, program, seeds=range(6), register_pools=_pools,
                           havoc_calls=(REG, RSP, 8), image=_image)
    assert report.runs and report.silent == []


def _keep_all_but_rcx(unit, plain):
    from tdo_v2.call_summary_effects import ProvenCallEffect
    from tdo_v2.span_geometry import ByteSpan, StorageObjectKind

    registers = next(definition.span.object_id for definition in plain.memory_ssa.definitions
                     if definition.span.object_id.kind is StorageObjectKind.REGISTER_FILE)
    call = next(f"1:{row.address.byte_offset:x}:{ordinal}:CALL" for row in unit.observation.instructions
                for ordinal, operation in enumerate(row.operations) if operation.opcode == "CALL")
    effect = ProvenCallEffect("1:1f00", (), (ByteSpan(registers, 0, RCX), ByteSpan(registers, RCX + 8, 0x1000)),
                              preserves_memory=True, observes_registers=False)
    return {call: effect}


def test_a_store_through_a_clobbered_register_is_uncertain():
    """rcx = &x; y = rbx; call f (keeps memory and every register but rcx);
    *rcx = rsi; r9 = y: f may leave rcx = &y, so the store is an
    uncertain-address writer and y's reload carries its debt."""
    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x80)
               .ins(add(reg(RCX), reg(RSP), const(0x40)))
               .ins(add(t, reg(RSP), const(0x48)), store(t, reg(RBX)))
               .call(0x1F00)
               .ins(store(reg(RCX), reg(RSI)))
               .ins(add(t, reg(RSP), const(0x48)), load(reg(R9), t))                     # instruction 5
               .add_rsp(0x80).ret())
    (unit,) = program_units(builder)
    function = FunctionNormalizer().normalize(
        unit, proven_call_effects=_keep_all_but_rcx(unit, FunctionNormalizer().normalize(unit)))
    reload = slice_from(function, operation_node_at(function, 5, 1))
    assert set(range(RSI, RSI + 8)) <= reload.register_bytes or not reload.is_complete


def test_a_rep_count_through_a_clobbered_register_is_not_used():
    """rcx = 1; call f (keeps memory and every register but rcx); dst = rbx;
    rep stosb with al = sil: the count may be anything after the call, so
    the site stays unexpanded (Astra, design consult)."""
    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x80)
               .ins(copy(reg(RCX), const(1)))
               .call(0x1F00)
               .ins(add(t, reg(RSP), const(0x40)), store(t, reg(RBX)))
               .ins(add(reg(RDI), reg(RSP), const(0x40)))
               .ins(copy(reg(RAX), reg(RSI)))
               .ins(copy(reg(DF, 1), const(0, 1))))
    index = len(builder._rows)
    builder.ins(*_rep(index, "stos"))
    builder.ins(add(t, reg(RSP), const(0x41)), load(reg(R9, 1), t))
    builder.add_rsp(0x80).ret()
    (unit,) = program_units(builder)
    function = FunctionNormalizer().normalize(
        unit, proven_call_effects=_keep_all_but_rcx(unit, FunctionNormalizer().normalize(unit)))
    assert not function.rep_blocks
    reload = slice_from(function, operation_node_at(function, index + 1, 1))
    assert RSI in reload.register_bytes or not reload.is_complete


def test_an_unconditional_uncertain_writer_is_no_alias_condition():
    """f: call h (rcx = *(rdi*rdi), memory kept); *rcx = rsi; rax = *rdx. The
    store also reaches rax's read as an ordinary alias of its static object,
    but its address is unknown after h: the read's debt must stay
    unconditional, not become the pair (rdx bytes, rcx's static bytes) that the
    caller decides disjoint (Fable, review of the implementation). Caller:
    b = rbx; f(&a, &b); r9 = rax -- and h returns &b."""
    from program_oracle import check_program
    from synthetic import CODE_BASE, REG
    from tdo_v2.interprocedural import analyze_units

    f_entry, h_entry = CODE_BASE + 0x800, CODE_BASE + 0xA00
    h = FunctionBuilder(entry=h_entry).ins(op("INT_MULT", [reg(RDI), reg(RDI)], tmp(0x200)),
                                           load(reg(RCX), tmp(0x200))).ret()
    f = (FunctionBuilder(entry=f_entry).sub_rsp(0x28).call(h_entry)
         .ins(store(reg(RCX), reg(RSI)))
         .ins(load(reg(RAX), reg(RDX)))
         .add_rsp(0x28).ret())
    t = tmp(0x100)
    caller = (FunctionBuilder().sub_rsp(0x80)
              .ins(add(t, reg(RSP), const(0x48)), store(t, reg(RBX)))
              .ins(add(reg(RCX), reg(RSP), const(0x40)))
              .ins(add(reg(RDX), reg(RSP), const(0x48)))
              .call(f_entry)
              .ins(copy(reg(R9), reg(RAX)))                                                   # instruction 5
              .add_rsp(0x80).ret())
    pointer = STACK - 0x80 + 0x48

    def image(space, address):
        if POINTER <= address < POINTER + 8:
            return (pointer >> (8 * (address - POINTER))) & 0xFF
        return None

    units = program_units(caller, f, h)
    analyzed = analyze_units(units)["1:1000"]
    function = analyzed.normalized
    reload = slice_from(function, operation_node_at(function, 5, 0))
    assert set(range(RSI, RSI + 8)) <= reload.register_bytes or not reload.is_complete
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    report = check_program(function, analyzed.unit.observation, program, seeds=range(6), register_pools=_pools,
                           havoc_calls=(REG, RSP, 8), image=image)
    assert report.runs and report.silent == []


# -- review of the implementation (Astra round 1) --------------------------------

def _run_program(units, instruction, ordinal=1, image=_image, externals=None):
    from program_oracle import check_program
    from synthetic import REG
    from tdo_v2.interprocedural import analyze_units

    analyzed = analyze_units(units)["1:1000"]
    function = analyzed.normalized
    reload = slice_from(function, operation_node_at(function, instruction, ordinal))
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    report = check_program(function, analyzed.unit.observation, program, seeds=range(6), register_pools=_pools,
                           havoc_calls=(REG, RSP, 8), image=image, externals=externals)
    return reload, report


def test_writer_conditions_guard_preserved_registers():
    """helper(q = rcx, value = rdx), S a global pointer slot (Astra): old = S;
    oldq = *q; S = &x; *q = value; saved = rbx; p = S; *p = r8; rbx = saved;
    S = old; *q = oldq. *p is a conditional writer ((S, *q) disjoint) whose
    static target is the helper's frame, and no exported run carries the
    condition -- rbx is IDENTITY only under it. Caller: q = &S, value =
    &saved: rbx comes back as r8. The condition must be decided at the call
    (``~cw``), not only located."""
    from synthetic import CODE_BASE, DATA_BASE

    helper_entry = CODE_BASE + 0x800
    slot = DATA_BASE + 0x40
    t, old, oldq, pointer = tmp(0x100), tmp(0x300), tmp(0x308), tmp(0x310)
    # no stack adjustment, no register but rbx written, a plain RETURN: no
    # computed run carries the condition (it would be decided as a run's)
    helper = (FunctionBuilder(entry=helper_entry)
              .ins(load(old, const(slot)))
              .ins(load(oldq, reg(RCX)))
              .ins(add(t, reg(RSP), const(-0x20 % (1 << 64))), store(const(slot), t))
              .ins(store(reg(RCX), reg(RDX)))
              .ins(add(t, reg(RSP), const(-0x10 % (1 << 64))), store(t, reg(RBX)))
              .ins(load(pointer, const(slot)))
              .ins(store(pointer, reg(R8)))
              .ins(add(t, reg(RSP), const(-0x10 % (1 << 64))), load(reg(RBX), t))
              .ins(store(const(slot), old))
              .ins(store(reg(RCX), oldq))
              .ret(realistic=False))
    saved = STACK - 0x80 - 8 - 0x10
    caller = (FunctionBuilder().sub_rsp(0x80)
              .ins(copy(reg(RCX), const(slot)))
              .ins(copy(reg(RDX), const(saved)))
              .call(helper_entry)
              .ins(copy(reg(R9), reg(RBX)))                                                   # instruction 4
              .add_rsp(0x80).ret())
    reload, report = _run_program(program_units(caller, helper), 4, ordinal=0)
    assert set(range(R8, R8 + 8)) <= reload.register_bytes or not reload.is_complete
    assert report.runs and report.silent == []


def test_a_condition_side_located_through_debt_is_not_decided():
    """caller: slot = &y; *q = &x (q == &slot, wild); rdx = slot; rcx = &x;
    helper: *rcx = rbx; *rdx = rsi; r9 = *rcx -- r9 = rbx only if (x, *rdx)
    are disjoint, and rdx's nominal &y rests on a read with debt."""
    from synthetic import CODE_BASE

    helper_entry = CODE_BASE + 0x800
    helper = (FunctionBuilder(entry=helper_entry)
              .ins(store(reg(RCX), reg(RBX)))
              .ins(store(reg(RDX), reg(RSI)))
              .ins(load(reg(R9), reg(RCX)))
              .ret())
    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x80)
               .ins(add(t, reg(RSP), const(0x20)), add(tmp(0x200), reg(RSP), const(0x48)),
                    store(t, tmp(0x200))))                                                   # slot = &y
    _slot_rewritten(builder, lambda t: [add(t, reg(RSP), const(0x40))])                      # *q = &x
    (builder
     .ins(add(t, reg(RSP), const(0x20)), load(reg(RDX), t))
     .ins(add(reg(RCX), reg(RSP), const(0x40)))
     .call(helper_entry)
     .ins(copy(reg(R8), reg(R9)))                                                           # instruction 7
     .add_rsp(0x80).ret())
    reload, report = _run_program(program_units(builder, helper), 7, ordinal=0)
    assert set(range(RSI, RSI + 8)) <= reload.register_bytes or not reload.is_complete
    assert report.runs and report.silent == []


def test_a_model_extent_with_debt_is_not_taken():
    """count = 1; *q = 2 (q == &count); dst = rbx; src = rsi; memcpy(dst, src,
    count); r9b = dst[1]: two bytes are copied."""

    from test_external_models import THUNKS, _analyze

    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x80)
               .ins(add(t, reg(RSP), const(0x20)), store(t, const(1))))
    _slot_rewritten(builder, lambda t: [copy(t, const(2))])
    builder = (builder
               .ins(add(t, reg(RSP), const(0x40)), store(t, reg(RBX)))
               .ins(add(t, reg(RSP), const(0x50)), store(t, reg(RSI)))
               .ins(add(t, reg(RSP), const(0x20)), load(reg(R8), t))
               .ins(add(reg(RCX), reg(RSP), const(0x40)))
               .ins(add(reg(RDX), reg(RSP), const(0x50)))
               .call(THUNKS["memcpy"])
               .ins(add(t, reg(RSP), const(0x41)), load(reg(R9, 1), t))                       # instruction 10
               .add_rsp(0x80).ret())
    from program_oracle import check_program
    from synthetic import REG

    results = _analyze(builder)
    analyzed = results["1:1000"]
    function = analyzed.normalized
    reload = slice_from(function, operation_node_at(function, 10, 1))
    assert RSI + 1 in reload.register_bytes or not reload.is_complete
    report = check_program(function, analyzed.unit.observation, {}, seeds=range(6), register_pools=_pools,
                           havoc_calls=(REG, RSP, 8), image=_image,
                           externals={(1, address): name for name, address in THUNKS.items()})
    assert report.runs and report.silent == []


def test_a_rep_direction_a_call_may_change_needs_the_assumption():
    """dst = rbx; rcx = 2; rdi = &dst; al = sil; DF = 0; call f (keeps all but
    rcx -- here: also DF); rep stosb: without direction-flag-clear the
    direction is unproven; with it, the assumption is reported."""
    from tdo_v2.call_summary_effects import ProvenCallEffect
    from tdo_v2.span_geometry import ByteSpan, StorageObjectKind

    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x80)
               .ins(add(t, reg(RSP), const(0x40)), store(t, reg(RBX)))
               .ins(copy(reg(RCX), const(2)))
               .ins(add(reg(RDI), reg(RSP), const(0x40)))
               .ins(copy(reg(RAX), reg(RSI)))
               .ins(copy(reg(DF, 1), const(0, 1)))
               .call(0x1F00))
    index = len(builder._rows)
    builder.ins(*_rep(index, "stos"))
    builder.ins(add(t, reg(RSP), const(0x41)), load(reg(R9, 1), t))
    builder.add_rsp(0x80).ret()
    (unit,) = program_units(builder)
    plain = FunctionNormalizer().normalize(unit)
    registers = next(definition.span.object_id for definition in plain.memory_ssa.definitions
                     if definition.span.object_id.kind is StorageObjectKind.REGISTER_FILE)
    call = next(f"1:{row.address.byte_offset:x}:{ordinal}:CALL" for row in unit.observation.instructions
                for ordinal, operation in enumerate(row.operations) if operation.opcode == "CALL")
    effect = {call: ProvenCallEffect("1:1f00", (), (ByteSpan(registers, 0, DF), ByteSpan(registers, DF + 1, 0x100)),
                                     preserves_memory=True, observes_registers=False)}
    without = FunctionNormalizer().normalize(unit, proven_call_effects=effect)
    assert not without.rep_blocks
    reload = slice_from(without, operation_node_at(without, index + 1, 1))
    assert not reload.is_complete or RBX + 1 in reload.register_bytes
    assumed = FunctionNormalizer().normalize(unit, proven_call_effects=effect, assume_direction_flag_clear=True)
    assert assumed.rep_blocks and assumed.assumed_direction_flag_clear


# -- review round 2 (Astra) ------------------------------------------------------------

R10 = 0x90


def test_a_below_stack_bound_needs_a_settled_stack_pointer():
    """slot = B; *q = B + 0x60 (q == &slot); [B+0x48] = rbx; r10 = rsp;
    rsp = slot; call helper (rsp -= 0x10; [rsp] = rsi; rsp += 0x10); rsp = r10;
    r9 = [B+0x48]: the helper's frame lands on B+0x48, not below B."""
    from synthetic import CODE_BASE

    helper_entry = CODE_BASE + 0x800
    helper = (FunctionBuilder(entry=helper_entry).sub_rsp(0x10)
              .ins(store(reg(RSP), reg(RSI)))
              .add_rsp(0x10).ret())
    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x80)
               .ins(add(t, reg(RSP), const(0x20)), store(t, reg(RSP))))                      # slot = B
    _slot_rewritten(builder, lambda t: [add(t, reg(RSP), const(0x60))])                      # *q = B + 0x60
    (builder
     .ins(add(t, reg(RSP), const(0x48)), store(t, reg(RBX)))
     .ins(copy(reg(R10), reg(RSP)))
     .ins(add(t, reg(RSP), const(0x20)), load(reg(RSP), t))
     .call(helper_entry)
     .ins(copy(reg(RSP), reg(R10)))
     .ins(add(t, reg(RSP), const(0x48)), load(reg(R9), t))                                   # instruction 9
     .add_rsp(0x80).ret())
    reload, report = _run_program(program_units(builder, helper), 9)
    assert set(range(RSI, RSI + 8)) <= reload.register_bytes or not reload.is_complete
    assert report.runs and report.silent == []


def _rep_after_call(before_call, after_call, kept):
    """dst = rbx; rcx = 2; rdi = &dst; al = sil; <before>; call f (keeps
    every register but ``kept`` excludes); <after>; rep stosb; r9b = dst[1]."""
    from tdo_v2.call_summary_effects import ProvenCallEffect
    from tdo_v2.span_geometry import ByteSpan, StorageObjectKind

    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x80)
               .ins(add(t, reg(RSP), const(0x40)), store(t, reg(RBX)))
               .ins(copy(reg(RCX), const(2)))
               .ins(add(reg(RDI), reg(RSP), const(0x40)))
               .ins(copy(reg(RAX), reg(RSI))))
    for row in before_call:
        builder.ins(row)
    builder.call(0x1F00)
    for row in after_call:
        builder.ins(row)
    index = len(builder._rows)
    builder.ins(*_rep(index, "stos"))
    builder.ins(add(t, reg(RSP), const(0x41)), load(reg(R9, 1), t))
    builder.add_rsp(0x80).ret()
    (unit,) = program_units(builder)
    plain = FunctionNormalizer().normalize(unit)
    registers = next(definition.span.object_id for definition in plain.memory_ssa.definitions
                     if definition.span.object_id.kind is StorageObjectKind.REGISTER_FILE)
    call = next(f"1:{row.address.byte_offset:x}:{ordinal}:CALL" for row in unit.observation.instructions
                for ordinal, operation in enumerate(row.operations) if operation.opcode == "CALL")
    preserved, start = [], 0
    for begin, end in sorted(kept):
        if begin > start:
            preserved.append(ByteSpan(registers, start, begin - start))
        start = end
    preserved.append(ByteSpan(registers, start, 0x300 - start))
    effect = {call: ProvenCallEffect("1:1f00", (), tuple(preserved), preserves_memory=True,
                                     observes_registers=False)}
    return FunctionNormalizer().normalize(unit, proven_call_effects=effect, assume_direction_flag_clear=True)


def test_a_backward_direction_before_a_call_is_not_kept():
    """DF = 1; call f (may return DF = 0, as the ABI requires): the direction at
    the rep is not the stale backward one."""
    function = _rep_after_call([copy(reg(DF, 1), const(1, 1))], [], [(DF, DF + 1)])
    assert not function.rep_blocks or function.rep_blocks[0][2] == 1


def test_a_direction_copied_from_a_clobbered_register_is_not_assumed():
    """rdx = 0; call f (may change rdx; DF clear on return); DF = dl: the
    clear-on-return assumption says nothing about dl."""
    function = _rep_after_call([copy(reg(RDX), const(0))], [copy(reg(DF, 1), reg(RDX, 1))],
                               [(RDX, RDX + 8), (DF, DF + 1)])
    assert not function.rep_blocks
