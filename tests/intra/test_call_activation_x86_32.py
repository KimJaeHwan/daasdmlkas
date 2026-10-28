"""Activation replays on 32-bit x86 (design C1: one pointer width w from the
observed call shape -- 4 here -- for the stack pointer, the 2^32 relative zero
point, the pre-push skip and the relation seam)."""

import pytest

from types import SimpleNamespace

from synthetic import (
    EAX, ECX, EDX, ESP, RCX, RSP, X64, X86_32, FunctionBuilder, add, const, load, op, program_units, reg, store,
    tmp,
)
from tdo_v2 import _forward_memory as refinement
from tdo_v2.normalize import FunctionNormalizer
from test_call_activation_lifetime import _key
from tdo_v2 import _call_activation
from tdo_v2.forward import _analyze
from tdo_v2.interprocedural import analyze_units

T = tmp(0x100, 4)


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def mode(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)


def _word(value, size=4):
    return const(value & ((1 << (8 * size)) - 1), size)


def _run(caller, callee, frame=False):
    result = analyze_units(program_units(caller, callee), assume_globals_disjoint_from_stack=True,
                           assume_entry_values_not_frame=frame,
                           assume_opaque_callees_leave_no_stack_addresses=False)
    return result["1:1000"], result["1:1600"]


def _original(owner, call):
    return owner.activations[call].activation_witness[0] if call in owner.activations else owner


def _reads(context, key):
    ssa = context.normalized.memory_ssa
    return [read for read in ssa.reads if ssa.actions[read.action_id].operation_key == key]


@pytest.mark.parametrize("frame", (False, True))
def test_a_pointer_and_a_stack_argument_are_seeded_at_four_bytes(frame):
    """caller: sub esp, 0x40; ecx = esp+0x10; [ecx] = 29; [esp] = 7; call.
    callee: eax = [ecx]; edx = [esp+4]; eax = [esp+2] (4 bytes over the return
    slot); ret. The relation ecx = entry esp + 0x14, the seeds 29 at [ecx]
    and 7 at [esp+4] (displacement 4: past the 4-byte push), none over the
    return slot; relative starts are 2^32 + d."""
    caller = (FunctionBuilder(arch=X86_32).sub_rsp(0x40)
              .ins(add(reg(ECX, 4), reg(ESP, 4), _word(0x10)), store(reg(ECX, 4), _word(29)))
              .ins(store(reg(ESP, 4), _word(7))))
    outer = _key(caller, 2, "CALL")
    caller.call(0x1600).add_rsp(0x40).ret()
    callee = FunctionBuilder(0x1600, arch=X86_32)
    pointer = _key(callee, 0, "LOAD")
    callee.ins(load(reg(EAX, 4), reg(ECX, 4)))
    argument = _key(callee, 1, "LOAD")
    callee.ins(add(T, reg(ESP, 4), _word(4)), load(reg(EDX, 4), T))
    straddle = _key(callee, 1, "LOAD")
    callee.ins(add(T, reg(ESP, 4), _word(2)), load(reg(EAX, 4), T)).ret()
    owner, generic = _run(caller, callee, frame)
    context = _call_activation.replay_activation(_original(owner, outer), generic, outer)
    # (frame premise on: _frame_compatible compares SP-relative accesses below
    # 2^32 + the private frame -- [ecx] at 2^32 + 0x14 is the caller's, skipped)
    assert context is not None
    entry = context.normalized.activation_entry
    assert any(destination.start == ECX and destination.size == 4 and delta == 0x14
               for destination, _, delta in entry.registers)
    seeded = {(span.start - (1 << 32), span.size): literal.unsigned for span, literal in entry.memory}
    assert seeded.get((4, 4)) == 7 and seeded.get((0x14, 4)) == 29
    assert all(start >= 4 or start + size <= 0 for start, size in seeded)
    (read,) = [row for row in _reads(context, argument) if row.span.size == 4 and row.span.start > 1 << 31]
    assert read.span.start == (1 << 32) + 4
    bind = _analyze(context.normalized, context.unit).bind
    for key, value in ((pointer, 29), (argument, 7)):
        span = next(row.span for row in _reads(context, key) if row.span.start > 1 << 31)
        assert bind(key, (span,))[0][span].single_number() == value
    span = next(row.span for row in _reads(context, straddle) if row.span.start > 1 << 31)
    assert bind(straddle, (span,))[0][span].single_number() is None


@pytest.mark.parametrize("arch,kept", ((X86_32, True), (X86_32, False), (X64, True), (X64, False)))
@pytest.mark.parametrize("sign", (1, -1))
def test_a_relation_at_the_relative_seam_is_refused_without_an_exception(arch, kept, sign):
    """ecx = entry sp + delta with |delta| = 2^(bits-2) - 1 (kept) or 2^(bits-2)
    (that relation refused): the relative-start seam of ``_relative_start``."""
    width = arch.pointer
    bits = 8 * width
    delta = sign * ((1 << (bits - 2)) - (1 if kept else 0))
    cx, sp = (ECX, ESP) if width == 4 else (RCX, RSP)
    caller = (FunctionBuilder(arch=arch).sub_rsp(0x40)
              .ins(add(reg(cx, width), reg(sp, width), _word(delta - width, width))))
    outer = _key(caller, 2, "CALL")
    caller.call(0x1600).add_rsp(0x40).ret()
    callee = FunctionBuilder(0x1600, arch=arch).ins(load(reg(EAX, 4), reg(cx, width))).ret()
    owner, generic = _run(caller, callee)
    bound = _call_activation._inputs(_original(owner, outer), generic, outer, (), None)
    relations = () if bound is None else bound[4]
    assert any(destination.start == cx and difference == delta
               for destination, _, difference in relations) is kept


def test_a_forward_memory_proof_on_x86_32():
    """C2: [esp+0x30] = ecx & 3; [esp + 4 * that + 0x10] = edx; eax = [esp+0x30]
    -- the indexed store's 32-bit offsets {0x10..0x1f} prove it apart from the
    slot (space bits == address operand bits == claim bits == 32)."""
    index, address, slot = tmp(0x100, 4), tmp(0x120, 4), tmp(0x130, 4)
    builder = (FunctionBuilder(arch=X86_32).sub_rsp(0x40)
               .ins(op("INT_AND", [reg(ECX, 4), _word(3)], index), add(slot, reg(ESP, 4), _word(0x30)),
                    store(slot, index))
               .ins(load(reg(ECX, 4), slot))
               .ins(op("INT_MULT", [reg(ECX, 4), _word(4)], address), add(address, address, reg(ESP, 4)),
                    add(address, address, _word(0x10)), store(address, reg(EDX, 4)))
               .ins(load(reg(EAX, 4), slot))
               .add_rsp(0x40).ret())
    (unit,) = program_units(builder)
    options = dict(assumed_call_effects={}, proven_call_effects={}, assume_globals_disjoint_from_stack=False,
                   readonly_image=None, assume_direction_flag_clear=False, private_frame_above=0, open_conditions={})
    normalized = FunctionNormalizer().normalize(unit, **options)
    result = SimpleNamespace(unit=unit, normalized=normalized, key="1:1000", declared={},
                             inherited_assumptions=frozenset(), proven={})
    plan = refinement.prepare_memory_refinement(result, options)
    assert plan is not None and plan.proofs
    assert all(proof.read_fact.claim.bits == 32 for proof in plan.proofs)
    replay = FunctionNormalizer().normalize(unit, **options, _forward_memory_plan=plan)
    assert replay.forward_memory_proofs == plan.proofs
