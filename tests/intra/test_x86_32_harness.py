"""32-bit x86 through the synthetic harness (``arch=X86_32``: Ghidra
x86:LE:32 offsets, 4-byte pointers and pushes): the stack pointer and call
shapes are recognized, frame reads are exact, summaries cross calls -- and
the 32-bit idiom that broke escape precision once (a stack address pushed as
an argument, then calls: docs 25.78) keeps its private push writes."""

from synthetic import (
    CODE_BASE, EAX, EBP, ECX, EDX, ESP, X86_32, FunctionBuilder, add, const, copy, load,
    operation_node_at, program_units, reg, slice_from, store, tmp,
)
from tdo_v2.interprocedural import analyze_units
from tdo_v2.observed_call_state import observed_call_state_projections

CALLEE, OTHER = CODE_BASE + 0x800, CODE_BASE + 0x900
T = tmp(0x100, 4)


def _fn(entry=CODE_BASE):
    """push ebp; mov ebp, esp; sub esp, 8."""
    builder = FunctionBuilder(entry=entry, arch=X86_32).push(EBP).ins(copy(reg(EBP, 4), reg(ESP, 4)))
    return builder.sub_rsp(8)


def _epilogue(builder):
    """mov esp, ebp; pop ebp; ret."""
    return builder.ins(copy(reg(ESP, 4), reg(EBP, 4))).pop(EBP).ret()


def _analyze(*builders):
    return analyze_units(program_units(*builders))


def test_a_frame_slot_is_exact_and_the_call_shape_is_four_bytes():
    """[ebp-4] = ecx; call other; eax = [ebp-4]."""
    builder = _fn().ins(add(T, reg(EBP, 4), const(-4 & 0xFFFFFFFF, 4)), store(T, reg(ECX, 4)))
    builder.call(OTHER)
    builder = _epilogue(builder.ins(add(T, reg(EBP, 4), const(-4 & 0xFFFFFFFF, 4)), load(reg(EAX, 4), T)))
    other = FunctionBuilder(entry=OTHER, arch=X86_32).ret()
    results = _analyze(builder, other)
    item = results["1:1000"]
    (shape,) = observed_call_state_projections(item.unit.observation)
    assert shape.memory_transition.displacement_delta == -4
    function = item.normalized
    view = slice_from(function, operation_node_at(function, 5, 1))   # (row 5: the load)
    assert view.is_complete and view.reaches(ECX, 4)


def test_a_callee_reading_its_stack_argument_is_exact_in_the_caller():
    """callee: eax = [esp+4]; ret.  caller: push edx; call callee; eax is edx."""
    callee = FunctionBuilder(entry=CALLEE, arch=X86_32).ins(
        add(T, reg(ESP, 4), const(4, 4)), load(reg(EAX, 4), T)).ret()
    caller = _fn().push(EDX).call(CALLEE).ins(copy(reg(ECX, 4), reg(EAX, 4)))
    caller = _epilogue(caller)
    function = _analyze(caller, callee)["1:1000"].normalized
    view = slice_from(function, operation_node_at(function, 5, 0))   # (row 5: ecx = eax)
    assert view.is_complete and view.reaches(EDX, 4)


def test_a_pushed_stack_address_keeps_later_push_writes_private():
    """lea eax, [ebp-4]; push eax; call other; call other: the second call's
    return-address push is a private frame write (docs 25.78: a held store
    is its write-side escape, as before) -- the pattern of v3-win32."""
    builder = _fn().ins(add(T, reg(EBP, 4), const(-4 & 0xFFFFFFFF, 4)), store(T, const(0, 4)))
    builder.ins(add(reg(EAX, 4), reg(EBP, 4), const(-4 & 0xFFFFFFFF, 4))).push(EAX)
    builder.call(OTHER)
    second = f"1:{builder._address(len(builder._rows)):x}:2:CALL~push"
    builder.call(OTHER)
    other = FunctionBuilder(entry=OTHER, arch=X86_32).ret()
    function = _analyze(_epilogue(builder), other)["1:1000"].normalized
    assert second in {key for key, _ in function.private_frame_writes}


def test_cdecl_frame_argument_and_caller_cleanup():
    """callee: push ebp; mov ebp, esp; eax = [ebp+8]; pop ebp; ret.  caller:
    push edx; call callee; add esp, 4; ecx = eax -- the argument reaches ecx."""
    callee = FunctionBuilder(entry=CALLEE, arch=X86_32).push(EBP).ins(copy(reg(EBP, 4), reg(ESP, 4)))
    callee = callee.ins(add(T, reg(EBP, 4), const(8, 4)), load(reg(EAX, 4), T)).pop(EBP).ret()
    caller = _fn().push(EDX).call(CALLEE).add_rsp(4).ins(copy(reg(ECX, 4), reg(EAX, 4)))
    function = _analyze(_epilogue(caller), callee)["1:1000"].normalized
    view = slice_from(function, operation_node_at(function, 6, 0))   # (row 6: ecx = eax)
    assert view.is_complete and view.reaches(EDX, 4)


def test_x86_32_indirect_and_tail_calls_build():
    """call_indirect / tail_call encode 4-byte pushes and targets."""
    builder = _fn().call_indirect(ECX)
    builder = _epilogue(builder)
    tail = FunctionBuilder(entry=OTHER, arch=X86_32).tail_call(CALLEE)
    callee = FunctionBuilder(entry=CALLEE, arch=X86_32).ret()
    results = _analyze(builder, tail, callee)
    (shape,) = observed_call_state_projections(results["1:1000"].unit.observation)
    assert shape.memory_transition.displacement_delta == -4
    assert results[f"1:{OTHER:x}"].normalized is not None
