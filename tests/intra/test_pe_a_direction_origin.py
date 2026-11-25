"""PE-a (S3 design r18, amendment 1): direction-flag-clear discharges a debt on
the direction flag only when every origin of DF at a rep site is the entry or a
return the premise covers (a call's return). A kernel return (syscall,
CALLOTHER), a wrapper forwarding its unknown DF, or an unidentified origin
cannot; a later definite DF write supersedes on the paths it covers.

Fixture: <steps>; dst = rbx at [rsp+0x40]; rcx = 2; rdi = &dst; al = sil;
rep stosb; r9b = dst[1] -- with count 2 and a known destination, a proven
forward direction writes dst+1 (r9b then reads AL), backward writes dst-1.
"""

import pytest

from synthetic import (
    CODE_BASE, R9, RAX, RBX, RCX, RDI, RSI, RSP, ZF, FunctionBuilder, add, const, copy, load, op,
    operation_node_at, program_units, reg, slice_from, store, tmp,
)
from test_rep_strings import DF, _rep
from tdo_v2.normalize import FunctionNormalizer

SYSCALL = 5   # x86-64 ``syscall`` as Ghidra 12 lifts it: CALLOTHER(5)


def _syscall(builder):
    builder.ins(op("CALLOTHER", [const(SYSCALL, 4)]))


def _cld(builder):
    builder.ins(copy(reg(DF, 1), const(0, 1)))


def _std(builder):
    builder.ins(copy(reg(DF, 1), const(1, 1)))


def _function(*steps):
    t = tmp(0x100)
    builder = FunctionBuilder().sub_rsp(0x80)
    for step in steps:   # (first: a kernel or call return clobbers the setup registers too)
        step(builder)
    (builder.ins(add(t, reg(RSP), const(0x40)), store(t, reg(RBX)))
     .ins(copy(reg(RCX), const(2)))
     .ins(add(reg(RDI), reg(RSP), const(0x40)))
     .ins(copy(reg(RAX), reg(RSI))))
    index = len(builder._rows)
    builder.ins(*_rep(index, "stos"))
    builder.ins(add(t, reg(RSP), const(0x41)), load(reg(R9, 1), t))
    builder.add_rsp(0x80).ret()
    return builder, index


def _direction(*steps, assume=True):
    """The rep site's proven direction (1 / -1) or None."""
    builder, _ = _function(*steps)
    (unit,) = program_units(builder)
    function = FunctionNormalizer().normalize(unit, assume_direction_flag_clear=assume)
    return function.rep_blocks[0][2] if function.rep_blocks else None


def test_a_kernel_return_is_not_covered():
    """cld; syscall; rep stosb: the kernel return is not "a call returns"."""
    assert _direction(_cld, _syscall) is None


@pytest.mark.parametrize("after, expected", ((_cld, 1), (_std, -1)))
def test_a_definite_write_after_the_kernel_return_decides(after, expected):
    assert _direction(_cld, _syscall, after) == expected


def _join_one_arm_cld_after(builder):
    """syscall; if (zf) cld; -- the other arm keeps the kernel return's DF."""
    _syscall(builder)
    builder.cbranch("joined", reg(ZF, 1))
    _cld(builder)
    builder.label("joined")


def test_a_join_where_one_arm_skips_the_cld_is_not_proven():
    assert _direction(_cld, _join_one_arm_cld_after) is None


def test_a_join_where_both_arms_write_the_flag_is_proven():
    def both(builder):
        _syscall(builder)
        builder.cbranch("other", reg(ZF, 1))
        _cld(builder)
        builder.branch("joined").label("other")
        _cld(builder)
        builder.label("joined")

    assert _direction(both) == 1


WRAPPER, OPAQUE = CODE_BASE + 0x800, CODE_BASE + 0xA00


def _through(callee_body):
    """The rep site's direction in the caller ``cld; call callee; ...`` with the
    callee summarized (analyze_units, direction-flag-clear on)."""
    from tdo_v2.interprocedural import analyze_units

    def call(builder):
        builder.call(WRAPPER)

    builder, _ = _function(_cld, call)
    callee = callee_body(FunctionBuilder(entry=WRAPPER)).ret()
    results = analyze_units(program_units(builder, callee), assume_direction_flag_clear=True)
    blocks = results["1:1000"].normalized.rep_blocks
    return blocks[0][2] if blocks else None


def test_a_wrapper_forwarding_a_kernel_return_is_not_covered():
    """w: syscall; ret -- the caller's DF after ``call w`` is the kernel's."""
    def wrapper(builder):
        _syscall(builder)
        return builder

    assert _through(wrapper) is None


def test_a_plain_call_return_is_covered():
    """An opaque call's return: the premise's own case (forward)."""
    from tdo_v2.interprocedural import analyze_units

    def call(builder):
        builder.call(OPAQUE)

    builder, _ = _function(_cld, call)
    results = analyze_units(program_units(builder), assume_direction_flag_clear=True)
    blocks = results["1:1000"].normalized.rep_blocks
    assert blocks and blocks[0][2] == 1


def _program_direction(*steps, extra=()):
    """The rep site's direction under analyze_units (direction-flag-clear on)."""
    from tdo_v2.interprocedural import analyze_units

    builder, _ = _function(*steps)
    results = analyze_units(program_units(builder, *extra), assume_direction_flag_clear=True)
    blocks = results["1:1000"].normalized.rep_blocks
    return blocks[0][2] if blocks else None


def _opaque_call(builder):
    builder.call(OPAQUE)   # (no function of the program there: an opaque call)


def test_an_opaque_call_and_an_unresolved_indirect_call_are_covered():
    assert _program_direction(_cld, _opaque_call) == 1
    assert _program_direction(_cld, lambda builder: builder.call_indirect(RBX)) == 1


def test_a_value_computed_from_df_after_a_covered_call_is_not_covered():
    """cld; call opaque; DF = DF ^ 0: the debt's reader is the XOR, not the
    site's direction read -- the premise gives DF at the return, not the
    computed value (amendment 1: no transformed DF; the stale SSA value is 0)."""
    def recompute(builder):
        builder.ins(op("INT_XOR", [reg(DF, 1), const(0, 1)], reg(DF, 1)))

    assert _program_direction(_cld, _opaque_call, recompute) is None
    assert _program_direction(_cld, _opaque_call) == 1   # (control)


def test_an_analysed_callee_that_does_not_keep_df_is_not_covered_yet():
    """PE-a1's stated cost: a call to analysed code is decided by its body, which
    carries no DF record before PE-a2 -- here a leaf whose own call is opaque."""
    leaf = FunctionBuilder(entry=WRAPPER).call(OPAQUE).ret()

    def call(builder):
        builder.call(WRAPPER)

    assert _program_direction(_cld, call, extra=(leaf,)) is None


def test_standalone_normalization_lists_no_covered_call():
    """Fail closed: without ``covered_call_returns`` no call return is covered."""
    builder, _ = _function(_cld, _opaque_call)
    (unit,) = program_units(builder)
    assert not FunctionNormalizer().normalize(unit, assume_direction_flag_clear=True).rep_blocks


def test_a_call_to_a_refused_function_of_the_program_is_not_covered():
    """The target is code of this program that was not analysed (refused at
    admission): no body record, and no opaque call either -- uncovered."""
    from synthetic import open_configured_extraction, _mint_orchestrator_capability, _Provider
    from test_pe_b_refused_callees import _refused
    from tdo_v2.interprocedural import analyze_units

    refused_entry = CODE_BASE + 0xC00

    def call(builder):
        builder.call(refused_entry)

    builder, _ = _function(_cld, call)
    with open_configured_extraction(_Provider([builder, _refused(refused_entry)]),
                                    _mint_orchestrator_capability()) as envelope:
        units = list(envelope.iter_scoped_functions())
    results = analyze_units(units, assume_direction_flag_clear=True)
    assert not results["1:1000"].normalized.rep_blocks


def test_an_indirect_call_resolved_to_an_analysed_wrapper_is_not_covered():
    """rbx = &w; call rbx -- once resolved, the target is analysed code (here a
    syscall wrapper): its body decides, not the premise."""
    wrapper = FunctionBuilder(entry=WRAPPER)
    _syscall(wrapper)

    def call(builder):
        builder.ins(copy(reg(RBX), const(WRAPPER)))
        builder.call_indirect(RBX)

    assert _program_direction(_cld, call, extra=(wrapper.ret(),)) is None
