"""PE-a1 (S3 design r18, amendment 1; owner 2026-11-25): direction-flag-clear
covers the function's entry value of DF only. A debt on DF -- any call's
return (ordinary, import, kernel / CALLOTHER, landing pad), a value computed
from DF -- is never waived here (call returns are PE-a2's); a later definite
DF write supersedes on the paths it covers. The premise applies only to the
architectural DF: the exported register table's DF row, or without a table the
one byte every recognised rep row of an x86 program names (decoder-matches-cpu).

Fixture: <steps>; dst = rbx at [rsp+0x40]; rcx = 2; rdi = &dst; al = sil;
rep stosb; r9b = dst[1] -- with count 2 and a known destination, a proven
forward direction writes dst+1 (r9b then reads AL), backward writes dst-1.
"""

import pytest

from synthetic import (
    CODE_BASE, R9, RAX, RBX, RCX, RDI, RDX, RSI, RSP, X64, ZF, FunctionBuilder, add, const, copy, load, op, ram,
    program_units, reg, register_evidence, store, tmp,
)
from test_rep_strings import DF, _rep
from tdo_v2.normalize import FunctionNormalizer

REGISTERS = register_evidence(X64)   # (the exported register table names DF)
SYSCALL = 5   # x86-64 ``syscall`` as Ghidra 12 lifts it: CALLOTHER(5)
WRAPPER, OPAQUE = CODE_BASE + 0x800, CODE_BASE + 0xA00


def _syscall(builder):
    builder.ins(op("CALLOTHER", [const(SYSCALL, 4)]))


def _cld(builder):
    builder.ins(copy(reg(DF, 1), const(0, 1)))


def _std(builder):
    builder.ins(copy(reg(DF, 1), const(1, 1)))


def _import_call(builder):
    """mov rbx, [__imp_free]; call rbx -- an identified import call."""
    from test_import_ssa_targets import OTHER_SLOT

    builder.ins(copy(reg(RBX), ram(OTHER_SLOT)))
    builder.call_indirect(RBX)


def _function(*steps, entry=CODE_BASE, arch=None):
    t = tmp(0x100)
    builder = (FunctionBuilder(entry=entry) if arch is None else FunctionBuilder(entry=entry, arch=arch)).sub_rsp(0x80)
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


def _direction(*steps, registers=REGISTERS, assume=True):
    """Standalone normalization: the rep site's proven direction (1 / -1) or None."""
    builder, _ = _function(*steps)
    (unit,) = program_units(builder, registers=registers)
    function = FunctionNormalizer().normalize(unit, assume_direction_flag_clear=assume)
    return function.rep_blocks[0][2] if function.rep_blocks else None


def _program_direction(*steps, extra=(), registers=REGISTERS):
    """analyze_units (direction-flag-clear on; the image's imports)."""
    from test_import_ssa_targets import INFO
    from tdo_v2.interprocedural import analyze_units

    builder, _ = _function(*steps)
    results = analyze_units(program_units(builder, *extra, registers=registers), assume_direction_flag_clear=True,
                            image_info=INFO, assume_import_slots_hold_exports=True)
    blocks = results["1:1000"].normalized.rep_blocks
    return blocks[0][2] if blocks else None


# -- the entry value and definite writes -------------------------------------------------

def test_the_entry_value_needs_the_premise():
    assert _direction() == 1
    assert _direction(assume=False) is None


@pytest.mark.parametrize("write, expected", ((_cld, 1), (_std, -1)))
def test_a_definite_write_needs_no_premise(write, expected):
    assert _direction(write, assume=False) == expected


# -- no call return is covered (amendment 1's hole and its relatives) ------------------

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


def test_a_wrapper_forwarding_a_kernel_return_is_not_covered():
    """w: syscall; ret -- the caller's DF after ``call w`` is the kernel's."""
    wrapper = FunctionBuilder(entry=WRAPPER)
    _syscall(wrapper)

    def call(builder):
        builder.call(WRAPPER)

    assert _program_direction(_cld, call, extra=(wrapper.ret(),)) is None


@pytest.mark.parametrize("call", ("import", "opaque", "indirect", "analysed"))
def test_no_call_return_is_covered_in_pe_a1(call):
    """Owner 2026-11-25: call returns -- an import call, a call to an address
    no function owns, an unresolved indirect call, an analysed leaf -- are
    PE-a2's (body records, call identity); here every one leaves its debt.
    (The analysed leaf calls an opaque function itself, so its summary does
    not keep DF; a leaf keeping DF leaves no debt at all.)"""
    leaf = FunctionBuilder(entry=WRAPPER).call(OPAQUE).ret()
    steps = {"import": _import_call, "opaque": lambda builder: builder.call(OPAQUE),
             "indirect": lambda builder: builder.call_indirect(RBX),
             "analysed": lambda builder: builder.call(WRAPPER)}
    extra = (leaf,) if call == "analysed" else ()
    assert _program_direction(_cld, steps[call], extra=extra) is None
    assert _program_direction(_cld, steps[call], _cld, extra=extra) == 1   # (control: a cld after it)


def test_a_value_computed_from_df_is_no_entry_value():
    """DF = DF ^ 0 at the start: the site reads the XOR's output, which is no
    entry value -- the premise does not reach through a computation."""
    def recompute(builder):
        builder.ins(op("INT_XOR", [reg(DF, 1), const(0, 1)], reg(DF, 1)))

    assert _direction(recompute) is None


# -- the architectural DF ------------------------------------------------------------------

def test_another_register_as_the_direction_operand_gets_no_premise(monkeypatch):
    """Astra r1 P1-5: a rep shape whose direction operand is DL takes nothing from
    the premise (the table names DF elsewhere)."""
    import test_rep_strings

    monkeypatch.setattr(test_rep_strings, "DF", RDX)
    assert _direction() is None
    assert _program_direction() is None


def test_without_a_table_the_program_wide_coordinate_decides():
    """No register table: standalone normalization has no certificate; the
    program-wide inference (every recognised rep row names one byte) gives one."""
    assert _direction(registers=None) is None
    assert _program_direction(registers=None) == 1


@pytest.mark.parametrize("main_reads, other_reads", (("DL", "DF"), ("DF", "DL")))
def test_disagreeing_rep_rows_give_no_inferred_coordinate(monkeypatch, main_reads, other_reads):
    """Two functions whose rep rows name different bytes: no inferred DF --
    whichever of them is DF (no coordinate is picked from a disagreement)."""
    import test_rep_strings

    registers = {"DF": DF, "DL": RDX}
    monkeypatch.setattr(test_rep_strings, "CODE_BASE", WRAPPER)   # (``_rep``'s addresses follow the entry)
    monkeypatch.setattr(test_rep_strings, "DF", registers[other_reads])
    other, _ = _function(entry=WRAPPER)
    monkeypatch.setattr(test_rep_strings, "CODE_BASE", CODE_BASE)
    monkeypatch.setattr(test_rep_strings, "DF", registers[main_reads])
    assert _program_direction(registers=None, extra=(other,)) is None


def test_agreeing_rep_rows_in_two_functions_give_the_coordinate(monkeypatch):
    import test_rep_strings

    monkeypatch.setattr(test_rep_strings, "CODE_BASE", WRAPPER)
    other, _ = _function(entry=WRAPPER)
    monkeypatch.setattr(test_rep_strings, "CODE_BASE", CODE_BASE)
    assert _program_direction(registers=None, extra=(other,)) == 1


def test_an_inferred_coordinate_never_overrides_a_table():
    """Normalization with a table lacking DF ignores a passed coordinate."""
    from tdo_v2.isa_identity import RegisterCoordinate

    table = {**REGISTERS, "registers": [row for row in REGISTERS["registers"] if row["name"] != "DF"]}
    builder, _ = _function()
    (unit,) = program_units(builder, registers=table)
    inferred = RegisterCoordinate("DF", 2, DF, 1)
    assert not FunctionNormalizer().normalize(unit, assume_direction_flag_clear=True,
                                              inferred_direction_flag=inferred).rep_blocks
    (bare,) = program_units(builder)
    assert FunctionNormalizer().normalize(bare, assume_direction_flag_clear=True,
                                          inferred_direction_flag=inferred).rep_blocks   # (control)


def test_a_table_takes_precedence_over_inference():
    """A table without a DF row: no certificate, whatever the rep rows agree on."""
    table = {**REGISTERS, "registers": [row for row in REGISTERS["registers"] if row["name"] != "DF"]}
    assert _program_direction(registers=table) is None


def test_the_inference_is_x86_and_table_free_only():
    from synthetic import AARCH64
    from tdo_v2.isa_identity import inferred_direction_flag

    builder, _ = _function()
    assert inferred_direction_flag(program_units(builder)) is not None
    assert inferred_direction_flag(program_units(builder, registers=REGISTERS)) is None   # (the table rule)
    arm, _ = _function(arch=AARCH64)   # (the same rep p-code in another language)
    assert inferred_direction_flag(program_units(arm)) is None
