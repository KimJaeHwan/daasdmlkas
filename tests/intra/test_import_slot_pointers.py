"""Named assumption import-slots-hold-their-exports (docs section 25.2 B).

A pointer read whole from an import slot is the import's address: a read AT
that address is image-backed static storage, so -- with
globals-disjoint-from-stack -- it cannot be a stack byte (UE's
``cmp byte [__imp_GIgnoreDebugger], 0`` made a stack-held source a possible
origin of every later root through control dependence). Nothing changes for
other displacements, without the assumption or globals-disjoint-from-stack,
for a slot the function writes, or for a narrower read of the slot."""

import pytest

from synthetic import (
    DATA_BASE, RAX, RCX, RDI, RSI, RSP, FunctionBuilder, add, const, load, program_units, reg, slice_op, store, tmp,
)
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_engine import run_assumptions

SLOT = DATA_BASE + 0x100
INFO = ImageInfo("synthetic", (), (ImportedSymbol("CORE.DLL", "GFlag", "?GFlag@@3_NA", ((1, SLOT),), ()),), (), ())
STACK_BYTES = set(range(RSI, RSI + 8))


def _function(displacement=0, write_slot=False, slot_width=8):
    """[entry sp + 0x30] = rsi (a stack byte of the caller's frame, which a
    pointer this function did not make may reach); p = [slot]; cl = byte [p + d]."""
    t = tmp(0x100)
    builder = FunctionBuilder().sub_rsp(0x40).ins(add(t, reg(RSP), const(0x70)), store(t, reg(RSI)))   # 1
    if write_slot:
        builder.ins(store(const(SLOT, 8), reg(RDI)))
    else:
        builder.ins(copy_nothing())
    return (builder
            .ins(load(reg(RAX, slot_width), const(SLOT, 8)))                                            # 3
            .ins(add(t, reg(RAX), const(displacement)), load(reg(RCX, 1), t))                          # 4
            .add_rsp(0x40).ret())


def copy_nothing():
    from synthetic import copy
    return copy(reg(RDI), reg(RDI))


def _analyze(function, *, imports=True, globals_disjoint=True):
    results = analyze_units(program_units(function), image_info=INFO,
                            assume_globals_disjoint_from_stack=globals_disjoint,
                            assume_import_slots_hold_exports=imports)
    return results, results["1:1000"].normalized


def _byte_read(normalized):
    return slice_op(normalized, "LOAD", 4)


def test_a_read_at_an_import_address_is_not_the_stack():
    results, normalized = _analyze(_function())
    read = _byte_read(normalized)
    assert not read.register_bytes & STACK_BYTES
    assert normalized.assumes_import_slots_hold_exports
    assert "import-slots-hold-their-exports" in run_assumptions(results)


@pytest.mark.parametrize("options", [dict(imports=False), dict(globals_disjoint=False)])
def test_without_the_assumptions_the_read_may_be_the_stack(options):
    results, normalized = _analyze(_function(), **options)
    assert _byte_read(normalized).register_bytes & STACK_BYTES
    assert not normalized.assumes_import_slots_hold_exports
    assert "import-slots-hold-their-exports" not in run_assumptions(results)


def test_another_displacement_gets_nothing():
    _, normalized = _analyze(_function(displacement=8))
    assert _byte_read(normalized).register_bytes & STACK_BYTES


def test_a_slot_the_function_writes_gets_nothing():
    _, normalized = _analyze(_function(write_slot=True))
    assert _byte_read(normalized).register_bytes & STACK_BYTES
    assert not normalized.assumes_import_slots_hold_exports


def test_a_narrower_read_of_the_slot_gets_nothing():
    _, normalized = _analyze(_function(slot_width=4))
    assert _byte_read(normalized).register_bytes & STACK_BYTES


def test_the_assumption_is_a_registered_switch():
    from tdo_v2.assumptions import switches

    item = next(item for item in switches() if item.name == "import-slots-hold-their-exports")
    assert item.default and item.parameter == "assume_import_slots_hold_exports"


@pytest.mark.parametrize("displacement", [0, 8])
def test_a_callee_writing_through_an_import_address_stays_anchored(displacement):
    """callee: p = [__imp]; [p + d] = rcx. Its write is anchored on the slot (a
    pointer read from entry memory), with or without the assumption: the
    caller keeps memory preservation and binds the write to its own slot."""
    from synthetic import CODE_BASE

    callee_entry = CODE_BASE + 0x800
    t = tmp(0x100)
    callee = (FunctionBuilder(entry=callee_entry).ins(load(reg(RAX), const(SLOT, 8)))
              .ins(add(t, reg(RAX), const(displacement)), store(t, reg(RCX))).ret())
    caller = FunctionBuilder().sub_rsp(0x28).call(callee_entry).add_rsp(0x28).ret()
    for imports in (False, True):
        results = analyze_units(program_units(caller, callee), image_info=INFO,
                                assume_globals_disjoint_from_stack=True,
                                assume_import_slots_hold_exports=imports)
        (effect,) = results["1:1000"].proven.values()
        assert effect.preserves_memory and effect.memory_runs, imports
        assert all(run.write.pointer is not None for run in effect.memory_runs), imports


def test_a_wider_read_at_the_import_address_gets_nothing():
    """Only the byte AT the address is known to be in the image (no extent)."""
    t = tmp(0x100)
    function = (FunctionBuilder().sub_rsp(0x40).ins(add(t, reg(RSP), const(0x70)), store(t, reg(RSI)))
                .ins(copy_nothing()).ins(load(reg(RAX), const(SLOT, 8)))
                .ins(add(t, reg(RAX), const(0)), load(reg(RCX, 4), t)).add_rsp(0x40).ret())
    _, normalized = _analyze(function)
    assert _byte_read(normalized).register_bytes & STACK_BYTES


def test_a_displacement_that_moves_with_the_image_base_is_not_at_the_import():
    """q = p + G - G where the first G is a relocated image address and the
    second a fixed number: zero here, not under another load address -- the
    access is base-dependent (recorded), never the import-static byte."""
    from synthetic import CODE_BASE, DATA_SIZE, sub
    from tdo_v2.relative_memory import ImageBaseTracking

    image_address = DATA_BASE + 0x200
    t, u = tmp(0x100), tmp(0x108)
    function = (FunctionBuilder().ins(load(reg(RAX), const(SLOT, 8)))                 # 0
                .ins(add(t, reg(RAX), const(image_address)))                        # 1: relocated
                .ins(sub(u, t, const(image_address)))                               # 2: a fixed number
                .ins(load(reg(RCX, 1), u)).ret())                                   # 3
    relocates = lambda instruction, length, value: instruction == CODE_BASE + 4   # noqa: E731
    with ImageBaseTracking(((CODE_BASE, DATA_BASE + DATA_SIZE),), relocates) as found:
        results = analyze_units(program_units(function), image_info=INFO, assume_globals_disjoint_from_stack=True,
                                assume_import_slots_hold_exports=True)
    normalized = results["1:1000"].normalized
    assert normalized.memory_ssa.function_scope.digest in found
    assert not _reads_import_static(normalized)


def _reads_import_static(normalized) -> bool:
    """Some memory read of the function is the import-static byte of GFlag."""
    from tdo_v2.relative_memory import ImportSlots, import_object_ids

    slots = ImportSlots(INFO)
    slots.active = True
    static = import_object_ids(normalized.memory_ssa.function_scope, slots.atom(1, SLOT), 1)[0]
    return any(read.span.object_id == static for read in normalized.memory_ssa.reads)


def test_the_byte_read_at_the_import_address_is_the_import_static_byte():
    _, normalized = _analyze(_function())
    assert _reads_import_static(normalized)


def test_a_callee_reading_the_slot_at_two_widths_binds_at_the_caller():
    """callee: e = [__imp] (4 bytes); p = [__imp] (8 bytes); [p] = cl (one
    byte: the import-static object); [p + 8] = rcx. Its runs are anchored on
    the 8-byte slot -- never the 4-byte read -- and the caller binds them (no
    unresolved write)."""
    from synthetic import CODE_BASE, RDX

    callee_entry = CODE_BASE + 0x800
    t = tmp(0x100)
    callee = (FunctionBuilder(entry=callee_entry).ins(load(reg(RDX, 4), const(SLOT, 8)))
              .ins(load(reg(RAX), const(SLOT, 8)))
              .ins(store(reg(RAX), reg(RCX, 1)))
              .ins(add(t, reg(RAX), const(8)), store(t, reg(RCX))).ret())
    caller = FunctionBuilder().sub_rsp(0x28).call(callee_entry).add_rsp(0x28).ret()
    for imports in (False, True):
        results = analyze_units(program_units(caller, callee), image_info=INFO,
                                assume_globals_disjoint_from_stack=True,
                                assume_import_slots_hold_exports=imports)
        (effect,) = results["1:1000"].proven.values()
        assert effect.preserves_memory and len(effect.memory_runs) == 2, imports
        assert {(run.write.pointer.size, run.write.displacement) for run in effect.memory_runs} == {(8, 0), (8, 8)}
        normalized = results["1:1000"].normalized
        assert not [row for row in normalized.effects if row.memory_write is not None], imports
