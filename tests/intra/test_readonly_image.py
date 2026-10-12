"""Named assumption readonly-image-data-is-constant (``image_info.ReadOnlyImage``).

MinGW reaches a global through a read-only pointer slot (``.refptr.g``):
``rax = [slot]; [rax] ^= x``. With the slot's image value the write is a
write to the global itself, so (with globals-disjoint-from-stack) it cannot
alias a stack local; without it, the pointer may point anywhere.
"""

from graph_oracle import check
from synthetic import (
    DATA_BASE, RAX, RBX, RDX, RSP, R9, FunctionBuilder, add, const, load, operation_node_at,
    program_units, reg, slice_from, store, tmp,
)
from tdo_v2.normalize import FunctionNormalizer

SLOT = DATA_BASE + 0x100        # read-only pointer slot
GLOBAL = DATA_BASE + 0x40       # the global it points to


class _Image:
    """A read-only slot holding GLOBAL (8 bytes, little endian)."""

    def value(self, space_id, offset, size):
        if offset == SLOT and size == 8:
            return GLOBAL
        return None


def _function():
    t = tmp(0x100)
    return (FunctionBuilder().sub_rsp(0x20)
            .ins(add(t, reg(RSP), const(0x28)), store(t, reg(RBX)))      # home slot (caller frame) = rbx
            .ins(load(reg(RAX), const(SLOT)))                             # rax = [.refptr.g]
            .ins(store(reg(RAX), reg(RDX)))                               # g = rdx
            .ins(add(t, reg(RSP), const(0x28)), load(reg(R9), t))        # r9 = home slot
            .add_rsp(0x20).ret())


def _normalize(readonly):
    (unit,) = program_units(_function())
    return FunctionNormalizer().normalize(unit, assume_globals_disjoint_from_stack=True,
                                          readonly_image=_Image() if readonly else None), unit


def test_readonly_slot_makes_the_write_a_global_write():
    function, _ = _normalize(readonly=True)
    assert function.assumes_readonly_image_constant
    result = slice_from(function, operation_node_at(function, 4, 1))
    assert result.is_complete and not result.reaches(RDX)
    assert set(range(RBX, RBX + 8)) <= result.register_bytes


def test_without_the_assumption_the_pointer_may_alias_the_local():
    function, _ = _normalize(readonly=False)
    result = slice_from(function, operation_node_at(function, 4, 1))
    assert not result.is_complete and result.reaches(RDX)


def test_dynamic_runs_agree_when_the_image_holds_the_pointer():
    function, unit = _normalize(readonly=True)
    image = {(1, SLOT + index): (GLOBAL >> (8 * index)) & 0xFF for index in range(8)}
    report = check(function, unit.observation, seeds=range(6),
                   register_pools=lambda seed: {RSP: 0x7000_0000, RBX: seed, RDX: 7 * seed},
                   image=lambda space, address: image.get((space, address)))
    assert report.runs and report.silent == []


def test_import_slots_are_not_image_constants():
    """The loader writes the import address table: a read of an import slot
    (or of bytes overlapping one) is not the image value at run time."""
    from tdo_v2.image_info import BlockPermissions, ImageInfo, ImportedSymbol, ReadOnlyImage

    block = BlockPermissions(1, 0x1000, 0x100, ".rdata", True, False, False, False, True)
    info = ImageInfo("pe", (block,), (ImportedSymbol("CORE.DLL", "GData", None, ((1, 0x1040),), ()),), (), ())
    image = ReadOnlyImage.__new__(ReadOnlyImage)
    image._info = info
    for offset, size in ((0x1040, 8), (0x1044, 4), (0x103c, 8)):
        assert image.value(1, offset, size) is None
