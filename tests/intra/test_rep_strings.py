"""x86 rep movs/stos as block effects (``tdo_v2.rep_strings``).

The instructions use Ghidra 12's exact lifting (ia.sinc). The concrete
interpreter runs the real in-instruction loop and keys iteration i >= 1 of
the element LOAD/STORE ``<key>~e<i>``, as the engine names its element rows;
``graph_oracle`` checks every dynamic dependency (and control dependence).
"""

import random

import pytest

from graph_oracle import check, check_control
from synthetic import (
    CODE_BASE, DATA_BASE, R8, R9, RAX, RBX, RCX, RDI, RDX, RSI, RSP, FunctionBuilder, add, const, copy, load,
    op, operation_node_at, program_units, ram, reg, slice_from, store, tmp,
)
from tdo_v2.normalize import FunctionNormalizer
from tdo_v2.rep_strings import recognize

DF = 0x20A


def _pointer(register, size, base):
    td, a, z, m = tmp(base, 8), tmp(base + 8, 8), tmp(base + 16, 8), tmp(base + 24, 8)
    return td, [
        copy(td, reg(register)),
        add(a, reg(register), const(size)),
        op("INT_ZEXT", [reg(DF, 1)], z),
        op("INT_MULT", [const(2 * size), z], m),
        op("INT_SUB", [a, m], reg(register)),
    ]


def _rep(index, kind="movs", size=1):
    """Ghidra 12 ``rep movs``/``rep stos`` at instruction ``index`` (stride 4)."""
    here, after = CODE_BASE + 4 * index, CODE_BASE + 4 * (index + 1)
    test = tmp(0x26800, 1)
    ops = [op("INT_EQUAL", [reg(RCX), const(0)], test), op("CBRANCH", [ram(after), test]),
           op("INT_SUB", [reg(RCX), const(1)], reg(RCX))]
    td, dst = _pointer(RDI, size, 0x22300)
    ops += dst
    if kind == "movs":
        ts, src = _pointer(RSI, size, 0x20b00)
        ops += src
        value = tmp(0x21000, size)
        ops += [load(value, ts), copy(tmp(0x22800, size), value)]
    else:
        ops += [copy(tmp(0x22800, size), reg(RAX, size))]
    ops += [store(td, tmp(0x22800, size)), op("BRANCH", [ram(here)])]
    return ops


def _function(count, kind="movs", source_offset=0x20, destination_offset=0x40, direction=0, size=1):
    """Stack bytes [rsp+0x20..0x30) = rbx, rdx; rep copy/fill; r8/r9 read the destination."""
    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x60)
               .ins(add(t, reg(RSP), const(0x20)), store(t, reg(RBX)))
               .ins(add(t, reg(RSP), const(0x28)), store(t, reg(RDX)))
               .ins(add(reg(RSI), reg(RSP), const(source_offset)))
               .ins(add(reg(RDI), reg(RSP), const(destination_offset)))
               .ins(copy(reg(RCX), const(count)) if type(count) is int else copy(reg(RCX), reg(count[1]))))
    if direction is not None:
        builder.ins(copy(reg(DF, 1), const(direction, 1)))      # cld / std
    else:
        builder.ins(copy(reg(R8), reg(R8)))                     # DF: the entry value
    index = len(builder._rows)
    builder.ins(*_rep(index, kind, size))
    builder.ins(add(t, reg(RSP), const(destination_offset)), load(reg(R8), t))
    builder.ins(add(t, reg(RSP), const(destination_offset + 8)), load(reg(R9), t))
    return builder.add_rsp(0x60).ret(), index


def _normalize(builder, assume=False):
    (unit,) = program_units(builder)
    return FunctionNormalizer().normalize(unit, assume_direction_flag_clear=assume), unit.observation


def test_recognizes_ghidra_lifting():
    (unit,) = program_units(_function(16)[0])
    sites = [recognize(row) for row in unit.observation.instructions]
    (site,) = [item for item in sites if item is not None]
    assert site.size == 1 and site.source is not None
    builder, _ = _function(16, kind="stos")
    (unit,) = program_units(builder)
    assert [recognize(row) for row in unit.observation.instructions if recognize(row)][0].source is None


def test_constant_copy_is_exact():
    """memcpy(rsp+0x40, rsp+0x20, 16): r8 = rbx's bytes, r9 = rdx's."""
    builder, index = _function(16)
    function, observation = _normalize(builder)
    assert function.rep_blocks and function.rep_blocks[0][1:] == (16, 1)
    first = slice_from(function, operation_node_at(function, index + 1, 1))
    second = slice_from(function, operation_node_at(function, index + 2, 1))
    assert first.is_complete and set(range(RBX, RBX + 8)) <= first.register_bytes
    assert not first.register_bytes & set(range(RDX, RDX + 8))
    assert second.is_complete and set(range(RDX, RDX + 8)) <= second.register_bytes


def test_direction_from_the_entry_needs_the_assumption():
    builder, _ = _function(16, direction=None)
    function, _ = _normalize(builder)
    assert not function.rep_blocks and not function.assumed_direction_flag_clear
    function, _ = _normalize(builder, assume=True)
    assert function.rep_blocks and function.assumed_direction_flag_clear


def test_unknown_count_keeps_the_access_unknown():
    builder, index = _function(("register", RBX))
    function, _ = _normalize(builder)
    assert not function.rep_blocks
    assert not slice_from(function, operation_node_at(function, index + 1, 1)).is_complete


def _pools(seed):
    rng = random.Random(seed)
    return {RSP: 0x7000_0000, RBX: rng.getrandbits(64), RDX: rng.getrandbits(64), RAX: rng.getrandbits(8),
            R8: 0, DF: 0}


@pytest.mark.parametrize("count", [0, 1, 2, 5, 16])
@pytest.mark.parametrize("kind", ["movs", "stos"])
@pytest.mark.parametrize("layout", [(0x20, 0x40), (0x20, 0x21), (0x21, 0x20), (0x20, 0x20)])
@pytest.mark.parametrize("direction", [0, 1])
def test_dynamic_dependencies_are_in_the_graph(count, kind, layout, direction):
    """Overlapping source/destination in both orders, both directions."""
    source, destination = layout
    if direction:  # std: the block ends at the start offset
        source, destination = source + 16, destination + 16
    builder, _ = _function(count, kind, source, destination, direction)
    function, observation = _normalize(builder)
    report = check(function, observation, seeds=range(3), register_pools=_pools)
    assert report.runs and report.silent == [], report.silent[:2]
    assert check_control(function, observation, seeds=range(2), register_pools=_pools) == []


def test_unknown_count_is_never_silent():
    builder, _ = _function(("register", R9))
    function, observation = _normalize(builder)
    pools = lambda seed: {**_pools(seed), R9: seed % 7}
    report = check(function, observation, seeds=range(6), register_pools=pools)
    assert report.runs and report.silent == []


def test_entry_direction_under_the_assumption_when_it_holds():
    builder, _ = _function(9, direction=None)
    function, observation = _normalize(builder, assume=True)
    report = check(function, observation, seeds=range(3), register_pools=_pools)  # DF = 0 at entry
    assert report.runs and report.silent == []
