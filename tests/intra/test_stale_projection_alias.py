"""A value read from memory feeds an address or a rep count only if it holds
on the final state (census round 2, Astra's round-2 counterexamples): here
the slot is rewritten through q = *(rdi*rdi), a pointer with no address
expression -- its write gets a definition atom (a wild object), so it is no
longer pending, yet it may land on the slot. The final validation
(``normalize``: ``relative_memory.stale_reads`` + the read's may-alias debt)
refuses the slot's value. Concrete runs: rdi*rdi points at the slot."""

import random

import pytest

from graph_oracle import check
from synthetic import (
    R9, RAX, RBX, RCX, RDI, RSI, RSP, FunctionBuilder, add, const, copy, load, op, operation_node_at,
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


@pytest.mark.xfail(strict=True, reason="open (census round 2): an uncertain-address writer of the root "
                   "function itself is not a debt for root slices -- design in progress")
def test_a_slot_rewritten_through_a_wild_pointer_is_not_used():
    reload, report = _run(_pointer_program(), 7)
    assert set(range(RSI, RSI + 8)) <= reload.register_bytes or not reload.is_complete
    assert report.runs and report.silent == []


def test_a_rep_count_rewritten_through_a_wild_pointer_is_not_used():
    builder, instruction = _count_program()
    reload, report = _run(builder, instruction)
    assert RSI in reload.register_bytes or not reload.is_complete
    assert report.runs and report.silent == []
