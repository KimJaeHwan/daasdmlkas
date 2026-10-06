"""Graph fidelity: every dynamic dependency of a call-free function is in the graph.

A concrete interpreter (``pcode_interpreter``) executes random call-free
functions on random inputs, with pointer registers drawn from a small pool so
that different pointers often alias. Every "operation W wrote a byte that
operation R read" observed at run time must be a backward path R -> W in the
static graph (``graph_oracle``); entry-state reads must reach an observed
input. A missing path is a silent hole in the graph.
"""

import random

import pytest

from graph_oracle import check
from synthetic import (
    CF, DATA_BASE, OF, R8, R9, RAX, RBX, RCX, RDI, RDX, RSI, RSP, SF, ZF,
    CODE_BASE, FunctionBuilder, add, const, copy, load, normalize_with_observation, op,
    ram, reg, store, sub, tmp,
)

REGS = (RAX, RCX, RDX, RBX, RSI, RDI, R8, R9)
POINTERS = (RDI, RSI, RDX, R8)
POOL = tuple(DATA_BASE + offset for offset in (0, 8, 1, 4, 0x40))


def _register_inputs(seed):
    rng = random.Random(seed * 7919 + 17)
    values = {register: rng.choice(POOL) for register in REGS}
    values[RSP] = 0x7000_0000
    for flag in (ZF, CF):  # force both branch directions to occur
        values[flag] = rng.randrange(2)
    return values


def _cmov(rng, next_address=None):
    """cmovcc: a CBRANCH skips one register write inside a single instruction.

    Ghidra uses either a relative ``CBRANCH +2`` or ``CBRANCH <next
    instruction>`` (the form seen in real MinGW code).
    """
    size = rng.choice((4, 8))
    flag = rng.choice((ZF, CF))
    destination = const(2, 8) if next_address is None else ram(next_address)
    return [
        op("BOOL_NEGATE", [reg(flag, 1)], tmp(0x200, 1)),
        op("CBRANCH", [destination, tmp(0x200, 1)]),
        copy(reg(rng.choice(REGS), size), reg(rng.choice(REGS), size)),
    ]


def _random_value_op(rng):
    size = rng.choice((1, 2, 4, 8))
    out = reg(rng.choice(REGS), size)
    left = reg(rng.choice(REGS), size)
    kind = rng.random()
    if kind < 0.15:
        return copy(out, left)
    if kind < 0.35:
        opcode = rng.choice(("INT_ADD", "INT_SUB", "INT_AND", "INT_OR", "INT_XOR", "INT_MULT"))
        return op(opcode, [left, const(rng.randint(0, 0x30), size)], out)
    if kind < 0.45:
        return op(rng.choice(("INT_ADD", "INT_XOR")), [left, reg(rng.choice(REGS), size)], out)
    if kind < 0.6 and size < 8:
        wide = rng.choice(tuple(s for s in (2, 4, 8) if s > size))
        return op(rng.choice(("INT_ZEXT", "INT_SEXT")), [left], reg(rng.choice(REGS), wide))
    if kind < 0.7 and size > 1:
        part = rng.choice(tuple(s for s in (1, 2, 4) if s < size))
        shift = rng.randrange(0, size - part + 1)
        return op("SUBPIECE", [left, const(shift, 4)], reg(rng.choice(REGS), part))
    if kind < 0.8 and size <= 4:
        return op("PIECE", [left, reg(rng.choice(REGS), size)], reg(rng.choice(REGS), 2 * size))
    return op(rng.choice(("INT_LEFT", "INT_RIGHT", "INT_SRIGHT")),
              [left, const(rng.randint(0, 9), 1)], out)


def _random_memory_ops(rng):
    size = rng.choice((1, 2, 4, 8))
    pointer = rng.choice(POINTERS)
    kind = rng.random()
    address = reg(pointer)
    pre = []
    if kind < 0.3:
        pre = [add(tmp(0x100), reg(pointer), const(rng.choice((0, 1, 4, 8))))]
        address = tmp(0x100)
    elif kind < 0.4:
        address = const(rng.choice(POOL))
    elif kind < 0.5:  # pointer loaded from memory (unknown base)
        pre = [load(tmp(0x110), reg(pointer))]
        address = tmp(0x110)
    elif kind < 0.55:  # non-affine address
        pre = [op("INT_AND", [reg(pointer), const(0xFFFFFFFFFFFFFFF8)], tmp(0x120))]
        address = tmp(0x120)
    if rng.random() < 0.5:
        return [*pre, store(address, reg(rng.choice(REGS), size))]
    return [*pre, load(reg(rng.choice(REGS), size), address)]


def _random_function(rng) -> FunctionBuilder:
    builder = FunctionBuilder()
    labels = []
    loop_used = False
    for index in range(rng.randint(2, 12)):
        if index and rng.random() < 0.15:
            labels.append(f"L{index}")
            builder.label(labels[-1])
        kind = rng.random()
        if kind < 0.4:
            builder.ins(_random_value_op(rng))
        elif kind < 0.75:
            builder.ins(*_random_memory_ops(rng))
        elif kind < 0.8:
            next_address = CODE_BASE + 4 * (len(builder._rows) + 1)
            builder.ins(*_cmov(rng, next_address if rng.random() < 0.5 else None))
        elif kind < 0.85:
            builder.push(rng.choice(REGS))
        elif kind < 0.9:
            builder.pop(rng.choice(REGS))
        else:
            size = rng.choice((1, 4, 8))
            builder.ins(
                op("INT_EQUAL", [reg(rng.choice(REGS), size), const(rng.randint(0, 3), size)],
                   reg(ZF, 1)),
                op("INT_LESS", [reg(rng.choice(REGS), size), const(8, size)], reg(CF, 1)),
            )
        if labels and not loop_used and rng.random() < 0.1:
            # bounded counter loop back to an earlier label
            loop_used = True
            builder.ins(sub(reg(R9), reg(R9), const(1)),
                        op("INT_NOTEQUAL", [reg(R9), const(0)], reg(SF, 1)))
            builder.cbranch(rng.choice(labels), reg(SF, 1))
    if labels and rng.random() < 0.5:
        builder.cbranch(rng.choice(labels), reg(rng.choice((ZF, CF, OF)), 1))
    return builder.ret(realistic=rng.random() < 0.7)


def _inputs_with_bounded_loop(seed):
    values = _register_inputs(seed)
    values[R9] = 3  # loop counter
    return values


@pytest.mark.parametrize("chunk", range(8))
def test_dynamic_dependencies_are_in_the_graph(chunk):
    silent, unexplained, runs = [], [], 0
    for seed in range(chunk * 60, (chunk + 1) * 60):
        builder = _random_function(random.Random(50_000 + seed))
        function, observation = normalize_with_observation(builder)
        report = check(function, observation, seeds=range(6),
                       register_pools=_inputs_with_bounded_loop)
        runs += report.runs
        silent += [(seed, item) for item in report.silent]
        unexplained += [(seed, item) for item in report.covered_by_debt]
    assert runs > 0
    assert silent == [], silent[:3]
    assert unexplained == [], unexplained[:3]


def test_conditional_move_keeps_the_old_value():
    """cmovz rax, rdx; rcx = rax: both RDX and the old RAX are origins."""
    builder = (
        FunctionBuilder()
        .ins(*_cmov_fixed())
        .ins(copy(reg(RCX), reg(RAX)))
        .ret()
    )
    function, observation = normalize_with_observation(builder)
    report = check(function, observation, seeds=range(8),
                   register_pools=lambda seed: {RSP: 0x7000_0000, ZF: seed % 2})
    assert report.runs == 8 and not report.silent and not report.covered_by_debt


def _cmov_fixed(next_address=None):
    destination = const(2, 8) if next_address is None else ram(next_address)
    return [
        op("BOOL_NEGATE", [reg(ZF, 1)], tmp(0x200, 1)),
        op("CBRANCH", [destination, tmp(0x200, 1)]),
        copy(reg(RAX), reg(RDX)),
    ]


def test_conditional_move_to_next_instruction_keeps_the_old_value():
    """Ghidra's real cmovcc shape: CBRANCH <next instruction>; COPY."""
    builder = (
        FunctionBuilder()
        .ins(*_cmov_fixed(next_address=CODE_BASE + 4))
        .ins(copy(reg(RCX), reg(RAX)))
        .ret()
    )
    function, observation = normalize_with_observation(builder)
    report = check(function, observation, seeds=range(8),
                   register_pools=lambda seed: {RSP: 0x7000_0000, ZF: seed % 2})
    assert report.runs == 8 and not report.silent and not report.covered_by_debt


def test_in_instruction_loop_is_a_typed_failure():
    """A backward p-code branch (REP-style) cannot be modelled per instruction."""
    from synthetic import _Provider
    from tdo_v2._scope_contracts import _mint_orchestrator_capability
    from tdo_v2._scope_envelope import open_configured_extraction
    from tdo_v2.normalize import (
        FunctionNormalizer, NormalizationFailureReason, UnresolvedNormalizedFunction,
    )

    builder = (
        FunctionBuilder()
        .ins(sub(reg(RCX), reg(RCX), const(1)),
             op("INT_NOTEQUAL", [reg(RCX), const(0)], tmp(0x200, 1)),
             op("CBRANCH", [const((-2) & 0xFFFFFFFFFFFFFFFF, 8), tmp(0x200, 1)]))
        .ret()
    )
    with open_configured_extraction(_Provider([builder]), _mint_orchestrator_capability()) as env:
        (unit,) = env.iter_scoped_functions()
    result = FunctionNormalizer().normalize(unit)
    assert type(result) is UnresolvedNormalizedFunction
    assert result.reason is NormalizationFailureReason.UNSUPPORTED_INTRA_INSTRUCTION_FLOW


def test_aliasing_pointers_are_connected():
    """*(RDI) = RDX; RAX = *(RSI) with RDI == RSI at run time."""
    builder = FunctionBuilder().ins(store(reg(RDI), reg(RDX))).ins(load(reg(RAX), reg(RSI))).ret()
    function, observation = normalize_with_observation(builder)
    report = check(function, observation, seeds=range(1),
                   register_pools=lambda seed: {RDI: DATA_BASE, RSI: DATA_BASE, RSP: 0x7000_0000})
    assert report.runs == 1 and not report.silent and not report.covered_by_debt
