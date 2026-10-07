"""Per-point stack escape keeps the graph sound (``may_alias``).

Random call-free functions with a frame (``sub rsp``) store frame addresses
through RDI at random points, reload them into RSI and write or read through
them, mixed with frame and global accesses and a bounded loop. The concrete
interpreter makes RSI really alias the frame after an escape, so every
dependency through such an alias must be in the graph (``graph_oracle``).
"""

import random

import pytest

from graph_oracle import check
from synthetic import (
    DATA_BASE, R9, RAX, RBX, RCX, RDI, RDX, RSI, RSP, SF, FunctionBuilder, add, const, load,
    normalize_with_observation, op, reg, store, sub, tmp,
)

VALUES = (RAX, RBX, RCX, RDX)
POOL = tuple(DATA_BASE + offset for offset in (0, 8, 0x40))
T = tmp(0x100)


def _random_function(rng) -> FunctionBuilder:
    builder = FunctionBuilder().sub_rsp(0x20)
    escaped = False
    labels = []
    for index in range(rng.randint(4, 14)):
        if index and rng.random() < 0.2:
            labels.append(f"L{index}")
            builder.label(labels[-1])
        slot = const(rng.choice((0, 8, 0x10, 0x18)))
        value = reg(rng.choice(VALUES))
        kind = rng.random()
        if kind < 0.2:
            builder.ins(add(T, reg(RSP), slot), store(T, value))
        elif kind < 0.4:
            builder.ins(add(T, reg(RSP), slot), load(value, T))
        elif kind < 0.5:  # escape: the frame address goes to memory
            builder.ins(add(T, reg(RSP), slot), store(reg(RDI), T))
            escaped = True
        elif kind < 0.6 and escaped:
            builder.ins(load(reg(RSI), reg(RDI)))
        elif kind < 0.75:
            builder.ins(store(reg(RSI), value))
        elif kind < 0.85:
            builder.ins(load(value, reg(RSI)))
        elif kind < 0.92:
            builder.ins(store(const(rng.choice(POOL)), value))
        else:
            builder.ins(load(value, const(rng.choice(POOL))))
    if labels and rng.random() < 0.6:
        builder.ins(sub(reg(R9), reg(R9), const(1)),
                    op("INT_NOTEQUAL", [reg(R9), const(0)], reg(SF, 1)))
        builder.cbranch(rng.choice(labels), reg(SF, 1))
    return builder.add_rsp(0x20).ret(realistic=True)


def _inputs(seed):
    rng = random.Random(seed * 104_729 + 3)
    values = {register: rng.randrange(1 << 32) for register in VALUES}
    values[RDI] = rng.choice(POOL)
    values[RSI] = rng.choice(POOL)
    values[RSP] = 0x7000_0000
    values[R9] = 3
    return values


@pytest.mark.parametrize("chunk", range(4))
def test_escaped_frame_aliases_are_in_the_graph(chunk):
    silent, unexplained, runs = [], [], 0
    for seed in range(chunk * 100, (chunk + 1) * 100):
        function, observation = normalize_with_observation(_random_function(random.Random(seed)))
        report = check(function, observation, seeds=range(4), register_pools=_inputs)
        runs += report.runs
        silent += [(seed, item) for item in report.silent]
        unexplained += [(seed, item) for item in report.covered_by_debt]
    assert runs > 0
    assert silent == [], silent[:3]
    assert unexplained == [], unexplained[:3]
