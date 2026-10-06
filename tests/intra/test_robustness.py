"""P0-2: normalization and slicing never crash on well-formed observations.

A deterministic random generator builds straight-line, branching, and looping
functions with partial-width registers, stack and global accesses. Unresolved
inputs must end as debt or ``UnresolvedNormalizedFunction``, never as an
exception.
"""

import random

import pytest

from synthetic import (
    DATA_BASE, R8, R9, RAX, RBX, RCX, RDI, RDX, RSI, RSP, ZF,
    FunctionBuilder, _Instruction, _Provider, add, const, copy, load,
    normalize, op, operation_nodes, reg, slice_from, store, sub, tmp,
)
from tdo_v2._scope_contracts import _mint_orchestrator_capability
from tdo_v2._scope_envelope import open_configured_extraction
from tdo_v2.normalize import (
    FunctionNormalizer,
    NormalizationFailureReason,
    UnresolvedNormalizedFunction,
)

REGS = (RAX, RCX, RDX, RBX, RSI, RDI, R8, R9)


def _pointer(rng):
    if rng.random() < 0.7:
        return reg(rng.choice(REGS))
    return const(DATA_BASE + rng.randint(0, 64))


def _random_function(rng) -> FunctionBuilder:
    builder = FunctionBuilder()
    labels = []
    for index in range(rng.randint(1, 10)):
        if index and rng.random() < 0.15:
            labels.append(f"L{index}")
            builder.label(labels[-1])
        size = rng.choice((1, 2, 4, 8))
        kind = rng.random()
        if kind < 0.2:
            builder.ins(copy(reg(rng.choice(REGS)), reg(rng.choice(REGS))))
        elif kind < 0.35:
            opcode = rng.choice(("INT_ADD", "INT_SUB", "INT_MULT", "INT_AND"))
            builder.ins(op(
                opcode,
                [reg(rng.choice(REGS), size), const(rng.randint(0, 32), size)],
                reg(rng.choice(REGS), size),
            ))
        elif kind < 0.55:
            if rng.random() < 0.3:
                builder.ins(
                    add(tmp(0x100), reg(rng.choice((RSP, RDI))), const(rng.randint(0, 16))),
                    load(reg(rng.choice(REGS), size), tmp(0x100)),
                )
            else:
                builder.ins(load(reg(rng.choice(REGS), size), _pointer(rng)))
        elif kind < 0.75:
            builder.ins(store(_pointer(rng), reg(rng.choice(REGS), size)))
        elif kind < 0.85:
            builder.push(rng.choice(REGS))
        elif kind < 0.92:
            builder.call(0x1800)
        else:
            builder.ins(sub(reg(RSP), reg(RSP), const(8 * rng.randint(1, 4))))
    if labels and rng.random() < 0.7:
        builder.cbranch(rng.choice(labels), reg(ZF, 1))
    return builder.ret(realistic=rng.random() < 0.7)


@pytest.mark.parametrize("chunk", range(10))
def test_random_functions_normalize_and_slice_without_exceptions(chunk):
    for seed in range(chunk * 200, (chunk + 1) * 200):
        function = normalize(_random_function(random.Random(seed)))
        for node in operation_nodes(function, "LOAD") + operation_nodes(function, "RETURN"):
            slice_from(function, node)


def test_unreachable_code_is_a_typed_normalization_failure():
    builder = FunctionBuilder().ins(copy(reg(RAX), reg(RDX))).ret(realistic=False)
    builder._rows.append(_Instruction([copy(reg(RAX), reg(RCX))]))
    builder._rows.append(_Instruction([op("RETURN", [reg(RSP)])], "return"))
    with open_configured_extraction(
        _Provider([builder]), _mint_orchestrator_capability()
    ) as envelope:
        (unit,) = envelope.iter_scoped_functions()
    result = FunctionNormalizer().normalize(unit)
    assert type(result) is UnresolvedNormalizedFunction
    assert result.reason is NormalizationFailureReason.DISCONNECTED_OBSERVED_CFG


def test_engine_failure_is_typed():
    pytest.importorskip("fcntl", reason="engine imports POSIX-only Bundle admission")
    from tdo_v2.engine import UnresolvedBundleFunctionError
    from tdo_v2.scope_identity import AddressCoordinate

    error = UnresolvedBundleFunctionError(
        3,
        AddressCoordinate(1, 0x1000),
        NormalizationFailureReason.DISCONNECTED_OBSERVED_CFG,
    )
    assert isinstance(error, ValueError)
    assert error.index == 3 and error.entry.byte_offset == 0x1000
    assert "at 1:1000" in str(error) and "disconnected_observed_cfg" in str(error)
