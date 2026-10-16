"""Synthetic functions for large-function work (docs 25.30, step A-5): each
builder returns a ``FunctionBuilder``; ``FIXTURES`` names the instances the
semantic snapshots and the benchmark use. ``per`` operations per instruction
keep functions inside the synthetic code range (1,024 instructions)."""

from __future__ import annotations

from synthetic import (
    CF, R8, R9, RAX, RBX, RCX, RDI, RDX, RSI, RSP, ZF, FunctionBuilder, add, const, copy, load, op, reg, store,
    tmp,
)

REGS = (RAX, RCX, RDX, RBX, RSI, RDI, R8, R9)


def chain(length, per=8):
    """rax += 1, ``length`` times: one chain of dependent values."""
    builder = FunctionBuilder()
    left = length
    while left:
        count = min(per, left)
        builder.ins(*[add(reg(RAX), reg(RAX), const(1)) for _ in range(count)])
        left -= count
    return builder.ret()


def chain_in_loop(length, per=8):
    """A loop whose body is a chain of ``length`` dependent values carried
    around the back edge (a cycle longer than any depth threshold)."""
    builder = FunctionBuilder().label("top")
    left = length
    while left:
        count = min(per, left)
        builder.ins(*[add(reg(RAX), reg(RAX), const(1)) for _ in range(count)])
        left -= count
    flag = tmp(0x300, 1)
    builder.ins(op("INT_SUB", [reg(R9), const(1)], reg(R9)))
    builder.cbranch("top", flag, op("INT_NOTEQUAL", [reg(R9), const(0)], flag))
    return builder.ins(copy(reg(R8), reg(RAX))).ret()


def loop_mixed_spans(rounds):
    """A loop writing al, then rax, then eax: JOIN cycles of mixed spans."""
    builder = FunctionBuilder().label("top")
    for index in range(rounds):
        builder.ins(add(reg(RAX, 1), reg(RAX, 1), const(index % 7 + 1)))
        builder.ins(add(reg(RAX), reg(RAX), reg(RCX)))
        builder.ins(add(reg(RAX, 4), reg(RAX, 4), const(3)))
    flag = tmp(0x300, 1)
    builder.cbranch("top", flag, op("INT_NOTEQUAL", [reg(R9), const(0)], flag))
    return builder.ins(copy(reg(R8), reg(RAX))).ret()


def diamonds(count):
    """``count`` if / else in a row, each arm adding a different constant to
    rax: JOINs of JOINs, 2**count paths."""
    builder = FunctionBuilder()
    for index in range(count):
        flag = tmp(0x300, 1)
        builder.cbranch(f"else{index}", flag, op("INT_EQUAL", [reg(REGS[index % 8], 1), const(index % 3, 1)], flag))
        builder.ins(add(reg(RAX), reg(RAX), const(1))).branch(f"join{index}")
        builder.label(f"else{index}").ins(add(reg(RAX), reg(RAX), const(2)))
        builder.label(f"join{index}")
    return builder.ins(copy(reg(R8), reg(RAX))).ret()


def wide(values):
    """``values`` independent computations cycling over the registers (many
    short chains)."""
    builder = FunctionBuilder()
    rows = []
    for index in range(values):
        register = REGS[index % 8]
        rows.append(op("INT_XOR", [reg(register), const(index & 0xFFFF)], reg(register)))
        if len(rows) == 8:
            builder.ins(*rows)
            rows = []
    if rows:
        builder.ins(*rows)
    return builder.ret()


def pointer_accesses(count):
    """[rdi + 8i] = rsi + i, then r8 = [rdi + 8j]: many accesses through one
    pointer (memory SSA and may-alias growth)."""
    builder = FunctionBuilder()
    address = tmp(0x100)
    value = tmp(0x200)
    for index in range(count):
        builder.ins(add(address, reg(RDI), const(8 * index)), add(value, reg(RSI), const(index)),
                    store(address, value))
    for index in range(0, count, max(1, count // 16)):
        builder.ins(add(address, reg(RDI), const(8 * index)), load(reg(R8), address))
    return builder.ret()


def stack_spills(count):
    """Spill / reload through the frame: rsp-relative stores and loads in a
    chain (the stack-pointer evaluation and frame objects)."""
    builder = FunctionBuilder().sub_rsp(0x400)
    slot = tmp(0x180)
    for index in range(count):
        offset = 8 * (index % 64)
        builder.ins(add(slot, reg(RSP), const(offset)), store(slot, reg(RAX)),
                    add(slot, reg(RSP), const(offset)), load(reg(RAX), slot),
                    add(reg(RAX), reg(RAX), const(1)))
    return builder.add_rsp(0x400).ret()


# name -> (builder, arguments); "baseline" fixtures run at the baseline too,
# "beyond" ones need independently known expected values
FIXTURES = {
    "chain-1k": (chain, (1000,)),
    "chain-5k": (chain, (5000,)),
    "chain-in-loop-600": (chain_in_loop, (600,)),
    "loop-mixed-spans-40": (loop_mixed_spans, (40,)),
    "diamonds-12": (diamonds, (12,)),
    "diamonds-30": (diamonds, (30,)),
    "wide-6k": (wide, (6000,)),
    "pointer-accesses-300": (pointer_accesses, (300,)),
    "stack-spills-200": (stack_spills, (200,)),
}
BEYOND = {
    "chain-8k": (chain, (8000,)),
}


def build(name):
    builder, arguments = {**FIXTURES, **BEYOND}[name]
    return builder(*arguments)
