"""Scale fixtures (docs 25.30 K2): a deterministic, seeded, x64-MSVC-like
large function and its callee closure, for measuring how each analysis phase
grows. ``realistic(ops, seed, **knobs)`` returns a ``ScaleProgram``: the
builders (the caller at the large layout's code base, callee bodies after it),
the symbol names of named targets (bodies or not), the boundary provider, the
embedded probes with their expected answers, and the actual structural counts.

Knobs are per MACHINE INSTRUCTION (``calls`` = call sites per instruction ...).
Two series: "scaled" (call sites, distinct targets and bodies grow with the
size: targets = ceil(0.33 x call sites), bodies 12 % of targets) and
"target-closure" (exactly ``targets`` distinct targets, e.g. 980 at 250k).
Nothing is clamped silently: the counts actually built are reported."""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

from synthetic import (
    CF, LARGE_LAYOUT, OF, R8, R9, RAX, RBX, RCX, RDI, RDX, RSI, RSP, ZF, FunctionBuilder, add, boundary, const, copy,
    load, op, ram, reg, store, sub, tmp,
)

R10, R11, R12, R13, R14, R15 = 0x90, 0x98, 0xA0, 0xA8, 0xB0, 0xB8
DF = 0x20A
SWI = 16   # CALLOTHER index of x86 swi (int n): int 0x29 = __fastfail (a pcodeop model names it)

# per machine instruction, the "target" proportions (estimated from the
# audited function: ~1 call per 15 instructions, ~1 conditional per 6,
# ~35 % memory operations)
DEFAULTS = dict(
    calls=1 / 15, branches=1 / 6, memory=0.35, loops=1 / 400, chain=0.15,
    fields=8, growing_fields=False, mixed_widths=True,
    escapes=0.0, unknown_stores=0.0, two_pointer=0.1, fanin=0.0, fanin_arms=64,
    rep=0.0, traps=0.0, resolvable_indirect=0.0, vtable=0.15, recursion=False,
    sinks=0.02, callee_size=8, multi_exit=0.2,
    targets_per_site=0.33, bodies_share=0.12, targets=None,
)
SOURCE, SOURCE_B, SINK, SINK1 = "tdo_source", "tdo_source_b", "tdo_sink", "tdo_sink1"
RODATA_OFFSET, RODATA_VALUE = 0x40, 0x48   # a read-only image constant the probe folds


@dataclass
class Probe:
    name: str
    sink: str                    # sink symbol
    occurrence: int              # the function's call-seed index of the sink call (-1: projected)
    labels: frozenset            # expected origin labels
    complete: bool | None        # expected path completeness (None: not asserted)
    function: int = 0            # the entry of the function holding the root
    base: int = 0                # projected: the function's call-seed count (projected rows follow)


@dataclass
class ScaleProgram:
    functions: list
    names: dict
    provider: object
    probes: list
    knobs: dict
    counts: dict = field(default_factory=dict)
    caller_entry: int = 0
    layout: object = None
    data: bytes = b""

    def pcodeop_models(self, evidences):
        """The swi trap model (int 0x29 = __fastfail never returns) for this
        program's language (debug-break-traps-do-not-return)."""
        from tdo_v2.pcodeop_models import PcodeOpModel

        namespace = evidences[0].unit.scopes.program.evidence.translation_namespace
        return (PcodeOpModel("x86-markers", 1, frozenset({(namespace.language_id, namespace.major_version,
                                                             namespace.minor_version)}), {},
                             {SWI: frozenset({3, 0x29})}),)


class _Gen:
    def __init__(self, seed, knobs, layout):
        self.rng = random.Random(seed)
        self.k = knobs
        self.layout = layout
        self.caller = FunctionBuilder(entry=layout.code_base)
        self.labels = 0
        self.sites = 0            # call sites in the caller (CALL + CALLIND)
        self.sink_sites = 0
        self.call_index = 0       # call-seed ordinal (direct and indirect calls, in order)
        self.probes: list[Probe] = []
        self.field_count = 0
        self.temp = 0x1000
        self.used: set = set()          # call targets actually referenced by the caller
        self.queue: list = []           # targets every call takes once first (coverage), then random

    # -- small helpers --------------------------------------------------------
    def label(self, stem):
        self.labels += 1
        return f"{stem}{self.labels}"

    def t(self, size=8):
        self.temp += 0x10
        if self.temp > 0x1F000:
            self.temp = 0x1000
        return tmp(self.temp, size)

    def field(self):
        if self.k["growing_fields"]:
            self.field_count += 1
            return 8 * self.field_count
        return 8 * self.rng.randrange(self.k["fields"])

    def width(self):
        return self.rng.choice((1, 4, 8)) if self.k["mixed_widths"] else 8

    def call(self, target):
        self.caller.call(target)
        self.sites += 1
        self.call_index += 1
        self.used.add(target)

    def pick(self, pool):
        """The next call target: the coverage queue first, then random."""
        if self.queue:
            return self.queue.pop()
        return self.rng.choice(pool)

    def call_indirect(self, register):
        self.caller.call_indirect(register)
        self.sites += 1
        self.call_index += 1


def realistic(ops: int, seed: int = 0, *, series: str = "scaled", layout=LARGE_LAYOUT, probes: bool = True,
              **overrides) -> ScaleProgram:
    knobs = {**DEFAULTS, **overrides}
    unknown = set(overrides) - set(DEFAULTS)
    if unknown:
        raise ValueError(f"unknown knobs {sorted(unknown)}")
    gen = _Gen(seed, knobs, layout)
    rng = gen.rng
    b = gen.caller
    instructions = max(64, round(ops / 4.6))    # ~4.6 p-code ops per instruction (x64 with flags; the
    # actual count is reported)
    sites = max(4, round(instructions * knobs["calls"]))
    if series == "target-closure":
        if knobs["targets"] is None:
            raise ValueError("target-closure needs targets=")
        targets = knobs["targets"]
    else:
        targets = max(2, math.ceil(knobs["targets_per_site"] * sites))
    bodies = max(2, round(targets * knobs["bodies_share"]))   # (the accessor and the sink caller at least)

    # addresses: caller at the code base; bodies after it; opaque / named targets at the top
    body_base = layout.code_base + 4 * (instructions * 3 + 4096)
    opaque_base = layout.code_base + layout.code_size - 16 * (targets + 64)
    names = {}
    sink_at, sink1_at = opaque_base, opaque_base + 16
    names.update({sink_at: SINK, sink1_at: SINK1})
    opaque = [opaque_base + 16 * (3 + index) for index in range(targets - bodies)]
    callees, callee_kinds = _callees(knobs, rng, body_base, bodies, sink_at)
    for index, callee in enumerate(callees):
        names[callee.entry] = f"callee_{index}"
    # the probes' sources have bodies (rax = a constant): summarized, so their
    # roots can be complete; the leaker stores its rcx at [rdx] (an escape when
    # rcx is a frame address)
    tail = callees[-1].entry + 4 * (len(callees[-1]._rows) + 16) if callees else body_base
    source_body = FunctionBuilder(entry=tail).ins(copy(reg(RAX), const(0x1111))).ret()
    source_b_body = FunctionBuilder(entry=tail + 0x40).ins(copy(reg(RAX), const(0x2222))).ret()
    leaker = FunctionBuilder(entry=tail + 0x80).ins(store(reg(RDX), reg(RCX))).ret()
    sink_body = FunctionBuilder(entry=sink_at).ret()
    sink1_body = FunctionBuilder(entry=sink1_at).ret()
    source_at, source_b_at = source_body.entry, source_b_body.entry
    names.update({source_at: SOURCE, source_b_at: SOURCE_B, leaker.entry: "tdo_leaker"})
    extra = [source_body, source_b_body, leaker, sink_body, sink1_body]
    # coverage: every body (but the sink caller) and every opaque target is
    # called once before the random choice starts (the queue pops from the end)
    gen.queue = [c.entry for c, kind in zip(callees, callee_kinds) if kind not in ("sink_caller", "recursive")] \
        + list(opaque)
    rng.shuffle(gen.queue)
    recursive = [c.entry for c, kind in zip(callees, callee_kinds) if kind == "recursive"]
    gen.queue += recursive[:1]   # (the recursive pair is reached through its first member)

    # prologue: non-volatiles, frame, this -> rbx
    for register in (RBX, RSI, RDI, R12):
        b.push(register)
    b.sub_rsp(0x200)
    b.ins(copy(reg(RBX), reg(RCX)))             # this
    b.ins(copy(reg(RSI), reg(RDX)))

    if probes:
        extra.append(_escape_helper(gen, leaker.entry + 0x40, source_at, source_b_at, leaker.entry, sink_at,
                                    layout))
    # segments until the caller holds ~``ops`` p-code ops (the probes and the
    # epilogue add a fixed ~300); the instruction count is whatever results
    budget = ops - (300 if probes else 40)
    weights = _weights(knobs)
    counted, total = 0, 0
    while total < budget:
        kind = rng.choices(list(weights), list(weights.values()))[0]
        _SEGMENTS[kind](gen, callees, callee_kinds, opaque, sink_at, source_at)
        for row in b._rows[counted:]:
            total += len(row.ops) + (1 if row.kind in ("cbranch", "branch") else 0)
        counted = len(b._rows)
    while gen.queue:   # coverage: targets the random segments did not reach yet (counted in the ops)
        _call(gen, callees, callee_kinds, opaque, sink_at, source_at)

    if probes:
        _emit_probes(gen, callees, callee_kinds, source_at, sink_at, sink1_at, opaque,
                     source_b_at=source_b_at, leaker_at=leaker.entry, layout=layout)

    # epilogue (one shared exit; early returns are in the segments)
    b.label("exit")
    b.add_rsp(0x200)
    for register in (R12, RDI, RSI, RBX):
        b.pop(register)
    b.ret()
    provider = boundary(sources={SOURCE: 8, SOURCE_B: 8}, sinks={SINK: 8, SINK1: 1})
    data = bytearray(layout.data_size)
    data[RODATA_OFFSET:RODATA_OFFSET + 8] = RODATA_VALUE.to_bytes(8, "little")   # (in .rdata: r--)
    program = ScaleProgram([b, *callees, *extra], names, provider, gen.probes,
                           {**knobs, "series": series, "seed": seed}, caller_entry=layout.code_base,
                           layout=layout, data=bytes(data))
    for probe in program.probes:
        if probe.occurrence < 0:
            probe.base = gen.sites   # (the caller has no tail calls)
    program.counts = _counts(program, sites=gen.sites, targets=len(gen.used), bodies=bodies)
    program.counts["target_pool"] = targets
    # the targets the caller must reference: every pool target (bodies but the
    # sink caller -- the probe calls it -- and the recursive pair's second
    # member, reached through the first; opaque targets) -- coverage checked
    expected = {c.entry for c, kind in zip(callees, callee_kinds) if kind != "recursive"} | set(opaque)
    expected |= {c.entry for c, kind in zip(callees, callee_kinds) if kind == "recursive"}.intersection(
        recursive[:1])
    program.counts["unreferenced_targets"] = len(expected - gen.used)
    return program


# -- callees ---------------------------------------------------------------------

def _callees(knobs, rng, base, count, sink_at):
    """Small bodies: accessor ``rax = [rcx+k]``, setter ``[rcx+k] = rdx``, value
    wrapper ``rax = (rcx ^ c) + d``, two-pointer ``[rcx+k] = [rdx+j]``, a sink
    caller ``sink(rcx)`` (projected sinks), multi-exit, and a larger store run;
    plus a mutually recursive pair when ``recursion``."""
    builders, kinds = [], []
    address = base
    for index in range(count):
        kind = ("accessor", "setter", "wrapper", "two_pointer", "multi_exit", "large")[
            index % 6] if index >= 2 else ("accessor", "sink_caller")[index]   # (one sink caller: the probe's)
        b = FunctionBuilder(entry=address)
        k = 8 * (index % 8)
        if kind == "accessor":
            b.ins(load(reg(RAX), tmp(0x100))) if False else None
            t = tmp(0x100)
            b.ins(add(t, reg(RCX), const(k)), load(reg(RAX), t))
        elif kind == "setter":
            t = tmp(0x100)
            b.ins(add(t, reg(RCX), const(k)), store(t, reg(RDX)))
        elif kind == "wrapper":
            b.ins(op("INT_XOR", [reg(RCX), const(0x5A5A5A5A)], reg(RAX)))
            b.ins(add(reg(RAX), reg(RAX), const(0x1234)))
        elif kind == "two_pointer":
            t, u, v = tmp(0x100), tmp(0x110), tmp(0x120)
            b.ins(add(t, reg(RDX), const(k)), load(v, t), add(u, reg(RCX), const(k + 8)), store(u, v))
        elif kind == "sink_caller":
            # (rcx read once: an argument passed through untouched has no
            # definition in the callee and its sink root stays unbound -- a
            # known engine limit, docs 25.31)
            b.ins(copy(reg(RCX), reg(RCX))).sub_rsp(0x28).call(sink_at).add_rsp(0x28)
        elif kind == "multi_exit":
            flag = tmp(0x300, 1)
            b.cbranch("other", flag, op("INT_EQUAL", [reg(RDX), const(0)], flag))
            t = tmp(0x100)
            b.ins(add(t, reg(RCX), const(k)), load(reg(RAX), t)).ret()
            b.label("other").ins(copy(reg(RAX), const(0)))
        else:  # large: a run of field stores
            for slot in range(knobs["callee_size"]):
                t = tmp(0x100 + 0x10 * slot)
                b.ins(add(t, reg(RCX), const(8 * slot)), store(t, reg(RDX)))
        b.ret()
        builders.append(b)
        kinds.append(kind)
        address += 4 * (len(b._rows) + 8)
    if knobs["recursion"]:
        first, second = address, address + 4 * 32
        a = FunctionBuilder(entry=first).sub_rsp(0x28).call(second).add_rsp(0x28).ret()
        c = FunctionBuilder(entry=second)
        flag = tmp(0x300, 1)
        c.cbranch("done", flag, op("INT_EQUAL", [reg(RCX), const(0)], flag))
        c.ins(sub(reg(RCX), reg(RCX), const(1))).sub_rsp(0x28).call(first).add_rsp(0x28)
        c.label("done").ret()
        builders += [a, c]
        kinds += ["recursive", "recursive"]
    return builders, kinds


# -- segments ----------------------------------------------------------------------

def _weights(k):
    return {
        "arith": max(0.0, 1 - k["memory"] - k["calls"] - k["branches"]) + k["chain"],
        "memory": k["memory"],
        "spill": k["memory"] * 0.4,
        "call": k["calls"] * (1 - k["vtable"] - k["resolvable_indirect"]),
        "vtable": k["calls"] * k["vtable"],
        "resolvable": k["calls"] * k["resolvable_indirect"],
        "diamond": k["branches"] * 0.8,
        "early_return": k["branches"] * 0.05,
        "loop": k["loops"],
        "escape": k["escapes"],
        "unknown_store": k["unknown_stores"],
        "two_pointer_call": k["calls"] * k["two_pointer"],
        "fanin": k["fanin"],
        "rep": k["rep"],
        "trap": k["traps"],
        "sink": k["sinks"] * k["calls"],
    }


def _flags(left, right, result, size):
    """x64 arithmetic flags as Ghidra lifts them (CF, OF, SF, ZF; PF elided)."""
    return [op("INT_CARRY", [left, right], reg(CF, 1)), op("INT_SCARRY", [left, right], reg(OF, 1)),
            op("INT_SLESS", [result, const(0, size)], reg(0x207, 1)), op("INT_EQUAL", [result, const(0, size)],
                                                                          reg(ZF, 1))]


def _arith(g, *_):
    b, rng = g.caller, g.rng
    register = rng.choice((RAX, R8, R9, R10, R11))
    width = g.width()
    if width == 4:   # 32-bit writes zero-extend into the full register
        value, right = g.t(4), const(rng.randrange(1, 99), 4)
        b.ins(*_flags(reg(register, 4), right, reg(register, 4), 4), add(value, reg(register, 4), right),
              op("INT_ZEXT", [value], reg(register)))
    elif width == 1:
        right = const(rng.randrange(1, 9), 1)
        b.ins(*_flags(reg(register, 1), right, reg(register, 1), 1),
              add(reg(register, 1), reg(register, 1), right))
    else:
        right = reg(rng.choice((RAX, R8, R9, R10, R11)))
        b.ins(*_flags(reg(register), right, reg(register), 8), add(reg(register), reg(register), right))


def _memory(g, *_):
    b, rng = g.caller, g.rng
    address = g.t()
    width = g.width()
    if rng.random() < 0.5:
        b.ins(add(address, reg(RBX), const(g.field())), load(reg(rng.choice((RAX, R8, R9)), width), address))
    else:
        b.ins(add(address, reg(RBX), const(g.field())), store(address, reg(rng.choice((RAX, R8, R9)), width)))


def _spill(g, *_):
    b, rng = g.caller, g.rng
    address = g.t()
    offset = 0x20 + 8 * rng.randrange(40)
    register = rng.choice((RAX, R8, R9))
    if rng.random() < 0.5:
        b.ins(add(address, reg(RSP), const(offset)), store(address, reg(register)))
    else:
        b.ins(add(address, reg(RSP), const(offset)), load(reg(register), address))


def _args(g):
    b, rng = g.caller, g.rng
    b.ins(copy(reg(RCX), reg(RBX)))
    b.ins(copy(reg(RDX), reg(rng.choice((RAX, R8, R9, RSI)))))


def _consume(g):
    g.caller.ins(add(reg(R8), reg(R8), reg(RAX)))


def _call(g, callees, kinds, opaque, sink_at, source_at):
    _args(g)
    pool = [c.entry for c, kind in zip(callees, kinds) if kind not in ("sink_caller", "recursive")] + list(opaque)
    g.call(g.pick(pool) if pool else source_at)
    _consume(g)


def _vtable(g, *_):
    b = g.caller
    _args(g)
    slot = g.t()
    b.ins(load(reg(RAX), reg(RBX)))                       # vtable = *this
    b.ins(add(slot, reg(RAX), const(8 * g.rng.randrange(16))), load(reg(R10), slot))
    g.call_indirect(R10)
    _consume(g)


def _resolvable(g, callees, kinds, *_):
    pool = [c.entry for c, kind in zip(callees, kinds) if kind in ("accessor", "wrapper")]
    if not pool:
        return _arith(g)
    _args(g)
    g.caller.ins(copy(reg(R10), const(g.rng.choice(pool))))
    g.call_indirect(R10)
    _consume(g)


def _diamond(g, callees, kinds, opaque, sink_at, source_at):
    b, rng = g.caller, g.rng
    other, join = g.label("else"), g.label("join")
    flag = g.t(1)
    b.cbranch(other, flag, op("INT_EQUAL", [reg(rng.choice((RAX, R8, R9)), 1), const(rng.randrange(4), 1)], flag))
    for _ in range(rng.randrange(1, 4)):
        rng.choice((_arith, _memory, _spill))(g)
    b.branch(join)
    b.label(other)
    for _ in range(rng.randrange(1, 4)):
        rng.choice((_arith, _memory, _spill))(g)
    b.label(join)


def _early_return(g, *_):
    b = g.caller
    flag = g.t(1)
    b.cbranch("exit", flag, op("INT_EQUAL", [reg(R9, 1), const(0x7F, 1)], flag))


def _loop(g, *_):
    b, rng = g.caller, g.rng
    top = g.label("loop")
    count = rng.randrange(2, 9)
    b.ins(copy(reg(R11), const(count)))
    b.label(top)
    address, index = g.t(), g.t()
    b.ins(op("INT_MULT", [reg(R11), const(8)], index), add(address, reg(RSP), index),
          store(address, reg(RAX)))                  # a local array indexed by the counter
    for _ in range(rng.randrange(1, 4)):
        rng.choice((_arith, _memory))(g)
    flag = g.t(1)
    b.ins(sub(reg(R11), reg(R11), const(1)))
    b.cbranch(top, flag, op("INT_NOTEQUAL", [reg(R11), const(0)], flag))


def _escape(g, callees, kinds, opaque, sink_at, source_at):
    b = g.caller
    b.ins(add(reg(RCX), reg(RSP), const(0x40 + 8 * g.rng.randrange(8))))   # lea rcx, [rsp+k]
    g.call(g.rng.choice(opaque) if opaque else source_at)


def _unknown_store(g, callees, kinds, opaque, sink_at, source_at):
    b = g.caller
    _args(g)
    g.call(g.rng.choice(opaque) if opaque else source_at)
    b.ins(store(reg(RAX), reg(R8)))                       # *(unknown) = r8
    address = g.t()
    b.ins(add(address, reg(RBX), const(g.field())), load(reg(R9), address))


def _two_pointer_call(g, callees, kinds, *_):
    pool = [c.entry for c, kind in zip(callees, kinds) if kind == "two_pointer"]
    if not pool:
        return _arith(g)
    b = g.caller
    address = g.t()
    b.ins(copy(reg(RCX), reg(RBX)))
    b.ins(add(address, reg(RBX), const(g.field())), load(reg(RDX), address))   # a second pointer
    g.call(g.rng.choice(pool))


def _fanin(g, *_):
    b, rng = g.caller, g.rng
    join = g.label("fanin_join")
    arms = [g.label("arm") for _ in range(g.k["fanin_arms"])]
    for value, arm in enumerate(arms):
        flag = g.t(1)
        b.cbranch(arm, flag, op("INT_EQUAL", [reg(R9, 4), const(value, 4)], flag))
    b.branch(join)
    eh = g.t()
    for value, arm in enumerate(arms):
        b.label(arm)
        b.ins(add(eh, reg(RSP), const(0x30)), store(eh, const(value)))   # an EH-state-like frame slot
        b.branch(join)
    b.label(join)


def _rep(g, *_):
    """``rep movs`` over a frame buffer (Ghidra 12 lifting)."""
    b = g.caller
    b.ins(add(reg(RSI), reg(RSP), const(0x100)))
    b.ins(add(reg(RDI), reg(RSP), const(0x140)))
    b.ins(copy(reg(RCX), const(16)))
    b.ins(copy(reg(DF, 1), const(0, 1)))
    index = len(b._rows)
    here, after = b.entry + 4 * index, b.entry + 4 * (index + 1)
    test = tmp(0x26800, 1)
    ops = [op("INT_EQUAL", [reg(RCX), const(0)], test), op("CBRANCH", [ram(after), test]),
           op("INT_SUB", [reg(RCX), const(1)], reg(RCX))]
    for register, base in ((RDI, 0x22300), (RSI, 0x20b00)):
        pointer, a, z, m = tmp(base, 8), tmp(base + 8, 8), tmp(base + 16, 8), tmp(base + 24, 8)
        ops += [copy(pointer, reg(register)), add(a, reg(register), const(1)),
                op("INT_ZEXT", [reg(DF, 1)], z), op("INT_MULT", [const(2), z], m), op("INT_SUB", [a, m], reg(register))]
    value = tmp(0x21000, 1)
    ops += [load(value, tmp(0x20b00, 8)), copy(tmp(0x22800, 1), value), store(tmp(0x22300, 8), tmp(0x22800, 1)),
            op("BRANCH", [ram(here)])]
    b.ins(*ops)


def _trap(g, *_):
    b = g.caller
    flag = g.t(1)
    skip = g.label("checked")
    b.cbranch(skip, flag, op("INT_NOTEQUAL", [reg(R8, 1), const(0xCC, 1)], flag))
    b.ins(op("CALLOTHER", [const(SWI, 4), const(0x29, 4)], None))   # __fastfail-like trap
    b.branch("exit")
    b.label(skip)


def _sink(g, callees, kinds, opaque, sink_at, source_at):
    b = g.caller
    b.ins(copy(reg(RCX), reg(g.rng.choice((RAX, R8, R9)))))
    g.call(sink_at)
    g.sink_sites += 1


_SEGMENTS = {
    "arith": _arith, "memory": _memory, "spill": _spill, "call": _call, "vtable": _vtable,
    "resolvable": _resolvable, "diamond": _diamond, "early_return": _early_return, "loop": _loop,
    "escape": _escape, "unknown_store": _unknown_store, "two_pointer_call": _two_pointer_call,
    "fanin": _fanin, "rep": _rep, "trap": _trap, "sink": _sink,
}


# -- probes ------------------------------------------------------------------------

def _probe(g, name, sink, labels, complete):
    g.probes.append(Probe(name, sink, g.call_index, frozenset(labels), complete, function=g.caller.entry))


def _escape_helper(g, entry, source_at, source_b_at, leaker_at, sink_at, layout):
    """(6) escape vs control in their own function (analysed in the same
    run, called by nothing): its entry values hold at its start, and the
    escape never reaches the caller's stress region. Returns the builder;
    its probes name its entry."""
    caller, index, sites, used = g.caller, g.call_index, g.sites, set(g.used)
    g.caller = FunctionBuilder(entry=entry)
    g.call_index = 0
    for register in (RBX, RSI, RDI):
        g.caller.push(register)
    g.caller.sub_rsp(0x200)
    g.caller.ins(copy(reg(RBX), reg(RCX)))
    _emit_escape_probes(g, source_at, source_b_at, leaker_at, sink_at, layout)
    g.caller.add_rsp(0x200)
    for register in (RDI, RSI, RBX):
        g.caller.pop(register)
    helper = g.caller.ret()
    g.caller, g.call_index, g.sites, g.used = caller, index, sites, used
    return helper


def _emit_escape_probes(g, source_at, source_b_at, leaker_at, sink_at, layout):
    """(6) escape vs control, right after the prologue: the only place entry
    values still hold (any opaque call later leaves every register unknown).
    slot = A; [rdi - 0x38] = B (a write through an entry value); leaker(rcx);
    sink(slot). Control (rcx = rbx): the frame stays private -- labels {A},
    complete. Escape (rcx = &frame): the slot may have been B's write target --
    labels {A, B}, incomplete. The control first: an escape is permanent."""
    b = g.caller
    a_label, b_label = f"{SOURCE}.ret", f"{SOURCE_B}.ret"
    base = R13
    b.ins(copy(reg(base), const(layout.data_base + layout.data_size // 2 + 0x100)))   # a .data object
    # (7) a read-only image constant (here: a load from .rdata after an opaque call is
    # call-clobbered in this engine despite readonly-image-data-is-constant -- docs 25.31 (d)): c = [.rdata+0x40] (0x48); [this+c] = source;
    # sink([this+0x48]) -- complete only if c is folded to its image value
    g.call(source_at)
    address, offset = g.t(), g.t()
    b.ins(load(offset, const(layout.data_base + RODATA_OFFSET)), add(address, reg(base), offset),
          store(address, reg(RAX)))
    b.ins(add(address, reg(base), const(RODATA_VALUE)), load(reg(RCX), address))
    _probe(g, "readonly", SINK, {a_label}, True)
    g.call(sink_at)
    for name, escaping in (("no_escape", False), ("escape", True)):
        g.call(source_at)
        slot, through = g.t(), g.t()
        b.ins(add(slot, reg(RSP), const(0x1E0)), store(slot, reg(RAX)))
        g.call(source_b_at)
        b.ins(add(through, reg(RDI), const(-0x38 % (1 << 64))), store(through, reg(RAX)))
        if escaping:
            b.ins(add(reg(RCX), reg(RSP), const(0x1C0)))
        else:
            b.ins(copy(reg(RCX), reg(RBX)))
        g.call(leaker_at)
        b.ins(add(slot, reg(RSP), const(0x1E0)), load(reg(RCX), slot))
        _probe(g, name, SINK, {a_label, b_label} if escaping else {a_label}, not escaping)
        g.call(sink_at)


def _emit_probes(g, callees, kinds, source_at, sink_at, sink1_at, opaque, *, source_b_at, leaker_at, layout):
    """Probe paths downstream of the stress region (docs 25.30 K2 C), their
    answers known independently; no opaque call between a probe's write and
    its read (an opaque call clobbers memory)."""
    b = g.caller
    a_label, b_label = f"{SOURCE}.ret", f"{SOURCE_B}.ret"
    base = R13
    b.ins(copy(reg(base), const(layout.data_base + layout.data_size // 2 + 0x100)))   # a .data object
    # (1) positive: source -> r12 -> sink, complete
    g.call(source_at)
    b.ins(copy(reg(R12), reg(RAX)), copy(reg(RCX), reg(R12)))
    _probe(g, "positive", SINK, {a_label}, True)
    g.call(sink_at)
    # (2) negative: the source overwritten by a constant before the sink, complete
    g.call(source_at)
    b.ins(copy(reg(RCX), reg(RAX)), copy(reg(RCX), const(7)))
    _probe(g, "negative", SINK, set(), True)
    g.call(sink_at)
    # (3) through a summarized accessor: [this+0] = source; sink(accessor(this)), complete
    accessor = next((c.entry for c, kind in zip(callees, kinds) if kind == "accessor"), None)
    if accessor is not None:   # (callee 0 is the accessor of [rcx+0])
        g.call(source_at)
        address = g.t()
        b.ins(add(address, reg(base), const(0)), store(address, reg(RAX)), copy(reg(RCX), reg(base)))
        g.call(accessor)
        b.ins(copy(reg(RCX), reg(RAX)))
        _probe(g, "accessor", SINK, {a_label}, True)
        g.call(sink_at)
    # (4) projected callee sink: sink_caller(source), complete
    sink_caller = next((c.entry for c, kind in zip(callees, kinds) if kind == "sink_caller"), None)
    if sink_caller is not None:
        g.call(source_at)
        b.ins(copy(reg(RCX), reg(RAX)))
        g.probes.append(Probe("projected", SINK, -1, frozenset({a_label}), True, function=g.caller.entry))
        g.call(sink_caller)
    # (5) byte lanes: r12 = A; r12b = B's low byte; 8-byte sink {A, B}, 1-byte sink {B}, complete
    g.call(source_at)
    b.ins(copy(reg(R12), reg(RAX)))
    g.call(source_b_at)
    b.ins(copy(reg(R12, 1), reg(RAX, 1)), copy(reg(RCX), reg(R12)))
    _probe(g, "lanes8", SINK, {a_label, b_label}, True)
    g.call(sink_at)
    b.ins(copy(reg(RCX), reg(R12)))
    _probe(g, "lanes1", SINK1, {b_label}, True)
    g.call(sink1_at)



# -- counts ------------------------------------------------------------------------

def _counts(program, *, sites, targets, bodies):
    caller, callees = program.functions[0], program.functions[1:]

    def measure(builder):
        rows = builder.to_json()["instructions"]
        operations = sum(len(row["operations"]) for row in rows)
        memory = sum(1 for row in rows for item in row["operations"] if item["opcode"] in ("LOAD", "STORE"))
        conditionals = sum(1 for row in rows for item in row["operations"] if item["opcode"] == "CBRANCH")
        return len(rows), operations, memory, conditionals

    instructions, operations, memory, conditionals = measure(caller)
    callee_rows = [measure(builder) for builder in callees]
    return {
        "caller_instructions": instructions, "caller_ops": operations, "caller_memory_ops": memory,
        "caller_conditionals": conditionals, "caller_call_sites": sites,
        "distinct_targets": targets, "bodies": bodies, "callee_functions": len(callees),
        "callee_instructions": sum(row[0] for row in callee_rows), "callee_ops": sum(row[1] for row in callee_rows),
        "probes": len(program.probes),
    }
