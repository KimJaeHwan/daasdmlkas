"""Shadow chi memory SSA (docs 25.83): opaque calls as definitions whose
sources are the pre-call definitions per fragment reproduce call_clobber's
calls crossed and the production SSA's origins, byte by byte."""

import pytest

from synthetic import (
    CODE_BASE, DATA_BASE, R8, R9, RAX, RBX, RCX, RDX, RSI, RSP, FunctionBuilder, add, const, copy, load, op,
    program_units, reg, store, tmp,
)
from tdo_v2 import _chi_shadow
from tdo_v2.interprocedural import analyze_units

OPAQUE_A, OPAQUE_B = CODE_BASE + 0xE00, CODE_BASE + 0xE10
T, FLAG = tmp(0x100), tmp(0x300, 1)


_STATE = (_chi_shadow.RESULTS, _chi_shadow.TERMINALS, _chi_shadow.TERMINAL_MISMATCHES, _chi_shadow.METRICS,
          _chi_shadow.TERMINAL_KINDS, _chi_shadow.LAZY)


@pytest.fixture(autouse=True, params=("1", "sparse", "sparse-dense-reference"))
def shadow(monkeypatch, request):
    monkeypatch.setenv("TDO_V2_CHI_SHADOW", request.param.split("-")[0])
    if request.param.endswith("reference"):
        monkeypatch.setenv("TDO_V2_CHI_REFERENCE", "dense")
    for state in _STATE:
        state.clear()
    yield request.param
    for state in _STATE:
        state.clear()


def _checked(builder):
    """Every pass equivalent, check (c) run on every function pass; the
    function's analysis."""
    result = analyze_units(program_units(builder))
    assert _chi_shadow.RESULTS
    for scope, found in _chi_shadow.RESULTS.items():
        assert found == [], found
    assert _chi_shadow.TERMINAL_MISMATCHES
    for scope, found in _chi_shadow.TERMINAL_MISMATCHES.items():
        assert found == [], found
    return result


def _metrics(shadow):
    """The sparse shadow's metrics of the (single) function's last pass."""
    if shadow == "1":
        return None
    found = [metrics for scope, metrics in _chi_shadow.METRICS.items() if not _is_probe(scope)]
    assert len(found) == 1, list(_chi_shadow.METRICS)
    return found[0]


def _is_probe(scope):
    return type(scope) is tuple and len(scope) == 4 and scope[1] == "probe"


def _frame(builder, offset, value):
    return builder.ins(add(T, reg(RSP), const(offset)), store(T, value))


def _read(builder, offset, out=R9, width=8):
    return builder.ins(add(T, reg(RSP), const(offset)), load(reg(out, width), T))


def test_two_calls_in_one_block():
    builder = _frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI)).call(OPAQUE_A)
    builder = _frame(_read(builder, 0x10), 0x18, reg(RDX)).call(OPAQUE_B)
    _checked(_read(_read(builder, 0x10, RBX), 0x18).add_rsp(0x48).ret())


def test_a_partial_overwrite_between_calls():
    """CALL A; [0x10..0x18) = rdx; CALL B; read: B only on the rewritten bytes."""
    builder = _frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI)).call(OPAQUE_A)
    builder = _frame(builder, 0x10, reg(RDX, 4)).call(OPAQUE_B)
    _checked(_read(builder, 0x10).add_rsp(0x48).ret())


def test_a_branch_and_a_loop():
    builder = _frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI))
    builder.cbranch("skip", FLAG, op("INT_EQUAL", [reg(RCX), const(0)], FLAG)).call(OPAQUE_A).label("skip")
    builder.label("top")
    builder = _read(builder, 0x10).call(OPAQUE_B)
    builder = _frame(builder, 0x18, reg(R8))
    builder.cbranch("top", FLAG, op("INT_EQUAL", [reg(RDX), const(0)], FLAG))
    _checked(_read(_read(builder, 0x10, RBX), 0x18).add_rsp(0x48).ret())


def test_globals_and_registers():
    builder = (FunctionBuilder().sub_rsp(0x28).ins(store(const(DATA_BASE + 0x40), reg(RBX)))
               .ins(copy(reg(RAX), reg(RSI))).call(OPAQUE_A)
               .ins(load(reg(R9), const(DATA_BASE + 0x40)), copy(reg(RDX), reg(RAX))).add_rsp(0x28).ret())
    _checked(builder)


def test_a_user_op_output_is_written_after_its_clobber():
    """rax = CALLOTHER(rsi); r9 = rax: the op's own output is no clobbered byte
    (call_clobber: reads, then the call, then the op's writes)."""
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(op("CALLOTHER", [const(7, 4), reg(RSI)], reg(RAX)))
               .ins(copy(reg(R9), reg(RAX))).add_rsp(0x28).ret())
    _checked(builder)


def _overwritten(rewrite):
    builder = _frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI)).call(OPAQUE_A)
    if rewrite:
        builder = _frame(builder, 0x10, const(0))
    return _read(builder.call(OPAQUE_B), 0x10).add_rsp(0x48).ret()


def test_exits_demand_no_chi_sources(shadow):
    """[0x10] = rsi; CALL A; ret: A's chi has sources only in check (c)'s
    exit measurement, never in the read demand; (c) still sees A at the exit."""
    _checked(_frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI)).call(OPAQUE_A).add_rsp(0x48).ret())
    assert any(_chi_shadow.TERMINALS.values())
    metrics = _metrics(shadow)
    if metrics is not None:
        assert metrics["chis"] > 0 and metrics["chi_sources_exits"] > 0
        assert metrics["chi_sources"] < metrics["chi_sources_eager"]


def test_an_overwrite_stops_the_demand(shadow):
    """CALL A; [0x10] = 0; CALL B; read [0x10]: B's sources stop at the
    store -- A's chi is not demanded for that class (it is without the store)."""
    _checked(_overwritten(True))
    with_store = _metrics(shadow)
    for state in _STATE:
        state.clear()
    _checked(_overwritten(False))
    without = _metrics(shadow)
    if with_store is not None:
        assert with_store["chi_sources"] < without["chi_sources"]


def test_a_call_on_each_arm(shadow):
    builder = _frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI))
    builder.cbranch("other", FLAG, op("INT_EQUAL", [reg(RCX), const(0)], FLAG)).call(OPAQUE_A).branch("join")
    builder.label("other").call(OPAQUE_B).label("join")
    _checked(_read(builder, 0x10).add_rsp(0x48).ret())


def test_a_probe_read_is_checked(shadow, monkeypatch):
    """A forward probe's added read (here [0x20], read nowhere else, CALL A
    between its store and the probed load) goes through the shadow too: its
    unit's chi sources include what that read demands."""
    from dataclasses import replace

    from tdo_v2.forward import probe

    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    builder = _frame(_frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI)), 0x20, reg(RDX)).call(OPAQUE_A)
    normalized = _checked(_read(builder, 0x10).add_rsp(0x48).ret())["1:1000"].normalized
    ssa = normalized.memory_ssa
    read = next(row for row in ssa.reads if ssa.actions[row.action_id].operation_key.endswith(":LOAD")
                and row.span.object_id.kind.value == "function_relative" and row.span.size == 8)
    function = _metrics(shadow)
    probe(normalized, ssa.actions[read.action_id].operation_key, (replace(read.span, start=read.span.start + 0x10),))
    probes = [scope for scope in _chi_shadow.RESULTS if _is_probe(scope)]
    assert probes and all(_chi_shadow.RESULTS[scope] == [] for scope in probes)
    if function is not None:
        assert _chi_shadow.METRICS[probes[-1]]["chi_sources"] > function["chi_sources"]


def test_a_store_on_one_arm_a_call_on_the_other(shadow):
    """Astra r1's diamond (S2c's measurement): [0x10] = 0 on one arm, CALL A
    on the other, joined, then read: A reaches the read on one path only."""
    builder = _frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI))
    builder.cbranch("other", FLAG, op("INT_EQUAL", [reg(RCX), const(0)], FLAG))
    builder = _frame(builder, 0x10, const(0)).branch("join")
    builder.label("other").call(OPAQUE_A).label("join")
    _checked(_read(builder, 0x10).add_rsp(0x48).ret())
    metrics = _metrics(shadow)
    if metrics is not None:
        assert metrics["joins_shadow"] >= metrics["joins_chi_free"]


def test_the_live_closure_drops_exactly_the_dead_effects(shadow, monkeypatch):
    """``live_crossed`` with nothing dead is the exit closure itself; with the
    calls declared dead, none of them is crossed (the "dead-masked" proof)."""
    if shadow == "1":
        return
    seen = []
    original = _chi_shadow.compare_terminals

    def spy(scope, crossed, dead_keys=frozenset(), limit=20):
        lazy = _chi_shadow.LAZY[scope]
        calls = frozenset(key[:-len("~chi")] for key in (lazy.definitions[item].operation_key
                                                          for item in lazy.chi_at))
        for (block, object_id), offsets in _chi_shadow.TERMINALS[scope].items():
            for offset, found in offsets.items():
                assert lazy.live_crossed(block, object_id, offset, frozenset()) == found
                assert not lazy.live_crossed(block, object_id, offset, calls)
                seen.append(offset)
        return original(scope, crossed, dead_keys, limit)

    monkeypatch.setattr(_chi_shadow, "compare_terminals", spy)
    builder = _frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI)).call(OPAQUE_A).call(OPAQUE_B)
    _checked(builder.add_rsp(0x48).ret())
    assert seen


class _Labels:
    def __init__(self, codes):
        self.codes = codes

    def decode(self, code):
        return self.codes[code]


def test_terminal_differences_are_classified_one_call_at_a_time():
    """Astra S2a r2: a dead call beside an unexplained one is not all "dead";
    an unexplained byte after ``limit`` explained ones is still counted."""
    from tdo_v2.span_geometry import StorageObjectKind

    frame = type("Frame", (), {"kind": StorageObjectKind.FUNCTION_RELATIVE})()   # (hashable)
    dead, stray, call, tail = "1:10:0:CALL", "1:20:0:CALL", "1:30:0:CALL", "1:40:0:BRANCH"
    shadow = {("exit", frame): {0: frozenset((dead, stray)), **{offset: frozenset((dead,)) for offset in range(1, 25)},
                                30: frozenset((call,)), 31: frozenset((dead,))}}
    universe = _Labels({0: [], 1: ["call:" + call, "call:" + tail], 2: ["call:" + call]})
    _chi_shadow.TERMINALS["f"] = shadow

    class _Live:   # the dead-transparent closure: only `call` reappears (at byte 31 and 32)
        def live_crossed(self, block, object_id, offset, dead):
            return frozenset((call,)) if offset in (31, 32) else frozenset()

    shadow[("exit", frame)][32] = frozenset((dead,))
    universe.codes[3] = ["call:" + call, "call:" + stray.replace("20", "50")]   # (masked + unrelated)
    _chi_shadow.LAZY["f"] = _Live()
    try:
        _chi_shadow.compare_terminals("f", {"label_universe": universe, ("exit", frame): {30: 1, 31: 2, 32: 3}},
                                      frozenset({dead}))
        assert _chi_shadow.TERMINAL_KINDS["f"] == {"dead": 27, "other": 2, "tail": 1, "dead-masked": 2}
        assert len(_chi_shadow.TERMINAL_MISMATCHES["f"]) == 20
    finally:
        for state in _STATE:
            state.pop("f", None)
