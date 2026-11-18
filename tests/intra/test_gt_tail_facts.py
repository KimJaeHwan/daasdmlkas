"""(G-T G2, docs 25.102) Unconditional tail jumps by code facts.

A ``jmp other_function`` is a tail call when the code says so -- the BRANCH
ends a reachable block that leaves by it, to the entry of another Bundle
function, from an instruction with no fallthrough, no S1 continuation
evidence and no other observed flow target -- whatever Ghidra's flow type.
Inside a thunk Ghidra leaves that jump without ``is_terminal`` (and without
the call flag); it used to be an unknown tail exit, now the callee's summary
is composed there. A jump whose observation disagrees stays an unknown exit.
"""

import dataclasses
from types import SimpleNamespace

from synthetic import CODE_BASE, R9, RAX, RCX, RDI, RSI, FunctionBuilder, add, const, copy, program_units, reg
from tdo_v2.interprocedural import _direct_calls, analyze_units, function_key_of

MAIN, CALLEE, OTHER = CODE_BASE, CODE_BASE + 0x400, CODE_BASE + 0x600
CALLEE_KEY = function_key_of(1, CALLEE)


def _callee():
    """ECX = 7; ret."""
    return FunctionBuilder(entry=CALLEE).ins(copy(reg(RCX, 4), const(7, 4))).ret()


def _thunk(builder, *, terminal=False, call=False, extra_target=None, index=-1):
    """The tail row of ``builder`` as Ghidra lifts a thunk's ``jmp``: a jump,
    no call flag, no terminal flag (unless asked); ``extra_target``: another
    observed flow target beside the jump's own."""
    raw = builder.to_json()
    row = raw["instructions"][index]
    row["flow_type"] = {**row["flow_type"], "is_call": call, "is_jump": not call, "is_terminal": terminal}
    if extra_target is not None:
        row["flow_targets"] = sorted([*row["flow_targets"], builder._coordinate(extra_target)],
                                     key=lambda item: (item["space_id"], item["byte_offset"]))
    builder.to_json = lambda raw=raw: raw
    return builder


def _main():
    """RAX = 1; jmp CALLEE."""
    return FunctionBuilder(entry=MAIN).ins(copy(reg(RAX), const(1))).tail_call(CALLEE)


def _main_unit(builder):
    return program_units(builder, _callee())[0]


def _tail_key(unit):
    row = unit.observation.instructions[-1]
    return f"{row.address.space_id:x}:{row.address.byte_offset:x}:{len(row.operations) - 1}:BRANCH"


def test_a_thunk_jump_without_the_terminal_flag_is_composed():
    """``middle: rdi = rsi; jmp leaf`` with the jump lifted as in a thunk (no
    terminal flag, no call flag): a tail call by its code facts -- the leaf's
    summary is composed there, middle has no tail exit left, and its caller
    gets middle's effect (stack pointer restored)."""
    leaf_entry, middle_entry = CODE_BASE + 0x800, CODE_BASE + 0x600
    leaf = FunctionBuilder(entry=leaf_entry).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    middle = _thunk(FunctionBuilder(entry=middle_entry).ins(copy(reg(RDI), reg(RSI))).tail_call(leaf_entry))
    caller = FunctionBuilder().call(middle_entry).ins(copy(reg(R9), reg(RAX))).ret()
    units = program_units(caller, middle, leaf)
    jump = units[1].observation.instructions[-1]
    assert not jump.flow.is_terminal and not jump.flow.is_call
    results = analyze_units(units)
    analyzed = results[function_key_of(1, middle_entry)]
    assert list(analyzed.proven) == [_tail_key(units[1])]
    assert analyzed.summary.tail_exits == ()
    (effect,) = results[function_key_of(1, CODE_BASE)].proven.values()
    assert effect.restores_stack


def test_the_terminal_flag_alone_no_longer_decides():
    """Ghidra's call-flagged terminal jump (the old criterion) is still a
    tail call -- by the same facts, not by the flag."""
    unit = _main_unit(_main())
    assert unit.observation.instructions[-1].flow.is_terminal
    assert _direct_calls(unit, {CALLEE_KEY: None}) == {_tail_key(unit): CALLEE_KEY}


def test_another_observed_flow_target_keeps_the_unknown_exit():
    """Observed flow listing a second target disagrees with the p-code: not a
    tail call, even with the terminal flag (the old rule took it)."""
    for terminal in (False, True):
        unit = _main_unit(_thunk(_main(), terminal=terminal, extra_target=OTHER))
        assert _direct_calls(unit, {CALLEE_KEY: None}) == {}


def test_s1_continuation_evidence_keeps_the_unknown_exit():
    """An instruction with S1 continuation evidence (a fallthrough Ghidra's
    flow guess removed) is no tail call."""
    from tdo_v2._scope_contracts import FallthroughExit

    for terminal in (False, True):
        unit = _main_unit(_thunk(_main(), terminal=terminal))
        row = unit.observation.instructions[-1]
        after = dataclasses.replace(row.address, byte_offset=row.address.byte_offset + 4)
        evidence = FallthroughExit(row.address, after, 4)
        observed = SimpleNamespace(observation=dataclasses.replace(unit.observation, fallthrough_exits=(evidence,),
                                                                   call_fallthrough_isa=True),
                                   scopes=unit.scopes)
        assert _direct_calls(observed, {CALLEE_KEY: None}) == {}


def test_a_jump_with_a_fallthrough_is_no_tail_call():
    for terminal in (False, True):
        unit = _main_unit(_thunk(_main(), terminal=terminal))
        row = unit.observation.instructions[-1]
        fallthrough = dataclasses.replace(row.address, byte_offset=row.address.byte_offset + 4)
        shaped = dataclasses.replace(row, fallthrough=fallthrough)
        observation = dataclasses.replace(unit.observation,
                                          instructions=(*unit.observation.instructions[:-1], shaped))
        assert _direct_calls(SimpleNamespace(observation=observation, scopes=unit.scopes),
                             {CALLEE_KEY: None}) == {}


def test_an_unreachable_jump_is_no_tail_call():
    """``ret`` then ``jmp CALLEE``: the jump is in no reachable block."""
    for terminal in (False, True):
        builder = _thunk(FunctionBuilder(entry=MAIN).ins(copy(reg(RAX), const(1))).ret().tail_call(CALLEE),
                         terminal=terminal)
        unit = _main_unit(builder)
        assert _direct_calls(unit, {CALLEE_KEY: None}) == {}


def test_a_call_is_unchanged():
    builder = FunctionBuilder(entry=MAIN).call(CALLEE).ret()
    unit = _main_unit(builder)
    (key,) = _direct_calls(unit, {CALLEE_KEY: None})
    assert key.endswith(":CALL")
