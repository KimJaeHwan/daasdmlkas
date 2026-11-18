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


def _with_row(unit, index, row):
    rows = list(unit.observation.instructions)
    rows[index] = row
    return SimpleNamespace(observation=dataclasses.replace(unit.observation, instructions=tuple(rows)),
                           scopes=unit.scopes)


def test_a_branch_ending_a_split_segment_is_a_tail_jump():
    """``CBRANCH +2 (relative); BRANCH callee; COPY`` in one instruction: the
    BRANCH ends a reachable sub-block that leaves by it -- a tail jump at its
    own ordinal (not the instruction's last operation; the old rule wanted
    the last), keyed by that ordinal."""
    from synthetic import ZF, ram
    from tdo_v2._scope_contracts import VarnodeKindCode

    unit = _main_unit(_thunk(_main()))
    row = unit.observation.instructions[-1]
    (branch,) = row.operations
    skip = dataclasses.replace(branch, opcode="CBRANCH", inputs=(
        dataclasses.replace(branch.inputs[0], kind=VarnodeKindCode.CONSTANT,
                            coordinate=dataclasses.replace(branch.inputs[0].coordinate, space_id=0, byte_offset=2)),
        unit.observation.instructions[0].operations[0].output))
    tail = branch
    after = unit.observation.instructions[0].operations[0]
    shaped = dataclasses.replace(row, operations=(skip, tail, after))
    found = _direct_calls(_with_row(unit, -1, shaped), {CALLEE_KEY: None})
    key = f"{row.address.space_id:x}:{row.address.byte_offset:x}:1:BRANCH"
    assert found == {key: CALLEE_KEY}


def test_a_branch_in_an_unreachable_split_segment_is_no_tail_call():
    """``BRANCH +2 (relative); BRANCH callee; COPY``: the relative branch
    skips the second operation, whose segment no path reaches -- not a tail
    jump (the instruction is reachable; its segment is not)."""
    from tdo_v2._scope_contracts import VarnodeKindCode

    unit = _main_unit(_thunk(_main()))
    row = unit.observation.instructions[-1]
    (branch,) = row.operations
    skip = dataclasses.replace(branch, inputs=(
        dataclasses.replace(branch.inputs[0], kind=VarnodeKindCode.CONSTANT,
                            coordinate=dataclasses.replace(branch.inputs[0].coordinate, space_id=0, byte_offset=2)),))
    after = unit.observation.instructions[0].operations[0]
    shaped = dataclasses.replace(row, operations=(skip, branch, after))
    observed = _with_row(unit, -1, shaped)
    from tdo_v2.pcode_blocks import build_pcode_block_graph

    graph = build_pcode_block_graph(observed.observation, unit.scopes.function.entry)
    assert graph.unsupported is None
    assert not any(block.instruction == row.address and block.start == 1 for block in graph.blocks)
    assert _direct_calls(observed, {CALLEE_KEY: None}) == {}


def test_a_jump_into_the_function_or_to_its_own_entry_is_no_tail_call():
    """A call-flagged ``jmp`` to an instruction of the function (its own
    entry included) leaves no block by its target: never a tail call, even
    when that address is a Bundle function entry (the function's own)."""
    unit = _main_unit(_thunk(_main(), call=True, terminal=True))
    row = unit.observation.instructions[-1]
    entry = unit.observation.instructions[0].address
    (branch,) = row.operations
    own = dataclasses.replace(branch, inputs=(dataclasses.replace(branch.inputs[0], coordinate=entry),))
    shaped = dataclasses.replace(row, operations=(own,), flow_targets=(entry,))
    own_key = function_key_of(entry.space_id, entry.byte_offset)
    assert _direct_calls(_with_row(unit, -1, shaped), {own_key: None, CALLEE_KEY: None}) == {}


def test_an_unsupported_graph_gives_no_tail_jump():
    """The p-code block builder refuses the graph (an indirect branch inside
    an instruction): no tail jump is taken from it -- the exit stays
    unknown, as the function stays unresolved."""
    from synthetic import RDX
    from tdo_v2._scope_contracts import ValidatedOperation

    unit = _main_unit(_thunk(_main()))
    row = unit.observation.instructions[0]
    first = row.operations[0]
    indirect = ValidatedOperation("BRANCHIND", (first.output,), None)
    shaped = dataclasses.replace(row, operations=(indirect, first))
    from tdo_v2.pcode_blocks import build_pcode_block_graph

    observed = _with_row(unit, 0, shaped)
    assert build_pcode_block_graph(observed.observation, unit.scopes.function.entry).unsupported is not None
    assert _direct_calls(observed, {CALLEE_KEY: None}) == {}


def test_a_jump_with_a_flow_override_is_no_tail_call():
    """A flow override on the instruction (Ghidra's analyst override of its
    flow) is refused, as ``escaping_branches`` and ``_split`` refuse it."""
    for terminal in (False, True):
        unit = _main_unit(_thunk(_main(), terminal=terminal))
        row = unit.observation.instructions[-1]
        shaped = dataclasses.replace(row, flow=dataclasses.replace(row.flow, is_override=True))
        assert _direct_calls(_with_row(unit, -1, shaped), {CALLEE_KEY: None}) == {}


def test_a_jump_to_a_non_entry_is_no_tail_call():
    """The target must be a Bundle function's entry: a jump into the middle
    of another function (or to no function) stays an unknown exit."""
    unit = _main_unit(_thunk(_main()))
    assert _direct_calls(unit, {function_key_of(1, CALLEE + 4): None}) == {}
    assert _direct_calls(unit, {}) == {}


def test_push_then_jump_into_the_next_function_is_composed_soundly():
    """``call $+5`` as Ghidra lifts it when it splits the target off as its
    own function (gate: clang-x86-O2 ``11ad0``): ``middle`` pushes a constant
    and jumps (no call, no terminal flag) to ``leaf: pop rbx; ret``. The leaf
    reads the slot middle wrote; composed, the caller gets rbx = that constant
    and the stack pointer back -- checked by the program oracle."""
    import test_graph_fidelity as fidelity
    from program_oracle import check_program
    from synthetic import REG, RBX, RSP, store, sub

    leaf_entry, middle_entry = CODE_BASE + 0x800, CODE_BASE + 0x600
    leaf = FunctionBuilder(entry=leaf_entry).pop(RBX).ret()
    middle = FunctionBuilder(entry=middle_entry).ins(
        sub(reg(RSP), reg(RSP), const(8)), store(reg(RSP), const(leaf_entry))).tail_call(leaf_entry)
    middle = _thunk(middle)
    caller = FunctionBuilder().call(middle_entry).ins(copy(reg(R9), reg(RBX))).ret()
    units = program_units(caller, middle, leaf)
    results = analyze_units(units)
    analyzed = results[function_key_of(1, middle_entry)]
    assert analyzed.summary.tail_exits == ()
    assert dict(analyzed.summary.register_deltas)[(RSP, 8)] == 8
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    for key in ("1:1000", function_key_of(1, middle_entry)):
        item = results[key]
        report = check_program(item.normalized, item.unit.observation, program, seeds=range(6),
                               register_pools=pools, havoc_calls=(REG, RSP, 8))
        assert report.silent == [], key
