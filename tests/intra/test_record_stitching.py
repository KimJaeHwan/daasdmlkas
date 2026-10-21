"""Stitched call records (docs 25.31 C-9, increment 1): a caller record's
summarized call output continues into the callee's own operations, the
callee's entry registers bound to the caller's values at the call; anything
outside the increment is a ``stitch_cut`` with its reason, and stitching
never changes the caller's own record or its evaluation."""

import copy as copying

import pytest

from synthetic import (
    CODE_BASE, R9, RAX, RBX, RCX, RDX, RSP, FunctionBuilder, add, const, copy, load, op, program_units, reg, tmp,
)
from tdo_v2.interprocedural import analyze_units
from tdo_v2.operation_records import (
    Ineligible, StitchContext, _compute, eligibility, evaluate, render, root_record, run_records,
)

F, G = CODE_BASE + 0x800, CODE_BASE + 0xA00
ROOT = "1:1000"


def _caller(*setup):
    return FunctionBuilder().sub_rsp(0x28).ins(*setup).call(F).add_rsp(0x28).ret()


def _record(functions, stitch=True, start=RAX, **options):
    """The caller's record of its exit RAX run (the one from byte ``start``),
    stitched or not (``options``: analyze_units')."""
    table: dict = {}
    results = analyze_units(program_units(*functions), record_provenance=table, **options)
    caller = results[ROOT]
    run = next(run for item in caller.summary.exits for run in item.runs
               if run.span.object_id.kind.value == "register_file" and run.span.start == start)
    nodes = [caller.normalized.memory_graph.definition_nodes[item] for item in run.definitions]
    assert len(nodes) == 1
    return root_record(caller.normalized, caller.unit, [(nodes[0], (run.span,))], declared=caller.declared,
                       provenance=table[id(caller)][1], stitch=StitchContext(table) if stitch else None)


def _call_nodes(record):
    return [node for node in record["nodes"] if node["kind"] == "call"]


def _values(record, part, registers):
    """Every value a part may have (phis: each alternative), entry registers
    from ``registers`` (offset -> value); a test-side evaluator of the
    stitched subtree (the engine's route "stitched" comes later)."""
    nodes = {node["id"]: node for node in record["nodes"]}

    def of(node_id):
        node = nodes[node_id]
        kind = node["kind"]
        if kind == "const":
            return {node["value"]}
        if kind == "entry":
            offset, size = node["register"]["offset"], node["register"]["size"]
            value = 0   # (an entry may span several registers: byte by byte; others 0)
            for index in range(size):
                byte = offset + index
                value |= ((registers.get(byte - byte % 8, 0) >> (8 * (byte % 8))) & 0xFF) << (8 * index)
            return {value}
        if kind in ("bound", "assemble"):
            return parts(node["parts"])
        if kind == "phi":
            return set().union(*(parts([alternative]) for alternative in node["alternatives"]))
        if kind == "call":
            (item,) = node["stitched"]
            return parts([item["part"]])
        assert kind == "op", node
        if node["opcode"] == "STORE":   # (its value: the stored operand)
            return parts(next(operand for operand in node["operands"] if operand["index"] == 2)["parts"])
        if node["opcode"] == "LOAD":   # (the loaded bytes: each candidate place)
            return set().union(*(parts(place["parts"]) for place in node["memory"]))
        operands = [operand for operand in node["operands"] if "parts" in operand]
        results = {0}
        widths = [operand["width"] for operand in operands]
        values = [parts(operand["parts"]) for operand in operands]
        combos = [[]]
        for found in values:
            combos = [combo + [value] for combo in combos for value in found]
        size = node["output"]["size"]
        results = {_compute(node["opcode"], combo, widths, size) & ((1 << (8 * size)) - 1) for combo in combos}
        return results

    def parts(items):
        found = {0}
        for item in items:
            a, b = item["bytes"]
            pieces = {(value >> (8 * a)) & ((1 << (8 * (b - a))) - 1) for value in of(item["node"])}
            found = {value | (piece << (8 * item["at"][0])) for value in found for piece in pieces}
        return found

    return parts([part])


def _stitched(record):
    (call,) = [node for node in _call_nodes(record) if node.get("stitched")]
    (item,) = call["stitched"]
    return call, item["part"]


def test_one_exit_binds_the_callers_values():
    callee = FunctionBuilder(entry=F).ins(add(reg(RAX), reg(RCX), reg(RDX))).ret()
    record = _record([_caller(copy(reg(RCX), const(0x10)), copy(reg(RDX), reg(RBX))), callee])
    call, part = _stitched(record)
    assert call["provenance"]["source"] == "summary"
    # (the callee's SSA may coalesce its entry registers into one bound node)
    assert any(node["kind"] == "bound" for node in record["nodes"])
    first = min(node["id"] for node in record["nodes"] if node.get("import"))
    assert all(node.get("import") for node in record["nodes"][first:])   # (imports: a suffix)
    assert _values(record, part, {RBX: 0x1234}) == {0x1244}
    assert "=>" in render(record) and "bound" in render(record)


def test_two_exits_are_alternatives():
    flag = tmp(0x300, 1)
    callee = (FunctionBuilder(entry=F)
              .cbranch("other", flag, op("INT_NOTEQUAL", [reg(R9), const(0)], flag))
              .ins(copy(reg(RAX), reg(RCX))).ret()
              .label("other").ins(copy(reg(RAX), reg(RDX))).ret())
    record = _record([_caller(copy(reg(RCX), const(7)), copy(reg(RDX), const(9))), callee])
    _, part = _stitched(record)
    phi = next(node for node in record["nodes"] if node["kind"] == "phi" and node.get("reason") == "callee exits")
    assert len(phi["alternatives"]) == 2 and phi["instance"]
    assert _values(record, part, {}) == {7, 9}


def test_bytes_an_exit_keeps_are_the_callers():
    """One exit writes rax, the other only eax: on that exit the upper bytes
    are the caller's rax before the call (their own call row: other sources)."""
    flag = tmp(0x300, 1)
    callee = (FunctionBuilder(entry=F)
              .cbranch("other", flag, op("INT_NOTEQUAL", [reg(R9), const(0)], flag))
              .ins(copy(reg(RAX), reg(RDX))).ret()
              .label("other").ins(copy(reg(RAX, 4), reg(RCX, 4))).ret())
    record = _record([_caller(copy(reg(RAX), const(0x1111_2222_3333_4444)), copy(reg(RCX), reg(RBX)),
                              copy(reg(RDX), const(0x7777_8888_0000_0005))), callee], start=RAX + 4)
    _, part = _stitched(record)
    assert any(node["kind"] == "bound" and node.get("unchanged") for node in record["nodes"])
    assert _values(record, part, {RBX: 0xAAAA_BBBB_CCCC_DDDD}) == {0x7777_8888, 0x1111_2222}


def test_two_levels():
    inner = FunctionBuilder(entry=G).ins(add(reg(RAX), reg(RCX), const(1))).ret()
    middle = FunctionBuilder(entry=F).sub_rsp(0x28).call(G).add_rsp(0x28).ret()
    record = _record([_caller(copy(reg(RCX), reg(RBX))), middle, inner])
    calls = _call_nodes(record)
    assert len([node for node in calls if node.get("stitched")]) == 2   # (the caller's and F's)
    _, part = _stitched_outer(record)
    assert _values(record, part, {RBX: 41}) == {42}


def _stitched_outer(record):
    call = next(node for node in _call_nodes(record) if node.get("stitched") and "import" not in node)
    return call, call["stitched"][0]["part"]


def _cut(functions):
    record = _record(functions)
    (call,) = [node for node in _call_nodes(record) if "import" not in node]
    assert "stitched" not in call
    assert not any(node.get("import") for node in record["nodes"])
    return call["stitch_cut"]


def test_cuts_name_their_reason():
    # [rcx] with rcx = the caller's stack pointer at the call: just above the
    # pushed return address -- bound since increment 3
    record = _record([_caller(copy(reg(RCX), reg(RSP))),
                      FunctionBuilder(entry=F).ins(load(reg(RAX), reg(RCX))).ret()])
    assert _stitched(record)
    flag = tmp(0x300, 1)
    recursive = (FunctionBuilder(entry=F)
                 .cbranch("done", flag, op("INT_NOTEQUAL", [reg(R9), const(0)], flag))
                 .ins(op("INT_SUB", [reg(R9), const(1)], reg(R9)))
                 .sub_rsp(0x28).call(F).add_rsp(0x28)
                 .label("done").ins(add(reg(RAX), reg(RAX), const(1))).ret())
    record = _record([_caller(), recursive])
    outer = next(node for node in _call_nodes(record) if "import" not in node)
    # either the outer instance is cut, or it holds F's own call, cut as recursion
    if "stitched" in outer:
        inner = [node for node in _call_nodes(record) if node.get("import")]
        assert inner and all(node.get("stitch_cut") for node in inner)
        assert any("recursi" in node["stitch_cut"] for node in inner)
    else:
        assert outer["stitch_cut"]


def test_stitching_never_changes_the_callers_record():
    flag = tmp(0x300, 1)
    callee = (FunctionBuilder(entry=F)
              .cbranch("other", flag, op("INT_NOTEQUAL", [reg(R9), const(0)], flag))
              .ins(copy(reg(RAX), reg(RCX))).ret()
              .label("other").ins(copy(reg(RAX), reg(RDX))).ret())
    functions = [_caller(copy(reg(RCX), const(7)), copy(reg(RDX), const(9))), callee]
    plain, stitched = _record(functions, stitch=False), _record(functions)
    own = [node for node in stitched["nodes"] if "import" not in node]
    stripped = [{key: value for key, value in node.items() if key not in ("stitched", "stitch_cut")} for node in own]
    assert stripped == plain["nodes"]
    assert stitched["truncated"] == plain["truncated"] and stitched["root"] == plain["root"]
    assert eligibility(stitched) == eligibility(plain)

    def entry(node):
        return 0

    def call(node, part):
        return 5

    assert evaluate(copying.deepcopy(stitched), entry, call=call) == evaluate(plain, entry, call=call)


def test_an_import_out_of_limits_is_rolled_back():
    from tdo_v2.operation_records import Limits

    callee = FunctionBuilder(entry=F).ins(add(reg(RAX), reg(RCX), reg(RDX))).ret()
    functions = [_caller(copy(reg(RCX), const(0x10)), copy(reg(RDX), reg(RBX))), callee]
    plain = _record(functions, stitch=False)
    table: dict = {}
    results = analyze_units(program_units(*functions), record_provenance=table)
    caller = results[ROOT]
    run = next(run for item in caller.summary.exits for run in item.runs
               if run.span.object_id.kind.value == "register_file" and run.span.start == RAX)
    node = caller.normalized.memory_graph.definition_nodes[run.definitions[0]]
    for limits in (Limits(nodes=len(plain["nodes"]) + 1), Limits(nodes=len(plain["nodes"]))):
        record = root_record(caller.normalized, caller.unit, [(node, (run.span,))], declared=caller.declared,
                             provenance=table[id(caller)][1], stitch=StitchContext(table), limits=limits)
        (call,) = _call_nodes(record)
        assert call.get("stitch_cut") == "limit" and "stitched" not in call
        assert record["truncated"] == plain["truncated"]
        assert [n for n in record["nodes"]] == [dict(n, stitch_cut="limit") if n["kind"] == "call" else n
                                               for n in plain["nodes"]]



# -- increment 2: the stack pointer and direct stack slots ----------------------

ENTRY_SP = 0x7000_0000
CALL_SP = ENTRY_SP - 0x28   # (the caller's stack pointer at the call, before the push)


def test_the_callee_stack_pointer_is_the_callers_minus_the_push():
    record = _record([_caller(), FunctionBuilder(entry=F).ins(add(reg(RAX), reg(RSP), const(0x10))).ret()])
    _, part = _stitched(record)
    assert any(node.get("call_shape") == -8 for node in record["nodes"])
    assert _values(record, part, {RSP: ENTRY_SP}) == {CALL_SP - 8 + 0x10}


def test_a_stack_argument_is_the_callers_store():
    """The callee reads [rsp+8] at entry: the caller's [rsp] at the call."""
    t = tmp(0x100)
    callee = FunctionBuilder(entry=F).ins(add(t, reg(RSP), const(8)), load(reg(RAX), t)).ret()
    from synthetic import store

    record = _record([_caller(store(reg(RSP), reg(RBX))), callee])
    _, part = _stitched(record)
    assert any(node["kind"] == "bound" and node.get("loaded_by") for node in record["nodes"])
    assert _values(record, part, {RSP: ENTRY_SP, RBX: 0x1234_5678_9ABC_DEF0}) == {0x1234_5678_9ABC_DEF0}


def test_part_of_a_larger_store():
    t = tmp(0x100)
    callee = FunctionBuilder(entry=F).ins(add(t, reg(RSP), const(12)), load(reg(RAX, 4), t)).ret()
    from synthetic import store

    record = _record([_caller(store(reg(RSP), reg(RBX))), callee])
    _, part = _stitched(record)
    assert _values(record, part, {RSP: ENTRY_SP, RBX: 0x1234_5678_9ABC_DEF0}) == {0x1234_5678}


def test_memory_cuts():
    t = tmp(0x100)
    # the return-address slot itself
    assert _cut([_caller(), FunctionBuilder(entry=F).ins(load(reg(RAX), reg(RSP))).ret()]) == "return address"
    # rcx = rsp - 8 in the caller: [rcx] is the pushed return address -- not bound
    from synthetic import sub

    assert _cut([_caller(sub(reg(RCX), reg(RSP), const(8))),
                 FunctionBuilder(entry=F).ins(load(reg(RAX), reg(RCX))).ret()]) == "return address"
    # a pointer chain p = [rsp+8]; rax = [p]
    chain = FunctionBuilder(entry=F).ins(add(t, reg(RSP), const(8)), load(t, t), load(reg(RAX), t)).ret()
    assert _cut([_caller(), chain]) in ("memory: overlay unproven", "unbound memory")


# -- increment 3: memory through a register, a pointer, a global ----------------

def _bound_memory(record):
    return [node for node in record["nodes"] if node["kind"] == "bound" and node.get("loaded_by")]


def test_a_pointer_to_the_callers_local():
    """rcx = &local (the caller's frame): the callee's [rcx] is the caller's
    store, outside the pushed return address (witness: the lea before the call)."""
    from synthetic import store

    t = tmp(0x100)
    caller = _caller(add(t, reg(RSP), const(0x20)), store(t, reg(RBX)), add(reg(RCX), reg(RSP), const(0x20)))
    record = _record([caller, FunctionBuilder(entry=F).ins(load(reg(RAX), reg(RCX))).ret()])
    _, part = _stitched(record)
    assert _bound_memory(record)
    assert _values(record, part, {RSP: ENTRY_SP, RBX: 0x0123_4567_89AB_CDEF}) == {0x0123_4567_89AB_CDEF}


def test_a_pointer_into_the_return_address_is_cut():
    from synthetic import sub

    caller = _caller(sub(reg(RCX), reg(RSP), const(8)))
    assert _cut([caller, FunctionBuilder(entry=F).ins(load(reg(RAX), reg(RCX))).ret()]) == "return address"


def _preceding_reader(caller_function):
    """The straight-path witness (``_Binding._preceding_reader``) of the
    caller's one call, checked on its own (other witnesses usually exist)."""
    from tdo_v2.operation_records import _Binding, _Builder

    results = analyze_units(program_units(caller_function, FunctionBuilder(entry=F)
                                          .ins(load(reg(RAX), reg(RCX))).ret()))
    caller = results[ROOT]
    builder = _Builder(caller.normalized, caller.unit)
    call, effect = next(iter(caller.normalized.proven_call_effects))
    binding = _Binding(builder, (), builder._stack_base(call), builder._stack_base(call, delta=True),
                       call=call, effect=effect)
    _, _, space, offset, size = binding._stack_pointer()
    return binding._preceding_reader(space, offset, size)


def test_the_straight_path_witness():
    from synthetic import sub

    found = _preceding_reader(_caller(add(reg(RCX), reg(RSP), const(0x20))))
    assert found is not None and found.endswith("INT_ADD")
    # rsp changed after the lea: the change reads and writes it -- no witness
    changed = (FunctionBuilder().sub_rsp(0x28)
               .ins(add(reg(RCX), reg(RSP), const(0x20)))
               .ins(sub(reg(RSP), reg(RSP), const(0x10)))
               .call(F)
               .ins(add(reg(RSP), reg(RSP), const(0x10)))
               .add_rsp(0x28).ret())
    assert _preceding_reader(changed) is None


def test_a_pointer_chain_through_a_stack_argument():
    """[rsp+8] holds &local: rax = [[rsp+8]] is the caller's local."""
    from synthetic import store

    t = tmp(0x100)
    caller = _caller(add(t, reg(RSP), const(0x20)), store(t, reg(RBX)), store(reg(RSP), t))
    u = tmp(0x200)
    callee = FunctionBuilder(entry=F).ins(add(u, reg(RSP), const(8)), load(u, u), load(reg(RAX), u)).ret()
    record = _record([caller, callee])
    _, part = _stitched(record)
    assert _values(record, part, {RSP: ENTRY_SP, RBX: 0x55}) == {0x55}


def test_a_global_needs_the_named_assumption():
    from synthetic import DATA_BASE, ram

    from synthetic import store

    callee = FunctionBuilder(entry=F).ins(copy(reg(RAX), ram(DATA_BASE + 0x10))).ret()
    caller = _caller(store(reg(RSP), reg(RBX)))   # (a stack store: the assumption is relied on)
    assert _cut([caller, callee]) == "memory: overlay unproven"
    record = _record([caller, callee], assume_globals_disjoint_from_stack=True)
    _stitched(record)
    assert any(node.get("assumptions") == ["globals-disjoint-from-stack"] for node in _bound_memory(record))


def test_an_unexpected_error_cuts_only_that_call(monkeypatch):
    """Records are diagnostics: a bug inside one stitch attempt cuts that
    call ("error: <type>"), rolled back like a limit; the run goes on."""
    from tdo_v2 import operation_records

    def broken(self, span, summary, instance):
        raise ValueError("boom")

    callee = FunctionBuilder(entry=F).ins(add(reg(RAX), reg(RCX), reg(RDX))).ret()
    functions = [_caller(copy(reg(RCX), const(0x10)), copy(reg(RDX), reg(RBX))), callee]
    plain = _record(functions, stitch=False)
    monkeypatch.setattr(operation_records._Builder, "_stitched_output", broken)
    record = _record(functions)
    (call,) = _call_nodes(record)
    assert call["stitch_cut"] == "error: ValueError"
    assert [node for node in record["nodes"]] == [dict(node, stitch_cut="error: ValueError")
                                                  if node["kind"] == "call" else node for node in plain["nodes"]]


# -- increment 4: memory output rows ---------------------------------------------

def _memory_caller(*setup, pointer=None):
    """The caller passes rcx = &local (or ``pointer``), calls F, returns the
    local (rax)."""
    t = tmp(0x100)
    return (FunctionBuilder().sub_rsp(0x28)
            .ins(add(t, reg(RSP), const(0x20)), *setup, pointer or add(reg(RCX), reg(RSP), const(0x20)))
            .call(F)
            .ins(add(t, reg(RSP), const(0x20)), load(reg(RAX), t))
            .add_rsp(0x28).ret())


def _memory_call(record):
    return [node for node in _call_nodes(record) if "import" not in node and node["output"].get("kind") == "memory"]


def test_a_memory_output_is_the_callees_store():
    from synthetic import store

    u = tmp(0x200)
    callee = FunctionBuilder(entry=F).ins(add(u, reg(RDX), const(1)), store(reg(RCX), u)).ret()
    record = _record([_memory_caller(copy(reg(RDX), reg(RBX))), callee])
    (call,) = _memory_call(record)
    assert call.get("stitched"), call.get("stitch_cut")
    assert call["stitched"][0]["output"]["place"]
    assert _values(record, {"node": call["id"], "bytes": [0, 8], "at": [0, 8]}, {RSP: ENTRY_SP, RBX: 41}) == {42}


def test_an_exit_keeping_memory_is_its_old_value():
    """One exit stores rdx at [rcx], the other leaves it: the old value is
    the caller's store before the call (through the entry-memory binding)."""
    from synthetic import store

    flag = tmp(0x300, 1)
    callee = (FunctionBuilder(entry=F)
              .cbranch("keep", flag, op("INT_NOTEQUAL", [reg(R9), const(0)], flag))
              .ins(store(reg(RCX), reg(RDX))).ret()
              .label("keep").ret())
    t = tmp(0x100)
    record = _record([_memory_caller(store(t, reg(RBX)), copy(reg(RDX), const(7))), callee])
    (call,) = _memory_call(record)
    assert call.get("stitched"), call.get("stitch_cut")
    assert any(node.get("unchanged") for node in record["nodes"] if node["kind"] == "bound")
    assert _values(record, {"node": call["id"], "bytes": [0, 8], "at": [0, 8]}, {RSP: ENTRY_SP, RBX: 5}) == {5, 7}


def test_a_global_output():
    from synthetic import DATA_BASE, store

    callee = FunctionBuilder(entry=F).ins(store(const(DATA_BASE + 0x10), reg(RDX))).ret()
    caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RDX), reg(RBX))).call(F)
              .ins(load(reg(RAX), const(DATA_BASE + 0x10))).add_rsp(0x28).ret())
    record = _record([caller, callee])
    calls = _memory_call(record)
    assert calls and calls[0].get("stitched"), [node.get("stitch_cut") for node in calls]
    assert _values(record, {"node": calls[0]["id"], "bytes": [0, 8], "at": [0, 8]}, {RBX: 9}) == {9}



def _keeping_callee(target):
    """One exit stores rdx at ``target``, the other leaves it."""
    from synthetic import store

    flag = tmp(0x300, 1)
    return (FunctionBuilder(entry=F)
            .cbranch("keep", flag, op("INT_NOTEQUAL", [reg(R9), const(0)], flag))
            .ins(store(target, reg(RDX))).ret()
            .label("keep").ret())


def _memory_cut(functions, **options):
    record = _record(functions, **options)
    calls = _memory_call(record)
    assert calls, "no memory output row reached"
    assert "stitched" not in calls[0]
    return calls[0]["stitch_cut"]


def test_memory_output_cuts():
    from synthetic import R8, store, sub

    t = tmp(0x100)
    # W is the pushed return address (rcx = rsp - 8), kept on one exit; the
    # caller reads it back through rbx (the callee keeps rbx)
    caller = (FunctionBuilder().sub_rsp(0x28)
              .ins(sub(reg(RCX), reg(RSP), const(8)), copy(reg(RBX), reg(RCX)))
              .call(F)
              .ins(load(reg(RAX), reg(RBX)))
              .add_rsp(0x28).ret())
    record = _record([caller, _keeping_callee(reg(RCX))])
    (call,) = _memory_call(record)   # (the old value at W is the return address: never bound)
    assert "stitched" not in call and call["stitch_cut"] == "return address"
    # W through rcx (a register anchor): its old-value load is checked whole,
    # and the engine gives that read a may-alias debt with the store through
    # r8 before the call -- cut (the direct-slot case of
    # test_an_entry_pointer_store_before_the_call has no such debt)
    assert _memory_cut([_memory_caller(store(t, reg(RBX)), store(reg(R8), reg(RBX))),
                        _keeping_callee(reg(RCX))]) == "memory: debt"


def test_memory_outputs_at_the_entry_stack_pointer():
    """An 8-byte callee store at its [rsp-4] crosses the entry SP (into the
    pushed slot): the row is cut "return address"; a store wholly below the
    entry SP is no output row at all (derivation folds it into
    ``clobbers_below``). The caller reads the bytes back through rbx."""
    from synthetic import store, sub

    u = tmp(0x200)

    def program(offset):
        callee = FunctionBuilder(entry=F).ins(sub(u, reg(RSP), const(offset)), store(u, reg(RDX))).ret()
        # callee [rsp - offset] = caller [rsp_at_call - 8 - offset]
        caller = (FunctionBuilder().sub_rsp(0x28)
                  .ins(sub(reg(RBX), reg(RSP), const(8 + offset)))
                  .call(F)
                  .ins(load(reg(RAX), reg(RBX)))
                  .add_rsp(0x28).ret())
        return [caller, callee]

    crossing = _memory_call(_record(program(4)))
    assert crossing and all(call.get("stitch_cut") == "return address" for call in crossing), crossing
    below = _memory_call(_record(program(0x20)))
    assert all("stitched" not in call for call in below)
    assert not below or all(call.get("stitch_cut") == "below entry stack pointer" for call in below)


def test_a_pointer_chain_memory_output():
    """[rsp+8] holds &local: the callee stores rdx through it."""
    from synthetic import store

    t = tmp(0x100)
    u = tmp(0x200)
    caller = (FunctionBuilder().sub_rsp(0x28)
              .ins(add(t, reg(RSP), const(0x20)), store(reg(RSP), t))
              .call(F)
              .ins(add(t, reg(RSP), const(0x20)), load(reg(RAX), t))
              .add_rsp(0x28).ret())
    callee = FunctionBuilder(entry=F).ins(add(u, reg(RSP), const(8)), load(u, u), store(u, reg(RDX))).ret()
    record = _record([caller, callee])
    calls = _memory_call(record)
    assert calls and calls[0].get("stitched"), [call.get("stitch_cut") for call in calls]


def test_a_kept_global_needs_the_named_assumption():
    from synthetic import DATA_BASE, store

    t = tmp(0x100)
    callee = _keeping_callee(const(DATA_BASE + 0x10))
    caller = (FunctionBuilder().sub_rsp(0x28)
              .ins(add(t, reg(RSP), const(0x20)), store(t, reg(RBX)), copy(reg(RDX), const(3)))
              .call(F)
              .ins(load(reg(RAX), const(DATA_BASE + 0x10))).add_rsp(0x28).ret())
    assert _memory_cut([caller, callee]) == "memory: overlay unproven"
    record = _record([caller, callee], assume_globals_disjoint_from_stack=True)
    calls = _memory_call(record)
    assert calls and calls[0].get("stitched"), [call.get("stitch_cut") for call in calls]
    assert any(node.get("assumptions") == ["globals-disjoint-from-stack"] for node in _bound_memory(record))


def test_an_entry_pointer_store_before_the_call():
    """Astra's case: the caller stores 5 at [rsp+0x38], then 99 through rdi;
    the callee stores 7 at its [rsp+0x40] on one exit only. Under the named
    assumption entry-values-do-not-address-the-new-frame (default on) rdi
    cannot reach the caller's new frame, so the engine has no debt there and
    the old value is 5: the stitched output is {5, 7}, as the engine's own
    model of the call. Without the assumption the store may alias: the
    old-value load then carries a debt and the call is cut "memory: debt"."""
    from synthetic import RDI, store

    t = tmp(0x100)
    u = tmp(0x200)
    flag = tmp(0x300, 1)
    callee = (FunctionBuilder(entry=F)
              .cbranch("keep", flag, op("INT_NOTEQUAL", [reg(R9), const(0)], flag))
              .ins(add(u, reg(RSP), const(0x40)), store(u, const(7))).ret()
              .label("keep").ret())
    caller = (FunctionBuilder().sub_rsp(0x48)
              .ins(add(t, reg(RSP), const(0x38)), store(t, const(5)), store(reg(RDI), const(99)))
              .call(F)
              .ins(add(t, reg(RSP), const(0x38)), load(reg(RAX), t))
              .add_rsp(0x48).ret())
    record = _record([caller, callee])
    (call,) = _memory_call(record)
    assert call.get("stitched"), call.get("stitch_cut")
    assert _values(record, {"node": call["id"], "bytes": [0, 8], "at": [0, 8]}, {RSP: ENTRY_SP}) == {5, 7}
    record = _record([caller, callee], assume_entry_values_not_frame=False)
    (call,) = _memory_call(record)
    assert "stitched" not in call and call["stitch_cut"] == "memory: debt", call


# -- A-2: the engine's "stitched" evaluation route ---------------------------------

def _entry(registers):
    """``evaluate``'s entry: caller entry registers from ``registers``, byte by byte."""
    def entry(node):
        if type(node) is tuple or "register" not in node:
            return None
        offset, size = node["register"]["offset"], node["register"]["size"]
        value = 0
        for index in range(size):
            byte = offset + index
            value |= ((registers.get(byte - byte % 8, 0) >> (8 * (byte % 8))) & 0xFF) << (8 * index)
        return value
    return entry


def test_the_stitched_route_matches_the_hand_evaluator():
    flag = tmp(0x300, 1)
    cases = [
        ([_caller(copy(reg(RCX), const(0x10)), copy(reg(RDX), reg(RBX))),
          FunctionBuilder(entry=F).ins(add(reg(RAX), reg(RCX), reg(RDX))).ret()], {RBX: 0x1234}),
        ([_caller(copy(reg(RCX), const(7)), copy(reg(RDX), const(9))),
          FunctionBuilder(entry=F).cbranch("other", flag, op("INT_NOTEQUAL", [reg(R9), const(0)], flag))
          .ins(copy(reg(RAX), reg(RCX))).ret().label("other").ins(copy(reg(RAX), reg(RDX))).ret()], {}),
        ([_caller(), FunctionBuilder(entry=F).ins(add(reg(RAX), reg(RSP), const(0x10))).ret()], {RSP: ENTRY_SP}),
    ]
    for functions, registers in cases:
        record = _record(functions)
        trace: set = set()
        found = evaluate(record, _entry(registers), route="stitched", trace=trace)
        assert found == _values(record, record["root"][0], registers)
        assert trace   # (through the stitched call)
        assert eligibility(record) is None   # (the injected route still needs ``call``)


def test_one_exit_choice_per_call_instance():
    """Astra's exact-set case: exits (rax, rdx) = (1, 10) or (2, 20); the
    caller returns rax + rdx: exactly {11, 22}, never 12 or 21."""
    flag = tmp(0x300, 1)
    callee = (FunctionBuilder(entry=F)
              .cbranch("other", flag, op("INT_NOTEQUAL", [reg(R9), const(0)], flag))
              .ins(copy(reg(RAX), const(1)), copy(reg(RDX), const(10))).ret()
              .label("other").ins(copy(reg(RAX), const(2)), copy(reg(RDX), const(20))).ret())
    caller = (FunctionBuilder().sub_rsp(0x28).call(F).ins(add(reg(RAX), reg(RAX), reg(RDX)))
              .add_rsp(0x28).ret())
    record = _record([caller, callee])
    assert evaluate(record, _entry({}), route="stitched") == {11, 22}


def test_an_unselected_output_does_not_block():
    """Astra's A-2 review: the root reads rax; another output of the same
    call (rdx, from an unsupported operation) is not reached."""
    callee = (FunctionBuilder(entry=F)
              .ins(copy(reg(RAX), reg(RCX)), op("INT_MULT", [reg(RCX), reg(RCX)], reg(RDX)))
              .ins(op("FLOAT_ADD", [reg(RCX), reg(RCX)], reg(RDX)))
              .ret())
    record = _record([_caller(copy(reg(RCX), const(3))), callee])
    assert evaluate(record, _entry({}), route="stitched") == {3}


# -- A-3: the whole-program concrete oracle ----------------------------------------

def test_a_phi_keeps_the_requested_bytes():
    """Bytes [0, 4) of a phi whose alternatives' upper bytes are unknown
    (an unsupported op) evaluate; the whole phi does not (Astra, A-2/A-3
    implementation review)."""
    nodes = [
        {"id": 0, "kind": "const", "value": 0x11, "size": 4},
        {"id": 1, "kind": "op", "opcode": "UNSUPPORTED_X", "operands": [], "output": {"size": 4}},
        {"id": 2, "kind": "assemble", "size": 8,
         "parts": [{"node": 0, "bytes": [0, 4], "at": [0, 4]}, {"node": 1, "bytes": [0, 4], "at": [4, 8]}]},
        {"id": 3, "kind": "phi", "reason": "test", "size": 8,
         "alternatives": [{"node": 2, "bytes": [0, 8], "at": [0, 8], "loop": False}]},
    ]
    low = {"nodes": nodes, "root": [{"node": 3, "bytes": [0, 4], "at": [0, 4]}]}
    whole = {"nodes": nodes, "root": [{"node": 3, "bytes": [0, 8], "at": [0, 8]}]}
    assert evaluate(low, _entry({}), route="stitched") == {0x11}
    with pytest.raises(Ineligible):
        evaluate(whole, _entry({}), route="stitched")


def test_a_loaded_phi_keeps_the_requested_bytes():
    """A LOAD of 4 bytes over a phi of 8 (the phi in memory): only those
    bytes are read -- an unsupported upper half, an upper-half phi or an
    upper-half stitched call is never evaluated or traced (Astra, A-2/A-3
    implementation review round 2)."""
    upper = [   # (one at a time as node 5: the same id in each variant)
        {"id": 5, "kind": "op", "opcode": "UNSUPPORTED_X", "operands": [], "output": {"size": 4}},
        {"id": 5, "kind": "phi", "reason": "test", "size": 4,
         "alternatives": [{"node": 9, "bytes": [0, 4], "at": [0, 4], "loop": False},
                          {"node": 9, "bytes": [0, 4], "at": [0, 4], "loop": False}]},
        {"id": 5, "kind": "call", "call": "c", "output": {"kind": "register_file", "start": 0, "size": 4},
         "stitched": [{"output": {"kind": "register_file", "start": 0, "size": 4},
                       "part": {"node": 9, "bytes": [0, 4], "at": [0, 4]}}]},
    ]
    for node in upper:
        nodes = [
            {"id": 0, "kind": "const", "value": 0x1000, "size": 8},
            {"id": 1, "kind": "const", "value": 0x11, "size": 4},
            {"id": 2, "kind": "assemble", "size": 8,
             "parts": [{"node": 1, "bytes": [0, 4], "at": [0, 4]}, {"node": 5, "bytes": [0, 4], "at": [4, 8]}]},
            {"id": 3, "kind": "phi", "reason": "test", "size": 8,
             "alternatives": [{"node": 2, "bytes": [0, 8], "at": [0, 8], "loop": False}]},
            {"id": 4, "kind": "op", "opcode": "LOAD", "space": 1, "output": {"size": 4},
             "operands": [{"index": 1, "width": 8, "role": "address",
                           "parts": [{"node": 0, "bytes": [0, 8], "at": [0, 8]}]}],
             "memory": [{"parts": [{"node": 3, "bytes": [0, 4], "at": [0, 4]}]}]},
            node,
            {"id": 9, "kind": "const", "value": 0x22, "size": 4},
        ]
        record = {"nodes": nodes, "root": [{"node": 4, "bytes": [0, 4], "at": [0, 4]}]}
        trace: set = set()
        assert evaluate(record, _entry({}), route="stitched", trace=trace) == {0x11}, node["kind"]
        assert trace == set(), node["kind"]


def _oracle(functions, pools=None, seeds=range(8), at=RAX, **options):
    """The caller's exit record (stitched) of the register run holding byte
    ``at`` (not UNKNOWN, no debts: only those runs' definitions give the
    value) checked against concrete runs of the whole program (callees
    executed)."""
    from record_oracle import check_stitched

    units = program_units(*functions)
    table: dict = {}
    results = analyze_units(units, record_provenance=table, **options)
    caller = results[ROOT]
    exit_key, run = next((item.block_key, run) for item in caller.summary.exits for run in item.runs
                     if run.span.object_id.kind.value == "register_file" and run.span.start <= at < run.span.end
                     and run.kind.value != "unknown" and not run.debts)
    (definition,) = run.definitions
    node = caller.normalized.memory_graph.definition_nodes[definition]
    record = root_record(caller.normalized, caller.unit, [(node, (run.span,))], declared=caller.declared,
                         provenance=table[id(caller)][1], stitch=StitchContext(table))
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    return record, lambda changed: check_stitched(caller, program, changed, register=run.span.start, size=run.span.size,
                                                  exit_key=exit_key, seeds=seeds, register_pools=pools)


def _pools(seed):
    import test_graph_fidelity as fidelity

    # (RAX with nonzero upper bytes: a kept byte taken as 0 must show)
    return {**fidelity._register_inputs(seed), RSP: ENTRY_SP, R9: seed % 2, RAX: 0x1122_3344_5566_7700 + seed}


def _fixtures():
    from synthetic import RSI, store, sub

    flag = tmp(0x300, 1)
    t = tmp(0x100)
    u = tmp(0x200)
    two_exits = (FunctionBuilder(entry=F)
                 .cbranch("other", flag, op("INT_NOTEQUAL", [reg(R9), const(0)], flag))
                 .ins(copy(reg(RAX), reg(RCX))).ret().label("other").ins(copy(reg(RAX), reg(RDX))).ret())
    keeps = (FunctionBuilder(entry=F)
             .cbranch("other", flag, op("INT_NOTEQUAL", [reg(R9), const(0)], flag))
             .ins(copy(reg(RAX), reg(RDX))).ret().label("other").ins(copy(reg(RAX, 4), reg(RCX, 4))).ret())
    return {
        "subtract": [_caller(copy(reg(RCX), reg(RBX)), copy(reg(RDX), reg(RSI))),
                     FunctionBuilder(entry=F).ins(sub(reg(RAX), reg(RCX), reg(RDX))).ret()],
        "two exits": [_caller(copy(reg(RCX), reg(RBX)), copy(reg(RDX), reg(RSI))), two_exits],
        "kept bytes": [_caller(copy(reg(RCX), reg(RBX)), copy(reg(RDX), reg(RSI))), keeps],
        "stack pointer": [_caller(), FunctionBuilder(entry=F).ins(add(reg(RAX), reg(RSP), const(0x10))).ret()],
        "stack argument": [_caller(store(reg(RSP), reg(RBX))),
                           FunctionBuilder(entry=F).ins(add(u, reg(RSP), const(8)), load(reg(RAX), u)).ret()],
        "pointer to a local": [_caller(add(t, reg(RSP), const(0x20)), store(t, reg(RBX)),
                                       add(reg(RCX), reg(RSP), const(0x20))),
                               FunctionBuilder(entry=F).ins(load(reg(RAX), reg(RCX))).ret()],
        "two levels": [_caller(copy(reg(RCX), reg(RBX))),
                       FunctionBuilder(entry=F).sub_rsp(0x28).call(G).add_rsp(0x28).ret(),
                       FunctionBuilder(entry=G).ins(add(reg(RAX), reg(RCX), const(1))).ret()],
        # memory outputs: the caller's local read back after the call
        "memory output": [_memory_caller(copy(reg(RDX), reg(RBX))),
                          FunctionBuilder(entry=F).ins(add(u, reg(RDX), const(1)), store(reg(RCX), u)).ret()],
        "kept memory": [_memory_caller(store(t, reg(RBX)), copy(reg(RDX), reg(RSI))), _keeping_callee(reg(RCX))],
        "pointer chain": [(FunctionBuilder().sub_rsp(0x28)
                           .ins(add(t, reg(RSP), const(0x20)), store(reg(RSP), t))
                           .call(F)
                           .ins(add(t, reg(RSP), const(0x20)), load(reg(RAX), t))
                           .add_rsp(0x28).ret()),
                          FunctionBuilder(entry=F).ins(add(u, reg(RSP), const(8)), load(u, u),
                                                       store(u, reg(RDX))).ret()],
    }


@pytest.mark.parametrize("name", sorted(_fixtures()))
def test_stitched_records_hold_on_whole_program_runs(name):
    for at in (RAX, RAX + 4) if name == "kept bytes" else (RAX,):   # (the kept upper bytes: their own run)
        record, check = _oracle(_fixtures()[name], _pools, at=at)
        report = check(record)
        assert report.failures == [], (at, report.failures)
        assert report.through_stitched > 0, (at, report.skipped, report.no_stitched_call)


def _mutated(record, change):
    import copy as copying

    changed = copying.deepcopy(record)
    change(changed)
    return changed


def test_the_oracle_rejects_mutations():
    """Each mutation must fail on some seed: swapped bindings, a call-shape
    delta off by 8, an unchanged byte taken as computed (const 0), and the
    shared exit choice broken (an exact-set check)."""
    fixtures = _fixtures()

    def swap_bound(record):
        bound = next(node for node in record["nodes"] if node["kind"] == "bound" and len(node["parts"]) >= 2)
        first, second = bound["parts"][0], bound["parts"][1]
        first["node"], second["node"] = second["node"], first["node"]
        first["bytes"], second["bytes"] = second["bytes"], first["bytes"]

    def shift_delta(record):
        shape = next(node for node in record["nodes"] if node.get("call_shape") is not None)
        constant = shape["operands"][1]["parts"][0]["node"]
        record["nodes"][constant]["value"] += 8

    def unchanged_as_zero(record):
        bound = next(node for node in record["nodes"] if node["kind"] == "bound" and node.get("unchanged"))
        zero = {"kind": "const", "value": 0, "size": bound["size"], "id": len(record["nodes"]), "import": "m"}
        record["nodes"].append(zero)
        bound["parts"] = [{"node": zero["id"], "bytes": [0, bound["size"]], "at": [0, bound["size"]]}]

    for name, change in (("subtract", swap_bound), ("stack pointer", shift_delta), ("kept bytes", unchanged_as_zero)):
        record, check = _oracle(fixtures[name], _pools, at=RAX + 4 if name == "kept bytes" else RAX)
        assert check(record).failures == []
        assert check(_mutated(record, change)).failures, name

    flag = tmp(0x300, 1)
    callee = (FunctionBuilder(entry=F)
              .cbranch("other", flag, op("INT_NOTEQUAL", [reg(R9), const(0)], flag))
              .ins(copy(reg(RAX), const(1)), copy(reg(RDX), const(10))).ret()
              .label("other").ins(copy(reg(RAX), const(2)), copy(reg(RDX), const(20))).ret())
    caller = (FunctionBuilder().sub_rsp(0x28).call(F).ins(add(reg(RAX), reg(RAX), reg(RDX)))
              .add_rsp(0x28).ret())
    record = _record([caller, callee])

    def unshare(record):
        for node in record["nodes"]:
            node.pop("instance", None)

    assert evaluate(record, _entry({}), route="stitched") == {11, 22}
    assert evaluate(_mutated(record, unshare), _entry({}), route="stitched") == {11, 12, 21, 22}


def _inexact_runs_are_refused(functions):
    """The runs the oracle skips (UNKNOWN, debts): their summary-run records
    are never evaluated, on either route."""
    table: dict = {}
    caller = analyze_units(program_units(*functions), record_provenance=table)[ROOT]
    for record in run_records(caller.normalized, caller.unit, caller.summary):
        if record.get("run_kind") == "unknown" or record.get("debts"):
            assert eligibility(record, "stitched") is not None, record["span"]
            assert eligibility(record) is not None, record["span"]


def test_random_programs_hold():
    """Random caller / callee pairs (test_interprocedural's bodies): every
    stitched evaluation allows the concrete result; some go through a call."""
    import random

    from test_interprocedural import _random_body

    through = 0
    for seed in range(30):
        rng = random.Random(83_000 + seed)
        callee = _random_body(rng, FunctionBuilder(entry=F))
        caller = _random_body(rng, FunctionBuilder(), calls=(F,))
        _inexact_runs_are_refused([caller, callee])
        try:
            record, check = _oracle([caller, callee], _pools, seeds=range(4))
        except (StopIteration, ValueError):
            continue   # (no exact single-definition exit rax run)
        report = check(record)
        assert report.failures == [], (seed, report.failures)
        through += report.through_stitched
    assert through > 0
