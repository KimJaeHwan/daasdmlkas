"""Stitched call records (docs 25.31 C-9, increment 1): a caller record's
summarized call output continues into the callee's own operations, the
callee's entry registers bound to the caller's values at the call; anything
outside the increment is a ``stitch_cut`` with its reason, and stitching
never changes the caller's own record or its evaluation."""

import copy as copying

from synthetic import (
    CODE_BASE, R9, RAX, RBX, RCX, RDX, RSP, FunctionBuilder, add, const, copy, load, op, program_units, reg, tmp,
)
from tdo_v2.interprocedural import analyze_units
from tdo_v2.operation_records import (
    StitchContext, _compute, eligibility, evaluate, render, root_record,
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
