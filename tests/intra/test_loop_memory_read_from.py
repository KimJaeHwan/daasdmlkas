"""Same-header-visit memory value relations, with independent concrete runs.

An issued row is a byte-level must-last-writer fact conditional on the LOAD
executing.  Its existence must never remove the original unresolved/alias
graph, infer an iteration count, or turn a previous-visit write into a fact.
"""

from collections import Counter
from dataclasses import replace

import pytest

from graph_oracle import check
from pcode_interpreter import Entry, Interpreter
from synthetic import (
    CONST, DATA_BASE, RAM, REG, R8, RAX, RBX, RCX, RDI, RDX, RSI, RSP,
    Arch, FunctionBuilder, add, const, copy, load, op, program_units, reg,
    ram, store, sub, tmp,
)
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.model import ByteSpan
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction


MODULUS, BASE, SLOT = 1 << 64, 0x50000000, DATA_BASE
VALUE, SENTINEL = 0x1122334455667788, 0xe1e2e3e4e5e6e7e8


def _fixture(variant="value", *, big_endian=False, return_unit=False):
    builder, keys = FunctionBuilder(), {}
    if big_endian:
        builder.arch = Arch("x86:BE:64:default", 8, RSP, 0x288)
    pointer, address, value = reg(RBX), tmp(0x6000), tmp(0x6100)
    counter, flag = tmp(0x6200), tmp(0x6300, 1)

    def ins(name, *operations):
        ordinal = len(operations) - 1
        keys[name] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:{ordinal}:{operations[-1][0]}"
        builder.ins(*operations)

    builder.ins(load(pointer, const(SLOT)), copy(counter, reg(RCX)))
    if variant == "other-family":
        builder.ins(load(reg(RSI), const(SLOT)))
    builder.cbranch("done", flag, op("INT_EQUAL", [counter, const(0)], flag))
    builder.label("loop")
    if variant in ("wrap", "wrap-partial"):
        builder.ins(sub(address, pointer, const(4 if variant == "wrap" else 2)))
    else:
        builder.ins(copy(address, pointer))
    if variant == "before":
        ins("read", load(reg(RAX), address))
    if variant == "previous":
        ins("read", sub(tmp(0x6500), pointer, const(16)), load(reg(RAX), tmp(0x6500)))
    if variant in ("bypass", "exclusive"):
        builder.cbranch("read-path", flag, op("INT_EQUAL", [counter, const(2)], flag))
    if variant in ("same-instruction", "same-instruction-before"):
        operations = [("value", add(value, reg(RDX), const(1))), ("write", store(address, value)),
                      ("read", load(reg(RAX), address))]
        if variant == "same-instruction-before":
            operations = [operations[2], *operations[:2]]
        instruction = builder.entry + len(builder._rows) * builder.stride
        for ordinal, (name, operation) in enumerate(operations):
            keys[name] = f"1:{instruction:x}:{ordinal}:{operation[0]}"
        builder.ins(*(operation for _, operation in operations))
    elif variant == "constant":
        ins("write", store(address, const(VALUE)))
    else:
        # Separate from the STORE so that a full SSA source must be retained,
        # rather than relying on a constant operand or the whole STORE node.
        ins("value", add(value, reg(RDX), const(1)))
        ins("write", store(address, value))
    if variant in ("partial", "conditional-overwrite"):
        if variant == "conditional-overwrite":
            builder.cbranch("read-path", flag, op("INT_EQUAL", [counter, const(2)], flag))
        ins("overwrite", add(tmp(0x6400), address, const(2)), store(tmp(0x6400), const(0xbeef, 2)))
    elif variant in ("source-fragments", "unknown-partial-value"):
        builder.ins(copy(reg(RDX, 4), const(5, 4)))
        if variant == "unknown-partial-value":
            ins("overwrite", add(tmp(0x6400), address, const(4)), store(tmp(0x6400), reg(RDX)))
        else:
            ins("overwrite", store(address, reg(RDX)))
    elif variant == "disjoint":
        ins("overwrite", add(tmp(0x6400), address, const(8)), store(tmp(0x6400), const(0xbeef, 4)))
    elif variant == "source-overwritten":
        builder.ins(copy(value, const(0)))
    elif variant == "direct-memory":
        ins("alias", copy(ram(DATA_BASE + 0x100), const(5)))
    elif variant == "alias":
        ins("alias", store(reg(RDI), const(0x5a, 1)))
    elif variant == "other-family":
        ins("alias", store(reg(RSI), const(0x5a, 1)))
    elif variant == "cross-block":
        builder.cbranch("right", flag, op("INT_EQUAL", [counter, const(2)], flag))
        builder.ins(copy(tmp(0x6600), const(7))).branch("read-path")
        builder.label("right").ins(copy(tmp(0x6600), const(9)))
    if variant == "exclusive":
        builder.branch("advance")
    builder.label("read-path")
    if variant not in ("before", "previous", "same-instruction", "same-instruction-before"):
        ins("read", load(reg(RAX), pointer if variant == "wrap-partial" else address))
    builder.label("advance").ins(add(pointer, pointer, const(16)))
    if variant == "other-family":
        builder.ins(add(reg(RSI), reg(RSI), const(16)))
    builder.ins(sub(counter, counter, const(1)))
    builder.cbranch("loop", flag, op("INT_NOTEQUAL", [counter, const(0)], flag))
    builder.label("done").ret()
    (unit,) = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    assert isinstance(normalized, NormalizedFunction)
    return normalized, unit if return_unit else unit.observation, keys


def _plan(normalized):
    binding = normalized.memory_graph.loop_memory
    assert binding is not None and binding.plan.families and binding.plan.accesses
    return binding.plan


def _rows(normalized, keys):
    binding = normalized.memory_graph.loop_memory
    if binding is None:
        return ()
    plan = binding.plan
    return tuple(row for row in plan.read_from
                 if plan.accesses[row.reader_access].operation_key == keys["read"])


def _image(base):
    def byte(space, address):
        if space == RAM and SLOT <= address < SLOT + 8:
            return base >> (8 * (address - SLOT)) & 0xff
        for start in (base, (base - 16) % MODULUS):
            delta = (address - start) % MODULUS
            if space == RAM and delta < 8:
                return SENTINEL >> (8 * delta) & 0xff
        return None
    return byte


def _execute(observation, count, *, base=BASE):
    interpreter = Interpreter(observation, constant_space=CONST, seed=0, image=_image(base))
    for register, value in {RSP: 0x70000000, RCX: count, RDX: VALUE - 1, RDI: base, R8: 0}.items():
        interpreter.preset(REG, register, 8, value)
    run = interpreter.run()
    assert run.completed and not interpreter.opaque_opcodes
    final = interpreter.final_bytes()
    result = sum(final[(REG, RAX + byte)][0] << (8 * byte) for byte in range(8)) \
        if all((REG, RAX + byte) in final for byte in range(8)) else None
    return interpreter, run, result


def _oracle(normalized, observation, *, base=BASE):
    report = check(normalized, observation, seeds=range(3), image=_image(base),
                   register_pools=lambda seed: {RSP: 0x70000000, RCX: (0, 1, 3)[seed],
                                                RDX: VALUE - 1, RDI: base, R8: 0})
    assert report.runs == 3 and report.checked and not report.unsupported
    assert not report.opaque_opcodes and not report.silent


@pytest.mark.parametrize("variant", ("value", "constant", "cross-block", "wrap", "same-instruction",
                                     "source-overwritten", "disjoint"))
@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_same_visit_last_writer_retains_exact_value_source_and_real_bytes(monkeypatch, variant, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    normalized, observation, keys = _fixture(variant)
    plan = _plan(normalized)
    (row,) = _rows(normalized, keys)
    assert plan.accesses[row.writer_access].operation_key == keys["write"]
    assert row.width == 8 and row.value_offset == row.output_offset == row.visit_delta == 0
    if variant == "constant":
        assert row.constant == (CONST, VALUE, 8)
        assert row.source_span is row.source_definition_id is None
    else:
        assert row.constant is None and row.source_span is not None
        source = normalized.memory_ssa.definitions[row.source_definition_id]
        assert source.operation_key == keys["value"] and source.span.contains(row.source_span)
    base = MODULUS - 2 if variant == "wrap" else BASE
    for count in (0, 1, 3):
        _, run, result = _execute(observation, count, base=base)
        assert run.executed.count(keys["read"]) == count
        if count:
            assert result == VALUE
            dependencies = [dependency for dependency in run.dependencies
                            if dependency.reader == keys["read"] and dependency.space_id == RAM]
            assert dependencies and {dependency.writer for dependency in dependencies} == {keys["write"]}
    _oracle(normalized, observation, base=base)


@pytest.mark.parametrize("variant", ("bypass", "exclusive", "before", "previous", "alias", "other-family",
                                     "same-instruction-before", "direct-memory"))
def test_no_same_visit_fact_when_writer_is_not_must_last(variant):
    normalized, observation, keys = _fixture(variant)
    plan = _plan(normalized)
    assert any(row.operation_key == keys["read"] for row in plan.accesses)
    rows = _rows(normalized, keys)
    assert not any(row.visit_delta == 0 for row in rows)
    assert all(row.visit_delta == -1 and row.requires_backedge for row in rows)
    assert bool(rows) is (variant == "previous")
    if variant in ("alias", "other-family", "direct-memory"):
        graph = normalized.dependencies
        assert graph.node_for_key("op:" + keys["alias"]) in graph.backward_reachable(
            (graph.node_for_key("op:" + keys["read"]),))
    if variant in ("before", "previous", "same-instruction-before"):
        _, run, _ = _execute(observation, 3)
        dependencies = [dependency for dependency in run.dependencies
                        if dependency.reader == keys["read"] and dependency.space_id == RAM]
        assert any(isinstance(dependency.writer, Entry) for dependency in dependencies)
    if variant == "direct-memory":
        # A mapped absolute output can genuinely overlap the otherwise
        # unknown pointer; raw COPY-to-memory must be a barrier as well.
        assert _execute(observation, 1, base=DATA_BASE + 0x100)[2] == 5
        _oracle(normalized, observation, base=DATA_BASE + 0x100)
    _oracle(normalized, observation)


def test_partial_overwrites_keep_each_source_byte_not_whole_store_inputs():
    normalized, observation, keys = _fixture("partial")
    plan, rows = _plan(normalized), _rows(normalized, keys)
    actual = {(plan.accesses[row.writer_access].operation_key, row.value_offset, row.output_offset, row.width)
              for row in rows}
    assert actual == {(keys["write"], 0, 0, 2), (keys["overwrite"], 0, 2, 2),
                      (keys["write"], 4, 4, 4)}
    assert all(row.visit_delta == 0 for row in rows)
    (replacement,) = [row for row in rows if plan.accesses[row.writer_access].operation_key == keys["overwrite"]]
    assert replacement.constant == (CONST, 0xbeef, 2)
    _, run, result = _execute(observation, 3)
    assert result == (VALUE & ~0xffff0000) | 0xbeef0000
    dependencies = [dependency for dependency in run.dependencies
                    if dependency.reader == keys["read"] and dependency.space_id == RAM]
    assert {dependency.writer for dependency in dependencies} == {keys["write"], keys["overwrite"]}
    _oracle(normalized, observation)


def test_conditional_overwrite_keeps_unconditional_fragments_but_not_ambiguous_bytes():
    normalized, observation, keys = _fixture("conditional-overwrite")
    plan, rows = _plan(normalized), _rows(normalized, keys)
    assert {(plan.accesses[row.writer_access].operation_key, row.value_offset, row.output_offset, row.width)
            for row in rows} == {(keys["write"], 0, 0, 2), (keys["write"], 4, 4, 4)}
    assert all(not (row.read_offset <= 2 < row.read_offset + row.width) for row in rows)
    _oracle(normalized, observation)


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_fragmented_store_value_keeps_each_original_ssa_source(monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    normalized, observation, keys = _fixture("source-fragments")
    plan, rows = _plan(normalized), _rows(normalized, keys)
    assert {(plan.accesses[row.writer_access].operation_key, row.write_offset, row.read_offset, row.width)
            for row in rows} == {(keys["overwrite"], 0, 0, 4), (keys["overwrite"], 4, 4, 4)}
    kinds = {row.write_offset: normalized.memory_ssa.definitions[row.source_definition_id].kind for row in rows}
    assert kinds == {0: MemoryDefinitionKind.DATA_WRITE, 4: MemoryDefinitionKind.ENTRY}
    _fragment_edges(normalized, rows, RDX, RAX)
    _, _, result = _execute(observation, 1)
    # Raw COPY into four register bytes preserves the upper four bytes.
    # This fixture does not model x86 EDX's architectural zero-extension.
    assert result == (VALUE & 0xffffffff00000000) | 5
    _oracle(normalized, observation)


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_partial_memory_overlap_uses_needed_value_fragment_without_restoring_old_writer(monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    normalized, observation, keys = _fixture("unknown-partial-value")
    plan, rows = _plan(normalized), _rows(normalized, keys)
    assert {(plan.accesses[row.writer_access].operation_key, row.write_offset, row.read_offset, row.width)
            for row in rows} == {(keys["write"], 0, 0, 4), (keys["overwrite"], 0, 4, 4)}
    for row in rows:
        if plan.accesses[row.writer_access].operation_key == keys["overwrite"]:
            _fragment_edges(normalized, (row,), RDX, RAX)
            assert normalized.memory_ssa.definitions[row.source_definition_id].kind is MemoryDefinitionKind.DATA_WRITE
    _, run, result = _execute(observation, 1)
    assert result == (VALUE & 0xffffffff) | (5 << 32)
    dependencies = [dependency for dependency in run.dependencies
                    if dependency.reader == keys["read"] and dependency.space_id == RAM]
    assert {dependency.writer for dependency in dependencies} == {keys["write"], keys["overwrite"]}
    _oracle(normalized, observation)


def _fragment_edges(normalized, rows, source_start, output_start):
    graph, memory = normalized.dependencies, normalized.memory_graph
    loop = memory.loop_memory
    for row in rows:
        assert row.constant is None and row.visit_delta == 0
        assert row.source_span.start == source_start + row.write_offset and row.source_span.size == row.width
        assert row.output_span.start == output_start + row.read_offset and row.output_span.size == row.width
        assert normalized.memory_ssa.definitions[row.source_definition_id].span.contains(row.source_span)
        number = loop.plan.read_from.index(row)
        source, target = memory.definition_nodes[row.source_definition_id], loop.read_from_nodes[number]
        reader = graph.node_for_key("op:" + loop.plan.accesses[row.reader_access].operation_key)
        assert loop.read_from_source_nodes[number] == source
        assert any(node == target and edge.kind == "loop_read_from_value" and edge.span == row.source_span
                   and edge.occurrence == row.write_offset for _, node, edge in graph.out_edges(source))
        assert any(node == reader and edge.kind == "loop_read_from" and edge.span == row.output_span
                   and edge.occurrence == row.read_offset for _, node, edge in graph.out_edges(target))


def _fragment_fixture(mode="pieces", *, readers=((1, 6),), writer_offset=0, return_unit=False):
    builder, keys = FunctionBuilder(), {}
    pointer, address, counter, flag = reg(RBX), tmp(0x6000), tmp(0x6200), tmp(0x6300, 1)

    def ins(name, *operations):
        keys[name] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:{len(operations) - 1}:{operations[-1][0]}"
        builder.ins(*operations)

    builder.ins(load(pointer, const(SLOT)), copy(counter, reg(RCX)))
    builder.cbranch("done", flag, op("INT_EQUAL", [counter, const(0)], flag))
    builder.label("header")
    if mode == "pieces":
        for number, (offset, width, value) in enumerate(((0, 2, 0x1122), (3, 1, 0x5a), (6, 2, 0xc3d4))):
            ins(f"piece{number}", copy(reg(RDX + offset, width), const(value, width)))
    elif mode == "join":
        builder.cbranch("other", flag, op("INT_EQUAL", [counter, const(2)], flag))
        ins("left", copy(reg(RDX, 4), const(5, 4)))
        builder.branch("join").label("other")
        ins("right", copy(reg(RDX, 4), const(7, 4)))
        builder.label("join")
    ins("write", add(address, pointer, const(writer_offset % MODULUS)), store(address, reg(RDX)))
    for number, (offset, width) in enumerate(readers):
        target, read_address = reg(RAX, width) if number == 0 else tmp(0x8000 + number * 16, width), tmp(0x9000)
        ins("read" if number == 0 else f"read{number}", add(read_address, pointer, const(offset % MODULUS)),
            load(target, read_address))
    builder.ins(add(pointer, pointer, const(16)), sub(counter, counter, const(1)))
    builder.cbranch("header", flag, op("INT_NOTEQUAL", [counter, const(0)], flag))
    builder.label("done").ret()
    (unit,) = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    assert isinstance(normalized, NormalizedFunction)
    return normalized, unit if return_unit else unit.observation, keys


@pytest.mark.parametrize("engine", ("sparse", "dense"))
@pytest.mark.parametrize("wrapped", (False, True))
def test_partial_reader_projects_five_original_value_fragments_with_modular_offsets(monkeypatch, engine, wrapped):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    normalized, observation, keys = _fragment_fixture(readers=((0 if wrapped else 1, 6),),
                                                     writer_offset=-2 if wrapped else 0)
    rows = _rows(normalized, keys)
    expected = {(2, 0, 1), (3, 1, 1), (4, 2, 2), (6, 4, 2)} if wrapped else \
        {(1, 0, 1), (2, 1, 1), (3, 2, 1), (4, 3, 2), (6, 5, 1)}
    assert {(row.write_offset, row.read_offset, row.width) for row in rows} == expected
    _fragment_edges(normalized, rows, RDX, RAX)
    assert {normalized.memory_ssa.definitions[row.source_definition_id].kind for row in rows} == \
        {MemoryDefinitionKind.DATA_WRITE, MemoryDefinitionKind.ENTRY}
    composed = ((VALUE - 1) & ~(0xffff | (0xff << 24) | (0xffff << 48))) | 0x1122 | (0x5a << 24) | (0xc3d4 << 48)
    base = MODULUS - 2 if wrapped else BASE
    for count in (0, 1, 3):
        interpreter, run, _ = _execute(observation, count, base=base)
        if count:
            final = interpreter.final_bytes()
            actual = sum(final[(REG, RAX + byte)][0] << (8 * byte) for byte in range(6))
            assert actual == composed >> (16 if wrapped else 8) & ((1 << 48) - 1)
            assert {row.writer for row in run.dependencies if row.reader == keys["read"] and row.space_id == RAM} == \
                {keys["write"]}
    _oracle(normalized, observation, base=base)


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_entry_source_subspan_keeps_its_nonzero_original_byte_offset(monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    normalized, observation, keys = _fragment_fixture("entry", readers=((3, 2),))
    (row,) = _rows(normalized, keys)
    source = normalized.memory_ssa.definitions[row.source_definition_id]
    assert source.kind is MemoryDefinitionKind.ENTRY
    assert source.span.contains(ByteSpan(source.span.object_id, RDX, 8))
    assert row.source_span.start - source.span.start == RDX + 3 - source.span.start > 0
    assert (row.write_offset, row.read_offset, row.width) == (3, 0, 2)
    _fragment_edges(normalized, (row,), RDX, RAX)
    _oracle(normalized, observation)


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_join_fragment_keeps_the_original_choice_node_not_one_selected_alternative(monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    normalized, observation, keys = _fragment_fixture("join", readers=((0, 8),))
    rows = _rows(normalized, keys)
    assert {(row.write_offset, row.read_offset, row.width) for row in rows} == {(0, 0, 4), (4, 4, 4)}
    _fragment_edges(normalized, rows, RDX, RAX)
    (joined,) = [row for row in rows if normalized.memory_ssa.definitions[row.source_definition_id].kind is MemoryDefinitionKind.JOIN]
    ssa, graph, memory = normalized.memory_ssa, normalized.dependencies, normalized.memory_graph
    (relation,) = [row for row in ssa.joins if row.join_definition_id == joined.source_definition_id]
    assert {ssa.definitions[identifier].operation_key for identifier in relation.source_definition_ids} == {keys["left"], keys["right"]}
    join_node = memory.definition_nodes[joined.source_definition_id]
    assert graph.node(join_node).kind is NodeKind.MEMORY_JOIN
    assert {source for source, _, edge in graph.in_edges(join_node) if edge.kind == "memory_join_input"} == \
        {memory.definition_nodes[identifier] for identifier in relation.source_definition_ids}
    assert joined.constant is None
    _oracle(normalized, observation)


@pytest.mark.parametrize("engine", ("sparse", "dense"))
@pytest.mark.parametrize("unavailable", (False, True))
def test_many_readers_share_one_store_value_projection_without_losing_fragments(monkeypatch, engine, unavailable):
    from tdo_v2 import _loop_memory_reads

    monkeypatch.setenv("TDO_V2_FORWARD", "0")
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    original, original_step, calls, work = _loop_memory_reads._value_sources, _loop_memory_reads.step, Counter(), 0

    def counted(index, key, value):
        calls[key] += 1
        return () if unavailable else original(index, key, value)

    def charged(amount=1):
        nonlocal work
        work += amount
        assert work < 10_000
        return original_step(amount)

    monkeypatch.setattr(_loop_memory_reads, "_value_sources", counted)
    monkeypatch.setattr(_loop_memory_reads, "step", charged)
    normalized, _, keys = _fragment_fixture(readers=tuple((number % 4, 4) for number in range(24)))
    assert calls == {keys["write"]: 1}
    assert 24 < work < 10_000
    plan = _plan(normalized)
    if unavailable:
        assert plan.read_from == ()
        assert normalized.memory_ssa.unresolved_reads and normalized.memory_ssa.unresolved_writes
        return
    readers = {plan.accesses[row.reader_access].operation_key for row in plan.read_from}
    assert readers == {key for name, key in keys.items() if name.startswith("read")}
    for number in range(24):
        selected = _rows(normalized, {"read": keys["read" if number == 0 else f"read{number}"]})
        assert sum(row.width for row in selected) == 4
        _fragment_edges(normalized, selected, RDX, RAX if number == 0 else 0x8000 + number * 16)


def test_unavailable_last_store_fragment_never_resurrects_overwritten_previous_writer(monkeypatch):
    from tdo_v2 import _loop_memory_reads

    original = _loop_memory_reads._value_sources

    def drop_low_source(index, key, value):
        # Deliberate projection-boundary fault injection, not a real malformed
        # SSA input. Only the high ENTRY fragment of an eight-byte value stays.
        sources = original(index, key, value)
        return tuple(row for row in sources if row[2] >= 4) if value.coordinate.byte_offset == RDX else sources

    monkeypatch.setattr(_loop_memory_reads, "_value_sources", drop_low_source)
    normalized, observation, keys = _fixture("unknown-partial-value")
    plan, rows = _plan(normalized), _rows(normalized, keys)
    assert {(plan.accesses[row.writer_access].operation_key, row.read_offset, row.width) for row in rows} == \
        {(keys["write"], 0, 4)}
    assert normalized.memory_ssa.unresolved_reads and normalized.memory_ssa.unresolved_writes
    _oracle(normalized, observation)


def test_source_projection_charges_each_existing_fragment_and_propagates_budget_exhaustion(monkeypatch):
    from tdo_v2 import _loop_memory_reads
    from tdo_v2._loop_memory import _Index
    from tdo_v2.resource_limits import AnalysisBudgetExceeded

    normalized, unit, keys = _fragment_fixture(return_unit=True)
    index = _Index(normalized.memory_unit, normalized.memory_ssa, unit.observation,
                   unit.scopes.function.entry, unit.scopes.resolution_context)
    value = index.raw[keys["write"]].inputs[2]
    charges = 0

    def exhausted(amount=1):
        nonlocal charges
        charges += amount
        if charges > 2:
            raise AnalysisBudgetExceeded("work", "test source fragment projection")

    monkeypatch.setattr(_loop_memory_reads, "step", exhausted)
    with pytest.raises(AnalysisBudgetExceeded, match="source fragment projection"):
        _loop_memory_reads._value_sources(index, keys["write"], value)
    assert charges == 3


@pytest.mark.parametrize("change", ("missing", "overlap", "foreign", "ambiguous"))
def test_malformed_source_fragments_are_rejected_by_the_existing_ssa_contract(change):
    # These are contract negatives, not purported machine-code cases. A
    # normal MemoryReadResolution already enforces contiguous full coverage.
    normalized, _, keys = _fragment_fixture()
    action = next(i for i, row in enumerate(normalized.memory_ssa.actions) if row.operation_key == keys["write"])
    (read,) = [row for row in normalized.memory_ssa.reads if row.action_id == action
               and row.span.object_id.kind.value == "register_file" and row.span.start == RDX]
    first, *rest = read.fragments
    with pytest.raises(ValueError):
        if change == "ambiguous":
            replace(first, definition_ids=(first.definition_ids[0], rest[0].definition_ids[0]))
        elif change == "missing":
            replace(read, fragments=tuple(rest))
        elif change == "overlap":
            replace(read, fragments=(first, first, *rest))
        else:
            foreign = normalized.memory_ssa.definitions[_plan(normalized).accesses[0].address_definition_id].span.object_id
            replace(read, fragments=(replace(first, span=ByteSpan(foreign, first.span.start, first.span.size)), *rest))


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_explicit_kill_in_typed_memory_ssa_remains_unknown_source_not_constant(monkeypatch, engine):
    from tdo_v2._loop_memory import derive_loop_memory
    from tdo_v2.graph import RustworkxDependencyGraph
    from tdo_v2.graph_contracts import NodeRecord
    from tdo_v2.memory_contracts import MemoryWriteMode
    from tdo_v2.memory_graph import _materialize_local_memory_ssa, _validate_materialized_local_memory_ssa
    from tdo_v2.memory_ssa import build_local_memory_ssa

    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    normalized, unit, keys = _fragment_fixture(return_unit=True)
    # Explicit typed SSA boundary test, not execution of a changed binary:
    # conservatively discard one raw COPY's value through the existing KILL
    # effect contract. Rebuild SSA normally; no definition IDs are fabricated.
    memory = replace(normalized.memory_unit, blocks=tuple(replace(block, actions=tuple(
        replace(action, write_mode=MemoryWriteMode.KILL) if action.operation_key == keys["piece0"] else action
        for action in block.actions)) for block in normalized.memory_unit.blocks))
    ssa = build_local_memory_ssa(memory)
    evidence = unit.scopes.program.evidence
    plan = derive_loop_memory(memory, ssa, unit.observation, unit.scopes.function.entry,
                              unit.scopes.resolution_context, evidence.address_spaces, evidence.translation_namespace)
    graph = RustworkxDependencyGraph()
    operations = {action.operation_key: graph.add_node(NodeRecord("op:" + action.operation_key, NodeKind.OPERATION, ""))
                  for action in ssa.actions}
    bindings = _materialize_local_memory_ssa(graph, ssa, operations, loop_memory=plan)
    _validate_materialized_local_memory_ssa(graph, ssa, bindings)
    (row,) = [row for row in plan.read_from if ssa.definitions[row.source_definition_id].kind is MemoryDefinitionKind.KILL]
    assert row.constant is None and (row.write_offset, row.read_offset, row.width) == (1, 0, 1)
    source = bindings.definition_nodes[row.source_definition_id]
    assert graph.node(source).label.startswith("kill:")
    number = plan.read_from.index(row)
    assert bindings.loop_memory.read_from_source_nodes[number] == source
    assert any(target == bindings.loop_memory.read_from_nodes[number] and edge.kind == "loop_read_from_value"
               and edge.span == row.source_span for _, target, edge in graph.out_edges(source))


def test_modular_overlap_selects_correct_value_bytes_without_linear_span_guess():
    normalized, observation, keys = _fixture("wrap-partial")
    plan = _plan(normalized)
    (row,) = _rows(normalized, keys)
    assert plan.accesses[row.writer_access].operation_key == keys["write"]
    assert (row.write_offset, row.read_offset, row.width) == (2, 0, 6)
    assert row.source_span.start == 0x6102 and row.source_span.size == 6
    assert row.output_span.start == RAX and row.output_span.size == 6
    _, run, result = _execute(observation, 1, base=MODULUS - 2)
    assert result == (VALUE >> 16) | (SENTINEL & 0xffff000000000000)
    dependencies = [dependency for dependency in run.dependencies
                    if dependency.reader == keys["read"] and dependency.space_id == RAM]
    assert any(isinstance(dependency.writer, Entry) for dependency in dependencies)
    _oracle(normalized, observation, base=MODULUS - 2)


@pytest.mark.parametrize("variant", ("value", "constant", "partial"))
def test_value_edges_start_at_actual_store_operand_and_end_at_selected_load_output(variant):
    normalized, _, keys = _fixture(variant)
    binding, graph = normalized.memory_graph.loop_memory, normalized.dependencies
    plan = _plan(normalized)
    assert len(binding.read_from_nodes) == len(plan.read_from)
    for row, node in zip(plan.read_from, binding.read_from_nodes):
        assert graph.node(node).kind is NodeKind.EFFECT
        assert graph.node(node).label == "loop_same_visit_read_from"
        writer, reader = plan.accesses[row.writer_access], plan.accesses[row.reader_access]
        writer_node, reader_node = (graph.node_for_key("op:" + item.operation_key) for item in (writer, reader))
        incoming = [(source, edge) for source, target, edge in graph.weighted_edges() if target == node]
        value_edges = [(source, edge) for source, edge in incoming if edge.kind == "loop_read_from_value"]
        assert len(value_edges) == 1
        source, edge = value_edges[0]
        assert source != writer_node  # STORE address/order is not its stored value.
        if row.source_definition_id is not None:
            assert source == normalized.memory_graph.definition_nodes[row.source_definition_id]
            assert edge.span == row.source_span
            assert row.source_span.start == 0x6100 + row.write_offset
            assert row.source_span.size == row.width
        else:
            assert graph.node(source).kind is NodeKind.CONSTANT
        assert (writer_node, "loop_read_from_witness") in {(source, edge.kind) for source, edge in incoming}
        assert any(target == reader_node and edge.kind == "loop_read_from" and edge.span == row.output_span
                   for _, target, edge in graph.out_edges(node))
        assert row.output_span.start == RAX + row.read_offset and row.output_span.size == row.width
        assert source in graph.backward_reachable((reader_node,))


def test_big_endian_input_cannot_issue_little_endian_byte_value_facts():
    normalized, _, keys = _fixture(big_endian=True)
    assert not _rows(normalized, keys)


def test_many_readers_share_one_family_pass_instead_of_rescanning_writer_prefix(monkeypatch):
    from tdo_v2 import _loop_memory_reads

    builder = FunctionBuilder()
    pointer, counter, flag = reg(RBX), tmp(0x9000), tmp(0x9010, 1)
    builder.ins(load(pointer, const(SLOT)), copy(counter, reg(RCX)))
    builder.cbranch("done", flag, op("INT_EQUAL", [counter, const(0)], flag)).label("loop")
    builder.ins(store(pointer, reg(RDX)))
    for number in range(32):
        builder.ins(load(tmp(0xa000 + number * 8), pointer))
    builder.ins(add(pointer, pointer, const(8)), sub(counter, counter, const(1)))
    builder.cbranch("loop", flag, op("INT_NOTEQUAL", [counter, const(0)], flag)).label("done").ret()
    calls, original = [], _loop_memory_reads._overwrite

    def counted(*args):
        calls.append(args[1:3])
        return original(*args)

    monkeypatch.setattr(_loop_memory_reads, "_overwrite", counted)
    unit, = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    assert len(_plan(normalized).read_from) == 32
    assert calls == [(0, 8)]


def test_same_visit_addition_preserves_ssa_old_alias_edges_and_all_debts(monkeypatch):
    from tdo_v2 import _loop_memory

    after, unit, keys = _fixture("partial", return_unit=True)
    assert _rows(after, keys)
    with monkeypatch.context() as disabled:
        disabled.setattr(_loop_memory, "derive_loop_memory", lambda *args: None)
        before = FunctionNormalizer().normalize(unit)
    assert after.memory_ssa == before.memory_ssa
    assert after.memory_unit == before.memory_unit
    assert after.may_alias_reads == before.may_alias_reads
    assert after.call_clobber_reads == before.call_clobber_reads
    assert after.uncertain_writers == before.uncertain_writers
    assert after.forward_memory_proofs == before.forward_memory_proofs
    assert after.load_value_proofs == before.load_value_proofs == ()
    kinds = {"loop_memory_address", "loop_possible_read", "loop_possible_write",
             "loop_read_from_value", "loop_read_from", "loop_read_from_witness"}

    def original_edges(graph):
        return Counter((graph.node(source).key, graph.node(target).key, edge)
                       for source, target, edge in graph.weighted_edges() if edge.kind not in kinds)

    assert original_edges(after.dependencies) == original_edges(before.dependencies)


@pytest.mark.parametrize("consumer", ("constructor", "validator"))
@pytest.mark.parametrize("field,value", (("width", 7), ("write_offset", 1), ("read_offset", 1),
                                       ("visit_delta", 1), ("reader_access", 0)))
def test_same_visit_issued_payload_cannot_be_changed(consumer, field, value):
    from tdo_v2._loop_memory import validate_loop_memory

    normalized, _, keys = _fixture()
    plan = _plan(normalized)
    (row,) = _rows(normalized, keys)
    if field == "reader_access":
        value = row.writer_access
    if consumer == "constructor":
        with pytest.raises(ValueError):
            changed = replace(row, **{field: value})
            replace(plan, read_from=(changed,))
    else:
        changed = replace(plan)
        altered_row = replace(row)
        object.__setattr__(altered_row, field, value)
        object.__setattr__(changed, "read_from", (altered_row,))
        with pytest.raises(ValueError):
            validate_loop_memory(changed, normalized.memory_ssa)
    validate_loop_memory(plan, normalized.memory_ssa)


def test_same_visit_snapshot_keeps_value_and_byte_evidence_without_authority():
    from tools.graph_fidelity.semantic_snapshot import encode

    normalized, _, keys = _fixture("partial")
    plan = _plan(normalized)
    assert _rows(normalized, keys)
    public = encode(plan)
    assert public["read_from"] == encode(plan.read_from)
    assert all(set(row) >= {"writer_access", "reader_access", "width", "source_span",
                            "source_definition_id", "constant", "write_offset", "read_offset", "output_span",
                            "visit_delta"}
               for row in public["read_from"])
    assert all(row.get("requires_backedge", False) is False for row in public["read_from"])
    assert "_proof" not in public


@pytest.mark.parametrize("forward", ("0", "1"))
@pytest.mark.parametrize("variant", ("partial", "source-fragments", "unknown-partial-value", "joined-fragments"))
def test_read_from_only_addition_preserves_summary_assumptions_and_original_candidates(monkeypatch, forward, variant):
    from tdo_v2 import _loop_memory_reads
    from tdo_v2.function_summary import summarize_function

    monkeypatch.setenv("TDO_V2_FORWARD", forward)
    after, unit, keys = _fragment_fixture("join", readers=((0, 8),), return_unit=True) if variant == "joined-fragments" \
        else _fixture(variant, return_unit=True)
    assert _rows(after, keys)
    with monkeypatch.context() as disabled:
        disabled.setattr(_loop_memory_reads, "derive_read_from", lambda *args: ())
        before = FunctionNormalizer().normalize(unit)
    assert isinstance(before, NormalizedFunction)
    assert before.memory_graph.loop_memory is not None
    assert before.memory_graph.loop_memory.plan.read_from == ()
    assert before.memory_graph.loop_memory.plan.families == after.memory_graph.loop_memory.plan.families
    assert before.memory_graph.loop_memory.plan.accesses == after.memory_graph.loop_memory.plan.accesses
    assert after.memory_ssa == before.memory_ssa
    assert after.memory_unit == before.memory_unit
    assert after.may_alias_reads == before.may_alias_reads
    assert after.call_clobber_reads == before.call_clobber_reads
    assert after.uncertain_writers == before.uncertain_writers
    assert after.forward_memory_proofs == before.forward_memory_proofs
    assert after.load_value_proofs == before.load_value_proofs == ()

    def old_edges(graph):
        return Counter((graph.node(source).key, graph.node(target).key, edge)
                       for source, target, edge in graph.weighted_edges()
                       if edge.kind not in ("loop_read_from", "loop_read_from_value", "loop_read_from_witness"))

    def debt_keys(normalized):
        binding = normalized.memory_graph
        return tuple(normalized.dependencies.node(node).key for node in
                     (*binding.unresolved_read_nodes, *binding.unresolved_write_nodes,
                      *normalized.may_alias_nodes))

    assert old_edges(after.dependencies) == old_edges(before.dependencies)
    assert debt_keys(after) == debt_keys(before)
    left, right = (summarize_function(item, unit.observation) for item in (before, after))
    assert left == right and left.premise_uses == right.premise_uses


@pytest.mark.parametrize("route", ("injected", "stitched"))
def test_same_visit_memory_fact_does_not_make_loop_expression_numerically_executable(route):
    from tdo_v2.operation_records import Ineligible, StitchContext, eligibility, evaluate, root_record

    normalized, unit, keys = _fixture(return_unit=True)
    assert _rows(normalized, keys)
    seeds = [(normalized.memory_graph.definition_nodes[index], (definition.span,))
             for index, definition in enumerate(normalized.memory_ssa.definitions)
             if definition.operation_key == keys["read"]]
    assert len(seeds) == 1
    record = root_record(normalized, unit, seeds, stitch=StitchContext({}, assumptions=()))
    assert eligibility(record, route=route) == "loop"

    def unreadable(_):
        raise AssertionError("Loop refusal must precede any numeric input read")

    with pytest.raises(Ineligible, match="loop"):
        evaluate(record, unreadable, route=route)


@pytest.mark.parametrize("change", ("writer-as-value", "missing-value-edge", "value-edge-kind"))
def test_read_from_topology_refuses_forged_source_or_missing_typed_value_edge(change):
    from tdo_v2.graph import RustworkxDependencyGraph
    from tdo_v2.graph_contracts import EdgeKind, EdgeRecord
    from tdo_v2.memory_graph import _validate_materialized_local_memory_ssa

    normalized, _, _ = _fixture()
    binding = normalized.memory_graph
    loop = binding.loop_memory
    (row,) = loop.plan.read_from
    _validate_materialized_local_memory_ssa(normalized.dependencies, normalized.memory_ssa, binding)
    if change == "writer-as-value":
        writer = loop.plan.accesses[row.writer_access]
        writer_node = normalized.dependencies.node_for_key("op:" + writer.operation_key)
        forged = replace(loop, read_from_source_nodes=(writer_node,))
        with pytest.raises(ValueError, match="actual STORE value source"):
            _validate_materialized_local_memory_ssa(normalized.dependencies, normalized.memory_ssa,
                                                    replace(binding, loop_memory=forged))
        return
    original_graph = normalized.dependencies
    (source,), (target,) = loop.read_from_source_nodes, loop.read_from_nodes
    original = [edge for _, found_target, edge in original_graph.out_edges(source)
                if found_target == target and edge.kind == "loop_read_from_value"]
    assert len(original) == 1
    # Rebuild only through the public facade, omitting exactly one typed
    # edge. Other edges sharing its endpoints and the original stay intact.
    graph, omitted = RustworkxDependencyGraph(), False
    for identifier in range(original_graph.node_count):
        assert graph.add_node(original_graph.node(identifier)) == identifier
    for a, b, edge in original_graph.weighted_edges():
        if not omitted and (a, b, edge) == (source, target, original[0]):
            omitted = True
            continue
        graph.add_edge(a, b, edge)
    assert omitted
    if change == "value-edge-kind":
        graph.add_edge(source, target, EdgeRecord(EdgeKind.LOOP_READ_FROM_WITNESS,
                                                  operation=original[0].operation,
                                                  occurrence=original[0].occurrence,
                                                  span=original[0].span))
    with pytest.raises(ValueError, match="topology"):
        _validate_materialized_local_memory_ssa(graph, normalized.memory_ssa, binding)
    _validate_materialized_local_memory_ssa(normalized.dependencies, normalized.memory_ssa, binding)



def _fragmented(count):
    builder = FunctionBuilder()
    pointer, counter, flag = reg(RBX), tmp(0x9000), tmp(0x9010, 1)
    builder.ins(load(pointer, const(SLOT)), copy(counter, reg(RCX)))
    builder.cbranch("done", flag, op("INT_EQUAL", [counter, const(0)], flag)).label("loop")
    for number in range(count):
        # Disjoint one-byte STOREs: every one adds intervals to the state.
        builder.ins(add(tmp(0xa000), pointer, const(2 * number)), store(tmp(0xa000), const(number & 0xff, 1)))
    builder.ins(load(tmp(0xb000, 1), pointer))
    builder.ins(add(pointer, pointer, const(2 * count)), sub(counter, counter, const(1)))
    builder.cbranch("loop", flag, op("INT_NOTEQUAL", [counter, const(0)], flag)).label("done").ret()
    unit, = program_units(builder)
    return unit


def test_fragmented_stores_splice_touched_intervals_without_dropping_the_first_writer(monkeypatch):
    from tdo_v2 import _loop_memory_reads

    count = 400  # 801 intervals: below the cap, so every writer is kept
    steps, original = [0], _loop_memory_reads.step

    def counted():
        steps[0] += 1
        return original()

    monkeypatch.setattr(_loop_memory_reads, "step", counted)
    plan = _plan(FunctionNormalizer().normalize(_fragmented(count)))
    # The first STORE is still the byte's last writer.
    (row,) = plan.read_from
    assert plan.accesses[row.writer_access].operation_key.endswith(":STORE") and row.constant[1] == 0
    assert (row.read_offset, row.width, row.visit_delta) == (0, 1, 0)
    assert steps[0] < 20 * count  # a full rebuild per STORE charged ~count**2


def test_fragmented_stores_beyond_the_interval_cap_forget_writers_instead_of_copying(monkeypatch):
    from tdo_v2 import _loop_memory_reads

    count, sizes, original = 1000, [], _loop_memory_reads._overwrite  # 2001 intervals

    def measured(state, *args):
        sizes.append(len(state))  # each splice copies the whole state
        return original(state, *args)

    monkeypatch.setattr(_loop_memory_reads, "_overwrite", measured)
    capped = _plan(FunctionNormalizer().normalize(_fragmented(count))).read_from
    assert len(sizes) == count and max(sizes) <= _loop_memory_reads._MAX_INTERVALS + 2
    monkeypatch.setattr(_loop_memory_reads, "_MAX_INTERVALS", 1 << 30)
    full = _plan(FunctionNormalizer().normalize(_fragmented(count))).read_from
    # Forgetting writers only drops rows; it never invents or changes one.
    assert set(capped) <= set(full) and len(full) == 1 and not capped


def _exclusive_branches(count, *, latches):
    """Eight-byte STOREs, then mutually exclusive branches each overwriting
    a different odd byte: every join (or latch fold) fragments the meet."""
    builder = FunctionBuilder()
    pointer, counter, flag = reg(RBX), tmp(0x9000), tmp(0x9010, 1)
    builder.ins(load(pointer, const(SLOT)), copy(counter, reg(RCX)))
    builder.cbranch("done", flag, op("INT_EQUAL", [counter, const(0)], flag)).label("loop")
    builder.ins(load(tmp(0xb000, 1), pointer))
    for number in range(count // 4 + 1):
        builder.ins(add(tmp(0xa000), pointer, const(8 * number)), store(tmp(0xa000), reg(RDX)))
    advance = (add(pointer, pointer, const(8 * (count // 4 + 1))), sub(counter, counter, const(1)))
    for number in range(count):
        builder.cbranch(f"w{number}", flag, op("INT_EQUAL", [reg(RSI), const(number)], flag))
    builder.branch("join")
    for number in range(count):
        builder.label(f"w{number}").ins(add(tmp(0xa000), pointer, const(2 * number + 1)),
                                        store(tmp(0xa000), const(number & 0xff, 1)))
        if latches:
            builder.ins(*advance)
            builder.cbranch("loop", flag, op("INT_NOTEQUAL", [counter, const(0)], flag)).branch("done")
        else:
            builder.branch("join")
    builder.label("join").ins(*advance)
    builder.cbranch("loop", flag, op("INT_NOTEQUAL", [counter, const(0)], flag)).label("done").ret()
    unit, = program_units(builder)
    return unit


@pytest.mark.parametrize("latches", (False, True), ids=("fan-in", "latches"))
def test_joins_and_latch_folds_are_capped_like_stores(monkeypatch, latches):
    from tdo_v2 import _loop_memory_reads

    sizes, meet, overwrite = [], _loop_memory_reads._meet, _loop_memory_reads._overwrite

    def measured_meet(left, right):
        sizes.append(max(len(left), len(right)))
        return meet(left, right)

    def measured_overwrite(state, *args):
        sizes.append(len(state))
        return overwrite(state, *args)

    monkeypatch.setattr(_loop_memory_reads, "_meet", measured_meet)
    monkeypatch.setattr(_loop_memory_reads, "_overwrite", measured_overwrite)
    monkeypatch.setattr(_loop_memory_reads, "_MAX_INTERVALS", 32)
    unit = _exclusive_branches(64, latches=latches)
    capped = _plan(FunctionNormalizer().normalize(unit)).read_from
    assert sizes and max(sizes) <= 32 + 2  # without the join cap the meets reach ~128 intervals
    sizes.clear()
    monkeypatch.setattr(_loop_memory_reads, "_MAX_INTERVALS", 1 << 30)
    full = _plan(FunctionNormalizer().normalize(unit)).read_from
    assert max(sizes) > 64  # the fixture really fragments the meets
    assert set(capped) <= set(full)
