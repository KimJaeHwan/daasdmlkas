"""A previous-visit value relation is conditional on taking a backedge.

Initial memory, all original SSA/alias debts, and original trip uncertainty
remain present. Concrete byte writers use the unmodified p-code interpreter.
"""

from collections import Counter
from dataclasses import replace

import pytest

from graph_oracle import check
from pcode_interpreter import Entry
from synthetic import (
    DATA_BASE, RAM, REG, RAX, RBX, RCX, RDX, RSI, RSP, FunctionBuilder,
    add, const, copy, load, op, program_units, ram, reg, store, sub, tmp,
)
from test_loop_memory_families import _execute as _counter_execute, _fixture as _counter_loop, _oracle as _counter_oracle
from test_loop_memory_read_from import BASE, MODULUS, SENTINEL, SLOT, VALUE, _execute, _image
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.model import ByteSpan, ResolvedStorage
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction, _storage_ref
from tdo_v2.storage import _resolve_validated_storage


PATCH = 0x5a6b7c8d


def _fixture(variant="base", *, readers=1, return_unit=False):
    builder, keys = FunctionBuilder(), {}
    pointer, previous, target = reg(RBX), tmp(0x6000), tmp(0x6010)
    counter, flag = tmp(0x6200), tmp(0x6300, 1)

    def ins(name, *operations):
        keys[name] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:{len(operations) - 1}:{operations[-1][0]}"
        builder.ins(*operations)

    builder.ins(load(pointer, const(SLOT)), copy(counter, reg(RCX)))
    if variant == "other-family":
        builder.ins(load(reg(RSI), const(SLOT)))
    builder.cbranch("done", flag, op("INT_EQUAL", [counter, const(0)], flag))
    builder.label("header").ins(sub(previous, pointer, const(16)))
    if variant == "split-wrap":
        # Raw four-byte p-code write, not x86 EDX zero-extension.
        ins("source", copy(reg(RDX, 4), const(5, 4)))
    if variant.startswith("prefix-"):
        if variant == "prefix-conditional":
            builder.cbranch("reads", flag, op("INT_EQUAL", [counter, const(2)], flag))
        if variant == "prefix-alias":
            ins("alias", store(reg(RSI), const(PATCH)))
        elif variant == "prefix-direct":
            ins("alias", copy(ram(DATA_BASE + 0x100), const(PATCH)))
        else:
            ins("prefix", store(previous, const(PATCH, 8 if variant == "prefix-full" else 4)))
    elif variant == "other-family":
        ins("alias", sub(target, reg(RSI), const(16)), store(target, const(PATCH)))
    builder.label("reads")
    for number in range(readers):
        ins("read" if number == 0 else f"read{number}",
            load(reg(RAX, 6 if variant == "split-wrap" else 8), pointer if variant == "same-slot" else previous))
    if variant in ("different-writers", "different-strides"):
        builder.cbranch("arm1", flag, op("INT_EQUAL", [counter, const(2)], flag))
        for number in range(2):
            builder.label(f"arm{number}")
            ins(f"write{number}", store(pointer, counter))
            stride = 32 if number == 1 and variant == "different-strides" else 16
            builder.ins(add(pointer, pointer, const(stride)), sub(counter, counter, const(1)))
            builder.cbranch("header", flag, op("INT_NOTEQUAL", [counter, const(0)], flag)).branch("done")
    else:
        if variant == "bypass":
            builder.cbranch("advance", flag, op("INT_EQUAL", [counter, const(2)], flag))
        if variant == "split-wrap":
            ins("write", sub(target, pointer, const(2)), store(target, reg(RDX)))
        else:
            ins("write", store(pointer, counter))
        if variant == "suffix-alias":
            ins("alias", store(reg(RSI), const(PATCH)))
        elif variant == "suffix-direct":
            ins("alias", copy(ram(DATA_BASE + 0x100), const(PATCH)))
        elif variant == "call":
            builder.call(0x1f00)
        builder.label("advance").ins(add(pointer, pointer, const(16)))
        if variant == "other-family":
            builder.ins(add(reg(RSI), reg(RSI), const(16)))
        builder.ins(sub(counter, counter, const(1)))
        builder.cbranch("header", flag, op("INT_NOTEQUAL", [counter, const(0)], flag))
    builder.label("done").ret()
    (unit,) = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    assert isinstance(normalized, NormalizedFunction)
    return normalized, unit if return_unit else unit.observation, keys


def _rows(normalized, reader):
    binding = normalized.memory_graph.loop_memory
    return () if binding is None else tuple(row for row in binding.plan.read_from
        if binding.plan.accesses[row.reader_access].operation_key == reader)


def _typed_phase(normalized, observation, row):
    memory, graph = normalized.memory_graph, normalized.dependencies
    binding, ssa = memory.loop_memory, normalized.memory_ssa
    assert row.visit_delta == -1 and row.requires_backedge is True
    number = binding.plan.read_from.index(row)
    effect, source = binding.read_from_nodes[number], binding.read_from_source_nodes[number]
    writer, reader = (binding.plan.accesses[index] for index in (row.writer_access, row.reader_access))
    writer_node, reader_node = (graph.node_for_key("op:" + access.operation_key) for access in (writer, reader))
    raw = {f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}:{ordinal}:{operation.opcode}": operation
           for instruction in observation.instructions for ordinal, operation in enumerate(instruction.operations)}
    output = _resolve_validated_storage(_storage_ref(raw[reader.operation_key].output), normalized.scopes.resolution_context)
    assert type(output) is ResolvedStorage
    assert row.output_span == ByteSpan(output.span.object_id, output.span.start + row.read_offset, row.width)
    assert graph.node(effect).kind is NodeKind.EFFECT
    assert graph.node(effect).label == "loop_previous_visit_read_from_if_backedge"
    assert source != writer_node
    if row.constant is None:
        assert source == memory.definition_nodes[row.source_definition_id]
        assert ssa.definitions[row.source_definition_id].span.contains(row.source_span)
        value = _resolve_validated_storage(_storage_ref(raw[writer.operation_key].inputs[2]), normalized.scopes.resolution_context)
        assert type(value) is ResolvedStorage
        assert row.source_span == ByteSpan(value.span.object_id, value.span.start + row.write_offset, row.width)
        action = next(i for i, action in enumerate(ssa.actions) if action.operation_key == writer.operation_key)
        assert any(fragment.span.contains(row.source_span) and row.source_definition_id in fragment.definition_ids
                   for read in ssa.reads if read.action_id == action for fragment in read.fragments)
    else:
        assert graph.node(source).kind is NodeKind.CONSTANT
        value = raw[writer.operation_key].inputs[2]
        assert row.constant == (value.coordinate.space_id, value.coordinate.byte_offset, value.byte_size)
    assert any(target == effect and edge.kind == "loop_previous_read_from_value" and edge.span == row.source_span
               and edge.occurrence == row.write_offset for _, target, edge in graph.out_edges(source))
    assert any(target == reader_node and edge.kind == "loop_previous_read_from" and edge.span == row.output_span
               and edge.occurrence == row.read_offset for _, target, edge in graph.out_edges(effect))
    assert not any(edge.kind == "loop_read_from" for _, _, edge in graph.out_edges(effect))
    assert any(target == effect and edge.kind == "loop_read_from_witness" for _, target, edge in graph.out_edges(writer_node))


def _debts(normalized):
    graph, ssa, memory = normalized.dependencies, normalized.memory_ssa, normalized.memory_graph
    for direction, occurrences, nodes in (("read", ssa.unresolved_reads, memory.unresolved_read_nodes),
                                          ("write", ssa.unresolved_writes, memory.unresolved_write_nodes)):
        for occurrence, debt in zip(occurrences, nodes, strict=True):
            operation = graph.node_for_key("op:" + ssa.actions[occurrence.action_id].operation_key)
            source, target = (debt, operation) if direction == "read" else (operation, debt)
            assert any(node == target and edge.kind == "unresolved_" + direction for _, node, edge in graph.out_edges(source))


def _oracle(normalized, observation, *, base=BASE):
    report = check(normalized, observation, seeds=range(3), image=_image(base),
                   register_pools=lambda seed: {RSP: 0x70000000, RCX: (0, 1, 3)[seed],
                                                RDX: VALUE - 1, RSI: base - 16})
    assert report.runs == 3 and report.checked and not report.unsupported
    assert not report.opaque_opcodes and not report.silent


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_first_visit_keeps_entry_and_later_visit_reads_previous_counter_not_current(monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    normalized, observation, keys = _fixture()
    (row,) = _rows(normalized, keys["read"])
    assert (row.write_offset, row.read_offset, row.width) == (0, 0, 8)
    _typed_phase(normalized, observation, row)
    for count in (0, 1, 3):
        _, run, result = _execute(observation, count)
        assert run.executed.count(keys["read"]) == count
        if count:
            assert result == (SENTINEL if count == 1 else 2)
        actual = {(dep.offset, dep.writer) for dep in run.dependencies if dep.reader == keys["read"] and dep.space_id == RAM}
        expected = {((BASE + (visit - 1) * 16 + byte) % MODULUS,
                     Entry(RAM, (BASE - 16 + byte) % MODULUS) if visit == 0 else keys["write"])
                    for visit in range(count) for byte in range(8)}
        assert actual == expected
    _debts(normalized)
    _oracle(normalized, observation)


@pytest.mark.parametrize("variant", ("prefix-partial", "prefix-conditional", "prefix-full"))
def test_current_prefix_only_removes_previous_relation_for_its_overwritten_bytes(variant):
    normalized, observation, keys = _fixture(variant)
    rows = _rows(normalized, keys["read"])
    previous = [row for row in rows if row.visit_delta == -1]
    current = [row for row in rows if row.visit_delta == 0]
    assert {(row.read_offset, row.width) for row in previous} == (set() if variant == "prefix-full" else {(4, 4)})
    expected = {(0, 8)} if variant == "prefix-full" else {(0, 4)} if variant == "prefix-partial" else set()
    assert {(row.read_offset, row.width) for row in current} == expected
    assert all(not row.requires_backedge for row in current)
    for row in previous:
        _typed_phase(normalized, observation, row)
    _debts(normalized)
    _oracle(normalized, observation)


@pytest.mark.parametrize("variant", ("prefix-alias", "suffix-alias", "prefix-direct", "suffix-direct",
                                     "other-family", "bypass", "different-writers", "same-slot", "call", "different-strides"))
def test_barriers_and_unproved_previous_writer_never_become_conditional_must(variant):
    normalized, observation, keys = _fixture(variant)
    assert not any(row.visit_delta == -1 for row in _rows(normalized, keys["read"]))
    if variant in ("call", "different-strides"):
        assert normalized.memory_graph.loop_memory is None
    if "alias" in variant or variant in ("other-family", "different-writers"):
        graph = normalized.dependencies
        reachable = graph.backward_reachable((graph.node_for_key("op:" + keys["read"]),))
        writers = [key for name, key in keys.items() if name == "alias" or name.startswith("write")]
        assert all(graph.node_for_key("op:" + key) in reachable for key in writers)
    _debts(normalized)
    if variant != "call":
        _oracle(normalized, observation)


def test_same_ssa_counter_has_separate_current_and_previous_occurrence_value_edges():
    normalized, observation, (loop,) = _counter_loop(variant="previous", width=8, stride=4)
    rows = _rows(normalized, loop["keys"]["read"])
    assert {(row.visit_delta, row.write_offset, row.read_offset, row.width) for row in rows} == \
        {(-1, 0, 0, 4), (0, 0, 4, 4)}
    assert len({row.source_definition_id for row in rows}) == 1
    previous, = [row for row in rows if row.visit_delta == -1]
    _typed_phase(normalized, observation, previous)
    for count in (1, 3):
        interpreter, _ = _counter_execute(observation, (count, 0, 0), stride=4)
        final = interpreter.final_bytes()
        result = sum(final[(REG, RAX + byte)][0] << (8 * byte) for byte in range(8))
        assert result == (1 << 32) | ((SENTINEL & 0xffffffff) if count == 1 else 2)
    _counter_oracle(normalized, observation, ((0, 0, 0), (1, 0, 0), (3, 0, 0)), stride=4)
    _debts(normalized)


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_previous_shift_wrap_and_split_store_value_preserve_all_source_byte_offsets(monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    normalized, observation, keys = _fixture("split-wrap")
    rows = _rows(normalized, keys["read"])
    assert {(row.visit_delta, row.write_offset, row.read_offset, row.width) for row in rows} == \
        {(-1, 2, 0, 2), (-1, 4, 2, 4)}
    assert {normalized.memory_ssa.definitions[row.source_definition_id].kind for row in rows} == \
        {MemoryDefinitionKind.DATA_WRITE, MemoryDefinitionKind.ENTRY}
    for row in rows:
        _typed_phase(normalized, observation, row)
    for count in (0, 1, 3):
        interpreter, run, _ = _execute(observation, count, base=1)
        if count:
            final = interpreter.final_bytes()
            result = sum(final[(REG, RAX + byte)][0] << (8 * byte) for byte in range(6))
            expected = SENTINEL if count == 1 else ((VALUE & 0xffffffff00000000) | 5) >> 16
            assert result == expected & ((1 << 48) - 1)
        assert run.executed.count(keys["read"]) == count
    _debts(normalized)
    _oracle(normalized, observation, base=1)


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_many_previous_readers_share_two_family_passes_and_one_store_source_projection(monkeypatch, engine):
    from tdo_v2 import _loop_memory_reads

    monkeypatch.setenv("TDO_V2_FORWARD", "0")
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    old_source, old_overwrite, old_step = (_loop_memory_reads._value_sources, _loop_memory_reads._overwrite,
                                          _loop_memory_reads.step)
    calls, work = Counter(), 0

    def source(index, key, value):
        calls["source"] += 1
        return old_source(index, key, value)

    def overwrite(*args):
        calls["overwrite"] += 1
        return old_overwrite(*args)

    def charged(amount=1):
        nonlocal work
        work += amount
        assert work < 5_000
        return old_step(amount)

    monkeypatch.setattr(_loop_memory_reads, "_value_sources", source)
    monkeypatch.setattr(_loop_memory_reads, "_overwrite", overwrite)
    monkeypatch.setattr(_loop_memory_reads, "step", charged)
    normalized, observation, keys = _fixture(readers=32)
    assert calls == {"source": 1, "overwrite": 2}
    assert 32 < work < 5_000
    rows = normalized.memory_graph.loop_memory.plan.read_from
    assert len(rows) == 32 and all(row.visit_delta == -1 and row.requires_backedge for row in rows)
    for row in rows:
        _typed_phase(normalized, observation, row)
    _debts(normalized)


@pytest.mark.parametrize("forward", ("0", "1"))
def test_conditional_previous_edges_do_not_rewrite_original_ssa_summary_or_debts(monkeypatch, forward):
    from tdo_v2 import _loop_memory_reads
    from tdo_v2.function_summary import summarize_function

    monkeypatch.setenv("TDO_V2_FORWARD", forward)
    after, unit, keys = _fixture(return_unit=True)
    assert _rows(after, keys["read"])
    with monkeypatch.context() as disabled:
        disabled.setattr(_loop_memory_reads, "derive_read_from", lambda *args: ())
        before = FunctionNormalizer().normalize(unit)
    assert after.memory_ssa == before.memory_ssa and after.memory_unit == before.memory_unit
    assert after.may_alias_reads == before.may_alias_reads and after.uncertain_writers == before.uncertain_writers
    assert summarize_function(before, unit.observation) == summarize_function(after, unit.observation)

    def original(graph):
        return Counter((graph.node(source).key, graph.node(target).key, edge) for source, target, edge in graph.weighted_edges()
                       if edge.kind not in ("loop_previous_read_from_value", "loop_previous_read_from", "loop_read_from_witness"))

    assert original(before.dependencies) == original(after.dependencies)
    _debts(after)


def test_previous_phase_contract_snapshot_and_original_payload_cannot_be_unconditionally_reused():
    from tools.graph_fidelity.semantic_snapshot import encode
    from tdo_v2._loop_memory import validate_loop_memory

    normalized, _, keys = _fixture()
    binding = normalized.memory_graph.loop_memory
    (row,) = _rows(normalized, keys["read"])
    assert encode(row)["visit_delta"] == -1 and encode(row)["requires_backedge"] is True
    with pytest.raises(ValueError):
        replace(row, requires_backedge=False)
    with pytest.raises(ValueError):
        replace(row, visit_delta=0)
    with pytest.raises(ValueError):
        replace(binding.plan, read_from=(replace(row, visit_delta=0, requires_backedge=False),))
    validate_loop_memory(binding.plan, normalized.memory_ssa)


@pytest.mark.parametrize("route", ("injected", "stitched"))
def test_previous_visit_relation_does_not_make_the_loop_numerically_executable(route):
    from tdo_v2.operation_records import Ineligible, StitchContext, eligibility, evaluate, root_record

    normalized, unit, keys = _fixture(return_unit=True)
    assert any(row.visit_delta == -1 and row.requires_backedge for row in _rows(normalized, keys["read"]))
    seeds = [(normalized.memory_graph.definition_nodes[i], (definition.span,))
             for i, definition in enumerate(normalized.memory_ssa.definitions) if definition.operation_key == keys["read"]]
    assert len(seeds) == 1
    record = root_record(normalized, unit, seeds, stitch=StitchContext({}, assumptions=()))
    assert eligibility(record, route=route) == "loop"

    def unreadable(_):
        raise AssertionError("phase-qualified static relation is not numeric loop execution")

    with pytest.raises(Ineligible, match="loop"):
        evaluate(record, unreadable, route=route)
