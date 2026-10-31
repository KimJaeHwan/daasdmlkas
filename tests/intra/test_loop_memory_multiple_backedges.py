"""Alternative full-pointer updates remain one occurrence-qualified loop.

These original-CFG fixtures never duplicate paths or stipulate a trip count
to the engine. Concrete zero/one/many visits use the existing interpreter.
"""

from collections import Counter

import pytest

from graph_oracle import check
from pcode_interpreter import Entry
from synthetic import (
    RAX, RBX, RCX, RDX, R8, RSP, RAM, REG, FunctionBuilder,
    add, const, copy, load, op, program_units, reg, store, sub, tmp,
)
from test_loop_memory_read_from import BASE, SLOT, VALUE, _execute, _image
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction


def _fixture(shape="multiple", *, variant=None, diamonds=0, return_unit=False):
    builder, keys = FunctionBuilder(), {}
    pointer, old, address = reg(RBX), tmp(0x6000), tmp(0x6010)
    value, counter, flag = tmp(0x6100), tmp(0x6200), tmp(0x6300, 1)
    arms, merged = (3 if shape == "three" else 2), shape == "merged" or variant == "ambiguous-address"

    def ins(name, *operations):
        ordinal = len(operations) - 1
        keys[name] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:{ordinal}:{operations[-1][0]}"
        builder.ins(*operations)

    builder.ins(load(pointer, const(SLOT)), copy(counter, reg(RCX)))
    builder.cbranch("done", flag, op("INT_EQUAL", [counter, const(0)], flag))
    builder.label("header").ins(copy(old, pointer))
    if variant == "previous":
        ins("read-header", sub(address, pointer, const(16)), load(reg(RAX), address))
    ins("value", add(value, reg(RDX), const(1)))
    if variant == "bypass-store":
        builder.cbranch("dispatch", flag, op("INT_EQUAL", [counter, const(2)], flag))
    if variant != "local-store":
        if variant == "partial-read":
            ins("write", add(address, old, const(2)), store(address, value))
        else:
            ins("write", store(old, value))
    builder.label("dispatch")
    for number in range(diamonds):
        scratch = tmp(0x7000 + number * 8)
        builder.cbranch(f"diamond{number}-right", flag, op("INT_EQUAL", [reg(R8), const(number)], flag))
        builder.ins(copy(scratch, const(1))).branch(f"diamond{number}-join")
        builder.label(f"diamond{number}-right").ins(copy(scratch, const(2)))
        builder.label(f"diamond{number}-join")
    for number in reversed(range(1, arms)):
        builder.cbranch(f"arm{number}", flag, op("INT_EQUAL", [counter, const(number)], flag))
    builder.branch("arm0")
    for number in range(arms):
        builder.label(f"arm{number}")
        if variant == "local-store" and number == 0:
            ins("write0", store(old, value))
        if variant == "ambiguous-address" and number == 0:
            builder.ins(copy(address, pointer))
        if variant == "partial-write" and number == 1:
            ins("partial", copy(reg(RBX, 4), reg(RDX, 4)))
        if variant != "missing-update" or number != 1:
            step = 32 if variant == "different-stride" and number == 1 else 16
            ins(f"update{number}", add(pointer, pointer, const(step)))
        if variant == "two-updates" and number == 1:
            ins("update-extra", add(pointer, pointer, const(16)))
        if variant == "ambiguous-address" and number == 1:
            # The two reaching address values are old S(k) and updated
            # S(k)+16. Their union is not the header's one current value.
            builder.ins(copy(address, pointer))
        if variant == "call" and number == 1:
            builder.call(0x1f00)
        if merged:
            builder.branch("read-join")
        else:
            if variant != "previous":
                if variant == "partial-read":
                    ins(f"read{number}", add(tmp(0x6500), old, const(4)), load(reg(RAX, 4), tmp(0x6500)))
                else:
                    ins(f"read{number}", load(reg(RAX), old))
            builder.ins(sub(counter, counter, const(1)))
            builder.cbranch("header", flag, op("INT_NOTEQUAL", [counter, const(0)], flag))
            builder.branch("done")
    if merged:
        builder.label("read-join")
        ins("read", load(reg(RAX), address if variant == "ambiguous-address" else old))
        builder.ins(sub(counter, counter, const(1)))
        builder.cbranch("header", flag, op("INT_NOTEQUAL", [counter, const(0)], flag))
    builder.label("done").ret()
    (unit,) = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    assert isinstance(normalized, NormalizedFunction)
    return normalized, unit if return_unit else unit.observation, keys


def _relations(normalized):
    binding = normalized.memory_graph.loop_memory
    if binding is None:
        return {}
    return {binding.plan.accesses[row.reader_access].operation_key: (index, row)
            for index, row in enumerate(binding.plan.read_from)}


def _original_debts(normalized, keys):
    graph, ssa, memory = normalized.dependencies, normalized.memory_ssa, normalized.memory_graph
    for direction, occurrences, nodes in (("read", ssa.unresolved_reads, memory.unresolved_read_nodes),
                                          ("write", ssa.unresolved_writes, memory.unresolved_write_nodes)):
        found = set()
        for occurrence, node in zip(occurrences, nodes, strict=True):
            key = ssa.actions[occurrence.action_id].operation_key
            if key not in keys.values():
                continue
            operation = graph.node_for_key("op:" + key)
            source, target = (node, operation) if direction == "read" else (operation, node)
            assert any(edge.kind == "unresolved_" + direction and actual_target == target
                       for _, actual_target, edge in graph.out_edges(source))
            found.add(key)
        expected = {key for key in keys.values() if key.rsplit(":", 1)[-1] == ("LOAD" if direction == "read" else "STORE")}
        assert found == expected


def _typed_relation(normalized, number, row, writer_key, *, write_offset=0, width=8):
    graph, binding = normalized.dependencies, normalized.memory_graph.loop_memory
    plan = binding.plan
    assert plan.accesses[row.writer_access].operation_key == writer_key
    assert row.visit_delta == row.read_offset == 0 and row.write_offset == write_offset and row.width == width
    assert row.constant is None and row.source_span.start == 0x6100 + write_offset and row.source_span.size == width
    assert row.output_span.start == RAX and row.output_span.size == width
    definition = normalized.memory_ssa.definitions[row.source_definition_id]
    assert definition.operation_key.endswith(":INT_ADD") and definition.span.contains(row.source_span)
    source = normalized.memory_graph.definition_nodes[row.source_definition_id]
    node = binding.read_from_nodes[number]
    reader = graph.node_for_key("op:" + plan.accesses[row.reader_access].operation_key)
    writer = graph.node_for_key("op:" + writer_key)
    assert binding.read_from_source_nodes[number] == source and source != writer
    assert graph.node(node).kind is NodeKind.EFFECT and graph.node(node).label == "loop_same_visit_read_from"
    assert any(target == node and edge.kind == "loop_read_from_value" and edge.span == row.source_span
               for _, target, edge in graph.out_edges(source))
    assert any(target == reader and edge.kind == "loop_read_from" and edge.span == row.output_span
               for _, target, edge in graph.out_edges(node))
    assert any(target == node and edge.kind == "loop_read_from_witness"
               for _, target, edge in graph.out_edges(writer))


def _oracle(normalized, observation):
    report = check(normalized, observation, seeds=range(3), image=_image(BASE),
                   register_pools=lambda seed: {RSP: 0x70000000, RCX: (0, 1, 3)[seed],
                                                RDX: VALUE - 1, R8: 0})
    assert report.runs == 3 and report.checked and not report.unsupported
    assert not report.opaque_opcodes and not report.silent


@pytest.mark.parametrize("shape", ("multiple", "merged", "three"))
@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_alternative_updates_and_multiple_backedges_share_one_visit_without_losing_value(monkeypatch, shape, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    normalized, observation, keys = _fixture(shape)
    relations = _relations(normalized)
    expected = {key for name, key in keys.items() if name.startswith("read")}
    assert set(relations) == expected
    binding = normalized.memory_graph.loop_memory
    assert len({row.family_index for row in binding.plan.accesses}) == 1
    for number, row in relations.values():
        _typed_relation(normalized, number, row, keys["write"])
    _original_debts(normalized, keys)
    for count in (0, 1, 3):
        _, run, result = _execute(observation, count)
        assert sum(run.executed.count(key) for key in expected) == count
        if count:
            assert result == VALUE
            dependencies = [row for row in run.dependencies if row.reader in expected and row.space_id == RAM]
            assert dependencies and {row.writer for row in dependencies} == {keys["write"]}
    _oracle(normalized, observation)


@pytest.mark.parametrize("shape", ("multiple", "merged"))
def test_store_bypass_remains_unknown_despite_equal_pointer_updates(shape):
    normalized, observation, keys = _fixture(shape, variant="bypass-store")
    assert normalized.memory_graph.loop_memory is not None
    assert not _relations(normalized)
    _original_debts(normalized, keys)
    _oracle(normalized, observation)


def test_branch_local_store_proves_only_reader_reached_through_that_store():
    normalized, observation, keys = _fixture(variant="local-store")
    relations = _relations(normalized)
    assert set(relations) == {keys["read0"]}
    _typed_relation(normalized, *relations[keys["read0"]], keys["write0"])
    _original_debts(normalized, keys)
    _, run, _ = _execute(observation, 3)
    dependencies = [row for row in run.dependencies if row.reader == keys["read0"] and row.space_id == RAM]
    assert dependencies and {row.writer for row in dependencies} == {keys["write0"]}
    _oracle(normalized, observation)


def test_multiple_backedges_keep_selected_store_value_bytes_after_pointer_update():
    normalized, observation, keys = _fixture(variant="partial-read")
    relations = _relations(normalized)
    assert set(relations) == {keys["read0"], keys["read1"]}
    for number, row in relations.values():
        _typed_relation(normalized, number, row, keys["write"], write_offset=2, width=4)
    for count in (1, 3):
        interpreter, run, _ = _execute(observation, count)
        final = interpreter.final_bytes()
        assert sum(final[(REG, RAX + byte)][0] << (8 * byte) for byte in range(4)) == VALUE >> 16 & 0xffffffff
        dependencies = [row for row in run.dependencies if row.reader in relations and row.space_id == RAM]
        assert dependencies and {row.writer for row in dependencies} == {keys["write"]}
    _original_debts(normalized, keys)
    _oracle(normalized, observation)


@pytest.mark.parametrize("variant", ("different-stride", "missing-update", "two-updates", "partial-write", "call"))
def test_unproved_per_path_update_cannot_issue_family_or_same_visit_read_from(variant):
    normalized, observation, keys = _fixture(variant=variant)
    assert normalized.memory_graph.loop_memory is None
    assert not _relations(normalized)
    _original_debts(normalized, keys)
    if variant != "call":
        _oracle(normalized, observation)
    else:
        # Its opaque effects are deliberately not fabricated by a concrete
        # implementation; zero visits still verifies the original bypass.
        _, run, _ = _execute(observation, 0)
        assert not any(key.endswith(":CALL") for key in run.executed)


def test_mixed_pre_and_post_update_address_join_is_not_a_header_value():
    normalized, observation, keys = _fixture(variant="ambiguous-address")
    assert normalized.memory_graph.loop_memory is not None
    assert not _relations(normalized)
    assert all(access.operation_key != keys["read"]
               for access in normalized.memory_graph.loop_memory.plan.accesses)
    _original_debts(normalized, keys)
    _oracle(normalized, observation)


@pytest.mark.parametrize("shape", ("multiple", "three"))
def test_previous_visit_writer_is_conditional_and_initial_memory_remains(shape):
    normalized, observation, keys = _fixture(shape, variant="previous")
    assert normalized.memory_graph.loop_memory is not None
    assert set(_relations(normalized)) == {keys["read-header"]}
    assert all(row.visit_delta == -1 and row.requires_backedge for _, row in _relations(normalized).values())
    _original_debts(normalized, keys)
    _, run, result = _execute(observation, 3)
    assert result == VALUE
    dependencies = [row for row in run.dependencies if row.reader == keys["read-header"] and row.space_id == RAM]
    assert any(isinstance(row.writer, Entry) for row in dependencies)
    assert any(row.writer == keys["write"] for row in dependencies)
    _oracle(normalized, observation)


def test_multiple_backedge_read_from_addition_never_removes_original_ssa_or_candidates(monkeypatch):
    from tdo_v2 import _loop_memory_reads
    from tdo_v2.function_summary import summarize_function

    after, unit, keys = _fixture("three", return_unit=True)
    assert _relations(after)
    with monkeypatch.context() as disabled:
        disabled.setattr(_loop_memory_reads, "derive_read_from", lambda *args: ())
        before = FunctionNormalizer().normalize(unit)
    assert after.memory_ssa == before.memory_ssa and after.memory_unit == before.memory_unit
    assert after.may_alias_reads == before.may_alias_reads and after.uncertain_writers == before.uncertain_writers

    def original_edges(graph):
        return Counter((graph.node(source).key, graph.node(target).key, edge)
                       for source, target, edge in graph.weighted_edges()
                       if edge.kind not in ("loop_read_from", "loop_read_from_value", "loop_read_from_witness"))

    assert original_edges(before.dependencies) == original_edges(after.dependencies)
    assert summarize_function(before, unit.observation) == summarize_function(after, unit.observation)
    _original_debts(after, keys)


def test_many_diamonds_do_not_enumerate_paths_when_proving_alternative_updates(monkeypatch):
    from tdo_v2 import _loop_memory, _loop_memory_reads, _ssa_cycles

    work = 0

    def charged(amount=1):
        nonlocal work
        work += amount
        assert work < 100_000, "loop proof enumerated diamond path combinations"

    for module in (_loop_memory, _loop_memory_reads, _ssa_cycles):
        monkeypatch.setattr(module, "step", charged)
    normalized, _, keys = _fixture("merged", diamonds=24)
    assert _relations(normalized)
    assert work < 100_000
    _original_debts(normalized, keys)


def test_actual_pointer_join_with_zero_or_one_prior_update_is_not_header_phi(monkeypatch):
    from tdo_v2._loop_memory import _Index, _Proof

    builder, keys = FunctionBuilder(), {}
    pointer, counter, flag = reg(RBX), tmp(0x6200), tmp(0x6300, 1)

    def ins(name, *operations):
        keys[name] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:{len(operations) - 1}:{operations[-1][0]}"
        builder.ins(*operations)

    builder.ins(load(pointer, const(SLOT)), copy(counter, reg(RCX)))
    builder.cbranch("done", flag, op("INT_EQUAL", [counter, const(0)], flag))
    builder.label("header")
    ins("write", store(pointer, const(VALUE)))
    # The untouched selector correlates the two real branches, so concrete
    # visits perform exactly one update. The static CFG deliberately retains
    # all cross-products rather than assuming that correlation was proved.
    builder.cbranch("read", reg(R8, 1))
    ins("early", add(pointer, pointer, const(16)))
    builder.label("read")
    ins("read", load(reg(RAX), pointer))
    builder.cbranch("late", reg(R8, 1)).branch("latch")
    builder.label("late")
    ins("late", add(pointer, pointer, const(16)))
    builder.label("latch").ins(sub(counter, counter, const(1)))
    builder.cbranch("header", flag, op("INT_NOTEQUAL", [counter, const(0)], flag))
    builder.label("done").ret()
    (unit,) = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    assert isinstance(normalized, NormalizedFunction)
    assert normalized.memory_graph.loop_memory is None  # static paths include zero/two writes
    _original_debts(normalized, keys)

    index = _Index(normalized.memory_unit, normalized.memory_ssa, unit.observation,
                   unit.scopes.function.entry, unit.scopes.resolution_context)
    region = index.region_of[index.locations[keys["read"]]]
    loop = index.region(region)
    header, latches, preheader, _ = loop
    reference = index.reference(keys["read"], index.raw[keys["read"]].inputs[1])
    identifier, span, _ = reference
    initial = index.edge(preheader, header, span)
    transitions = frozenset(d for latch in latches for d in index.edge(latch, header, span)[1])
    proof = _Proof(index, loop, span, initial[1] | transitions, transitions, index.orders[region])
    assert proof.before_counts[keys["read"]] == (0, 1)
    assert frozenset(index.joins[identifier]) == proof.sources
    assert not proof.before_update(keys["read"])
    assert proof.form(*reference) is None
    # A source-set-only shortcut produces the false header identity on this
    # very original SSA, demonstrating why the use-point count guard matters.
    with monkeypatch.context() as changed:
        changed.setattr(proof, "before_update", lambda _: True)
        proof.cache.clear()
        assert proof.form(*reference) == (1, 0)
    proof.cache.clear()
    assert proof.form(*reference) is None

    report = check(normalized, unit.observation, seeds=range(6), image=_image(BASE),
                   register_pools=lambda seed: {RSP: 0x70000000, RCX: (0, 1, 3)[seed // 2],
                                                RDX: VALUE - 1, R8: seed % 2})
    assert report.runs == 6 and report.checked and not report.unsupported
    assert not report.opaque_opcodes and not report.silent
