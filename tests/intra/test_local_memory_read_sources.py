"""Local STORE/LOAD identity settles memory, not unknown source values.

Original SSA and debt nodes remain immutable. Only a complete, ordered read
source view may stop following the memory alternatives of its exact LOAD.
"""

from collections import Counter
from dataclasses import replace

import pytest

from pcode_interpreter import Interpreter
from synthetic import (
    CONST, DATA_BASE, RAM, REG, R8, RAX, RBX, RCX, RDI, RDX, RSI, RSP,
    FunctionBuilder, add, const, copy, load, op, program_units, reg, store, tmp,
)
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.model import ByteSpan
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction


BASE, VALUE = DATA_BASE + 0x100, 0x0123456789abcdef


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def _engine(monkeypatch, request):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)


def _fixture(variant="base"):
    builder, keys = FunctionBuilder(), {}
    address, reloaded, value, flag = tmp(0x8100), tmp(0x8110), tmp(0x8120), tmp(0x8130, 1)

    def ins(name, *operations):
        keys[name] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:{len(operations)-1}:{operations[-1][0]}"
        builder.ins(*operations)

    if variant in ("alias-before", "source-debt", "loaded-address"):
        ins("old_alias", store(reg(R8), const(0x87654321)))
    pointer = reg(RDI)
    if variant == "loaded-address":
        pointer = tmp(0x8150)
        ins("pointer", load(pointer, reg(RDI)))
    if variant == "source-debt":
        ins("value", load(value, reg(RSI)))
    elif variant == "fragments":
        # Raw four-byte p-code COPY, not ISA EDX upper-byte zero-extension.
        ins("value", copy(reg(RDX, 4), const(5, 4)))
        value = reg(RDX)
    elif variant == "constant":
        value = const(VALUE)
    else:
        ins("value", add(value, reg(RDX), const(1)))
    ins("address", add(address, pointer, const(16)))
    if variant == "bypass":
        builder.cbranch("read", reg(RCX, 1))
    ins("write", store(address, value))
    if variant == "write":
        ins("barrier", store(reg(RSI), const(7, 1)))
    elif variant == "partial-write":
        ins("barrier", add(tmp(0x8140), address, const(3)), store(tmp(0x8140), const(7, 1)))
    elif variant == "call":
        builder.call(0x1f00)
    elif variant == "address-redefined":
        ins("change", add(reg(RDI), reg(RDI), const(8)))
    elif variant == "address-partial-write":
        ins("change", copy(reg(RDI, 4), reg(RBX, 4)))
    elif variant == "source-overwritten":
        ins("change", copy(value, const(0)))
    elif variant == "diamond":
        builder.cbranch("right", reg(RCX, 1))
        builder.ins(copy(reg(RBX), const(1))).branch("read")
        builder.label("right").ins(copy(reg(RBX), const(2)))
    elif variant == "cycle":
        builder.label("spin").ins(copy(reg(RBX), reg(RBX))).cbranch("spin", reg(RCX, 1))
    builder.label("read")
    if variant == "32-vs-64":
        ins("reload_address", op("INT_ZEXT", [reg(RDI, 4)], reloaded),
            add(reloaded, reloaded, const(16)))
    elif variant == "same-varnode":
        reloaded = address
    else:
        ins("reload_address", add(reloaded, pointer, const(16)))
    ins("read", load(reg(RAX), reloaded))
    builder.ret()
    (unit,) = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    assert isinstance(normalized, NormalizedFunction)
    return normalized, unit, keys


def _rows(normalized, reader):
    binding = normalized.memory_graph.local_reads
    return () if binding is None else tuple(row for row in binding.plan.reads if row.reader == reader)


def _current_use_fixture(variant="unchanged"):
    """The CALL makes RDI unknown; later uses need not equal entry RDI.

    Two present register reads can still be equal when the requested bytes
    are preserved between those reads. No calling convention is supplied.
    """
    builder, keys = FunctionBuilder().call(0x1f00), {}
    first, second = tmp(0x9100), tmp(0x9110)

    def ins(name, *operations):
        keys[name] = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:{len(operations)-1}:{operations[-1][0]}"
        builder.ins(*operations)

    if variant == "read-then-write":
        first = reg(RDI)
    ins("first", add(first, reg(RDI), const(16)))
    ins("write", store(first, const(VALUE)))
    if variant == "partial-write":
        ins("change", copy(reg(RDI, 1), const(0x77, 1)))
    elif variant == "unrelated-write":
        ins("change", copy(reg(RBX, 1), const(0x77, 1)))
    elif variant == "bypass-write":
        builder.cbranch("second", reg(RCX, 1))
        ins("change", copy(reg(RDI, 1), const(0x77, 1)))
    elif variant == "call":
        builder.call(0x1f10)
    elif variant == "kill":
        ins("change", op("CALLOTHER", [const(0x777, 4), reg(RDI)], reg(RDI)))
    elif variant == "cycle":
        builder.label("spin").ins(copy(reg(RBX), reg(RBX))).cbranch("spin", reg(RCX, 1))
    builder.label("second")
    ins("second", add(second, reg(RDI), const(16)))
    ins("read", load(reg(RAX), second))
    builder.ret()
    (unit,) = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    assert isinstance(normalized, NormalizedFunction)
    return normalized, unit, keys


def _seeds(normalized, reader):
    return [(normalized.memory_graph.definition_nodes[index], (definition.span,))
            for index, definition in enumerate(normalized.memory_ssa.definitions)
            if definition.operation_key == reader]


def _target_debts(normalized, reader):
    graph = normalized.dependencies
    return {source for source, _, edge in graph.in_edges(graph.node_for_key("op:" + reader))
            if edge.kind in ("may_alias_read", "unresolved_read", "call_clobber_read")}


def _typed(normalized, row):
    graph, memory, ssa = normalized.dependencies, normalized.memory_graph, normalized.memory_ssa
    binding = memory.local_reads
    start = sum(len(prior.parts) for prior in binding.plan.reads[:binding.plan.reads.index(row)])
    assert row.parts and row.output_span.size == sum(part.width for part in row.parts)
    assert [(part.output_offset, part.width) for part in row.parts] == \
        [(sum(prior.width for prior in row.parts[:index]), part.width) for index, part in enumerate(row.parts)]
    for number, part in enumerate(row.parts, start):
        source, effect = binding.source_nodes[number], binding.effect_nodes[number]
        assert graph.node(effect).kind is NodeKind.EFFECT and graph.node(effect).label == "local_memory_read_from"
        assert source != graph.node_for_key("op:" + row.writer)
        if part.constant is None:
            assert part.source_definition_id is not None and part.source_span is not None
            assert source == memory.definition_nodes[part.source_definition_id]
            assert ssa.definitions[part.source_definition_id].span.contains(part.source_span)
        else:
            assert part.source_definition_id is part.source_span is None
            assert graph.node(source).kind is NodeKind.CONSTANT
        assert any(target == effect and edge.kind == "local_read_from_value" and edge.span == part.source_span
                   and edge.occurrence == part.value_offset for _, target, edge in graph.out_edges(source))
        output = ByteSpan(row.output_span.object_id, row.output_span.start + part.output_offset, part.width)
        assert any(target == graph.node_for_key("op:" + row.reader) and edge.kind == "local_read_from"
                   and edge.span == output and edge.occurrence == part.output_offset
                   for _, target, edge in graph.out_edges(effect))
        assert any(source == graph.node_for_key("op:" + row.writer) and edge.kind == "local_read_from_witness"
                   for source, _, edge in graph.in_edges(effect))


def _concrete(unit, keys, variant, branch=0):
    def image(space, address):
        return (BASE + 0x80) >> (8 * (address - BASE)) & 255 \
            if variant == "loaded-address" and space == RAM and BASE <= address < BASE + 8 else None

    vm = Interpreter(unit.observation, constant_space=CONST, seed=0, image=image)
    for register, value in {RSP: 0x70000000, RDI: BASE, R8: BASE + 16, RSI: BASE + 16,
                            RDX: VALUE - 1, RCX: branch}.items():
        vm.preset(REG, register, 8, value)
    run = vm.run()
    assert run.completed and not vm.opaque_opcodes
    actual = {(row.offset, row.writer) for row in run.dependencies if row.reader == keys["read"] and row.space_id == RAM}
    target = BASE + (0x90 if variant == "loaded-address" else 16)
    assert actual == {(target + byte, keys["write"]) for byte in range(8)}
    expected = ((VALUE - 1) & ~0xffffffff) | 5 if variant == "fragments" else \
        0x87654321 if variant == "source-debt" else VALUE
    assert sum(vm.final_bytes()[REG, RAX + byte][0] << (8 * byte) for byte in range(8)) == expected


@pytest.mark.parametrize("variant", ("base", "same-varnode", "constant", "alias-before", "loaded-address",
                                     "diamond", "source-overwritten"))
def test_original_address_identity_and_all_path_order_link_exact_stored_bytes(variant):
    from tdo_v2._memory_read_sources import read_source
    from tdo_v2.lane_slice import lane_slice

    normalized, unit, keys = _fixture(variant)
    (row,) = _rows(normalized, keys["read"])
    assert row.writer == keys["write"] and row.reader == keys["read"]
    _typed(normalized, row)
    view = read_source(normalized, keys["read"])
    assert view.local == row and view.image is None and view.output_span == row.output_span
    old_debts = _target_debts(normalized, keys["read"])
    assert old_debts <= set(view.inactive_debts)
    lane = lane_slice(normalized, unit, _seeds(normalized, keys["read"]))
    assert not (old_debts & lane.nodes)
    if variant == "loaded-address":
        pointer_debts = _target_debts(normalized, keys["pointer"])
        assert pointer_debts and not (pointer_debts & set(view.inactive_debts))
        assert pointer_debts <= lane.nodes
    for branch in (0, 1) if variant == "diamond" else (0,):
        _concrete(unit, keys, variant, branch)


def test_partial_original_register_sources_keep_entry_bytes_and_offsets():
    normalized, unit, keys = _fixture("fragments")
    (row,) = _rows(normalized, keys["read"])
    _typed(normalized, row)
    assert [(part.value_offset, part.output_offset, part.width) for part in row.parts] == [(0, 0, 4), (4, 4, 4)]
    assert [normalized.memory_ssa.definitions[part.source_definition_id].kind for part in row.parts] == \
        [MemoryDefinitionKind.DATA_WRITE, MemoryDefinitionKind.ENTRY]
    assert [part.source_span.start for part in row.parts] == [RDX, RDX + 4]
    _concrete(unit, keys, "fragments")


@pytest.mark.parametrize("byte", (0, 5))
def test_byte_demand_uses_only_the_corresponding_store_source_fragment(byte):
    from tdo_v2.lane_slice import lane_slice

    normalized, unit, keys = _fixture("fragments")
    (row,) = _rows(normalized, keys["read"])
    ((output, _),) = _seeds(normalized, keys["read"])
    selected = ByteSpan(row.output_span.object_id, row.output_span.start + byte, 1)
    lane = lane_slice(normalized, unit, ((output, (selected,)),))
    wanted, other = (row.parts[0], row.parts[1]) if byte == 0 else (row.parts[1], row.parts[0])
    source = normalized.memory_graph.definition_nodes[wanted.source_definition_id]
    assert lane.demands[source] == frozenset({RDX + byte})
    assert normalized.memory_graph.definition_nodes[other.source_definition_id] not in lane.nodes


@pytest.mark.parametrize("forward", ("0", "1"))
def test_settled_target_memory_does_not_hide_an_independent_source_value_debt(monkeypatch, forward):
    from tdo_v2._memory_read_sources import read_source
    from tdo_v2.lane_slice import lane_slice
    from tdo_v2.operation_records import Ineligible, eligibility, evaluate, root_record

    monkeypatch.setenv("TDO_V2_FORWARD", forward)
    normalized, unit, keys = _fixture("source-debt")
    (row,) = _rows(normalized, keys["read"])
    _typed(normalized, row)
    source_debts = _target_debts(normalized, keys["value"])
    assert source_debts
    view = read_source(normalized, keys["read"])
    assert not (source_debts & set(view.inactive_debts))
    lane = lane_slice(normalized, unit, _seeds(normalized, keys["read"]))
    assert source_debts <= lane.nodes
    record = root_record(normalized, unit, _seeds(normalized, keys["read"]))
    assert eligibility(record) == "debt"

    def unreadable(_):
        raise AssertionError("A local overwrite cannot invent the independent source LOAD value")

    with pytest.raises(Ineligible, match="debt"):
        evaluate(record, unreadable)
    _concrete(unit, keys, "source-debt")


@pytest.mark.parametrize("variant", ("write", "call", "address-redefined", "address-partial-write",
                                     "bypass", "cycle", "32-vs-64"))
def test_interference_or_unequal_address_occurrences_issue_no_complete_source(variant):
    from tdo_v2._memory_read_sources import read_source

    normalized, _, keys = _fixture(variant)
    assert not _rows(normalized, keys["read"])
    assert read_source(normalized, keys["read"]) is None


def test_exact_partial_interference_replaces_only_its_written_byte():
    from tdo_v2._memory_read_sources import read_source

    normalized, _, keys = _fixture("partial-write")
    source = read_source(normalized, keys["read"])
    assert source is not None and source.local.complete
    assert [(p.output_offset, p.width, p.writer) for p in source.local.parts] == [
        (0, 3, keys["write"]), (3, 1, keys["barrier"]), (4, 4, keys["write"])]


@pytest.mark.parametrize("excluded", ("write", "read", "address", "reload_address"))
def test_overridden_original_address_or_access_is_not_reproved_as_raw_pcode(excluded):
    from tdo_v2._memory_read_sources import derive_local_read_sources

    normalized, unit, keys = _fixture()
    plan = derive_local_read_sources(normalized.memory_unit, normalized.memory_ssa, unit.observation,
        unit.scopes.function.entry, unit.scopes.resolution_context, unit.scopes.program.evidence.address_spaces,
        unit.scopes.program.evidence.translation_namespace, clobbered=normalized.call_clobber_reads,
        excluded=frozenset({keys[excluded]}))
    assert plan is None or all(row.reader != keys["read"] for row in plan.reads)


def test_local_relation_off_keeps_original_ssa_graph_and_memory_uncertainty(monkeypatch):
    from tdo_v2 import _memory_read_sources

    after, unit, keys = _fixture("loaded-address")
    assert _rows(after, keys["read"])
    with monkeypatch.context() as disabled:
        disabled.setattr(_memory_read_sources, "derive_local_read_sources", lambda *args, **kwargs: None)
        before = FunctionNormalizer().normalize(unit)
    assert before.memory_graph.local_reads is None
    for field in ("memory_ssa", "memory_unit", "may_alias_reads", "call_clobber_reads", "uncertain_writers",
                  "forward_memory_proofs", "load_value_proofs", "premise_uses"):
        assert getattr(before, field) == getattr(after, field)

    def edges(normalized):
        graph = normalized.dependencies
        return Counter((graph.node(source).key, graph.node(target).key, edge)
                       for source, target, edge in graph.weighted_edges() if not edge.kind.startswith("local_read_from"))

    assert edges(before) == edges(after)
    assert _target_debts(before, keys["read"])


@pytest.mark.parametrize("change", ("writer", "source", "offset", "source-node"))
def test_original_fact_and_source_bindings_cannot_be_changed(change):
    normalized, _, keys = _fixture()
    binding = normalized.memory_graph.local_reads
    (row,) = _rows(normalized, keys["read"])
    with pytest.raises((ValueError, TypeError)):
        if change == "source-node":
            local = replace(binding, source_nodes=(normalized.dependencies.node_for_key("op:" + row.writer),))
        else:
            part = row.parts[0]
            changed = replace(row, writer=keys["read"]) if change == "writer" else replace(row, parts=(
                replace(part, source_definition_id=0) if change == "source" else replace(part, output_offset=1),))
            local = replace(binding, plan=replace(binding.plan, reads=(changed,)))
        replace(normalized, memory_graph=replace(normalized.memory_graph, local_reads=local))


@pytest.mark.parametrize("variant", ("unchanged", "unrelated-write"))
def test_past_call_leaves_equal_current_register_reads_but_not_a_known_entry_pointer(variant):
    from tdo_v2._memory_read_sources import read_source
    from tdo_v2.lane_slice import lane_slice
    from tdo_v2.operation_records import Ineligible, eligibility, evaluate, root_record

    normalized, unit, keys = _current_use_fixture(variant)
    (row,) = _rows(normalized, keys["read"])
    _typed(normalized, row)
    (first, second, span, corridor), = row.address_ports
    assert (first, second) == (keys["first"], keys["second"])
    assert span.object_id.kind.value == "register_file" and (span.start, span.size) == (RDI, 8)
    assert set(corridor) == {keys["write"], *([keys["change"]] if variant == "unrelated-write" else [])}
    address_debts = _target_debts(normalized, keys["second"])
    assert address_debts
    view = read_source(normalized, keys["read"])
    assert not (address_debts & set(view.inactive_debts))
    lane = lane_slice(normalized, unit, _seeds(normalized, keys["read"]))
    assert address_debts <= lane.nodes
    record = root_record(normalized, unit, _seeds(normalized, keys["read"]))
    assert eligibility(record) == "debt"

    def unreadable(_):
        raise AssertionError("Present-use equality cannot recover the pre-CALL pointer value")

    with pytest.raises(Ineligible, match="debt"):
        evaluate(record, unreadable)


@pytest.mark.parametrize("variant", ("partial-write", "read-then-write", "call", "kill", "bypass-write", "cycle"))
def test_current_register_snapshot_cannot_cross_changes_or_repeated_cfg(variant):
    from tdo_v2._memory_read_sources import read_source

    normalized, _, keys = _current_use_fixture(variant)
    assert not _rows(normalized, keys["read"])
    assert read_source(normalized, keys["read"]) is None


def test_first_address_producer_read_before_write_does_not_preserve_its_register():
    from tdo_v2._guarded_image_reads import _Index
    from tdo_v2._memory_corridor import write_free_corridor
    from tdo_v2._sparse_dataflow import DominatorGraph

    normalized, unit, keys = _current_use_fixture("read-then-write")
    index = _Index(normalized.memory_unit, normalized.memory_ssa, unit.observation, unit.scopes.function.entry,
                   unit.scopes.resolution_context, frozenset(), normalized.call_clobber_reads, frozenset())
    span = index.span(index.raw[keys["first"]].inputs[0])
    dom = DominatorGraph(index.cfg.entry, index.predecessors)
    assert write_free_corridor(index, keys["first"], keys["second"], dom, register_span=span) is None


@pytest.mark.parametrize("excluded", ("first", "second", "write", "read"))
def test_current_register_snapshot_does_not_hide_original_override_boundaries(excluded):
    from tdo_v2._memory_read_sources import derive_local_read_sources

    normalized, unit, keys = _current_use_fixture()
    assert _rows(normalized, keys["read"])
    plan = derive_local_read_sources(normalized.memory_unit, normalized.memory_ssa, unit.observation,
        unit.scopes.function.entry, unit.scopes.resolution_context, unit.scopes.program.evidence.address_spaces,
        unit.scopes.program.evidence.translation_namespace, clobbered=normalized.call_clobber_reads,
        excluded=frozenset({keys[excluded]}))
    assert plan is None or all(row.reader != keys["read"] for row in plan.reads)


@pytest.mark.parametrize("clobbered,depth", ((False, 24), (True, 18)))
def test_shared_address_dags_are_finite_or_refused_with_bounded_work(monkeypatch, clobbered, depth):
    from tdo_v2 import _memory_read_sources as sources

    work, original_step, original_charge = [0, 0], sources.step, sources._Address.charge

    def counted_step():
        work[0] += 1
        assert work[0] <= 20_000, "Shared ADD(x,x) must not cause path/tree expansion"
        original_step()

    def counted_charge(self):
        try:
            return original_charge(self)
        finally:
            work[1] = max(work[1], self.work)

    monkeypatch.setattr(sources, "step", counted_step)
    monkeypatch.setattr(sources._Address, "charge", counted_charge)
    builder = FunctionBuilder()
    if clobbered:
        builder.call(0x1f00)
    value = reg(RDI)
    for number in range(depth):
        output = tmp(0xa000 + 16 * number)
        builder.ins(add(output, value, value))
        value = output
    writer = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:0:STORE"
    builder.ins(store(value, const(VALUE)))
    reader = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:0:LOAD"
    builder.ins(load(reg(RAX), value)).ret()
    (unit,) = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    assert isinstance(normalized, NormalizedFunction)
    if clobbered:
        assert work[1] == 1025 and not _rows(normalized, reader)
    else:
        (row,) = _rows(normalized, reader)
        assert row.writer == writer and not row.address_ports
        assert work[1] < 1025
        vm = Interpreter(unit.observation, constant_space=CONST, seed=0)
        vm.preset(REG, RSP, 8, 0x70000000)
        vm.preset(REG, RDI, 8, 3)
        run = vm.run()
        assert run.completed and not vm.opaque_opcodes
        assert {dependency.writer for dependency in run.dependencies
                if dependency.reader == reader and dependency.space_id == RAM} == {writer}


@pytest.mark.parametrize("change", ("call-clobbers", "override", "intrinsic", "memory-identity"))
def test_local_read_authority_rejects_stale_call_or_operation_policy(change):
    normalized, _, keys = _current_use_fixture()
    assert _rows(normalized, keys["read"])
    changes = {
        "call-clobbers": {"call_clobber_reads": (), "call_clobber_debts": ()},
        "override": {"operation_overrides": ((keys["first"], 0),)},
        "intrinsic": {"intrinsic_refinements": ((keys["first"], None),)},
        "memory-identity": {"memory_unit": replace(normalized.memory_unit)},
    }
    # A new policy key invalidates the old derivation before the value of
    # that proposed override/intrinsic is interpreted by any consumer.
    with pytest.raises(ValueError, match="local reads require unchanged memory"):
        replace(normalized, **changes[change])


def test_repeated_operand_reads_require_identical_original_fragments():
    from tdo_v2._guarded_image_reads import _Index, _Refused

    builder = (FunctionBuilder().ins(copy(reg(RDI), reg(RBX)))
               .ins(add(tmp(0xb000), reg(RDI), reg(RDI)))
               .ins(store(tmp(0xb000), const(VALUE))).ins(load(reg(RAX), tmp(0xb000))).ret())
    (unit,) = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    ssa, key = normalized.memory_ssa, "1:1004:0:INT_ADD"
    reads = [read for read in ssa.reads if ssa.actions[read.action_id].operation_key == key]
    assert len(reads) == 2 and reads[0].fragments == reads[1].fragments

    def index(result):
        return _Index(normalized.memory_unit, result, unit.observation, unit.scopes.function.entry,
                      unit.scopes.resolution_context, frozenset(), normalized.call_clobber_reads, frozenset())

    original = index(ssa)
    assert original.fragments(key, reads[0].span) == reads[0].fragments
    entry = next(identifier for identifier, definition in enumerate(ssa.definitions)
                 if definition.kind is MemoryDefinitionKind.ENTRY and definition.span.contains(reads[0].span))
    altered = replace(reads[1], fragments=(replace(reads[1].fragments[0], definition_ids=(entry,)),))
    assert altered.fragments != reads[0].fragments
    # This is malformed-SSA consumer defense, not a claim that the ordinary
    # SSA builder gives different pre-write values to ADD(x,x)'s operands.
    forged = replace(ssa, reads=tuple(altered if read is reads[1] else read for read in ssa.reads))
    conflicting = index(forged)
    assert conflicting.reads[reads[0].action_id, reads[0].span] is None
    with pytest.raises(_Refused):
        conflicting.fragments(key, reads[0].span)


@pytest.mark.parametrize("joined", (False, True))
@pytest.mark.parametrize("selected", ((0,), (1,), (0, 2), (0, 1), (7,), tuple(range(8))))
def test_partial_read_ports_keep_byte_demand_without_waiving_original_memory_debts(joined, selected):
    from tdo_v2._memory_read_sources import read_source
    from tdo_v2.lane_slice import lane_slice

    builder = FunctionBuilder()
    address, patch_address, patch_value = tmp(0x9800), tmp(0x9810), tmp(0x9820, 1)
    builder.ins(add(address, reg(RDI), const(16)), store(address, reg(RDX)))
    # This unrelated-address STORE may overwrite any byte of the old value.
    # A later exact one-byte patch proves only output byte 1, never a full read.
    barrier = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:0:STORE"
    builder.ins(store(reg(RSI), const(0x778899aa)))
    if joined:
        builder.cbranch("right", reg(R8, 1))
        builder.ins(copy(patch_value, reg(RCX, 1))).branch("patch")
        builder.label("right").ins(copy(patch_value, reg(RBX, 1))).label("patch")
    else:
        builder.ins(copy(patch_value, reg(RCX, 1)))
    writer = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:1:STORE"
    builder.ins(add(patch_address, address, const(1)), store(patch_address, patch_value))
    reader = f"1:{builder.entry + len(builder._rows) * builder.stride:x}:0:LOAD"
    builder.ins(load(reg(RAX), address)).ret()
    unit, = program_units(builder)
    normalized = FunctionNormalizer().normalize(unit)
    row, = _rows(normalized, reader)
    assert not row.complete and read_source(normalized, reader) is None
    part, = row.parts
    assert (part.writer, part.output_offset, part.value_offset, part.width) == (writer, 1, 0, 1)
    source = normalized.memory_graph.definition_nodes[part.source_definition_id]
    if joined:
        definition = normalized.memory_ssa.definitions[part.source_definition_id]
        assert definition.kind is MemoryDefinitionKind.JOIN
    seeds = [(node, tuple(ByteSpan(span.object_id, span.start + byte, 1) for byte in selected))
             for node, (span,) in _seeds(normalized, reader)]
    original_ssa = normalized.memory_ssa
    original_edges = Counter(normalized.dependencies.weighted_edges())
    lane = lane_slice(normalized, unit, seeds)
    assert normalized.memory_ssa is original_ssa
    assert Counter(normalized.dependencies.weighted_edges()) == original_edges
    assert (source in lane.nodes) is (1 in selected)
    binding = normalized.memory_graph.local_reads
    port = sum(len(prior.parts) for prior in binding.plan.reads[:binding.plan.reads.index(row)])
    assert (binding.effect_nodes[port] in lane.nodes) is (1 in selected)
    if source in lane.nodes:
        assert lane.demands[source] == frozenset({part.source_span.start})
    if joined:
        join, = [join for join in normalized.memory_ssa.joins
                 if join.join_definition_id == part.source_definition_id]
        alternatives = {normalized.memory_graph.definition_nodes[i] for i in join.source_definition_ids}
        assert len(alternatives) == 2
        assert alternatives <= lane.nodes if 1 in selected else not alternatives & lane.nodes
    # Partial ports add evidence only: even for covered byte 1, retain the
    # original raw memory read, its possible alias writer, and every debt.
    debts = _target_debts(normalized, reader)
    assert debts and debts <= lane.nodes
    assert normalized.dependencies.node_for_key("op:" + barrier) in lane.nodes
    action = next(i for i, action in enumerate(normalized.memory_ssa.actions)
                  if action.operation_key == reader)
    read, = [read for read in normalized.memory_ssa.reads if read.action_id == action
             and read.span.object_id.kind.value == "function_relative"]
    for fragment in read.fragments:
        if any(fragment.span.start <= read.span.start + byte < fragment.span.end for byte in selected):
            assert {normalized.memory_graph.definition_nodes[i] for i in fragment.definition_ids} <= lane.nodes


def test_address_equality_never_expands_shared_subterms_with_tuple_equality():
    from tdo_v2._memory_read_sources import _same_address

    calls = [0]

    class Term(tuple):
        def __eq__(self, other):
            calls[0] += 1
            return tuple.__eq__(self, other)

        __hash__ = tuple.__hash__

    def shared(depth):
        term = Term(("entry", 0, "span"))
        for _ in range(depth):
            term = Term(("INT_ADD", 8, Term((term, term))))  # ADD(x, x): 2**depth paths
        return term

    # Two independently built (not identical) DAGs: only the memoized walk may
    # compare them, never a recursive tuple comparison of whole sub-DAGs.
    assert _same_address(shared(16), shared(16), None, None, [])
    assert calls[0] < 1000
