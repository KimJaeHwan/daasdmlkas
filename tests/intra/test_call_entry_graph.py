"""Physical entry links survive absent return effects and sink selection."""

from dataclasses import replace

import pytest

from synthetic import (
    AARCH64, X64, X86_32, DATA_BASE, RAX, RCX, RDX, RSI, RSP, FunctionBuilder,
    add, const, copy, load, program_units, ram, reg, store, tmp,
)
from tdo_v2.call_entry_graph import state_sources
from tdo_v2.interprocedural import analyze_units
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.span_geometry import StorageObjectKind
from test_interprocedural import _sink_roots


LEAF = 0x1800


def _entry(item, kind, start=None):
    return next(identifier for identifier, definition in enumerate(item.normalized.memory_ssa.definitions)
                if definition.kind is MemoryDefinitionKind.ENTRY
                and definition.span.object_id.kind is kind
                and (start is None or definition.span.start <= start < definition.span.end))


def _relations(caller, leaf, **options):
    result = analyze_units(program_units(caller, leaf), **options)
    owner = result['1:1000']
    relation = next(row for row in owner.entry_relations if row.target == f'1:{LEAF:x}')
    return result, owner, relation


def _register_port(results, relation, offset, width=8):
    from tdo_v2.span_geometry import ByteSpan
    identifier = _entry(results['1:1800'], StorageObjectKind.REGISTER_FILE, offset)
    span = results['1:1800'].normalized.memory_ssa.definitions[identifier].span
    return relation.register_binding(identifier, ByteSpan(span.object_id, offset, width))


def test_no_return_or_sink_is_needed_for_entry_register_sources(monkeypatch):
    monkeypatch.setenv('TDO_V2_FORWARD', '1')
    caller = FunctionBuilder().ins(copy(reg(RCX), reg(RSI))).call(LEAF).ret()
    leaf = (FunctionBuilder(entry=LEAF).ins(copy(tmp(0x300), reg(RCX)))
            .tail_call(0x1f00))
    baseline, owner, relation = _relations(caller, leaf)
    assert relation.call not in owner.proven
    binding = relation.register_binding(_entry(baseline['1:1800'], StorageObjectKind.REGISTER_FILE, RCX))
    assert binding.operation == 'identity' and not binding.frontier
    assert {owner.normalized.memory_ssa.definitions[index].operation_key
            for part in binding.sources for index in part.definition_ids} == {'1:1000:0:COPY'}
    # This is an actual cross-graph dependency, not just a target-name link:
    # caller COPY -> caller SSA def -> entry overlay -> callee ENTRY -> COPY.
    edge = next(edge for edge in relation.edges() if edge.destination_span == binding.span
                and edge.kind == 'call-entry-register')
    caller_copy = owner.normalized.dependencies.node_for_key('op:1:1000:0:COPY')
    callee_copy = baseline['1:1800'].normalized.dependencies.node_for_key('op:1:1800:0:COPY')
    assert caller_copy in owner.normalized.dependencies.backward_reachable((edge.caller_node,))
    assert edge.callee_node in baseline['1:1800'].normalized.dependencies.backward_reachable((callee_copy,))
    sink, _, sink_relation = _relations(caller, leaf, sink_roots=_sink_roots)
    assert sink_relation.call in sink['1:1000'].proven
    sink_binding = sink_relation.register_binding(_entry(sink['1:1800'], StorageObjectKind.REGISTER_FILE, RCX))
    def source_keys(binding, item):
        return [(part.span, tuple(item.normalized.memory_ssa.definitions[index].canonical_key
                                  for index in part.definition_ids)) for part in binding.sources]
    assert source_keys(binding, owner) == source_keys(sink_binding, sink['1:1000'])
    assert (binding.operation, binding.delta, binding.literal, binding.frontier) == \
           (sink_binding.operation, sink_binding.delta, sink_binding.literal, sink_binding.frontier)


@pytest.mark.parametrize('arch', (X64, X86_32, AARCH64))
def test_shared_call_state_keeps_existing_register_and_memory_sources(arch):
    size = arch.pointer
    out = RAX if arch is not AARCH64 else 0x4000
    source = RDX if arch is not AARCH64 else 0x4008
    caller = (FunctionBuilder(arch=arch).ins(copy(reg(source, size), const(19, size)))
              .ins(copy(ram(DATA_BASE, size), reg(source, size))).call(LEAF).ret())
    leaf = FunctionBuilder(entry=LEAF, arch=arch).ins(copy(reg(out, size), ram(DATA_BASE, size))).ret()
    results, owner, relation = _relations(caller, leaf)
    binding = relation.memory_binding(_entry(results['1:1800'], StorageObjectKind.ADDRESS_SPACE, DATA_BASE))
    assert binding.caller_place.start == DATA_BASE
    assert binding.sources
    assert all(owner.normalized.memory_ssa.definitions[identifier].operation_key == '1:1004:0:COPY'
               for part in binding.sources for identifier in part.definition_ids)
    assert 'memory content requires original writer/alias conditions' in binding.frontier


def test_two_call_sites_and_unknown_targets_keep_distinct_contexts():
    caller = FunctionBuilder().call(LEAF).call(LEAF).call(0x1f00).ret()
    leaf = FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), reg(RCX))).ret()
    results = analyze_units(program_units(caller, leaf))
    rows = results['1:1000'].entry_relations
    assert len(rows) == 3 and len({row.context for row in rows}) == 3
    assert rows[0]._callee is rows[1]._callee
    unknown = next(row for row in rows if row.target == '1:1f00')
    assert unknown.frontier == ('analyzed callee body unavailable',)
    assert unknown.state is not None


def test_call_state_and_edges_do_not_invent_untracked_registers():
    caller = FunctionBuilder().call(LEAF).ret()
    leaf = FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), reg(RSI))).tail_call(0x1f00)
    results, _, relation = _relations(caller, leaf)
    binding = relation.register_binding(_entry(results['1:1800'], StorageObjectKind.REGISTER_FILE, RSI))
    assert not binding.sources
    assert 'untracked caller register bytes' in binding.frontier
    edge = next(edge for edge in relation.edges() if edge.destination_span == binding.span)
    assert edge.kind == 'call-entry-state-point' and edge.caller_node is None and edge.frontier


def test_shared_snapshot_memory_is_not_a_preservation_proof_across_unknown_calls():
    caller = FunctionBuilder().call(0x1f00).call(LEAF).ret()
    leaf = FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), reg(RSI))).ret()
    results, _, relation = _relations(caller, leaf)
    binding = relation.register_binding(_entry(results['1:1800'], StorageObjectKind.REGISTER_FILE, RSI))
    assert binding.frontier
    assert relation.call in results['1:1000'].proven  # return effects are independent


def test_stale_instance_is_rejected_and_old_graphs_are_not_mutated():
    caller = FunctionBuilder().ins(copy(reg(RCX), reg(RSI))).call(LEAF).ret()
    leaf = FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), reg(RCX))).ret()
    results, owner, relation = _relations(caller, leaf)
    before = owner.normalized
    assert relation._normalized is before
    owner.normalized = replace(before, fault_reachable=not before.fault_reachable)
    with pytest.raises(ValueError, match='source instance changed'):
        relation.bindings()


def test_replacing_state_projection_context_or_target_does_not_authorize_an_edge():
    caller = FunctionBuilder().call(LEAF).call(LEAF).ret()
    leaf = FunctionBuilder(entry=LEAF).ins(load(reg(RAX), reg(RSP))).tail_call(0x1f00)
    results = analyze_units(program_units(caller, leaf))
    first, second = results['1:1000'].entry_relations
    for changes in ({'state': second.state}, {'projection': second.projection},
                    {'context': second.context}, {'target': '1:1f00'}):
        with pytest.raises(ValueError, match='source instance changed'):
            replace(first, **changes).bindings()


def test_separate_publications_have_distinct_contexts_even_for_identical_ssa():
    caller = FunctionBuilder().call(LEAF).ret()
    leaf = FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), reg(RCX))).ret()
    _, _, first = _relations(caller, leaf)
    _, _, second = _relations(caller, leaf)
    assert first._normalized.memory_ssa == second._normalized.memory_ssa
    assert first.context != second.context


def test_unprojected_arm_link_write_is_in_the_entry_state():
    from synthetic import X0, X30
    caller = FunctionBuilder(arch=AARCH64).call(LEAF).ret()
    leaf = FunctionBuilder(entry=LEAF, arch=AARCH64).ins(copy(reg(X0), reg(X30))).ret()
    results, owner, relation = _relations(caller, leaf)
    assert relation.projection is None
    binding = relation.register_binding(_entry(results['1:1800'], StorageObjectKind.REGISTER_FILE, X30))
    assert not binding.frontier
    assert {owner.normalized.memory_ssa.definitions[index].operation_key
            for part in binding.sources for index in part.definition_ids} == {'1:1000:0:INT_ADD'}


def test_loop_body_and_recursive_calls_keep_finite_entry_relations():
    caller = FunctionBuilder().call(LEAF).ret()
    leaf = FunctionBuilder(entry=LEAF).label('loop').call(LEAF).branch('loop')
    results = analyze_units(program_units(caller, leaf))
    assert len(results['1:1000'].entry_relations) == 1
    (recursive,) = results['1:1800'].entry_relations
    assert recursive.target == '1:1800' and recursive.state is not None
    assert recursive._callee is results['1:1800']


def test_nonreturning_body_stack_read_links_to_the_callers_original_store():
    caller = (FunctionBuilder().sub_rsp(0x28)
              .ins(add(tmp(0x100), reg(RSP), const(0x10)), store(tmp(0x100), reg(RDX)))
              .call(LEAF).add_rsp(0x28).ret())
    leaf = (FunctionBuilder(entry=LEAF)
            .ins(add(tmp(0x100), reg(RSP), const(0x18)), load(reg(RAX), tmp(0x100)))
            .tail_call(0x1f00))
    results, owner, relation = _relations(caller, leaf)
    assert relation.call not in owner.proven
    identifier = _entry(results['1:1800'], StorageObjectKind.FUNCTION_RELATIVE, (1 << 64) + 0x18)
    binding = relation.memory_binding(identifier)
    assert binding.caller_place is not None and binding.sources
    assert {owner.normalized.memory_ssa.definitions[index].operation_key
            for source in binding.sources for index in source.definition_ids} == {'1:1004:1:STORE'}
    assert binding.frontier == ('memory content requires original writer/alias conditions',)


def test_observed_call_push_binds_literal_without_inventing_a_return():
    caller = FunctionBuilder().call(LEAF).ret()
    leaf = FunctionBuilder(entry=LEAF).ins(load(reg(RAX), reg(RSP))).tail_call(0x1f00)
    results, owner, relation = _relations(caller, leaf)
    identifier = _entry(results['1:1800'], StorageObjectKind.FUNCTION_RELATIVE, 1 << 64)
    binding = relation.memory_binding(identifier)
    assert binding.operation == 'observed-call-store' and binding.literal == 0x1004
    edge = next(edge for edge in relation.edges() if edge.kind == 'call-entry-observed-store')
    assert edge.literal == binding.literal and edge.caller_node is not None
    assert relation.call not in owner.proven
    assert not any(operation.opcode == 'RETURN' for row in results['1:1800'].unit.observation.instructions
                   for operation in row.operations)


@pytest.mark.parametrize('value', (-1, True, '0', 10**9))
def test_definition_ports_reject_negative_noninteger_and_out_of_range_ids(value):
    results, _, relation = _relations(FunctionBuilder().call(LEAF).ret(),
        FunctionBuilder(entry=LEAF).ins(load(reg(RAX), reg(RSP))).ret())
    for method in (relation.register_binding, relation.memory_binding):
        with pytest.raises(ValueError, match='in-range exact int'):
            method(value)


def test_a_call_after_the_current_boundary_does_not_pollute_its_entry():
    caller = (FunctionBuilder().ins(copy(reg(RCX), reg(RSI))).call(LEAF)
              .call(0x1f00).ret())
    leaf = FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), reg(RCX))).tail_call(0x1e00)
    results, _, relation = _relations(caller, leaf)
    port = _register_port(results, relation, RCX)
    assert not port.frontier


def test_overwrite_after_opaque_call_clears_only_the_written_register_bytes():
    from tdo_v2.span_geometry import ByteSpan
    caller = (FunctionBuilder().ins(copy(reg(RCX), reg(RSI))).call(0x1f00)
              .ins(copy(reg(RCX, 4), const(9, 4))).call(LEAF).ret())
    leaf = FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), reg(RCX))).tail_call(0x1e00)
    results, _, relation = _relations(caller, leaf)
    identifier = _entry(results['1:1800'], StorageObjectKind.REGISTER_FILE, RCX)
    span = results['1:1800'].normalized.memory_ssa.definitions[identifier].span
    low = relation.register_binding(identifier, ByteSpan(span.object_id, RCX, 4))
    high = relation.register_binding(identifier, ByteSpan(span.object_id, RCX + 4, 4))
    assert not low.frontier
    assert any('register preservation unresolved' in reason for reason in high.frontier)
    edges = [edge for edge in relation.edges() if edge.kind == 'call-entry-register'
             and edge.destination_span.start < RCX + 8 and RCX < edge.destination_span.end]
    assert {(edge.source_span.start, edge.source_span.size, edge.destination_span.size)
            for edge in edges} == {(RCX, 4, 4), (RCX + 4, 4, 4)}


def test_one_opaque_branch_still_reaches_the_entry_frontier():
    from synthetic import ZF
    caller = (FunctionBuilder().ins(copy(reg(RCX), reg(RSI))).cbranch('clean', reg(ZF, 1))
              .call(0x1f00).label('clean').call(LEAF).ret())
    leaf = FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), reg(RCX))).tail_call(0x1e00)
    results, _, relation = _relations(caller, leaf)
    port = _register_port(results, relation, RCX)
    assert any('register preservation unresolved' in reason for reason in port.frontier)


def test_previous_visit_of_the_same_static_call_remains_a_clobber():
    caller = FunctionBuilder().ins(copy(reg(RCX), reg(RSI))).label('loop').call(LEAF).branch('loop')
    leaf = FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), reg(RCX))).tail_call(0x1e00)
    results, _, relation = _relations(caller, leaf)
    port = _register_port(results, relation, RCX)
    assert f'register preservation unresolved at {relation.call}' in port.frontier


def test_coalesced_sp_and_adjacent_register_entry_is_split_at_transition_bytes():
    from synthetic import RBP
    caller = FunctionBuilder().ins(copy(reg(RBP), reg(RSI))).call(LEAF).ret()
    leaf = (FunctionBuilder(entry=LEAF).ins(copy(tmp(0x100), reg(RSP)))
            .ins(copy(tmp(0x108), reg(RBP))).tail_call(0x1e00))
    _, _, relation = _relations(caller, leaf)
    ports = [port for port in relation.bindings() if port.span.object_id.kind is StorageObjectKind.REGISTER_FILE]
    assert any(port.span.start == RSP and port.span.size == 8 and port.operation == 'add-and-select' for port in ports)
    assert any(port.span.start == RBP and port.span.size == 8 and port.operation == 'identity' for port in ports)


@pytest.mark.parametrize('cached', (False, True))
def test_mutated_preservation_contract_is_rejected_before_and_after_lazy_cache(cached):
    caller = FunctionBuilder().ins(copy(reg(RCX), reg(RSI))).call(LEAF).ret()
    leaf = FunctionBuilder(entry=LEAF).ins(copy(reg(RAX), reg(RCX))).tail_call(0x1e00)
    results, owner, relation = _relations(caller, leaf)
    if cached:
        _register_port(results, relation, RCX)
        assert relation._index.clobbers is not None
    owner.normalized.call_clobber_contract[1]['modified'] = ()
    with pytest.raises(ValueError, match='clobber contract changed'):
        relation.bindings()
