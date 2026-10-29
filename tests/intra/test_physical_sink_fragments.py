"""A memory demand keeps the byte offset inside a larger raw STORE value."""

import pytest

from synthetic import DATA_BASE, R8, RAX, RCX, RDX, RSI, RSP, ZF, FunctionBuilder, add, const, copy, op, reg, store, tmp
from test_state_barrier import SINK, OPAQUE, _view, _keys
from tdo_v2.integration.configured_boundary_demands import _canonical_boundary_nodes, _direct_sink_boundary_nodes
from tdo_v2.integration.configured_physical_state import _FunctionPhysicalStateBackend
from tdo_v2.physical_state import PhysicalMemorySlice, PhysicalRegisterSlice, PhysicalValueFragment


def _program(*, after=None, offset=0):
    # A fixed-address pointer intentionally exercises relational binding,
    # rather than the direct entry-relative memory candidate path.
    value = tmp(0x800, 16)
    body = (FunctionBuilder().sub_rsp(0x28)
            .ins(op("PIECE", [reg(R8), reg(RSI)], value))
            .ins(copy(reg(RDX), const(DATA_BASE)), store(reg(RDX), value)))
    if after is not None:
        after(body)
    if offset:
        body.ins(add(reg(RDX), reg(RDX), const(offset)))
    return body.call(SINK).add_rsp(0x28).ret()


def _resolve(body, offset=8, size=2):
    view = _view(body)
    key = _keys(view, "CALL")[-1]
    selector = PhysicalMemorySlice(PhysicalRegisterSlice(RDX, 8), offset, size)
    backend = _FunctionPhysicalStateBackend(view)
    return view, key, selector, backend.value_fragments(selector, view.position(key))


@pytest.mark.parametrize("offset,size", ((0, 2), (3, 4), (8, 2), (14, 2), (0, 16)))
def test_subrange_receipt_uses_the_stored_values_own_storage(offset, size):
    view, key, selector, fragments = _resolve(_program(), offset, size)
    (fragment,) = fragments
    definition = view.memory.definitions[fragment.definition_id]
    assert fragment.source_span.object_id == definition.span.object_id
    assert fragment.source_span.start == definition.span.start + offset
    assert fragment.source_span.size == size
    assert definition.span.contains(fragment.source_span)
    assert view.operation(definition.operation_key).opcode == "PIECE"
    (boundary,) = _direct_sink_boundary_nodes(view, "consumer.bytes", key, view.position(key), 0, (selector,))
    assert boundary.physical_spans == (fragment.source_span,)


@pytest.mark.parametrize("offset,size", ((-1, 2), (15, 2), (16, 1), (0, 17)))
def test_a_wide_store_never_authorizes_bytes_outside_its_written_range(offset, size):
    assert not _resolve(_program(), offset, size)[-1]


def test_a_disjoint_later_store_keeps_the_selected_bytes():
    def after(body):
        body.ins(add(reg(RCX), reg(RDX), const(12)), store(reg(RCX), const(0, 4)))
    assert _resolve(_program(after=after))[-1]


@pytest.mark.parametrize("offset,width", ((8, 1), (9, 1), (7, 4), (0, 16)))
def test_an_overlapping_later_store_never_returns_the_stale_wide_definition(offset, width):
    def after(body):
        body.ins(add(reg(RCX), reg(RDX), const(offset)), store(reg(RCX), const(0, width)))
    view, _, _, found = _resolve(_program(after=after))
    assert not found or all(view.memory.definitions[f.definition_id].operation_key
                            != _keys(view, "PIECE")[0] for f in found)


def test_an_opaque_call_blocks_a_wide_store_receipt():
    assert not _resolve(_program(after=lambda body: body.call(OPAQUE)))[-1]


def test_a_store_through_an_unrelated_pointer_is_an_alias_barrier():
    assert not _resolve(_program(after=lambda body: body.ins(store(reg(RAX), const(0, 4)))))[-1]


def test_conditional_overwrite_cannot_reuse_the_dominating_wide_value():
    def after(body):
        (body.cbranch("join", reg(ZF, 1)).ins(add(reg(RCX), reg(RDX), const(8)), store(reg(RCX), const(0, 2)))
         .label("join"))
    assert not _resolve(_program(after=after))[-1]


def test_disjoint_fragments_of_one_definition_retain_both_byte_selections():
    view, key, _, _ = _resolve(_program())
    selectors = tuple(PhysicalMemorySlice(PhysicalRegisterSlice(RDX, 8), offset, 2) for offset in (0, 8))
    boundaries = _direct_sink_boundary_nodes(view, "consumer.bytes", key, view.position(key), 0, selectors)
    assert len(boundaries) == 2 and boundaries[0].node == boundaries[1].node
    assert not boundaries[0].physical_spans[0].overlaps(boundaries[1].physical_spans[0])
    (canonical,) = _canonical_boundary_nodes(list(boundaries))
    assert canonical.physical_spans == tuple(row.physical_spans[0] for row in boundaries)


@pytest.mark.parametrize("offset,wanted,unwanted", ((0, RSI, R8), (8, R8, RSI)))
def test_a_subrange_follows_only_its_actual_source_bytes_in_the_existing_graph(offset, wanted, unwanted):
    from tdo_v2.lane_slice import lane_slice, reached_bytes
    view, key, selector, _ = _resolve(_program(), offset, 2)
    (boundary,) = _direct_sink_boundary_nodes(view, "consumer.bytes", key, view.position(key), 0, (selector,))
    lanes = lane_slice(view.normalized, view.analysis.evidence.unit, [(boundary.node, boundary.physical_spans)])
    registers = reached_bytes(lanes, view.normalized)
    assert {wanted, wanted + 1} <= registers
    assert registers.isdisjoint(range(unwanted, unwanted + 8))


def test_canonicalization_retains_distinct_consumptions_of_the_same_value():
    from dataclasses import replace
    view, key, selector, _ = _resolve(_program())
    (boundary,) = _direct_sink_boundary_nodes(view, "consumer.bytes", key, view.position(key), 0, (selector,))
    assert len(_canonical_boundary_nodes([boundary, replace(boundary, occurrence_ordinal=1)])) == 2


def test_definition_only_compatibility_api_does_not_widen_a_partial_receipt():
    view, key, selector, fragments = _resolve(_program())
    assert fragments
    assert not _FunctionPhysicalStateBackend(view).value_ids(selector, view.position(key))


def test_fragment_contract_rejects_invalid_definition_identity():
    view, _, _, (fragment,) = _resolve(_program())
    with pytest.raises(TypeError):
        PhysicalValueFragment(True, fragment.source_span)


def test_proven_store_to_consumption_edges_are_in_the_result_graph_without_assumptions():
    from synthetic import LANGUAGE, analyze_summaries
    from tdo_v2.boundary import BoundaryKind
    from tdo_v2.boundary_rules import BoundaryRule, SymbolBoundaryProvider
    selector = PhysicalMemorySlice(PhysicalRegisterSlice(RDX, 8), 8, 2)
    provider = SymbolBoundaryProvider((BoundaryRule("consumer", LANGUAGE, BoundaryKind.SINK,
                                                   "consumer.bytes", (selector,)),))
    run = analyze_summaries([_program(), FunctionBuilder(entry=SINK).ret()], provider, names={SINK: "consumer"},
                            assume_globals_disjoint_from_stack=False, assume_direction_flag_clear=False,
                            assume_win64_home_space_private=False, assume_debug_break_traps_do_not_return=False,
                            assume_import_slots_hold_exports=False, assume_entry_values_not_frame=False,
                            assume_opaque_callees_leave_no_stack_addresses=False, assume_pre_escape_values_not_frame=False,
                            operation_records=True)
    assert not run.failed_functions and not run.assumptions
    (root,) = run.roots
    assert root.is_effectively_complete
    proof = root.explanation["physical_binding_graph"]
    assert not proof["candidate_only"]
    assert proof == root.explanation["record"]["physical_binding_graph"]
    assert {e["kind"] for e in proof["edges"]} == {"stored_value_bytes", "current_memory_bytes", "physical_consumption"}
    identifiers = {node["id"] for node in proof["nodes"]}
    assert all(edge["source"] in identifiers and edge["target"] in identifiers for edge in proof["edges"])
    data = next(edge for edge in proof["edges"] if edge["kind"] == "stored_value_bytes")
    assert data["width"] == 2 and data["store_byte_offset"] == 8
    assert proof["proofs"][0]["store_width"] == 16


@pytest.mark.parametrize("mode", ("summary", "legacy"))
def test_source_labels_and_graph_keep_the_demanded_half_of_a_wide_store(mode):
    from synthetic import CODE_BASE, LANGUAGE, analyze_program, analyze_summaries
    from tdo_v2.boundary import BoundaryKind
    from tdo_v2.boundary_rules import BoundaryRule, SymbolBoundaryProvider
    lo, hi = CODE_BASE + 0x400, CODE_BASE + 0x600
    value = tmp(0x800, 16)
    caller = (FunctionBuilder().sub_rsp(0x28).call(lo).ins(copy(reg(RSI), reg(RAX)))
              .call(hi).ins(op("PIECE", [reg(RAX), reg(RSI)], value))
              .ins(copy(reg(RDX), const(DATA_BASE)), store(reg(RDX), value))
              .call(SINK).add_rsp(0x28).ret())
    functions = [caller, FunctionBuilder(entry=lo).ins(copy(reg(RAX), const(7))).ret(),
                 FunctionBuilder(entry=hi).ins(copy(reg(RAX), const(11))).ret(), FunctionBuilder(entry=SINK).ret()]
    provider = SymbolBoundaryProvider((
        BoundaryRule("lo", LANGUAGE, BoundaryKind.SOURCE, "lo.ret", (PhysicalRegisterSlice(RAX, 8),)),
        BoundaryRule("hi", LANGUAGE, BoundaryKind.SOURCE, "hi.ret", (PhysicalRegisterSlice(RAX, 8),)),
        BoundaryRule("consumer", LANGUAGE, BoundaryKind.SINK, "consumer.bytes",
                     (PhysicalMemorySlice(PhysicalRegisterSlice(RDX, 8), 8, 2),)),
    ))
    if mode == "legacy":
        roots = analyze_program(dict(zip(("caller", "lo", "hi", "consumer"), functions)), provider)
        root = roots[("caller", "consumer.bytes")]
        # Legacy origin propagation is node-level and may retain the other
        # half's label. It must never lose the demanded half or its byte proof.
        assert "hi.ret" in root.reached_origin_labels
        graph = root.explanation["physical_binding_graph"]
        data = next(edge for edge in graph["edges"] if edge["kind"] == "stored_value_bytes")
        assert data["width"] == 2 and data["store_byte_offset"] == 8
        return
    run = analyze_summaries(functions, provider, names={lo: "lo", hi: "hi", SINK: "consumer"},
                            assume_globals_disjoint_from_stack=False, assume_direction_flag_clear=False,
                            assume_win64_home_space_private=False, assume_debug_break_traps_do_not_return=False,
                            assume_import_slots_hold_exports=False, assume_entry_values_not_frame=False,
                            assume_opaque_callees_leave_no_stack_addresses=False, assume_pre_escape_values_not_frame=False)
    assert not run.failed_functions and not run.assumptions
    (root,) = run.roots
    assert root.reached_origin_labels == ("hi.ret",)
    assert root.is_effectively_complete
    assert root.explanation["physical_binding_graph"]["proofs"]
