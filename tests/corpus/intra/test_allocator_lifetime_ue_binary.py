"""Original UE allocator calls cannot silently preserve all prior memory.

Uses the existing pinned Core/Trace bundles. These are static conservative
regressions: the actual Free bodies only reload their return address after
Free, not freed pointee data. No allocation extent, allocator success, or
new lifetime/ABI assumption is supplied.
"""

from collections import Counter

import pytest

from test_callee_preserved_low_binary import (
    APPEND, CONSTRUCTOR, DESTRUCTOR, R002, R005, _projector, core, image_ranges, run_dfbench, trace,
)
from test_entry_frame_ue_limits_binary import DERIVED_CALLS, FRAME, HOME, _trace_analysis
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.interprocedural import analyze_units
from tdo_v2.query import BackwardSliceQuery
from tdo_v2.relative_memory import ImageBaseTracking
from tdo_v2.span_geometry import StorageObjectKind
from tdo_v2.summary_templates import image_provenance


CORE_GROW, TRACE_GROW, TRACE_FREE = "1b1:18010b8d0", "1b1:180005af0", "1b1:180005930"
DIGESTS = {
    DESTRUCTOR: "02c0577ac9ac13131911aa3a9610b725deab5fe849c17273c56d8d43ded848c7",
    CORE_GROW: "b1f7031a15b8e2f1e1bb588bbb0f2612d576ce8b9589b365edef7654e64e1016",
    TRACE_FREE: "25dda4017b340802bb6595ba75bcc0cde268067b2f30efd2355e30e84ddecad8",
    TRACE_GROW: "dbee5f070693d619dae6f5c44f28f5b05f1e233c0bfb54fa4ce8a88893121010",
}
FREE_CASES = (
    ("core", DESTRUCTOR, "1b1:18003bc0c:2:CALL", "1b1:18003bc16:0:LOAD"),
    ("trace", TRACE_FREE, "1b1:18000598a:3:CALLIND", "1b1:180005995:0:LOAD"),
)
REALLOC_CASES = (
    ("core", CORE_GROW, "1b1:18010b946:2:CALL", "1b1:18010b94e:1:LOAD",
     "1b1:18010b92e:0:LOAD", "1b1:18010b94b:1:STORE"),
    ("trace", TRACE_GROW, "1b1:180005b87:3:CALLIND", "1b1:180005b8d:1:LOAD",
     "1b1:180005b84:0:LOAD", "1b1:180005b92:1:STORE"),
)


@pytest.fixture(scope="module")
def allocator_lifetime(core, trace):
    space = core["scope"].evidence.image_base.space_id
    relocates = image_provenance(lambda address, size: core["image"].value(space, address, size),
                                [(offset, size) for sid, offset, size in core["info"].relocations if sid == space])
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("TDO_V2_FORWARD", "1")
        with ImageBaseTracking(image_ranges(core["info"], space), relocates):
            core_results = analyze_units(
                list(core["units"].values()), image_info=core["info"], external_models=core["models"],
                pcodeop_models=run_dfbench.pcodeop_models(), private_frame_above=0,
                assume_globals_disjoint_from_stack=True, assume_entry_values_not_frame=False,
                assume_opaque_callees_leave_no_stack_addresses=True,
                assume_debug_break_traps_do_not_return=True, own_library="UNREALEDITOR-CORE.DLL",
                keep_uncut=frozenset((APPEND, CONSTRUCTOR, DESTRUCTOR)))
        traced = _trace_analysis(trace, False, trace["models"])
        public = {(False, True): traced}
        for frame, forward in ((False, False), (True, False), (True, True)):
            public[frame, forward] = _trace_analysis(trace, frame, trace["models"], forward=forward)
    for key, digest in DIGESTS.items():
        units = core["units"] if key in core["units"] else trace["units"]
        assert units[key].scopes.function.observation_digest.hex() == digest
    return dict(core=core_results, trace=traced["trace"], roots=traced["roots"], run=traced["engine_run"],
                public=public)


def _assert_named_graph_debt(item, call, reader, width):
    normalized = item.normalized
    rows = [(row, node) for row, node in zip(normalized.call_clobber_reads, normalized.call_clobber_nodes)
            if row.operation_key == reader and call in row.intervening_calls]
    assert rows, (call, reader)
    graph = normalized.dependencies
    target = graph.node_for_key(f"op:{reader}")
    assert target is not None and graph.node_for_key(f"op:{call}") is not None
    for row, node in rows:
        assert any(span.size == width and span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE
                   for span in row.spans)
        assert graph.node(node).kind is NodeKind.MEMORY_DEBT
        assert graph.node(node).label == "call_clobber_read"
        assert node in graph.predecessors(target)


def _assert_call_debt(item, call, reader):
    effect = dict(item.normalized.proven_call_effects)[call]
    assert not effect.preserves_memory
    _assert_named_graph_debt(item, call, reader, 8)
    # The summary may not turn a body-level lifetime uncertainty back into
    # an unconditional all-memory preservation claim at its caller.
    calls = [row for row in item.summary.inner_calls if row[0] == call]
    assert len(calls) == 1 and calls[0][2] is False
    return effect


@pytest.mark.parametrize("group,function,call,reader", FREE_CASES)
def test_original_free_has_exact_return_load_clobber_and_unpreserved_inner_call(
        allocator_lifetime, group, function, call, reader):
    item = allocator_lifetime[group][function]
    _, operations = _projector(item)
    assert "external-model:ue-core-win64/FMemory::Free@" in item.declared[call]
    assert operations[call].opcode in ("CALL", "CALLIND")
    assert operations[reader].output.byte_size == 8
    # Do not invent an actual post-Free UAF case: this is the return-address
    # register RIP, and it is the body's only raw memory LOAD after Free.
    assert operations[reader].output.coordinate.byte_offset == 648
    assert [key for key, op in operations.items() if op.opcode == "LOAD"
            and int(key.split(":")[1], 16) > int(call.split(":")[1], 16)] == [reader]
    _assert_call_debt(item, call, reader)


@pytest.mark.parametrize("group,function,call,reader,old_load,result_store", REALLOC_CASES)
def test_original_realloc_keeps_result_relation_but_not_whole_memory_preservation(
        allocator_lifetime, group, function, call, reader, old_load, result_store):
    item = allocator_lifetime[group][function]
    _, operations = _projector(item)
    assert "external-model:ue-core-win64/FMemory::Realloc@" in item.declared[call]
    assert operations[old_load].output.byte_size == 8
    assert operations[result_store].inputs[2].byte_size == 8
    effect = _assert_call_debt(item, call, reader)
    ((result, original),) = effect.same_object_registers
    assert (result.start, result.size, original.start, original.size) == (0, 8, 8, 8)
    rows = [(row, staging, argument) for row, staging, argument in item.normalized.same_object_rows
            if row == f"{call}~0"]
    assert len(rows) == 1
    row, staging, argument = rows[0]
    assert staging == f"{call}~in0"
    assert argument.coordinate.byte_offset == 8 and argument.byte_size == 8
    # The declared same-object/null-is-fresh result relation remains. It is
    # not an allocation extent or permission to drop old-memory call debt.
    assert not effect.fresh_registers


def test_original_fmemory_contracts_keep_frees_and_realloc_identity(core):
    entries = {entry.name: entry for model in core["models"].files for entry in model.entries
               if model.file_id == "ue-core-win64"}
    assert entries["FMemory::Free"].frees == ((8, 8),)
    assert entries["FMemory::Realloc"].frees == ((8, 8),)
    assert entries["FMemory::Realloc"].same_object == (((0, 8), (8, 8)),)
    assert entries["FMemory::Malloc"].fresh == ((0, 8),)


@pytest.mark.parametrize("function,origins,debt,proven", (
    (R002, ("dfb_source_A.ret", "dfb_source_B.ret"), 33, 9),
    (R005, (), 15, 10),
))
def test_current_actual_roots_report_conservative_lifetime_debt(
        allocator_lifetime, function, origins, debt, proven):
    root, item = allocator_lifetime["roots"][function], allocator_lifetime["trace"][function]
    assert root.reached_origin_labels == origins
    assert not root.is_effectively_complete
    assert root.effective_completeness.reachable_unresolved_reads == debt
    assert len(item.proven) == proven and not item.refused_models


@pytest.mark.parametrize("function,call,reader,width", (
    (R002, "1b1:180006053:2:CALL", "1b1:1800060c2:1:LOAD", 8),
    (R002, "1b1:1800061ea:2:CALL", "1b1:180006257:1:LOAD", 4),
    (R005, "1b1:18000acdc:3:CALLIND", "1b1:18000adc3:1:LOAD", 8),
    (R005, "1b1:18000acef:3:CALLIND", "1b1:18000adf4:0:LOAD", 2),
))
def test_actual_callers_keep_named_resize_or_append_debt_on_original_loads(
        allocator_lifetime, function, call, reader, width):
    item = allocator_lifetime["trace"][function]
    _, operations = _projector(item)
    assert operations[reader].output.byte_size == width
    assert not item.proven[call].preserves_memory
    _assert_named_graph_debt(item, call, reader, width)


def test_current_rederived_pack_is_used_without_removing_source_assumptions(allocator_lifetime, trace):
    item = allocator_lifetime["trace"][R005]
    (model,) = [model for model in trace["models"].files if model.file_id == "ue-core-win64-derived"]
    assert len(model.entries) == 3
    assert len(model.source_field("assumptions")) == 11
    assert FRAME not in model.source_field("assumptions") and HOME not in model.source_field("assumptions")
    for call, name in DERIVED_CALLS.items():
        assert f"derived-model:ue-core-win64-derived/{name}@" in item.declared[call]
        assert call in item.proven
    # Real dtor and Append payloads now carry nonpreserving inner calls;
    # consumers cannot silently use the old whole-memory-preserved claim.
    for call in ("1b1:18000acdc:3:CALLIND", "1b1:18000acef:3:CALLIND",
                 "1b1:18000ae03:3:CALLIND", "1b1:18000ae0e:3:CALLIND"):
        assert not item.proven[call].preserves_memory


def test_original_trace_realloc_first_frame_reload_reaches_uncertain_data_store(allocator_lifetime):
    item = allocator_lifetime["trace"][TRACE_GROW]
    call, reader, writer = "1b1:180005b87:3:CALLIND", "1b1:180005b8d:1:LOAD", "1b1:180005b92:1:STORE"
    _assert_named_graph_debt(item, call, reader, 8)
    normalized, (_, operations) = item.normalized, _projector(item)
    # Original this is reloaded from its stack spill, copied to RCX, then used
    # as the STORE address. The clobbered pointer is not silently trusted.
    assert operations[reader].output == operations["1b1:180005b8d:2:COPY"].inputs[0]
    assert operations["1b1:180005b8d:2:COPY"].output == operations[writer].inputs[1]
    assert writer in dict(normalized.uncertain_writers)
    assert dict(normalized.uncertain_writers)[writer] is None
    graph = normalized.dependencies
    reached = set(graph.backward_reachable((graph.node_for_key(f"op:{writer}"),)))
    assert graph.node_for_key(f"op:{reader}") in reached
    assert any(node in reached for row, node in zip(normalized.call_clobber_reads, normalized.call_clobber_nodes)
               if row.operation_key == reader and call in row.intervening_calls)


@pytest.mark.parametrize("call,index_read,base_read,writer", (
    ("1b1:180006053:2:CALL", "1b1:180006058:1:LOAD", "1b1:180006063:1:LOAD", "1b1:180006099:1:STORE"),
    ("1b1:1800061ea:2:CALL", "1b1:1800061ef:1:LOAD", "1b1:1800061fa:1:LOAD", "1b1:180006230:1:STORE"),
))
def test_actual_r002_clobbered_index_and_base_keep_later_array_writer_uncertain(
        allocator_lifetime, call, index_read, base_read, writer):
    item = allocator_lifetime["trace"][R002]
    normalized, (_, operations) = item.normalized, _projector(item)
    assert operations[index_read].output.byte_size == 4
    assert operations[base_read].output.byte_size == 8
    assert operations[writer].inputs[2].byte_size == 8
    _assert_named_graph_debt(item, call, index_read, 4)
    _assert_named_graph_debt(item, call, base_read, 8)
    graph = normalized.dependencies
    reached = set(graph.backward_reachable((graph.node_for_key(f"op:{writer}"),)))
    assert {graph.node_for_key(f"op:{key}") for key in (index_read, base_read)} <= reached
    assert writer in dict(normalized.uncertain_writers)
    assert dict(normalized.uncertain_writers)[writer] is None
    assert len(item.proven[call].unknown_memory) == 3


def test_actual_r002_additional_debt_is_call_and_unknown_writer_transport_not_just_a_count(allocator_lifetime):
    item, root = allocator_lifetime["trace"][R002], allocator_lifetime["roots"][R002]
    normalized, graph = item.normalized, item.normalized.dependencies
    debt = {node for seed in root.root_nodes
            for node in BackwardSliceQuery().run(normalized, seed).reachable_unresolved_read_nodes}
    # Before the fix this original root had seven may-alias and three
    # conditional-writer debts. The new total is not "23 new loads": it is
    # +16 call clobbers, +6 opaque writes, +4 net aliases, -3 conditional debts.
    assert Counter(graph.node(node).label for node in debt) == {
        "call_clobber_read": 16, "may_alias_read": 11, "opaque_call_write": 6}
    assert root.local_completeness == root.effective_completeness
    for call in ("1b1:180006053:2:CALL", "1b1:1800061ea:2:CALL"):
        nodes = [node for node in normalized.opaque_nodes
                 if node in debt and any(graph.node(node).key.endswith(f":{call}~u{i}") for i in range(3))]
        assert len(nodes) == 3
    for reader in ("1b1:1800060c2:1:LOAD", "1b1:1800060e5:1:LOAD", "1b1:18000612e:1:LOAD",
                   "1b1:18000613b:1:LOAD", "1b1:180006148:1:LOAD"):
        assert any(node in debt and row.operation_key == reader
                   and "1b1:180006099:1:STORE" in row.uncertain
                   for row, node in zip(normalized.may_alias_reads, normalized.may_alias_nodes))


@pytest.mark.parametrize("frame,forward", ((False, False), (False, True), (True, False), (True, True)))
def test_public_root_lifetime_results_are_stable_in_both_frame_and_forward_modes(allocator_lifetime, frame, forward):
    state = allocator_lifetime["public"][frame, forward]
    assert not state["engine_run"].failed_functions
    for function, origins, debt, proven in (
        (R002, ("dfb_source_A.ret", "dfb_source_B.ret"), 33, 9), (R005, (), 15, 10),
    ):
        item, root = state["trace"][function], state["roots"][function]
        assert root.reached_origin_labels == origins and not root.is_effectively_complete
        assert root.effective_completeness.reachable_unresolved_reads == debt
        assert len(item.proven) == proven and not item.refused_models
    assert all(call in state["trace"][R005].declared for call in DERIVED_CALLS)

