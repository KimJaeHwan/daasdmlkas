"""Independent original-result/snapshot proofs, never legacy same_object alone."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from synthetic import RAX, RBX, RCX, RDI, RDX, RSI, add, const, copy, load, op, reg, store, tmp
from test_allocation_lifetime import FLAG, _begin, _contracts, _finish, _guard, _key, _run, models
from tdo_v2._forward_memory import RefinementRefused, verification_session
from tdo_v2._realloc_contents import _raw_access, prepare_realloc_contents, successful_resize
from tdo_v2._scope_contracts import AddressCoordinate, VarnodeKindCode
from tdo_v2.forward import probe
from tdo_v2.memory_contracts import MemoryDefinitionKind


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def engines(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_FORWARD", "1")


def contracts(models, **changes):
    changes = dict(version=2, format_version=2, contents="preserve-prefix", **changes)
    return _contracts(models, resize=True, resize_changes=changes)


def case(*, old_alias=False, guard=True, patch=False, size=16, tail=False, barrier=None):
    builder, allocation = _begin()
    _guard(builder)
    low = _key(builder, 0, "STORE")
    builder.ins(store(reg(RBX), const(0x44332211, 4)))
    high = _key(builder, 1, "STORE")
    builder.ins(add(reg(RDI), reg(RBX), const(4)), store(reg(RDI), const(0x88776655, 4)))
    builder.ins(copy(reg(RCX), reg(RBX)), copy(reg(RDX), const(size)))
    resize = _key(builder, 2, "CALL")
    from test_external_models import THUNKS
    builder.call(THUNKS["realloc"])
    builder.ins(copy(reg(RDI), reg(RAX)))
    if guard:
        builder.cbranch("done", FLAG, op("INT_EQUAL", [reg(RDI), const(0)], FLAG))
    if barrier is not None:
        barrier(builder)
    if old_alias:
        builder.ins(copy(reg(RDI), reg(RBX)))
    if tail:
        builder.ins(add(reg(RDI), reg(RDI), const(4)))
    patch_key = None
    if patch:
        patch_key = _key(builder, 1, "STORE")
        builder.ins(add(tmp(0x800), reg(RDI), const(2)), store(tmp(0x800), const(0xCAFE, 2)))
    reader = _key(builder, 0, "LOAD")
    builder.ins(load(reg(RSI), reg(RDI)))
    return _finish(builder), dict(allocation=allocation, low=low, high=high,
                                 resize=resize, reader=reader, patch=patch_key)


def copies(item):
    plan = item.normalized.forward_inputs.read_separations
    return () if plan is None else plan.copy_proofs


def call_debts(item, reader):
    return {call for row in item.normalized.call_clobber_reads if row.operation_key == reader
            for call in row.intervening_calls}


def test_success_copies_two_original_fragments_with_explicit_transfer_and_guard(models):
    builder, points = case()
    before, _ = _run(builder, models, _contracts(models, resize=True))
    item, analysis = _run(builder, models, contracts(models))
    assert points["resize"] in call_debts(before, points["reader"])
    assert points["resize"] not in call_debts(item, points["reader"])
    rows = copies(item)
    assert len(rows) == 2
    assert {row.source[1] for row in rows} == {points["low"], points["high"]}
    assert {row.offset for row in rows} == {0, 4}
    assert all((row.old_size, row.new_size) == (8, 16) for row in rows)
    assert all(row.result_definitions and row.outcome.definitions for row in rows)
    assert successful_resize(analysis, points["resize"], points["reader"])
    normalized, graph = item.normalized, item.normalized.dependencies
    bindings = normalized.memory_graph
    assert len(bindings.transfers) == len(bindings.transfer_nodes) == 2
    for transfer, node in zip(bindings.transfers, bindings.transfer_nodes, strict=True):
        definition = normalized.memory_ssa.definitions[transfer.definition_id]
        assert definition.kind is MemoryDefinitionKind.DATA_WRITE
        assert definition.operation_key in {points["low"], points["high"]}
        source = bindings.definition_nodes[transfer.definition_id]
        target = bindings.action_nodes[transfer.action_id]
        assert any(left == source and edge.kind == "memory_transfer" and edge.span == transfer.span
                   for left, _, edge in graph.in_edges(node))
        assert any(right == target and edge.kind == "memory_read" and edge.span == transfer.span
                   for _, right, edge in graph.out_edges(node))
        assert graph.node_for_key("op:" + transfer.guard) in {left for left, _, _ in graph.in_edges(node)}
        assert graph.node_for_key("op:" + transfer.call) in {left for left, _, _ in graph.in_edges(node)}
        found, labels = probe(normalized, points["reader"], (transfer.span,))
        assert found[transfer.span] == transfer.definition_id
        assert set(transfer.requires) <= set(labels) <= set(item.inherited_assumptions)
    assert not item.proven[points["resize"]].preserves_memory
    assert all(span.object_id.kind.value == "register_file" for span in item.proven[points["resize"]].preserved)


@pytest.mark.parametrize("change", ({"old_alias": True}, {"guard": False}, {"size": 0}, {"tail": True}))
def test_unproved_result_guard_size_or_copy_tail_keeps_debt(models, change):
    builder, points = case(**change)
    item, _ = _run(builder, models, contracts(models))
    rows = copies(item)
    if change == {"tail": True}:
        # Only initialized old-prefix bytes have a writer. New/uninitialized
        # bytes cannot acquire the other writer or a whole-read certificate.
        assert all(row.offset + row.span.size <= 8 for row in rows)
        assert sum(row.span.size for row in rows) < 8
    else:
        assert not rows
        assert points["resize"] in call_debts(item, points["reader"])


def test_partial_overwrite_keeps_new_writer_and_copies_only_other_bytes(models):
    builder, points = case(patch=True)
    item, _ = _run(builder, models, contracts(models))
    rows = copies(item)
    assert sorted((row.offset, row.span.size) for row in rows) == [(0, 2), (4, 4)]
    assert {row.source[1] for row in rows} == {points["low"], points["high"]}
    ssa, bindings, graph = item.normalized.memory_ssa, item.normalized.memory_graph, item.normalized.dependencies
    read = next(row for row in ssa.reads if ssa.actions[row.action_id].operation_key == points["reader"]
                and row.span.size == 8 and row.span.object_id.kind.value == "function_relative")
    patch = next(fragment for fragment in read.fragments
                 if ssa.definitions[fragment.definition_ids[0]].operation_key == points["patch"])
    assert patch.span.size == 2
    assert any(left == bindings.definition_nodes[patch.definition_ids[0]] and edge.kind == "memory_read"
               for left, _, edge in graph.in_edges(bindings.action_nodes[read.action_id]))
    assert all(row.span != patch.span for row in bindings.transfers)


@pytest.mark.parametrize("weak", ("contents", "old_owned", "new_owned", "model_digest"))
def test_same_object_projection_is_not_an_independent_copy_contract(models, weak):
    selected = contracts(models)
    if weak == "contents":
        selected = tuple(replace(row, contents="unknown") for row in selected)
    elif weak == "old_owned":
        selected = tuple(replace(row, owned_footprint=False) if row.kind == "allocate" else row for row in selected)
    elif weak == "new_owned":
        selected = tuple(replace(row, owned_footprint=False) if row.kind == "resize" else row for row in selected)
    else:
        selected = tuple(replace(row, model_digest="0" * 64) for row in selected)
    builder, points = case()
    item, _ = _run(builder, models, selected)
    assert not copies(item)
    assert points["resize"] in call_debts(item, points["reader"])


def test_sealed_copy_rejects_forged_fragment_guard_and_original_snapshot(models):
    builder, _ = case()
    item, _ = _run(builder, models, contracts(models))
    plan = item.normalized.forward_inputs.read_separations
    assert plan is not None and plan.copy_proofs
    plan.verify()
    proof = plan.copy_proofs[0]
    for forged in (replace(proof, offset=proof.offset + 1),
                   replace(proof, outcome=replace(proof.outcome, guard="forged")),
                   replace(proof, source=plan.copy_proofs[1].source),
                   replace(proof, requires=())):
        with pytest.raises(RefinementRefused):
            replace(plan, copy_proofs=(forged, *plan.copy_proofs[1:])).verify()
    assert prepare_realloc_contents(plan.source, results=dict(plan.peers)).copy_proofs == plan.copy_proofs


def test_prefix_proof_never_excludes_stack_alias_outside_shrunken_extent(models):
    from synthetic import RSP
    def spill(builder):
        builder.ins(add(tmp(0x900), reg(RSP), const(0x30)), store(tmp(0x900), const(99, 8)))
    builder, points = case(size=4, barrier=spill)
    item, _ = _run(builder, models, contracts(models))
    rows = copies(item)
    assert [(row.offset, row.span.size, row.new_size) for row in rows] == [(0, 4, 4)]
    plan = item.normalized.forward_inputs.read_separations
    assert all(proof.span.size == 4 for proof in plan.proofs if proof.read == points["reader"])
    debts = [row for row in item.normalized.may_alias_reads if row.operation_key == points["reader"]]
    assert debts and all(span.size == 4 for row in debts for span in row.spans)
    copied = rows[0].span
    assert all(not span.overlaps(copied) for row in debts for span in row.spans)
    # The retained four-byte tail cannot gain a whole-read probe certificate.
    read = next(row for row in item.normalized.memory_ssa.reads
                if item.normalized.memory_ssa.actions[row.action_id].operation_key == points["reader"]
                and row.span.size == 8 and row.span.object_id == copied.object_id)
    found, _ = probe(item.normalized, points["reader"], (read.span,))
    assert found[read.span] is None


def test_empty_branch_arms_reconverging_at_read_are_not_a_success_guard(models):
    def reconverge(builder):
        builder.cbranch("merged", FLAG, op("INT_EQUAL", [reg(RDI), const(0)], FLAG))
        builder.ins()  # Original NOP / zero p-code fallthrough, not a dead arm.
        builder.label("merged")
    builder, points = case(guard=False, barrier=reconverge)
    item, analysis = _run(builder, models, contracts(models))
    assert not successful_resize(analysis, points["resize"], points["reader"])
    assert not copies(item)
    assert points["resize"] in call_debts(item, points["reader"])


def _raw_gate_context(analysis, *, overrides=(), spaces=None):
    """Test-only admitted-context projection with one changed gate input."""
    original = analysis.item.unit.scopes.program.evidence.address_spaces
    evidence = SimpleNamespace(address_spaces=original if spaces is None else spaces)
    scopes = SimpleNamespace(program=SimpleNamespace(evidence=evidence))
    return SimpleNamespace(
        item=SimpleNamespace(unit=SimpleNamespace(scopes=scopes)),
        normalized=SimpleNamespace(operation_overrides=overrides),
    )


@pytest.mark.parametrize("direction", ("read", "write"))
@pytest.mark.parametrize("mutation", (
    "override", "nonconstant-selector", "nonmemory-selector", "32bit-space",
    "32bit-pointer", "mismatched-effect-width", "mismatched-operation-width",
))
def test_raw_copy_access_gate_rejects_changed_original_geometry(models, direction, mutation):
    """Negative gate inputs are test-only mutations of an admitted raw access.

    They do not purport to be independently admitted P-code functions: the
    original effect and address-space geometry are retained except for the
    one field named by each mutation.
    """
    builder, points = case()
    item, analysis = _run(builder, models, contracts(models))
    key = points["reader"] if direction == "read" else points["low"]
    operation = analysis.ops[key]
    effect = next(row for row in item.normalized.effects if row.operation_key == key)
    context = _raw_gate_context(analysis)
    original = _raw_access(context, key, operation, effect, direction)
    assert original is not None
    assert original.size == (8 if direction == "read" else 4)
    if mutation == "override":
        context = _raw_gate_context(analysis, overrides=((key, object()),))
    elif mutation == "nonconstant-selector":
        selector = replace(operation.inputs[0], kind=VarnodeKindCode.REGISTER)
        operation = replace(operation, inputs=(selector, *operation.inputs[1:]))
    elif mutation == "nonmemory-selector":
        selector = replace(operation.inputs[0], coordinate=AddressCoordinate(0, 0))
        operation = replace(operation, inputs=(selector, *operation.inputs[1:]))
    elif mutation == "32bit-space":
        spaces = tuple(replace(space, address_size_bits=32) if space.space_id == 1 else space
                       for space in analysis.item.unit.scopes.program.evidence.address_spaces)
        context = _raw_gate_context(analysis, spaces=spaces)
    elif mutation == "32bit-pointer":
        pointer = replace(operation.inputs[1], byte_size=4)
        operation = replace(operation, inputs=(operation.inputs[0], pointer, *operation.inputs[2:]))
    elif mutation == "mismatched-effect-width":
        rows = effect.reads if direction == "read" else effect.writes
        changed = tuple(replace(row, span=replace(row.span, size=3)) if row.span == original else row
                        for row in rows)
        effect = replace(effect, **{("reads" if direction == "read" else "writes"): changed})
    else:
        if direction == "read":
            operation = replace(operation, output=replace(operation.output, byte_size=4))
        else:
            value = replace(operation.inputs[2], byte_size=8)
            operation = replace(operation, inputs=(*operation.inputs[:2], value))
    assert _raw_access(context, key, operation, effect, direction) is None


def _peer_copy_plan(models):
    builder, _ = case()
    item, _ = _run(builder, models, contracts(models))
    source = item.normalized.forward_inputs.read_separations.source
    peer = replace(source)
    plan = prepare_realloc_contents(source, results={peer.key: peer})
    assert plan is not None and plan.copy_proofs and plan.peers == ((peer.key, peer),)
    return plan, source, peer


@pytest.mark.parametrize("changed", ("source", "peer", "contract", "runtime-policy"))
def test_copy_plan_cache_hit_still_rejects_mutated_inputs(models, monkeypatch, changed):
    """The second verify is a cache hit unless its original pin has changed."""
    plan, source, peer = _peer_copy_plan(models)
    with verification_session():
        plan.verify()
        if changed == "runtime-policy":
            with monkeypatch.context() as patch:
                patch.setenv("TDO_V2_FORWARD", "0")
                with pytest.raises(RefinementRefused):
                    plan.verify()
            return
        target = peer if changed == "peer" else source
        field = "allocation_contracts" if changed == "contract" else "allocation_models"
        original = getattr(target, field)
        # Deliberate test-only mutation of a frozen source/peer snapshot.
        object.__setattr__(target, field, ())
        try:
            with pytest.raises(RefinementRefused):
                plan.verify()
        finally:
            object.__setattr__(target, field, original)
        plan.verify()


def test_copy_plan_rederives_after_verification_session_ends(models, monkeypatch):
    from tdo_v2 import _realloc_contents

    plan, _, _ = _peer_copy_plan(models)
    original = _realloc_contents.prepare_realloc_contents
    calls = []

    def counted(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(_realloc_contents, "prepare_realloc_contents", counted)
    with verification_session():
        plan.verify()
        plan.verify()
        assert len(calls) == 1
    plan.verify()
    assert len(calls) == 2


@pytest.mark.parametrize("changed", ("source", "peer"))
def test_copy_cache_hit_rechecks_new_inherited_dependency(models, monkeypatch, changed):
    from tdo_v2 import _realloc_contents

    plan, source, peer = _peer_copy_plan(models)
    target = source if changed == "source" else peer
    original = target.inherited_assumptions
    derive = _realloc_contents.prepare_realloc_contents
    calls = []

    def counted(*args, **kwargs):
        calls.append(1)
        return derive(*args, **kwargs)

    monkeypatch.setattr(_realloc_contents, "prepare_realloc_contents", counted)
    try:
        with verification_session():
            plan.verify()
            assert len(calls) == 1
            # A later dependency is a changed proof premise, even when the
            # source/peer object identity and original normalized SSA are stable.
            target.inherited_assumptions = original | {"new-dependency"}
            if changed == "source":
                with pytest.raises(RefinementRefused):
                    plan.verify()
            else:
                # This cloned peer is unused by the local copy proof, so a
                # *fresh* verification still accepts it. The changed peer
                # must nevertheless invalidate the session cache and rederive.
                plan.verify()
            assert len(calls) == 2
        # The same changed input has the same verdict without a cache.
        if changed == "source":
            with pytest.raises(RefinementRefused):
                plan.verify()
        else:
            plan.verify()
        assert len(calls) == 3
    finally:
        target.inherited_assumptions = original
    plan.verify()  # a new session derives independently of its old cache
    assert len(calls) == 4


def test_parent_cache_hit_revalidates_prior_plan_source(models):
    builder, _ = case()
    item, _ = _run(builder, models, contracts(models))
    prior = item.normalized.forward_inputs.read_separations
    assert prior is not None and prior.copy_proofs
    # Test-only valid layered baseline: the prior plan retains its original
    # accepted source, while the parent has its own source clone and baseline.
    source = prior.source
    baseline = replace(source.normalized, forward_inputs=replace(
        source.normalized.forward_inputs, read_separations=prior
    ))
    parent = prepare_realloc_contents(replace(source, normalized=baseline))
    assert parent is not None and parent.baseline.forward_inputs.read_separations is prior
    original = source.inherited_assumptions
    with verification_session():
        parent.verify()
        source.inherited_assumptions = original | {"prior-new-dependency"}
        try:
            with pytest.raises(RefinementRefused):
                parent.verify()
        finally:
            source.inherited_assumptions = original
        parent.verify()


def test_copy_cache_hit_rechecks_original_mutable_import_slot_policy(models):
    from synthetic import program_units
    from test_external_models import _image
    from tdo_v2.interprocedural import analyze_units

    builder, _ = case()
    result = analyze_units(
        program_units(builder), image_info=_image(), external_models=models,
        lifecycle_contracts=contracts(models), private_frame_above=40,
        assume_globals_disjoint_from_stack=True,
        assume_entry_values_not_frame=False,
        assume_opaque_callees_leave_no_stack_addresses=False,
        assume_import_slots_hold_exports=True,
    )
    plan = result["1:1000"].normalized.forward_inputs.read_separations
    assert plan is not None and plan.copy_proofs
    slots = plan.source.normalization_context[2]
    assert slots is not None and slots.active is True
    with verification_session():
        plan.verify()
        slots.active = False
        try:
            with pytest.raises(RefinementRefused, match="policies changed"):
                plan.verify()
        finally:
            slots.active = True
        plan.verify()


def test_a_split_debt_row_is_judged_on_all_its_rows(models):
    """A copy proof splits every reader's row per span (``subtract_copy_clobbers``)
    and the parts keep the reader's one debt node: every consumer judges the node
    on ALL its parts, never the last (docs 25.83 S2d D0)."""
    from tdo_v2.call_clobber import rows_by_node
    from tdo_v2.integration.configured_call_clobber_discharge import CallClobberDischarger, DischargeKind
    from tdo_v2.normalize import call_clobber_spans
    from synthetic import R8

    keys = {}

    def two_registers(builder):   # (rcx and rdx both crossed by the realloc)
        keys["reader"] = _key(builder, 0, "INT_ADD")
        builder.ins(add(reg(R8), reg(RCX), reg(RDX)))

    builder, _ = case(barrier=two_registers)
    item, _ = _run(builder, models, contracts(models))
    assert copies(item)
    normalized = item.normalized
    parts = tuple(row for row in normalized.call_clobber_reads if row.operation_key == keys["reader"])
    assert len(parts) == 2 and parts[0].spans != parts[1].spans
    nodes = {node for row, node in zip(normalized.call_clobber_reads, normalized.call_clobber_nodes)
             if row.operation_key == keys["reader"]}
    assert len(nodes) == 1
    (node,) = nodes
    assert rows_by_node(normalized.call_clobber_reads, normalized.call_clobber_nodes)[node] == parts
    assert call_clobber_spans(normalized)[node] == parts[0].spans + parts[1].spans
    # the discharger: one part not dischargeable keeps the node's debt
    discharger = CallClobberDischarger.__new__(CallClobberDischarger)
    discharger._clobber_rows = {"f": {node: parts}}
    for undischargeable in parts:
        discharger._discharge_read = lambda entry, read, context, active, bad=undischargeable: (
            None if read is bad else (DischargeKind.PRESERVED,))
        assert not discharger.discharge("f", ())
        assert not discharger._debt_discharged("f", (node,), None, ())
    discharger._discharge_read = lambda entry, read, context, active: (DischargeKind.PRESERVED,)
    assert [row.debt_node for row in discharger.discharge("f", ())] == [node]
