"""Pre-CALL old ownership, independently of any resize result or copy proof."""
from dataclasses import replace

import pytest

from synthetic import RBX, RCX, RDI, RDX, RSI, RSP, add, const, copy, load, reg, store, tmp
from test_allocation_lifetime import _begin, _contracts, _finish, _guard, _key, _run, models
from test_external_models import THUNKS
from tdo_v2._forward_memory import RefinementRefused, exclusions_for, verification_session
from tdo_v2._load_identity import definition_identity
from tdo_v2._realloc_contents import OldAllocationSnapshotDemand, prepare_old_allocation_snapshot
from tdo_v2.forward import probe
from tdo_v2.memory_contracts import MemoryDefinitionKind


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def engines(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_FORWARD", "1")


def source(models, *, stack_offset=None, stack_width=8, barrier=False, release=False, owned=True,
           unknown_writer=False, future=False, prior=False, heap_overwrite=False, stale_address=0,
           stale_push=False, dirty_value=False):
    body, birth = _begin()
    _guard(body)
    if prior:
        body.ins(add(tmp(0x980), reg(RSP), const(0x30)), store(tmp(0x980), const(123)))
    writer = _key(body, 0, "STORE")
    body.ins(store(reg(RBX), const(0x44332211, 4)))
    if prior:
        body.ins(load(reg(RSI), tmp(0x980)))
    if stale_address or stale_push:
        body.ins(add(reg(RDX), reg(RSP), const(0 if stale_push else 0x30)))
    crossing = _key(body, 2, "CALL")
    body.call(THUNKS["strlen"])
    stack_writer = None
    if stale_address:
        registers = (RSI, RDI, RCX)
        before = RDX
        for current in registers[:stale_address]:
            body.ins(copy(reg(current), reg(before)))
            before = current
        stack_writer = _key(body, 0, "STORE")
        body.ins(store(reg(before), const(99, 8)))
    dirty_push = None
    if stale_push:
        body.ins(copy(reg(RSP), reg(RDX)))
        dirty_push = _key(body, 2, "CALL") + "~push"
        body.call(THUNKS["strlen"])
    if stack_offset is not None:
        stack_writer = _key(body, 1, "STORE")
        body.ins(add(tmp(0x900), reg(RSP), const(stack_offset & ((1 << 64) - 1))),
                 store(tmp(0x900), reg(RDX, stack_width) if dirty_value else const(99, stack_width)))
    if unknown_writer:
        body.ins(store(reg(RSI), const(77, 4)))
    if heap_overwrite:
        body.ins(store(reg(RBX), const(0x88776655, 4)))
    if barrier:
        body.call(0x1700)
    if release:
        body.ins(copy(reg(RCX), reg(RBX))).call(THUNKS["free"])
    body.ins(copy(reg(RCX), reg(RBX)), copy(reg(RDX), const(16)))
    resize = _key(body, 2, "CALL")
    body.call(THUNKS["realloc"])
    if future:
        writer = _key(body, 0, "STORE")
        body.ins(store(reg(RBX), const(0x88776655, 4)))
    # Deliberately NO result test or post-CALL memory LOAD: they cannot help
    # establish this pre-CALL certificate, and contents="unknown" is enough.
    contracts = tuple(replace(row, owned_footprint=owned) if row.kind == "allocate" else row
                      for row in _contracts(models, release=release, resize=True))
    item, analysis = _run(_finish(body), models, contracts)
    definition = next(row for row in analysis.ssa.definitions
                      if row.operation_key == writer and row.kind is MemoryDefinitionKind.DATA_WRITE
                      and row.span.object_id.kind.value == "function_relative")
    demand = OldAllocationSnapshotDemand(resize, definition_identity(definition), definition.span)
    return item, analysis, demand, dict(birth=birth, crossing=crossing, stack=stack_writer,
                                      writer=writer, dirty_push=dirty_push)


def query(item, analysis, demand, plan):
    normalized = replace(item.normalized, forward_inputs=replace(
        item.normalized.forward_inputs, read_separations=plan))
    return probe(normalized, analysis.first(demand.call), (demand.span,))[0][demand.span]


def test_original_stack_push_is_separated_without_outcome_result_or_copy(models):
    item, analysis, demand, keys = source(models)
    # The only raw LOAD is RET's original stack read, not a resize result.
    assert all(operation.inputs[1].coordinate.byte_offset == RSP
               for operation in analysis.ops.values() if operation.opcode == "LOAD")
    assert analysis.contracts[demand.call].contents == "unknown"
    assert query(item, analysis, demand, item.normalized.forward_inputs.read_separations) is None
    plan = prepare_old_allocation_snapshot(item, (demand,))
    assert plan is not None and plan.evidence_kind == "allocation-snapshot"
    assert plan.snapshot_demands == (demand,)
    assert not plan.copy_proofs and not plan.call_effects and not plan.call_decisions
    assert any(row.writer == keys["crossing"] + "~push" for row in plan.proofs)
    assert query(item, analysis, demand, plan) == analysis.ssa.definitions.index(
        next(row for row in analysis.ssa.definitions if definition_identity(row) == demand.source))
    # A certificate for a dynamically added probe read does not apply to the
    # original effect unit, or license a different timestamp/extra byte.
    with pytest.raises(RefinementRefused, match="original read occurrence"):
        exclusions_for(plan, item.normalized.forward_inputs.effect_unit)
    assert all(row.read == analysis.first(demand.call) and row.span == demand.span
               for row in plan.proofs[len(item.normalized.forward_memory_proofs):])
    plan.verify()


@pytest.mark.parametrize("offset,width,excluded", ((0x30, 8, True), (-8, 8, True), (-16, 8, False), (-12, 8, False)))
def test_whole_stack_writer_must_be_active_at_old_birth(models, offset, width, excluded):
    item, analysis, demand, keys = source(models, stack_offset=offset, stack_width=width)
    plan = prepare_old_allocation_snapshot(item, (demand,))
    assert plan is not None
    assert any(row.writer == keys["stack"] for row in plan.proofs) is excluded
    result = query(item, analysis, demand, plan)
    assert (result is not None) is excluded


@pytest.mark.parametrize("change", ({"barrier": True}, {"unknown_writer": True}))
def test_original_unknown_call_or_unknown_writer_is_not_excused(models, change):
    item, analysis, demand, _ = source(models, **change)
    plan = prepare_old_allocation_snapshot(item, (demand,))
    # A useful independent stack exclusion may exist, but cannot erase the
    # unrelated raw CALL/unknown writer debt of the original snapshot.
    if plan is not None:
        assert query(item, analysis, demand, plan) is None


@pytest.mark.parametrize("change", ({"release": True}, {"owned": False}, {"future": True}))
def test_dead_unowned_or_future_source_cannot_authorize_snapshot(models, change):
    item, _, demand, _ = source(models, **change)
    assert prepare_old_allocation_snapshot(item, (demand,)) is None


@pytest.mark.parametrize("mutation", ("call", "source", "span", "source-offset", "contract", "override",
                                       "kind", "copy", "effects", "decisions", "requires", "assumptions"))
def test_sealed_snapshot_rejects_changed_payload_and_original_inputs(models, mutation):
    item, _, demand, _ = source(models)
    plan = prepare_old_allocation_snapshot(item, (demand,))
    assert plan is not None
    plan.verify()
    if mutation in ("call", "source", "span", "source-offset"):
        changes = {"call": {"call": "forged"}, "source": {"source": ()},
                   "span": {"span": replace(demand.span, size=demand.span.size + 1)},
                   "source-offset": {"span": replace(demand.span, start=demand.span.start + 1)}}
        forged = replace(plan, snapshot_demands=(replace(demand, **changes[mutation]),))
    elif mutation == "contract":
        forged = replace(plan, contracts=())
    elif mutation == "override":
        changed = replace(item.normalized, operation_overrides=((demand.source[1], object()),))
        original = item.normalized
        object.__setattr__(item, "normalized", changed)
        try:
            with pytest.raises(RefinementRefused):
                plan.verify()
        finally:
            object.__setattr__(item, "normalized", original)
        return
    else:
        changes = {"kind": {"evidence_kind": "allocation"}, "copy": {"copy_proofs": (object(),)},
                   "effects": {"call_effects": (object(),)}, "decisions": {"call_decisions": (object(),)},
                   "requires": {"requires": ()}, "assumptions": {"assumptions": ("forged",)}}
        forged = replace(plan, **changes[mutation])
    with pytest.raises(RefinementRefused):
        forged.verify()


def test_partial_bytes_preserve_prior_proofs_and_missing_contract_refuses(models):
    item, analysis, demand, _ = source(models, prior=True)
    assert item.normalized.forward_memory_proofs
    assert item.normalized.forward_inputs.read_separations is not None
    partial = replace(demand, span=replace(demand.span, start=demand.span.start + 1, size=2))
    plan = prepare_old_allocation_snapshot(item, (partial,))
    assert plan is not None
    assert plan.proofs[:len(item.normalized.forward_memory_proofs)] == item.normalized.forward_memory_proofs
    assert all(row.span == partial.span for row in plan.proofs[len(item.normalized.forward_memory_proofs):])
    assert query(item, analysis, partial, plan) is not None
    assert prepare_old_allocation_snapshot(replace(item, allocation_contracts=()), (demand,)) is None


def test_demand_does_not_force_an_old_writer_over_a_genuine_later_heap_store(models):
    item, analysis, demand, _ = source(models, heap_overwrite=True)
    plan = prepare_old_allocation_snapshot(item, (demand,))
    assert plan is not None
    result = query(item, analysis, demand, plan)
    assert result is not None and definition_identity(analysis.ssa.definitions[result]) != demand.source
    assert analysis.ssa.definitions[result].operation_key != demand.source[1]


def test_snapshot_plan_does_not_license_other_read_time_or_extra_bytes(models):
    item, analysis, demand, _ = source(models)
    plan = prepare_old_allocation_snapshot(item, (demand,))
    assert plan is not None
    normalized = replace(item.normalized, forward_inputs=replace(
        item.normalized.forward_inputs, read_separations=plan))
    with pytest.raises(RefinementRefused, match="original read occurrence"):
        probe(normalized, demand.call, (demand.span,))
    with pytest.raises(RefinementRefused, match="original read occurrence"):
        probe(normalized, analysis.first(demand.call), (replace(demand.span, size=demand.span.size + 1),))


@pytest.mark.parametrize("copies", (1, 2, 3))
def test_stack_writer_with_transitively_call_clobbered_address_is_not_excluded(models, copies):
    from tdo_v2._allocation_memory import stack_range
    from tdo_v2._realloc_contents import _raw_access
    item, analysis, demand, keys = source(models, stale_address=copies)
    effect = next(row for row in item.normalized.effects if row.operation_key == keys["stack"])
    projected = _raw_access(analysis, keys["stack"], analysis.ops[keys["stack"]], effect, "write")
    assert projected is not None
    target = next(iter(analysis.argument(demand.call, analysis.contracts[demand.call].pointer).targets))
    assert stack_range(analysis, target.allocation, projected) is not None
    plan = prepare_old_allocation_snapshot(item, (demand,))
    assert plan is not None
    assert not any(row.writer == keys["stack"] for row in plan.proofs)
    assert query(item, analysis, demand, plan) is None


def test_push_with_transitively_call_clobbered_stack_pointer_is_not_excluded(models):
    item, analysis, demand, keys = source(models, stale_push=True)
    assert keys["dirty_push"] in {row.operation_key for row in item.normalized.effects}
    plan = prepare_old_allocation_snapshot(item, (demand,))
    if plan is not None:
        assert not any(row.writer == keys["dirty_push"] for row in plan.proofs)
        assert query(item, analysis, demand, plan) is None


def test_independent_stored_value_debt_does_not_become_an_address_debt(models):
    item, analysis, demand, keys = source(models, stack_offset=0x30, dirty_value=True)
    assert any(row.operation_key == keys["stack"] for row in item.normalized.call_clobber_reads)
    plan = prepare_old_allocation_snapshot(item, (demand,))
    assert plan is not None and any(row.writer == keys["stack"] for row in plan.proofs)
    assert query(item, analysis, demand, plan) is not None


def test_local_structure_caps_fail_closed_and_no_copy_plan_can_feed_snapshot(models, monkeypatch):
    from tdo_v2 import _realloc_contents
    from test_realloc_contents import case, contracts
    item, _, demand, _ = source(models)
    for cap in ("_SNAPSHOT_DEMANDS", "_SNAPSHOT_EFFECTS", "_SNAPSHOT_PROOFS"):
        with monkeypatch.context() as patch:
            patch.setattr(_realloc_contents, cap, 0)
            assert prepare_old_allocation_snapshot(item, (demand,)) is None
    assert prepare_old_allocation_snapshot(item, (demand, demand)) is None
    body, _ = case()
    copied, _ = _run(body, models, contracts(models))
    assert copied.normalized.forward_inputs.read_separations.evidence_kind == "realloc-copy"
    # The forbidden future certificate must be rejected before a numeric
    # analysis constructor could recursively verify/consume it.
    monkeypatch.setattr(_realloc_contents, "AllocationAnalysis", lambda *a, **k: pytest.fail("future evidence consumed"))
    assert prepare_old_allocation_snapshot(copied, (demand,)) is None


@pytest.mark.parametrize("changed", ("source", "peer", "contract", "runtime-policy"))
def test_snapshot_cached_verification_rechecks_every_original_pin(models, monkeypatch, changed):
    item, _, demand, _ = source(models)
    peer = replace(item)
    plan = prepare_old_allocation_snapshot(item, (demand,), results={peer.key: peer})
    assert plan is not None
    with verification_session():
        plan.verify()
        if changed == "runtime-policy":
            with monkeypatch.context() as patch:
                patch.setenv("TDO_V2_FORWARD", "0")
                with pytest.raises(RefinementRefused):
                    plan.verify()
            return
        target = peer if changed == "peer" else item
        name = "allocation_contracts" if changed == "contract" else "allocation_models"
        original = getattr(target, name)
        object.__setattr__(target, name, ())
        try:
            with pytest.raises(RefinementRefused):
                plan.verify()
        finally:
            object.__setattr__(target, name, original)


def test_snapshot_cache_demand_pin_cannot_hide_a_changed_timestamp(models):
    item, _, demand, _ = source(models)
    plan = prepare_old_allocation_snapshot(item, (demand,))
    with verification_session():
        plan.verify()
        object.__setattr__(plan, "snapshot_demands", (replace(demand, call="forged"),))
        with pytest.raises(RefinementRefused):
            plan.verify()
