"""Only a current, source-pinned discharged fault removes a once barrier."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from synthetic import (
    CODE_BASE, RAX, RCX, RDX, FunctionBuilder, const, load, op, program_units, reg, store,
)
from test_fault_premise import _pe
from tdo_v2.fault_premise import EMPTY_PLAN, plan_faults
from tdo_v2.interprocedural import analyze_units
from tdo_v2.normalize import FunctionNormalizer
from tdo_v2.pcode_blocks import build_pcode_block_graph
from tdo_v2.relative_memory import (
    _OnceControlReceipt, _fault_once_control, single_execution_blocks, single_execution_keys,
)


HELPER = CODE_BASE + 0x400


def _function(*, unknown=False, loop=False, interfering=False):
    body = FunctionBuilder()
    if loop:
        body.label("again")
    body.call(HELPER)
    if interfering:
        body.ins(store(reg(RCX), const(7)), load(reg(RDX), reg(RAX)))
    else:
        body.ins(load(reg(RDX), reg(RAX)))
    if loop:
        body.cbranch("again", reg(RCX, 1))
    body.cbranch("fault", reg(RCX, 1))
    if unknown:
        body.jump_indirect(reg(RDX))
    else:
        body.ret()
    return body.label("fault").ud2()


def _receipt(builder=None):
    unit, = program_units(builder or _function())
    key = f"1:{unit.scopes.function.entry.byte_offset:x}"
    plan = plan_faults({key: unit}, _pe(), CODE_BASE)
    state = {"discharged": plan.discharged, "revoked": {}}
    receipt = _fault_once_control(unit, plan, state)
    assert receipt is not None
    cfg = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
    return unit, plan, state, receipt, cfg


def test_only_the_issued_fault_cut_recovers_once_keys_and_blocks():
    unit, _, _, receipt, cfg = _receipt()
    assert not single_execution_keys(unit.observation, cfg)
    keys = single_execution_keys(unit.observation, cfg, control=receipt)
    assert any(key.endswith(":CALL") for key in keys)
    assert single_execution_blocks(unit.observation, cfg, control=receipt)
    assert receipt.verify(unit, receipt.cuts)


@pytest.mark.parametrize("builder", (_function(unknown=True), _function(loop=True)))
def test_another_unknown_successor_or_real_cycle_still_blocks_the_call(builder):
    unit, _, _, receipt, cfg = _receipt(builder)
    keys = single_execution_keys(unit.observation, cfg, control=receipt)
    assert not any(key.endswith(":CALL") for key in keys)


def test_rep_straight_regions_are_not_made_once_by_a_fault_receipt():
    unit, _, _, receipt, cfg = _receipt()
    first = unit.observation.instructions[0].address
    keys = single_execution_keys(unit.observation, cfg, frozenset({first}), control=receipt)
    assert not any(key.endswith(":CALL") for key in keys)


@pytest.mark.parametrize("change", ("unit", "policy", "revoke", "hazard", "evidence", "image", "authority"))
def test_source_fault_policy_and_current_discharge_are_rechecked(change):
    unit, plan, state, receipt, cfg = _receipt()
    site = receipt.cuts[0][0]
    cuts = receipt.cuts
    if change == "unit":
        unit, = program_units(_function())  # same bytes, distinct admitted instance
    elif change == "policy":
        cuts = ()
    elif change == "revoke":
        state["discharged"] = frozenset()
    elif change == "hazard":
        plan.hazards[site] = ("H1:handler",)
    elif change == "evidence":
        plan.evidence[site] = tuple((key, "handler" if key == "h1" else value)
                                    for key, value in plan.evidence[site])
    elif change == "image":
        object.__setattr__(plan, "image_digest", "different")
    else:
        receipt = replace(receipt, _proof=())
    with pytest.raises(ValueError):
        receipt.verify(unit, cuts)
    if change not in ("unit", "policy"):
        with pytest.raises(ValueError):
            single_execution_keys(unit.observation, cfg, control=receipt)


def test_raw_terminal_or_metadata_alone_is_not_control_authority():
    unit, _, _, _, cfg = _receipt()
    assert _fault_once_control(unit, EMPTY_PLAN, {"discharged": frozenset()}) is None
    with pytest.raises(TypeError):
        single_execution_keys(unit.observation, cfg, control=("terminal",))
    forged = _OnceControlReceipt(unit.scopes.program.scope, unit.scopes.function.scope,
                                unit.scopes.function.observation_digest, (), ())
    with pytest.raises(ValueError):
        forged.verify(unit, ())


def test_normalizer_requires_its_exact_current_fault_cuts():
    unit, _, state, receipt, _ = _receipt()
    with pytest.raises(ValueError):
        FunctionNormalizer().normalize(unit, _once_control=receipt)
    result = FunctionNormalizer().normalize(unit, _once_control=receipt, fault_cuts=receipt.cuts)
    assert result.fault_cuts == receipt.cuts
    state["discharged"] = frozenset()
    with pytest.raises(ValueError):
        FunctionNormalizer().normalize(unit, _once_control=receipt, fault_cuts=receipt.cuts)


def test_real_analysis_transports_receipt_without_inventing_pointer_values(monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    helper = FunctionBuilder(entry=HELPER).ins(op("INT_MULT", [reg(RCX), reg(RDX)], reg(RAX))).ret()
    units = program_units(_function(interfering=True), helper)
    common = dict(exception_directory=_pe())
    before = analyze_units(units, **common)
    after = analyze_units(units, **common, assume_faults_end_execution=True,
                          assume_stock_ghidra_translator=True)
    key = f"1:{CODE_BASE:x}"
    old, new = before[key], after[key]
    reader = next(row.operation_key for row in old.normalized.memory_ssa.actions
                  if row.operation_key.endswith(":LOAD") and row.operation_key.split(":")[1] == f"{CODE_BASE + 4:x}")
    assert any(row.operation_key == reader for row in old.normalized.memory_ssa.actions)
    options = dict(new.normalization_options)
    assert type(options["_once_control"]) is _OnceControlReceipt
    assert options["_once_control"].verify(new.unit, new.normalized.fault_cuts)
    assert new.normalized.memory_ssa.unresolved_reads != old.normalized.memory_ssa.unresolved_reads
    assert new.normalized.may_alias_reads  # a captured pointer is not non-aliasing


def test_a_stale_receipt_cannot_reauthorize_a_frozen_memory_plan(monkeypatch):
    from test_finite_read_addresses import _body
    from test_forward_memory_refinement import _options
    from tdo_v2._call_activation import _source_signature
    from tdo_v2._forward_memory import RefinementRefused, prepare_memory_refinement

    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    body = _body(fault=True)
    unit, = program_units(body)
    key = f"1:{CODE_BASE:x}"
    faults = plan_faults({key: unit}, _pe(), CODE_BASE)
    state = {"discharged": faults.discharged, "revoked": {}}
    receipt = _fault_once_control(unit, faults, state)
    options = {**_options(), "_once_control": receipt, "fault_cuts": receipt.cuts}
    normalized = FunctionNormalizer().normalize(unit, **options)
    source = SimpleNamespace(unit=unit, normalized=normalized, key=key, declared={}, proven={},
        inherited_assumptions=frozenset(), normalization_options=tuple(options.items()),
        normalization_context=(), summary_inputs=(), lifetime_models=(), allocation_models=(),
        allocation_contracts=(), replay_feedback=())
    plan = prepare_memory_refinement(source, options)
    assert plan is not None
    plan.verify()
    _source_signature(source)
    state["discharged"] = frozenset()
    with pytest.raises(RefinementRefused):
        _source_signature(source)
    with pytest.raises(RefinementRefused):
        plan.verify()


def test_outer_fault_revocation_does_not_publish_or_replay_a_stale_cut(monkeypatch):
    from test_fault_premise import MAIN, HELPER as CHECKED, ON, _analyze, _checked_helper, _main, _rva
    from synthetic import copy

    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    main = _main().ins(copy(reg(RAX), const(CHECKED))).call_indirect(RAX).add_rsp(0x28).ret()
    results = _analyze(main, _checked_helper(), directory=_pe([(*_rva(MAIN), 1)]), **ON)
    assert not any(getattr(row.normalized, "fault_cuts", ()) for row in results.values())
    checked = results[f"1:{CHECKED:x}"]
    assert checked.summary.unknown_transfers
    assert not dict(checked.normalization_options).get("_once_control")
