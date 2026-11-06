"""Audited output effects preserve the graph without inventing SIMD values."""

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from synthetic import (
    AARCH64, X86_32, RAX, RBX, RCX, RDX, RSP, ZF, FunctionBuilder,
    const, copy, load, op, program_units, ram, reg, store, tmp,
)
from test_operation_records import _analyzed, _record
from test_register_delta_proofs import _span
from tdo_v2.function_summary import SummaryKind
from tdo_v2.intrinsic_refinements import refinements_for, semantics_from_record
from tdo_v2.lane_slice import lane_index, lane_slice, reached_bytes
from tdo_v2.operation_records import Ineligible, eligibility, evaluate
from tdo_v2.register_delta_proofs import derive_register_delta_proof, verify_register_delta_proof


XMM0, XMM1 = 0x1200, 0x1240


def _instruction(index, *, destination=None, source=None, immediate=None):
    destination = reg(XMM0, 16) if destination is None else destination
    source = reg(XMM1, 16) if source is None else source
    operands = [const(index, 4), destination, source]
    if index == 157:
        operands.append(const(0x1B, 8) if immediate is None else immediate)
    return op("CALLOTHER", operands, destination)


def _body(index, *, entry=0x1000, before=()):
    return FunctionBuilder(entry=entry).ins(*before, _instruction(index)).ins(
        op("SUBPIECE", [reg(XMM0, 16), const(3, 4)], reg(RAX, 1))).ret()


@pytest.mark.parametrize("index,name", [(132, "packsswb"), (157, "pshuflw")])
@pytest.mark.parametrize("forward", ["0", "1"])
def test_explicit_output_and_all_input_dependencies_survive_without_numeric_permission(monkeypatch, index, name, forward):
    monkeypatch.setenv("TDO_V2_FORWARD", forward)
    analyzed = _analyzed(_body(index))
    norm, unit = analyzed.normalized, analyzed.unit
    (key, refinement), = norm.intrinsic_refinements
    assert refinement.semantics is None and refinement.output_only is not None
    assert not norm.assumed_call_effects and not norm.proven_call_effects
    assert not norm.call_clobber_reads
    graph = norm.dependencies
    node = graph.node_for_key("op:" + key)
    assert graph.node(node).semantic_identity == refinement.semantic_id
    action, = [a for a in norm.memory_ssa.actions if a.operation_key == key]
    assert sum(norm.memory_ssa.definitions[i].span.size for i in action.write_definition_ids) == 16
    assert all(norm.memory_ssa.definitions[i].kind.value == "data_write" for i in action.write_definition_ids)
    index_ = lane_index(norm, unit)
    defined = next(i for i, d in enumerate(norm.memory_ssa.definitions)
                   if d.operation_key == "1:1004:0:SUBPIECE")
    definition = norm.memory_ssa.definitions[defined]
    sliced = lane_slice(norm, unit, [(index_.definition_node[defined], (definition.span,))], index=index_)
    assert reached_bytes(sliced, norm) == frozenset(range(XMM0, XMM0+16)) | frozenset(range(XMM1, XMM1+16))
    record = _record(analyzed, RAX, 1)
    userop, = [row for row in record["nodes"] if row.get("opcode") == "CALLOTHER"]
    assert "intrinsic" not in userop
    assert userop["intrinsic_effect"] == refinement.record()
    assert userop["intrinsic_effect"]["userop_name"] == name
    assert userop["intrinsic_effect"]["value_semantics"] is None
    assert semantics_from_record(userop["intrinsic_effect"]) is None
    assert [o["index"] for o in userop["operands"]] == list(range(4 if index == 157 else 3))
    assert eligibility(record) == "unsupported CALLOTHER"
    with pytest.raises(Ineligible, match="unsupported CALLOTHER"):
        evaluate(record, lambda node: 0)


@pytest.mark.parametrize("index", [132, 157])
@pytest.mark.parametrize("engine", ["sparse", "dense"])
def test_unwritten_register_flags_upper_vector_bytes_and_memory_are_preserved(monkeypatch, index, engine):
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    builder = (FunctionBuilder().sub_rsp(32).ins(store(reg(RSP), reg(RCX)))
               .ins(copy(reg(RAX), const(0x1234)), copy(reg(ZF, 1), const(1, 1)))
               .ins(_instruction(index))
               .ins(load(reg(RBX), reg(RSP)), copy(reg(RDX), reg(RAX)),
                    copy(reg(0x1280, 48), reg(XMM0+16, 48)), copy(reg(0x1380, 1), reg(ZF, 1)))
               .add_rsp(32).ret())
    analyzed = _analyzed(builder)
    assert not analyzed.normalized.call_clobber_reads
    assert evaluate(_record(analyzed, RDX), lambda node: None) == {0x1234}
    assert evaluate(_record(analyzed, 0x1380, 1), lambda node: None) == {1}
    assert evaluate(_record(analyzed, RBX), lambda node: 0x5678) == {0x5678}
    key = next(iter(dict(analyzed.normalized.intrinsic_refinements)))
    action, = [a for a in analyzed.normalized.memory_ssa.actions if a.operation_key == key]
    assert [(analyzed.normalized.memory_ssa.definitions[i].span.start,
             analyzed.normalized.memory_ssa.definitions[i].span.size) for i in action.write_definition_ids] == [(XMM0, 16)]
    # A read of upper YMM/ZMM bytes remains an entry dependency, not a SIMD result.
    upper = _record(analyzed, 0x1280, 48)
    assert not any(node.get("opcode") == "CALLOTHER" for node in upper["nodes"])
    assert evaluate(upper, lambda node: 0xABC) == {0xABC}
    assert any(run.span.start == XMM0 and run.span.size == 16 and run.kind is not SummaryKind.IDENTITY
               for exit_ in analyzed.summary.exits for run in exit_.runs)


@pytest.mark.parametrize("index", [132, 157])
def test_prior_opaque_call_and_actual_memory_load_debts_are_not_erased(index):
    source = tmp(0x18000, 16)
    builder = FunctionBuilder().ins(op("CALLOTHER", [const(999, 4)]))
    builder.ins(load(source, reg(RCX)), _instruction(index, source=source))
    builder.ins(op("SUBPIECE", [reg(XMM0, 16), const(0, 4)], reg(RAX, 1))).ret()
    analyzed = _analyzed(builder)
    assert len(analyzed.normalized.intrinsic_refinements) == 1
    assert analyzed.normalized.call_clobber_reads
    assert all(row.intervening_calls == ("1:1000:0:CALLOTHER",)
               for row in analyzed.normalized.call_clobber_reads)
    record = _record(analyzed, RAX, 1)
    assert any(node.get("opcode") == "LOAD" for node in record["nodes"])
    assert any(node.get("debts") for node in record["nodes"])
    assert eligibility(record) is not None
    with pytest.raises(Ineligible):
        evaluate(record, lambda node: 0)


def _changed(index, field, value):
    opcode, inputs, output = deepcopy(_instruction(index))
    if field == "inputs":
        inputs = value
    elif field == "output":
        output = value
    else:
        inputs[field] = value
    return op(opcode, inputs, output)


@pytest.mark.parametrize("index", [132, 157])
@pytest.mark.parametrize("field,value", [
    (0, const(999, 4)), (0, const(132, 8)), (0, reg(132, 4)),
    ("inputs", []), ("inputs", [const(132, 4), reg(XMM0, 16)]),
    (1, reg(XMM1, 16)), (2, reg(XMM1, 8)), (2, ram(0x4000, 16)),
    (2, reg(XMM1+1, 16)), (2, reg(XMM1+16, 16)), (2, reg(0x1600, 16)),
    ("output", None), ("output", reg(XMM0, 8)), ("output", reg(XMM0, 32)),
    ("output", reg(XMM0+1, 16)), ("output", reg(XMM0+16, 16)),
    ("output", reg(0x1600, 16)), ("output", reg(RSP, 16)),
    ("output", tmp(0x18000, 16)), ("output", ram(0x4000, 16)),
])
def test_malformed_signatures_never_gain_output_only_effect(index, field, value):
    unit, = program_units(FunctionBuilder().ins(_changed(index, field, value)).ret())
    assert not refinements_for(unit)


@pytest.mark.parametrize("immediate", [const(256, 8), const(1, 1), const(1, 4), reg(RAX), tmp(0x18000)])
def test_shuffle_immediate_must_be_the_actual_eight_byte_constant(immediate):
    analyzed = _analyzed(FunctionBuilder().ins(_instruction(157, immediate=immediate)).ret())
    assert not analyzed.normalized.intrinsic_refinements
    assert analyzed.normalized.call_clobber_reads


@pytest.mark.parametrize("index", [132, 157])
@pytest.mark.parametrize("arch", [X86_32, AARCH64])
def test_unverified_architectures_do_not_inherit_the_rule(index, arch):
    unit, = program_units(FunctionBuilder(arch=arch).ins(_instruction(index)).ret())
    assert not refinements_for(unit)


@pytest.mark.parametrize("index", [132, 157])
@pytest.mark.parametrize("change", ["version", "constant", "register", "unique"])
def test_minor_version_and_space_classifications_are_not_inferred(monkeypatch, index, change):
    from synthetic import _Provider, CONST, REG, UNIQUE, RAM
    original = _Provider._program_candidate
    def candidate(provider):
        raw = original(provider)
        if change == "version":
            raw["translation_namespace"]["minor_version"] = 7
        elif change != "unique":
            # Swap actual classifications, not the varnode kind codes. The
            # authentic scope pipeline must carry the altered translation.
            changed = {"constant": CONST, "register": REG, "unique": UNIQUE}[change]
            spaces = raw["address_spaces"]
            left = next(row for row in spaces if row["space_id"] == changed)
            right = next(row for row in spaces if row["space_id"] == UNIQUE)
            left_id, right_id = left["space_id"], right["space_id"]
            left["space_id"], right["space_id"] = right_id, left_id
        return raw
    monkeypatch.setattr(_Provider, "_program_candidate", candidate)
    source = tmp(0x18000, 16)
    if change == "unique":
        source = dict(tmp(0x4000, 16), space_id=RAM)
    unit, = program_units(FunctionBuilder().ins(load(source, reg(RCX)), _instruction(index, source=source)).ret())
    assert not refinements_for(unit)


@pytest.mark.parametrize("index", [132, 157])
def test_register_delta_certificate_reaudits_effect_and_rejects_output_overlap(index):
    unit, = program_units(_body(index))
    rules = refinements_for(unit)
    proof = derive_register_delta_proof(unit, _span(unit), {}, rules)
    assert proof is not None and proof.delta == 8
    assert verify_register_delta_proof(proof, unit, _span(unit), {}, rules)
    assert proof.intrinsics == tuple((key, rule.semantic_id) for key, rule in rules.items())
    assert derive_register_delta_proof(unit, _span(unit), {}, {}) is None
    assert derive_register_delta_proof(unit, _span(unit, XMM0, 8), {}, rules) is None
    key, rule = next(iter(rules.items()))
    forged = replace(rule, output_only=replace(rule.output_only, effect_id="unverified"))
    assert derive_register_delta_proof(unit, _span(unit), {}, {key: forged}) is None


@pytest.mark.parametrize("index", [132, 157])
def test_record_effect_is_reaudited_and_never_promoted_to_numeric_semantics(index):
    analyzed = _analyzed(_body(index))
    key, rule = next(iter(dict(analyzed.normalized.intrinsic_refinements).items()))
    forged = replace(rule, output_only=replace(rule.output_only, effect_id="unverified"))
    altered = replace(analyzed, normalized=replace(analyzed.normalized, intrinsic_refinements=((key, forged),)))
    node, = [node for node in _record(altered, RAX, 1)["nodes"] if node.get("opcode") == "CALLOTHER"]
    assert "intrinsic_effect" not in node and "intrinsic" not in node
    record = deepcopy(_record(analyzed, RAX, 1))
    node, = [node for node in record["nodes"] if node.get("opcode") == "CALLOTHER"]
    node["intrinsic"] = node["intrinsic_effect"]
    assert eligibility(record) == "unsupported CALLOTHER"


@pytest.mark.parametrize("index", [132, 157])
def test_removing_effect_registry_reinstates_opaque_debt(monkeypatch, index):
    from tdo_v2 import intrinsic_refinements
    monkeypatch.setattr(intrinsic_refinements, "_OUTPUT_ONLY", {})
    analyzed = _analyzed(_body(index))
    assert not analyzed.normalized.intrinsic_refinements
    assert analyzed.normalized.call_clobber_reads


@pytest.mark.parametrize("index", [132, 157])
def test_cold_and_saved_summaries_preserve_the_same_physical_state_and_reject_old_cache(tmp_path, index):
    from test_summary_templates import F, WIN64, _client, _effect
    from tdo_v2.summary_store import load_external_models
    # Track the same physical register universe in the direct and cached
    # clients; preservation beyond unobserved caller bytes is not comparable.
    caller = lambda target: FunctionBuilder().call(target).ins(copy(reg(XMM1, 16), reg(XMM1, 16))).ret()
    direct = _client(tmp_path, caller, _body(index, entry=F), template=False)
    saved = _client(tmp_path, caller, _body(index, entry=F), template=True)
    a, b = _effect(direct), _effect(saved)
    assert a.restores_stack and b.restores_stack
    assert (a.preserved, a.preserves_memory, a.observes_registers) == (b.preserved, b.preserves_memory, b.observes_registers)
    assert not any(label.startswith("pcodeop-model:") for label in saved.inherited_assumptions)
    path = tmp_path / "derived.json"
    raw = json.loads(path.read_text())
    assert raw["source"]["engine"]["semantics_version"] == 47
    raw["source"]["engine"]["semantics_version"] = 44
    path.write_text(json.dumps(raw))
    old = load_external_models([path], *WIN64)
    assert all(entry.refusal is not None for file in old.files for entry in file.entries)
