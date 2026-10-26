"""Raw caller/callee writes bound the optional NULL-realloc activation proof.

These are graph proofs under the shipped CRT contracts, not native allocator
executions or a general no-use-after-free/whole-object extent theorem.
"""

import json

import pytest

from synthetic import (RBX, RCX, RDX, RDI, RSP, FunctionBuilder,
                       add, const, copy, load, program_units, reg, store, tmp)
from test_external_models import MODELS, THUNKS, _image
from tdo_v2._call_activation import _first
from tdo_v2._load_identity import definition_identity
from tdo_v2.forward import probe
from tdo_v2.interprocedural import analyze_units
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.span_geometry import StorageObjectKind
from tdo_v2.summary_store import load_external_models


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def forward_on(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_FORWARD", "1")


@pytest.fixture(scope="module")
def models():
    return load_external_models(MODELS, "x86:LE:64:default", "win64")


def _key(builder, ordinal, opcode):
    return f"1:{builder._address(len(builder._rows)):x}:{ordinal}:{opcode}"


def _case(kind="unchanged", *, saved_displacement=0x30):
    caller = (FunctionBuilder().sub_rsp(0x80)
              .ins(add(reg(RCX), reg(RSP), const(0x30))))
    data = _key(caller, 0, "STORE")
    caller.ins(store(reg(RCX), const(0)))
    outer = _key(caller, 2, "CALL")
    caller.call(0x1600).add_rsp(0x80).ret()

    callee = (FunctionBuilder(0x1600).sub_rsp(0x38)
              .ins(copy(reg(RBX), reg(RCX))))
    saved = _key(callee, 1, "STORE")
    offset = const(saved_displacement & ((1 << 64) - 1))
    callee.ins(add(tmp(0x100), reg(RSP), offset), store(tmp(0x100), reg(RBX)))
    changed = None
    if kind in ("full-write", "partial-write", "unknown-write"):
        changed = _key(callee, 0, "STORE")
        pointer = reg(RDI) if kind == "unknown-write" else reg(RBX)
        callee.ins(store(pointer, const(1, 1 if kind == "partial-write" else 8)))
    elif kind == "unknown-call":
        changed = _key(callee, 2, "CALL")
        callee.call(0x1700)
    old_read = _key(callee, 0, "LOAD")
    callee.ins(load(reg(RCX), reg(RBX))).ins(copy(reg(RDX), const(16)))
    realloc = _key(callee, 2, "CALL")
    callee.call(THUNKS["realloc"])
    reader = _key(callee, 1, "LOAD")
    callee.ins(add(tmp(0x100), reg(RSP), offset), load(reg(RBX), tmp(0x100)))
    callee.add_rsp(0x38).ret()
    return (caller, callee), dict(data=data, outer=outer, saved=saved, changed=changed,
                                 old_read=old_read, realloc=realloc, reader=reader)


def _run(models, kind="unchanged", *, saved_displacement=0x30, **options):
    builders, points = _case(kind, saved_displacement=saved_displacement)
    result = analyze_units(program_units(*builders), image_info=_image(), external_models=models,
                           private_frame_above=40, assume_globals_disjoint_from_stack=True,
                           assume_entry_values_not_frame=False,
                           assume_opaque_callees_leave_no_stack_addresses=False, **options)
    return result, points


def _read(item, key):
    return next(read for read in item.normalized.memory_ssa.reads
                if item.normalized.memory_ssa.actions[read.action_id].operation_key == key
                and read.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE)


def _clobbered(item, points):
    return any(row.operation_key == points["reader"] and points["realloc"] in row.intervening_calls
               for row in item.normalized.call_clobber_reads)


def test_original_null_data_specializes_only_the_call_and_keeps_the_saved_writer(models):
    result, points = _run(models)
    caller, generic = result["1:1000"], result["1:1600"]
    assert _clobbered(generic, points)
    assert not generic.proven[points["realloc"]].preserves_memory
    assert generic.normalized.activation_entry is None and not generic.activations
    assert points["outer"] in caller.activations
    context = caller.activations[points["outer"]]
    assert context.normalized.activation_entry.context == (caller.key, points["outer"])
    assert not context.proven[points["realloc"]].preserves_memory
    assert not _clobbered(context, points)
    read = _read(context, points["reader"])
    ids, _ = probe(context.normalized, points["reader"], (read.span,))
    definition = context.normalized.memory_ssa.definitions[ids[read.span]]
    assert definition.kind is MemoryDefinitionKind.DATA_WRITE and definition.operation_key == points["saved"]
    assert read.span in context.proven[points["realloc"]].preserved
    # The 56-byte entry relation is derived from raw call shape/RCX, not a
    # Trace address, helper name, or the example's special SP+80 constant.
    assert any(delta == 56 for _, _, delta in context.normalized.activation_entry.registers)
    assert len(context.activation_witness[3]) > 0
    assert all(literal.unsigned == 0 for _, _, literal in context.activation_witness[3])
    original = context.activation_witness[0]
    for span, identity, literal in context.activation_witness[3]:
        ids, _ = probe(original.normalized, _first(original.normalized, points["outer"]), (span,))
        definition = original.normalized.memory_ssa.definitions[ids[span]]
        assert definition.kind is MemoryDefinitionKind.DATA_WRITE
        assert definition.operation_key == points["data"] and identity == definition_identity(definition)
    assert "registered-handlers-are-not-observed" in context.inherited_assumptions
    assert "entry-values-do-not-address-the-new-frame" not in context.normalized.activation_entry.requires


@pytest.mark.parametrize("kind", ("full-write", "partial-write", "unknown-write", "unknown-call"))
def test_original_intermediate_write_or_call_cannot_reuse_the_null_proof(models, kind):
    result, points = _run(models, kind)
    caller, generic = result["1:1000"], result["1:1600"]
    assert generic.normalized.activation_entry is None
    context = caller.activations[points["outer"]]
    assert context.normalized.activation_entry is not None
    assert _clobbered(context, points)
    assert not any(row.preserved and row.demand.call == points["realloc"]
                   for row in context.call_memory_decisions)
    assert context.proven[points["realloc"]] == generic.proven[points["realloc"]]
    assert _clobbered(generic, points)
    target = _read(generic, points["reader"])
    assert target.span not in generic.proven[points["realloc"]].preserved
    operations = {f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:{operation.opcode}": operation
                  for row in generic.unit.observation.instructions
                  for ordinal, operation in enumerate(row.operations)}
    assert points["changed"] in operations
    assert operations[points["changed"]].opcode == ("CALL" if kind == "unknown-call" else "STORE")
    if kind in ("full-write", "partial-write"):
        operation = operations[points["changed"]]
        assert operation.inputs[-1].byte_size == (1 if kind == "partial-write" else 8)
        assert operation.inputs[-1].coordinate.byte_offset == 1
        old = _read(generic, points["old_read"])
        assert any(generic.normalized.memory_ssa.definitions[identifier].operation_key == points["changed"]
                   for fragment in old.fragments for identifier in fragment.definition_ids)
    elif kind == "unknown-write":
        assert any(row.operation_key == points["old_read"] for row in generic.normalized.may_alias_reads)
    else:
        assert any(row.operation_key == points["old_read"] and points["changed"] in row.intervening_calls
                   for row in generic.normalized.call_clobber_reads)


def test_registered_callback_assumption_off_cannot_create_a_scope_proof(models):
    result, points = _run(models, assume_registered_handlers_not_observed=False)
    caller, callee = result["1:1000"], result["1:1600"]
    assert not callee.lifetime_models
    assert points["realloc"] not in callee.proven
    assert points["realloc"] in callee.refused_models
    assert "registered-handlers-are-not-observed" in callee.refused_models[points["realloc"]]
    assert _clobbered(callee, points)
    context = caller.activations.get(points["outer"])
    if context is not None:
        assert _clobbered(context, points)
        assert not any(row.preserved for row in context.call_memory_decisions)


def test_forward_off_keeps_the_original_generic_call_debt(models, monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "0")
    result, points = _run(models)
    caller, callee = result["1:1000"], result["1:1600"]
    assert not caller.activations and callee.normalized.activation_entry is None
    assert callee.lifetime_models and _clobbered(callee, points)
    assert _read(callee, points["reader"]).span not in callee.proven[points["realloc"]].preserved


@pytest.mark.parametrize("saved_displacement", (-16, -12))
def test_slot_in_callee_frame_is_not_preserved(models, saved_displacement):
    result, points = _run(models, saved_displacement=saved_displacement)
    caller, callee = result["1:1000"], result["1:1600"]
    context = caller.activations.get(points["outer"])
    if context is not None:
        assert _clobbered(context, points)
        target = _read(context, points["reader"])
        assert target.span not in context.proven[points["realloc"]].preserved
    assert not callee.proven[points["realloc"]].preserves_memory
    assert _clobbered(callee, points)


@pytest.mark.parametrize("saved_displacement", (-8, -4))
def test_slot_on_the_calls_return_address_reads_the_push(models, saved_displacement):
    """The saved slot is (partly) the inner CALL's own return-address slot:
    no exclusion is needed there -- the push is its definition
    (``normalize._push_row``), so with the call preserving memory the read
    gets the pushed bytes (and the old store's for the rest), exactly. (The
    program oracle checks the caller's graph, which embeds the context.)"""
    from test_interprocedural import _check

    result, points = _run(models, saved_displacement=saved_displacement)
    caller, callee = result["1:1000"], result["1:1600"]
    context = caller.activations[points["outer"]]
    assert not _clobbered(context, points)
    ssa = context.normalized.memory_ssa
    writers = {ssa.definitions[fragment.definition_ids[0]].operation_key
               for read in ssa.reads if ssa.actions[read.action_id].operation_key == points["reader"]
               and read.span.object_id.kind.value == "function_relative" for fragment in read.fragments}
    assert f"{points['realloc']}~push" in writers
    assert _clobbered(callee, points)   # (the generic callee: no activation facts, the call keeps its debt)
    program = {(1, item.unit.scopes.function.entry.byte_offset): item.unit.observation for item in result.values()}
    assert _check(result, program).silent == []


def test_explicit_other_memory_contract_withdrawal_keeps_the_raw_call_debt(models, tmp_path):
    # Explicit contract variation, strictly reloaded with its own identity and
    # digest. It is not presented as the shipped CRT's real implementation.
    source = next(path for path in MODELS if path.name == "crt_win64.json")
    raw = json.loads(source.read_text(encoding="utf-8"))
    raw["id"] = "activation-realloc-clobbered-control"
    realloc = next(entry for entry in raw["entries"] if entry["name"] == "realloc")
    realloc["other_memory"] = "clobbered"
    path = tmp_path / "realloc-clobbered.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    changed = load_external_models((path,), "x86:LE:64:default", "win64")
    assert changed.lookup("realloc")[0].digest != models.lookup("realloc")[0].digest
    result, points = _run(changed)
    caller, callee = result["1:1000"], result["1:1600"]
    assert callee.lifetime_models
    context = caller.activations.get(points["outer"])
    if context is not None:
        assert _clobbered(context, points)
        assert not any(row.preserved for row in context.call_memory_decisions)
        assert context.proven[points["realloc"]] == callee.proven[points["realloc"]]
    assert not callee.lifetime_models[0][2].keeps_other_memory
    assert _clobbered(callee, points)
    target = _read(callee, points["reader"])
    assert target.span not in callee.proven[points["realloc"]].preserved
