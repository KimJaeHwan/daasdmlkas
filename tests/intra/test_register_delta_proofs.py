"""Independent CFG/register proofs never import memory-conditional deltas."""
from copy import deepcopy
from dataclasses import replace

import pytest

from synthetic import (RAX, RBX, RSP, ZF, X86_32, ESP, FunctionBuilder, add, const, copy,
                       load, op, program_units, reg, store, tmp)
from tdo_v2.interprocedural import analyze_units
from tdo_v2.intrinsic_refinements import refinements_for
from tdo_v2.model import StorageObjectId
from tdo_v2.register_delta_proofs import (derive_register_delta_proof, validate_proof_record,
                                        verify_register_delta_proof)
from tdo_v2.span_geometry import ByteSpan, StorageObjectKind


def _span(unit, start=RSP, size=8):
    return ByteSpan(StorageObjectId(StorageObjectKind.REGISTER_FILE, unit.scopes.program.scope, 0), start, size)


def _plain(builder, *, start=RSP, size=8, intrinsics=True):
    unit, = program_units(builder)
    span = _span(unit, start, size)
    rules = refinements_for(unit) if intrinsics else {}
    return derive_register_delta_proof(unit, span, {}, rules), unit, span, rules


def _called(tail=False):
    target = 0x1800
    caller = FunctionBuilder().tail_call(target) if tail else FunctionBuilder().sub_rsp(40).call(target).add_rsp(40).ret()
    # The engine identifies the program's stack register from an observed
    # call shape; the extra caller supplies that evidence for a pure thunk.
    extra = (FunctionBuilder(entry=0x1c00).call(0x1000).ret(),) if tail else ()
    results = analyze_units(program_units(caller, FunctionBuilder(entry=target).ret(), *extra),
                            assume_entry_values_not_frame=False, assume_globals_disjoint_from_stack=False,
                            assume_opaque_callees_leave_no_stack_addresses=False, private_frame_above=0)
    item = results['1:1000']
    return item, _span(item.unit)


def test_arithmetic_cfg_certificate_records_original_operations_and_roundtrips():
    proof, unit, span, rules = _plain(FunctionBuilder().sub_rsp(40).add_rsp(40).ret())
    assert proof is not None and proof.register == (RSP, 8) and proof.delta == 8
    assert proof.function_scope == unit.scopes.function.scope.digest.hex()
    assert proof.observation_digest == unit.scopes.function.observation_digest.hex()
    assert '1:1008:1:INT_ADD' in proof.operation_keys
    assert proof.exits == ('1:1008',)
    assert not proof.call_facts and not proof.intrinsics
    assert validate_proof_record(proof.record()) == proof
    assert verify_register_delta_proof(proof, unit, span, {}, rules)


@pytest.mark.parametrize('tail', [False, True])
def test_known_call_and_pure_tail_compose_the_correct_raw_stack_delta(tail):
    item, span = _called(tail)
    proof = derive_register_delta_proof(item.unit, span, item.proven, {})
    assert proof is not None and proof.delta == 8
    fact, = proof.call_facts
    assert fact.kind == ('tail' if tail else 'call')
    assert fact.delta == 8
    assert fact.observed_push_delta == (None if tail else -8)
    assert fact.callee == '1:1800'
    assert validate_proof_record(proof.record()) == proof
    assert verify_register_delta_proof(proof, item.unit, span, item.proven, {})


def test_memory_writes_do_not_license_memory_values_but_are_irrelevant_to_register_arithmetic():
    proof, *_ = _plain(FunctionBuilder().sub_rsp(40)
        .ins(store(reg(RAX), reg(RBX))).add_rsp(40).ret())
    assert proof is not None and proof.delta == 8


@pytest.mark.parametrize('write', [copy(reg(RSP, 4), const(0, 4)),
    copy(reg(RSP), reg(RBX)), load(reg(RSP), reg(RAX)),
    op('INT_AND', [reg(RSP), const(-16 & ((1 << 64) - 1))], reg(RSP)),
    op('INT_ADD', [reg(RSP), reg(RBX)], reg(RSP))])
def test_partial_nonaffine_and_memory_based_stack_writes_refuse(write):
    proof, *_ = _plain(FunctionBuilder().ins(write).ret())
    assert proof is None


def test_conditional_stack_deltas_are_not_merged_into_one_claim():
    builder = FunctionBuilder().cbranch('other', reg(ZF, 1)).add_rsp(8).branch('end')
    builder.label('other').add_rsp(16).label('end').ret()
    assert _plain(builder)[0] is None


def test_equal_conditional_deltas_are_valid_on_all_paths():
    builder = FunctionBuilder().cbranch('other', reg(ZF, 1)).add_rsp(8).branch('end')
    builder.label('other').add_rsp(8).label('end').ret()
    proof, *_ = _plain(builder)
    assert proof is not None and proof.delta == 16


@pytest.mark.parametrize('amount,accepted', [(0, True), (8, False)])
def test_loop_backedge_must_preserve_the_entry_invariant(amount, accepted):
    builder = FunctionBuilder().label('again').add_rsp(amount).cbranch('again', reg(ZF, 1)).ret()
    proof, *_ = _plain(builder)
    assert (proof is not None) is accepted


@pytest.mark.parametrize('change', [lambda effect: None,
    lambda effect: replace(effect, restores_stack=False),
    lambda effect: replace(effect, writer_conditions=(('unknown', 'pair'),)),
    lambda effect: replace(effect, noreturn=True),
    lambda effect: replace(effect, callee='1:1804'),
    lambda effect: replace(effect, tail_stack_delta=8)])
def test_missing_conditional_or_inapplicable_call_facts_refuse(change):
    item, span = _called()
    key, effect = next(iter(item.proven.items()))
    assert derive_register_delta_proof(item.unit, span, {key: change(effect)}, {}) is None


def test_tail_must_not_use_vacuously_true_restores_stack():
    item, span = _called(tail=True)
    key, effect = next(iter(item.proven.items()))
    assert effect.restores_stack
    for wrong in (replace(effect, tail_stack_delta=None), replace(effect, tail_stack=()),
                  replace(effect, tail_stack=(_span(item.unit, RAX),))):
        assert derive_register_delta_proof(item.unit, span, {key: wrong}, {}) is None


def test_a_call_without_observed_push_shape_is_not_a_restoring_call():
    from synthetic import ram
    item, span = _called()
    effect = next(iter(item.proven.values()))
    unit, = program_units(FunctionBuilder().ins(op('CALL', [ram(0x1800)])).ret())
    assert derive_register_delta_proof(unit, _span(unit), {'1:1000:0:CALL': effect}, {}) is None


def test_indirect_call_is_outside_the_narrow_certificate_scope():
    proof, *_ = _plain(FunctionBuilder().call_indirect(RAX).ret())
    assert proof is None


def test_unresolved_tail_and_indirect_terminal_are_not_normal_exit_proofs():
    assert _plain(FunctionBuilder().tail_call(0x1800))[0] is None
    assert _plain(FunctionBuilder().ins(op('BRANCHIND', [reg(RAX)])).ret())[0] is None


def test_store_to_register_address_space_is_not_ignored_as_memory():
    from synthetic import REG
    assert _plain(FunctionBuilder().ins(op('STORE', [const(REG), reg(RAX), reg(RBX)])).ret())[0] is None


@pytest.mark.parametrize('index,supply,accepted', [(483, True, True), (483, False, False), (484, True, False)])
def test_intrinsic_requires_the_independently_audited_refinement(index, supply, accepted):
    builder = FunctionBuilder().ins(op('CALLOTHER', [const(index, 4), reg(0x1200, 32),
                                      reg(0x1240, 32)], tmp(0x18000, 32))).ret()
    proof, *_ = _plain(builder, intrinsics=supply)
    assert (proof is not None) is accepted
    if accepted:
        assert proof.intrinsics == (('1:1000:0:CALLOTHER', 'x86-vpcmpeqw-avx2-le256-v1'),)
        assert validate_proof_record(proof.record()) == proof


def test_register_parameter_is_not_hardcoded_to_x64_rsp():
    proof, *_ = _plain(FunctionBuilder(arch=X86_32).sub_rsp(20).add_rsp(20).ret(), start=ESP, size=4)
    assert proof is not None and proof.register == (ESP, 4) and proof.delta == 4


def test_wrong_register_object_identity_refuses():
    _, unit, span, rules = _plain(FunctionBuilder().ret())
    other_scope = replace(span.object_id.scope, digest=bytes(32))
    wrong = ByteSpan(replace(span.object_id, scope=other_scope), span.start, span.size)
    assert derive_register_delta_proof(unit, wrong, {}, rules) is None


def test_rehashed_inconsistent_cfg_receipt_refuses_even_structurally():
    proof, *_ = _plain(FunctionBuilder().sub_rsp(8).add_rsp(8).ret())
    bad_blocks = (replace(proof.blocks[0], exit_delta=123), *proof.blocks[1:])
    assert validate_proof_record(replace(proof, blocks=bad_blocks).record()) is None


@pytest.mark.parametrize('change', [lambda row: row.update(delta=True), lambda row: row.update(version=True),
    lambda row: row.update(delta=9), lambda row: row.update(unknown='extra'),
    lambda row: row['blocks'][0].update(entry_delta='0'),
    lambda row: row.update(function_scope='unknown'),
    lambda row: row.update(exits=[]), lambda row: row.update(content_sha256='0' * 64)])
def test_malformed_or_modified_receipt_refuses(change):
    proof, *_ = _plain(FunctionBuilder().ret())
    record = deepcopy(proof.record())
    change(record)
    assert validate_proof_record(record) is None


def test_structural_validation_is_not_recomputation_of_proof():
    original, unit, span, rules = _plain(FunctionBuilder().ret())
    # Public dataclasses/JSON are evidence transport, not minting authority.
    fabricated = replace(original, delta=16, blocks=tuple(replace(b, exit_delta=16) for b in original.blocks))
    assert validate_proof_record(fabricated.record()) == fabricated
    assert not verify_register_delta_proof(fabricated, unit, span, {}, rules)
    changed, changed_unit, changed_span, changed_rules = _plain(FunctionBuilder().add_rsp(8).ret())
    assert changed.delta == 16
    assert not verify_register_delta_proof(original, changed_unit, changed_span, {}, changed_rules)


def test_current_call_fact_changes_invalidate_a_recorded_proof():
    item, span = _called()
    proof = derive_register_delta_proof(item.unit, span, item.proven, {})
    key, effect = next(iter(item.proven.items()))
    assert not verify_register_delta_proof(proof, item.unit, span, {key: replace(effect, restores_stack=False)}, {})


def test_existing_no_effect_model_is_explicitly_inherited_not_an_isa_proof():
    from tdo_v2.assumed_call_effects import AssumedCallEffect
    unit, = program_units(FunctionBuilder().ins(op('CALLOTHER', [const(17, 4)])).ret())
    span = _span(unit)
    key, label = '1:1000:0:CALLOTHER', 'pcodeop-model:x86-markers/LOCK@v1'
    declared = {key: AssumedCallEffect(label, ())}
    assert derive_register_delta_proof(unit, span, {}, {}) is None
    proof = derive_register_delta_proof(unit, span, {}, {}, assumed_call_effects=declared)
    assert proof is not None and proof.delta == 8
    assert proof.assumed_no_effect == ((key, label),) and not proof.intrinsics
    assert validate_proof_record(proof.record()) == proof
    assert verify_register_delta_proof(proof, unit, span, {}, {}, assumed_call_effects=declared)
    assert not verify_register_delta_proof(proof, unit, span, {}, {})
    assert not verify_register_delta_proof(proof, unit, span, {}, {},
        assumed_call_effects={key: AssumedCallEffect('different-model-premise', ())})


@pytest.mark.parametrize('shape', ['output', 'argument', 'read', 'write', 'ordinary-call'])
def test_no_effect_declaration_never_licenses_other_call_or_output_shapes(shape):
    from tdo_v2.assumed_call_effects import AssumedCallEffect
    from tdo_v2.physical_state import PhysicalRegisterSlice
    from synthetic import ram
    output = tmp(0x18000) if shape == 'output' else None
    inputs = [const(17, 4), reg(RAX)] if shape == 'argument' else [const(17, 4)]
    opcode = 'CALLOTHER'
    if shape == 'ordinary-call':
        opcode, inputs = 'CALL', [ram(0x1800)]
    unit, = program_units(FunctionBuilder().ins(op(opcode, inputs, output)).ret())
    declared = AssumedCallEffect('explicit-model',
        (PhysicalRegisterSlice(RAX, 8),) if shape == 'write' else (),
        (PhysicalRegisterSlice(RAX, 8),) if shape == 'read' else ())
    assert derive_register_delta_proof(unit, _span(unit), {}, {},
        assumed_call_effects={f'1:1000:0:{opcode}': declared}) is None
