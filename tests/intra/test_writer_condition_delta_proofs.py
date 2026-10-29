"""Refusing memory-writer premises preserves only independent register facts."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path

import pytest

from synthetic import (RAX, RBX, RCX, RDX, RDI, RSI, RSP, FunctionBuilder, const, load,
                       op, program_units, reg, store)
from tdo_v2.call_summary_effects import derive_proven_call_effect
from tdo_v2.interprocedural import analyze_units
from tdo_v2.relative_memory import ImageBaseTracking
from tdo_v2.span_geometry import ByteSpan, StorageObjectKind
from tdo_v2.summary_templates import (TemplateError, TemplateRefused, _export_delta_proofs,
                                     export_summary, instantiate)


def _conditional(*, load_stack=False, marker=False):
    body = FunctionBuilder()
    if marker:
        body.ins(op('CALLOTHER', [const(17, 4)]))
    body = (body
        .ins(load(reg(RAX), reg(RSI)), store(reg(RAX), reg(RDX)))
        .ins(store(reg(RDI), reg(RCX)))
        .ins(load(reg(RAX), reg(RSI)), store(reg(RAX), reg(RBX))))
    if load_stack:
        body.ins(load(reg(RSP), reg(RAX)))
    return body.ret()


def _marker_models():
    from tdo_v2.pcodeop_models import load_pcodeop_models
    return load_pcodeop_models([Path(__file__).resolve().parents[2] / 'models/pcodeops/x86.json'])


def _analyzed(*, load_stack=False, marker=False):
    with ImageBaseTracking(((0x1000, 0x5000),), lambda address, size, value: 0x1000 <= value < 0x5000):
        result = analyze_units(program_units(_conditional(load_stack=load_stack, marker=marker)),
            assume_entry_values_not_frame=False, assume_globals_disjoint_from_stack=False,
            assume_opaque_callees_leave_no_stack_addresses=False, private_frame_above=0,
            assume_debug_break_traps_do_not_return=False,
            pcodeop_models=_marker_models() if marker else None)['1:1000']
    assert result.summary.writer_conditions
    return result


def _register_object(item):
    return next(d.span.object_id for d in item.normalized.memory_ssa.definitions
                if d.span.object_id.kind is StorageObjectKind.REGISTER_FILE)


def _rejected_effect(item, summary=None):
    obj = _register_object(item)
    # No memory anchors: the generic writer conditions cannot be located.
    return derive_proven_call_effect(summary or item.summary, item.key, obj, 0x300,
        excluded=(ByteSpan(obj, RSP, 8),), anchors={}, stack_deltas={(RSP, 8): -8})


def test_conditional_writer_refusal_retains_only_a_genuine_independent_stack_fact():
    item = _analyzed()
    proof, = item.summary.independent_delta_proofs
    assert proof.register == (RSP, 8) and proof.delta == 8
    assert not proof.assumed_no_effect
    effect = _rejected_effect(item)
    assert effect.restores_stack
    assert effect.register_delta_proofs == (proof,)
    assert not effect.preserves_memory and not effect.preserved and not effect.runs and not effect.memory_runs
    assert effect.escapes_stack and effect.observes_registers


def test_old_conditional_delta_without_certificate_is_still_erased():
    item = _analyzed()
    assert dict(item.summary.register_deltas)[(RSP, 8)] == 8
    bare = replace(item.summary, independent_delta_proofs=())
    effect = _rejected_effect(item, bare)
    assert not effect.restores_stack and not effect.register_delta_proofs
    assert not effect.preserves_memory and not effect.preserved


def test_potentially_aliased_load_into_stack_cannot_acquire_independent_proof():
    item = _analyzed(load_stack=True)
    assert not item.summary.independent_delta_proofs
    # Even if an older/value-sensitive derivation offered a conditional +8,
    # no register-only certificate authorizes keeping it when guards fail.
    conditional = replace(item.summary, register_deltas=(((RSP, 8), 8),))
    assert not _rejected_effect(item, conditional).restores_stack


def test_template_roundtrip_preserves_proof_but_does_not_restore_other_state():
    item = _analyzed()
    template = export_summary(item, {item.key: item})
    assert template['writer_conditions'] and template['independent_delta_proofs']
    summary, _ = instantiate(template, 'derived-test', _register_object(item), 1)
    assert summary.independent_delta_proofs == item.summary.independent_delta_proofs
    effect = _rejected_effect(item, summary)
    assert effect.restores_stack and effect.register_delta_proofs
    assert not effect.preserves_memory and not effect.preserved and not effect.runs


def test_export_recomputes_instead_of_accepting_a_rehashed_fabricated_receipt():
    item = _analyzed()
    proof, = item.summary.independent_delta_proofs
    fake = replace(proof, delta=16, blocks=tuple(replace(block, exit_delta=16) if block.exits else block
                                               for block in proof.blocks))
    item.summary = replace(item.summary, register_deltas=(((RSP, 8), 16),), independent_delta_proofs=(fake,))
    with pytest.raises(TemplateRefused, match='original evidence'):
        _export_delta_proofs(item)


def test_export_refuses_certificate_for_stale_original_code():
    item = _analyzed()
    changed, = program_units(FunctionBuilder().ret())
    item.unit = changed
    with pytest.raises(TemplateRefused, match='original evidence'):
        _export_delta_proofs(item)


@pytest.mark.parametrize('change', [
    lambda record: record['independent_delta_proofs'][0].update(delta=16),
    lambda record: record['independent_delta_proofs'].append(deepcopy(record['independent_delta_proofs'][0])),
    lambda record: record.update(register_deltas=[]),
    lambda record: record['independent_delta_proofs'][0].update(content_sha256='0' * 64),
])
def test_template_rejects_invalid_or_unmatched_proof_receipts(change):
    item = _analyzed()
    template = export_summary(item, {item.key: item})
    change(template)
    with pytest.raises(TemplateError, match='independent register delta proof'):
        instantiate(template, 'derived-test', _register_object(item), 1)


def _model_file(item):
    from tdo_v2.function_summary import FUNCTION_SUMMARY_VERSION
    from tdo_v2.summary_templates import ENGINE_SEMANTICS_VERSION, TEMPLATE_VERSION, pcodeop_digest
    proof, = item.summary.independent_delta_proofs
    language = item.unit.scopes.program.evidence.translation_namespace
    return dict(format_version=1, kind='summary', id='delta-proof-test', version=1,
        language_id=language.language_id, abi_tag='win64', libraries=['PROOF.DLL'],
        source=dict(kind='derived', library='PROOF.DLL', sha256=proof.executable_sha256,
            image_base=item.unit.scopes.program.evidence.image_base.byte_offset,
            language=dict(id=language.language_id, major=language.major_version, minor=language.minor_version),
            engine=dict(summary_version=FUNCTION_SUMMARY_VERSION, template_version=TEMPLATE_VERSION,
                        semantics_version=ENGINE_SEMANTICS_VERSION),
            parameters=dict(private_frame_above=0), models=[],
            pcodeops=pcodeop_digest(_marker_models() if proof.assumed_no_effect else None),
            assumptions=sorted({label for _, label in proof.assumed_no_effect})),
        entries=[dict(name='F', original_names=['F'], summary=export_summary(item, {item.key: item}))])


@pytest.mark.parametrize('mismatch,reason', [('assumption', 'hides assumptions'), ('binary', 'another source binary')])
def test_derived_loader_refuses_hidden_model_premise_or_other_binary_and_never_applies_it(tmp_path, mismatch, reason):
    from tdo_v2.summary_store import load_external_models
    from tdo_v2.image_info import ImageInfo, ImportedSymbol
    item = _analyzed(marker=True)
    raw = _model_file(item)
    assert raw['source']['assumptions'] == ['pcodeop-model:x86-markers/LOCK@v1']
    if mismatch == 'assumption':
        raw['source']['assumptions'] = []
    else:
        raw['source']['sha256'] = '0' * 64
    path = tmp_path / 'derived.json'
    path.write_text(json.dumps(raw))
    models = load_external_models([path], 'x86:LE:64:default', 'win64')
    entry, = models.files[0].entries
    assert reason in entry.refusal
    target = 0x1f00
    image = ImageInfo('synthetic', (), (ImportedSymbol('PROOF.DLL', 'F', 'F', (), ((1, target),)),), (), ())
    caller = analyze_units(program_units(FunctionBuilder().call(target).ret()), image_info=image,
        external_models=models, pcodeop_models=_marker_models(), private_frame_above=0)['1:1000']
    assert not caller.proven
    assert any(reason in refusal for refusal in caller.refused_models.values())


def test_derived_loader_keeps_the_existing_marker_assumption_visible(tmp_path):
    from tdo_v2.summary_store import load_model_file
    item = _analyzed(marker=True)
    path = tmp_path / 'derived.json'
    path.write_text(json.dumps(_model_file(item)))
    entry, = load_model_file(path).entries
    assert entry.refusal is None
    assert 'pcodeop-model:x86-markers/LOCK@v1' in entry.inherited
