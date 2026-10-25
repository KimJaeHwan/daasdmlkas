"""Original UE constructor zero bytes survive summaries, templates and calls.

Uses TDO_UE_CORE_BUNDLE, TDO_UE_TRACE_BUNDLE and TDO_UE_STACK_EVIDENCE, as
test_callee_preserved_low_binary. The current derived model must be regenerated
by the production workflow; these tests never write or regenerate model files.
"""

from copy import deepcopy
import json

import pytest

from test_callee_preserved_low_binary import (
    CONSTRUCTOR, CORE_SHA, R005, REPO, _core_results, _projector, _trace_run, core, trace,
)
from tdo_v2.constant_value import ExactConstant
from tdo_v2.forward import probe
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.span_geometry import ByteSpan, StorageObjectKind
from tdo_v2.summary_templates import (
    ENGINE_SEMANTICS_VERSION, TEMPLATE_VERSION, TemplateError, export_summary, instantiate,
)


CTOR_WRITERS = ("1b1:180037a82:1:STORE", "1b1:180037a85:2:STORE")
CTOR_CALLS = ("1b1:18000acbe:3:CALLIND", "1b1:18000acc9:3:CALLIND")
FIRST_APPEND, FINAL_HEADER_LOAD = "1b1:18000acdc:3:CALLIND", "1b1:18000adc3:1:LOAD"
DIGESTS = {
    CONSTRUCTOR: "6dba5c6dcb8e0c0b9d529d769b6c539c5d27ff5ae94de58ecab08dbc6f0b338d",
    R005: "44a186e08425a98889a2ac0b5afad93f4b1a27db2521de5aa8f4f06afe20b29a",
}


@pytest.fixture(scope="module")
def original_constructor(core):
    assert core["units"][CONSTRUCTOR].scopes.function.observation_digest.hex() == DIGESTS[CONSTRUCTOR]
    # Match the independently rederived shipped model's OFF policy; keep
    # equality with its real summary, including the return-slot conditions.
    results = _core_results(core, pytest.MonkeyPatch(), tracking=True, frame=False)
    return results[CONSTRUCTOR], results


def _header_runs(summary):
    return [run for exit_ in summary.exits for run in exit_.runs
            if run.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE
            and any(writer in CTOR_WRITERS for writer in run.writers)]


def test_original_constructor_has_two_exact_eight_byte_zero_memory_runs(original_constructor):
    item, _ = original_constructor
    runs = _header_runs(item.summary)
    assert len(runs) == 2
    assert {writer for run in runs for writer in run.writers} == set(CTOR_WRITERS)
    assert {run.span.start for run in runs} == {1 << 64, (1 << 64) + 8}
    for run in runs:
        assert run.span.size == 8 and run.literal == ExactConstant(8, 0)
        assert not run.debts and not run.crossed
        for identifier in run.definitions:
            definition = item.normalized.memory_ssa.definitions[identifier]
            assert definition.kind is MemoryDefinitionKind.DATA_WRITE
            assert definition.operation_key in CTOR_WRITERS
            assert definition.span == run.span
    # The constructor returns its input address, not integer zero; lack of an
    # ordinary source must never manufacture a scalar literal for that address.
    returned = [run for exit_ in item.summary.exits for run in exit_.runs
                if run.span.object_id.kind is StorageObjectKind.REGISTER_FILE
                and run.span.start == 0 and run.span.size == 8]
    assert len(returned) == 1 and returned[0].literal is None


def test_original_constructor_template_literal_roundtrip_and_width_refusal(original_constructor):
    item, results = original_constructor
    template = export_summary(item, results)
    raw_runs = [run for exit_ in template["exits"] for run in exit_["runs"]
                if any(writer.endswith(key) for writer in run["writers"] for key in CTOR_WRITERS)]
    assert len(raw_runs) == 2
    assert all(run["literal"] == {"byte_size": 8, "unsigned": 0} for run in raw_runs)
    register = next(definition.span.object_id for definition in item.normalized.memory_ssa.definitions
                    if definition.span.object_id.kind is StorageObjectKind.REGISTER_FILE)
    restored, _ = instantiate(template, "actual-core-constructor-zero", register, 0x1B1)
    restored_runs = [run for exit_ in restored.exits for run in exit_.runs
                     if any(writer.endswith(key) for writer in run.writers for key in CTOR_WRITERS)]
    assert len(restored_runs) == 2
    assert all(run.literal == ExactConstant(8, 0) for run in restored_runs)
    wrong = deepcopy(template)
    changed = next(run for exit_ in wrong["exits"] for run in exit_["runs"] if run["literal"] is not None)
    changed["literal"] = {"byte_size": changed["span"]["size"] - 1, "unsigned": 0}
    with pytest.raises(TemplateError):
        instantiate(wrong, "actual-core-constructor-wrong-width", register, 0x1B1)


def test_current_derived_constructor_payload_keeps_the_original_zero_bits(original_constructor):
    # Read the shipped output of the normal derivation; never create a test-only replacement model.
    raw = json.loads((REPO / "models" / "derived" / "ue_core_win64_fstring.json").read_text())
    assert raw["source"]["sha256"] == CORE_SHA
    assert raw["source"]["engine"]["template_version"] == TEMPLATE_VERSION
    assert raw["source"]["engine"]["semantics_version"] == ENGINE_SEMANTICS_VERSION
    (entry,) = [entry for entry in raw["entries"] if entry["name"] == "??0FString@@QEAA@XZ"]
    runs = [run for exit_ in entry["summary"]["exits"] for run in exit_["runs"]
            if any(writer.endswith(key) for writer in run["writers"] for key in CTOR_WRITERS)]
    assert len(runs) == 2
    assert all(run["literal"] == {"byte_size": 8, "unsigned": 0} for run in runs)
    item, results = original_constructor
    assert entry["summary"] == export_summary(item, results)
    assert all(run.literal == ExactConstant(8, 0) for run in _header_runs(item.summary))


def test_original_trace_constructor_effects_and_each_header_byte_are_zero_before_append(trace, monkeypatch):
    assert trace["units"][R005].scopes.function.observation_digest.hex() == DIGESTS[R005]
    _, roots, results = _trace_run(trace, monkeypatch, True)
    item = results[R005]
    normalized, ssa = item.normalized, item.normalized.memory_ssa
    projector, _ = _projector(item)
    effects = dict(normalized.proven_call_effects)
    pointer_rows = dict(normalized.pointer_rows)
    headers = []
    for call in CTOR_CALLS:
        effect = effects[call]
        runs = [run for run in effect.memory_runs
                if run.write.anchor is not None and run.write.anchor.start == 8
                and run.write.displacement in (0, 8) and run.write.size == 8]
        assert len(runs) == 2
        assert all(run.literal == ExactConstant(8, 0) for run in runs)
        rows = {key for key, row in pointer_rows.items() if key.startswith(call + "~") and row == ("const", 8, 0)}
        definitions = [(identifier, definition) for identifier, definition in enumerate(ssa.definitions)
                       if definition.operation_key in rows
                       and definition.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE]
        assert len(definitions) == 2
        for identifier, definition in definitions:
            assert definition.span.size == 8
            full = projector._expression_for_definition(identifier, definition.span)
            assert full is not None and not full.atoms and full.displacement == 0 and full.byte_size == 8
            for offset in (0, 4):
                partial = ByteSpan(definition.span.object_id, definition.span.start + offset, 4)
                value = projector._expression_for_definition(identifier, partial)
                assert value is not None and not value.atoms and value.displacement == 0 and value.byte_size == 4
            for offset in range(8):
                byte = ByteSpan(definition.span.object_id, definition.span.start + offset, 1)
                value = projector._expression_for_definition(identifier, byte)
                assert value is not None and not value.atoms and value.displacement == 0 and value.byte_size == 1
            overrun = ByteSpan(definition.span.object_id, definition.span.start, 9)
            assert projector._expression_for_definition(identifier, overrun) is None
            headers.append((identifier, definition.span))
    assert len(headers) == 4
    stage = next(effect.operation_key for block in normalized.forward_inputs.effect_unit.blocks for effect in block.effects
                 if effect.operation_key.startswith(FIRST_APPEND + "~"))
    found, _ = probe(normalized, stage, tuple(span for _, span in headers))
    assert {span: identifier for identifier, span in headers} == found
    # AppendChar remains an unknown/clobbering effect in this bounded stage.
    assert effects[FIRST_APPEND].unknown_memory or not effects[FIRST_APPEND].preserves_memory
    assert roots[R005].effective_completeness.reachable_unresolved_reads > 0
    assert any(row.operation_key == FINAL_HEADER_LOAD for row in normalized.call_clobber_reads)
    final = [definition for definition in ssa.definitions if definition.operation_key == FINAL_HEADER_LOAD]
    assert final
    for definition in final:
        identifier = ssa.definitions.index(definition)
        value = projector._expression_for_definition(identifier, definition.span)
        assert value is None or value.atoms  # the old constructor zero must not erase AppendChar debt
