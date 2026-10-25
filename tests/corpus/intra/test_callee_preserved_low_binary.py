"""Original UE calls preserve a full register and its exact low-byte input.

Set TDO_UE_CORE_BUNDLE, TDO_UE_TRACE_BUNDLE and TDO_UE_STACK_EVIDENCE.
These checks analyze the admitted bodies with the current models; they do not
derive or save models and do not claim whole FString/TArray completion.
"""

from hashlib import sha256
from contextlib import nullcontext
import os
from pathlib import Path
import sys

import pytest

from tdo_v2 import summary_engine
from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from tdo_v2.image_info import ReadOnlyImage, load_image_info
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.interprocedural import analyze_units, function_key
from tdo_v2.normalize import NormalizedFunction
from tdo_v2.pcode_blocks import build_pcode_block_graph
from tdo_v2.relative_memory import (
    ImageBaseTracking, _Projector, _configured_projector, single_execution_blocks, single_execution_keys,
)
from tdo_v2.span_geometry import ByteSpan
from tdo_v2.stack_evidence import assumption_allowed, load_stack_evidence
from tdo_v2.summary_templates import image_provenance


REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "tools" / "bundle_export"))
sys.path.insert(0, str(REPO / "tools" / "derive_models"))
import run_dfbench
from derive_models import image_ranges


APPEND, CONSTRUCTOR, DESTRUCTOR = "1b1:1800f4fd0", "1b1:180037a80", "1b1:18003bc00"
PRESERVED = "1b1:1800f5019:2:CALL~2"
INDEX = "1b1:1800f5073:0:INT_SEXT"
R005, R002 = "1b1:18000acb0", "1b1:180005ed0"
CORE_SHA = "fdea959764879bb55602c88a80a1adf6307b637c0c04f4b01f2e28c2fcb7b942"
TRACE_SHA = "440c863ed5ce6bdbca892b51dadec20fa601a64cfb150b60740fc51df6608c6a"


def _load(environment):
    location, stack = os.environ.get(environment), os.environ.get("TDO_UE_STACK_EVIDENCE")
    if not location or not stack:
        pytest.skip(f"set {environment} and TDO_UE_STACK_EVIDENCE to the original UE evidence")
    generation = Path(location)
    binding = NamingBindingExpectation(sha256((REPO / "ghidra" / "GhidraV2CallNaming.java").read_bytes()).digest(),
                                       CALL_NAMING_GHIDRA_VERSION)
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        scope = session.program_result
        evidences = list(session.iter_functions())
    units = {function_key(row.unit.scopes.function.entry): row.unit for row in evidences}
    info = load_image_info(generation)
    assert info is not None
    return dict(generation=generation, scope=scope, evidences=evidences, units=units, info=info,
                image=ReadOnlyImage(generation, info), stack=load_stack_evidence(stack))


@pytest.fixture(scope="module")
def core():
    result = _load("TDO_UE_CORE_BUNDLE")
    assert result["scope"].evidence.executable_sha256.hex() == CORE_SHA
    assert {APPEND, CONSTRUCTOR, DESTRUCTOR} <= result["units"].keys()
    assert len(result["units"]) == 11
    allowed, _ = assumption_allowed((result["stack"],), requested=True, require_for=CORE_SHA)
    assert allowed
    result["models"] = run_dfbench.external_models(result["generation"])
    return result


@pytest.fixture(scope="module")
def trace():
    result = _load("TDO_UE_TRACE_BUNDLE")
    assert result["scope"].evidence.executable_sha256.hex() == TRACE_SHA
    assert {R005, R002} <= result["units"].keys()
    assert len(result["units"]) == 13
    result["models"] = run_dfbench.external_models(result["generation"], (REPO / "models" / "derived",))
    return result


def _projector(item):
    normalized = item.normalized
    assert isinstance(normalized, NormalizedFunction)
    inputs, observation = normalized.forward_inputs, item.unit.observation
    operations = {f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:{operation.opcode}": operation
                  for row in observation.instructions for ordinal, operation in enumerate(row.operations)}
    graph = build_pcode_block_graph(observation, item.unit.scopes.function.entry)
    projector = _configured_projector(
        inputs.effect_unit, observation, inputs.context, inputs.address_spaces, normalized.memory_ssa,
        operations, item.unit.scopes.program.evidence.translation_namespace.language_id,
        once_keys=single_execution_keys(observation, graph), once_blocks=single_execution_blocks(observation, graph),
        fresh_keys=normalized.fresh_rows, same_object={key: (reader, argument)
                                                     for key, reader, argument in normalized.same_object_rows},
        pointer_rows=dict(normalized.pointer_rows))
    return projector, operations


def _core_run(core, monkeypatch, enabled, *, tracking=False):
    space = core["scope"].evidence.image_base.space_id
    relocates = image_provenance(lambda address, size: core["image"].value(space, address, size),
                                [(offset, size) for sid, offset, size in core["info"].relocations if sid == space])
    with monkeypatch.context() as patch:
        patch.setenv("TDO_V2_FORWARD", "1")
        if not enabled:
            patch.setattr(_Projector, "_preserved_register_low", lambda *_: None)
        context = ImageBaseTracking(image_ranges(core["info"], space), relocates) if tracking else nullcontext()
        with context:
            results = analyze_units(
                list(core["units"].values()), image_info=core["info"], external_models=core["models"],
                pcodeop_models=run_dfbench.pcodeop_models(), private_frame_above=40,
                assume_globals_disjoint_from_stack=True, assume_debug_break_traps_do_not_return=True,
                own_library="UNREALEDITOR-CORE.DLL", keep_uncut=frozenset((APPEND, CONSTRUCTOR, DESTRUCTOR)))
            item = results[APPEND]
            projector, operations = _projector(item)
            ssa = item.normalized.memory_ssa
            (row,) = [(identifier, definition) for identifier, definition in enumerate(ssa.definitions)
                      if definition.operation_key == PRESERVED]
            identifier, definition = row
            low_span = ByteSpan(definition.span.object_id, definition.span.start, 4)
            full = projector._expression_for_definition(identifier, definition.span)
            low = projector._expression_for_definition(identifier, low_span)
            index = projector._expression_for_input(INDEX, operations[INDEX].inputs[0])
            pointer = dict(item.normalized.pointer_rows)[PRESERVED]
            argument = projector._resolved_span(pointer[2])
            source_low = ByteSpan(argument.object_id, argument.start, 4)
            (source_fragment,) = [fragment for read in ssa.reads
                                  if ssa.actions[read.action_id].operation_key == pointer[1]
                                  and read.span.contains(source_low) for fragment in read.fragments
                                  if fragment.span.contains(source_low)]
            (source_definition,) = source_fragment.definition_ids
            low_input = projector._expression_for_definition(source_definition, source_low)
            full_input = projector._expression_for_input(pointer[1], pointer[2])
            return dict(results=results, item=item, definition=definition, low_span=low_span, full=full, low=low,
                        index=index, boundaries=dict(projector._boundary),
                        pointer=pointer, low_input=low_input, full_input=full_input)


def test_original_core_call_low_four_bytes_recover_the_original_index_expression(core, monkeypatch):
    before = _core_run(core, monkeypatch, False)
    after = _core_run(core, monkeypatch, True)
    assert before["full"] is not None and after["full"] == before["full"]
    assert before["low"] is None and before["index"] is None
    assert before["full_input"] is None and before["low_input"] is not None
    assert after["low"] is not None and after["low"].byte_size == 4
    assert after["index"] is not None and after["index"].byte_size == 4
    assert after["definition"].span.size == 8 and after["low_span"].size == 4
    assert after["pointer"][0] == "reg" and not after["pointer"][3]
    assert after["low"].atoms
    assert after["low_input"] is not None and after["low"] == after["low_input"]
    print("UE Core AppendChar: full8 preserved; CALL~2 low4 None -> original low-byte input; index None -> expression")


def test_original_core_model_derivation_keeps_the_prior_conservative_projection(core, monkeypatch):
    before = _core_run(core, monkeypatch, False, tracking=True)
    after = _core_run(core, monkeypatch, True, tracking=True)
    assert before["full"] is not None and after["full"] == before["full"]
    assert before["low"] is None and after["low"] is None
    assert before["index"] is None and after["index"] is None
    for key in (APPEND, CONSTRUCTOR, DESTRUCTOR):
        assert before["results"][key].summary == after["results"][key].summary
    print("UE Core image-base tracking: original full8/low4/index results and all three export summaries preserved")


def _trace_run(trace, monkeypatch, enabled):
    captured = {}
    analyze = summary_engine.analyze_units

    def capture(*args, **options):
        results = analyze(*args, **options)
        captured.update(results)
        return results

    with monkeypatch.context() as patch:
        patch.setenv("TDO_V2_FORWARD", "1")
        patch.setattr(summary_engine, "analyze_units", capture)
        if not enabled:
            patch.setattr(_Projector, "_preserved_register_low", lambda *_: None)
        run = summary_engine.analyze_observed_with_summaries(
            trace["scope"], trace["evidences"], image_info=trace["info"], readonly_image=trace["image"],
            boundary_provider=run_dfbench.boundary_provider(False, "win64"), external_models=trace["models"],
            pcodeop_models=run_dfbench.pcodeop_models(), stack_evidence=(trace["stack"],),
            operation_records=True, origin_witnesses=True)
    assert not run.failed_functions
    roots = {f"{root.function_space_id:x}:{root.function_byte_offset:x}": root for root in run.roots}
    assert roots.keys() == {R005, R002}
    return run, roots, captured


def test_original_trace_roots_keep_current_models_and_report_the_remaining_debt(trace, monkeypatch):
    before, old_roots, _ = _trace_run(trace, monkeypatch, False)
    after, roots, _ = _trace_run(trace, monkeypatch, True)
    assert before.assumptions == after.assumptions
    assert any("AppendChar" in label for label in after.assumptions)
    for key in (R005, R002):
        old, new = old_roots[key], roots[key]
        print("UE Trace", key, "origins", old.reached_origin_labels, "->", new.reached_origin_labels,
              "debts", old.effective_completeness.reachable_unresolved_reads, "->",
              new.effective_completeness.reachable_unresolved_reads)
        assert new.reached_origin_labels == old.reached_origin_labels
        assert new.effective_completeness == old.effective_completeness
