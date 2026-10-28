"""Original UE register restoration retains allocator lifetime uncertainty.

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
from tdo_v2.function_summary import SummaryKind
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.normalize import NormalizedFunction
from tdo_v2.pcode_blocks import build_pcode_block_graph
from tdo_v2.relative_memory import (
    ImageBaseTracking, _Projector, _configured_projector, single_execution_blocks, single_execution_keys,
)
from tdo_v2.query import BackwardSliceQuery
from tdo_v2.stack_evidence import assumption_allowed, load_stack_evidence
from tdo_v2.summary_templates import image_provenance


REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "tools" / "bundle_export"))
sys.path.insert(0, str(REPO / "tools" / "derive_models"))
import run_dfbench
from derive_models import image_ranges


APPEND, CONSTRUCTOR, DESTRUCTOR = "1b1:1800f4fd0", "1b1:180037a80", "1b1:18003bc00"
GROW_CALL, GROW, REALLOC = "1b1:1800f5019:2:CALL", "1b1:18010b8d0", "1b1:18010b946:2:CALL"
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


def _core_results(core, monkeypatch, enabled=True, *, tracking=False, frame=True):
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
                pcodeop_models=run_dfbench.pcodeop_models(), private_frame_above=40 if frame else 0,
                assume_entry_values_not_frame=frame,
                assume_globals_disjoint_from_stack=True, assume_debug_break_traps_do_not_return=True,
                own_library="UNREALEDITOR-CORE.DLL", keep_uncut=frozenset((APPEND, CONSTRUCTOR, DESTRUCTOR)))
            return results


def _assert_current_rdi_lifetime_debt(results):
    """The old CALL~2 was RDI[0x38:8], not a stable staging ordinal.

    Realloc now fences memory, including the callee's saved-register slots.
    This withdraws the old whole-register copy premise; narrowing must not
    recreate it. An opaque input expression alone is not a debt-free value.
    """
    item = results[APPEND]
    normalized = item.normalized
    effect = dict(normalized.proven_call_effects)[GROW_CALL]
    assert not effect.preserves_memory
    assert not any(span.start <= 56 and span.end >= 64 for span in effect.preserved)
    assert not any(span.start < 64 and 56 < span.end for run in effect.runs for span in run.writes)
    assert not any(row[0] == "reg" and row[2].coordinate.byte_offset == 56
                   for key, row in normalized.pointer_rows if key.startswith(GROW_CALL + "~"))
    assert not any(definition.operation_key is not None
                   and definition.operation_key.startswith(GROW_CALL + "~")
                   and definition.span.object_id.kind.value == "register_file"
                   and definition.span.start < 64 and 56 < definition.span.end
                   for definition in normalized.memory_ssa.definitions)

    projector, operations = _projector(item)
    operation = operations[INDEX]
    assert operation.inputs[0].coordinate.byte_offset == 56 and operation.inputs[0].byte_size == 4
    assert operation.output.byte_size == 8
    graph = normalized.dependencies
    index_node = graph.node_for_key("op:" + INDEX)
    from tdo_v2.call_clobber import debt_pairs

    (row, node), = [(row, node) for row, call, node in debt_pairs(normalized.call_clobber_reads,
                                                                   normalized.call_clobber_debts)
                    if row.operation_key == INDEX and call == GROW_CALL]
    assert any(span.start == 56 and span.size == 4 for span in row.spans)
    assert graph.node(node).kind is NodeKind.MEMORY_DEBT
    assert graph.node(node).label == "call_clobber_read" and node in graph.predecessors(index_node)
    assert not BackwardSliceQuery().run(normalized, index_node).is_complete

    grow = results[GROW]
    assert "FMemory::Realloc@" in grow.declared[REALLOC]
    assert not grow.proven[REALLOC].preserves_memory
    for register, reader, writer in ((24, "1b1:18010b94e:1:LOAD", "1b1:18010b94e:2:COPY"),
                                     (56, "1b1:18010b957:1:LOAD", "1b1:18010b957:3:COPY")):
        (run,) = [run for exit_ in grow.summary.exits for run in exit_.runs
                  if run.span.object_id.kind.value == "register_file"
                  and run.span.start == register and run.span.size == 8]
        assert run.kind is SummaryKind.COMPUTED and "call_clobber_read" in run.debts
        assert writer in run.writers
        local = grow.normalized
        (read,) = [read for read in local.memory_ssa.reads
                   if local.memory_ssa.actions[read.action_id].operation_key == reader
                   and read.span.object_id.kind.value == "function_relative"]
        assert read.span.size == 8
        (debt, debt_node), = [(row, node) for row, call, node in debt_pairs(local.call_clobber_reads,
                                                                             local.call_clobber_debts)
                             if row.operation_key == reader and call == REALLOC]
        assert read.span in debt.spans
        assert local.dependencies.node(debt_node).kind is NodeKind.MEMORY_DEBT
        assert debt_node in local.dependencies.predecessors(local.dependencies.node_for_key("op:" + reader))
    # Opaque numeric atoms remain representable, but may not become new
    # entry-address relations while the original register read has call debt.
    writers = {"1b1:1800f5078:3:STORE", "1b1:1800f50d6:3:STORE"}
    assert writers <= set(item.summary.unknown_writers)
    objects, relations = dict(item.summary.writer_objects), dict(item.summary.address_relations)
    assert all(objects.get(writer) not in relations for writer in writers)
    return projector._expression_for_input(INDEX, operation.inputs[0])


def test_original_core_low_byte_feature_does_not_recreate_withdrawn_rdi_preservation(core, monkeypatch):
    before = _core_results(core, monkeypatch, False)
    after = _core_results(core, monkeypatch, True)
    assert _assert_current_rdi_lifetime_debt(before) == _assert_current_rdi_lifetime_debt(after)
    assert before[APPEND].normalized.memory_ssa == after[APPEND].normalized.memory_ssa


def test_original_core_model_derivation_keeps_the_same_named_lifetime_debt(core, monkeypatch):
    before = _core_results(core, monkeypatch, False, tracking=True)
    after = _core_results(core, monkeypatch, True, tracking=True)
    assert _assert_current_rdi_lifetime_debt(before) == _assert_current_rdi_lifetime_debt(after)
    for key in (APPEND, CONSTRUCTOR, DESTRUCTOR):
        assert before[key].summary == after[key].summary


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
