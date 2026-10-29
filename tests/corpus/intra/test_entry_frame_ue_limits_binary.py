"""Original UE frame-independent models and independent-base limits.

Uses TDO_UE_CORE_BUNDLE, TDO_UE_TRACE_BUNDLE, TDO_UE_STACK_EVIDENCE.
The current models are genuinely rederived OFF, not stripped of assumptions.
A genuinely derived ON control still refuses six calls when consumed OFF.
"""

import json

import pytest

from test_callee_preserved_low_binary import (
    APPEND, CONSTRUCTOR, DESTRUCTOR, R002, R005, REPO, _projector, core, image_ranges, run_dfbench, trace,
)
from derive_models import derive_library
from tdo_v2 import summary_engine
from tdo_v2._scope_contracts import VarnodeKindCode
from tdo_v2.forward import forward_facts, probe
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.interprocedural import analyze_units
from tdo_v2.relative_memory import ImageBaseTracking, definition_constants
from tdo_v2.span_geometry import ByteSpan, StorageObjectKind
from tdo_v2.summary_store import load_model_file, validated_models
from tdo_v2.summary_templates import build_file, image_provenance


FRAME = "entry-values-do-not-address-the-new-frame"
HOME = "win64-home-space-callee-private"
HELPER = "1b1:180bca600"
PAIR_DIGESTS = {
    CONSTRUCTOR: "6dba5c6dcb8e0c0b9d529d769b6c539c5d27ff5ae94de58ecab08dbc6f0b338d",
    HELPER: "c3f7fcb655ac3f451a8a2b260035df63b1fa30e305f38146412351bdef36ce2b",
}
PAIRS = (
    (CONSTRUCTOR, "1b1:180037a82:1:STORE", "1b1:180037a8c:0:LOAD", 8, 0, 32, 0),
    (CONSTRUCTOR, "1b1:180037a85:2:STORE", "1b1:180037a8c:0:LOAD", 8, 8, 32, 0),
    (HELPER, "1b1:180bca613:2:STORE", "1b1:180bca618:0:LOAD", 32, -24, 128, 0),
)
DERIVED_CALLS = {
    "1b1:18000acbe:3:CALLIND": "??0FString@@QEAA@XZ",
    "1b1:18000acc9:3:CALLIND": "??0FString@@QEAA@XZ",
    "1b1:18000acdc:3:CALLIND": "?AppendChar@FString@@QEAAAEAV1@_W@Z",
    "1b1:18000acef:3:CALLIND": "?AppendChar@FString@@QEAAAEAV1@_W@Z",
    "1b1:18000ae03:3:CALLIND": "??1FString@@QEAA@XZ",
    "1b1:18000ae0e:3:CALLIND": "??1FString@@QEAA@XZ",
}


def _trace_analysis(trace, enabled, models, *, forward=True):
    captured, provenance = {}, {}
    analyze = summary_engine.analyze_units

    def capture(*args, **options):
        results = analyze(*args, **options)
        captured.update(results)
        provenance.update(options.get("record_provenance") or {})
        return results

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("TDO_V2_FORWARD", "1" if forward else "0")
        patch.setattr(summary_engine, "analyze_units", capture)
        engine_run = summary_engine.analyze_observed_with_summaries(
            trace["scope"], trace["evidences"], image_info=trace["info"], readonly_image=trace["image"],
            boundary_provider=run_dfbench.boundary_provider(False, "win64"), external_models=models,
            pcodeop_models=run_dfbench.pcodeop_models(), stack_evidence=(trace["stack"],),
            assume_globals_disjoint_from_stack=True, assume_entry_values_not_frame=enabled,
            assume_opaque_callees_leave_no_stack_addresses=True,
            assume_direction_flag_clear=True, assume_import_slots_hold_exports=True,
            assume_win64_home_space_private=True, assume_debug_break_traps_do_not_return=True,
            operation_records=True, origin_witnesses=True)
    assert not engine_run.failed_functions
    roots = {f"{root.function_space_id:x}:{root.function_byte_offset:x}": root for root in engine_run.roots}
    assert roots.keys() == {R002, R005}
    return dict(trace=captured, roots=roots, engine_run=engine_run, provenance=provenance)


@pytest.fixture(scope="module")
def ue_entry_frames(core, trace):
    space = core["scope"].evidence.image_base.space_id
    relocates = image_provenance(lambda address, size: core["image"].value(space, address, size),
                                [(offset, size) for sid, offset, size in core["info"].relocations if sid == space],
                                language_id="x86:LE:64:default")
    found = {}
    for enabled in (True, False):
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv("TDO_V2_FORWARD", "1")
            with ImageBaseTracking(image_ranges(core["info"], space), relocates) as base_dependent:
                core_results = analyze_units(
                    list(core["units"].values()), image_info=core["info"], external_models=core["models"],
                    pcodeop_models=run_dfbench.pcodeop_models(), private_frame_above=40,
                    assume_globals_disjoint_from_stack=True, assume_entry_values_not_frame=enabled,
                    assume_opaque_callees_leave_no_stack_addresses=True,
                    assume_debug_break_traps_do_not_return=True, own_library="UNREALEDITOR-CORE.DLL",
                    keep_uncut=frozenset((APPEND, CONSTRUCTOR, DESTRUCTOR)))
        found[enabled] = dict(core=core_results, core_base_dependent=frozenset(base_dependent),
                              **_trace_analysis(trace, enabled, trace["models"]))
    return found


@pytest.fixture(scope="module")
def genuine_on_control(core, trace, tmp_path_factory):
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("TDO_V2_FORWARD", "1")
        raw, refused, missing = derive_library(
            core["generation"], "UNREALEDITOR-CORE.DLL", sorted(set(DERIVED_CALLS.values())),
            file_id="actual-core-frame-on-control", version=1, models=core["models"],
            pcodeops=run_dfbench.pcodeop_models(), stack_evidence=(core["stack"].path,),
            entry_values_not_frame=True, per_export=False, log=lambda _: None)
    assert not refused and not missing and len(raw["entries"]) == 3
    assert {FRAME, HOME} <= set(raw["source"]["assumptions"])
    path = tmp_path_factory.mktemp("ue-frame-on-control") / "model.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    model = load_model_file(path)  # strict production import, no labels removed
    models = validated_models(tuple(item for item in trace["models"].files
                                    if item.file_id != "ue-core-win64-derived") + (model,))
    return raw, _trace_analysis(trace, False, models)


@pytest.mark.parametrize("function,writer,reader,write_base,write_offset,read_base,read_offset", PAIRS)
def test_original_three_pairs_keep_independent_entry_bases_and_off_alias_debt(
        ue_entry_frames, function, writer, reader, write_base, write_offset, read_base, read_offset):
    claims = []
    for enabled in (True, False):
        item = ue_entry_frames[enabled]["core"][function]
        assert item.unit.scopes.function.observation_digest.hex() == PAIR_DIGESTS[function]
        projector, operations = _projector(item)
        store, load = operations[writer], operations[reader]
        assert store.opcode == "STORE" and load.opcode == "LOAD"
        assert store.inputs[2].byte_size == load.output.byte_size == 8
        if function == CONSTRUCTOR:
            written = projector._expression_for_input(writer, store.inputs[2])
            assert written is not None and written.byte_size == 8
            assert not written.atoms and written.displacement == 0
        # These originals use the same RAM selector ID at different storage
        # widths. Accepting that selector does not equate independent bases.
        assert store.inputs[0].kind is load.inputs[0].kind is VarnodeKindCode.CONSTANT
        assert store.inputs[0].coordinate.byte_offset == load.inputs[0].coordinate.byte_offset == 0x1B1
        assert (store.inputs[0].byte_size, load.inputs[0].byte_size) == (
            (4, 8) if function == CONSTRUCTOR else (4, 4))
        addresses = [projector._expression_for_input(key, operations[key].inputs[1]) for key in (writer, reader)]
        assert all(value is not None and value.byte_size == 8 and value.image == 0 for value in addresses)
        assert addresses[0].displacement == write_offset and addresses[1].displacement == read_offset
        assert all(len(value.atoms) == 1 and value.atoms[0][1] == 1 for value in addresses)
        assert addresses[0].atoms != addresses[1].atoms
        facts = {(fact.operation, fact.input): fact for fact in forward_facts(item.normalized, item.unit)}
        subjects = (facts[writer, 1], facts[reader, 1])
        for fact, base, offset in zip(subjects, (write_base, read_base), (write_offset, read_offset)):
            ((origin, interval),) = fact.claim.items
            assert origin == ("entry", base, 8)
            assert interval.lo == interval.hi == offset
            if not enabled:
                assert FRAME not in fact.requires and HOME not in fact.requires
        claims.append(tuple(fact.claim for fact in subjects))
        rows = [(row, node) for row, node in zip(item.normalized.may_alias_reads, item.normalized.may_alias_nodes)
                if row.operation_key == reader and writer in row.writers]
        if enabled:
            assert not rows
        else:
            assert rows
            graph = item.normalized.dependencies
            for row, node in rows:
                assert writer in row.plain and writer not in row.uncertain and not row.unknown_address
                assert graph.node(node).kind is NodeKind.MEMORY_DEBT
                assert graph.node_for_key(f"op:{writer}") in graph.predecessors(node)
                assert node in graph.predecessors(graph.node_for_key(f"op:{reader}"))
            assert not any(proof.read == reader and proof.writer == writer
                           for proof in item.normalized.forward_memory_proofs)
    assert claims[0] == claims[1]


def test_original_r002_has_no_new_frame_on_off_precision_gain(ue_entry_frames):
    items = []
    for enabled in (True, False):
        state = ue_entry_frames[enabled]
        root, item = state["roots"][R002], state["trace"][R002]
        assert root.reached_origin_labels == ("dfb_source_A.ret", "dfb_source_B.ret")
        # frees-bearing Realloc now retains lifetime call debt in both
        # policies; switching frame privacy still supplies no new proof.
        assert root.effective_completeness.reachable_unresolved_reads == 33 and not root.is_effectively_complete
        assert not item.refused_models
        items.append(item)
    assert items[0].declared == items[1].declared
    assert items[0].normalized.may_alias_reads == items[1].normalized.may_alias_reads


def test_current_frame_independent_models_are_accepted_in_both_trace_policies(ue_entry_frames, trace):
    for enabled in (True, False):
        state = ue_entry_frames[enabled]
        item = state["trace"][R005]
        assert len(item.proven) == 10 and not item.refused_models
        for call, name in DERIVED_CALLS.items():
            assert f"derived-model:ue-core-win64-derived/{name}@" in item.declared[call]
            assert call in item.proven
            (source,) = [model for model in trace["models"].files if model.file_id == "ue-core-win64-derived"]
            assert FRAME not in source.source_field("assumptions") and HOME not in source.source_field("assumptions")
        root = state["roots"][R005]
        assert root.reached_origin_labels == () and not root.is_effectively_complete
        assert root.effective_completeness.reachable_unresolved_reads == 15
        if not enabled:
            assert FRAME not in state["engine_run"].assumptions and HOME not in state["engine_run"].assumptions
            assert FRAME not in item.inherited_assumptions and HOME not in item.inherited_assumptions


def test_genuine_on_control_still_refuses_six_calls_off_not_a_precision_gain(genuine_on_control):
    raw, state = genuine_on_control
    item = state["trace"][R005]
    assert len(item.proven) == 4
    for call, name in DERIVED_CALLS.items():
        assert call not in item.proven and call not in item.declared
        reason = item.refused_models[call]
        assert name in reason and FRAME in reason and HOME in reason and "switched off" in reason
    assert not any(label.startswith("derived-model:") for label in item.declared.values())
    root = state["roots"][R005]
    assert root.reached_origin_labels == () and not root.is_effectively_complete
    assert root.effective_completeness.reachable_unresolved_reads == 7
    assert {FRAME, HOME} <= set(raw["source"]["assumptions"])
    assert FRAME not in state["engine_run"].assumptions and HOME not in state["engine_run"].assumptions


def _assert_original_ctor_zero_bytes_and_return_conditions(state):
    item = state["trace"][R005]
    normalized = item.normalized
    projector = _projector(item)[0] if normalized.forward_inputs is not None else None
    provenance = state["provenance"][id(item)][1]
    headers = []
    for call in ("1b1:18000acbe:3:CALLIND", "1b1:18000acc9:3:CALLIND"):
        effect = item.proven[call]
        (ordinal, returned), = [(ordinal, run) for ordinal, run in enumerate(effect.runs)
                                if any(span.start == 648 and span.size == 8 for span in run.writes)]
        # The original RETURN LOAD's two independent-base conditions are
        # transported AND actually discharged by the existing caller path.
        assert len(returned.conditions) == 2
        assert {(read.anchor.start, read.displacement, read.size,
                 write.anchor.start, write.displacement, write.size)
                for read, write in returned.conditions} == {(32, 0, 8, 8, 0, 8), (32, 0, 8, 8, 8, 8)}
        assert provenance.final[call, f"cr{ordinal}"] == ("ok", "ok")
        assert not provenance.failed.get(call) and not provenance.rejections.get(call)
        assert len(effect.memory_runs) == 2
        assert {(run.write.displacement, run.write.size, run.literal.byte_size, run.literal.unsigned)
                for run in effect.memory_runs} == {(0, 8, 8, 0), (8, 8, 8, 0)}
        definitions = [(identifier, definition) for identifier, definition
                       in enumerate(normalized.memory_ssa.definitions)
                       if definition.operation_key and definition.operation_key.startswith(call + "~")
                       and definition.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE
                       and definition.span.size == 8]
        assert len(definitions) == 2
        for identifier, definition in definitions:
            # These are exact original writer-definition byte slices, not
            # invented Num/Max LOAD instructions in the caller.
            for offset, width in ((0, 8), (0, 4), (4, 4)):
                span = ByteSpan(definition.span.object_id, definition.span.start + offset, width)
                if projector is not None:
                    value = projector._expression_for_definition(identifier, span)
                    assert value is not None and value.byte_size == width
                    assert not value.atoms and value.displacement == 0
                else:
                    literal = definition_constants(normalized, item.unit.observation, {(identifier, span)})[
                        identifier, span]
                    assert literal.byte_size == width and literal.unsigned == 0
            headers.append((identifier, definition.span))
    assert len(headers) == 4 and sum(span.size for _, span in headers) == 32
    assert {span.start - (1 << 64) for _, span in headers} == {-72, -64, -32, -24}
    if normalized.forward_inputs is not None:
        stage = next(effect.operation_key for block in normalized.forward_inputs.effect_unit.blocks
                     for effect in block.effects if effect.operation_key.startswith("1b1:18000acdc:3:CALLIND~"))
        reached, requires = probe(normalized, stage, tuple(span for _, span in headers))
        assert all(reached[span] == identifier for identifier, span in headers)
        assert FRAME not in requires and HOME not in requires
    else:
        # Forward OFF retains no stage probe. The new lifetime-limited
        # Append summary no longer exports the old exact Num4 LOAD at all;
        # do not invent it to retain the former stage-read assertion. The
        # four original ctor definitions and exact subwidth bits were all
        # independently checked above. ON tests also check the stage probe.
        assert not any(normalized.memory_ssa.actions[read.action_id].operation_key ==
                       "1b1:18000acdc:3:CALLIND~ld0"
                       and read.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE
                       for read in normalized.memory_ssa.reads)
        assert not item.proven["1b1:18000acdc:3:CALLIND"].preserves_memory
    for read in ("1b1:18000adc3:1:LOAD", "1b1:18000adf4:0:LOAD"):
        (clobbered,) = [row for row in normalized.call_clobber_reads if row.operation_key == read]
        assert set(clobbered.intervening_calls) == {"1b1:18000acdc:3:CALLIND", "1b1:18000acef:3:CALLIND"}


@pytest.mark.parametrize("enabled", (True, False))
def test_original_ctor_zero_bytes_and_return_conditions_reach_real_callers(ue_entry_frames, enabled):
    _assert_original_ctor_zero_bytes_and_return_conditions(ue_entry_frames[enabled])


def test_frame_off_current_models_do_not_require_runtime_forward_refinement(trace):
    state = _trace_analysis(trace, False, trace["models"], forward=False)
    item = state["trace"][R005]
    assert len(item.proven) == 10 and not item.refused_models
    for call, name in DERIVED_CALLS.items():
        assert call in item.proven and f"derived-model:ue-core-win64-derived/{name}@" in item.declared[call]
    assert state["roots"][R005].effective_completeness.reachable_unresolved_reads == 15
    assert state["roots"][R005].reached_origin_labels == ()
    assert state["roots"][R002].effective_completeness.reachable_unresolved_reads == 33
    assert state["roots"][R002].reached_origin_labels == ("dfb_source_A.ret", "dfb_source_B.ret")
    assert FRAME not in state["engine_run"].assumptions and HOME not in state["engine_run"].assumptions
    _assert_original_ctor_zero_bytes_and_return_conditions(state)


def test_current_ctor_template_retains_both_original_return_alias_conditions(ue_entry_frames, core):
    raw = json.loads((REPO / "models" / "derived" / "ue_core_win64_fstring.json").read_text())
    assert FRAME not in raw["source"]["assumptions"] and HOME not in raw["source"]["assumptions"]
    assert len(raw["source"]["assumptions"]) == 14   # (+ the three allocator row labels, docs 25.74)
    assert raw["source"]["parameters"]["private_frame_above"] == 0
    assert set(DERIVED_CALLS.values()) <= {entry["name"] for entry in raw["entries"]}
    (ctor,) = [entry["summary"] for entry in raw["entries"] if entry["name"] == "??0FString@@QEAA@XZ"]
    stored = [run for exit_ in ctor["exits"] for run in exit_["runs"]
              if any(writer.endswith(("1b1:180037a82:1:STORE", "1b1:180037a85:2:STORE"))
                     for writer in run["writers"])]
    assert len(stored) == 2
    assert {run["span"]["start"] - (1 << 64) for run in stored} == {0, 8}
    assert all(run["span"]["size"] == 8 and run["literal"] == {"byte_size": 8, "unsigned": 0}
               for run in stored)
    (returned,) = [run for exit_ in ctor["exits"] for run in exit_["runs"]
                   if run["span"] == {"object": "registers", "start": 648, "size": 8}]
    assert len(returned["conditions"]) == 2
    relations = set()
    for read, write in returned["conditions"]:
        assert read["size"] == write["size"] == 8
        relations.add((ctor["objects"][read["object"]]["anchor"]["start"], read["start"] - (1 << 64),
                       ctor["objects"][write["object"]]["anchor"]["start"], write["start"] - (1 << 64)))
    assert relations == {(32, 0, 8, 0), (32, 0, 8, 8)}
    state = ue_entry_frames[False]
    derived, refused = build_file(
        state["core"], ((CONSTRUCTOR, "??0FString@@QEAA@XZ", ("??0FString@@QEAA@XZ",)),),
        file_id="actual-core-off-frame-limit", version=1, library="UNREALEDITOR-CORE.DLL",
        external_models=core["models"], pcodeop_models=run_dfbench.pcodeop_models(),
        private_frame_above=40, base_dependent=state["core_base_dependent"], traps=True)
    assert not refused and len(derived["entries"]) == 1
    assert derived["entries"][0]["summary"] == ctor
    assert FRAME not in derived["source"]["assumptions"] and HOME not in derived["source"]["assumptions"]
    assert not state["core"][CONSTRUCTOR].inherited_assumptions
    assert derived["source"]["sha256"] == raw["source"]["sha256"]
