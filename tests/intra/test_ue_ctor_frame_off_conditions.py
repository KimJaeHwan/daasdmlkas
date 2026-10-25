"""Consume the shipped UE ctor's return-slot conditions in synthetic callers.

These are deliberately adversarial synthetic importers, not new executions
or modifications of the UE binary. With frame privacy OFF, ctor writes at
entry RCX and RCX+8 cannot silently authorize a return-slot value when they
overlap it, or when their separation is not provable.
"""

from pathlib import Path

import pytest

from synthetic import (
    R9, RCX, RIP, RSP, FunctionBuilder, add, const, copy, operation_node_at,
    program_units, reg, slice_from,
)
from test_constant_summary_values import REGISTERS
from test_summary_templates import THUNK, WIN64, ImageInfo, ImportedSymbol, _effect
from tdo_v2 import interprocedural
from tdo_v2.function_summary import SummaryKind
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.pcodeop_models import load_pcodeop_models
from tdo_v2.summary_store import load_external_models, load_model_file
from tdo_v2.summary_templates import ENGINE_SEMANTICS_VERSION, instantiate, pcodeop_digest


REPO = Path(__file__).resolve().parents[2]
MODEL = REPO / "models" / "derived" / "ue_core_win64_fstring.json"
CTOR = "??0FString@@QEAA@XZ"
LIBRARY = "UNREALEDITOR-CORE.DLL"
FRAME = "entry-values-do-not-address-the-new-frame"
HOME = "win64-home-space-callee-private"
BIAS = 1 << 64


@pytest.fixture(scope="module")
def shipped():
    model = load_model_file(MODEL)  # strict engine/schema validation; no rewritten model
    assert all(entry.template is not None and entry.refusal is None for entry in model.entries)
    (constructor,) = [entry for entry in model.entries if entry.name == CTOR]
    paths = [REPO / "models" / "external" / "crt_win64.json",
             REPO / "models" / "external" / "ue_core_win64.json", MODEL]
    models = load_external_models(paths, *WIN64)
    pcodeops = load_pcodeop_models([REPO / "models" / "pcodeops" / "x86.json"])
    assert model.source_field("engine")["semantics_version"] == ENGINE_SEMANTICS_VERSION
    assert model.source_field("parameters") == {"private_frame_above": 0}
    assert model.source_field("pcodeops") == pcodeop_digest(pcodeops)
    assert not {FRAME, HOME} & set(model.source_field("assumptions"))
    assert not {FRAME, HOME} & set(constructor.inherited)
    # Apply the exact files recorded by the derivation, not substitutes with
    # the same names or a freshly weakened source.assumptions list.
    files = {file.file_id: file for file in models.files}
    assert all(files[row["file"]].digest == row["sha256"] for row in model.source_field("models"))
    return model, constructor, models, pcodeops


@pytest.mark.parametrize("memory_space", (1, 9))
def test_shipped_strict_template_keeps_both_original_return_conditions(shipped, memory_space):
    _, constructor, _, _ = shipped
    summary, anchors = instantiate(constructor.template, constructor.label, REGISTERS, memory_space)
    (returned,) = [run for exit_ in summary.exits for run in exit_.runs
                   if run.span.object_id == REGISTERS and run.span.start == RIP and run.span.size == 8]
    assert returned.kind is SummaryKind.COMPUTED and not returned.debts
    assert returned.writers == ("dll:1b1:180037a8c:0:LOAD",)
    assert len(returned.conditions) == 2
    located = set()
    for read, write in returned.conditions:
        read_anchor, read_space = anchors[read.object_id]
        write_anchor, write_space = anchors[write.object_id]
        assert read_space == write_space == memory_space
        assert read_anchor.object_id == write_anchor.object_id == REGISTERS
        located.add((read_anchor.start, read.start - BIAS, read.size,
                     write_anchor.start, write.start - BIAS, write.size))
    assert located == {(RSP, 0, 8, RCX, 0, 8), (RSP, 0, 8, RCX, 8, 8)}


@pytest.mark.parametrize("engine", ("sparse", "dense"))
@pytest.mark.parametrize("offset,expected", ((-8, ("fail", "ok")), (-15, ("fail", "fail")),
                                             (None, ("open", "open")), (0x30, ("ok", "ok"))),
                         ids=("first-write-overlaps-return", "partial-both-write-overlap",
                              "unbound-entry-rcx", "disjoint-frame-object"))
def test_shipped_ctor_return_claim_requires_actual_separation(shipped, monkeypatch, engine, offset, expected):
    model, _, models, pcodeops = shipped
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    builder = FunctionBuilder().sub_rsp(0x68)
    if offset is not None:
        builder.ins(add(reg(RCX), reg(RSP), const(offset & (BIAS - 1))))
    call = f"1:{builder._address(len(builder._rows)):x}:2:CALL"
    builder.call(THUNK)
    returned_at = len(builder._rows)
    # An explicit consumer of the model's RIP run makes a failed/open claim
    # observable as graph debt instead of checking a provenance label alone.
    builder.ins(copy(reg(R9), reg(RIP))).add_rsp(0x68).ret()
    info = ImageInfo("synthetic", (), (ImportedSymbol(LIBRARY, CTOR, CTOR, (), ((1, THUNK),)),), (), ())
    history, provenance = [], {}
    decide = interprocedural._decide_conditions

    def recorded(*args, **kwargs):
        verdicts = decide(*args, **kwargs)
        if (call, "cr4") in verdicts:
            history.append(tuple(value if value in ("ok", "fail") else "open"
                                 for value in verdicts[call, "cr4"]))
        return verdicts

    monkeypatch.setattr(interprocedural, "_decide_conditions", recorded)
    item = interprocedural.analyze_units(
        program_units(builder), image_info=info, external_models=models, pcodeop_models=pcodeops,
        assume_entry_values_not_frame=False, private_frame_above=0,
        assume_globals_disjoint_from_stack=True, assume_debug_break_traps_do_not_return=True,
        record_provenance=provenance)["1:1000"]
    assert not item.refused_models and call in item.declared
    assert item.declared[call].startswith("derived-model:ue-core-win64-derived/" + CTOR)
    assert "derived-model-runtime-matches" in item.inherited_assumptions
    assert set(model.source_field("assumptions")) <= item.inherited_assumptions
    assert not {FRAME, HOME} & item.inherited_assumptions
    assert not item.normalized.forward_inputs.entry_values_not_frame
    assert not item.normalized.assumes_entry_values_not_frame
    assert item.normalized.forward_inputs.private_frame_above == 0
    assert history and all(verdict == expected for verdict in history)

    saved_item, note = provenance[id(item)]
    assert saved_item is item
    effect = _effect(item)
    rip_runs = [run for run in effect.runs if any(span.start == RIP and span.size == 8 for span in run.writes)]
    view = slice_from(item.normalized, operation_node_at(item.normalized, returned_at, 0))
    debts = {item.normalized.dependencies.node(node).label for node in view.result.reachable_nodes
             if item.normalized.dependencies.node(node).kind is NodeKind.MEMORY_DEBT}
    if "fail" in expected:
        # Fixed-point derivation withdraws cr4, so final has no misleading
        # successful verdict; the failure remains in failed/rejections.
        assert not rip_runs and (call, "cr4") not in note.final
        assert len(note.failed[call]) == expected.count("fail")
        assert len(note.rejections[call]) == expected.count("fail")
        assert not view.is_complete and "call_clobber_read" in debts
    elif "open" in expected:
        assert len(rip_runs) == 1 and len(rip_runs[0].conditions) == 2
        assert len(note.opened[call]) == 2 and not note.failed
        assert all(value not in ("ok", "fail") for value in note.final[call, "cr4"])
        assert not view.is_complete and "open_condition" in debts
    else:
        assert len(rip_runs) == 1 and note.final[call, "cr4"] == ("ok", "ok")
        assert not note.failed and not note.opened and not note.rejections.get(call)
        assert view.is_complete and not debts
