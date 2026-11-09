"""Import identities use finished SSA, not instruction adjacency or an ABI."""

import json
from pathlib import Path

import pytest

from synthetic import (CODE_BASE, DATA_BASE, R8, RAX, RBX, RCX, RDI, RDX, RSI, RSP, FunctionBuilder,
                       add, const, copy, load, op, program_units, ram, reg, slice_op, store, tmp)
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units, import_call_sites
from tdo_v2.summary_engine import run_assumptions
from tdo_v2.summary_store import load_external_models

SLOT, OTHER_SLOT, KEEP = DATA_BASE + 0x100, DATA_BASE + 0x108, CODE_BASE + 0x800
INFO = ImageInfo("synthetic", (), (
    ImportedSymbol("CRT", "strlen", None, ((1, SLOT),), ()),
    ImportedSymbol("CRT", "free", None, ((1, OTHER_SLOT),), ())), (), ())
MODELS = sorted((Path(__file__).resolve().parents[2] / "models" / "external").glob("*.json"))


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def engines(monkeypatch, request):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)


def _caller(*middle):
    return (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), ram(SLOT)))
            .ins(*middle).call(KEEP).call_indirect(RBX).add_rsp(0x28).ret())


def _analyze(monkeypatch, caller, callee=None, *, forward=True, imports=True, **options):
    monkeypatch.setenv("TDO_V2_FORWARD", "1" if forward else "0")
    units = program_units(caller, *((callee,) if callee is not None else ()))
    models = load_external_models(MODELS, "x86:LE:64:default", "win64")
    results = analyze_units(units, image_info=INFO, external_models=models,
                            assume_import_slots_hold_exports=imports,
                            assume_globals_disjoint_from_stack=True, **options)
    return results["1:1000"], results


@pytest.mark.parametrize("load_kind", ("copy", "load"))
def test_import_identity_survives_a_body_proven_preserving_call(monkeypatch, load_kind):
    caller = _caller(copy(reg(RCX), const(DATA_BASE + 0x200)))
    if load_kind == "load":
        caller._rows[1].ops = [load(reg(RBX), const(SLOT))]
    item, results = _analyze(monkeypatch, caller, FunctionBuilder(entry=KEEP).ret())
    assert import_call_sites(item.unit, INFO) == {}  # the static scan stays narrow
    call = next(key for key in item.declared if key.endswith(":CALLIND"))
    assert item.declared[call] == "external-model:crt-win64/strlen@v8"
    assert call in item.proven
    assert "import-slots-hold-their-exports" in run_assumptions(results)
    assert ("import-slots-hold-their-exports", "resolution", call) in item.normalized.premise_uses


@pytest.mark.parametrize("forward,imports", ((False, True), (True, False)))
def test_switches_do_not_silently_enable_ssa_import_resolution(monkeypatch, forward, imports):
    item, _ = _analyze(monkeypatch, _caller(), FunctionBuilder(entry=KEEP).ret(),
                       forward=forward, imports=imports)
    assert not item.declared


@pytest.mark.parametrize("kind", ("opaque", "partial", "whole", "computed"))
def test_missing_or_nonidentity_preservation_cannot_bind_the_old_import(monkeypatch, kind):
    callee = None if kind == "opaque" else FunctionBuilder(entry=KEEP)
    if kind == "partial":
        callee.ins(copy(reg(RBX, 1), reg(RDX, 1)))
    elif kind == "whole":
        callee.ins(copy(reg(RBX), reg(RDX)))
    elif kind == "computed":
        callee.ins(add(reg(RBX), reg(RBX), const(1)))
    if callee is not None:
        callee.ret()
    item, _ = _analyze(monkeypatch, _caller(), callee)
    assert not item.declared


@pytest.mark.parametrize("middle", (
    (add(reg(RBX), reg(RBX), const(1)),),
    (copy(reg(RBX, 4), ram(SLOT, 4)),),
    (copy(reg(RBX), reg(RDX)),),
))
def test_changed_pointer_is_not_the_import(monkeypatch, middle):
    item, _ = _analyze(monkeypatch, _caller(*middle), FunctionBuilder(entry=KEEP).ret())
    assert not item.declared


def test_loaded_snapshot_is_distinct_from_a_later_slot_rewrite(monkeypatch):
    caller = _caller(store(const(SLOT), reg(RDX)))
    item, _ = _analyze(monkeypatch, caller, FunctionBuilder(entry=KEEP).ret())
    assert len(item.declared) == 1  # held old value is unchanged
    caller._rows[2].ops.append(copy(reg(RBX), ram(SLOT)))
    item, _ = _analyze(monkeypatch, caller, FunctionBuilder(entry=KEEP).ret())
    assert not item.declared  # a reload sees the actual rewrite


def test_overwritten_call_snapshot_cannot_resolve_an_earlier_copy(monkeypatch):
    caller = _caller()
    call_row = caller._rows[4]
    target = tmp(0x900)
    call_row.ops = [copy(target, reg(RBX)), copy(target, reg(RDX)), op("CALLIND", [target])]
    item, _ = _analyze(monkeypatch, caller, FunctionBuilder(entry=KEEP).ret())
    assert not item.declared


def test_overwrite_through_another_unique_space_cannot_resolve_the_copy(monkeypatch):
    # (review fix, Astra P1-1) the SSA keeps every UNIQUE-kind space in one function temporary object:
    # a write to the same bytes through a second UNIQUE space id overwrites the target
    import synthetic

    original = synthetic._Provider._program_candidate

    def two_unique_spaces(self):
        candidate = original(self)
        candidate["address_spaces"].append(synthetic._space(5, unique=True, bits=self.arch.address_bits))
        return candidate

    monkeypatch.setattr(synthetic._Provider, "_program_candidate", two_unique_spaces)
    caller = _caller()
    call_row = caller._rows[4]
    target, alias = tmp(0x400), dict(tmp(0x400), space_id=5)
    call_row.ops = [copy(target, reg(RBX)), copy(alias, const(0x1e00)), op("CALLIND", [target])]
    item, _ = _analyze(monkeypatch, caller, FunctionBuilder(entry=KEEP).ret())
    assert not item.declared


@pytest.mark.parametrize("other", (OTHER_SLOT, None))
def test_different_import_or_unknown_path_join_is_not_a_single_identity(monkeypatch, other):
    flag = tmp(0x600, 1)
    caller = (FunctionBuilder().sub_rsp(0x28)
              .cbranch("other", flag, op("INT_NOTEQUAL", [reg(RCX), const(0)], flag))
              .ins(copy(reg(RBX), ram(SLOT))).branch("join").label("other")
              .ins(copy(reg(RBX), ram(other) if other is not None else reg(RDX)))
              .label("join").call(KEEP).call_indirect(RBX).add_rsp(0x28).ret())
    item, _ = _analyze(monkeypatch, caller, FunctionBuilder(entry=KEEP).ret())
    assert not item.declared


def test_a_loop_cannot_use_its_own_import_model_to_prove_its_target(monkeypatch):
    flag = tmp(0x600, 1)
    caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), ram(OTHER_SLOT)))
              .label("loop").call_indirect(RBX)
              .cbranch("loop", flag, op("INT_NOTEQUAL", [reg(RCX), const(0)], flag))
              .add_rsp(0x28).ret())
    item, _ = _analyze(monkeypatch, caller)
    assert not item.declared


def test_a_new_import_binding_cannot_seed_another_from_its_own_effect(monkeypatch):
    caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RDI), ram(SLOT)))
              .ins(copy(reg(RBX), ram(OTHER_SLOT))).ins(copy(reg(RCX), const(0)))
              .call_indirect(RBX).call_indirect(RDI).add_rsp(0x28).ret())
    item, _ = _analyze(monkeypatch, caller)
    assert list(item.declared.values()) == ["external-model:crt-win64/free@v8"]
    # free's model now preserves RDI, but that second binding had no
    # independent round-1 target proof. It intentionally stays unresolved.
    assert len([key for key in item.proven if key.endswith(":CALLIND")]) == 1


def test_same_symbol_on_both_paths_is_one_identity(monkeypatch):
    flag = tmp(0x600, 1)
    caller = (FunctionBuilder().sub_rsp(0x28)
              .cbranch("other", flag, op("INT_NOTEQUAL", [reg(RCX), const(0)], flag))
              .ins(copy(reg(RBX), ram(SLOT))).branch("join").label("other")
              .ins(copy(reg(RBX), ram(SLOT)))
              .label("join").call(KEEP).call_indirect(RBX).add_rsp(0x28).ret())
    item, _ = _analyze(monkeypatch, caller, FunctionBuilder(entry=KEEP).ret())
    assert list(item.declared.values()) == ["external-model:crt-win64/strlen@v8"]


@pytest.mark.parametrize("off", (False, True))
def test_model_assumption_refusal_is_not_bypassed_by_ssa_binding(monkeypatch, off):
    info = ImageInfo("synthetic", (), (
        ImportedSymbol("CRT", "malloc", None, ((1, SLOT),), ()),), (), ())
    monkeypatch.setattr(__import__(__name__), "INFO", info)
    caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), ram(SLOT)))
              .ins(copy(reg(RCX), const(0))).call_indirect(RBX).add_rsp(0x28).ret())
    options = {"disabled_model_assumptions": ("allocator-results-are-fresh",)} if off else {}
    item, _ = _analyze(monkeypatch, caller, **options)
    assert bool(item.declared) is not off
    if off:
        assert any("switched off" in reason for reason in item.refused_models.values())


def test_import_effect_connects_source_memory_through_the_call_to_the_reload(monkeypatch):
    slot, source, destination = SLOT + 0x20, DATA_BASE + 0x200, DATA_BASE + 0x300
    info = ImageInfo("synthetic", (), (*INFO.imports,
        ImportedSymbol("CRT", "memcpy", None, ((1, slot),), ())), (), ())
    monkeypatch.setattr(__import__(__name__), "INFO", info)
    caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), ram(slot)))
              .ins(store(const(source), reg(RSI)))
              .ins(copy(reg(RCX), const(destination)), copy(reg(RDX), const(source)), copy(reg(R8), const(8)))
              .call(KEEP).call_indirect(RBX).ins(load(reg(RAX), const(destination))).add_rsp(0x28).ret())
    item, _ = _analyze(monkeypatch, caller, FunctionBuilder(entry=KEEP).ret())
    call, = item.declared
    assert item.declared[call] == "external-model:crt-win64/memcpy@v8"
    assert item.proven[call].memory_runs
    view = slice_op(item.normalized, "LOAD", 6)
    assert view.is_complete and set(range(RSI, RSI + 8)) <= view.register_bytes


def test_unresolved_callee_writer_condition_does_not_prove_register_preservation(monkeypatch):
    t = tmp(0x700)
    callee = (FunctionBuilder(entry=KEEP)
              .ins(load(reg(R8), reg(RSI))).ins(store(reg(R8), reg(RCX)))
              .ins(store(reg(RDI), reg(RDX))).ins(load(reg(R8), reg(RSI)))
              .ins(add(t, reg(R8), const(8)), store(t, reg(RCX))).ret())
    item, results = _analyze(monkeypatch, _caller(), callee)
    assert results[f"1:{KEEP:x}"].summary.writer_conditions
    assert not item.declared


@pytest.mark.parametrize("stale", (False, True))
def test_derived_target_model_still_passes_existing_template_admission(monkeypatch, tmp_path, stale):
    from test_summary_templates import LIBRARY, MANGLED, WIN64, _derive

    body = FunctionBuilder(entry=KEEP).ins(copy(reg(RAX), reg(RCX))).ret()
    path, refused, hand = _derive(tmp_path, body)
    assert not refused
    if stale:
        raw = json.loads(path.read_text())
        raw["source"]["engine"]["semantics_version"] -= 1
        path.write_text(json.dumps(raw))
    models = load_external_models([*MODELS, hand, path], *WIN64)
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    info = ImageInfo("synthetic", (), (ImportedSymbol(LIBRARY, "F", MANGLED, ((1, SLOT),), ()),), (), ())
    caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RBX), ram(SLOT)))
              .ins(copy(reg(RCX), reg(RSI))).call_indirect(RBX)
              .ins(copy(reg(RDX), reg(RAX))).add_rsp(0x28).ret())
    item = analyze_units(program_units(caller), image_info=info, external_models=models,
                         assume_import_slots_hold_exports=True,
                         assume_globals_disjoint_from_stack=True)["1:1000"]
    if stale:
        assert not item.declared and item.refused_models
    else:
        assert len(item.declared) == 1 and next(iter(item.declared.values())).startswith("derived-model:")
        assert "derived-model-runtime-matches" in run_assumptions({item.key: item})
        view = slice_op(item.normalized, "COPY", 4)
        assert view.is_complete and set(range(RSI, RSI + 8)) <= view.register_bytes


@pytest.mark.parametrize("already_used", (False, True))
def test_candidate_query_preserves_the_original_assumption_use_record(monkeypatch, already_used):
    from tdo_v2.relative_memory import IMPORT_SLOTS, ImportSlots, import_values

    item, _ = _analyze(monkeypatch, _caller(), FunctionBuilder(entry=KEEP).ret())
    instruction = item.unit.observation.instructions[4]
    request = (f"1:{instruction.address.byte_offset:x}:0:COPY", instruction.operations[0].inputs[0])
    scope = item.normalized.memory_ssa.function_scope
    slots = ImportSlots(INFO)
    slots.active = True
    if already_used:
        slots.used.add(scope)
    original = set(slots.used)
    token = IMPORT_SLOTS.set(slots)
    try:
        assert import_values(item.normalized, item.unit.observation, [request], INFO)[request].name == "strlen"
        assert slots.used == original
    finally:
        IMPORT_SLOTS.reset(token)


def test_failed_candidate_query_also_preserves_assumption_uses(monkeypatch):
    from tdo_v2 import relative_memory as memory

    item, _ = _analyze(monkeypatch, _caller(), FunctionBuilder(entry=KEEP).ret())
    instruction = item.unit.observation.instructions[4]
    request = (f"1:{instruction.address.byte_offset:x}:0:COPY", instruction.operations[0].inputs[0])
    scope = item.normalized.memory_ssa.function_scope
    slots = memory.ImportSlots(INFO)
    slots.active = True

    class Broken:
        def _expression_for_input(self, *args):
            slots.used.add(scope)
            raise RuntimeError("candidate query failed")

    monkeypatch.setattr(memory, "_final_projector", lambda *args: Broken())
    token = memory.IMPORT_SLOTS.set(slots)
    try:
        with pytest.raises(RuntimeError, match="candidate query failed"):
            memory.import_values(item.normalized, item.unit.observation, [request], INFO)
        assert not slots.used
    finally:
        memory.IMPORT_SLOTS.reset(token)
