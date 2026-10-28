"""A model's frees audit cannot license whole-memory preservation.

The existing deterministic allocator oracle is used only as a p-code graph
oracle. Its free leaves old bytes readable and realloc moves/copies bytes;
neither behavior is a claim about a live libc or valid C use after free.
"""

from dataclasses import replace

import pytest

from synthetic import (
    R9, RAX, RBP, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder,
    add, const, copy, load, program_units, reg, slice_from, store, tmp,
)
from test_constant_summary_values import REGISTERS
from test_definition_atoms import _grown_buffer
from test_external_models import MODELS, THUNKS, _check, _image
from tdo_v2.call_summary_effects import derive_proven_call_effect
from tdo_v2.interprocedural import analyze_units
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.summary_store import Access, load_external_models, model_effect


@pytest.fixture(params=(("sparse", False), ("dense", False), ("sparse", True), ("dense", True)),
                ids=("sparse-default", "dense-default", "sparse-forward", "dense-forward"))
def mode(request, monkeypatch):
    engine, forward = request.param
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_FORWARD", "1" if forward else "0")


@pytest.fixture(scope="module")
def models():
    return load_external_models(MODELS, "x86:LE:64:default", "win64")


def _analyze(builder, models):
    return analyze_units(program_units(builder), image_info=_image(), external_models=models)


def _key(builder, ordinal, opcode):
    return f"1:{builder._address(len(builder._rows)):x}:{ordinal}:{opcode}"


def _free_case(kind="direct", *, post_store=None):
    slot = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x48).ins(copy(reg(RCX), const(16))).call(THUNKS["malloc"])
               .ins(copy(reg(RBX), reg(RAX))))
    initial = _key(builder, 0, "STORE")
    builder.ins(store(reg(RBX), reg(RSI)))
    pointer = reg(RBX)
    if kind == "copy":
        builder.ins(copy(reg(RBP), reg(RBX)))
        pointer = reg(RBP)
    elif kind == "spill":
        builder.ins(add(slot, reg(RSP), const(0x20)), store(slot, reg(RBX)))
    if kind == "one-path":
        builder.cbranch("after-free", reg(RDI, 1))
    free = None
    if kind != "no-free":
        builder.ins(copy(reg(RCX), reg(RDI) if kind == "unknown-pointer" else reg(RBX)))
        free = _key(builder, 2, "CALL")
        builder.call(THUNKS["free"])
    if kind == "one-path":
        builder.label("after-free")
    if kind == "spill":
        builder.ins(add(slot, reg(RSP), const(0x20)), load(reg(RBP), slot))
        pointer = reg(RBP)
    writer = None
    if post_store is not None:
        # The oracle reuses the freed address, but the analysis need not make
        # any whole-object lifetime/extent claim to honor this exact write.
        builder.ins(copy(reg(RCX), const(16))).call(THUNKS["malloc"])
        pointer = reg(RAX)
        writer = _key(builder, 0, "STORE")
        builder.ins(store(pointer, reg(RDI, post_store)))
    reader = _key(builder, 0, "LOAD")
    builder.ins(load(reg(R9), pointer)).add_rsp(0x48).ret()
    return builder, dict(initial=initial, free=free, reader=reader, writer=writer)


def _view(item, key):
    return slice_from(item.normalized, item.normalized.dependencies.node_for_key("op:" + key))


def _assert_fence_debt(item, reader, call):
    view = _view(item, reader)
    assert not view.is_complete
    normalized = item.normalized
    from tdo_v2.call_clobber import debt_pairs

    assert any(crossing == call and node in view.result.reachable_nodes
               and any(span.object_id.kind.value in ("address_space", "function_relative") for span in row.spans)
               for row, crossing, node in debt_pairs(normalized.call_clobber_reads, normalized.call_clobber_debts))
    return view


def _oracle(results):
    report = _check(results, seeds=range(8), pools=lambda seed: {
        RSP: 0x70000000, RSI: 0x1234567890ABCD00 + seed, RDI: seed & 1,
    })
    assert report.runs == 8 and report.checked and not report.unsupported
    assert not report.silent, report.silent[:3]


@pytest.mark.parametrize("kind", ("direct", "copy", "spill", "one-path", "unknown-pointer"))
def test_free_keeps_the_exact_call_as_reachable_memory_debt(mode, models, kind):
    builder, points = _free_case(kind)
    results = _analyze(builder, models)
    item = results["1:1000"]
    effect = item.proven[points["free"]]
    assert not effect.preserves_memory and not effect.memory_runs
    assert effect.memory_runs_final  # no listed writes does NOT preserve every byte
    assert item.declared[points["free"]] == "external-model:crt-win64/free@v8"
    assert "registered-handlers-are-not-observed" in item.inherited_assumptions
    view = _assert_fence_debt(item, points["reader"], points["free"])
    assert set(range(RSI, RSI + 8)) <= view.register_bytes
    _oracle(results)


def test_no_free_control_keeps_the_original_exact_definition(mode, models):
    builder, points = _free_case("no-free")
    results = _analyze(builder, models)
    item = results["1:1000"]
    assert _view(item, points["reader"]).is_complete
    assert not any(row.operation_key == points["reader"] for row in item.normalized.call_clobber_reads)
    _oracle(results)


def test_realloc_keeps_its_same_object_contract_but_not_all_old_bytes(mode, models):
    results = _analyze(_grown_buffer(), models)
    item = results["1:1000"]
    (call,) = [call for call, label in item.declared.items() if "/realloc@" in label]
    effect = item.proven[call]
    assert not effect.preserves_memory and effect.same_object_registers
    assert item.declared[call] == "external-model:crt-win64/realloc@v8"
    assert "registered-handlers-are-not-observed" in item.inherited_assumptions
    (reader,) = [f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:LOAD"
                 for row in item.unit.observation.instructions for ordinal, operation in enumerate(row.operations)
                 if operation.opcode == "LOAD" and operation.output is not None
                 and operation.output.coordinate.byte_offset == R9]
    view = _assert_fence_debt(item, reader, call)
    assert set(range(RSI, RSI + 8)) <= view.register_bytes
    _oracle(results)


@pytest.mark.parametrize("width", (4, 8))
def test_only_exact_post_free_written_bytes_kill_old_call_debt(mode, models, width):
    builder, points = _free_case(post_store=width)
    results = _analyze(builder, models)
    item = results["1:1000"]
    ssa = item.normalized.memory_ssa
    (read,) = [row for row in ssa.reads if ssa.actions[row.action_id].operation_key == points["reader"]
               and row.span.object_id.kind.value in ("address_space", "function_relative")]
    assert read.span.size == 8
    definitions = [ssa.definitions[identifier] for fragment in read.fragments for identifier in fragment.definition_ids]
    assert any(row.kind is MemoryDefinitionKind.DATA_WRITE and row.operation_key == points["writer"]
               and row.span.size == width for row in definitions)
    if width == 8:
        assert _view(item, points["reader"]).is_complete
        assert not any(row.operation_key == points["reader"] for row in item.normalized.call_clobber_reads)
    else:
        _assert_fence_debt(item, points["reader"], points["free"])
    _oracle(results)


def test_free_cannot_borrow_a_private_frame_exemption_without_memory_runs(mode, models):
    address = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x48)
               .ins(add(address, reg(RSP), const(0x20)), store(address, reg(RSI)))
               .ins(copy(reg(RCX), const(0))))
    call = _key(builder, 2, "CALL")
    builder.call(THUNKS["free"])
    reader = _key(builder, 1, "LOAD")
    builder.ins(add(address, reg(RSP), const(0x20)), load(reg(R9), address)).add_rsp(0x48).ret()
    results = _analyze(builder, models)
    item = results["1:1000"]
    assert not item.proven[call].preserves_memory and not item.proven[call].memory_runs
    _assert_fence_debt(item, reader, call)
    _oracle(results)


def test_declared_final_memory_run_remains_exact_not_a_blanket_lifetime_claim(models):
    """Static custom-contract check only: this declared extra write is NOT
    an assertion about the existing free oracle's implementation."""
    (file,) = [file for file in models.files if file.file_id == "crt-win64"]
    (free,) = [entry for entry in file.entries if entry.name == "free"]
    custom = replace(free, memory=((Access((RDX, 8), 0, 8), ((RSI, 8),), ()),))

    def derive(summary, anchors):
        return derive_proven_call_effect(summary, custom.label, REGISTERS, 0x300, anchors=anchors)

    effect = model_effect(derive, file, custom, REGISTERS, 0x300, REG, 1, {})
    assert custom.frees == free.frees and custom.label == free.label
    assert not effect.preserves_memory and effect.memory_runs_final
    (run,) = effect.memory_runs
    assert run.write.anchor.start == RDX and run.write.size == 8
    assert any(span.start == RSI and span.size == 8 for span in run.reads)
