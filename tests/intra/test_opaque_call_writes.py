"""Exact-place writes of unknown value (``ProvenCallEffect.unknown_memory``):
a model row ``{"write": ..., "value": "unknown"}`` -- or a callee summary
whose anchored memory ends with a value it cannot state -- writes exactly
those bytes with an "opaque_call_write" debt; the rest of memory is kept as
the model or summary says."""

import json
from pathlib import Path

import pytest

from synthetic import (
    CODE_BASE, DATA_BASE, R8, R9, RBX, RCX, RDX, RSI, RSP, FunctionBuilder, add, const, copy, load,
    operation_node_at, program_units, reg, slice_from, store, tmp,
)
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import ModelError, load_external_models, load_model_file

THUNK = CODE_BASE + 0xF00
WIN64 = ("x86:LE:64:default", "win64")


def _file(tmp_path, memory, other_memory="preserved"):
    entry = {"name": "fill", "registers": [{"write": [0, 8], "from": [[8, 8]]}], "memory": memory,
             "other_memory": other_memory, "observes": [[8, 8]]}
    raw = {"format_version": 1, "kind": "declared", "id": "opaque-test", "version": 1,
           "language_id": WIN64[0], "abi_tag": WIN64[1], "stack_pointer": [32, 8], "stack_delta": 8,
           "preserved": [[24, 8], [40, 8], [48, 8], [56, 8]], "entries": [entry]}
    path = Path(tmp_path) / "opaque.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


UNKNOWN_12 = [{"write": {"base": [8, 8], "disp": 0, "size": 12}, "value": "unknown"}]


def _analyze(tmp_path, *functions, memory=UNKNOWN_12):
    """With globals-disjoint-from-stack: the global reload then shows only
    what the call itself does."""
    info = ImageInfo("synthetic", (), (ImportedSymbol("TEST", "fill", None, (), ((1, THUNK),)),), (), ())
    models = load_external_models([_file(tmp_path, memory)], *WIN64)
    return analyze_units(program_units(*functions), image_info=info, external_models=models,
                         assume_globals_disjoint_from_stack=True)


def _caller(callee=THUNK, argument=None):
    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x48)
               .ins(store(const(DATA_BASE + 0x40), reg(RBX)))                               # global
               .ins(add(t, reg(RSP), const(0x30)), store(t, reg(RSI))))                     # stack local
    builder = builder.ins(argument or add(reg(RCX), reg(RSP), const(0x10)))                 # rcx = rsp+0x10
    return (builder.call(callee)                                                            # instruction 4
            .ins(load(reg(R9), const(DATA_BASE + 0x40)))                                    # 5
            .ins(add(t, reg(RSP), const(0x30)), load(reg(R8), t))                           # 6
            .ins(add(t, reg(RSP), const(0x10)), load(reg(RDX), t))                          # 7: written
            .add_rsp(0x48).ret())


def _reloads(function):
    return [slice_from(function, operation_node_at(function, index, ordinal))
            for index, ordinal in ((5, 0), (6, 1), (7, 1))]


def _opaque(function, reload):
    return any(function.dependencies.node(node).label == "opaque_call_write"
               for node in reload.result.reachable_unresolved_read_nodes)


def test_a_model_writing_an_unknown_value_keeps_the_rest_of_memory(tmp_path):
    function = _analyze(tmp_path, _caller())["1:1000"].normalized
    global_, local, written = _reloads(function)
    assert global_.is_complete and set(range(RBX, RBX + 8)) <= global_.register_bytes
    assert local.is_complete and set(range(RSI, RSI + 8)) <= local.register_bytes
    assert not written.is_complete and _opaque(function, written)
    assert len(function.opaque_nodes) == 1


def test_a_summary_passes_unknown_memory_on(tmp_path):
    """wrapper: call fill -- its summary's memory at rcx has the debt; the
    caller of the wrapper gets the same exact place, the rest kept."""
    wrapper = CODE_BASE + 0xA00
    results = _analyze(tmp_path, _caller(wrapper),
                       FunctionBuilder(entry=wrapper).sub_rsp(0x28).call(THUNK).add_rsp(0x28).ret())
    (effect,) = [effect for _, effect in results["1:1000"].normalized.proven_call_effects]
    assert effect.preserves_memory and len(effect.unknown_memory) == 1
    assert effect.unknown_memory[0].size == 12
    function = results["1:1000"].normalized
    global_, local, written = _reloads(function)
    assert global_.is_complete and local.is_complete
    assert not written.is_complete and _opaque(function, written)


def test_an_unknown_value_at_an_address_the_caller_cannot_locate_keeps_nothing(tmp_path):
    """rcx = an entry pointer loaded from [rdx]: the write may land on the
    global or the local -- neither reload is complete."""
    function = _analyze(tmp_path, _caller(argument=load(reg(RCX), reg(RDX))))["1:1000"].normalized
    global_, local, _ = _reloads(function)
    assert not global_.is_complete


def test_an_unknown_variable_extent_keeps_no_memory(tmp_path):
    memory = [{"write": {"base": [8, 8], "disp": 0, "size": {"reg": [16, 8]}}, "value": "unknown"}]
    function = _analyze(tmp_path, _caller(), memory=memory)["1:1000"].normalized
    global_, local, written = _reloads(function)
    assert not global_.is_complete and not local.is_complete and not written.is_complete


@pytest.mark.parametrize("row", [
    {"write": {"base": [8, 8], "disp": 0, "size": 4}, "value": "unknown", "from": [[16, 8]]},
    {"write": {"base": [8, 8], "disp": 0, "size": 4}, "value": "zero"},
    {"write": {"base": [8, 8], "disp": 0, "size": 4}, "extra": 1},
])
def test_malformed_unknown_rows_are_rejected(tmp_path, row):
    with pytest.raises(ModelError, match="memory rows"):
        load_model_file(_file(tmp_path, [row]))


def _global_overlap(callee_body):
    callee = CODE_BASE + 0xB00
    caller = (FunctionBuilder().sub_rsp(0x28)
              .ins(copy(reg(RDX), const(DATA_BASE + 0x40)))
              .call(callee)
              .ins(load(reg(R9), const(DATA_BASE + 0x40)))                                  # instruction 3
              .add_rsp(0x28).ret())
    results = analyze_units(program_units(caller, callee_body(FunctionBuilder(entry=callee)).ret()))
    function = results["1:1000"].normalized
    return slice_from(function, operation_node_at(function, 3, 0))


@pytest.mark.parametrize("order", ["global-last", "pointer-last"])
def test_an_anchored_write_landing_on_a_global_the_call_writes_stays_unresolved(order):
    """callee: [rdx] = rsi and G = rbx, in either order; the caller passes
    rdx = &G. The summary's rows say nothing about which write came last,
    so the reload of G is not complete (Fable, step-A review)."""
    def body(builder):
        pointer, global_ = store(reg(RDX), reg(RSI)), store(const(DATA_BASE + 0x40), reg(RBX))
        first, last = (pointer, global_) if order == "global-last" else (global_, pointer)
        return builder.ins(first).ins(last)
    reload = _global_overlap(body)
    assert not reload.is_complete


def test_a_store_through_an_opaque_value_is_an_uncertain_writer(tmp_path):
    """rdi = the 8 opaque bytes; [rdi] = rsi: the store may land on the
    global -- its reload is not complete."""
    from synthetic import RDI

    t = tmp(0x100)
    caller = (FunctionBuilder().sub_rsp(0x48)
              .ins(store(const(DATA_BASE + 0x40), reg(RBX)))
              .ins(add(reg(RCX), reg(RSP), const(0x10)))
              .call(THUNK)
              .ins(add(t, reg(RSP), const(0x10)), load(reg(RDI), t))
              .ins(store(reg(RDI), reg(RSI)))
              .ins(load(reg(R9), const(DATA_BASE + 0x40)))                                  # instruction 6
              .add_rsp(0x48).ret())
    function = _analyze(tmp_path, caller)["1:1000"].normalized
    assert not slice_from(function, operation_node_at(function, 6, 0)).is_complete


def test_a_tail_jump_to_the_model_passes_unknown_memory_on(tmp_path):
    """thunk: jmp [__imp_fill] -- composed like a tail call; its summary's
    unknown memory reaches the caller at the same place (Fable, step-A review)."""
    from synthetic import _Instruction, op, ram

    slot, thunk = DATA_BASE + 0x800, CODE_BASE + 0xA00
    jump = FunctionBuilder(entry=thunk)
    jump._rows.append(_Instruction([op("BRANCHIND", [ram(slot)])], "return"))
    raw_json = jump.to_json

    def as_ghidra():  # Ghidra: a computed jump, not terminal, no fallthrough
        raw = raw_json()
        last = raw["instructions"][-1]
        last["flow_type"] = {key: key in ("is_flow", "is_jump", "is_computed", "is_unconditional")
                             for key in last["flow_type"]}
        return raw

    jump.to_json = as_ghidra
    info = ImageInfo("synthetic", (), (ImportedSymbol("TEST", "fill", None, ((1, slot),), ()),), (), ())
    models = load_external_models([_file(tmp_path, UNKNOWN_12)], *WIN64)
    results = analyze_units(program_units(_caller(thunk), jump), image_info=info, external_models=models,
                            assume_globals_disjoint_from_stack=True)
    assert results[f"1:{thunk:x}"].declared and not results[f"1:{thunk:x}"].summary.tail_exits
    (effect,) = [effect for _, effect in results["1:1000"].normalized.proven_call_effects]
    assert len(effect.unknown_memory) == 1
    function = results["1:1000"].normalized
    global_, local, written = _reloads(function)
    assert global_.is_complete and local.is_complete
    assert not written.is_complete and _opaque(function, written)


def test_the_unknown_write_address_is_the_one_at_the_call(tmp_path):
    """wrapper: call fill (writes [rcx]); rcx = rdx. Its summary's unknown
    memory is at the entry rcx: the caller locates it with rcx at the call,
    not after the wrapper's rcx output (Astra, step-A review)."""
    wrapper = CODE_BASE + 0xA00
    body = (FunctionBuilder(entry=wrapper).sub_rsp(0x28).call(THUNK)
            .ins(copy(reg(RCX), reg(RDX))).add_rsp(0x28).ret())
    caller = (FunctionBuilder().sub_rsp(0x28)
              .ins(store(const(DATA_BASE + 0x40), reg(RBX)))
              .ins(copy(reg(RCX), const(DATA_BASE + 0x40)))
              .ins(copy(reg(RDX), const(DATA_BASE + 0x80)))
              .call(wrapper)
              .ins(load(reg(R9), const(DATA_BASE + 0x40)))                                  # instruction 5
              .ins(load(reg(R8), const(DATA_BASE + 0x80)))                                  # 6
              .add_rsp(0x28).ret())
    function = _analyze(tmp_path, caller, body)["1:1000"].normalized
    written = slice_from(function, operation_node_at(function, 5, 0))
    assert not written.is_complete and _opaque(function, written)
    assert slice_from(function, operation_node_at(function, 6, 0)).is_complete


def test_the_root_explanation_lists_the_opaque_write(tmp_path):
    from tdo_v2.integration.configured_explanation_graph import root_local_explanation

    function = _analyze(tmp_path, _caller())["1:1000"].normalized
    root = operation_node_at(function, 7, 1)
    report = root_local_explanation(function, slice_from(function, root).result.reachable_nodes, (root,), 0)
    assert report["status"] == "partial"
    assert [gap["operation_key"] for gap in report["gaps"] if gap["kind"] == "opaque_call_write"] \
        == [f"{function.proven_call_effects[0][0]}~u0"]


def test_the_oracle_excuses_only_reads_wholly_of_unknown_memory(tmp_path):
    """program_oracle: a read taking only the call's unknown bytes is debt;
    one also taking other bytes ([rsp+0xc, +8): 4 bytes before the unknown
    write) keeps the usual checks (Astra, step-A round 2)."""
    from program_oracle import _all_opaque, _opaque_rows

    t = tmp(0x100)
    caller = (FunctionBuilder().sub_rsp(0x48)
              .ins(add(reg(RCX), reg(RSP), const(0x10)))
              .call(THUNK)
              .ins(add(t, reg(RSP), const(0x10)), load(reg(RDX), t))                         # 3: unknown only
              .ins(add(t, reg(RSP), const(0x0C)), load(reg(R8), t))                          # 4: straddles
              .add_rsp(0x48).ret())
    function = _analyze(tmp_path, caller)["1:1000"].normalized
    ((call, rows),) = _opaque_rows(function).items()
    graph = function.dependencies
    key = lambda index: graph.node(operation_node_at(function, index, 1)).key.removeprefix("op:")
    assert _all_opaque(graph, key(3), rows)
    assert not _all_opaque(graph, key(4), rows)
