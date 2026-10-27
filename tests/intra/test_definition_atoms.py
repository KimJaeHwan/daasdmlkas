"""Definition atoms (``relative_memory``): a pointer a call returns or a LOAD
reads, defined once per activation, is a base of its own.

The program oracle runs the real code (including allocator behavior) and checks
the caller's graph: nothing is silently missed. A fresh/nonstack origin does
not prove the extent of an eight-byte access: spills, globals and reallocated
members therefore retain alias debt and their possible writers. Exact
same-address SSA definitions remain useful without object-wide disjointness.
The mutations distinguish a missing wild-object guard from a mere declared
origin label, which cannot grant separation authority.
"""

import pytest

import test_graph_fidelity as fidelity
import tdo_v2.normalize as normalize_module
import tdo_v2.relative_memory as relative_memory
from program_oracle import check_program
from synthetic import (
    CODE_BASE, R8, R9, RAX, RBP, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const, copy, load,
    operation_node_at, program_units, reg, slice_from, store, tmp,
)
from test_external_models import THUNKS, _analyze, _check
from tdo_v2.interprocedural import analyze_units
from tdo_v2.pcode_blocks import build_pcode_block_graph

LEAF = CODE_BASE + 0x800
HAVOC = (REG, RSP, 8)


def _heap_fields():
    """obj = malloc(16); obj->a = rsi; obj->b = rdi; r9 = obj->a."""
    t = tmp(0x100)
    return (FunctionBuilder().sub_rsp(0x28)
            .ins(copy(reg(RCX), const(16)))
            .call(THUNKS["malloc"])
            .ins(store(reg(RAX), reg(RSI)))
            .ins(add(t, reg(RAX), const(8)), store(t, reg(RDI)))
            .ins(load(reg(R9), reg(RAX)))
            .add_rsp(0x28).ret())


def _reload(function):
    """The slice of the final ``r9 = *obj`` (the last LOAD of the caller)."""
    rows = [row for row in function.effects if row.operation_key.endswith(":LOAD")]
    index = int(rows[-2].operation_key.split(":")[1], 16)  # before the ret's own LOAD
    instruction = (index - CODE_BASE) // 4
    return slice_from(function, operation_node_at(function, instruction, 0))


def test_heap_fields_are_exact():
    results = _analyze(_heap_fields())
    function = results["1:1000"].normalized
    reload = _reload(function)
    assert reload.is_complete
    assert set(range(RSI, RSI + 8)) <= reload.register_bytes
    assert not reload.register_bytes & set(range(RDI, RDI + 8))
    report = _check(results)
    assert report.runs and report.silent == []


def test_without_definition_atoms_the_heap_access_is_unknown(monkeypatch):
    monkeypatch.setattr(relative_memory, "DEFINITION_ATOMS", False)
    function = _analyze(_heap_fields())["1:1000"].normalized
    assert not _reload(function).is_complete


def test_two_allocations_merged_are_one_nonstack_value():
    """rax = cond ? malloc() : malloc(); *rax = rbp; r9 = *rax: the join of two
    new blocks in a block run once is one non-stack value (the same pointer
    both times), so the reload is exact."""
    builder = (FunctionBuilder().sub_rsp(0x28)
               .cbranch("other", reg(RSI, 1))
               .call(THUNKS["malloc"])
               .branch("join")
               .label("other").call(THUNKS["malloc"])
               .label("join").ins(store(reg(RAX), reg(RBP)))
               .ins(load(reg(R9), reg(RAX)))
               .add_rsp(0x28).ret())
    results = _analyze(builder)
    reload = _reload(results["1:1000"].normalized)
    assert reload.is_complete and set(range(RBP, RBP + 8)) <= reload.register_bytes
    assert _check(results).silent == []


def _frame_pointer_program():
    """leaf returns its entry stack pointer + 0x28 -- the caller's local at
    rsp+0x20; the caller stores through it and reloads the local."""
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RSP), const(0x28))).ret()
    t = tmp(0x100)
    caller = (FunctionBuilder().sub_rsp(0x40)
              .ins(add(t, reg(RSP), const(0x20)), store(t, reg(RBX)))
              .call(LEAF)
              .ins(store(reg(RAX), reg(RDX)))
              .ins(add(t, reg(RSP), const(0x20)), load(reg(R9), t))
              .add_rsp(0x40).ret())
    return caller, leaf


def _check_frame_pointer():
    caller, leaf = _frame_pointer_program()
    units = program_units(caller, leaf)
    results = analyze_units(units)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    analyzed = results["1:1000"]
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    return analyzed, check_program(analyzed.normalized, analyzed.unit.observation, program,
                                   seeds=range(4), register_pools=pools, havoc_calls=HAVOC)


def test_a_returned_pointer_into_the_private_frame_is_not_missed():
    analyzed, report = _check_frame_pointer()
    assert analyzed.proven  # the leaf is summarized: its rax becomes a definition atom
    assert report.runs and report.silent == []


def test_mutation_without_wild_objects_misses(monkeypatch):
    original = normalize_module.derive_may_alias_reads

    def no_wild(*args, **kwargs):
        # (the leaf's stack-derived result also makes its call an escape,
        # docs 25.27: off too, so the wild rule is the one left to miss)
        kwargs["wild_objects"] = frozenset()
        kwargs["escaping_calls"] = frozenset()
        return original(*args, **kwargs)

    monkeypatch.setattr(normalize_module, "derive_may_alias_reads", no_wild)
    _, report = _check_frame_pointer()
    assert report.silent


def _keys(builder):
    (unit,) = program_units(builder)
    graph = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
    return relative_memory.single_execution_keys(unit.observation, graph), unit.observation


def test_loop_blocks_are_not_single_execution():
    builder = (FunctionBuilder()
               .ins(copy(reg(RBX), const(0)))
               .label("loop").ins(load(reg(R9), reg(RDI)))
               .cbranch("loop", reg(RSI, 1))
               .ret())
    keys, observation = _keys(builder)
    loop_load = f"1:{CODE_BASE + 4:x}:0:LOAD"
    assert loop_load not in keys
    assert f"1:{CODE_BASE:x}:0:COPY" in keys


def test_an_unresolved_indirect_jump_disables_single_execution():
    from synthetic import _Instruction, op
    builder = FunctionBuilder().ins(load(reg(R9), reg(RDI)))
    builder._rows.append(_Instruction([op("BRANCHIND", [reg(RAX)])], "return"))
    keys, _ = _keys(builder)
    assert keys == frozenset()


def _spilled_heap_pointer():
    """Debug-build shape: obj = malloc(); spilled to [rsp+0x20] and reloaded
    for every use: obj->a = rsi; r9 = obj->a."""
    t = tmp(0x100)
    return (FunctionBuilder().sub_rsp(0x48)
            .ins(copy(reg(RCX), const(16)))
            .call(THUNKS["malloc"])
            .ins(add(t, reg(RSP), const(0x20)), store(t, reg(RAX)))
            .ins(add(t, reg(RSP), const(0x20)), load(reg(RDX), t))
            .ins(store(reg(RDX), reg(RSI)))
            .ins(add(t, reg(RSP), const(0x20)), load(reg(RCX), t))
            .ins(load(reg(R9), reg(RCX)))
            .add_rsp(0x48).ret())


def _assert_unbounded_access_debt(function, view, registers, writers):
    """Keep both alias uncertainty and original writer candidates, not just
    an incomplete flag after removing the old object-wide nonstack rule."""
    assert not view.is_complete
    assert any(function.dependencies.node(node).kind == "memory_debt"
               for node in view.result.reachable_nodes)
    for register in registers:
        assert set(range(register, register + 8)) <= view.register_bytes
    for writer in writers:
        assert function.dependencies.node_for_key("op:" + writer) in view.result.reachable_nodes


def _without_pre_escape(builder):
    """As ``_analyze`` with pre-escape-values-do-not-address-the-new-frame off."""
    from test_external_models import MODELS, _image
    from tdo_v2.summary_store import load_external_models

    return analyze_units(program_units(builder), image_info=_image(),
                         external_models=load_external_models(MODELS, "x86:LE:64:default", "win64"),
                         assume_pre_escape_values_not_frame=False)


def test_a_fresh_block_spilled_to_the_frame_keeps_extent_debt():
    """Fresh describes the returned base, not the range of its eight-byte
    store. Its possible alias with the pointer's home slot stays explicit
    (without pre-escape-values-do-not-address-the-new-frame)."""
    results = _without_pre_escape(_spilled_heap_pointer())
    function = results["1:1000"].normalized
    _assert_unbounded_access_debt(function, _reload(function), (RSI,),
                                 ("1:100c:1:STORE", "1:1014:0:STORE"))
    report = _check(results)
    assert report.runs == 6 and report.checked and not report.unsupported and report.silent == []


def test_without_fresh_the_spilled_pointer_stays_unsure(monkeypatch):
    import tdo_v2.summary_store as store_module
    original = store_module.load_model_file

    def without_fresh(path):
        model = original(path)
        from dataclasses import replace
        return replace(model, entries=tuple(replace(entry, fresh=()) for entry in model.entries))

    monkeypatch.setattr(store_module, "load_model_file", without_fresh)
    results = _without_pre_escape(_spilled_heap_pointer())
    assert not _reload(results["1:1000"].normalized).is_complete
    assert _check(results).silent == []


def test_a_spilled_heap_pointer_under_pre_escape_values():
    """With pre-escape-values-do-not-address-the-new-frame (default on) the
    malloc result -- no escape before it -- addresses no byte of the new
    frame: the reload of its home slot is exact; the label and the call are
    reported; nothing is silent (docs 25.77)."""
    results = _analyze(_spilled_heap_pointer())
    function = results["1:1000"].normalized
    assert _reload(function).is_complete
    assert function.assumes_pre_escape_values_not_frame and function.pre_escape_definitions
    assert _check(results).silent == []


def _grown_buffer():
    """DFB031: buf = malloc(16); buf[0] = rsi; buf[1] = rdi;
    buf = realloc(buf, 32); r9 = buf[0]."""
    t = tmp(0x100)
    return (FunctionBuilder().sub_rsp(0x28)
            .ins(copy(reg(RCX), const(16)))
            .call(THUNKS["malloc"])
            .ins(store(reg(RAX), reg(RSI)))
            .ins(add(t, reg(RAX), const(8)), store(t, reg(RDI)))
            .ins(copy(reg(RCX), reg(RAX)), copy(reg(RDX), const(32)))
            .call(THUNKS["realloc"])
            .ins(load(reg(R9), reg(RAX)))
            .add_rsp(0x28).ret())


def test_realloc_keeps_declared_object_relation_but_not_unproved_old_bytes():
    """realloc's result addresses the old block's object (the model's
    same_object_as, assuming the old pointer is not used afterwards): the
    oracle moves the block for real and every byte keeps its writer. The
    relation alone is not independent lifetime/whole-memory preservation."""
    results = _analyze(_grown_buffer())
    reload = _reload(results["1:1000"].normalized)
    assert not reload.is_complete
    normalized = results["1:1000"].normalized
    assert any(normalized.dependencies.node(node).label == "call_clobber_read"
               for node in reload.result.reachable_nodes)
    realloc = [effect for key, effect in results["1:1000"].proven.items()
               if effect.same_object_registers]
    assert len(realloc) == 1 and not realloc[0].preserves_memory
    assert set(range(RSI, RSI + 8)) <= reload.register_bytes
    assert not reload.register_bytes & set(range(RDI, RDI + 8))
    report = _check(results)
    assert report.runs and report.silent == []


def test_without_same_object_the_grown_buffer_is_unsure(monkeypatch):
    monkeypatch.setattr(normalize_module, "_same_object_rows", lambda *args: {})
    results = _analyze(_grown_buffer())
    assert not _reload(results["1:1000"].normalized).is_complete
    assert _check(results).silent == []


def _fresh_and_global(through_pointer):
    """obj = malloc(); *obj = rsi; then either a global write (*G = rdi) or
    G = obj; q = *rbx; *q = rdi -- rbx points to G at run time, so q is the
    block's address back through a pointer the engine cannot follow; r9 = *obj."""
    from synthetic import DATA_BASE
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(copy(reg(RCX), const(16)))
               .call(THUNKS["malloc"])
               .ins(store(reg(RAX), reg(RSI))))
    if through_pointer:
        builder.ins(store(const(DATA_BASE + 0x40), reg(RAX)))
        builder.ins(load(reg(RDX), reg(RBX)), store(reg(RDX), reg(RDI)))
    else:
        builder.ins(store(const(DATA_BASE + 0x40), reg(RDI)))
    return builder.ins(load(reg(R9), reg(RAX))).add_rsp(0x28).ret()


def _global_pools(seed):
    from synthetic import DATA_BASE
    return {**fidelity._register_inputs(seed), RSP: 0x7000_0000, RBX: DATA_BASE + 0x40}


def test_a_fresh_block_without_extent_keeps_the_global_writer():
    """An origin label alone cannot exclude the global write from an
    unbounded eight-byte heap demand, even when this execution is disjoint."""
    results = _analyze(_fresh_and_global(False))
    function = results["1:1000"].normalized
    _assert_unbounded_access_debt(function, _reload(function), (RSI, RDI),
                                 ("1:100c:0:STORE", "1:1010:0:STORE"))
    report = _check(results)
    assert report.runs == 6 and report.checked and not report.unsupported and report.silent == []


def test_a_loaded_pointer_may_reach_a_fresh_block():
    results = _analyze(_fresh_and_global(True))
    reload = _reload(results["1:1000"].normalized)
    assert not reload.is_complete
    assert _check(results, pools=_global_pools).silent == []


def test_mutation_fresh_disjoint_from_everything_misses(monkeypatch):
    """The fresh rule alone is load-bearing: with uncertain-address writers off
    (q's read has alias debt, so *q is one and would cover this mutation)."""
    import tdo_v2.function_summary as function_summary_module
    import tdo_v2.may_alias as may_alias_module
    original = may_alias_module._Policy.may_alias
    monkeypatch.setattr(function_summary_module, "uncertain_writers_of", lambda normalized, observation: {})

    def disjoint(self, left, right):
        if left in self.fresh_objects or right in self.fresh_objects:
            return False
        return original(self, left, right)

    monkeypatch.setattr(may_alias_module._Policy, "may_alias", disjoint)
    assert _check(_analyze(_fresh_and_global(True)), pools=_global_pools).silent


# -- (d) pointer values across calls -----------------------------------------------

HELPER = CODE_BASE + 0x800


def _grow_helper(points_into_frame=False):
    """TArray::ResizeGrow-like: this->Data = realloc(this->Data, 32) -- or,
    with ``points_into_frame``, this->Data = &this->Num (this + 8)."""
    builder = FunctionBuilder(entry=HELPER).sub_rsp(0x28).ins(copy(reg(RDI), reg(RCX)))
    if points_into_frame:
        builder.ins(add(reg(RAX), reg(RDI), const(8)))
    else:
        builder.ins(load(reg(RCX), reg(RDI))).ins(copy(reg(RDX), const(32))).call(THUNKS["realloc"])
    return builder.ins(store(reg(RDI), reg(RAX))).add_rsp(0x28).ret()


def _array_caller(preallocated=False):
    """Arr at [rsp+0x20]: Data, Num (= rbx). grow(&Arr); Data = Arr.Data;
    *Data = rsi; r9 = Arr.Num; r8 = Data[1] (written before the call when
    ``preallocated``: Data = malloc(16), Data[1] = rbp)."""
    t = tmp(0x100)
    builder = FunctionBuilder().sub_rsp(0x48)
    if preallocated:
        builder.ins(copy(reg(RCX), const(16))).call(THUNKS["malloc"])
        builder.ins(add(t, reg(RAX), const(8)), store(t, reg(RBP)))
        builder.ins(add(t, reg(RSP), const(0x20)), store(t, reg(RAX)))
    else:
        builder.ins(add(t, reg(RSP), const(0x20)), store(t, const(0)))
    return (builder
            .ins(add(t, reg(RSP), const(0x28)), store(t, reg(RBX)))
            .ins(add(reg(RCX), reg(RSP), const(0x20)))
            .call(HELPER)
            .ins(add(t, reg(RSP), const(0x20)), load(reg(RAX), t))
            .ins(store(reg(RAX), reg(RSI)))
            .ins(add(t, reg(RSP), const(0x28)), load(reg(R9), t))
            .ins(add(t, reg(RAX), const(8)), load(reg(R8), t))
            .add_rsp(0x48).ret())


def _program_check(caller, helper):
    from test_external_models import MODELS, _image
    from tdo_v2.summary_store import load_external_models

    units = program_units(caller, helper)
    results = analyze_units(units, image_info=_image(),
                            external_models=load_external_models(MODELS, "x86:LE:64:default", "win64"))
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    analyzed = results["1:1000"]
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    report = check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=range(6),
                           register_pools=pools, havoc_calls=HAVOC,
                           externals={(1, address): name for name, address in THUNKS.items()})
    return results, report


def _load_slice(function, nth_from_end):
    rows = [row.operation_key for row in function.effects if row.operation_key.endswith(":LOAD")
            and "~" not in row.operation_key]
    address = int(rows[-1 - nth_from_end].split(":")[1], 16)   # rows[-1] is the ret's own LOAD
    return slice_from(function, operation_node_at(function, (address - CODE_BASE) // 4, 1))


def test_a_reallocated_member_origin_does_not_bound_its_access():
    """The same-object/null-is-fresh descriptor remains, but supplies no
    extent certificate excluding the Data write from the frame's Num slot."""
    results, report = _program_check(_array_caller(), _grow_helper())
    from tdo_v2.span_geometry import StorageObjectKind
    (run,) = [run for exit_summary in results[f"1:{HELPER:x}"].summary.exits for run in exit_summary.runs
              if run.value is not None and run.span.object_id.kind is not StorageObjectKind.REGISTER_FILE
              and run.value[0] == "same" and run.value[2]]   # realloc of this->Data, null is fresh
    function = results["1:1000"].normalized
    _assert_unbounded_access_debt(function, _load_slice(function, 2), (RBX, RSI),
                                 ("1:1008:1:STORE", "1:1018:0:STORE"))
    assert report.runs == 6 and report.checked and not report.unsupported and report.silent == []


def test_a_reallocated_member_keeps_content_candidates_and_extent_debt():
    """Do not demand an exact pointer after uncertain frame aliases. Retain
    the original heap contents and frame writers alongside the alias debt."""
    results, report = _program_check(_array_caller(preallocated=True), _grow_helper())
    function = results["1:1000"].normalized
    _assert_unbounded_access_debt(function, _load_slice(function, 1), (RBP, RBX),
                                 ("1:100c:1:STORE", "1:1014:1:STORE"))
    _assert_unbounded_access_debt(function, _load_slice(function, 2), (RBX, RSI),
                                 ("1:1014:1:STORE", "1:1024:0:STORE"))
    assert report.runs == 6 and report.checked and not report.unsupported and report.silent == []


def test_a_member_pointing_into_the_frame_gets_no_value():
    results, report = _program_check(_array_caller(), _grow_helper(points_into_frame=True))
    from tdo_v2.span_geometry import StorageObjectKind
    # this->Data = this + 8: a computed address, no pointer value
    assert not [run for exit_summary in results[f"1:{HELPER:x}"].summary.exits for run in exit_summary.runs
                if run.value is not None and run.span.object_id.kind is not StorageObjectKind.REGISTER_FILE
                and any(writer.endswith(":STORE") for writer in run.writers)]
    assert not _load_slice(results["1:1000"].normalized, 2).is_complete
    assert report.silent == []


def test_mutation_frame_pointer_tagged_nonstack_cannot_hide_frame_writers(monkeypatch):
    """A forged declared-origin label is not a byte-range certificate: the
    real frame writer and alias debt survive even without an exact pointer."""
    import tdo_v2.function_summary as summary_module
    from dataclasses import replace
    from tdo_v2.function_summary import ExitSummary, SummaryKind

    original = summary_module._pointer_values

    def everything_nonstack(normalized, observation, exits, tracer):
        exits = original(normalized, observation, exits, tracer)
        return [ExitSummary(item.block_key, tuple(
            replace(run, value=("nonstack",)) if run.kind is SummaryKind.COMPUTED and run.span.size == 8 else run
            for run in item.runs)) for item in exits]

    monkeypatch.setattr(summary_module, "_pointer_values", everything_nonstack)
    results, report = _program_check(_array_caller(), _grow_helper(points_into_frame=True))
    assert any(run.value == ("nonstack",) for exit_summary in results[f"1:{HELPER:x}"].summary.exits
               for run in exit_summary.runs)
    function = results["1:1000"].normalized
    _assert_unbounded_access_debt(function, _load_slice(function, 2), (RBX, RSI),
                                 ("1:1008:1:STORE", "1:1018:0:STORE"))
    assert report.runs == 6 and report.checked and not report.unsupported and report.silent == []


def test_a_reused_block_after_free_is_not_missed():
    """p = malloc(); *p = rsi; free(p); q = malloc() (the same address again);
    *q = rdi; r9 = *q: the oracle reuses freed addresses."""
    builder = (FunctionBuilder().sub_rsp(0x28)
               .ins(copy(reg(RCX), const(16))).call(THUNKS["malloc"])
               .ins(store(reg(RAX), reg(RSI)))
               .ins(copy(reg(RCX), reg(RAX))).call(THUNKS["free"])
               .ins(copy(reg(RCX), const(16))).call(THUNKS["malloc"])
               .ins(store(reg(RAX), reg(RDI)))
               .ins(load(reg(R9), reg(RAX)))
               .add_rsp(0x28).ret())
    results = _analyze(builder)
    reload = _reload(results["1:1000"].normalized)
    assert reload.is_complete and set(range(RDI, RDI + 8)) <= reload.register_bytes
    assert _check(results).silent == []


# -- DebugGame shape: this spilled and reloaded around a write of an unproven value --

def _debug_grow_helper(max_field=12, data_field=0):
    """spill this (rcx) to the home slot; free(); this->Max = eax (unknown
    after the call); this->Data = rsi; this->Max = 16 -- each through a
    reload of this. The Data write's address rests on "the Max write did not
    hit the home slot" (an alias condition), not on the unknown eax."""
    t, u = tmp(0x100), tmp(0x108)
    return (FunctionBuilder(entry=HELPER)
            .ins(add(t, reg(RSP), const(8)), store(t, reg(RCX)))
            .sub_rsp(0x28)
            .call(THUNKS["free"])
            .ins(add(t, reg(RSP), const(0x30)), load(reg(RCX), t))
            .ins(add(u, reg(RCX), const(max_field)), store(u, reg(RAX, 4)))
            .ins(add(t, reg(RSP), const(0x30)), load(reg(RCX), t))
            .ins(add(u, reg(RCX), const(data_field)), store(u, reg(RSI)))
            .ins(add(t, reg(RSP), const(0x30)), load(reg(RCX), t))
            .ins(add(u, reg(RCX), const(max_field)), store(u, const(16, 4)))
            .add_rsp(0x28).ret())


def _debug_caller(displacement=0x10):
    """kept = rbx at [rsp+0x38]; helper(&s at rsp + displacement); r9 = kept."""
    t = tmp(0x100)
    return (FunctionBuilder().sub_rsp(0x48)
            .ins(add(t, reg(RSP), const(0x38)), store(t, reg(RBX)))
            .ins(add(reg(RCX), reg(RSP), const(displacement & 0xFFFFFFFFFFFFFFFF)))
            .call(HELPER)
            .ins(add(t, reg(RSP), const(0x38)), load(reg(R9), t))
            .add_rsp(0x48).ret())


def test_realloc_lifetime_debt_prevents_conditional_only_address_claim():
    """In addition to the old Max/this conditional alias, realloc may end
    the old memory's lifetime. Without an extent proof even a frame spill
    cannot silently survive that call: the later address stays uncertain."""
    results, report = _program_check(_debug_caller(), _debug_grow_helper())
    summary = results[f"1:{HELPER:x}"].summary
    assert summary.unknown_writers == ("1:1810:1:STORE", "1:1818:1:STORE", "1:1820:1:STORE")
    (effect,) = [e for k, e in results["1:1000"].proven.items() if k.endswith(":CALL")]
    assert not effect.preserves_memory
    kept = _load_slice(results["1:1000"].normalized, 1)
    assert not kept.is_complete and set(range(RBX, RBX + 8)) <= kept.register_bytes
    assert report.runs and report.silent == []


@pytest.mark.parametrize("displacement", [-16, -12, -8, -4, 0, 4, 8, 0x10])
@pytest.mark.parametrize("max_field", [8, 12, 16])
def test_debug_grow_any_layout(displacement, max_field):
    _, report = _program_check(_debug_caller(displacement), _debug_grow_helper(max_field))
    assert report.silent == [], report.silent[:2]


def test_mutation_full_address_slice_loses_the_proof(monkeypatch):
    """The old rule (every debt behind the address, through the writers of
    conditional debts) makes the Data write unconditional again."""
    import tdo_v2.function_summary as summary_module
    monkeypatch.setattr(summary_module, "_address_slice",
                        lambda graph, inputs, conditions_of: graph.backward_reachable(tuple(inputs)))
    results, _ = _program_check(_debug_caller(), _debug_grow_helper())
    assert results[f"1:{HELPER:x}"].summary.unknown_writers


def test_xor_of_a_register_with_itself_reads_nothing():
    """free() clobbers rdx; xor edx, edx makes it zero whatever it held: no
    call-clobber debt on the result (the oracle computes it the same way)."""
    from synthetic import op
    builder = (FunctionBuilder().sub_rsp(0x28)
               .call(THUNKS["free"])
               .ins(op("INT_XOR", [reg(RDX, 4), reg(RDX, 4)], reg(RDX, 4)))
               .ins(add(reg(R9, 4), reg(RDX, 4), const(0, 4)))
               .add_rsp(0x28).ret())
    results = _analyze(builder)
    function = results["1:1000"].normalized
    # The register computation is exact even though the old return-address
    # memory can no longer be assumed to survive a frees-bearing call.
    exact = slice_from(function, operation_node_at(function, 3))
    assert exact.is_complete and not exact.register_bytes
    assert {row.operation_key for row in function.call_clobber_reads} == {"1:1014:0:LOAD"}
    assert _check(results).silent == []
