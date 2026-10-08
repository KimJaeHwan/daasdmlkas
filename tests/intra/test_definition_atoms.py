"""Definition atoms (``relative_memory``): a pointer a call returns or a LOAD
reads, defined once per activation, is a base of its own.

The program oracle runs the real code (``malloc`` with C semantics) and checks
the caller's graph: nothing is silently missed. The mutations prove the guards
matter: without the wild-object rule of ``may_alias`` a pointer a callee
returns into the caller's private frame is missed.
"""

import pytest

import test_graph_fidelity as fidelity
import tdo_v2.normalize as normalize_module
import tdo_v2.relative_memory as relative_memory
from program_oracle import check_program
from synthetic import (
    CODE_BASE, R9, RAX, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const, copy, load,
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


def test_two_allocations_merged_stay_debt():
    """rax = cond ? malloc() : malloc(); *rax = rdx; r9 = *rax: the join of two
    definitions has no single atom, the store stays an unknown write."""
    t = tmp(0x100)
    builder = (FunctionBuilder().sub_rsp(0x28)
               .cbranch("other", reg(RSI, 1))
               .call(THUNKS["malloc"])
               .branch("join")
               .label("other").call(THUNKS["malloc"])
               .label("join").ins(store(reg(RAX), reg(RDX)))
               .ins(add(t, reg(RAX), const(0)), load(reg(R9), t))
               .add_rsp(0x28).ret())
    results = _analyze(builder)
    function = results["1:1000"].normalized
    assert not _reload(function).is_complete
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
        kwargs["wild_objects"] = frozenset()
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


def test_a_fresh_block_spilled_to_the_frame_is_exact():
    """malloc's model declares its result fresh (never a stack address): its
    object is not wild, so the private frame slot holding the pointer is not
    disturbed by the heap store."""
    results = _analyze(_spilled_heap_pointer())
    reload = _reload(results["1:1000"].normalized)
    assert reload.is_complete
    assert set(range(RSI, RSI + 8)) <= reload.register_bytes
    assert _check(results).silent == []


def test_without_fresh_the_spilled_pointer_stays_unsure(monkeypatch):
    import tdo_v2.summary_store as store_module
    original = store_module.load_model_file

    def without_fresh(path):
        model = original(path)
        from dataclasses import replace
        return replace(model, entries=tuple(replace(entry, fresh=()) for entry in model.entries))

    monkeypatch.setattr(store_module, "load_model_file", without_fresh)
    results = _analyze(_spilled_heap_pointer())
    assert not _reload(results["1:1000"].normalized).is_complete
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


def test_realloc_keeps_the_object():
    """realloc's result addresses the old block's object (the model's
    same_object_as, assuming the old pointer is not used afterwards): the
    oracle moves the block for real and every byte keeps its writer."""
    results = _analyze(_grown_buffer())
    reload = _reload(results["1:1000"].normalized)
    assert reload.is_complete
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


def test_a_fresh_block_is_disjoint_from_globals():
    results = _analyze(_fresh_and_global(False))
    reload = _reload(results["1:1000"].normalized)
    assert reload.is_complete and set(range(RSI, RSI + 8)) <= reload.register_bytes
    assert not reload.register_bytes & set(range(RDI, RDI + 8))
    assert _check(results).silent == []


def test_a_loaded_pointer_may_reach_a_fresh_block():
    results = _analyze(_fresh_and_global(True))
    reload = _reload(results["1:1000"].normalized)
    assert not reload.is_complete
    assert _check(results, pools=_global_pools).silent == []


def test_mutation_fresh_disjoint_from_everything_misses(monkeypatch):
    import tdo_v2.may_alias as may_alias_module
    original = may_alias_module._Policy.may_alias

    def disjoint(self, left, right):
        if left in self.fresh_objects or right in self.fresh_objects:
            return False
        return original(self, left, right)

    monkeypatch.setattr(may_alias_module._Policy, "may_alias", disjoint)
    assert _check(_analyze(_fresh_and_global(True)), pools=_global_pools).silent
