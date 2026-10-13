"""Oracle placement, second round (Astra's oracle review round 2): bytes copied
back by a later call, the entry-relative home-space bound, pointer slots at
composed displacements, pointer slots across the address wrap, and bytes an
allocator model moved after a summarized call wrote them."""

import test_graph_fidelity as fidelity
from program_oracle import _place, check_program
from summary_oracle import check_summary
from synthetic import (
    R8, RAM, RAX, RBP, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder, add, const, copy, load,
    normalize_with_observation, program_units, reg, store, tmp,
)
from test_oracle_locations import LEAF, OTHER, POOLS, _check_with_moved_runs, _shifted
from tdo_v2.call_summary_effects import AnchoredSpan
from tdo_v2.function_summary import summarize_function
from tdo_v2.interprocedural import analyze_units
from tdo_v2.span_geometry import ByteSpan, StorageObjectId, StorageObjectKind, StorageScopeId, StorageScopeKind


def test_a_byte_copied_back_by_a_later_call_keeps_its_writer_and_inputs(monkeypatch):
    """A: *(rdi) = rsi; B: *(rdi) = *(rdi) (copied back unchanged); the caller
    reads it: still A's write with A's inputs -- A's runs stripped of their
    inputs are caught through B as they are without it."""
    t = tmp(0x100)
    first = FunctionBuilder(entry=LEAF).ins(store(reg(RDI), reg(RSI))).ret()
    second = FunctionBuilder(entry=OTHER).ins(load(t, reg(RDI))).ins(store(reg(RDI), t)).ret()
    caller = (FunctionBuilder().sub_rsp(0x40).ins(add(reg(RDI), reg(RSP), const(0))).call(LEAF)
              .ins(add(reg(RDI), reg(RSP), const(0))).call(OTHER).ins(load(reg(RAX), reg(RSP)))
              .add_rsp(0x40).ret())
    right = _check_with_moved_runs(monkeypatch, (caller, first, second), 0)
    assert right.silent == [] and right.covered_by_debt == []
    wrong = _check_with_moved_runs(monkeypatch, (caller, first, second), 0, mutate_call=LEAF, no_inputs=True)
    assert wrong.silent or wrong.covered_by_debt


def test_the_home_space_bound_is_entry_relative(monkeypatch):
    """private_frame_above 0x28: [entry, entry + 0x28) is the callee's; its
    write at [entry + 0x28] (the caller's [rsp + 0x20]) is exported -- dropping
    that run is caught by the footprint check."""
    t = tmp(0x100)
    leaf = FunctionBuilder(entry=LEAF).ins(add(t, reg(RSP), const(0x28)), store(t, reg(RCX))).ret()
    caller = (FunctionBuilder().sub_rsp(0x40).call(LEAF)
              .ins(add(t, reg(RSP), const(0x20)), load(reg(RAX), t)).add_rsp(0x40).ret())
    right = _check_with_moved_runs(monkeypatch, (caller, leaf), 0, private_frame_above=0x28)
    assert right.silent == [] and right.footprint_checked > 0
    wrong = _check_with_moved_runs(monkeypatch, (caller, leaf), 0, drop=True, private_frame_above=0x28)
    assert any(reason == "write outside the call's footprint" for _, reason in wrong.silent)


def test_a_pointer_slot_at_a_composed_displacement_is_located():
    """p = *(rsi + 0x120 + 0xe0); *p = rdi: 0x200 is no literal of the
    function; a run moved by 8 is a violation, not an unlocated cover."""
    t = tmp(0x100)
    function, observation = normalize_with_observation(
        FunctionBuilder().ins(add(t, reg(RSI), const(0x120))).ins(add(t, t, const(0xE0)))
        .ins(load(reg(RAX), t)).ins(store(reg(RAX), reg(RDI))).ret())
    summary = summarize_function(function, observation)
    right = check_summary(summary, observation, seeds=range(4), register_pools=POOLS)
    assert right.violations == [] and right.place_covered > 0 and right.place_unlocated_only == 0
    wrong = check_summary(_shifted(summary, 8), observation, seeds=range(4), register_pools=POOLS)
    assert any(row[0] == "write outside its run" for row in wrong.violations)


def test_a_pointer_slot_across_the_wrap_is_read():
    top = (1 << 64) - 4
    value = 0x1122334455667788
    snapshot = {(RAM, (top + index) % (1 << 64)): (value >> (8 * index)) & 0xFF for index in range(8)}
    scope = StorageScopeId(StorageScopeKind.PROGRAM, b"\x02" * 32)
    slot = AnchoredSpan(None, top, 8, RAM, ByteSpan(StorageObjectId(StorageObjectKind.ADDRESS_SPACE, scope, RAM),
                                                    top, 4))
    anchored = AnchoredSpan(None, 0x10, 4, RAM, pointer=slot)
    assert _place(anchored, snapshot, {}, REG, moduli={RAM: 1 << 64}) == (RAM, value + 0x10, 4)


def test_a_byte_a_call_wrote_then_realloc_moved_is_placed_where_it_was_written():
    """Data = malloc(16); W(Data) writes Data[1]; grow (realloc) moves the
    block; the caller reads the moved Data[1]: W's run holds it at the place W
    wrote it -- no false "write outside its run"."""
    from test_definition_atoms import HELPER, _grow_helper
    from test_external_models import MODELS, THUNKS, _image
    from tdo_v2.summary_store import load_external_models

    writer = OTHER + 0x100
    t = tmp(0x100)
    w = FunctionBuilder(entry=writer).ins(add(t, reg(RCX), const(8)), store(t, reg(RDX))).ret()
    caller = (FunctionBuilder().sub_rsp(0x48)
              .ins(copy(reg(RCX), const(16))).call(THUNKS["malloc"])
              .ins(add(t, reg(RSP), const(0x20)), store(t, reg(RAX)))
              .ins(copy(reg(RCX), reg(RAX))).ins(copy(reg(RDX), reg(RBP))).call(writer)
              .ins(add(t, reg(RSP), const(0x28)), store(t, reg(RBX)))
              .ins(add(reg(RCX), reg(RSP), const(0x20))).call(HELPER)
              .ins(add(t, reg(RSP), const(0x20)), load(reg(RAX), t))
              .ins(add(t, reg(RAX), const(8)), load(reg(R8), t))
              .add_rsp(0x48).ret())
    units = program_units(caller, _grow_helper(), w)
    results = analyze_units(units, image_info=_image(),
                            external_models=load_external_models(MODELS, "x86:LE:64:default", "win64"))
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    analyzed = results["1:1000"]
    report = check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=range(6),
                           register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                           havoc_calls=(REG, RSP, 8),
                           externals={(1, address): name for name, address in THUNKS.items()})
    assert report.runs
    assert not [row for row in report.silent + report.covered_by_debt if row[1] == "write outside its run"]


def test_a_callee_writing_its_own_fresh_block_does_not_claim_to_preserve_memory():
    """Guard for the footprint check: it does not exclude blocks allocated
    during the activation, which is right only while the engine takes such a
    call as not preserving memory (an unanchored fresh object). If this
    changes, the footprint check must leave those blocks out."""
    from test_external_models import MODELS, THUNKS, _image
    from tdo_v2.summary_store import load_external_models

    leaf = (FunctionBuilder(entry=LEAF).sub_rsp(0x28).ins(copy(reg(RCX), const(16))).call(THUNKS["malloc"])
            .ins(store(reg(RAX), reg(RDX))).add_rsp(0x28).ret())
    caller = FunctionBuilder().sub_rsp(0x28).call(LEAF).ins(load(reg(RBX), reg(RAX))).add_rsp(0x28).ret()
    units = program_units(caller, leaf)
    results = analyze_units(units, image_info=_image(),
                            external_models=load_external_models(MODELS, "x86:LE:64:default", "win64"))
    (effect,) = results["1:1000"].proven.values()
    assert not effect.preserves_memory


def test_memory_wraps_at_the_declared_width_not_at_the_address_operands():
    """32-bit address operands in a 64-bit space: a store at 2**32 - 4 runs on
    to 2**32 .. 2**32 + 3 -- it wraps to 0 only in a 32-bit space."""
    from pcode_interpreter import Dependency, Interpreter
    from synthetic import CONST

    function = (FunctionBuilder().ins(store(reg(RCX, 4), reg(RDX))).ins(load(reg(RAX, 4), const(0, 4)))
                .ret(realistic=False))
    observation = normalize_with_observation(function)[1]
    for bits, wraps in ((None, False), ({RAM: 64}, False), ({RAM: 32}, True)):
        interpreter = Interpreter(observation, constant_space=CONST, seed=0, address_bits=bits)
        interpreter.preset(REG, RCX, 8, (1 << 32) - 4)
        run = interpreter.run()
        store_key = next(key for key in run.executed if key.endswith("STORE"))
        load_key = next(key for key in run.executed if key.endswith("LOAD"))
        assert (Dependency(load_key, RAM, 0, store_key) in run.dependencies) is wraps, bits


def test_a_moved_byte_copied_back_keeps_its_original_place():
    """As the realloc test, then B copies the moved Data[1] back unchanged:
    the read is still placed where W wrote it."""
    from test_definition_atoms import HELPER, _grow_helper
    from test_external_models import MODELS, THUNKS, _image
    from tdo_v2.summary_store import load_external_models

    writer, copier = OTHER + 0x100, OTHER + 0x200
    t, u = tmp(0x100), tmp(0x108)
    w = FunctionBuilder(entry=writer).ins(add(t, reg(RCX), const(8)), store(t, reg(RDX))).ret()
    b = (FunctionBuilder(entry=copier).ins(add(t, reg(RCX), const(8)), load(u, t))
         .ins(add(t, reg(RCX), const(8)), store(t, u)).ret())
    caller = (FunctionBuilder().sub_rsp(0x48)
              .ins(copy(reg(RCX), const(16))).call(THUNKS["malloc"])
              .ins(add(t, reg(RSP), const(0x20)), store(t, reg(RAX)))
              .ins(copy(reg(RCX), reg(RAX))).ins(copy(reg(RDX), reg(RBP))).call(writer)
              .ins(add(t, reg(RSP), const(0x28)), store(t, reg(RBX)))
              .ins(add(reg(RCX), reg(RSP), const(0x20))).call(HELPER)
              .ins(add(t, reg(RSP), const(0x20)), load(reg(RCX), t)).call(copier)
              .ins(add(t, reg(RSP), const(0x20)), load(reg(RAX), t))
              .ins(add(t, reg(RAX), const(8)), load(reg(R8), t))
              .add_rsp(0x48).ret())
    units = program_units(caller, _grow_helper(), w, b)
    results = analyze_units(units, image_info=_image(),
                            external_models=load_external_models(MODELS, "x86:LE:64:default", "win64"))
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    analyzed = results["1:1000"]
    report = check_program(analyzed.normalized, analyzed.unit.observation, program, seeds=range(6),
                           register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                           havoc_calls=(REG, RSP, 8),
                           externals={(1, address): name for name, address in THUNKS.items()})
    assert report.runs
    assert not [row for row in report.silent + report.covered_by_debt if row[1] == "write outside its run"]
