"""Allocator windows through summaries (docs 25.79 3b): a function returning
an allocation of a proven size exports ("nonstack", N, nullable, labels); its
caller keeps accesses inside [p, p + N) apart from the stack -- under its own
null test when nullable. No window from a function resizing any block, from a
non-copy (p + 8), from a run not COMPUTED; exits / joins take the smallest;
a switched-off label drops it. Pre-escape-values is off here."""

import pytest

from synthetic import (
    CODE_BASE, R9, RAX, RBX, RCX, RDX, RSI, RSP, FunctionBuilder, add, const, copy, load, op, program_units, reg,
)
from test_allocator_windows import ALLOC, ALLOC_NN, FLAG, RESIZE, T, TOUCH, _models
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units

WRAP = CODE_BASE + 0x900


def _analyze(tmp_path, caller, wrapper, **options):
    image = ImageInfo("synthetic", (), tuple(
        ImportedSymbol("CORE", name, None, (), ((1, thunk),))
        for name, thunk in (("Alloc", ALLOC), ("AllocNN", ALLOC_NN), ("Touch", TOUCH), ("Resize", RESIZE))), (), ())
    return analyze_units(program_units(caller, wrapper), image_info=image, external_models=_models(tmp_path),
                         **{"assume_pre_escape_values_not_frame": False, **options})


def _wrapper(*body, allocator=ALLOC, size=32):
    """rcx = size; rax = allocator(); body; ret."""
    return FunctionBuilder(entry=WRAP).sub_rsp(0x28).ins(copy(reg(RCX), const(size))).call(allocator) \
        .ins(*body).add_rsp(0x28).ret() if body else \
        FunctionBuilder(entry=WRAP).sub_rsp(0x28).ins(copy(reg(RCX), const(size))).call(allocator).add_rsp(0x28).ret()


def _caller(guard=True, offset=8):
    """rax = Wrap(); rbx = rax; [if rax == 0 return;] Touch() -- a push; r9 = [rbx + offset]."""
    builder = FunctionBuilder().sub_rsp(0x28).call(WRAP).ins(copy(reg(RBX), reg(RAX)))
    if guard:
        builder.cbranch("out", FLAG, op("INT_EQUAL", [reg(RAX), const(0)], FLAG))
    builder.call(TOUCH).ins(add(T, reg(RBX), const(offset)), load(reg(R9), T))
    return builder.label("out").add_rsp(0x28).ret()


def _pushed(results, builder) -> bool:
    index = next(index for index, row in enumerate(builder._rows) if row.ops and row.ops[-1][0] == "LOAD")
    key = f"1:{builder.entry + builder.stride * index:x}:1:LOAD"
    return any(writer.endswith("~push") for row in results["1:1000"].normalized.may_alias_reads
               if row.operation_key == key for writer in row.writers)


def _value(results):
    return {run.value for item in results[f"1:{WRAP:x}"].summary.exits for run in item.runs
            if run.span.object_id.kind.value == "register_file" and run.span.start == RAX and run.span.size == 8}


def test_a_wrapper_exports_its_window_and_the_caller_tests_null(tmp_path):
    caller = _caller()
    results = _analyze(tmp_path, caller, _wrapper())
    (value,) = _value(results)
    assert value[:3] == ("nonstack", 32, True) and "allocator-results-are-fresh" in value[3]
    assert not _pushed(results, caller)
    caller = _caller(guard=False)
    assert _pushed(_analyze(tmp_path, caller, _wrapper()), caller)


def test_a_never_null_wrapper_needs_no_test_in_the_caller(tmp_path):
    caller = _caller(guard=False)
    results = _analyze(tmp_path, caller, _wrapper(allocator=ALLOC_NN))
    (value,) = _value(results)
    assert value[:3] == ("nonstack", 32, False)
    assert not _pushed(results, caller)


def test_outside_the_window_or_a_non_copy_keeps_the_push(tmp_path):
    caller = _caller(offset=32)
    assert _pushed(_analyze(tmp_path, caller, _wrapper()), caller)
    results = _analyze(tmp_path, _caller(), _wrapper(add(reg(RAX), reg(RAX), const(8))))
    assert not any(value is not None and len(value) == 4 for value in _value(results))


def test_two_exits_take_the_smaller_window(tmp_path):
    """rsi ? malloc(32) : malloc(64), two RETURNs."""
    wrapper = (FunctionBuilder(entry=WRAP).sub_rsp(0x28)
               .cbranch("big", FLAG, op("INT_EQUAL", [reg(RSI), const(0)], FLAG))
               .ins(copy(reg(RCX), const(32))).call(ALLOC).add_rsp(0x28).ret()
               .label("big").ins(copy(reg(RCX), const(64))).call(ALLOC).add_rsp(0x28).ret())
    caller = _caller()
    results = _analyze(tmp_path, caller, wrapper)
    effect = dict(results["1:1000"].normalized.proven_call_effects)
    values = {run.value for item in effect.values() for run in item.runs if run.value is not None}
    assert any(value[:3] == ("nonstack", 32, True) for value in values)
    assert not _pushed(results, caller)


def test_a_resizing_wrapper_exports_no_window(tmp_path):
    """p = malloc(32); q = Resize(p, 4); return p (an alias of the resized block)."""
    wrapper = (FunctionBuilder(entry=WRAP).sub_rsp(0x28).ins(copy(reg(RCX), const(32))).call(ALLOC)
               .ins(copy(reg(RBX), reg(RAX)), copy(reg(RCX), reg(RAX)), copy(reg(RDX), const(4))).call(RESIZE)
               .ins(copy(reg(RAX), reg(RBX))).add_rsp(0x28).ret())
    results = _analyze(tmp_path, _caller(), wrapper)
    assert not any(value is not None and len(value) == 4 for value in _value(results))
    assert ("nonstack",) in _value(results)   # (F1: "a block" stays as before)


def test_a_windowed_and_a_plain_exit_give_a_plain_block(tmp_path):
    """rsi ? malloc(32) : Alloc of an unproven size: one exit has no window."""
    wrapper = (FunctionBuilder(entry=WRAP).sub_rsp(0x28)
               .cbranch("other", FLAG, op("INT_EQUAL", [reg(RSI), const(0)], FLAG))
               .ins(copy(reg(RCX), const(32))).call(ALLOC).add_rsp(0x28).ret()
               .label("other").ins(copy(reg(RCX), reg(RDX))).call(ALLOC).add_rsp(0x28).ret())
    caller = _caller()
    results = _analyze(tmp_path, caller, wrapper)
    effect = dict(results["1:1000"].normalized.proven_call_effects)
    values = {run.value for item in effect.values() for run in item.runs if run.value is not None}
    assert ("nonstack",) in values and not any(len(value) == 4 for value in values)
    assert _pushed(results, caller)


def test_a_nested_wrapper_keeps_the_window(tmp_path):
    """Outer() = Wrap(): the window passes through the second summary."""
    outer_entry = WRAP + 0x80
    outer = FunctionBuilder(entry=outer_entry).sub_rsp(0x28).call(WRAP).add_rsp(0x28).ret()
    caller = FunctionBuilder().sub_rsp(0x28).call(outer_entry).ins(copy(reg(RBX), reg(RAX)))
    caller.cbranch("out", FLAG, op("INT_EQUAL", [reg(RAX), const(0)], FLAG))
    caller.call(TOUCH).ins(add(T, reg(RBX), const(8)), load(reg(R9), T)).label("out").add_rsp(0x28).ret()
    image = ImageInfo("synthetic", (), tuple(
        ImportedSymbol("CORE", name, None, (), ((1, thunk),))
        for name, thunk in (("Alloc", ALLOC), ("Touch", TOUCH))), (), ())
    results = analyze_units(program_units(caller, _wrapper(), outer), image_info=image,
                            external_models=_models(tmp_path), assume_pre_escape_values_not_frame=False)
    assert not _pushed(results, caller)


def test_a_switched_off_label_drops_the_window(tmp_path):
    caller = _caller(guard=False)
    results = _analyze(tmp_path, caller, _wrapper(allocator=ALLOC_NN),
                       disabled_model_assumptions=("alloc-test:never-null",))
    assert _pushed(results, caller)


def test_template_round_trip_and_refusals():
    from test_constant_summary_values import REGISTERS, _run, _template
    from tdo_v2.summary_templates import TemplateError, instantiate

    value = ("nonstack", 32, True, ("allocator-results-are-fresh",))
    summary, _ = instantiate(_template(_run(literal=None, value=value)), "test", REGISTERS, 1)
    assert summary.exits[0].runs[0].value == value
    for index, bad in ((1, 0), (1, 1 << 63), (2, 1), (3, []), (3, ["b", "a"]), (3, [""])):
        raw = _template(_run(literal=None, value=value))
        raw["exits"][0]["runs"][0]["value"][index] = bad
        with pytest.raises(TemplateError):
            instantiate(raw, "test", REGISTERS, 1)


def test_a_stored_window_resting_on_a_disabled_label_is_dropped():
    """A summary or template effect built in a run with a label off (not the
    one that derived it): the window goes, "a block" stays."""
    from dataclasses import dataclass

    from tdo_v2.interprocedural import _without_disabled_windows

    @dataclass(frozen=True)
    class Run:
        value: tuple

    @dataclass(frozen=True)
    class Effect:
        runs: tuple
        memory_runs: tuple

    window = ("nonstack", 32, False, ("allocator-results-are-fresh", "x:never-null"))
    effect = Effect((Run(window),), ())
    assert _without_disabled_windows(effect, {"x:never-null"}).runs[0].value == ("nonstack",)
    assert _without_disabled_windows(effect, {"other"}).runs[0].value == window


def _oracle(results, wrapper_alloc):
    from program_oracle import check_program
    import test_graph_fidelity as fidelity
    from synthetic import REG, RSP

    (alloc,) = program_units(wrapper_alloc)
    (touch,) = program_units(FunctionBuilder(entry=TOUCH).ret())
    program = {(1, ALLOC): alloc.observation, (1, TOUCH): touch.observation,
               (1, WRAP): results[f"1:{WRAP:x}"].unit.observation}
    item = results["1:1000"]
    return check_program(item.normalized, item.unit.observation, program, seeds=range(4),
                         register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                         havoc_calls=(REG, RSP, 8))


def test_the_oracle_finds_nothing_silent_with_a_real_allocator(tmp_path):
    results = _analyze(tmp_path, _caller(), _wrapper())
    real = FunctionBuilder(entry=ALLOC).ins(copy(reg(RAX), const(0x6000_0000))).ret()
    assert _oracle(results, real).silent == []


def test_the_oracle_catches_an_allocator_returning_the_stack(tmp_path):
    """An "allocator" returning its caller's stack pointer (the wrapper's
    frame, below the caller's): with 0x40 bytes, [p + 0x28] is the slot the
    caller's Touch() pushes its return address into -- inside the exported
    window, so only the contract kept it apart; the oracle sees it."""
    results = _analyze(tmp_path, _caller(offset=0x28), _wrapper(size=0x40))
    assert "allocator-results-are-fresh" in results["1:1000"].normalized.nonstack_labels
    fake = FunctionBuilder(entry=ALLOC).ins(add(reg(RAX), reg(RSP), const(8))).ret()
    assert _oracle(results, fake).silent != []


def test_an_overlapping_output_pair_exports_no_window(tmp_path):
    """Wrap(rdi, rsi): [rdi] = malloc(32); [rsi] = 0 -- the caller passes one
    slot twice: the stored value is not known, so no window reaches the
    caller's reload of the slot."""
    from synthetic import RDI, store
    wrapper = (FunctionBuilder(entry=WRAP).sub_rsp(0x28).ins(copy(reg(RCX), const(32))).call(ALLOC)
               .ins(store(reg(RDI), reg(RAX)), store(reg(RSI), const(0))).add_rsp(0x28).ret())
    slot = T
    caller = (FunctionBuilder().sub_rsp(0x48).ins(add(reg(RDI), reg(RSP), const(0x20)), copy(reg(RSI), reg(RDI)))
              .call(WRAP).ins(add(slot, reg(RSP), const(0x20)), load(reg(RBX), slot)))
    caller.cbranch("out", FLAG, op("INT_EQUAL", [reg(RBX), const(0)], FLAG))
    caller.call(TOUCH).ins(add(slot, reg(RBX), const(8)), load(reg(R9), slot)).label("out").add_rsp(0x48).ret()
    results = _analyze(tmp_path, caller, wrapper)
    rows = caller._rows
    index = max(index for index, row in enumerate(rows) if row.ops and row.ops[-1][0] == "LOAD")
    key = f"1:{caller.entry + caller.stride * index:x}:1:LOAD"
    assert any(writer.endswith("~push") for row in results["1:1000"].normalized.may_alias_reads
               if row.operation_key == key for writer in row.writers)
