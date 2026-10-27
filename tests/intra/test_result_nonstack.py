"""A model entry's ``result_nonstack`` (docs 25.75): the first ``extent``
bytes of every result are in no thread's stack -- in the calling function an
object addressed by exactly the result, every access of which lies inside,
is kept apart from the stack (pushes and the private frame included). The
claim rests on a declared assumption: reported where a window is made,
switched off by its label (the entry still applies, without the window).
Only in the function making the call; a realloc-like call of the result
keeps no window."""

import json

import pytest

import test_graph_fidelity as fidelity
from program_oracle import check_program
from synthetic import (
    NO_CALLBACKS, CODE_BASE, DATA_BASE, R9, RAX, RBP, RBX, RCX, RDX, REG, RSP, FunctionBuilder, add, const, copy,
    load, op, operation_node_at, program_units, reg, slice_from, sub, tmp,
)
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units
from tdo_v2.summary_store import ModelError, load_external_models

GET = CODE_BASE + 0xE00     # the accessor's import thunk
GET2 = CODE_BASE + 0xE30    # another accessor with a smaller window
WRAP = CODE_BASE + 0x800    # an in-Bundle function returning GetObj's result
TOUCH = CODE_BASE + 0xE10   # a model call between: its CALL pushes a return address
MOVE = CODE_BASE + 0xE20    # realloc-like: the result is the same object as rcx
LABEL = "nonstack-test:off-stack"
T = tmp(0x100)
SLOT = {"base": [RCX, 8], "disp": 0, "size": 8}
WINDOW = {"result": [RAX, 8], "extent": 0x40, "rests_on": LABEL}


def _get(**changes):
    entry = {"name": "GetObj", "registers": [{"write": [RAX, 8], "from": [[RCX, 8]], "loads": [SLOT]}],
             "memory": [], **NO_CALLBACKS, "other_memory": "preserved", "observes": [[RCX, 8]],
             "same_result": {"result": [RAX, 8], "inputs": [], "reads": [SLOT]}, "result_nonstack": WINDOW}
    entry.update(changes)
    return {key: value for key, value in entry.items() if value is not None}


def _models(tmp_path, get=None, more=()):
    raw = {"format_version": 1, "kind": "declared", "id": "nonstack-test", "version": 1,
           "language_id": "x86:LE:64:default", "abi_tag": "win64", "stack_pointer": [RSP, 8], "stack_delta": 8,
           "preserved": [[24, 8], [40, 8], [48, 8], [56, 8]],
           "declares_assumptions": [{"id": "off-stack", "statement": "GetObj results are off the stack.",
                                     "fails_when": "A stack object is returned."}],
           "entries": [get or _get(),
                       {"name": "Touch", "registers": [], "memory": [], **NO_CALLBACKS, "other_memory": "preserved",
                        "observes": []},
                       {"name": "Move", "registers": [{"write": [RAX, 8], "same_object_as": [RCX, 8]}],
                        "memory": [], **NO_CALLBACKS, "other_memory": "preserved", "observes": [[RCX, 8]]},
                       *more]}
    path = tmp_path / "nonstack.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return load_external_models([path], "x86:LE:64:default", "win64")


def _analyze(tmp_path, builder, get=None, more=(), others=(), **options):
    image = ImageInfo("synthetic", (), tuple(
        ImportedSymbol("CORE", name, None, (), ((1, thunk),))
        for name, thunk in (("GetObj", GET), ("Touch", TOUCH), ("Move", MOVE), ("GetObj2", GET2))), (), ())
    return analyze_units(program_units(builder, *others), image_info=image,
                         external_models=_models(tmp_path, get, more), **options)["1:1000"]


def _caller(*offsets, move=False):
    """rbp = Get(rbx); [Move(rbp)]; Touch() -- a push between; r9 = [rbp + offset] for each offset (the
    last one is read last: instruction ``_last``)."""
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), reg(RBX))).call(GET).ins(copy(reg(RBP), reg(RAX)))
    if move:
        builder.ins(copy(reg(RCX), reg(RBP))).call(MOVE).ins(copy(reg(RBP), reg(RAX)))
    builder.call(TOUCH)
    for offset in offsets:
        builder.ins(sub(T, reg(RBP), const(-offset & (1 << 64) - 1)) if offset < 0 else
                    add(T, reg(RBP), const(offset)), load(reg(R9), T))
    return builder.add_rsp(0x28).ret()


def _last_read(analyzed, builder):
    index = len(builder._rows) - 3   # (the last load; add_rsp and ret follow)
    return slice_from(analyzed.normalized, operation_node_at(analyzed.normalized, index, 1))


@pytest.mark.parametrize("same_result", [False, True])
def test_a_read_inside_the_window_is_kept_apart_from_the_push(tmp_path, same_result):
    """With or without the accessor identity (same-result-functions): the
    window rides with the value, not with the identity."""
    builder = _caller(8)
    analyzed = _analyze(tmp_path, builder, assume_same_result_functions=same_result)
    assert _last_read(analyzed, builder).result.is_complete
    assert LABEL in analyzed.inherited_assumptions and LABEL in analyzed.normalized.nonstack_labels


def test_without_the_window_the_push_may_reach_the_read(tmp_path):
    builder = _caller(8)
    analyzed = _analyze(tmp_path, builder, get=_get(result_nonstack=None))
    assert not _last_read(analyzed, builder).result.is_complete
    assert LABEL not in analyzed.inherited_assumptions


@pytest.mark.parametrize("offsets", [(-8, 8), (0x40, 8), (0x3C, 8)])
def test_one_access_outside_the_window_revokes_it(tmp_path, offsets):
    """A negative offset, an access at the extent, an access crossing it:
    the whole object stays wild -- the read checked is the INSIDE one,
    [r + 8], after the outside access (every access must lie inside)."""
    builder = _caller(*offsets)
    analyzed = _analyze(tmp_path, builder)
    assert not _last_read(analyzed, builder).result.is_complete


def test_switching_the_label_off_keeps_the_entry_but_no_window(tmp_path):
    builder = _caller(8)
    analyzed = _analyze(tmp_path, builder, disabled_model_assumptions=(LABEL,))
    assert not _last_read(analyzed, builder).result.is_complete
    assert LABEL not in analyzed.inherited_assumptions
    assert any(label.startswith("external-model:nonstack-test/GetObj@") for label in analyzed.declared.values())


def test_switching_the_label_off_removes_the_identity_rows_window_too(tmp_path):
    """same-result-functions on: the accessor identity row loses the window as
    the plain row does."""
    builder = _caller(8)
    analyzed = _analyze(tmp_path, builder, assume_same_result_functions=True, disabled_model_assumptions=(LABEL,))
    assert not _last_read(analyzed, builder).result.is_complete
    assert LABEL not in analyzed.inherited_assumptions


def test_a_realloc_like_call_of_the_result_keeps_no_window(tmp_path):
    builder = _caller(8, move=True)
    analyzed = _analyze(tmp_path, builder)
    assert not _last_read(analyzed, builder).result.is_complete


def test_without_an_identity_the_value_still_gets_its_window(tmp_path, monkeypatch):
    """same-result-functions on, but no accessor key can be made (Astra,
    design D round 2): the plain value keeps the window."""
    from tdo_v2 import relative_memory

    monkeypatch.setattr(relative_memory._Projector, "_same_result_key", lambda self, row, size: None)
    builder = _caller(8)
    analyzed = _analyze(tmp_path, builder, assume_same_result_functions=True)
    assert _last_read(analyzed, builder).result.is_complete


@pytest.mark.parametrize("change, problem", [
    ({"result_nonstack": {"result": [RAX, 8], "extent": 0x40}}, "no label"),
    ({"result_nonstack": {**WINDOW, "rests_on": "other-file:off-stack"}}, "another file's label"),
    ({"result_nonstack": {**WINDOW, "rests_on": "nonstack-test:undeclared"}}, "undeclared"),
    ({"result_nonstack": {**WINDOW, "extent": 0}}, "empty extent"),
    ({"result_nonstack": {**WINDOW, "result": [RCX, 8]}}, "not a register write"),
    ({"same_result": {"result": [RAX, 8], "inputs": [], "reads": [SLOT], "nonstack": True}}, "old nonstack"),
])
def test_a_result_nonstack_entry_is_validated(tmp_path, change, problem):
    with pytest.raises(ModelError):
        _models(tmp_path, _get(**change))


def test_the_oracle_finds_nothing_silent_with_heap_results(tmp_path):
    """A real getter returning a heap block: no read is silently missed."""
    builder = _caller(8)
    analyzed = _analyze(tmp_path, builder)
    (getter,) = program_units(FunctionBuilder(entry=GET).ins(load(reg(RAX), reg(RCX))).ret())
    (touch,) = program_units(FunctionBuilder(entry=TOUCH).ret())
    report = check_program(analyzed.normalized, analyzed.unit.observation,
                           {(1, GET): getter.observation, (1, TOUCH): touch.observation},
                           seeds=range(6),
                           register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                           havoc_calls=(REG, RSP, 8))
    assert report.silent == []


def test_the_oracle_catches_a_getter_breaking_the_contract(tmp_path):
    """A getter returning its own stack: [r + 8] is then the slot the next
    CALL pushes its return address into -- the window rests on the claim,
    and a run breaking it is caught (the claim, not luck, is load-bearing)."""
    builder = _caller(8)
    analyzed = _analyze(tmp_path, builder)
    assert _last_read(analyzed, builder).result.is_complete
    (getter,) = program_units(FunctionBuilder(entry=GET).ins(sub(reg(RAX), reg(RSP), const(8))).ret())
    (touch,) = program_units(FunctionBuilder(entry=TOUCH).ret())
    report = check_program(analyzed.normalized, analyzed.unit.observation,
                           {(1, GET): getter.observation, (1, TOUCH): touch.observation},
                           seeds=range(4),
                           register_pools=lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000},
                           havoc_calls=(REG, RSP, 8))
    assert report.silent != []


# -- joins, wrappers, write-back, image-relative accesses (Astra, impl review) --

def _get2(extent):
    return {**_get(result_nonstack={**WINDOW, "extent": extent}), "name": "GetObj2"}


def _joined(offset, other):
    """rdx == 0: rbp = Get(rbx) (window 0x40); else ``other`` -- then
    Touch() (a push) and r9 = [rbp + offset]."""
    builder = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), reg(RBX)))
    builder.cbranch("other", tmp(0x300, 1), op("INT_NOTEQUAL", [reg(RDX), const(0)], tmp(0x300, 1)))
    builder.call(GET).ins(copy(reg(RBP), reg(RAX))).branch("join")
    builder.label("other")
    other(builder)
    builder.label("join").call(TOUCH)
    builder.ins(add(T, reg(RBP), const(offset)), load(reg(R9), T))
    return builder.add_rsp(0x28).ret()


def _second_getter(builder):
    builder.call(GET2).ins(copy(reg(RBP), reg(RAX)))


@pytest.mark.parametrize("offset, complete", [(8, True), (0x18, False)])
def test_a_join_of_two_windows_keeps_the_smaller(tmp_path, offset, complete):
    """Windows 0x40 and 0x10 joined: 0x10 (an access at 0x18 is outside)."""
    builder = _joined(offset, _second_getter)
    analyzed = _analyze(tmp_path, builder, more=[_get2(0x10)])
    assert _last_read(analyzed, builder).result.is_complete is complete


def test_a_join_with_a_null_path_has_no_window(tmp_path):
    """rbp = 0 on the other path: the contract covers GetObj's results only."""
    builder = _joined(8, lambda builder: builder.ins(copy(reg(RBP), const(0))))
    analyzed = _analyze(tmp_path, builder)
    assert not _last_read(analyzed, builder).result.is_complete


def test_a_wrapper_exports_no_window(tmp_path):
    """w() returns GetObj's result: the caller of w gets no window (this
    function only, docs 25.75)."""
    wrapper = FunctionBuilder(entry=WRAP).sub_rsp(0x28).call(GET).add_rsp(0x28).ret()
    builder = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), reg(RBX))).call(WRAP)
               .ins(copy(reg(RBP), reg(RAX))).call(TOUCH)
               .ins(add(T, reg(RBP), const(8)), load(reg(R9), T)).add_rsp(0x28).ret())
    analyzed = _analyze(tmp_path, builder, others=(wrapper,))
    assert not _last_read(analyzed, builder).result.is_complete
    assert LABEL not in analyzed.inherited_assumptions


def test_a_written_back_slot_reloaded_has_no_window(tmp_path):
    """The slot's new value (write-back) is a value of its own: reloading
    it gives no window, though it equals the result."""
    get = _get(memory=[{"write": SLOT, "from": [[RCX, 8]], "loads": [SLOT]}],
               same_result={"result": [RAX, 8], "inputs": [], "reads": [SLOT], "write_back": True})
    builder = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), reg(RBX))).call(GET)
               .ins(load(reg(RBP), reg(RBX))).call(TOUCH)
               .ins(add(T, reg(RBP), const(8)), load(reg(R9), T)).add_rsp(0x28).ret())
    analyzed = _analyze(tmp_path, builder, get=get, assume_same_result_functions=True)
    assert not _last_read(analyzed, builder).result.is_complete


@pytest.mark.parametrize("tracking", [False, True])
def test_an_image_relative_access_refuses_the_window(tmp_path, tracking):
    """rbp + DATA_BASE - (DATA_BASE - 8): under image-base tracking, with
    DATA_BASE a relocating address and the other a fixed number, the access
    is at rbp + 8 only for one load address -- its object's window is refused,
    so the ordinary read [rbp + 8] after it is not kept apart either."""
    from contextlib import nullcontext

    from tdo_v2.relative_memory import ImageBaseTracking

    builder = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), reg(RBX))).call(GET)
               .ins(copy(reg(RBP), reg(RAX))).call(TOUCH)
               .ins(add(T, reg(RBP), const(DATA_BASE)), sub(T, T, const(DATA_BASE - 8)), load(reg(RDX), T))
               .ins(add(T, reg(RBP), const(8)), load(reg(R9), T)).add_rsp(0x28).ret())
    with (ImageBaseTracking(((CODE_BASE, DATA_BASE + 0x1000),), lambda address, length, value: value == DATA_BASE)
          if tracking else nullcontext()):
        analyzed = _analyze(tmp_path, builder)
    assert _last_read(analyzed, builder).result.is_complete is not tracking
