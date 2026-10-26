"""Named assumption opaque-callees-leave-no-stack-addresses (docs 25.29): an
opaque call (no proven effect) is a stack escape only when a register it may
see holds a stack-derived value -- its own stack-derived results are assumed
away. Off: every opaque call is an escape. Reported per use: a byte decided
private only because the opaque calls were not escapes."""

from synthetic import (
    CODE_BASE, RAX, RBX, RCX, RDI, RDX, RSP, FunctionBuilder, add, const, load, op, program_units, reg,
    slice_from, store, tmp,
)
from test_index_addresses import _load_node
from tdo_v2.interprocedural import analyze_units
from tdo_v2.may_alias import OPAQUE_NO_STACK_ADDRESSES
from tdo_v2.summary_engine import run_assumptions

NAME = "opaque-callees-leave-no-stack-addresses"
OPAQUE = CODE_BASE + 0xF00     # not in the program: an opaque callee


def _function(stack_argument=False):
    """[rsp+0x10] = rbx; [rdi - 0x38] = rdx; (rcx = rsp+8;) call opaque;
    rax = [rsp+0x10]. The write is through an entry value, before the call
    (after it rdi would be a call result: a wild base, never kept out); the
    read after the call is private only if the call is no escape."""
    t, u = tmp(0x100), tmp(0x200)
    builder = (FunctionBuilder().sub_rsp(0x40)
               .ins(add(t, reg(RSP), const(0x10)), store(t, reg(RBX)))
               .ins(add(u, reg(RDI), const(-0x38 % (1 << 64))), store(u, reg(RDX))))
    if stack_argument:
        builder.ins(add(reg(RCX), reg(RSP), const(8)))
    builder.call(OPAQUE)
    reload = len(builder._rows)
    builder.ins(add(t, reg(RSP), const(0x10)), load(reg(RAX), t)).add_rsp(0x40).ret()
    return builder, reload


def _analyzed(builder, on=True):
    results = analyze_units(program_units(builder), assume_opaque_callees_leave_no_stack_addresses=on)
    return results, results["1:1000"]


def _reaches_rdx(analyzed, reload):
    """The write through rdi may land on the slot (the opaque call's own
    clobber of memory is a debt either way: completeness says nothing here)."""
    found = slice_from(analyzed.normalized, _load_node(analyzed.normalized, reload))
    return bool(set(range(RDX, RDX + 8)) & found.register_bytes)


def test_on_the_frame_slot_stays_private_across_the_opaque_call_and_the_assumption_is_reported():
    builder, reload = _function()
    results, analyzed = _analyzed(builder, True)
    assert not _reaches_rdx(analyzed, reload)
    assert analyzed.normalized.assumes_opaque_callees_leave_no_stack_addresses
    assert NAME in run_assumptions(results)


def test_off_the_opaque_call_is_an_escape():
    builder, reload = _function()
    results, analyzed = _analyzed(builder, False)
    assert _reaches_rdx(analyzed, reload)
    assert not analyzed.normalized.assumes_opaque_callees_leave_no_stack_addresses
    assert NAME not in run_assumptions(results)
    assert OPAQUE_NO_STACK_ADDRESSES.get() is True   # reset after the run


def test_not_reported_when_the_call_escapes_anyway():
    """rcx holds a frame address at the call: it is an escape with or without
    the assumption -- no decision rests on it."""
    builder, reload = _function(stack_argument=True)
    results, analyzed = _analyzed(builder, True)
    assert _reaches_rdx(analyzed, reload)
    assert not analyzed.normalized.assumes_opaque_callees_leave_no_stack_addresses
    assert NAME not in run_assumptions(results)


def test_not_reported_without_an_opaque_call():
    from test_frame_assumption import _below_the_caller

    results = analyze_units(program_units(_below_the_caller()))
    assert results["1:1000"].normalized.assumes_entry_values_not_frame
    assert NAME not in run_assumptions(results)


# -- templates (Astra, step A review 2: keep as regressions) ---------------------------

def _consume(tmp_path, body, *, derive_on, run_on):
    """Derive F's template with the assumption ``derive_on``; apply it in a
    run with it ``run_on`` (as test_frame_assumption._consume)."""
    import json
    from pathlib import Path

    from test_summary_templates import (
        F, LIBRARY, MANGLED, THUNK, WIN64, _caller_writes, _every_constant_relocates, _hand_file,
    )
    from tdo_v2.image_info import ExportedSymbol, ImageInfo, ImportedSymbol
    from tdo_v2.relative_memory import ImageBaseTracking
    from tdo_v2.summary_store import load_external_models
    from tdo_v2.summary_templates import build_file

    hand = _hand_file(tmp_path)
    models = load_external_models([hand], *WIN64)
    info = ImageInfo("synthetic", (), (), (ExportedSymbol(1, F, MANGLED, True),), ())
    with ImageBaseTracking(((0x1000, 0x8000),), _every_constant_relocates) as found:
        results = analyze_units(program_units(body), image_info=info, external_models=models, own_library=LIBRARY,
                                assume_opaque_callees_leave_no_stack_addresses=derive_on)
    raw, refused = build_file(results, [(f"1:{F:x}", "F", [MANGLED])], file_id="synth-derived", version=1,
                              library=LIBRARY, external_models=models, pcodeop_models=None,
                              private_frame_above=0, base_dependent=found)
    assert not refused, refused
    path = Path(tmp_path) / "derived.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    models = load_external_models([hand, path], *WIN64)
    info = ImageInfo("synthetic", (), (ImportedSymbol(LIBRARY, "F", MANGLED, (), ((1, THUNK),)),), (), ())
    return raw, analyze_units(program_units(_caller_writes(THUNK)), image_info=info, external_models=models,
                              assume_opaque_callees_leave_no_stack_addresses=run_on)["1:1000"]


def _body_with_an_opaque_call():
    """F: [rsp+8] = rcx (its frame); [rdx - 0x38] = r8; call opaque; rax = rcx."""
    from test_summary_templates import F

    t, u = tmp(0x100), tmp(0x200)
    return (FunctionBuilder(entry=F).sub_rsp(0x28)
            .ins(add(t, reg(RSP), const(8)), store(t, reg(RCX)))
            .ins(add(u, reg(RDX), const(-0x38 % (1 << 64))), store(u, reg(0x80)))
            .call(CODE_BASE + 0xF80)
            .ins(add(t, reg(RSP), const(8)), load(reg(RAX), t))
            .add_rsp(0x28).ret())


def test_a_template_resting_on_it_carries_the_label_and_is_refused_with_it_off(tmp_path):
    raw, analyzed = _consume(tmp_path, _body_with_an_opaque_call(), derive_on=True, run_on=False)
    assert NAME in raw["source"]["assumptions"]
    assert not analyzed.proven
    (reason,) = analyzed.refused_models.values()
    assert NAME in reason


def test_a_template_resting_on_it_applies_with_it_on(tmp_path):
    raw, analyzed = _consume(tmp_path, _body_with_an_opaque_call(), derive_on=True, run_on=True)
    assert NAME in raw["source"]["assumptions"] and analyzed.proven


def test_a_template_of_an_older_engine_is_refused(tmp_path):
    """Version 10 templates rest on the assumption unlabelled (docs 25.29)."""
    import json

    from tdo_v2.summary_store import load_model_file
    from tdo_v2.summary_templates import refusal

    raw, _ = _consume(tmp_path, _body_with_an_opaque_call(), derive_on=True, run_on=True)
    raw["source"]["engine"]["semantics_version"] = 10
    path = tmp_path / "old.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    from test_summary_templates import WIN64, _hand_file
    from tdo_v2.summary_store import load_external_models

    models = load_external_models([_hand_file(tmp_path), path], *WIN64)
    old = next(item for item in models.files if item.file_id == "synth-derived")
    assert old.entries[0].refusal is not None or refusal(
        old, old.entries[0], external_models=models, pcodeop_models=None, private_frame_above=0,
        language=("x86:LE:64:default", 1, 0)) is not None


# -- per-use reporting paths ---------------------------------------------------------------

def _reported(builder):
    results = analyze_units(program_units(builder))
    return results["1:1000"].normalized.assumes_opaque_callees_leave_no_stack_addresses


def _entry_write(builder):
    """[rdi - 0x38] = rdx: a write through an entry value -- a frame read it
    may reach is decided by the private-frame rule (no other object: no
    decision to make, nothing reported)."""
    u = tmp(0x200)
    return builder.ins(add(u, reg(RDI), const(-0x38 % (1 << 64))), store(u, reg(RDX)))


def test_a_frame_read_before_the_only_opaque_call_does_not_rest_on_it():
    t = tmp(0x100)
    read_first = _entry_write(FunctionBuilder().sub_rsp(0x40))
    read_first.ins(add(t, reg(RSP), const(0x10)), load(reg(RAX), t)).call(OPAQUE)
    # (the CALL's push is a frame write at the opaque call itself
    # (``normalize._push_row``): keeping it from other objects is a decision
    # that rests on the assumption -- reported, as for any frame write there)
    assert _reported(read_first.add_rsp(0x40).ret())


def test_a_frame_write_before_an_opaque_call_rests_on_it():
    t = tmp(0x100)
    write_first = (FunctionBuilder().sub_rsp(0x40)
                   .ins(add(t, reg(RSP), const(0x10)), store(t, reg(RBX)))
                   .call(OPAQUE).add_rsp(0x40).ret())
    assert _reported(write_first)


def test_a_loop_through_the_opaque_call_rests_on_it():
    """The read precedes the call in the block, but the loop brings the call
    before it on the next iteration."""
    t, flag = tmp(0x100), tmp(0x300, 1)
    builder = _entry_write(FunctionBuilder().sub_rsp(0x40)).label("top")
    builder.ins(add(t, reg(RSP), const(0x10)), load(reg(RAX), t))
    builder.call(OPAQUE)
    builder.cbranch("top", flag, op("INT_NOTEQUAL", [reg(RBX), const(0)], flag))
    assert _reported(builder.add_rsp(0x40).ret())
