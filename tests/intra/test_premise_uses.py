"""2b-P part b: normalization records the named assumptions it decided under
(docs 25.91) -- policy switches stay inputs; use records say which were used."""

import pytest

from synthetic import RAX, FunctionBuilder, const, copy, load, program_units, reg, store
from tdo_v2.interprocedural import analyze_units

MAIN = 0x1000


def _uses(builder, **options):
    (result,) = analyze_units(program_units(builder), **options).values()
    return {name for name, stage, _ in result.normalized.premise_uses if stage == "normalize"}


def test_globals_disjoint_is_recorded_only_when_it_excluded_an_alias():
    main = FunctionBuilder(entry=MAIN).ins(store(const(0x4000), const(1, 8))).ret()
    assert "globals-disjoint-from-stack" in _uses(main, assume_globals_disjoint_from_stack=True)
    assert "globals-disjoint-from-stack" not in _uses(main, assume_globals_disjoint_from_stack=False)


def test_a_function_that_never_needs_it_does_not_list_it():
    main = FunctionBuilder(entry=MAIN).ins(copy(reg(RAX), const(1))).ret()
    assert _uses(main, assume_globals_disjoint_from_stack=True) == set()


def test_home_space_is_recorded_when_a_byte_above_entry_sp_was_decided_private():
    """Astra 2b-P r1: `store [entry RAX], 1; ret` is PROVEN only with the
    home space private -- its support must name it."""
    main = FunctionBuilder(entry=MAIN).ins(store(reg(RAX), const(1, 8))).ret()
    with_home = _uses(main, private_frame_above=0x28)
    without = _uses(main, private_frame_above=0)
    assert "win64-home-space-callee-private" in with_home
    assert "win64-home-space-callee-private" not in without


def test_a_readonly_image_read_is_recorded_where_it_was_read():
    """A pointer loaded from .rdata and dereferenced: its constant value came
    from the image (the read address is where)."""
    from synthetic import DATA_BASE, RBX, synthetic_image

    data = bytearray(4096)
    data[8:16] = (DATA_BASE + 0x20).to_bytes(8, "little")
    info, image = synthetic_image(data=bytes(data))
    main = FunctionBuilder(entry=MAIN).ins(load(reg(RAX), const(DATA_BASE + 8))).ins(load(reg(RBX), reg(RAX))).ret()
    (result,) = analyze_units(program_units(main), image_info=info, readonly_image=image).values()
    found = [(name, at) for name, stage, at in result.normalized.premise_uses
             if name == "readonly-image-data-is-constant"]
    assert found and all(at.endswith(f"{DATA_BASE + 8:x}") for _, at in found), result.normalized.premise_uses
    (plain,) = analyze_units(program_units(main), image_info=info).values()
    assert not any(name == "readonly-image-data-is-constant" for name, _, _ in plain.normalized.premise_uses)


def test_the_recording_image_notes_only_values_it_returned():
    from tdo_v2.normalize import _RecordingImage

    class Inner:
        size = 3

        def value(self, space, offset, size):
            return 7 if offset == 0x10 else None

    uses = []
    image = _RecordingImage(Inner(), uses)
    assert image.value(1, 0x10, 8) == 7 and image.value(1, 0x20, 8) is None and image.size == 3
    assert uses == ["1:10"]


@pytest.mark.parametrize("engine", ["sparse", "dense"])
def test_a_held_slot_above_entry_sp_records_the_home_space(engine, monkeypatch):
    """Astra 2b-P r1 P1: the held-slot decision admits [rsp + 8] = rsp only
    with the home space private; it keeps a below-SP read private, and a later
    escape keeps the return read from recording it incidentally."""
    from synthetic import RCX, RDI, RSP, R9, DATA_BASE, add, tmp

    if engine == "dense":
        monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", "dense")
    main = (FunctionBuilder(entry=MAIN)
            .ins(add(tmp(0x100), reg(RSP), const(8)), store(tmp(0x100), reg(RSP)))
            .ins(store(reg(RCX), reg(RDI)))
            .ins(add(tmp(0x108), reg(RSP), const(-8 & 0xFFFFFFFFFFFFFFFF)), load(reg(R9), tmp(0x108)))
            .ins(store(const(DATA_BASE + 0x10), reg(RSP)))
            .ret())
    with_home = _uses(main, private_frame_above=0x28)
    assert "win64-home-space-callee-private" in with_home, with_home
    assert "win64-home-space-callee-private" not in _uses(main, private_frame_above=0)


def test_the_summary_records_its_own_globals_disjoint_exclusion():
    """b2: the summary's exit crossings exclude a constant-address write from
    the stack object under globals-disjoint -- a summary-stage use."""
    from synthetic import RSP, sub as isub

    main = (FunctionBuilder(entry=MAIN).sub_rsp(0x18)
            .ins(store(reg(RSP), const(7, 8)), store(const(0x4000), const(1, 8))).add_rsp(0x18).ret())
    (result,) = analyze_units(program_units(main), assume_globals_disjoint_from_stack=True).values()
    assert ("globals-disjoint-from-stack", "summary") in {(n, s) for n, s, _ in result.summary.premise_uses}
    (plain,) = analyze_units(program_units(main), assume_globals_disjoint_from_stack=False).values()
    assert not plain.summary.premise_uses


@pytest.mark.parametrize("forward", ["0", "1"])
def test_a_caller_side_discharge_under_globals_disjoint_is_recorded(forward, monkeypatch):
    """b2: the callee writes [rcx] then reads a global -- its result holds
    while that write misses the global (a writer condition); the caller passes
    a stack address and discharges it only under globals-disjoint. With forward
    facts the condition is settled before any caller discharge: the assumption
    is then recorded at the normalization instead -- recorded either way."""
    monkeypatch.setenv("TDO_V2_FORWARD", forward)
    from synthetic import CODE_BASE, DATA_BASE, RCX, RSP, add

    leaf = (FunctionBuilder(entry=CODE_BASE + 0x800)
            .ins(store(reg(RCX), const(1, 8))).ins(load(reg(RAX), const(DATA_BASE + 0x20))).ret())
    caller = (FunctionBuilder(entry=MAIN).sub_rsp(0x28)
              .ins(add(reg(RCX), reg(RSP), const(8))).call(CODE_BASE + 0x800).add_rsp(0x28).ret())

    def uses(flag):
        results = analyze_units(program_units(caller, leaf), assume_globals_disjoint_from_stack=flag)
        (main,) = [item for key, item in results.items() if key.endswith(f"{MAIN:x}")]
        return {(name, stage) for name, stage, _ in main.normalized.premise_uses}

    on, off = uses(True), uses(False)
    if forward == "0":
        assert ("globals-disjoint-from-stack", "condition-discharge") in on, on
    assert any(name == "globals-disjoint-from-stack" for name, _ in on), on
    assert not any(name == "globals-disjoint-from-stack" for name, _ in off), off


def _opaque_caller():
    """sub rsp; [rsp] = 7; call opaque; rax = [rsp]; add rsp; ret -- the slot
    read after the call is addressed through the call-shape stack pointer."""
    from synthetic import CODE_BASE, RSP

    return (FunctionBuilder(entry=MAIN).sub_rsp(0x28).ins(store(reg(RSP), const(7, 8)))
            .call(CODE_BASE + 0xC00).ins(load(reg(RAX), reg(RSP))).add_rsp(0x28).ret())


def test_an_opaque_calls_kept_stack_pointer_is_a_recorded_use():
    (result,) = analyze_units(program_units(_opaque_caller())).values()
    found = [(stage, at) for name, stage, at in result.normalized.premise_uses
             if name == "opaque-callees-restore-stack-pointer"]
    assert found and all(at.endswith(":CALL") for _, at in found), result.normalized.premise_uses


def test_switching_opaque_restores_sp_off_disables_the_inference():
    """B6: OFF is not a label change -- the stack pointer after the opaque call
    is call-clobbered (more debt), and nothing records the assumption."""
    (on,) = analyze_units(program_units(_opaque_caller())).values()
    (off,) = analyze_units(program_units(_opaque_caller()),
                           assume_opaque_callees_restore_stack_pointer=False).values()
    assert not any(name == "opaque-callees-restore-stack-pointer" for name, _, _ in off.normalized.premise_uses)
    assert off.normalized.assumes_opaque_callees_restore_stack_pointer is False
    assert len(off.normalized.call_clobber_debts) > len(on.normalized.call_clobber_debts)


def test_the_switch_is_registered_and_disables_dependent_models():
    from tdo_v2.assumptions import by_name, disabled

    row = by_name("opaque-callees-restore-stack-pointer")
    assert row.kind == "switch" and row.parameter == "assume_opaque_callees_restore_stack_pointer"
    base = dict(globals_disjoint=True, readonly_image=True, direction_flag=True, entry_values_not_frame=True,
                home_space=True, opaque_no_stack=True, traps=True, import_slots=True, same_result=True,
                accessor_separate=True, accessor_private_state=True, registered_handlers=True)
    assert "opaque-callees-restore-stack-pointer" in disabled(**base, opaque_restores_sp=False)
    assert "opaque-callees-restore-stack-pointer" not in disabled(**base)


def test_the_linker_takes_the_switch():
    """Astra B6 r1 P1-1: summary_engine passes opaque_restores_sp to the linker,
    whose signature did not accept it (a TypeError either way)."""
    import inspect

    from tdo_v2.linking import Linker

    assert "opaque_restores_sp" in inspect.signature(Linker.__call__).parameters


def _sp_then_unknown_jump():
    """Astra B6 r1 P1-2: mov rax, rsp; call opaque; jmp rax (no RETURN)."""
    from synthetic import CODE_BASE, RSP, _Instruction, op

    main = FunctionBuilder(entry=MAIN).ins(copy(reg(RAX), reg(RSP))).call(CODE_BASE + 0xC00)
    main._rows.append(_Instruction([op("BRANCHIND", [reg(RAX)])], "return"))
    raw = main.to_json

    def jump():
        data = raw()
        last = data["instructions"][-1]
        last["flow_type"] = {key: key in ("is_flow", "is_jump", "is_computed", "is_unconditional")
                             for key in last["flow_type"]}
        return data

    main.to_json = jump
    return main


def test_off_the_summary_does_not_export_a_restored_stack_pointer():
    """Astra B6 r1 P1-2: the summary's exit crossings read the call shape's
    stack pointer directly -- OFF must neither export it as delta 0 nor list it
    preserved by the opaque call."""
    sp = (0x20, 8)
    (on,) = analyze_units(program_units(_sp_then_unknown_jump())).values()
    (off,) = analyze_units(program_units(_sp_then_unknown_jump()),
                           assume_opaque_callees_restore_stack_pointer=False).values()
    assert dict(on.summary.register_deltas).get(sp) == 0
    assert sp not in dict(off.summary.register_deltas), off.summary.register_deltas
    assert all(not kept for _, kept, *_ in off.summary.inner_calls)


def test_off_is_captured_for_replay(monkeypatch):
    """Astra B6 r1 P1-3: the replay policy keeps the switch."""
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    (off,) = analyze_units(program_units(_opaque_caller()),
                           assume_opaque_callees_restore_stack_pointer=False).values()
    assert len(off.normalization_context) == 9 and off.normalization_context[-1] is False


def test_off_switches_dependent_models_off(monkeypatch):
    """Astra B6 r1 P1-4: the in-run model filter learns the switch."""
    from tdo_v2 import assumptions

    seen = []
    original = assumptions.disabled

    def spy(**kwargs):
        seen.append(kwargs.get("opaque_restores_sp", True))
        return original(**kwargs)

    monkeypatch.setattr(assumptions, "disabled", spy)
    analyze_units(program_units(_opaque_caller()), assume_opaque_callees_restore_stack_pointer=False)
    assert seen and not any(seen)


def test_a_failed_function_reports_the_runs_own_switch():
    """Astra B6 r1 P2: an unresolved normalization has no recorded policy."""
    from types import SimpleNamespace
    from tdo_v2.summary_engine import run_assumptions

    (on,) = analyze_units(program_units(_opaque_caller())).values()
    failed = SimpleNamespace(normalized=SimpleNamespace(), unit=on.unit, proven={}, superseded=None,
                             declared={}, inherited_assumptions=frozenset(), summary_inputs=((), (), ()))
    assert "opaque-callees-restore-stack-pointer" not in run_assumptions({"f": failed}, opaque_restores_sp=False)


def test_a_failed_function_keeps_the_switch_it_failed_under(monkeypatch):
    """Astra B6 r2 P2: a report after the run (template source.assumptions)
    must read the failure's own switch, not the reset ambient one."""
    from tdo_v2.normalize import UnresolvedNormalizedFunction
    from tdo_v2.summary_engine import run_assumptions

    monkeypatch.setenv("TDO_V2_FUNCTION_WORK", "1")
    results = analyze_units(program_units(_opaque_caller()), assume_opaque_callees_restore_stack_pointer=False)
    (item,) = results.values()
    assert type(item.normalized) is UnresolvedNormalizedFunction, item.normalized
    assert item.normalized.assumes_opaque_callees_restore_stack_pointer is False
    assert "opaque-callees-restore-stack-pointer" not in run_assumptions(results)


def test_an_assumed_or_pcodeop_effect_is_an_admission_use():
    """Astra 2b-P b79 r1 P2-3: a no-effect p-code op model (an assumed call
    effect) is applied like a model -- recorded at its call."""
    from synthetic import op
    from tdo_v2.assumed_call_effects import AssumedCallEffect

    main = FunctionBuilder(entry=MAIN).ins(op("CALLOTHER", [const(17, 4)])).ret()
    key, label = "1:1000:0:CALLOTHER", "pcodeop-model:x86-markers/LOCK@v1"
    (result,) = analyze_units(program_units(main),
                              assumed_call_effects={"1:1000": {key: AssumedCallEffect(label, ())}}).values()
    assert (label, "admission", key) in result.normalized.premise_uses, result.normalized.premise_uses
