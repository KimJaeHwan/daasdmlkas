"""Named assumption entry-values-do-not-address-the-new-frame (docs 25.9):
the private-frame rule of ``may_alias``, now a switch reported per use."""

from graph_oracle import check
from synthetic import (
    CODE_BASE, RAX, RBX, RDI, RDX, RSP, FunctionBuilder, add, const, load, program_units, reg, slice_from, store,
    tmp,
)
from tdo_v2.interprocedural import analyze_units
from tdo_v2.may_alias import ENTRY_VALUES_NOT_FRAME
from tdo_v2.summary_engine import run_assumptions

NAME = "entry-values-do-not-address-the-new-frame"


def _below_the_caller(displacement=-0x38 % (1 << 64)):
    """[rsp+0x10] = rbx; [rdi - 0x38] = rdx; rax = [rsp+0x10]. With rdi = entry
    sp + 8 (a pointer into the caller's frame) rdi - 0x38 is that frame slot."""
    t, u = tmp(0x100), tmp(0x200)
    return (FunctionBuilder().sub_rsp(0x40)
            .ins(add(t, reg(RSP), const(0x10)), store(t, reg(RBX)))
            .ins(add(u, reg(RDI), const(displacement)), store(u, reg(RDX)))
            .ins(add(t, reg(RSP), const(0x10)), load(reg(RAX), t))
            .add_rsp(0x40).ret())


def _analyzed(builder, on):
    (unit,) = program_units(builder)
    results = analyze_units([unit], assume_entry_values_not_frame=on)
    return results, results["1:1000"]


def _reload(analyzed):
    from test_index_addresses import _load_node

    return slice_from(analyzed.normalized, _load_node(analyzed.normalized, 3))


def _bytes(register):
    return set(range(register, register + 8))


def _pools(seed):
    return {RSP: 0x7000_0000, RDI: 0x7000_0008, RBX: 0x1111, RDX: 0x2222}


def test_on_the_frame_slot_is_private_and_the_assumption_is_reported():
    results, analyzed = _analyzed(_below_the_caller(), True)
    found = _reload(analyzed)
    assert found.is_complete and not _bytes(RDX) & found.register_bytes
    assert analyzed.normalized.assumes_entry_values_not_frame
    assert NAME in run_assumptions(results)
    # the assumption's failure case: rdi = entry sp + 8 makes the write land there
    report = check(analyzed.normalized, analyzed.unit.observation, seeds=range(2), register_pools=_pools)
    assert report.silent


def test_off_no_byte_is_private():
    results, analyzed = _analyzed(_below_the_caller(), False)
    found = _reload(analyzed)
    assert _bytes(RDX) <= found.register_bytes and not found.is_complete
    assert not analyzed.normalized.assumes_entry_values_not_frame
    labels = run_assumptions(results, home_space=0x28)
    assert NAME not in labels and "win64-home-space-callee-private" not in labels
    report = check(analyzed.normalized, analyzed.unit.observation, seeds=range(2), register_pools=_pools)
    assert report.runs and report.silent == []


def test_the_switch_is_reset_after_the_run():
    _analyzed(_below_the_caller(), False)
    assert ENTRY_VALUES_NOT_FRAME.get() is True


def test_a_function_that_never_decides_a_private_byte_does_not_report_it():
    """No frame access: the rule is never used -- a template derived from it
    stays applicable in runs with the assumption off."""
    results, analyzed = _analyzed(FunctionBuilder().ins(store(reg(RDI), reg(RDX))).ret(), True)
    assert not analyzed.normalized.assumes_entry_values_not_frame
    labels = run_assumptions(results, home_space=0x28)
    assert NAME not in labels and "win64-home-space-callee-private" not in labels


def test_off_a_callee_frame_write_still_keeps_the_caller_memory():
    """The caller-side exclusion of a callee's own frame is structural (below
    the call-time stack pointer), not this assumption."""
    callee = (FunctionBuilder(entry=CODE_BASE + 0x800).sub_rsp(0x28)
              .ins(add(tmp(0x200), reg(RSP), const(8)), store(tmp(0x200), reg(RDX)))
              .add_rsp(0x28).ret())
    caller = FunctionBuilder().sub_rsp(0x28).call(CODE_BASE + 0x800).add_rsp(0x28).ret()
    results = analyze_units(program_units(caller, callee), assume_entry_values_not_frame=False)
    (effect,) = [effect for key, effect in results["1:1000"].proven.items() if key.endswith(":CALL")]
    assert effect.preserves_memory


def _consume(tmp_path, body, *, derive_on, run_on):
    """Derive F's template with the frame assumption ``derive_on``, apply it
    in a run with it ``run_on``: the caller's analysis."""
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
                                assume_entry_values_not_frame=derive_on)
    raw, refused = build_file(results, [(f"1:{F:x}", "F", [MANGLED])], file_id="synth-derived", version=1,
                              library=LIBRARY, external_models=models, pcodeop_models=None,
                              private_frame_above=0, base_dependent=found)
    assert not refused, refused
    path = Path(tmp_path) / "derived.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    models = load_external_models([hand, path], *WIN64)
    info = ImageInfo("synthetic", (), (ImportedSymbol(LIBRARY, "F", MANGLED, (), ((1, THUNK),)),), (), ())
    return raw, analyze_units(program_units(_caller_writes(THUNK)), image_info=info, external_models=models,
                              assume_entry_values_not_frame=run_on)["1:1000"]


def _spilling_body():
    """F: [rsp+8] = rcx (its own frame); rax = [rsp+8] -- decides a private byte."""
    from test_summary_templates import F

    t = tmp(0x100)
    return (FunctionBuilder(entry=F).sub_rsp(0x18)
            .ins(add(t, reg(RSP), const(8)), store(t, reg(0x08)))
            .ins(add(t, reg(RSP), const(8)), load(reg(RAX), t))
            .add_rsp(0x18).ret())


def test_a_template_resting_on_the_rule_is_refused_with_it_off_and_the_reason_recorded(tmp_path):
    raw, analyzed = _consume(tmp_path, _spilling_body(), derive_on=True, run_on=False)
    assert NAME in raw["source"]["assumptions"]
    assert not analyzed.proven
    (reason,) = analyzed.refused_models.values()
    assert NAME in reason and "switched off" in reason


def test_the_template_matrix(tmp_path):
    """derived on and used -> applies on; derived off -> applies off and on;
    derived on but never deciding a private byte -> applies off."""
    from test_summary_templates import F

    plain = FunctionBuilder(entry=F).ins(add(reg(RAX), reg(0x08), const(1))).ret()
    for body, derive_on, run_on in ((_spilling_body(), True, True), (_spilling_body(), False, False),
                                    (_spilling_body(), False, True), (plain, True, False)):
        directory = tmp_path / f"{derive_on}-{run_on}-{len(body._rows)}"
        directory.mkdir()
        raw, analyzed = _consume(directory, body, derive_on=derive_on, run_on=run_on)
        assert analyzed.proven, (derive_on, run_on, analyzed.refused_models)
        assert (NAME in raw["source"]["assumptions"]) == (derive_on and body is not plain)
