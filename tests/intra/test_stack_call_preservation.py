"""Raw leaf identity replaces a particular ABI exception, not all calls."""

import pytest

from synthetic import (RBP, RSP, RAX, RBX, REG, CODE_BASE, DATA_BASE, FunctionBuilder,
                       add, const, copy, reg, store, program_units)
from tdo_v2.interprocedural import program_switches_stack
from tdo_v2 import may_alias
from tdo_v2 import _stack_preservation as proof

LEAF = CODE_BASE + 0x800


def _check(leaf, *, first=False, width=8):
    caller = FunctionBuilder()
    if not first:
        caller.ins(copy(reg(RBP), reg(RSP)))
    caller.call(LEAF)
    if first:
        caller.ins(add(reg(RSP), reg(RSP), reg(RBP, width)))
    else:
        caller.ins(copy(reg(RSP), reg(RBP)))
    caller.ret()
    notes = {}
    found = program_switches_stack(program_units(caller, leaf), call_evidence=notes)
    return found, notes


def _statuses(notes, start=RBP, size=8):
    return {value[1] for key, value in notes.items() if key[2:] == (REG, start, size)}


def test_raw_untouched_leaf_needs_no_language_preservation(monkeypatch):
    monkeypatch.setitem(may_alias.CALL_PRESERVED, "x86:LE:64", ())
    found, notes = _check(FunctionBuilder(entry=LEAF).ret())
    assert found == {} and _statuses(notes) == {"identity"}


@pytest.mark.parametrize("width", [1, 2, 4, 8])
def test_unconditional_raw_write_overrides_nonvolatile_list(width):
    leaf = FunctionBuilder(entry=LEAF).ins(copy(reg(RBP, width), const(0x40, width))).ret()
    found, notes = _check(leaf)
    assert "1:1000" in found and _statuses(notes) == {"unknown"}


@pytest.mark.parametrize("width", [1, 8])
def test_post_call_first_read_is_unknown_not_implicit_zero(width):
    leaf = FunctionBuilder(entry=LEAF).ins(copy(reg(RBP), const(DATA_BASE))).ret()
    found, notes = _check(leaf, first=True, width=width)
    assert "1:1000" in found and _statuses(notes, size=width) == {"unknown"}


def test_all_exits_have_to_preserve_the_same_bytes():
    leaf = (FunctionBuilder(entry=LEAF).cbranch("other", reg(RAX, 1)).ret()
            .label("other").ins(copy(reg(RBP), const(DATA_BASE))).ret())
    found, notes = _check(leaf)
    assert "1:1000" in found and _statuses(notes) == {"unknown"}


def test_unproved_computation_is_unknown_not_proven_clobber():
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RBP), reg(RBP), const(0))).ret()
    found, notes = _check(leaf)
    assert "1:1000" in found and _statuses(notes) == {"unknown"}


def test_missing_body_stays_explicit_legacy_not_identity():
    caller = FunctionBuilder().ins(copy(reg(RBP), reg(RSP))).call(LEAF).ins(copy(reg(RSP), reg(RBP))).ret()
    notes = {}
    assert program_switches_stack(program_units(caller), call_evidence=notes) == {}
    assert _statuses(notes) == {"legacy"}


def test_denied_proof_never_gets_an_identity_label(monkeypatch):
    monkeypatch.setattr(proof, "_leaf_summary", lambda unit: None)
    found, notes = _check(FunctionBuilder(entry=LEAF).ret())
    assert found == {} and _statuses(notes) == {"legacy"}


def test_failed_leaf_is_cached_and_does_not_grant_preservation(monkeypatch):
    from tdo_v2.resource_limits import AnalysisBudgetExceeded

    calls = []

    def fail(unit):
        calls.append(unit)
        raise AnalysisBudgetExceeded("work", "test", scope="function")

    monkeypatch.setattr(proof, "_leaf_summary", fail)
    found, notes = _check(FunctionBuilder(entry=LEAF).ret())
    assert found == {} and _statuses(notes) == {"legacy"} and len(calls) == 1


def test_run_budget_failure_is_not_swallowed(monkeypatch):
    from tdo_v2.resource_limits import AnalysisBudgetExceeded

    def fail(unit):
        raise AnalysisBudgetExceeded("work", "test", scope="run")

    monkeypatch.setattr(proof, "_leaf_summary", fail)
    with pytest.raises(AnalysisBudgetExceeded):
        _check(FunctionBuilder(entry=LEAF).ret())


def test_leaf_normalization_has_independent_policies_and_restores_them(monkeypatch):
    from tdo_v2.normalize import FunctionNormalizer
    from tdo_v2.relative_memory import IMPORT_SLOTS

    original = FunctionNormalizer.normalize
    policies = []

    def normalize(self, unit, **kwargs):
        policies.append((may_alias.ENTRY_VALUES_NOT_FRAME.get(), may_alias.OPAQUE_NO_STACK_ADDRESSES.get(),
                         IMPORT_SLOTS.get(), kwargs))
        return original(self, unit, **kwargs)

    monkeypatch.setattr(FunctionNormalizer, "normalize", normalize)
    old = may_alias.ENTRY_VALUES_NOT_FRAME.set(True)
    token = IMPORT_SLOTS.set(object())
    try:
        found, notes = _check(FunctionBuilder(entry=LEAF).ret())
        assert found == {} and _statuses(notes) == {"identity"}
        assert policies == [(False, False, None, {"assume_globals_disjoint_from_stack": False})]
        assert may_alias.ENTRY_VALUES_NOT_FRAME.get() and IMPORT_SLOTS.get() is not None
    finally:
        IMPORT_SLOTS.reset(token)
        may_alias.ENTRY_VALUES_NOT_FRAME.reset(old)


def test_same_address_from_another_admitted_program_is_not_evidence(monkeypatch):
    from synthetic import Layout

    caller = FunctionBuilder().ins(copy(reg(RBP), reg(RSP))).call(LEAF).ins(copy(reg(RSP), reg(RBP))).ret()
    (caller_unit,) = program_units(caller)
    (foreign,) = program_units(FunctionBuilder(entry=LEAF).ret(), layout=Layout(data_size=0x2000))
    assert caller_unit.scopes.program.scope != foreign.scopes.program.scope
    monkeypatch.setitem(may_alias.CALL_PRESERVED, "x86:LE:64", ())
    notes = {}
    found = program_switches_stack([caller_unit, foreign], call_evidence=notes)
    assert "1:1000" in found and _statuses(notes) == {"legacy"}


def test_coverage_work_uses_the_same_callee_function_budget(monkeypatch):
    from tdo_v2.resource_limits import AnalysisBudgetExceeded, last_run, run_analysis

    (leaf,) = program_units(FunctionBuilder(entry=LEAF).ins(copy(reg(RBP), reg(RBP))).ret())
    summary = proof._leaf_summary(leaf)
    assert summary is not None
    monkeypatch.setattr(proof, "_leaf_summary", lambda unit: summary)
    # Isolate coverage cost from the already charged existing SSA producer.
    def decide():
        return proof.LeafPreservation({"1:1800": leaf}).decision("1:1800", REG, RBP, 8)

    assert run_analysis(decide) == "identity"
    ledger = last_run().ledgers[("function", leaf.scopes.function.scope)]
    assert ledger.work > 8
    monkeypatch.setenv("TDO_V2_FUNCTION_WORK", "4")
    with pytest.raises(AnalysisBudgetExceeded) as failure:
        run_analysis(decide)
    assert failure.value.scope == "function"


def test_memory_failure_is_never_converted_into_legacy_success(monkeypatch):
    def fail(unit):
        raise MemoryError("test")

    monkeypatch.setattr(proof, "_leaf_summary", fail)
    with pytest.raises(MemoryError):
        _check(FunctionBuilder(entry=LEAF).ret())
