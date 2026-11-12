"""Slot-loaded register calls on a function with a targetless jump (design S-R r3).

``mov R, [__imp_X]; ...; call R`` is recognized on the OBSERVED graph: "every
execution of the call comes through the load". A targetless BRANCHIND (a ud2,
an unresolved ``jmp rax``, a ``jmp [__imp_X]`` tail) may land anywhere, so the
recognizer no longer refuses the whole function; the binding is made and its
effect carries the sites it rests on -- the function's own frontier this round
(a discharged fault leaves it) and its import-tail sites (exempt from the
frontier, still a re-entry obligation). A ``jmp [slot]`` tail itself and an
in-instruction ``call [slot]`` make no predecessor claim and carry nothing.
"""

from types import SimpleNamespace

import pytest
from synthetic import (
    CODE_BASE, DATA_BASE, RAM, RAX, RBX, RCX, ZF, FunctionBuilder, const, copy, op, program_units, ram, reg, sub,
    tmp,
)
from tdo_v2.control_context import site_key, unknown_transfer_sites
from tdo_v2.image_info import ImageInfo, ImportedSymbol
from tdo_v2.interprocedural import analyze_units, import_call_sites
from tdo_v2.summary_store import load_external_models

from test_fault_premise import _pe, _rva
from test_import_ssa_targets import MODELS

MAIN, HELPER = CODE_BASE, CODE_BASE + 0x400
SLOT, OTHER_SLOT, ABORT_SLOT = DATA_BASE + 0x100, DATA_BASE + 0x108, DATA_BASE + 0x110
INFO = ImageInfo("synthetic", (), (
    ImportedSymbol("CRT", "strlen", None, ((1, SLOT),), ()),
    ImportedSymbol("CRT", "free", None, ((1, OTHER_SLOT),), ()),
    ImportedSymbol("CRT", "abort", None, ((1, ABORT_SLOT),), ())), (), ())
F1 = dict(assume_faults_end_execution=True, assume_stock_ghidra_translator=True)
STRLEN, FREE = "external-model:crt-win64/strlen@v8", "external-model:crt-win64/free@v8"


def _key(entry):
    return f"{RAM:x}:{entry:x}"


def _main(entry=MAIN):
    return FunctionBuilder(entry=entry).sub_rsp(0x28)


def _guarded(builder, transfer):
    """``if (zf) goto ok; <transfer>; ok:`` -- the transfer never falls into ``ok``."""
    return transfer(builder.cbranch("ok", reg(ZF, 1))).label("ok")


def _slot_call(builder, slot=SLOT, *middle):
    """``mov rbx, [slot]; <middle>...; call rbx``."""
    builder = builder.ins(copy(reg(RBX), ram(slot)))
    for row in middle:
        builder = builder.ins(*row)
    return builder.call_indirect(RBX)


def _analyze(*functions, forward=True, monkeypatch=None, **options):
    if monkeypatch is not None:
        monkeypatch.setenv("TDO_V2_FORWARD", "1" if forward else "0")
    models = load_external_models(MODELS, "x86:LE:64:default", "win64")
    options.setdefault("exception_directory", _pe())
    return analyze_units(program_units(*functions), image_info=INFO, external_models=models,
                         assume_import_slots_hold_exports=True, assume_globals_disjoint_from_stack=True,
                         **options)


def _own_sites(item):
    return unknown_transfer_sites(item.key, item.unit.observation)


def _callind(item):
    (call,) = [key for key in item.declared if key.endswith(":CALLIND")]
    return call


# -- the recognizer: per call, never the whole function ------------------------------------------

@pytest.mark.parametrize("transfer", ("ud2", "register", "tail"))
def test_a_targetless_jump_elsewhere_no_longer_hides_the_call(transfer):
    jump = {"ud2": lambda b: b.ud2(), "register": lambda b: b.jump_indirect(reg(RAX)),
            "tail": lambda b: b.jump_indirect(ram(OTHER_SLOT))}[transfer]
    main = _slot_call(_guarded(_main(), jump)).add_rsp(0x28).ret()
    (unit,) = program_units(main)
    assert [symbol.name for key, symbol in import_call_sites(unit, INFO).items()
            if key.endswith(":CALLIND")] == ["strlen"]


@pytest.mark.parametrize("middle,bound", (
    ((), True),
    (((copy(reg(RCX), const(1)),),), True),
    (((copy(reg(RCX), const(1)),), (copy(reg(RAX), const(2)),)), True),   # three instructions back
    (((copy(reg(RBX, 4), const(1, 4)),),), False),                        # a write of part of rbx
    (((op("CALLOTHER", [const(1, 4)]),),), False),                        # may change rbx unnamed
))
def test_the_load_may_be_several_plain_instructions_back(middle, bound):
    main = _slot_call(_main(), SLOT, *middle).add_rsp(0x28).ret()
    (unit,) = program_units(main)
    assert bool(import_call_sites(unit, INFO)) is bound


def test_a_join_into_the_chain_after_the_load_keeps_it_opaque():
    flag = tmp(0x300, 1)
    main = (_main().cbranch("mid", flag, op("INT_NOTEQUAL", [reg(RCX), const(0)], flag))
            .ins(copy(reg(RBX), ram(SLOT))).label("mid").ins(copy(reg(RCX), const(1)))
            .call_indirect(RBX).add_rsp(0x28).ret())
    (unit,) = program_units(main)
    assert import_call_sites(unit, INFO) == {}


def test_the_walk_never_crosses_the_entry():
    """entry: rcx = 1; call rbx; if (..) done; rbx = [slot]; goto entry -- the
    first execution reaches the call with the caller's rbx."""
    flag = tmp(0x300, 1)
    main = (FunctionBuilder(entry=MAIN).label("top").ins(copy(reg(RCX), const(1))).call_indirect(RBX)
            .cbranch("done", flag, op("INT_NOTEQUAL", [reg(RCX), const(0)], flag))
            .ins(copy(reg(RBX), ram(SLOT))).branch("top").label("done").ret())
    (unit,) = program_units(main)
    assert import_call_sites(unit, INFO) == {}


class _Switch(FunctionBuilder):
    """Row ``row`` (a ``jump_indirect``) lists ``labels`` as its flow targets (a switch)."""

    def __init__(self, row, labels):
        super().__init__(entry=MAIN)
        self.row, self.targets = row, labels

    def to_json(self):
        raw = super().to_json()
        raw["instructions"][self.row]["flow_targets"] = sorted(
            (self._coordinate(self._address(self._labels[name])) for name in self.targets),
            key=lambda item: (item["space_id"], item["byte_offset"]) if isinstance(item, dict) else item)
        return raw


@pytest.mark.parametrize("into,bound", (("case", True), ("mid", False)))
def test_a_switch_target_after_the_load_breaks_the_chain(into, bound):
    """A targeted BRANCHIND is an observed edge: a case landing on the load
    keeps the proof; one landing between the load and the call breaks it."""
    main = (_Switch(1, (into, "other")).sub_rsp(0x28).jump_indirect(reg(RAX))
            .label("case").ins(copy(reg(RBX), ram(SLOT))).label("mid").ins(copy(reg(RCX), const(1)))
            .call_indirect(RBX).add_rsp(0x28).ret().label("other").add_rsp(0x28).ret())
    (unit,) = program_units(main)
    assert bool(import_call_sites(unit, INFO)) is bound


# -- the binding carries the sites it rests on ---------------------------------------------------

def test_an_undischarged_ud2_is_carried_by_the_binding():
    main = _slot_call(_guarded(_main(), lambda b: b.ud2())).add_rsp(0x28).ret()
    item = _analyze(main)[_key(MAIN)]
    call = _callind(item)
    assert item.declared[call] == STRLEN
    sites = _own_sites(item)
    assert sites and sites <= set(item.proven[call].control_sites)
    assert sites <= set(item.summary.control_support)


def test_a_discharged_ud2_leaves_the_binding_unconditional():
    main = _slot_call(_guarded(_main(), lambda b: b.ud2())).add_rsp(0x28).ret()
    item = _analyze(main, **F1)[_key(MAIN)]
    call = _callind(item)
    assert item.declared[call] == STRLEN
    assert item.normalized.fault_cuts
    assert not set(item.proven[call].control_sites) & _own_sites(item)


def test_an_import_tail_stays_exempt_but_is_the_bindings_reentry_obligation():
    main = _slot_call(_guarded(_main(), lambda b: b.jump_indirect(ram(OTHER_SLOT)))).add_rsp(0x28).ret()
    item = _analyze(main)[_key(MAIN)]
    call = _callind(item)
    (tail,) = _own_sites(item)
    assert item.declared[call] == STRLEN
    assert tail in item.proven[call].control_sites
    assert tail in item.summary.control_support
    assert not item.summary.unknown_transfers   # (still exempt from the frontier)


def test_a_genuine_targetless_jump_is_carried_and_reaches_a_caller():
    helper = _slot_call(_guarded(_main(HELPER), lambda b: b.jump_indirect(reg(RAX)))).add_rsp(0x28).ret()
    main = _main().call(HELPER).add_rsp(0x28).ret()
    results = _analyze(main, helper)
    item = results[_key(HELPER)]
    (site,) = _own_sites(item)
    assert site in item.proven[_callind(item)].control_sites
    assert any(site in effect.control_sites for effect in results[_key(MAIN)].proven.values())


@pytest.mark.parametrize("forward", (True, False))
def test_a_later_round_slot_admission_is_stamped_too(monkeypatch, forward):
    """The same slot on both paths of a join: no static chain, the SSA
    identity binds it in a later round -- with the tail's re-entry obligation."""
    flag = tmp(0x600, 1)
    main = (_guarded(_main(), lambda b: b.jump_indirect(ram(ABORT_SLOT)))
            .cbranch("other", flag, op("INT_NOTEQUAL", [reg(RCX), const(0)], flag))
            .ins(copy(reg(RBX), ram(SLOT))).branch("join").label("other")
            .ins(copy(reg(RBX), ram(SLOT)))
            .label("join").call_indirect(RBX).add_rsp(0x28).ret())
    item = _analyze(main, monkeypatch=monkeypatch, forward=forward)[_key(MAIN)]
    calls = [key for key in item.declared if key.endswith(":CALLIND")]
    if not forward:
        assert calls == []
        return
    (call,) = calls
    (tail,) = _own_sites(item)
    assert item.declared[call] == STRLEN
    assert tail in item.proven[call].control_sites


# -- noreturn ---------------------------------------------------------------------------------------

def test_a_noreturn_model_at_a_site_dependent_binding_is_not_cut():
    main = _slot_call(_guarded(_main(), lambda b: b.ud2()), ABORT_SLOT).add_rsp(0x28).ret()
    item = _analyze(main)[_key(MAIN)]
    (call,) = [key for key in item.vetoed_models if key.endswith(":CALLIND")]
    assert call not in item.proven


def test_a_noreturn_model_with_a_discharged_site_is_cut():
    main = _slot_call(_guarded(_main(), lambda b: b.ud2()), ABORT_SLOT).add_rsp(0x28).ret()
    item = _analyze(main, **F1)[_key(MAIN)]
    assert not [key for key in item.vetoed_models if key.endswith(":CALLIND")]
    assert any(effect.noreturn for key, effect in item.proven.items() if key.endswith(":CALLIND"))


def test_an_import_thunk_and_an_in_instruction_call_carry_nothing():
    """``jmp [slot]`` itself and ``call [slot]`` make no predecessor claim:
    a modelled thunk's caller keeps its noreturn cut; ``call [__imp_abort]``
    next to an import tail is still cut."""
    thunk = FunctionBuilder(entry=HELPER).jump_indirect(ram(ABORT_SLOT))
    main = _main().call(HELPER).add_rsp(0x28).ret()
    results = _analyze(main, thunk)
    assert not results[_key(HELPER)].summary.control_support
    assert results[_key(HELPER)].summary.dead_exits   # (the thunk still never returns)
    assert not results[_key(MAIN)].vetoed_models
    direct = _guarded(_main(), lambda b: b.jump_indirect(ram(OTHER_SLOT))).call_indirect(RBX)
    row = direct._rows[-1]
    row.ops = [copy(tmp(0x400), ram(ABORT_SLOT)), *row.ops[1:]]
    item = _analyze(direct.add_rsp(0x28).ret())[_key(MAIN)]
    effects = [effect for key, effect in item.proven.items() if key.endswith(":CALLIND")]
    assert effects and all(effect.noreturn and not effect.control_sites for effect in effects)
    assert not [key for key in item.vetoed_models if key.endswith(":CALLIND")]


# -- revocation and withdrawal ----------------------------------------------------------------------

def test_a_revoked_discharge_equals_a_run_where_it_was_never_discharged():
    """helper: if (zf) ud2; rbx = [slot]; call rbx -- discharged in round 1,
    revoked after main's handler-covered indirect call to helper is resolved:
    the binding's support equals a run where helper's site is a hazard from the start."""
    helper = _slot_call(_guarded(_main(HELPER), lambda b: b.ud2())).add_rsp(0x28).ret()
    main = _main().ins(copy(reg(RAX), const(HELPER))).call_indirect(RAX).add_rsp(0x28).ret()
    revoked = _analyze(main, helper, exception_directory=_pe([(*_rva(MAIN), 1)]), **F1)[_key(HELPER)]
    fresh = _analyze(main, helper, exception_directory=_pe([(*_rva(HELPER), 1)]), **F1)[_key(HELPER)]
    assert not revoked.normalized.fault_cuts and not fresh.normalized.fault_cuts
    call = _callind(revoked)
    assert revoked.proven[call].control_sites == fresh.proven[call].control_sites
    assert _own_sites(revoked) <= set(revoked.proven[call].control_sites)
    assert revoked.summary.control_support == fresh.summary.control_support


def test_without_the_import_slot_premise_nothing_is_admitted():
    main = _slot_call(_guarded(_main(), lambda b: b.jump_indirect(ram(OTHER_SLOT)))).add_rsp(0x28).ret()
    models = load_external_models(MODELS, "x86:LE:64:default", "win64")
    item = analyze_units(program_units(main), image_info=INFO, external_models=models,
                         assume_import_slots_hold_exports=False)[_key(MAIN)]
    assert not item.declared


# -- reporting --------------------------------------------------------------------------------------

def test_a_carried_import_tail_is_reported_as_a_reentry_obligation():
    from tdo_v2.summary_engine import _control_sites

    tail = site_key(_key(MAIN), SimpleNamespace(space_id=RAM, byte_offset=MAIN + 8))
    other = site_key(_key(MAIN), SimpleNamespace(space_id=RAM, byte_offset=MAIN + 12))
    rows = _control_sites({}, {_key(MAIN): {tail, other}}, frozenset({tail}))
    assert {row[0]: row[1] for row in rows} == {tail: "import-tail-reentry", other: "unknown-transfer"}
