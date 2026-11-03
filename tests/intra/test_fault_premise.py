"""The fault premise (F1, docs 25.94): faults-end-the-execution with
stock-ghidra-translator, both opt-in.

A recognized ud2 (``t = CALLOTHER invalidInstructionException; BRANCHIND t``)
with no hazard ends its path: the block is no unresolved terminal (callers
get the effect of the returning paths), the site leaves the control contexts
(recorded as an exemption), and a ``FaultOutcome`` keeps where, why, on what
condition and in what state. A fault never makes a function noreturn. A
hazard -- an exception-directory handler (or an unreadable directory), a
transactional instruction, either in a caller -- keeps the site an unknown
transfer, also when it appears only in a later round.
"""

import struct
from pathlib import Path
from types import SimpleNamespace

import pytest
from synthetic import (
    CODE_BASE, RAM, RAX, RCX, RSI, ZF,
    FunctionBuilder, analyze_summaries, boundary, const, copy, op, program_units, reg,
)
from tdo_v2.exception_directory import parse_exception_directory
from tdo_v2.fault_premise import fault_sites
from tdo_v2.interprocedural import analyze_units

MAIN, HELPER, G, H, SINK = CODE_BASE, CODE_BASE + 0x400, CODE_BASE + 0x600, CODE_BASE + 0x800, CODE_BASE + 0xA00
NAMES = {SINK: "sink", HELPER: "helper"}
REGISTER_SINK = boundary({}, {"sink": 8})
SWI, XBEGIN = 16, 85
ON = dict(assume_faults_end_execution=True, assume_stock_ghidra_translator=True)


def _key(entry):
    return f"{RAM:x}:{entry:x}"


def _pe(entries=(), *, truncated=None):
    """A PE32+ image whose one executable section maps the synthetic code
    (image base = the code base: rva = address - CODE_BASE) and holds an
    exception directory: ``entries`` (begin, end, unwind flags) as rvas;
    ``truncated``: an unwind record claiming that many codes at the section's end."""
    section = bytearray(0x10000)
    pdata, xdata = 0x8000, 0x9000
    rows = sorted(entries)
    for index, (begin, end, flags) in enumerate(rows):
        unwind = xdata + 16 * index
        struct.pack_into("<III", section, pdata + 12 * index, begin, end, unwind)
        struct.pack_into("<BBBB", section, unwind, 1 | (flags << 3), 0, 0, 0)
        if flags & 3:
            struct.pack_into("<I", section, unwind + 4, 0x100)
    if truncated is not None:
        unwind = 0x10000 - 4
        rows.append((0x700, 0x800, 0))
        struct.pack_into("<III", section, pdata + 12 * (len(rows) - 1), 0x700, 0x800, unwind)
        struct.pack_into("<BBBB", section, unwind, 1, 0, truncated, 0)
    header = bytearray(0x400)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", header, 0x44, 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    optional = 0x58
    struct.pack_into("<H", header, optional, 0x20B)
    struct.pack_into("<I", header, optional + 108, 16)
    struct.pack_into("<II", header, optional + 112 + 24, pdata, 12 * len(rows))
    table = optional + 0xF0
    struct.pack_into("<8sIIII", header, table, b".text", 0x10000, 0, 0x10000, 0x400)
    struct.pack_into("<I", header, table + 36, 0x60000020)
    return parse_exception_directory(bytes(header) + bytes(section))


def _rva(entry, length=0x100):
    return (entry - CODE_BASE, entry - CODE_BASE + length)


def _main(entry=MAIN):
    return FunctionBuilder(entry=entry).sub_rsp(0x28)


def _checked_helper(*pre):
    """helper: if (zf) ud2; return."""
    return (FunctionBuilder(entry=HELPER).ins(*pre) if pre else FunctionBuilder(entry=HELPER)) \
        .cbranch("fault", reg(ZF, 1)).ret().label("fault").ud2()


def _caller():
    """main: rcx = 7; call helper; call sink(rcx)."""
    return _main().ins(copy(reg(RCX), const(7))).call(HELPER).call(SINK).add_rsp(0x28).ret()


def _units(*functions):
    return program_units(*functions, FunctionBuilder(entry=SINK).ret())


def _analyze(*functions, directory="empty", **options):
    return analyze_units(_units(*functions), exception_directory=_pe() if directory == "empty" else directory,
                         **options)


def _run(*functions, directory="empty", **options):
    return analyze_summaries([*functions, FunctionBuilder(entry=SINK).ret()], REGISTER_SINK, names=NAMES,
                             exception_directory=_pe() if directory == "empty" else directory, **options)


def _root(run, entry=MAIN):
    found = [root for root in run.roots if root.function_byte_offset == entry and root.label == "sink.arg0"]
    assert len(found) == 1
    return found[0]


def _discharged(results, entry=HELPER):
    return tuple(row[0] for row in results[_key(entry)].normalized.fault_cuts)


# -- recognition ---------------------------------------------------------------

def test_a_ud2_is_recognized_by_its_exact_shape():
    unit, *_ = program_units(_checked_helper())
    (site,) = fault_sites(unit)
    assert site.key == f"control:{_key(HELPER)}:{RAM:x}:{HELPER + 2 * 4:x}"
    assert site.cut.endswith(":0:CALLOTHER") and site.branch.endswith(":1:BRANCHIND")


@pytest.mark.parametrize("variant", ["index", "index-width", "extra-op", "register-target"])
def test_another_shape_is_no_fault_site(variant):
    from synthetic import tmp

    builder = FunctionBuilder(entry=HELPER).cbranch("fault", reg(ZF, 1)).ret().label("fault")
    unique = tmp(0x500)
    if variant == "index":
        builder.jump_indirect(unique, op("CALLOTHER", [const(0x4C, 4)], unique))
    elif variant == "index-width":
        builder.jump_indirect(unique, op("CALLOTHER", [const(0x4D, 8)], unique))
    elif variant == "extra-op":
        builder.jump_indirect(unique, copy(reg(RAX), const(0)), op("CALLOTHER", [const(0x4D, 4)], unique))
    else:
        builder.jump_indirect(reg(RAX), op("CALLOTHER", [const(0x4D, 4)], reg(RAX)))
    unit, *_ = program_units(builder)
    assert fault_sites(unit) == ()


# -- the premise off: U2a exactly ------------------------------------------------

def test_off_the_site_stays_an_unknown_transfer():
    results = _analyze(_caller(), _checked_helper())
    helper = results[_key(HELPER)]
    assert helper.normalized.fault_cuts == () and helper.summary.tail_exits
    assert helper.summary.fault_outcomes == ()
    run = _run(_caller(), _checked_helper())
    assert not _root(run).is_effectively_complete
    assert not any(label in run.assumptions for label in ("faults-end-the-execution", "stock-ghidra-translator"))


@pytest.mark.parametrize("switch", ["assume_faults_end_execution", "assume_stock_ghidra_translator"])
def test_one_switch_alone_discharges_nothing(switch):
    results = _analyze(_caller(), _checked_helper(), **{switch: True})
    assert _discharged(results) == ()


# -- the premise on, no hazard ---------------------------------------------------

def test_a_discharged_fault_ends_its_path_and_the_caller_gets_the_effect():
    results = _analyze(_caller(), _checked_helper(), **ON)
    helper = results[_key(HELPER)]
    assert len(_discharged(results)) == 1
    assert not helper.summary.tail_exits and helper.summary.exits
    (outcome,) = helper.summary.fault_outcomes
    assert outcome.site == _discharged(results)[0] and outcome.origin == _key(HELPER)
    assert outcome.premises == ("faults-end-the-execution", "stock-ghidra-translator")
    assert dict(outcome.evidence)["h1"] == "no-entry"
    assert outcome.guard and all(row[0].endswith(":CBRANCH") for row in outcome.guard)
    assert any(key.endswith(":CALL") for key in results[_key(MAIN)].proven)
    run = _run(_caller(), _checked_helper(), **ON)
    root = _root(run)
    assert root.is_effectively_complete
    assert root.effective_completeness.control_obligations == ()
    assert ("faults-end-the-execution" in run.assumptions and "stock-ghidra-translator" in run.assumptions)
    assert (outcome.site, "faults-end-the-execution") in run.control_exemptions


def test_the_cut_is_a_normalization_input():
    """Replay re-normalizes from ``normalization_options``: the cut and the
    may-reach flag are there, so every reconstruction sees the same graph."""
    results = _analyze(_caller(), _checked_helper(), **ON)
    options = dict(results[_key(HELPER)].normalization_options)
    assert options["fault_cuts"] == results[_key(HELPER)].normalized.fault_cuts
    assert options.get("fault_reachable") is True


def test_the_barrier_takes_a_discharged_jump_as_a_terminal():
    """helper: rcx = 7; if (zf) ud2; call sink -- with the site discharged the
    successor graph is complete: the root is bound strictly (no conditional
    binding, no obligation) and complete; off it is U2a's conditional root."""
    helper = (FunctionBuilder(entry=HELPER).sub_rsp(0x28).ins(copy(reg(RCX), const(7)))
              .cbranch("fault", reg(ZF, 1)).call(SINK).add_rsp(0x28).ret().label("fault").ud2())
    on = _root(_run(helper, **ON), HELPER)
    assert on.effective_completeness.conditional_roots == 0 and on.is_effectively_complete
    off = _root(_run(helper), HELPER)
    assert off.effective_completeness.conditional_roots == 1 and not off.is_effectively_complete


# -- hazards --------------------------------------------------------------------

def test_without_an_exception_directory_nothing_is_discharged():
    results = _analyze(_caller(), _checked_helper(), directory=None, **ON)
    assert _discharged(results) == ()
    assert results[_key(HELPER)].summary.tail_exits


@pytest.mark.parametrize("flags", [1, 2])
def test_a_handler_over_the_site_keeps_it(flags):
    results = _analyze(_caller(), _checked_helper(), directory=_pe([(*_rva(HELPER), flags)]), **ON)
    assert _discharged(results) == ()


def test_an_entry_without_a_handler_is_no_hazard():
    results = _analyze(_caller(), _checked_helper(), directory=_pe([(*_rva(HELPER), 0)]), **ON)
    assert len(_discharged(results)) == 1


def test_a_truncated_unwind_record_is_malformed():
    """Astra r7: 255 codes claimed, only the 4-byte header mapped."""
    directory = _pe(truncated=255)
    assert directory.verdict(0x700) == "malformed"
    results = _analyze(_caller(), _checked_helper(), directory=directory, **ON)
    assert len(_discharged(results)) == 1   # (that entry covers no site here)
    covering = _pe([(*_rva(MAIN), 0)], truncated=255)
    assert covering.verdict(0x700) == "malformed"


def test_a_transactional_instruction_keeps_the_site():
    helper = _checked_helper(op("CALLOTHER", [const(XBEGIN, 4)], None))
    results = _analyze(_caller(), helper, **ON)
    assert _discharged(results) == ()


def test_a_handler_over_a_callers_call_site_keeps_the_site():
    results = _analyze(_caller(), _checked_helper(), directory=_pe([(*_rva(MAIN), 1)]), **ON)
    assert _discharged(results) == ()


def test_a_hazard_found_in_a_later_round_revokes_the_cut():
    """main: rax = helper; call rax (resolved in round 2), its call site under
    a handler: helper's site is discharged in round 1, revoked after round 1;
    the published helper rests on no cut."""
    main = _main().ins(copy(reg(RAX), const(HELPER))).call_indirect(RAX).add_rsp(0x28).ret()
    results = _analyze(main, _checked_helper(), directory=_pe([(*_rva(MAIN), 1)]), **ON)
    assert _key(HELPER) in results[_key(MAIN)].calls.values()
    assert _discharged(results) == ()
    assert results[_key(HELPER)].summary.tail_exits


# -- noreturn is never inferred from a fault -------------------------------------

def _trap_model(units):
    from tdo_v2.pcodeop_models import PcodeOpModel

    namespace = units[0].scopes.program.evidence.translation_namespace
    return (PcodeOpModel("x86-markers", 1, frozenset({(namespace.language_id, namespace.major_version,
                                                        namespace.minor_version)}), {}, {SWI: frozenset({3})}),)


def _int3():
    return op("CALLOTHER", [const(SWI, 4), const(3, 4)], None)


def _analyze_traps(*functions, **options):
    units = _units(*functions)
    return analyze_units(units, exception_directory=_pe(), pcodeop_models=_trap_model(units),
                         assume_debug_break_traps_do_not_return=True, **options)


def _noreturn_calls(results, entry):
    return [key for key, effect in results[_key(entry)].proven.items() if effect.noreturn]


def test_a_fault_only_function_is_not_noreturn():
    helper = FunctionBuilder(entry=HELPER).ud2()
    results = _analyze_traps(_caller(), helper, **ON)
    assert len(_discharged(results)) == 1
    assert not results[_key(HELPER)].summary.exits
    assert _noreturn_calls(results, MAIN) == []


def test_a_mixed_trap_and_fault_function_is_not_noreturn():
    """helper: if (rsi) int3; else ud2 -- the trap alone would make it noreturn."""
    helper = (FunctionBuilder(entry=HELPER).cbranch("trap", reg(RSI, 1)).ud2()
              .label("trap").ins(_int3()).ret())
    results = _analyze_traps(_caller(), helper, **ON)
    assert len(_discharged(results)) == 1
    assert _noreturn_calls(results, MAIN) == []
    trap_only = FunctionBuilder(entry=HELPER).ins(_int3()).ret()
    assert _noreturn_calls(_analyze_traps(_caller(), trap_only, **ON), MAIN)   # (as today)


def test_a_recursive_wrapper_never_becomes_noreturn():
    """Astra r9: F: call G; int3.  G: if (p) ud2; else { call F; ret }.  H: call F."""
    f = FunctionBuilder(entry=HELPER).sub_rsp(0x28).call(G).ins(_int3()).ret()
    g = FunctionBuilder(entry=G).sub_rsp(0x28).cbranch("fault", reg(ZF, 1)).call(HELPER).add_rsp(0x28).ret() \
        .label("fault").ud2()
    h = FunctionBuilder(entry=H).sub_rsp(0x28).call(HELPER).add_rsp(0x28).ret()
    results = _analyze_traps(f, g, h, **ON)
    assert len(_discharged(results, G)) == 1
    assert results[_key(HELPER)].normalized.fault_reachable
    assert _noreturn_calls(results, H) == [] and _noreturn_calls(results, G) == []


def test_an_indirect_transfer_vetoes_noreturn_while_a_fault_is_discharged():
    """wrapper: call rax (listed target or not: a wildcard); int3 -- some
    fault elsewhere is discharged: the wrapper may reach it, never noreturn."""
    wrapper = FunctionBuilder(entry=G).sub_rsp(0x28).call_indirect(RAX).ins(_int3()).ret()
    caller = FunctionBuilder(entry=H).sub_rsp(0x28).call(G).add_rsp(0x28).ret()
    results = _analyze_traps(_caller(), _checked_helper(), wrapper, caller, **ON)
    assert len(_discharged(results)) == 1
    assert results[_key(G)].normalized.fault_reachable
    assert _noreturn_calls(results, H) == []
    off = _analyze_traps(_caller(), _checked_helper(), wrapper, caller)
    assert _noreturn_calls(off, H)   # (the premise off: noreturn as today)


def test_the_noreturn_conjunction_has_one_reader():
    source = Path(__file__).resolve().parents[2] / "src" / "tdo_v2"
    needle = "not summary.exits and not summary.tail_exits"
    readers = [path.name for path in source.rglob("*.py") if needle in path.read_text(encoding="utf-8")]
    assert readers == ["call_summary_effects.py"]
    text = (source / "call_summary_effects.py").read_text(encoding="utf-8")
    assert text.count(needle) == 1


# -- outcomes, guards, references ------------------------------------------------

def test_a_nested_guard_keeps_both_decisions_with_their_edges():
    """helper: if (zf) { if (rsi) ud2; }; ret."""
    helper = (FunctionBuilder(entry=HELPER).cbranch("outer", reg(ZF, 1)).ret()
              .label("outer").cbranch("fault", reg(RSI, 1)).ret().label("fault").ud2())
    results = _analyze(_caller(), helper, **ON)
    (outcome,) = results[_key(HELPER)].summary.fault_outcomes
    decisions = {row[0] for row in outcome.guard}
    assert len(decisions) == 2
    assert all(row[2] != "unknown-edge" for row in outcome.guard)


def test_a_caller_references_the_callees_outcome():
    results = _analyze(_caller(), _checked_helper(), **ON)
    references = results[_key(MAIN)].summary.fault_references
    assert [(row.callee) for row in references] == [_key(HELPER)]
    assert references[0].call.endswith(":CALL")


def test_recursion_keeps_references_finite():
    """G: if (zf) ud2; call G; ret -- one reference per (call, callee)."""
    g = (FunctionBuilder(entry=G).sub_rsp(0x28).cbranch("fault", reg(ZF, 1)).call(G).add_rsp(0x28).ret()
         .label("fault").ud2())
    results = _analyze(_caller(), _checked_helper(), g, **ON)
    references = results[_key(G)].summary.fault_references
    assert len(references) == len({(row.call, row.callee) for row in references}) == 1


def test_a_template_refuses_a_function_resting_on_a_cut():
    from tdo_v2.summary_templates import TemplateRefused, export_summary

    results = _analyze(_caller(), _checked_helper(), **ON)
    with pytest.raises(TemplateRefused, match="faults-end-the-execution"):
        export_summary(results[_key(HELPER)], results)


def test_a_fallback_after_a_revocation_publishes_the_dependents_failed():
    from tdo_v2.fault_premise import FaultPlan, FaultSite
    from tdo_v2.interprocedural import _without_revoked_faults

    results = _analyze(_caller(), _checked_helper(), **ON)
    site = results[_key(HELPER)].normalized.fault_cuts[0]
    plan = FaultPlan({_key(HELPER): (FaultSite(site[0], site[1], site[2], 0),)}, frozenset({site[0]}), {},
                     frozenset(), {}, None)
    functions = {key: item.unit for key, item in results.items()}
    calls = {key: dict(item.calls) for key, item in results.items()}
    published = _without_revoked_faults(results, plan, frozenset(), functions, calls)
    for key in (_key(HELPER), _key(MAIN)):
        assert published[key].failure_detail == "fault:revoked"
    assert published[_key(SINK)] is results[_key(SINK)]


# -- review fixes (Astra code review) ---------------------------------------------

@pytest.mark.parametrize("indirect", [False, True])
def test_a_handler_over_a_recursive_call_keeps_the_site(indirect):
    """helper: if (zf) ud2; call helper (direct, or CALLIND listing helper) --
    only the call instruction under a handler (the ud2 itself is not)."""
    builder = FunctionBuilder(entry=HELPER).sub_rsp(0x28).cbranch("fault", reg(ZF, 1))
    call = len(builder._rows)
    if indirect:
        builder.call_indirect(RAX)
    else:
        builder.call(HELPER)
    helper = builder.add_rsp(0x28).ret().label("fault").ud2()
    address = HELPER + 4 * call

    class Listed(FunctionBuilder):
        def to_json(self):
            value = super().to_json()
            if indirect:
                value["instructions"][call]["flow_targets"] = [{"space_id": RAM, "byte_offset": HELPER}]
            return value

    if indirect:
        helper.__class__ = Listed
    covered = _analyze(_caller(), helper, directory=_pe([(address - CODE_BASE, address - CODE_BASE + 4, 1)]), **ON)
    assert _discharged(covered) == ()
    ((_, status, detail),) = covered[_key(HELPER)].fault_decisions
    assert status == "hazard" and "H3" in detail and "H1" not in detail


def test_switched_off_premises_are_disabled_for_models():
    from tdo_v2.assumptions import disabled

    base = dict(globals_disjoint=True, readonly_image=True, direction_flag=True, entry_values_not_frame=True,
                home_space=True, opaque_no_stack=True, traps=True, import_slots=True, same_result=True,
                accessor_separate=True, accessor_private_state=True, registered_handlers=True)
    assert {"faults-end-the-execution", "stock-ghidra-translator"} <= disabled(**base)
    assert not {"faults-end-the-execution", "stock-ghidra-translator"} & disabled(
        **base, faults_end_execution=True, stock_translator=True)


def test_an_exhaustion_after_a_revocation_publishes_no_stale_cut(monkeypatch):
    """Round 1 discharges helper's site; its resolution finds main's handler-
    covered call to helper (D shrinks); round 2's resolution exhausts the run:
    the round-1 publication must not keep the revoked cut."""
    import tdo_v2.interprocedural as ip
    from tdo_v2.resource_limits import AnalysisBudgetExceeded

    original, seen = ip._indirect_targets, []

    def targets(item, program):
        seen.append(item.key)
        if len(seen) > len(program):
            raise AnalysisBudgetExceeded("time", "injected", scope="run")
        return original(item, program)

    monkeypatch.setattr(ip, "_indirect_targets", targets)
    main = _main().ins(copy(reg(RAX), const(HELPER))).call_indirect(RAX).add_rsp(0x28).ret()
    results = _analyze(main, _checked_helper(), directory=_pe([(*_rva(MAIN), 1)]), **ON)
    helper = results[_key(HELPER)]
    assert helper.failure_detail == "fault:revoked"
    assert not getattr(helper.normalized, "fault_cuts", ())
    ((_, status, detail),) = helper.fault_decisions
    assert status == "revoked" and detail.startswith("H3:")


def test_the_decisions_are_reported():
    results = _analyze(_caller(), _checked_helper(), **ON)
    ((site, status, _),) = results[_key(HELPER)].fault_decisions
    assert status == "discharged"
    hazard = _analyze(_caller(), _checked_helper(), directory=_pe([(*_rva(HELPER), 1)]), **ON)
    ((_, status, detail),) = hazard[_key(HELPER)].fault_decisions
    assert status == "hazard" and detail.startswith("H1:handler")
    main = _main().ins(copy(reg(RAX), const(HELPER))).call_indirect(RAX).add_rsp(0x28).ret()
    revoked = _analyze(main, _checked_helper(), directory=_pe([(*_rva(MAIN), 1)]), **ON)
    ((_, status, detail),) = revoked[_key(HELPER)].fault_decisions
    assert status == "revoked" and detail.startswith("H3:")
    run = _run(_caller(), _checked_helper(), **ON)
    assert [row[1] for row in run.fault_report] == ["discharged"]


def test_the_reader_refuses_a_directory_outside_the_optional_header():
    directory = _pe([(*_rva(HELPER), 0)])
    data = bytearray(directory.data)
    struct.pack_into("<HH", data, 0x44 + 16, 112, 0x22)   # SizeOfOptionalHeader = 112: no directory fits
    assert parse_exception_directory(bytes(data)).verdict(_rva(HELPER)[0]) == "malformed"


def test_the_reader_refuses_a_chained_entry_outside_code():
    section = 0x400
    directory = _pe([(*_rva(HELPER), 4)])   # CHAININFO, the chained record follows the header
    data = bytearray(directory.data)
    unwind = section + 0x9000
    struct.pack_into("<III", data, unwind + 4, 0x20000, 0x20100, 0x9100)   # beyond the executable section
    assert parse_exception_directory(bytes(data)).verdict(_rva(HELPER)[0]) == "malformed"


# -- review fixtures (Astra code review, rounds 2-3) --------------------------------

class _Listed(FunctionBuilder):
    """A builder whose instruction ``listed_row`` lists ``listed_targets`` as Ghidra flow targets."""

    listed_row: int = -1
    listed_targets: tuple = ()

    def to_json(self):
        value = super().to_json()
        if self.listed_row >= 0:
            value["instructions"][self.listed_row]["flow_targets"] = [
                {"space_id": RAM, "byte_offset": target} for target in self.listed_targets]
        return value


def test_a_listed_indirect_target_is_still_a_wildcard():
    """wrapper: rax = helper; CALLIND rax listing only sink; int3 -- resolved to
    the fault-bearing helper later: the wrapper may reach the fault (wildcard,
    r11), never noreturn; neither is its caller."""
    from tdo_v2.fault_premise import observed_calls

    wrapper = _Listed(entry=G).sub_rsp(0x28).ins(copy(reg(RAX), const(HELPER)))
    wrapper.listed_row = len(wrapper._rows)
    wrapper.listed_targets = (SINK,)
    wrapper.call_indirect(RAX).ins(_int3()).ret()
    caller = FunctionBuilder(entry=H).sub_rsp(0x28).call(G).add_rsp(0x28).ret()
    results = _analyze_traps(_caller(), _checked_helper(), wrapper, caller, **ON)
    assert _key(HELPER) in results[_key(G)].calls.values()   # (the resolution happened)
    assert results[_key(G)].normalized.fault_reachable
    assert _noreturn_calls(results, H) == []
    units = {f"{RAM:x}:{unit.scopes.function.entry.byte_offset:x}": unit for unit in _units(wrapper)}
    listed, wildcard = observed_calls(units[_key(G)], frozenset(units))
    assert wildcard and _key(SINK) in listed
    several = _Listed(entry=G).sub_rsp(0x28)
    several.listed_row = len(several._rows)
    several.listed_targets = (SINK, HELPER)
    several.call_indirect(RAX).ins(_int3()).ret()
    unit = next(unit for unit in _units(several) if unit.scopes.function.entry.byte_offset == G)
    assert observed_calls(unit, frozenset(units) | {_key(HELPER)})[1]


def test_a_refused_candidate_still_gets_its_reference():
    """A multi-target candidate whose effect did not lower is no call of the
    caller's ``calls`` / ``multi_calls``: the raw candidate gives the reference."""
    from tdo_v2.interprocedural import _with_fault_references

    main = _main().call_indirect(RAX).add_rsp(0x28).ret()
    results = _analyze(main, _checked_helper(), **ON)
    item = results[_key(MAIN)]
    key = next(f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:CALLIND"
               for row in item.unit.observation.instructions for ordinal, operation in enumerate(row.operations)
               if operation.opcode == "CALLIND")
    assert not item.summary.fault_references
    item.multi_candidates = {key: (_key(HELPER),)}
    _with_fault_references(results)
    assert [(row.call, row.callee) for row in results[_key(MAIN)].summary.fault_references] == [(key, _key(HELPER))]


def test_an_unstable_resolution_keeps_the_smallest_discharged_set(monkeypatch):
    """main's handler-covered CALLIND resolves to helper only every other
    round (never stable): the unstable exit analyses without resolution, but
    with D as small as any round made it -- helper's site stays revoked."""
    import tdo_v2.interprocedural as ip

    original, count = ip._indirect_targets, {"main": 0}

    def flicker(item, program):
        found = original(item, program)
        if item.key == _key(MAIN):
            count["main"] += 1
            return found if count["main"] % 2 else {}
        return found

    monkeypatch.setattr(ip, "_indirect_targets", flicker)
    main = _main().ins(copy(reg(RAX), const(HELPER))).call_indirect(RAX).add_rsp(0x28).ret()
    results = _analyze(main, _checked_helper(), directory=_pe([(*_rva(MAIN), 1)]), **ON)
    assert _discharged(results) == ()
    ((_, status, _),) = results[_key(HELPER)].fault_decisions
    assert status == "revoked"


def test_a_fault_beside_a_composed_tail():
    """wrapper: if (zf) ud2; jmp plain -- the tail composes with plain's
    summary, the fault is an outcome, the wrapper is no unresolved terminal."""
    plain = FunctionBuilder(entry=H).ret()
    wrapper = FunctionBuilder(entry=HELPER).cbranch("fault", reg(ZF, 1)).tail_call(H).label("fault").ud2()
    results = _analyze(_caller(), wrapper, plain, **ON)
    summary = results[_key(HELPER)].summary
    assert len(summary.fault_outcomes) == 1 and not summary.tail_exits
    assert any(effect.callee == _key(HELPER) and not effect.noreturn for effect in results[_key(MAIN)].proven.values())


def test_a_noreturn_call_beside_a_fault_is_not_noreturn():
    """helper: if (zf) call trap_only (noreturn); else ud2 -- the dead exit of
    the noreturn call would make it noreturn; the fault forbids it."""
    trap_only = FunctionBuilder(entry=H).ins(_int3()).ret()
    helper = (FunctionBuilder(entry=HELPER).sub_rsp(0x28).cbranch("fault", reg(ZF, 1)).call(H).add_rsp(0x28).ret()
              .label("fault").ud2())
    results = _analyze_traps(_caller(), helper, trap_only, **ON)
    assert _noreturn_calls(results, HELPER)   # (the trap-only callee is noreturn, as today)
    assert _noreturn_calls(results, MAIN) == []


def test_another_language_recognizes_no_site():
    from synthetic import X86_32

    builder = FunctionBuilder(entry=HELPER, arch=X86_32).cbranch("fault", reg(ZF, 1)).ret().label("fault").ud2()
    unit, *_ = program_units(builder)
    assert fault_sites(unit) == ()


def _patched(directory, offset, fmt, *values):
    data = bytearray(directory.data)
    struct.pack_into(fmt, data, offset, *values)
    return parse_exception_directory(bytes(data))


def test_the_reader_validates_chains_and_tables():
    section, xdata = 0x400, 0x9000
    begin, end = _rva(HELPER)
    chained = _pe([(begin, end, 4)])
    unwind = section + xdata
    assert _patched(chained, unwind + 4, "<III", begin, end, xdata).verdict(begin) == "malformed"   # a cycle
    assert _patched(chained, unwind + 4, "<III", begin, end, 0xFFF0).verdict(begin) == "malformed"  # past the section
    second = _patched(chained, unwind + 4, "<III", begin, end, xdata + 16)
    data = bytearray(second.data)
    struct.pack_into("<BBBB", data, unwind + 16, 1 | (1 << 3), 0, 0, 0)   # the chained record has a handler
    assert parse_exception_directory(bytes(data)).verdict(begin) == "handler"
    table = _pe([(0x100, 0x200, 0), (0x300, 0x400, 0)])
    assert _patched(table, section + 0x8000, "<III", 0x300, 0x400, 0x9000).verdict(0x100) == "malformed"   # unsorted
    assert _patched(table, section + 0x8000 + 12, "<III", 0x150, 0x400, 0x9010).verdict(0x300) == "malformed"  # overlap


A2, B2, C2 = CODE_BASE + 0x800, CODE_BASE + 0x900, CODE_BASE + 0xC00


def _table_call(entry, *after):
    """[rsp+0x20] = A2; [rsp+0x28] = B2; call [rsp+0x20+(rcx&1)*8] -- Ghidra
    lists only B2 as the CALLIND's target; then ``after``."""
    from synthetic import RSP, add, load, store, tmp

    t, u, i = tmp(0x100), tmp(0x180), tmp(0x200)
    builder = _Listed(entry=entry).sub_rsp(0x48)
    builder.ins(add(t, reg(RSP), const(0x20)), store(t, const(A2)), add(u, reg(RSP), const(0x28)),
                store(u, const(B2)))
    builder.ins(op("INT_AND", [reg(RCX), const(1)], i), op("INT_MULT", [i, const(8)], i),
                add(i, i, reg(RSP)), add(i, i, const(0x20)), load(reg(RAX), i))
    builder.listed_row = len(builder._rows)
    builder.listed_targets = (B2,)
    builder.call_indirect(RAX)
    for item in after:
        builder.ins(item)
    return builder.add_rsp(0x48).ret()


@pytest.mark.parametrize("fault_only", [False, True])
def test_a_multi_target_call_keeps_every_fault_bearing_candidate(monkeypatch, fault_only):
    """A two-target table call (forward facts) to A2 (fault-bearing, not in the
    listing) and B2: the candidates are both; A2's site is discharged; the
    caller references (call, A2). With A2 returning too the composition is
    accepted; with A2 ending only in the fault it is an opaque member and the
    composition refused -- the raw candidate still gives the reference. A
    wrapper ending in int3 after such a call is never noreturn."""
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    fault = FunctionBuilder(entry=A2).ud2() if fault_only else         FunctionBuilder(entry=A2).cbranch("fault", reg(ZF, 1)).ins(copy(reg(RAX), const(1))).ret().label("fault").ud2()
    other = FunctionBuilder(entry=B2).ins(copy(reg(RAX), const(2))).ret()
    wrapper = _table_call(G, _int3())
    caller = FunctionBuilder(entry=C2).sub_rsp(0x28).call(G).add_rsp(0x28).ret()
    units = program_units(_table_call(MAIN), fault, other, wrapper, caller)
    results = analyze_units(units, exception_directory=_pe(), pcodeop_models=_trap_model(units),
                            assume_debug_break_traps_do_not_return=True, **ON)
    main = results[_key(MAIN)]
    (call, members), = main.multi_candidates.items()
    assert set(members) == {_key(A2), _key(B2)}
    assert len(_discharged(results, A2)) == 1
    assert (call, _key(A2)) in {(row.call, row.callee) for row in main.summary.fault_references}
    assert (call in main.proven) is (not fault_only)
    assert results[_key(G)].normalized.fault_reachable
    assert _noreturn_calls(results, C2) == []


def test_a_fault_in_a_loop_keeps_a_finite_cyclic_guard():
    """helper: loop: if (zf) ud2; if (rsi) goto loop; ret."""
    helper = (FunctionBuilder(entry=HELPER).label("loop").cbranch("fault", reg(ZF, 1))
              .cbranch("loop", reg(RSI, 1)).ret().label("fault").ud2())
    results = _analyze(_caller(), helper, **ON)
    (outcome,) = results[_key(HELPER)].summary.fault_outcomes
    decisions = {row[0] for row in outcome.guard}
    assert len(decisions) == 2   # (the fault's own decision and the loop's back edge controlling it)
    assert len(outcome.guard) == len(set(outcome.guard))
    # the cycle is kept: a decision block of the guard is itself a dependent of the guard's back edge
    dependents = {row[3] for row in outcome.guard}
    assert any(row[1] in dependents for row in outcome.guard)


def test_a_cut_callers_handler_is_still_h3():
    """Fable: H3 walks every observed caller, also one a model cut from the
    analysis -- here directly through ``plan_faults`` with a caller set wider
    than the analysed one."""
    from tdo_v2.fault_premise import plan_faults

    units = {f"{RAM:x}:{unit.scopes.function.entry.byte_offset:x}": unit for unit in _units(_caller(), _checked_helper())}
    analysed = {key: unit for key, unit in units.items() if key != _key(MAIN)}
    directory = _pe([(*_rva(MAIN), 1)])
    assert plan_faults(analysed, directory, CODE_BASE).discharged   # (main unseen: no hazard)
    assert not plan_faults(analysed, directory, CODE_BASE, units).discharged


def test_the_report_lists_registration_imports():
    from tdo_v2.image_info import ImportedSymbol

    imports = (ImportedSymbol("KERNEL32.DLL", "AddVectoredExceptionHandler", None, ((RAM, 0x4100),), ()),)
    run = _run(_caller(), _checked_helper(), image=True, imports=imports, **ON)
    assert ("registration-import", "AddVectoredExceptionHandler", "KERNEL32.DLL") in run.fault_report
