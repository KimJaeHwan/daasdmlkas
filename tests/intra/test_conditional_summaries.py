"""U2b (docs 25.95): conditional summaries.

A block ending in an unknown-transfer site (a BRANCHIND without flow targets
the run does not exempt) is no exit, tail exit or dead exit of its summary:
the callee's effect comes from the remaining exits and carries the summary's
``control_support`` (its frontier sites, every ``control_sites`` its
normalization consumed, and ``continuation:<function>:*``) as
``control_sites``. The marks are already on every root through the U2a
control contexts, which also list ``continuation:<function>:*`` ("every call
in the function's reach returns to its next instruction"). No function that
may reach a site is noreturn; a function whose values may rest on a site
takes no noreturn cut at a call it resolved; invariants at report time.
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from synthetic import (
    CODE_BASE, RAM, RAX, RCX, ZF,
    FunctionBuilder, analyze_summaries, boundary, const, copy, op, program_units, reg,
)
from tdo_v2.call_summary_effects import derive_composed_call_effect, summary_noreturn
from tdo_v2.control_context import continuation_key, control_contexts, site_key, site_reach
from tdo_v2.interprocedural import _register_file, analyze_units
from tdo_v2.summary_engine import ControlSupportViolation, _check_control_support

MAIN, G, H, A, K, X, SINK, OPAQUE = (CODE_BASE + offset for offset in
                                     (0, 0x200, 0x400, 0x600, 0x800, 0xA00, 0xC00, 0xE00))
NAMES = {SINK: "sink", OPAQUE: "opaque"}
REGISTER_SINK = boundary({}, {"sink": 8})
STRIDE = 4
SWI = 16


def _key(entry):
    return f"{RAM:x}:{entry:x}"


def _site(entry, index):
    return site_key(_key(entry), SimpleNamespace(space_id=RAM, byte_offset=entry + index * STRIDE))


def _frontier(entry=G):
    """``if (zf) goto s; rax = 7; ret; s: jmp rax`` -- the site is instruction 3."""
    return FunctionBuilder(entry=entry).cbranch("s", reg(ZF, 1)).ins(copy(reg(RAX), const(7))).ret() \
        .label("s").jump_indirect(reg(RAX))


def _caller(callee=G, entry=MAIN):
    """``call callee; rcx = rax; call sink; ret``."""
    return FunctionBuilder(entry=entry).sub_rsp(0x28).call(callee).ins(copy(reg(RCX), reg(RAX))) \
        .call(SINK).add_rsp(0x28).ret()


def _units(*functions):
    return program_units(*functions, FunctionBuilder(entry=SINK).ret())


def _int3():
    return op("CALLOTHER", [const(SWI, 4), const(3, 4)], None)


def _analyze_traps(*functions, **options):
    from tdo_v2.pcodeop_models import PcodeOpModel

    units = _units(*functions)
    namespace = units[0].scopes.program.evidence.translation_namespace
    model = PcodeOpModel("x86-markers", 1, frozenset({(namespace.language_id, namespace.major_version,
                                                        namespace.minor_version)}), {}, {SWI: frozenset({3})})
    return analyze_units(units, pcodeop_models=(model,), assume_debug_break_traps_do_not_return=True, **options)


def _call_key(item, opcode="CALL"):
    (key,) = [key for key in item.proven if key.endswith(":" + opcode)
              and item.calls.get(key) not in (None, _key(SINK))] or [None]
    return key


# -- the frontier and the conditional effect --------------------------------------

def test_a_frontier_callee_gives_its_caller_a_conditional_effect():
    results = analyze_units(_units(_caller(), _frontier()))
    g = results[_key(G)].summary
    site = _site(G, 3)
    assert [row.site for row in g.unknown_transfers] == [site] and g.tail_exits == () and g.exits
    assert g.control_support == (continuation_key(_key(G)), site)
    main = results[_key(MAIN)]
    effect = next(effect for key, effect in main.proven.items() if main.calls.get(key) == _key(G))
    assert effect.control_sites == g.control_support and not effect.noreturn
    assert any(run.literal is not None for run in effect.runs)   # (rax = 7 reaches the caller)
    assert set(main.summary.control_support) == {site, continuation_key(_key(G)), continuation_key(_key(MAIN))}


def test_the_caller_root_lists_the_site_and_its_continuation_key():
    run = analyze_summaries([_caller(), _frontier(), FunctionBuilder(entry=SINK).ret()], REGISTER_SINK, names=NAMES)
    (root,) = [root for root in run.roots if root.function_byte_offset == MAIN and root.label == "sink.arg0"]
    assert root.effective_completeness.control_obligations == (continuation_key(_key(MAIN)), _site(G, 3))
    assert not root.is_effectively_complete


def test_a_function_without_a_site_is_unchanged():
    plain = FunctionBuilder(entry=G).ins(copy(reg(RAX), const(7))).ret()
    results = analyze_units(_units(_caller(), plain))
    for item in results.values():
        assert item.summary.unknown_transfers == () and item.summary.control_support == ()
        assert not item.summary.site_reachable
        assert all(effect.control_sites == () for effect in item.proven.values())


def test_a_site_only_callee_gives_no_state_and_is_never_noreturn():
    only = FunctionBuilder(entry=G).jump_indirect(reg(RAX))
    trapped = FunctionBuilder(entry=H).cbranch("s", reg(ZF, 1)).ins(_int3()).ret().label("s").jump_indirect(reg(RAX))
    results = _analyze_traps(_caller(G), _caller(H, entry=K), only, trapped)
    for callee in (G, H):
        summary = results[_key(callee)].summary
        assert summary.unknown_transfers and not summary.exits and not summary_noreturn(summary)
    for caller in (MAIN, K):
        assert not any(effect.noreturn for effect in results[_key(caller)].proven.values())


def test_a_site_behind_a_cut_keeps_its_row():
    """``int3; jmp rax``: the site is behind the trap's cut -- still a frontier row, no dead exit."""
    behind = FunctionBuilder(entry=G).ins(_int3()).jump_indirect(reg(RAX))
    summary = _analyze_traps(_caller(), behind)[_key(G)].summary
    assert summary.unknown_transfers and not summary.dead_exits and not summary_noreturn(summary)


def test_an_import_slot_tail_stays_a_tail_exit_only_under_its_premise():
    from synthetic import DATA_BASE, ram
    from tdo_v2.image_info import ImportedSymbol

    slot = DATA_BASE + 0x100
    imports = (ImportedSymbol("KERNEL32.DLL", "ExitProcess", None, ((RAM, slot),), ()),)
    thunk = FunctionBuilder(entry=G).jump_indirect(ram(slot))
    on = analyze_summaries([_caller(), thunk, FunctionBuilder(entry=SINK).ret()], REGISTER_SINK, names=NAMES,
                           image=True, imports=imports)
    off = analyze_summaries([_caller(), thunk, FunctionBuilder(entry=SINK).ret()], REGISTER_SINK, names=NAMES,
                            image=True, imports=imports, assume_import_slots_hold_exports=False)
    assert dict(on.control_contexts) == {}
    assert dict(off.control_contexts)[_key(MAIN)] == (continuation_key(_key(MAIN)), _site(G, 0))


# -- continuation keys -------------------------------------------------------------

def test_a_helper_continuation_is_in_its_consumers_reach():
    """Astra r4: ``A: call opaque; rax = 7; ret``, ``G: if (zf) goto s; call A; ret; s: jmp rax``,
    ``H: call G`` -- H and G list their continuation keys; A is in both scopes."""
    helper = FunctionBuilder(entry=A).sub_rsp(0x28).call(OPAQUE).ins(copy(reg(RAX), const(7))).add_rsp(0x28).ret()
    g = FunctionBuilder(entry=G).sub_rsp(0x28).cbranch("s", reg(ZF, 1)).call(A).add_rsp(0x28).ret() \
        .label("s").jump_indirect(reg(RAX))
    run = analyze_summaries([_caller(G, entry=H), g, helper, FunctionBuilder(entry=SINK).ret()], REGISTER_SINK,
                            names=NAMES)
    contexts = dict(run.control_contexts)
    assert continuation_key(_key(H)) in contexts[_key(H)] and continuation_key(_key(G)) in contexts[_key(G)]
    assert _key(A) not in contexts   # (A reaches no site: unchanged)


def test_the_continuation_key_is_one_per_function():
    results = analyze_units(_units(_caller(), _frontier()))
    contexts = control_contexts(results, {})
    assert contexts[_key(MAIN)] == frozenset({_site(G, 3), continuation_key(_key(MAIN))})
    assert contexts[_key(G)] == frozenset({_site(G, 3), continuation_key(_key(G))})
    assert contexts.get(_key(SINK), frozenset()) == frozenset()


# -- cuts --------------------------------------------------------------------------

def test_site_reach_counts_an_exempt_tail_as_a_wildcard():
    """Astra r2: T: jmp [__imp_X] (exempt), F: call T; int3, H: call F, S: a site elsewhere."""
    tail = FunctionBuilder(entry=X).jump_indirect(reg(RAX))
    f = FunctionBuilder(entry=A).sub_rsp(0x28).call(X).ins(_int3()).ret()
    h = FunctionBuilder(entry=H).sub_rsp(0x28).call(A).add_rsp(0x28).ret()
    units = {f"{RAM:x}:{unit.scopes.function.entry.byte_offset:x}": unit
             for unit in _units(tail, f, h, _frontier())}
    exempt = {_key(X): frozenset({_site(X, 0)})}
    assert {_key(X), _key(A), _key(H), _key(G)} <= site_reach(units, exempt)
    # (no non-exempt site anywhere: nothing is vetoed)
    del units[_key(G)]
    assert site_reach(units, exempt) == frozenset()


def test_a_wrapper_that_may_reach_a_site_is_never_noreturn():
    """F: call G (G may jmp ?); int3 -- F and its caller H: no noreturn, H not cut."""
    f = FunctionBuilder(entry=A).sub_rsp(0x28).call(G).ins(_int3()).ret()
    h = FunctionBuilder(entry=H).sub_rsp(0x28).call(A).add_rsp(0x28).ret()
    results = _analyze_traps(f, h, _frontier())
    assert results[_key(A)].normalized.site_reachable
    assert not summary_noreturn(results[_key(A)].summary)
    assert not any(effect.noreturn for effect in results[_key(H)].proven.values())
    # (no site anywhere: as today)
    plain = FunctionBuilder(entry=G).ins(copy(reg(RAX), const(7))).ret()
    assert any(effect.noreturn for effect in _analyze_traps(f, h, plain)[_key(H)].proven.values())


def test_no_noreturn_cut_at_a_call_resolved_in_a_supported_function():
    """F: call G (conditional); rax = X; call rax -- X never returns (int3): the
    resolved call keeps its path in F; without the conditional call it is cut."""
    x = FunctionBuilder(entry=X).ins(_int3()).ret()
    supported = FunctionBuilder(entry=A).sub_rsp(0x28).call(G).ins(copy(reg(RAX), const(X))).call_indirect(RAX) \
        .add_rsp(0x28).ret()
    plain = FunctionBuilder(entry=A).sub_rsp(0x28).ins(copy(reg(RAX), const(X))).call_indirect(RAX) \
        .add_rsp(0x28).ret()
    on = _analyze_traps(supported, x, _frontier())[_key(A)]
    key = next(key for key in on.calls if key.endswith(":CALLIND"))
    assert on.calls[key] == _key(X)
    assert key in on.proven and not on.proven[key].noreturn
    off = _analyze_traps(plain, x)[_key(A)]
    assert off.proven[next(key for key in off.calls if key.endswith(":CALLIND"))].noreturn


# -- composition and invariants -------------------------------------------------------

def test_a_composition_keeps_a_conditional_members_support():
    plain = FunctionBuilder(entry=K).ins(copy(reg(RAX), const(9))).ret()
    results = analyze_units(_units(_caller(), _frontier(), plain))
    g, k = results[_key(G)], results[_key(K)]
    unit = results[_key(MAIN)].unit
    register_object, register_limit = _register_file(unit.observation, unit.scopes.resolution_context)
    effect = derive_composed_call_effect(((g.summary, g.anchors), (k.summary, k.anchors)), "targets:g|k",
                                         register_object, register_limit)
    assert effect is not None and set(g.summary.control_support) <= set(effect.control_sites)


@pytest.mark.parametrize("forge", ["effect", "summary"])
def test_a_dropped_mark_raises(forge):
    results = analyze_units(_units(_caller(), _frontier()))
    contexts = control_contexts(results, {})
    _check_control_support(results, {}, contexts)   # (as analysed: holds)
    main = results[_key(MAIN)]
    if forge == "effect":
        main.proven = {key: replace(effect, control_sites=()) for key, effect in main.proven.items()}
    else:
        main.summary = replace(main.summary, control_support=())
    with pytest.raises(ControlSupportViolation):
        _check_control_support(results, {}, contexts)


def test_an_omitted_frontier_raises():
    """Astra code r1: the frontier and the support deleted together."""
    results = analyze_units(_units(_caller(), _frontier()))
    contexts = control_contexts(results, {})
    g = results[_key(G)]
    g.summary = replace(g.summary, unknown_transfers=(), control_support=())
    with pytest.raises(ControlSupportViolation):
        _check_control_support(results, {}, contexts)


def test_a_retained_producer_instance_is_checked():
    """A consumed producer instance (not the published one) with a dropped support raises."""
    import copy as _copy

    results = analyze_units(_units(_caller(), _frontier()))
    contexts = control_contexts(results, {})
    main, g = results[_key(MAIN)], results[_key(G)]
    forged = _copy.copy(g)
    forged.summary = replace(g.summary, control_support=())
    call = next(key for key, callee in main.calls.items() if callee == _key(G))
    main.consumed = {**main.consumed, call: (*main.consumed.get(call, ()), forged)}
    with pytest.raises(ControlSupportViolation):
        _check_control_support(results, {}, contexts)


def test_the_records_list_the_frontier():
    from tdo_v2.operation_records import render, run_records

    results = analyze_units(_units(_caller(), FunctionBuilder(entry=G).jump_indirect(reg(RAX))))
    g = results[_key(G)]
    records = run_records(g.normalized, g.unit, g.summary)
    (row,) = [record for record in records if record["record"] == "unknown transfer"]
    assert row["site"] == _site(G, 0) and row["control_support"] == list(g.summary.control_support)
    assert "site=" in render(row)


def test_a_tail_jump_into_a_frontier_function_carries_its_support():
    main = FunctionBuilder(entry=MAIN).tail_call(G)
    # (a call shape elsewhere names the program's one stack pointer: tails compose through it)
    results = analyze_units(_units(main, _frontier(), _caller(G, entry=K)))
    item = results[_key(MAIN)]
    effects = [effect for key, effect in item.proven.items() if item.calls.get(key) == _key(G)]
    assert effects and all(_site(G, 3) in effect.control_sites for effect in effects)
    assert _site(G, 3) in item.summary.control_support


def test_a_recursive_component_with_a_frontier_converges_with_its_support():
    """F: if (zf) goto s; call H; ret; s: jmp rax -- H: call F; ret (one SCC)."""
    f = FunctionBuilder(entry=A).sub_rsp(0x28).cbranch("s", reg(ZF, 1)).call(H).add_rsp(0x28).ret() \
        .label("s").jump_indirect(reg(RAX))
    h = FunctionBuilder(entry=H).sub_rsp(0x28).call(A).add_rsp(0x28).ret()
    run = analyze_summaries([_caller(H), f, h, FunctionBuilder(entry=SINK).ret()], REGISTER_SINK, names=NAMES)
    contexts = dict(run.control_contexts)
    site = site_key(_key(A), SimpleNamespace(space_id=RAM, byte_offset=A + 2 * STRIDE))
    for key in (MAIN, A, H):
        assert continuation_key(_key(key)) in contexts[_key(key)]
    assert any(key.startswith("control:") for key in contexts[_key(MAIN)])


@pytest.mark.parametrize("forge", ["site", "continuation"])
def test_a_mark_outside_the_context_raises(forge):
    """Invariant (2): a site key the context lacks; a continuation scope the function cannot reach."""
    results = analyze_units(_units(_caller(), _frontier()))
    contexts = control_contexts(results, {})
    g = results[_key(G)]
    if forge == "site":
        contexts = {**contexts, _key(G): frozenset({continuation_key(_key(G))})}
    else:
        g.summary = replace(g.summary, control_support=tuple(sorted(
            {*g.summary.control_support, continuation_key(_key(MAIN))})))
    with pytest.raises(ControlSupportViolation):
        _check_control_support(results, {}, contexts)


def test_the_semantics_version_moved():
    """Templates derived before U2b may carry a noreturn the veto forbids: refused by version."""
    from tdo_v2.summary_templates import ENGINE_SEMANTICS_VERSION

    assert ENGINE_SEMANTICS_VERSION == 43


def test_a_carrier_lost_in_the_normalization_raises():
    """Astra code r2: the normalized effect lost its marks, the published copy kept them."""
    results = analyze_units(_units(_caller(), _frontier()))
    contexts = control_contexts(results, {})
    main = results[_key(MAIN)]
    main.normalized = replace(main.normalized, proven_call_effects=tuple(
        (key, replace(effect, control_sites=())) for key, effect in main.normalized.proven_call_effects))
    main.summary = replace(main.summary, control_support=())
    with pytest.raises(ControlSupportViolation):
        _check_control_support(results, {}, contexts)


def test_frontier_records_keep_the_state_sources():
    """``rax = rcx; jmp rax`` and ``rax = rdx; jmp rax``: different frontier states, different records."""
    from synthetic import RDX
    from tdo_v2.operation_records import run_records

    states = []
    for source in (RCX, RDX):
        jump = FunctionBuilder(entry=G).ins(copy(reg(RAX), reg(source))).jump_indirect(reg(RAX))
        g = analyze_units(_units(_caller(), jump))[_key(G)]
        (row,) = [record for record in run_records(g.normalized, g.unit, g.summary)
                  if record["record"] == "unknown transfer"]
        states.append(row["state"])
    assert states[0] != states[1]


@pytest.mark.parametrize("side", ["normalized", "published"])
def test_a_missing_carrier_entry_raises(side):
    """Astra code r3: the conditional call's effect deleted from one representation."""
    results = analyze_units(_units(_caller(), _frontier()))
    contexts = control_contexts(results, {})
    main = results[_key(MAIN)]
    call = next(key for key, callee in main.calls.items() if callee == _key(G))
    if side == "normalized":
        main.normalized = replace(main.normalized, proven_call_effects=tuple(
            row for row in main.normalized.proven_call_effects if row[0] != call))
    else:
        main.proven = {key: effect for key, effect in main.proven.items() if key != call}
    main.summary = replace(main.summary, control_support=())
    with pytest.raises(ControlSupportViolation):
        _check_control_support(results, {}, contexts)


def test_frontier_records_keep_the_condition_operands():
    from tdo_v2.operation_records import _frontier_run
    from tdo_v2.function_summary import SummaryKind, SummaryRun
    from tdo_v2.span_geometry import ByteSpan

    results = analyze_units(_units(_caller(), _frontier()))
    run = results[_key(G)].summary.unknown_transfers[0].state.runs[0]
    other = ByteSpan(run.span.object_id, run.span.start, run.span.size)
    a = replace(run, conditions=((run.span, other),))
    b = replace(run, conditions=((run.span, ByteSpan(run.span.object_id, run.span.start + 1, run.span.size)),))
    assert _frontier_run(a)["conditions"] != _frontier_run(b)["conditions"]
