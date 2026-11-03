"""U2a (docs 25.93): an unknown control transfer no longer discards what the
observed graph solves -- it MARKS it.

A BRANCHIND without targets (``ud2``, an unresolved ``jmp [rip+x]``) leaves
the successor graph incomplete; the state barrier refuses every lookup of
its function. The reported sink roots are now bound on the observed graph
(``conditional_state_definition``: every other barrier check unchanged), and
every root of a function whose control context holds a site -- its own or a
reachable function's -- lists the site keys and is never complete. Nothing
else changes: summaries, sink demands, effects and the strict engine path
refuse as before.
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from synthetic import (
    CODE_BASE, DATA_BASE, LANGUAGE, RAM, RAX, RCX, RDX, ZF,
    FunctionBuilder, analyze_program, analyze_summaries, boundary, const, copy, ram, reg, store,
)
from tdo_v2.boundary import BoundaryKind
from tdo_v2.boundary_rules import BoundaryRule, SymbolBoundaryProvider
from tdo_v2.control_context import _closure, control_contexts, site_key, unavailable_key
from tdo_v2.image_info import ImportedSymbol
from tdo_v2.physical_state import PhysicalMemorySlice, PhysicalRegisterSlice
from tdo_v2.query_contracts import LocalCompleteness, with_control

MAIN, SINK, OPAQUE, HELPER = CODE_BASE, CODE_BASE + 0xA00, CODE_BASE + 0xC00, CODE_BASE + 0xE00
NAMES = {SINK: "sink", OPAQUE: "opaque", HELPER: "helper"}
REGISTER_SINK = boundary({}, {"sink": 8})
STRIDE = 4


def _key(entry):
    return f"{RAM:x}:{entry:x}"


def _site(entry, index):
    """The site key of the ``index``-th instruction of the function at ``entry``."""
    return site_key(_key(entry), SimpleNamespace(space_id=RAM, byte_offset=entry + index * STRIDE))


def _main(entry=MAIN):
    return FunctionBuilder(entry=entry).sub_rsp(0x28)


def _guarded(builder, then, transfer):
    """``if (zf) goto ok; <transfer>; ok: <then>`` -- the transfer is instruction len(rows) + 1."""
    index = len(builder._rows) + 1
    return then(transfer(builder.cbranch("ok", reg(ZF, 1))).label("ok")), index


def _guarded_ud2(builder, then):
    """``if (zf) goto ok; ud2; ok: <then>``."""
    return _guarded(builder, then, lambda b: b.ud2())



def _run(main, extra=(), provider=REGISTER_SINK, **options):
    bodies = [main, FunctionBuilder(entry=SINK).ret(), *extra]
    return analyze_summaries(bodies, provider, names=NAMES, **options)


def _roots(run, entry=MAIN, label="sink.arg0"):
    found = [root for root in run.roots if root.function_byte_offset == entry and root.label == label]
    assert found, "the sink occurrence was dropped"
    return found


def test_a_sink_before_a_ud2_path_is_bound_and_marked():
    """rcx = 7; if (zf) goto ok; ud2; ok: call sink -- before U2a the ud2 made
    the barrier refuse: an unbound root. Now: bound to the constant on the
    observed graph, conditional on the ud2."""
    main, index = _guarded_ud2(_main().ins(copy(reg(RCX), const(7))),
                               lambda b: b.call(SINK).add_rsp(0x28).ret())
    root, = _roots(_run(main))
    completeness = root.effective_completeness
    assert completeness.unbound_roots == 0
    assert completeness.conditional_roots == 1
    assert completeness.control_obligations == (_site(MAIN, index),)
    assert not root.is_effectively_complete and not root.is_locally_complete


def test_the_strict_engine_path_still_refuses():
    """``engine.analyze_observed_functions`` never takes the conditional lookup."""
    main, _ = _guarded_ud2(_main().ins(copy(reg(RCX), const(7))),
                           lambda b: b.call(SINK).add_rsp(0x28).ret())
    roots = analyze_program({"main": main, "sink": FunctionBuilder(entry=SINK).ret()}, REGISTER_SINK)
    root = roots[("main", "sink.arg0")]
    assert root.effective_completeness.unbound_roots == 1
    assert root.effective_completeness.control_obligations == ()


def test_another_barrier_still_refuses_the_conditional_lookup():
    """rcx = 7; call opaque; ... ud2 ...; call sink: the opaque call may change
    rcx -- an obligation is not a definition: the root stays unbound (and marked)."""
    main, index = _guarded_ud2(_main().ins(copy(reg(RCX), const(7))).call(OPAQUE),
                               lambda b: b.call(SINK).add_rsp(0x28).ret())
    root, = _roots(_run(main))
    completeness = root.effective_completeness
    assert completeness.unbound_roots == 1 and completeness.conditional_roots == 0
    assert completeness.control_obligations == (_site(MAIN, index),)
    assert not root.is_effectively_complete


def test_a_callee_site_marks_every_root_of_its_callers():
    """main: rcx = 7; call sink; call helper -- helper may ud2. The root is
    bound strictly and was complete; the ud2 may resume anywhere (by unwinding,
    in main too): main's root rests on helper's site."""
    helper, index = _guarded_ud2(_main(HELPER), lambda b: b.add_rsp(0x28).ret())
    main = _main().ins(copy(reg(RCX), const(7))).call(SINK).call(HELPER).add_rsp(0x28).ret()
    run = _run(main, extra=(helper,))
    root, = _roots(run)
    completeness = root.effective_completeness
    assert completeness.unbound_roots == 0 and completeness.conditional_roots == 0
    assert completeness.control_obligations == (_site(HELPER, index),)
    assert not root.is_effectively_complete
    assert dict(run.control_contexts) == {_key(MAIN): (_site(HELPER, index),),
                                          _key(HELPER): (_site(HELPER, index),)}


def test_a_function_without_a_site_is_unchanged():
    main = _main().ins(copy(reg(RCX), const(7))).call(SINK).add_rsp(0x28).ret()
    run = _run(main)
    root, = _roots(run)
    assert root.is_effectively_complete
    assert root.effective_completeness == LocalCompleteness(True, 0, 0)
    assert run.control_contexts == ()


def test_a_tail_sink_is_bound_and_marked():
    """rcx = 7; if (zf) goto ok; ud2; ok: jmp sink."""
    main, index = _guarded_ud2(_main().ins(copy(reg(RCX), const(7))),
                               lambda b: b.add_rsp(0x28).tail_call(SINK))
    root, = _roots(_run(main))
    completeness = root.effective_completeness
    assert completeness.unbound_roots == 0 and completeness.conditional_roots == 1
    assert completeness.control_obligations == (_site(MAIN, index),)


def test_a_memory_sink_names_its_fragment_through_the_conditional_pointer():
    """[rdx] = 5; ... ud2 ...; call sink([rdx]) (rdx: the entry pointer): the
    sink's base register is read on the observed graph only to name this
    root's fragment."""
    provider = SymbolBoundaryProvider((
        BoundaryRule("sink", LANGUAGE, BoundaryKind.SINK, "sink.mem",
                     (PhysicalMemorySlice(PhysicalRegisterSlice(RDX, 8), 0, 4),)),
    ))
    main, index = _guarded_ud2(
        _main().ins(store(reg(RDX), const(5, 4))),
        lambda b: b.call(SINK).add_rsp(0x28).ret())
    root, = _roots(_run(main, provider=provider), label="sink.mem")
    completeness = root.effective_completeness
    assert completeness.unbound_roots == 0 and completeness.conditional_roots == 1
    assert completeness.control_obligations == (_site(MAIN, index),)


def test_the_summary_sink_demand_stays_strict():
    """helper: rcx = 7; ... ud2 ...; call sink. helper's own reported root is
    bound conditionally, but its summary's sink demand -- what main's projected
    root takes -- is the strict, unbound one: main's projected root stays
    incomplete, carrying helper's site."""
    helper, index = _guarded_ud2(_main(HELPER).ins(copy(reg(RCX), const(7))),
                                 lambda b: b.call(SINK).add_rsp(0x28).ret())
    main = _main().call(HELPER).add_rsp(0x28).ret()
    run = _run(main, extra=(helper,))
    own, = _roots(run, HELPER)
    assert own.effective_completeness.conditional_roots == 1
    for root in _roots(run, MAIN):
        assert root.inherited_incomplete and not root.is_effectively_complete
        assert root.effective_completeness.control_obligations == (_site(HELPER, index),)
        assert root.effective_completeness.conditional_roots == 0


def test_the_record_lists_the_obligations():
    main, index = _guarded_ud2(_main().ins(copy(reg(RCX), const(7))),
                               lambda b: b.call(SINK).add_rsp(0x28).ret())
    root, = _roots(_run(main, operation_records=True))
    completeness = root.explanation["record"]["completeness"]
    assert completeness["control_obligations"] == [_site(MAIN, index)]
    assert completeness["conditional_roots"] == 1
    plain = _main().ins(copy(reg(RCX), const(7))).call(SINK).add_rsp(0x28).ret()
    root, = _roots(_run(plain, operation_records=True))
    assert "control_obligations" not in root.explanation["record"]["completeness"]


# -- r6: a terminal jump through an import slot is a tail call to the import --

SLOT = DATA_BASE + 0x100


def _thunk(slot=SLOT):
    """helper: ``jmp [slot]``."""
    return FunctionBuilder(entry=HELPER).jump_indirect(ram(slot))


def _caller_of_thunk():
    return _main().ins(copy(reg(RCX), const(7))).call(SINK).call(HELPER).add_rsp(0x28).ret()


IMPORTS = (ImportedSymbol("KERNEL32.DLL", "ExitProcess", None, ((RAM, SLOT),), ()),)


def test_an_import_slot_tail_is_no_unknown_transfer():
    """main: rcx = 7; call sink; call helper (helper: jmp [__imp_X]) -- the
    jump is a tail call to the import (its continuation: the opaque-callee
    rule's, 2c): no key, the exemption recorded under its premise."""
    run = _run(_caller_of_thunk(), extra=(_thunk(),), image=True, imports=IMPORTS)
    root, = _roots(run)
    assert root.is_effectively_complete
    assert root.effective_completeness.control_obligations == ()
    assert run.control_contexts == ()
    assert run.control_exemptions == ((_site(HELPER, 0), "import-slots-hold-their-exports"),)
    assert "import-slots-hold-their-exports" in run.assumptions   # (the import has no model: only the exemption uses it)


def test_without_the_premise_the_import_jump_is_a_site():
    run = _run(_caller_of_thunk(), extra=(_thunk(),), image=True, imports=IMPORTS,
               assume_import_slots_hold_exports=False)
    root, = _roots(run)
    assert root.effective_completeness.control_obligations == (_site(HELPER, 0),)
    assert run.control_exemptions == ()
    assert "import-slots-hold-their-exports" not in run.assumptions


@pytest.mark.parametrize("target", ["global-slot", "register"])
def test_a_jump_to_an_unknown_destination_stays_a_site(target):
    """``jmp [slot]`` whose slot names no import, ``jmp rax``: unknown."""
    thunk = _thunk(SLOT + 8) if target == "global-slot" else FunctionBuilder(entry=HELPER).jump_indirect(reg(RAX))
    run = _run(_caller_of_thunk(), extra=(thunk,), image=True, imports=IMPORTS)
    root, = _roots(run)
    assert root.effective_completeness.control_obligations == (_site(HELPER, 0),)
    assert not root.is_effectively_complete
    assert run.control_exemptions == ()


def test_an_exempt_jump_leaves_no_key_but_the_binding_stays_conditional():
    """rcx = 7; if (zf) goto ok; jmp [__imp_X]; ok: call sink -- no unknown
    transfer remains (the jump is an import tail), but the state barrier still
    sees an incomplete successor graph: the root is bound on the observed
    graph, marked conditional, incomplete."""
    main, _ = _guarded(_main().ins(copy(reg(RCX), const(7))),
                       lambda b: b.call(SINK).add_rsp(0x28).ret(),
                       lambda b: b.jump_indirect(ram(SLOT)))
    run = _run(main, image=True, imports=IMPORTS)
    root, = _roots(run)
    completeness = root.effective_completeness
    assert completeness.control_obligations == ()
    assert completeness.unbound_roots == 0 and completeness.conditional_roots == 1
    assert not root.is_effectively_complete
    assert len(run.control_exemptions) == 1


def test_a_cut_conditional_binding_falls_back_to_the_strict_one(monkeypatch):
    """Its own diagnostic budget exhausted, the conditional binding is
    dropped: today's unbound root, still marked by the function's site.
    (The exhaustion is injected: this fixture's binding charges no work unit,
    so no budget could cut it.)"""
    from tdo_v2.integration import configured_boundary_demands as demands
    from tdo_v2.resource_limits import DiagnosticExhausted

    def exhausted(self, span, before_position):
        raise DiagnosticExhausted("cut")

    monkeypatch.setattr(demands._ConditionalSinkState, "state_definition", exhausted)
    main, index = _guarded_ud2(_main().ins(copy(reg(RCX), const(7))),
                               lambda b: b.call(SINK).add_rsp(0x28).ret())
    root, = _roots(_run(main))
    completeness = root.effective_completeness
    assert completeness.unbound_roots == 1 and completeness.conditional_roots == 0
    assert completeness.control_obligations == (_site(MAIN, index),)


def test_a_resource_failure_in_the_context_graph_refuses_transient_first():
    """F ends in ``jmp rax`` (a semantic refusal: tail exits not composed);
    its context also reaches H, out of a resource -- the refusal is TRANSIENT
    (linking retries it), as export_summary's own closure check would say."""
    from test_summary_templates import F, LIBRARY, MANGLED, WIN64, _every_constant_relocates, _hand_file
    from tdo_v2.image_info import ExportedSymbol, ImageInfo
    from tdo_v2.interprocedural import analyze_units
    from tdo_v2.normalize import NormalizationFailureReason
    from tdo_v2.relative_memory import ImageBaseTracking
    from tdo_v2.summary_store import load_external_models
    from tdo_v2.summary_templates import build_file
    from synthetic import program_units

    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        models = load_external_models([_hand_file(directory)], *WIN64)
        info = ImageInfo("synthetic", (), (), (ExportedSymbol(1, F, MANGLED, True),), ())
        body = FunctionBuilder(entry=F).ins(copy(reg(RCX), const(7))).jump_indirect(reg(RAX))
        with ImageBaseTracking(((0x1000, 0x8000),), _every_constant_relocates) as found:
            results = analyze_units(program_units(body), image_info=info, external_models=models, own_library=LIBRARY)

        def export(extra):
            items = dict(results)
            items.update(extra)
            return build_file(items, [(f"1:{F:x}", "F", [MANGLED])], file_id="synth-derived", version=1,
                              library=LIBRARY, external_models=models, pcodeop_models=None,
                              private_frame_above=0, base_dependent=found)[1]["F"]

        assert export({}).kind == "semantic"
        failed = replace(results[f"1:{F:x}"], key="1:9000", calls={}, multi_calls={}, multi_candidates={},
                         normalized=SimpleNamespace(reason=NormalizationFailureReason.ANALYSIS_BUDGET))
        results[f"1:{F:x}"].multi_candidates = {"x": ("1:9000",)}
        assert export({"1:9000": failed}).kind == "transient"


def test_a_root_left_at_its_consume_event_is_not_marked_conditional():
    """... ud2 ...; call sink([rdx]) with rdx known but [rdx] never written:
    the base resolves on the observed graph, the bytes do not -- an unbound
    root, not a conditional binding."""
    provider = SymbolBoundaryProvider((
        BoundaryRule("sink", LANGUAGE, BoundaryKind.SINK, "sink.mem",
                     (PhysicalMemorySlice(PhysicalRegisterSlice(RDX, 8), 0, 4),)),
    ))
    main, index = _guarded_ud2(_main().ins(copy(reg(RDX), reg(RCX))), lambda b: b.call(SINK).add_rsp(0x28).ret())
    root, = _roots(_run(main, provider=provider), label="sink.mem")
    completeness = root.effective_completeness
    assert completeness.conditional_roots == 0
    assert completeness.control_obligations == (_site(MAIN, index),)


def test_a_callee_failing_after_its_callers_roots_marks_them_unavailable(monkeypatch):
    """main: rcx = 7; call sink; call helper -- main's root is built, then
    helper fails in the roots loop: main rests on helper, whose context is
    now unknown (r5 A'): ``control:unavailable:helper``, incomplete."""
    import tdo_v2.summary_engine as engine
    from tdo_v2.resource_limits import AnalysisBudgetExceeded

    original = engine._raw_root_groups

    def failing(analysis, rows):
        if analysis.entry.byte_offset == HELPER:
            raise AnalysisBudgetExceeded("work", "injected")
        return original(analysis, rows)

    monkeypatch.setattr(engine, "_raw_root_groups", failing)
    helper = _main(HELPER).add_rsp(0x28).ret()
    main = _main().ins(copy(reg(RCX), const(7))).call(SINK).call(HELPER).add_rsp(0x28).ret()
    run = _run(main, extra=(helper,))
    root, = _roots(run)
    assert unavailable_key(_key(HELPER)) in root.effective_completeness.control_obligations
    assert not root.is_effectively_complete
    assert any(key == _key(HELPER) for key, _, _ in run.failed_functions)


# -- the completeness contract ------------------------------------------------

def test_a_root_resting_on_a_transfer_is_never_complete():
    with pytest.raises(ValueError):
        LocalCompleteness(True, 0, 0, control_obligations=("control:1:0:4",))
    with pytest.raises(ValueError):
        LocalCompleteness(True, 0, 0, conditional_roots=1)
    marked = with_control(LocalCompleteness(True, 0, 0), ("control:1:0:4",))
    assert not marked.complete and marked.control_obligations == ("control:1:0:4",)
    assert with_control(marked, ()) is marked


# -- control contexts ---------------------------------------------------------

def _row(address, *, opcodes=("COPY",), targets=(), call=None):
    operations = [SimpleNamespace(opcode=opcode, inputs=()) for opcode in opcodes]
    if call is not None:
        operations.append(SimpleNamespace(opcode="CALL", inputs=(SimpleNamespace(
            coordinate=SimpleNamespace(space_id=RAM, byte_offset=call)),)))
    return SimpleNamespace(address=SimpleNamespace(space_id=RAM, byte_offset=address),
                           flow_targets=tuple(SimpleNamespace(space_id=RAM, byte_offset=t) for t in targets),
                           operations=operations)


def _item(rows, calls=(), multi=()):
    return SimpleNamespace(unit=SimpleNamespace(observation=SimpleNamespace(instructions=rows)),
                           calls=dict(calls), multi_calls={}, multi_candidates=dict(multi))


def test_contexts_follow_calls_candidates_and_cycles():
    a, b, c, d, e = 0x100, 0x200, 0x300, 0x400, 0x500
    results = {
        _key(a): _item([_row(a, call=b)]),
        _key(b): _item([_row(b, opcodes=("BRANCHIND",)), _row(b + 4, call=a)]),   # site; cycle a <-> b
        _key(c): _item([_row(c)], multi={"x": (_key(b),)}),                       # an unfiltered candidate
        _key(d): _item([_row(d, opcodes=("BRANCHIND",), targets=(e,))]),          # a targeted jump: no site
        _key(e): _item([_row(e)]),
    }
    found = control_contexts(results, {_key(e): "failed"})
    site = site_key(_key(b), SimpleNamespace(space_id=RAM, byte_offset=b))
    assert found[_key(a)] == found[_key(b)] == found[_key(c)] == frozenset({site})
    assert found[_key(d)] == found[_key(e)] == frozenset({unavailable_key(_key(e))})


def test_the_closure_is_reachability():
    own = {"a": {"x"}, "b": set(), "c": {"y"}, "d": set(), "e": {"z"}}
    edges = {"a": {"b"}, "b": {"c", "a"}, "c": set(), "d": {"a"}, "e": set()}
    assert _closure(own, edges) == {"a": {"x", "y"}, "b": {"x", "y"}, "c": {"y"}, "d": {"x", "y"}, "e": {"z"}}


def test_a_template_refuses_a_function_resting_on_a_transfer():
    from tdo_v2.normalize import NormalizationFailureReason
    from tdo_v2.summary_templates import TemplateRefused, _refuse_control_context

    _refuse_control_context("1:100", frozenset(), {})
    with pytest.raises(TemplateRefused) as error:
        _refuse_control_context("1:100", frozenset({"control:1:100:1:104"}), {})
    assert error.value.kind == "semantic"
    failed = {"1:200": SimpleNamespace(normalized=SimpleNamespace(reason=NormalizationFailureReason.ANALYSIS_BUDGET))}
    with pytest.raises(TemplateRefused) as error:
        _refuse_control_context("1:100", frozenset({unavailable_key("1:200")}), failed)
    assert error.value.kind == "transient"
