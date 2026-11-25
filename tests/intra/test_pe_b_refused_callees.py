"""PE-b (design `design_s3_r18.md` amendment 3, PRE-EXISTING): a function whose
admission is refused is no analysed function, but it is still a function of the
program. Callers reaching it -- by a direct call, a tail jump or a resolved
indirect call -- rest on code nobody analysed: their support carries
``control:unavailable:<entry>`` (docs 25.93) and their roots are never complete.
Before PE-b the refused member vanished before call discovery and such a call
read as a call outside the analysed set (no key)."""

import pytest
from synthetic import (
    CODE_BASE, RAM, RAX, RCX, FunctionBuilder, _Provider, _mint_orchestrator_capability, _naming_for, boundary, const,
    copy, open_configured_extraction, ram, reg,
)
from tdo_v2._scope_results import ScopeConstructionStage, UnresolvedFunctionScope
from tdo_v2.control_context import unavailable_key
from tdo_v2.integration.observed_function_session import ObservedFunctionAdmissionFailure

MAIN, SINK, REFUSED, WRAPPER, OTHER = (CODE_BASE, CODE_BASE + 0xA00, CODE_BASE + 0xC00, CODE_BASE + 0xE00,
                                       CODE_BASE + 0x1000)
NAMES = {SINK: "sink"}
REGISTER_SINK = boundary({}, {"sink": 8})


def _key(entry):
    return f"{RAM:x}:{entry:x}"


def _refused(entry=REFUSED):
    # ADDRESS zero is not committed: the observation is refused (stage FUNCTION_OBSERVATION)
    return FunctionBuilder(entry=entry).ins(copy(reg(RAX), ram(0))).ret()


def _run(bodies, **options):
    from tdo_v2.call_seeds import seed_function_calls, seed_tail_calls
    from tdo_v2.integration.observed_function_session import ObservedFunctionEvidence
    from tdo_v2.summary_engine import analyze_observed_with_summaries

    with open_configured_extraction(_Provider(list(bodies)), _mint_orchestrator_capability()) as envelope:
        program = envelope.program_result
        units = list(envelope.iter_scoped_functions())
    evidences = []
    for index, unit in enumerate(units):
        if type(unit.scopes.function) is UnresolvedFunctionScope:
            evidences.append(ObservedFunctionAdmissionFailure(
                b"g" * 32, f"function-{index}", f"function-{index}", bytes([index + 1]) * 32, unit))
            continue
        seeds, tails = seed_function_calls(unit), seed_tail_calls(unit)
        evidences.append(ObservedFunctionEvidence(unit, seeds, _naming_for(unit, seeds, NAMES, tails), tails))
    return analyze_observed_with_summaries(program, evidences, boundary_provider=REGISTER_SINK, **options)


def _root(run, entry=MAIN):
    found = [root for root in run.roots if root.function_byte_offset == entry and root.label == "sink.arg0"]
    assert len(found) == 1, "the sink occurrence was dropped"
    return found[0]


def _main(*then):
    builder = FunctionBuilder(entry=MAIN).sub_rsp(0x28).ins(copy(reg(RCX), const(7))).call(SINK)
    for target in then:
        builder = builder.call(target)
    return builder.add_rsp(0x28).ret()


def test_an_observation_refusal_keeps_its_validated_entry():
    with open_configured_extraction(_Provider([_refused()]), _mint_orchestrator_capability()) as envelope:
        unit, = list(envelope.iter_scoped_functions())
    scope = unit.scopes.function
    assert type(scope) is UnresolvedFunctionScope
    assert scope.stage is ScopeConstructionStage.FUNCTION_OBSERVATION
    assert (scope.refused_entry.space_id, scope.refused_entry.byte_offset) == (RAM, REFUSED)
    assert not hasattr(scope, "entry")   # (code tells an admitted scope by ``entry``)


def test_only_an_observation_refusal_may_retain_an_entry():
    from tdo_v2._scope_contracts import AddressCoordinate
    from tdo_v2._scope_results import ScopeConstructionReason

    with pytest.raises(ValueError):
        UnresolvedFunctionScope(ScopeConstructionStage.FUNCTION_COORDINATE,
                                ScopeConstructionReason.INVALID_FUNCTION_ENTRY, refused_entry=AddressCoordinate(RAM, REFUSED))


def test_a_direct_call_to_a_refused_function_marks_the_caller_unavailable():
    """main: rcx = 7; call sink; call refused -- the constant root stays (its
    value is computable) but rests on the refused function: never complete."""
    run = _run([_main(REFUSED), FunctionBuilder(entry=SINK).ret(), _refused()])
    assert len(run.admission_failures) == 1
    root = _root(run)
    assert unavailable_key(_key(REFUSED)) in root.effective_completeness.control_obligations
    assert not root.is_effectively_complete


def test_the_mark_reaches_callers_through_a_wrapper():
    wrapper = FunctionBuilder(entry=WRAPPER).sub_rsp(0x28).call(REFUSED).add_rsp(0x28).ret()
    run = _run([_main(WRAPPER), FunctionBuilder(entry=SINK).ret(), wrapper, _refused()])
    root = _root(run)
    assert unavailable_key(_key(REFUSED)) in root.effective_completeness.control_obligations
    assert not root.is_effectively_complete


def test_a_function_not_reaching_the_refused_one_is_unaffected():
    other = FunctionBuilder(entry=OTHER).sub_rsp(0x28).call(REFUSED).add_rsp(0x28).ret()
    run = _run([_main(), FunctionBuilder(entry=SINK).ret(), other, _refused()])
    root = _root(run)
    assert unavailable_key(_key(REFUSED)) not in root.effective_completeness.control_obligations
    assert root.is_effectively_complete


def test_without_the_refused_member_the_call_is_outside_the_set_as_before():
    """Control: the same caller with no refused member in the run (a call to an
    address that is no function of the Bundle) keeps today's reading."""
    run = _run([_main(REFUSED), FunctionBuilder(entry=SINK).ret()])
    root = _root(run)
    assert unavailable_key(_key(REFUSED)) not in root.effective_completeness.control_obligations


def test_a_refusal_without_entry_marks_every_wildcard_holder():
    """A member refused before its entry was validated (FUNCTION_COORDINATE)
    has no known entry: a function holding a wildcard transfer (here a call to
    an address that is no function of the program) may reach it --
    ``control:unavailable:unidentified``."""
    unknown = FunctionBuilder(entry=0x10).ret()   # (entry outside committed memory)
    run = _run([_main(REFUSED), FunctionBuilder(entry=SINK).ret(), unknown])
    assert len(run.admission_failures) == 1
    assert run.admission_failures[0].unit.scopes.function.refused_entry is None
    root = _root(run)
    assert unavailable_key("unidentified") in root.effective_completeness.control_obligations
    assert not root.is_effectively_complete


def test_a_resolved_indirect_call_to_a_refused_function_marks_the_caller():
    """main: rax = &refused; call rax -- the indirect target resolves to a
    refused function: the call stays opaque and the caller rests on it."""
    main = (FunctionBuilder(entry=MAIN).sub_rsp(0x28).ins(copy(reg(RCX), const(7))).call(SINK)
            .ins(copy(reg(RAX), const(REFUSED))).call_indirect(RAX).add_rsp(0x28).ret())
    run = _run([main, FunctionBuilder(entry=SINK).ret(), _refused()])
    root = _root(run)
    assert unavailable_key(_key(REFUSED)) in root.effective_completeness.control_obligations


# -- the static may-reach set (PE-b r2: one set before round 1, not per channel) --

def _units(*bodies):
    with open_configured_extraction(_Provider(list(bodies)), _mint_orchestrator_capability()) as envelope:
        return [unit for unit in envelope.iter_scoped_functions()
                if type(unit.scopes.function) is not UnresolvedFunctionScope]


def test_summary_support_holds_the_key_through_a_register_free_tail_chain():
    """a: tail -> b; b: tail -> refused. Neither touches a register: the key
    must be in each SUMMARY's support (not only in the report-time context)."""
    from tdo_v2.interprocedural import analyze_units

    a = FunctionBuilder(entry=MAIN).tail_call(WRAPPER)
    b = FunctionBuilder(entry=WRAPPER).tail_call(REFUSED)
    results = analyze_units(_units(a, b), unavailable_entries=frozenset({_key(REFUSED)}))
    for entry in (MAIN, WRAPPER):
        summary = results[_key(entry)].summary
        assert summary is not None and unavailable_key(_key(REFUSED)) in summary.control_support


def test_a_cut_wrapper_still_carries_the_key_to_its_callers():
    """The set runs over every observed function, cut ones included: a caller
    of a (model- or binding-) cut wrapper that calls a refused function is
    marked even though the wrapper is never analysed."""
    from tdo_v2.interprocedural import _refused_reach

    units = {f"{RAM:x}:{u.scopes.function.entry.byte_offset:x}": u for u in _units(
        FunctionBuilder(entry=MAIN).sub_rsp(0x28).call(WRAPPER).add_rsp(0x28).ret(),
        FunctionBuilder(entry=WRAPPER).sub_rsp(0x28).call(REFUSED).add_rsp(0x28).ret(),
        FunctionBuilder(entry=OTHER).ret())}
    reach = _refused_reach(units, frozenset({_key(REFUSED)}), False)
    assert reach[_key(WRAPPER)] == {unavailable_key(_key(REFUSED))}
    assert reach[_key(MAIN)] == {unavailable_key(_key(REFUSED))}   # (through the cut wrapper's body)
    assert _key(OTHER) not in reach


def test_an_unresolved_indirect_transfer_follows_the_2c_limit():
    """Owner 2026-11-24: an UNRESOLVED CALLIND emits no refused key (the named
    limit 2c: an unresolved indirect call emits no key whatever it may reach);
    a resolved one does (``test_a_resolved_indirect_call_...``)."""
    from tdo_v2.interprocedural import _refused_reach

    holder = FunctionBuilder(entry=MAIN).sub_rsp(0x28).ins(copy(reg(RAX), reg(RCX))).call_indirect(RAX).add_rsp(0x28).ret()
    units = {_key(MAIN): _units(holder)[0]}
    assert _refused_reach(units, frozenset({_key(REFUSED)}), False) == {}
    assert _refused_reach(units, frozenset(), True) == {}


def test_an_admitted_and_a_refused_member_sharing_an_entry_is_rejected():
    from tdo_v2.interprocedural import analyze_units

    with pytest.raises(ValueError, match="share an entry"):
        analyze_units(_units(_main()), unavailable_entries=frozenset({_key(MAIN)}))


def test_no_refusal_no_change():
    from tdo_v2.interprocedural import _refused_reach

    units = {_key(MAIN): _units(_main(REFUSED))[0]}
    assert _refused_reach(units, frozenset(), False) == {}


# -- code review r2 (Astra): conditional tails, implicit refusals, bindings, mixed forward sets --

def test_a_conditional_tail_into_a_refused_entry_is_a_transfer():
    """``if (zf) goto refused`` as an absolute CBRANCH with no listed target:
    the static set still sees it (Astra r2 P1-1)."""
    from synthetic import ZF, op
    from tdo_v2.interprocedural import _refused_reach

    main = (FunctionBuilder(entry=MAIN).ins(copy(reg(RAX), reg(RCX)))
            .ins(op("CBRANCH", [ram(REFUSED), reg(ZF, 1)])).ret())
    units = {_key(MAIN): _units(main)[0]}
    assert _refused_reach(units, frozenset({_key(REFUSED)}), False)[_key(MAIN)] == {unavailable_key(_key(REFUSED))}


def test_a_conditional_jump_out_of_the_program_is_an_outside_transfer():
    from synthetic import ZF, op
    from tdo_v2.interprocedural import _refused_reach

    main = (FunctionBuilder(entry=MAIN).ins(copy(reg(RAX), reg(RCX)))
            .ins(op("CBRANCH", [ram(CODE_BASE + 0x800), reg(ZF, 1)])).ret())   # (committed code, no function)
    units = {_key(MAIN): _units(main)[0]}
    assert unavailable_key("unidentified") in _refused_reach(units, frozenset(), True)[_key(MAIN)]


def test_a_refused_unit_passed_to_analyze_units_is_never_dropped():
    """The public ``analyze_units`` with an admitted caller and a refused unit
    and no ``unavailable_entries``: the refusal is taken from the unit itself
    (Astra r2 P1-4) -- the caller's summary carries the key."""
    from tdo_v2.interprocedural import analyze_units

    with open_configured_extraction(_Provider([_main(REFUSED), FunctionBuilder(entry=SINK).ret(), _refused()]),
                                    _mint_orchestrator_capability()) as envelope:
        units = list(envelope.iter_scoped_functions())
    assert any(type(unit.scopes.function) is UnresolvedFunctionScope for unit in units)
    results = analyze_units(units)
    assert unavailable_key(_key(REFUSED)) in results[_key(MAIN)].summary.control_support


def test_a_binding_naming_a_refused_entry_is_refused_not_an_abort():
    """Astra r2 P1-2: a model binding at a refused member's rva raised
    ``ModelError`` and aborted the run; it is now recorded and not applied."""
    from types import SimpleNamespace

    from tdo_v2.interprocedural import _bound_cuts

    unit = _units(_main())[0]
    evidence = unit.scopes.program.evidence
    binding = SimpleNamespace(
        executable_sha256=evidence.executable_sha256.hex(), language_id=evidence.translation_namespace.language_id,
        abi_tag="abi", binding_id="b", rows=[(REFUSED - evidence.image_base.byte_offset, "m", None)],
        entry=lambda model_id: (_ for _ in ()).throw(AssertionError("a refused entry is never looked up")))
    models = SimpleNamespace(files=[SimpleNamespace(abi_tag="abi")])
    refusals = {}
    found = _bound_cuts({_key(MAIN): unit}, [binding], frozenset(), models, refusals, frozenset({_key(REFUSED)}))
    assert found == {}
    assert "refused at admission" in next(iter(refusals[_key(REFUSED)].values()))


def test_a_mixed_forward_set_keeps_the_healthy_members_support(monkeypatch):
    """A forward set {refused, leaf}: the call stays opaque, but the leaf's
    support (its unknown-transfer site) and the refused key both reach the
    caller's summary, and the leaf stays a published candidate (Astra r2 P1-3)."""
    import tdo_v2.interprocedural as ip
    from tdo_v2.control_context import site_key

    leaf = FunctionBuilder(entry=WRAPPER).jump_indirect(reg(RAX))   # (a targetless BRANCHIND: a site)
    main = (FunctionBuilder(entry=MAIN).sub_rsp(0x28).ins(copy(reg(RAX), reg(RCX))).call_indirect(RAX)
            .add_rsp(0x28).ret())
    units = _units(main, leaf)
    monkeypatch.setattr(ip, "_forward_switched_on", lambda: True)

    def forward(item, functions, readonly_image, refused=frozenset()):
        if item.unit.scopes.function.entry.byte_offset != MAIN:
            return {}, {}
        key = next(call for call, _, _ in ip._callind_sites(item.unit))
        return {key: (_key(REFUSED), _key(WRAPPER))}, {key: frozenset()}

    monkeypatch.setattr(ip, "_forward_targets", forward)
    results = ip.analyze_units(units, unavailable_entries=frozenset({_key(REFUSED)}))
    support = results[_key(MAIN)].summary.control_support
    assert unavailable_key(_key(REFUSED)) in support
    leaf_sites = {site for site in results[_key(WRAPPER)].summary.control_support if site.startswith("control:")}
    # the leaf is ordered first (an ordering edge): its own obligations reach the caller
    assert leaf_sites and leaf_sites <= set(support)
    assert any(_key(WRAPPER) in members for members in results[_key(MAIN)].multi_candidates.values())


# -- code review r3 (Astra): overlapping / listed targets, kind-4 exits, fallbacks, import models, contexts --

def _double(entry, rows, exits=()):
    from types import SimpleNamespace as NS

    return NS(scopes=NS(function=NS(entry=NS(space_id=RAM, byte_offset=entry))),
              observation=NS(instructions=rows, fallthrough_exits=exits))


def _drow(address, opcodes=(), targets=()):
    from types import SimpleNamespace as NS

    return NS(address=NS(space_id=RAM, byte_offset=address),
              operations=[NS(opcode=opcode, inputs=()) for opcode in opcodes],
              flow_targets=tuple(NS(space_id=RAM, byte_offset=t) for t in targets))


def test_a_listed_target_equal_to_a_refused_entry_is_a_transfer_even_inside_the_row_range():
    from tdo_v2.interprocedural import _static_transfers

    # (the refused entry is also one of the caller's own row addresses: overlapping code)
    unit = _double(MAIN, [_drow(MAIN, ("CALLIND",), targets=(MAIN + 4,)), _drow(MAIN + 4)])
    targets, _, _ = _static_transfers(unit, {_key(MAIN): unit}, frozenset({_key(MAIN + 4)}))
    assert _key(MAIN + 4) in targets


def test_a_kind_4_exit_naming_a_refused_entry_is_a_transfer():
    from types import SimpleNamespace as NS

    from tdo_v2.interprocedural import _static_transfers

    exit_row = NS(source=NS(space_id=RAM, byte_offset=MAIN), target=NS(space_id=RAM, byte_offset=REFUSED),
                  kind=4, function=None)
    unit = _double(MAIN, [_drow(MAIN, ("CALL",))], exits=(exit_row,))
    targets, _, _ = _static_transfers(unit, {_key(MAIN): unit}, frozenset({_key(REFUSED)}))
    assert _key(REFUSED) in targets


def test_a_late_refused_resolution_fails_the_round_1_publication():
    """A fallback publishes round 1, where the transfer later resolved to a
    refused function is still unresolved: its owner and callers fail
    (``refused:late-resolution``), never a complete result."""
    from tdo_v2.interprocedural import _without_late_refusals, analyze_units

    units = _units(_main(WRAPPER), FunctionBuilder(entry=WRAPPER).ret(), FunctionBuilder(entry=SINK).ret())
    published = analyze_units(units)
    functions = {f"{RAM:x}:{u.scopes.function.entry.byte_offset:x}": u for u in units}
    found = _without_late_refusals(published, {_key(WRAPPER)}, functions, {})
    assert found[_key(WRAPPER)].failure_detail == "refused:late-resolution"
    assert found[_key(MAIN)].failure_detail == "refused:late-resolution"   # (a caller)
    assert found[_key(SINK)] is published[_key(SINK)]                       # (unrelated)
    assert _without_late_refusals(published, (), functions, {}) is published


def test_no_import_model_at_a_transfer_to_a_refused_entry():
    from tdo_v2.interprocedural import _transfers_to

    unit = _units(_main(REFUSED))[0]
    keys = _transfers_to(unit, frozenset({_key(REFUSED)}))
    assert len(keys) == 1 and next(iter(keys)).endswith(":CALL")
    assert _transfers_to(unit, frozenset({_key(OTHER)})) == frozenset()


def test_contexts_follow_jumps_and_conditional_jumps_to_entries():
    from types import SimpleNamespace as NS

    from tdo_v2._scope_contracts import VarnodeKindCode
    from tdo_v2.control_context import control_contexts

    def jump(opcode, target):
        return NS(opcode=opcode, inputs=(NS(kind=VarnodeKindCode.ADDRESS,
                                            coordinate=NS(space_id=RAM, byte_offset=target)),))

    row = NS(address=NS(space_id=RAM, byte_offset=MAIN), flow_targets=(), operations=[jump("CBRANCH", REFUSED)])
    item = NS(unit=NS(observation=NS(instructions=[row])), calls={}, multi_calls={}, multi_candidates={})
    found = control_contexts({_key(MAIN): item}, {_key(REFUSED): ("admission",)})
    assert unavailable_key(_key(REFUSED)) in found[_key(MAIN)]


def test_a_resolved_target_that_is_a_cut_wrapper_carries_the_wrappers_static_reach(tmp_path):
    """main: rax = &helper; call rax -- helper is cut by an internal model
    (never analysed: the model is applied) and its body calls a refused
    function. The resolution names helper: main carries helper's static reach."""
    import json
    from pathlib import Path

    from synthetic import NO_CALLBACKS, program_units
    from tdo_v2.image_info import ExportedSymbol, ImageInfo
    from tdo_v2.interprocedural import analyze_units
    from tdo_v2.summary_store import load_external_models

    helper_entry, mangled = CODE_BASE + 0x800, "?Helper@@YA_K_K@Z"
    entry = {"name": "Helper", "original_names": [mangled], "registers": [{"write": [0, 8], "from": [[8, 8]]}],
             "memory": [], **NO_CALLBACKS, "other_memory": "preserved", "internal": True}
    raw = {"format_version": 1, "kind": "declared", "id": "synth", "version": 1,
           "language_id": "x86:LE:64:default", "abi_tag": "win64", "libraries": ["SYNTH.DLL"],
           "stack_pointer": [32, 8], "stack_delta": 8, "preserved": [[24, 8], [40, 8], [48, 8], [56, 8]],
           "entries": [entry]}
    path = Path(tmp_path) / "synth.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    models = load_external_models([path], "x86:LE:64:default", "win64")
    info = ImageInfo("synthetic", (), (), (ExportedSymbol(1, helper_entry, mangled, True),), ())
    helper = FunctionBuilder(entry=helper_entry).sub_rsp(0x28).call(REFUSED).add_rsp(0x28).ret()
    main = (FunctionBuilder(entry=MAIN).sub_rsp(0x28).ins(copy(reg(RAX), const(helper_entry))).call_indirect(RAX)
            .add_rsp(0x28).ret())
    results = analyze_units(program_units(main, helper), image_info=info, external_models=models,
                            own_library="SYNTH.DLL", unavailable_entries=frozenset({_key(REFUSED)}))
    assert _key(helper_entry) not in results   # (cut)
    assert unavailable_key(_key(REFUSED)) in results[_key(MAIN)].summary.control_support


def test_no_import_model_is_bound_at_a_call_to_a_refused_entry():
    from types import SimpleNamespace as NS

    from tdo_v2.interprocedural import _external_sites

    unit = _units(_main(REFUSED))[0]
    call = next(iter(__import__("tdo_v2.interprocedural", fromlist=["_transfers_to"])._transfers_to(
        unit, frozenset({_key(REFUSED)}))))
    model = (NS(), NS(noreturn=True, inherited=(), label="abort"))
    models = NS(lookup=lambda symbol: model)
    refused = {}
    assert _external_sites(unit, None, models, sites={call: "abort"}) == {call: model}   # (control)
    assert _external_sites(unit, None, models, refused=refused, sites={call: "abort"},
                           refused_entries=frozenset({_key(REFUSED)})) == {}
    assert "refused at admission" in refused[call]


def test_a_forward_set_naming_a_refused_function_is_kept_whatever_else_it_names(monkeypatch):
    """{refused, an address that is no function}: the all-members filter
    used to drop the whole set (and the refused member with it)."""
    from dataclasses import replace
    from types import SimpleNamespace as NS

    import tdo_v2.forward as forward_module
    import tdo_v2.interprocedural as ip

    unit = _units(FunctionBuilder(entry=MAIN).sub_rsp(0x28).ins(copy(reg(RAX), reg(RCX))).call_indirect(RAX)
                  .add_rsp(0x28).ret())[0]
    normalized = replace(ip.analyze_units([unit])[_key(MAIN)].normalized, forward_inputs=object())
    call = next(c for c, _, _ in ip._callind_sites(unit))
    interval = NS(lo=CODE_BASE + 0x800, hi=REFUSED, stride=REFUSED - (CODE_BASE + 0x800))
    fact = NS(operation=call, claim=NS(is_top=False, items=[(("abs",), interval)]), requires=())
    monkeypatch.setattr(forward_module, "forward_facts", lambda *a, **k: [fact])
    item = NS(normalized=normalized, unit=unit)
    assert ip._forward_targets(item, {_key(MAIN)}, None) == ({}, {})   # (control: dropped)
    found, _ = ip._forward_targets(item, {_key(MAIN)}, None, refused=frozenset({_key(REFUSED)}))
    assert found == {call: tuple(sorted((_key(REFUSED), _key(CODE_BASE + 0x800))))}


# -- code review r4 (Astra 5 P1, Fable 2 P2): cut bodies, late fallbacks, kind-4 targets, jumps --

def _cut_models(tmp_path, cut_entry, mangled="?Helper@@YA_K_K@Z"):
    import json
    from pathlib import Path

    from synthetic import NO_CALLBACKS
    from tdo_v2.image_info import ExportedSymbol, ImageInfo
    from tdo_v2.summary_store import load_external_models

    entry = {"name": "Helper", "original_names": [mangled], "registers": [{"write": [0, 8], "from": [[8, 8]]}],
             "memory": [], **NO_CALLBACKS, "other_memory": "preserved", "internal": True}
    raw = {"format_version": 1, "kind": "declared", "id": "synth", "version": 1,
           "language_id": "x86:LE:64:default", "abi_tag": "win64", "libraries": ["SYNTH.DLL"],
           "stack_pointer": [32, 8], "stack_delta": 8, "preserved": [[24, 8], [40, 8], [48, 8], [56, 8]],
           "entries": [entry]}
    path = Path(tmp_path) / "synth.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    info = ImageInfo("synthetic", (), (), (ExportedSymbol(1, cut_entry, mangled, True),), ())
    return info, load_external_models([path], "x86:LE:64:default", "win64")


def test_a_model_cut_replaces_its_body_and_its_premise_covers_what_it_reaches(tmp_path):
    """main -> cut wrapper -> inner; inner's CALLIND resolves to a refused
    function. The cut is replaced by its model: main uses the model under its
    named premise, which covers the body (and what the body reaches) -- PE-b
    does not look behind a cut (docs 25.116; widening timed out the UE
    derivation). Inner itself carries the key."""
    from synthetic import program_units
    from tdo_v2.interprocedural import analyze_units

    cut = CODE_BASE + 0x800
    info, models = _cut_models(tmp_path, cut)
    inner = (FunctionBuilder(entry=WRAPPER).sub_rsp(0x28).ins(copy(reg(RAX), const(REFUSED))).call_indirect(RAX)
             .add_rsp(0x28).ret())
    wrapper = FunctionBuilder(entry=cut).sub_rsp(0x28).call(WRAPPER).add_rsp(0x28).ret()
    results = analyze_units(program_units(_main(cut), wrapper, inner, FunctionBuilder(entry=SINK).ret()),
                            image_info=info, external_models=models, own_library="SYNTH.DLL",
                            unavailable_entries=frozenset({_key(REFUSED)}))
    assert _key(cut) not in results
    assert unavailable_key(_key(REFUSED)) in results[_key(WRAPPER)].summary.control_support
    assert unavailable_key(_key(REFUSED)) not in results[_key(MAIN)].summary.control_support
    assert "external-model:synth/Helper@v1" in results[_key(MAIN)].declared.values()


def test_a_kind_4_exit_to_an_admitted_entry_is_an_edge():
    from types import SimpleNamespace as NS

    from tdo_v2.interprocedural import _static_transfers

    exit_row = NS(source=NS(space_id=RAM, byte_offset=MAIN), target=NS(space_id=RAM, byte_offset=WRAPPER),
                  kind=4, function=None)
    unit = _double(MAIN, [_drow(MAIN, ("CALL",))], exits=(exit_row,))
    other = _double(WRAPPER, [_drow(WRAPPER)])
    targets, _, _ = _static_transfers(unit, {_key(MAIN): unit, _key(WRAPPER): other}, frozenset())
    assert _key(WRAPPER) in targets


def test_a_late_fallback_follows_resolved_edges_and_identified_transfers():
    """The owner's caller reaches it only by a CALLIND resolved in a later
    round (``late_edges``): it is published failed too."""
    from tdo_v2.interprocedural import _without_late_refusals, analyze_units

    holder = (FunctionBuilder(entry=MAIN).sub_rsp(0x28).ins(copy(reg(RAX), reg(RCX))).call_indirect(RAX)
              .add_rsp(0x28).ret())
    units = _units(holder, FunctionBuilder(entry=WRAPPER).ret(), FunctionBuilder(entry=SINK).ret())
    published = analyze_units(units)
    functions = {f"{RAM:x}:{u.scopes.function.entry.byte_offset:x}": u for u in units}
    without = _without_late_refusals(published, {_key(WRAPPER)}, functions, {})
    assert without[_key(MAIN)] is published[_key(MAIN)]   # (control: no edge known)
    found = _without_late_refusals(published, {_key(WRAPPER)}, functions, {},
                                   late_edges={_key(MAIN): {_key(WRAPPER)}})
    assert found[_key(MAIN)].failure_detail == "refused:late-resolution"


def test_no_noreturn_model_at_a_jump_to_a_refused_entry():
    from types import SimpleNamespace as NS

    from tdo_v2.interprocedural import _noreturn_jumps

    unit = _units(FunctionBuilder(entry=MAIN).tail_call(REFUSED))[0]
    info = NS(import_at_thunk=lambda space, offset: "abort" if offset == REFUSED else None)
    model = (NS(), NS(noreturn=True, inherited=(), label="abort"))
    models = NS(lookup=lambda symbol: model if symbol == "abort" else None)
    assert _noreturn_jumps(unit, info, models, {}) != {}   # (control)
    refused = {}
    assert _noreturn_jumps(unit, info, models, {}, refused=refused,
                           refused_entries=frozenset({_key(REFUSED)})) == {}
    assert any("refused at admission" in why for why in refused.values())


def test_a_forward_fact_on_a_jump_is_read_for_a_refused_member_only(monkeypatch):
    from dataclasses import replace
    from types import SimpleNamespace as NS

    import tdo_v2.forward as forward_module
    import tdo_v2.interprocedural as ip

    unit = _units(FunctionBuilder(entry=MAIN).jump_indirect(reg(RAX)))[0]
    normalized = replace(ip.analyze_units([unit])[_key(MAIN)].normalized, forward_inputs=object())
    key = "1:%x:0:BRANCHIND" % MAIN
    fact = NS(operation=key, claim=NS(is_top=False, items=[(("abs",), NS(lo=REFUSED, hi=REFUSED, stride=0))]),
              requires=())
    monkeypatch.setattr(forward_module, "forward_facts", lambda *a, **k: [fact])
    item = NS(normalized=normalized, unit=unit)
    assert ip._forward_targets(item, {_key(MAIN), _key(REFUSED)}, None) == ({}, {})
    found, _ = ip._forward_targets(item, {_key(MAIN)}, None, refused=frozenset({_key(REFUSED)}))
    assert found == {key: (_key(REFUSED),)}


# -- PE-c (r18 amendment 4): refused members and the stack-switch check --

def test_a_refused_member_withdraws_globals_disjoint_without_whole_program_evidence():
    """The stack-switch check never saw a refused member's code: without clean
    whole-program evidence for this executable, globals-disjoint-from-stack is
    withdrawn (not in the run's assumptions); clean evidence keeps it."""
    from types import SimpleNamespace

    refused_run = _run([_main(), FunctionBuilder(entry=SINK).ret(), _refused()])
    assert "globals-disjoint-from-stack" not in refused_run.assumptions
    plain = _run([_main(), FunctionBuilder(entry=SINK).ret()])
    assert "globals-disjoint-from-stack" in plain.assumptions   # (control)
    evidence = SimpleNamespace(clean=True, executable_sha256=refused_run.executable_sha256, describe=lambda: "x",
                               program="p")
    kept = _run([_main(), FunctionBuilder(entry=SINK).ret(), _refused()], stack_evidence=(evidence,))
    assert "globals-disjoint-from-stack" in kept.assumptions
    other = SimpleNamespace(clean=True, executable_sha256="0" * 64, describe=lambda: "x", program="other")
    elsewhere = _run([_main(), FunctionBuilder(entry=SINK).ret(), _refused()], stack_evidence=(other,))
    assert "globals-disjoint-from-stack" not in elsewhere.assumptions   # (another executable's scan)


def _refused_failures(bodies):
    with open_configured_extraction(_Provider(list(bodies)), _mint_orchestrator_capability()) as envelope:
        units = list(envelope.iter_scoped_functions())
    admitted = [unit for unit in units if type(unit.scopes.function) is not UnresolvedFunctionScope]
    failures = tuple(ObservedFunctionAdmissionFailure(b"g" * 32, f"function-{index}", f"function-{index}",
                                                      bytes([index + 1]) * 32, unit)
                     for index, unit in enumerate(units) if type(unit.scopes.function) is UnresolvedFunctionScope)
    return units, admitted, failures


def test_analyze_units_with_a_refused_unit_withdraws_globals_disjoint_unless_covered():
    """Astra PE-c r1 P1: the direct entry scanned admitted functions only."""
    from tdo_v2.interprocedural import analyze_units

    units, _, _ = _refused_failures([_main(), FunctionBuilder(entry=SINK).ret(), _refused()])
    off = analyze_units(units, assume_globals_disjoint_from_stack=True)
    assert not off[_key(MAIN)].normalized.assumes_globals_disjoint_from_stack
    covered = analyze_units(units, assume_globals_disjoint_from_stack=True, refusals_covered_by_evidence=True)
    assert covered[_key(MAIN)].normalized.assumes_globals_disjoint_from_stack


def test_base_graphs_with_a_refusal_withdraw_globals_disjoint():
    from tdo_v2.base_graph import BaseGraphPolicy, BaseGraphPublication

    _, admitted, failures = _refused_failures([_main(), FunctionBuilder(entry=SINK).ret(), _refused()])
    policy = BaseGraphPolicy(assume_globals_disjoint_from_stack=True)
    result = BaseGraphPublication(admitted, policy=policy, admission_failures=failures).build()
    assert result.policy.assume_globals_disjoint_from_stack is False
    plain = BaseGraphPublication(admitted, policy=policy).build()
    assert plain.policy.assume_globals_disjoint_from_stack is True   # (control)


def test_the_evidence_may_be_a_one_shot_iterator():
    """Astra PE-c r1 P2: the evidence was consumed before the executable check."""
    from types import SimpleNamespace

    probe = _run([_main(), FunctionBuilder(entry=SINK).ret(), _refused()])
    evidence = SimpleNamespace(clean=True, executable_sha256=probe.executable_sha256, describe=lambda: "x",
                               program="p")
    kept = _run([_main(), FunctionBuilder(entry=SINK).ret(), _refused()], stack_evidence=iter((evidence,)))
    assert "globals-disjoint-from-stack" in kept.assumptions


def test_a_dirty_evidence_iterator_still_withdraws():
    """The evidence is read twice (the executable match, then the dirty check):
    as a one-shot iterator, dirty evidence must still withdraw the assumption."""
    from types import SimpleNamespace

    dirty = SimpleNamespace(clean=False, executable_sha256="0" * 64, describe=lambda: "x", program="p")
    run = _run([_main(), FunctionBuilder(entry=SINK).ret()], stack_evidence=iter((dirty,)))
    assert "globals-disjoint-from-stack" not in run.assumptions


def test_the_combined_entry_rejects_disagreeing_refusals():
    """Astra PE-c r2 P1: base graphs and the proof pass must hold the same
    refusals (each decides its stack assumption from its own)."""
    from tdo_v2.base_graph import BaseGraphPolicy, BaseGraphPublication
    from tdo_v2.interprocedural import analyze_units

    _, admitted, failures = _refused_failures([_main(), FunctionBuilder(entry=SINK).ret(), _refused()])
    policy = BaseGraphPolicy(assume_globals_disjoint_from_stack=True)
    publication = BaseGraphPublication(admitted, policy=policy, admission_failures=failures)
    with pytest.raises(ValueError, match="disagree on admission refusals"):
        analyze_units(admitted, base_graphs=publication, assume_globals_disjoint_from_stack=True)
    other = BaseGraphPublication(admitted, policy=policy)
    with pytest.raises(ValueError, match="disagree on admission refusals"):
        analyze_units(admitted, base_graphs=other, assume_globals_disjoint_from_stack=True,
                      unavailable_entries=frozenset({_key(REFUSED)}))
    agreed = BaseGraphPublication(admitted, policy=policy, admission_failures=failures)
    results = analyze_units(admitted, base_graphs=agreed, assume_globals_disjoint_from_stack=True,
                            unavailable_entries=frozenset({_key(REFUSED)}))
    assert not results[_key(MAIN)].normalized.assumes_globals_disjoint_from_stack
