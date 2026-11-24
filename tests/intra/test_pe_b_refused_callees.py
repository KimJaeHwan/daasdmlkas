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
    assert (scope.entry.space_id, scope.entry.byte_offset) == (RAM, REFUSED)


def test_only_an_observation_refusal_may_retain_an_entry():
    from tdo_v2._scope_contracts import AddressCoordinate
    from tdo_v2._scope_results import ScopeConstructionReason

    with pytest.raises(ValueError):
        UnresolvedFunctionScope(ScopeConstructionStage.FUNCTION_COORDINATE,
                                ScopeConstructionReason.INVALID_FUNCTION_ENTRY, entry=AddressCoordinate(RAM, REFUSED))


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
    assert run.admission_failures[0].unit.scopes.function.entry is None
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

    def forward(item, functions, readonly_image):
        if item.unit.scopes.function.entry.byte_offset != MAIN:
            return {}, {}
        key = next(call for call, _, _ in ip._callind_sites(item.unit))
        return {key: (_key(REFUSED), _key(WRAPPER))}, {key: frozenset()}

    monkeypatch.setattr(ip, "_forward_targets", forward)
    results = ip.analyze_units(units, unavailable_entries=frozenset({_key(REFUSED)}))
    support = results[_key(MAIN)].summary.control_support
    assert unavailable_key(_key(REFUSED)) in support
    leaf_sites = {site for site in results[_key(WRAPPER)].summary.control_support if site.startswith("control:")}
    # the leaf's own obligations, or (not yet summarized when the caller derives) the leaf as unavailable
    assert leaf_sites and (leaf_sites <= set(support) or unavailable_key(_key(WRAPPER)) in support)
    assert any(_key(WRAPPER) in members for members in results[_key(MAIN)].multi_candidates.values())
