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


def test_a_refusal_without_entry_marks_every_call_outside_the_program():
    """A member refused before its entry was validated (FUNCTION_COORDINATE)
    has no known entry: any direct call to an address that is no function of
    the program may reach it -- unavailable under the called address."""
    unknown = FunctionBuilder(entry=0x10).ret()   # (entry outside committed memory)
    run = _run([_main(REFUSED), FunctionBuilder(entry=SINK).ret(), unknown])
    assert len(run.admission_failures) == 1
    assert run.admission_failures[0].unit.scopes.function.entry is None
    root = _root(run)
    assert unavailable_key(_key(REFUSED)) in root.effective_completeness.control_obligations
    assert not root.is_effectively_complete


def test_a_resolved_indirect_call_to_a_refused_function_marks_the_caller():
    """main: rax = &refused; call rax -- the indirect target resolves to a
    refused function: the call stays opaque and the caller rests on it."""
    main = (FunctionBuilder(entry=MAIN).sub_rsp(0x28).ins(copy(reg(RCX), const(7))).call(SINK)
            .ins(copy(reg(RAX), const(REFUSED))).call_indirect(RAX).add_rsp(0x28).ret())
    run = _run([main, FunctionBuilder(entry=SINK).ret(), _refused()])
    root = _root(run)
    assert unavailable_key(_key(REFUSED)) in root.effective_completeness.control_obligations
