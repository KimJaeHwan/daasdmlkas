"""2b-P P-c3 (design r5 C): typed continuation and SP supports. Continuation
rests on the function's own uses, the closure of what it consumed and its
callees' certificates; an SP delta rests on its independent proof, each
receipt's exact admitted effect and that effect's producers -- not on the
continuation, so an UNKNOWN continuation leaves a proven delta's support."""

from dataclasses import replace

from synthetic import (
    CODE_BASE, DATA_BASE, RAX, RSP, FunctionBuilder, const, copy, op, program_units, reg, register_evidence, store,
)
from tdo_v2.interprocedural import analyze_units
from tdo_v2.premises import ClaimType, PremiseResolver, registry_premise
from tdo_v2.return_relations import PAC_SPEC_12_0_4, certificate_supports, program_certificates

MAIN, CALLEE = CODE_BASE, CODE_BASE + 0x800
GLOBALS = registry_premise("globals-disjoint-from-stack")


def _key(entry):
    return f"1:{entry:x}"


def _units(*builders):
    return program_units(*builders, registers=register_evidence(builders[0].arch))


def _run(*builders, resolver=None, mutate=None, **options):
    results = analyze_units(_units(*builders), **options)
    if mutate is not None:
        mutate(results)
    functions = {key: (item.normalized, item.unit.observation, item.unit.scopes, dict(item.calls), item.summary,
                       item.inherited_assumptions) for key, item in results.items()}
    certificates = program_certificates(functions, code_reader=lambda a, s: None, pac_spec=PAC_SPEC_12_0_4)
    return certificates, certificate_supports(certificates, results, resolver or PremiseResolver()), results


def _caller():
    return FunctionBuilder(entry=MAIN).sub_rsp(0x28).call(CALLEE).add_rsp(0x28).ret()


def _global_leaf():
    return FunctionBuilder(entry=CALLEE).ins(store(const(DATA_BASE + 0x40), const(1, 8))).ret()


def test_a_proven_continuation_rests_on_its_callees_producers_and_certificate():
    certificates, supports, _ = _run(_caller(), _global_leaf(), assume_globals_disjoint_from_stack=True)
    support = supports[_key(MAIN)]
    assert certificates[_key(MAIN)].status == "proven"
    assert support.continuation.claim is ClaimType.CONTINUATION and support.continuation.established
    assert GLOBALS in support.continuation_unpadded.premises
    assert [item.subject for item in support.continuation.via] == [_key(CALLEE)]
    assert any(item.kind == "graph" for item in support.continuation.evidence)


def test_an_sp_delta_rests_on_the_receipts_effect_producers():
    certificates, supports, _ = _run(_caller(), _global_leaf(), assume_globals_disjoint_from_stack=True)
    (row,) = certificates[_key(MAIN)].exits
    support = supports[_key(MAIN)]
    assert row.sp_delta == 8 and support.sp is not None and support.sp.claim is ClaimType.REGISTER_DELTA
    assert support.sp.established and GLOBALS in support.sp_unpadded.premises
    assert any(item.kind == "proof" for item in support.sp.evidence)


def test_a_leaf_sp_delta_needs_no_premise():
    _, supports, _ = _run(FunctionBuilder(entry=MAIN).ins(copy(reg(RAX), const(1))).ret())
    support = supports[_key(MAIN)]
    assert support.sp.established and support.sp_unpadded.engine_proven   # (published: + policy padding)


def test_an_unknown_continuation_keeps_a_proven_sp_support():
    """A damaged return slot: continuation UNKNOWN; the SP proof (no SP write)
    still holds and its support is unaffected (design r5 C, Astra r4 P1)."""
    certificates, supports, _ = _run(FunctionBuilder(entry=MAIN).ins(store(reg(RSP), const(0xDEAD))).ret())
    support = supports[_key(MAIN)]
    assert certificates[_key(MAIN)].status == "unknown" and not support.continuation.established
    assert support.sp is not None and support.sp.established


def test_an_unknown_label_in_a_producer_fails_both_supports_of_the_consumer():
    def mutate(results):
        leaf = results[_key(CALLEE)]
        leaf.normalized = replace(leaf.normalized, premise_uses=(*leaf.normalized.premise_uses,
                                                                 ("no-such-premise", "normalize", "x")))
    _, supports, _ = _run(_caller(), _global_leaf(), mutate=mutate, assume_globals_disjoint_from_stack=True)
    support = supports[_key(MAIN)]
    assert "no-such-premise" in support.continuation.obligations and not support.continuation.established
    assert "no-such-premise" in support.sp.obligations and not support.sp.established


def test_a_receipt_whose_effect_no_longer_matches_is_an_obligation(monkeypatch):
    from tdo_v2 import register_delta_proofs

    results = analyze_units(_units(_caller(), _global_leaf()))
    functions = {key: (item.normalized, item.unit.observation, item.unit.scopes, dict(item.calls), item.summary,
                       item.inherited_assumptions) for key, item in results.items()}
    certificates = program_certificates(functions, code_reader=lambda a, s: None, pac_spec=PAC_SPEC_12_0_4)

    def derive(*args, **kwargs):
        proof = original_derive(*args, **kwargs)
        if proof is not None and proof.call_facts:
            proof = replace(proof, call_facts=tuple(replace(fact, effect_fingerprint="0" * 64)
                                                    for fact in proof.call_facts))
        return proof

    original_derive = register_delta_proofs.derive_register_delta_proof
    monkeypatch.setattr(register_delta_proofs, "derive_register_delta_proof", derive)
    supports = certificate_supports(certificates, results, PremiseResolver())
    support = supports[_key(MAIN)]
    assert any(item.startswith("receipt:") for item in support.sp.obligations) and not support.sp.established


def test_an_assumed_no_effect_label_is_an_sp_premise_or_fails_closed():
    from tdo_v2.assumed_call_effects import AssumedCallEffect

    main = FunctionBuilder(entry=MAIN).ins(op("CALLOTHER", [const(17, 4)])).ret()
    key, label = f"1:{MAIN:x}:0:CALLOTHER", "pcodeop-model:x86-markers/LOCK@v1"
    _, supports, _ = _run(main, assumed_call_effects={_key(MAIN): {key: AssumedCallEffect(label, ())}})
    support = supports[_key(MAIN)]
    # (no p-code op model is loaded in this resolver: the label names nothing it consumed)
    assert label in support.sp.obligations and not support.sp.established


def test_a_recursive_pair_is_never_an_established_continuation():
    first = FunctionBuilder(entry=MAIN).sub_rsp(0x28).call(CALLEE).add_rsp(0x28).ret()
    second = FunctionBuilder(entry=CALLEE).sub_rsp(0x28).call(MAIN).add_rsp(0x28).ret()
    certificates, supports, _ = _run(first, second)
    for key in (_key(MAIN), _key(CALLEE)):
        assert certificates[key].status == "unknown" and not supports[key].continuation.established


def _receipt_call(results):
    (call,) = [key for key in results[_key(MAIN)].proven if key.endswith(":CALL")]
    return call


def test_an_unknown_caller_side_requirement_at_a_receipt_is_an_obligation():
    """Astra pc3 r1 P1-1: an unresolved use the caller recorded at the receipt's
    call (here an admission) fails the SP support, not only the closure."""
    def mutate(results):
        caller = results[_key(MAIN)]
        call = _receipt_call(results)
        caller.normalized = replace(caller.normalized, premise_uses=(*caller.normalized.premise_uses,
                                                                     ("no-such-model", "admission", call)))
    _, supports, _ = _run(_caller(), _global_leaf(), mutate=mutate)
    support = supports[_key(MAIN)]
    assert "no-such-model" in support.sp_unpadded.obligations and not support.sp_unpadded.established
    assert not support.sp.established


def test_a_receipt_without_its_producer_is_unbacked():
    """Astra pc3 r1 P1-2: the effect still matches its fingerprint, but its
    producer edge is gone -- never an established, premise-free support."""
    def mutate(results):
        results[_key(MAIN)].consumed = {}
    _, supports, results = _run(_caller(), _global_leaf(), mutate=mutate, assume_globals_disjoint_from_stack=True)
    support = supports[_key(MAIN)]
    assert f"unbacked-receipt:{_receipt_call(results)}" in support.sp.obligations
    assert not support.sp.established and not support.sp_unpadded.established


def test_sp_evidence_names_the_engine_and_resolver_identities():
    from test_external_models import MODELS
    from tdo_v2.summary_store import load_external_models

    leaf = FunctionBuilder(entry=MAIN).ins(copy(reg(RAX), const(1))).ret()
    _, plain, _ = _run(leaf)
    models = load_external_models(MODELS, "x86:LE:64:default", "win64")
    _, other, _ = _run(leaf, resolver=PremiseResolver(model_sets=(models,)))
    kinds = {item.kind for item in plain[_key(MAIN)].sp.evidence}
    assert {"engine", "resolver", "proof"} <= kinds
    assert plain[_key(MAIN)].sp.evidence != other[_key(MAIN)].sp.evidence


def test_an_arm64_callee_overwriting_x30_keeps_its_and_its_callers_sp_support():
    """Astra r4 P1: continuation UNKNOWN (x30 replaced) for callee and caller;
    both prove sp_delta 0 and keep established SP supports (link-call receipt)."""
    from synthetic import AARCH64, X1, X29, X30

    callee = (FunctionBuilder(entry=CALLEE, arch=AARCH64).ins(copy(reg(X30, 8), reg(X1, 8))).ret())
    caller = (FunctionBuilder(entry=MAIN, arch=AARCH64).stp_pre(X29, X30, -0x20).call(CALLEE)
              .ldp_post(X29, X30, 0x20).ret())
    certificates, supports, _ = _run(caller, callee)
    assert certificates[_key(CALLEE)].status == "unknown"
    for key in (_key(MAIN), _key(CALLEE)):
        assert [row.sp_delta for row in certificates[key].exits] == [0] * len(certificates[key].exits)
        assert supports[key].sp is not None and supports[key].sp.established, supports[key].sp
    assert not supports[_key(MAIN)].continuation.established


def test_a_tail_receipt_rests_on_its_targets_producers():
    """A pure x86 tail thunk (an extra caller supplies the call-shape evidence,
    as in ``test_register_delta_proofs``): its tail receipt rests on the
    target's producers."""
    tail = FunctionBuilder(entry=MAIN).tail_call(CALLEE)
    extra = FunctionBuilder(entry=CODE_BASE + 0xC00).call(MAIN).ret()
    _, supports, results = _run(tail, _global_leaf(), extra, assume_globals_disjoint_from_stack=True,
                                assume_entry_values_not_frame=False, private_frame_above=0)
    support = supports[_key(MAIN)]
    assert any(key.endswith(":BRANCH") for key in results[_key(MAIN)].consumed)
    assert support.sp is not None and support.sp.established, support.sp
    assert GLOBALS in support.sp_unpadded.premises


def test_a_composition_call_has_no_sp_receipt(monkeypatch):
    """(the register-delta checker refuses CALLIND: no SP support to build)"""
    from test_multi_target_calls import A, B, ROOT, _returns, _table

    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    _, supports, results = _run(_table(), _returns(A, 1), _returns(B, 2))
    assert results[ROOT].multi_calls and supports[ROOT].sp is None


def _unbacked(mutate):
    _, supports, results = _run(_caller(), _global_leaf(), mutate=mutate, assume_globals_disjoint_from_stack=True)
    return supports[_key(MAIN)], _receipt_call(results)


def test_an_unrelated_admission_does_not_back_a_summary_receipt():
    """Astra pc3 r2 P1-1: a registry assumption or another model admitted at
    the call does not stand in for the producer the effect came from."""
    def mutate(results):
        caller = results[_key(MAIN)]
        call = _receipt_call(results)
        caller.consumed = {}
        caller.normalized = replace(caller.normalized, premise_uses=(*caller.normalized.premise_uses,
                                                                     ("direction-flag-clear", "admission", call)))
    support, call = _unbacked(mutate)
    assert f"unbacked-receipt:{call}" in support.sp.obligations and not support.sp_unpadded.established


def test_a_substituted_producer_does_not_back_a_receipt():
    other = FunctionBuilder(entry=CODE_BASE + 0x900).ins(copy(reg(RAX), const(2))).ret()

    def mutate(results):
        caller = results[_key(MAIN)]
        caller.consumed = {_receipt_call(results): (results[_key(CODE_BASE + 0x900)],)}
    _, supports, results = _run(_caller(), _global_leaf(), other, mutate=mutate,
                                assume_globals_disjoint_from_stack=True)
    support = supports[_key(MAIN)]
    assert f"unbacked-receipt:{_receipt_call(results)}" in support.sp.obligations
    assert not support.sp_unpadded.established


def _lock_run(mutate=None):
    from tdo_v2.assumed_call_effects import AssumedCallEffect
    from tdo_v2.pcodeop_models import PcodeOpModel

    lock = PcodeOpModel("x86-markers", 1, frozenset({("x86:LE:64:default", 1, 0)}), {17: "LOCK"})
    main = FunctionBuilder(entry=MAIN).ins(op("CALLOTHER", [const(17, 4)])).ret()
    key, label = f"1:{MAIN:x}:0:CALLOTHER", "pcodeop-model:x86-markers/LOCK@v1"
    _, supports, _ = _run(main, resolver=PremiseResolver(pcodeop_models=(lock,)), mutate=mutate,
                          assumed_call_effects={_key(MAIN): {key: AssumedCallEffect(label, ())}})
    return supports[_key(MAIN)], key, label


def test_a_loaded_no_effect_model_is_an_sp_premise_at_its_operation():
    support, _, label = _lock_run()
    assert support.sp_unpadded.established and label in {item.id for item in support.sp_unpadded.premises}


def test_a_no_effect_receipt_keeps_the_callers_unresolved_requirement_there():
    """Astra pc3 r2 P1-2."""
    def mutate(results):
        caller = results[_key(MAIN)]
        caller.normalized = replace(caller.normalized, premise_uses=(*caller.normalized.premise_uses,
                                                                     ("no-such-model", "admission",
                                                                      f"1:{MAIN:x}:0:CALLOTHER")))
    support, _, _ = _lock_run(mutate)
    assert "no-such-model" in support.sp_unpadded.obligations and not support.sp.established


def test_a_no_effect_receipt_without_its_admission_is_unbacked():
    def mutate(results):
        caller = results[_key(MAIN)]
        caller.normalized = replace(caller.normalized, premise_uses=tuple(
            row for row in caller.normalized.premise_uses if row[1] != "admission"))
    support, key, _ = _lock_run(mutate)
    assert f"unbacked-receipt:{key}" in support.sp_unpadded.obligations
