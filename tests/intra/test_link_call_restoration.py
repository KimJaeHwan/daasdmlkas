"""ARM64 Stage 2b-S (docs 25.90): an AArch64 link call is a call shape for the
callee's stack restoration (delta 0), a link call in the independent
register-delta proof, and the continuation certificates' SP delta comes from
that proof -- never from the summary's own AFFINE constant."""

from dataclasses import replace

import pytest

from synthetic import (AARCH64, CODE_BASE, SP, X0, X1, X29, X30, FunctionBuilder, add, const, copy, program_units, reg,
                       register_evidence)
from tdo_v2.call_summary_effects import StackRestoration
from tdo_v2.interprocedural import analyze_units
from tdo_v2.model import StorageObjectId
from tdo_v2.register_delta_proofs import derive_register_delta_proof, validate_proof_record
from tdo_v2.span_geometry import ByteSpan, StorageObjectKind

MAIN, CALLEE, OTHER, OPAQUE = CODE_BASE, CODE_BASE + 0x800, CODE_BASE + 0xA00, CODE_BASE + 0xC00


def _a64(entry=MAIN):
    return FunctionBuilder(entry=entry, arch=AARCH64)


def _leaf(entry=CALLEE):
    return _a64(entry).ins(copy(reg(X0, 8), const(1, 8))).ret()


def _framed(entry, target):
    return _a64(entry).stp_pre(X29, X30, -0x20).call(target).ldp_post(X29, X30, 0x20).ret()


def _results(*builders):
    return analyze_units(program_units(*builders, registers=register_evidence(AARCH64)))


def _restorations(results, key="1:1000"):
    return [effect.stack_restoration for _, effect in results[key].normalized.proven_call_effects]


@pytest.mark.parametrize("callees,expected", [
    ([_leaf()], StackRestoration.PROVEN),
    ([_framed(CALLEE, OTHER), _leaf(OTHER)], StackRestoration.PROVEN),
    ([_a64(CALLEE).call(OTHER).ret(), _leaf(OTHER)], StackRestoration.PROVEN),
    # an inner opaque call may move SP: the callee does not write SP itself,
    # but the opaque call preserves nothing -- never "untouched, so 0"
    ([_framed(CALLEE, OPAQUE)], StackRestoration.UNKNOWN),
    ([_a64(CALLEE).call(OPAQUE).ret()], StackRestoration.UNKNOWN),
], ids=["leaf", "framed-calls-leaf", "calls-leaf", "framed-calls-opaque", "calls-opaque"])
def test_a_link_call_restores_sp_exactly_when_the_callee_leaves_it_unchanged(callees, expected):
    assert _restorations(_results(_a64().call(CALLEE).ret(), *callees)) == [expected]


def test_a_callee_moving_sp_is_disproven():
    callee = _a64(CALLEE).ins(add(reg(SP, 8), reg(SP, 8), const(16, 8))).ret()
    assert _restorations(_results(_a64().call(CALLEE).ret(), callee)) == [StackRestoration.DISPROVEN]


def _sp_written(shape):
    """Callees that write SP to something other than entry SP (Astra 2b-S r1
    P1): an exported register write is a write even when its value is known."""
    if shape == "copy-x1":
        return [_a64(CALLEE).ins(copy(reg(SP, 8), reg(X1, 8))).ret()]
    if shape == "constant":
        return [_a64(CALLEE).ins(copy(reg(SP, 8), const(0x7000, 8))).ret()]
    if shape == "partial":
        return [_a64(CALLEE).ins(copy(reg(SP, 4), const(0x70, 4))).ret()]
    from synthetic import ZF
    return [_a64(CALLEE).cbranch("other", reg(ZF, 1)).ins(add(reg(SP, 8), reg(SP, 8), const(16, 8))).ret()
            .label("other").ins(add(reg(SP, 8), reg(SP, 8), const(32, 8))).ret()]


@pytest.mark.parametrize("shape", ["copy-x1", "constant", "partial", "two-exit-deltas"])
def test_a_callee_writing_sp_is_never_restored_by_default(shape):
    assert _restorations(_results(_a64().call(CALLEE).ret(), *_sp_written(shape))) != [StackRestoration.PROVEN]


def test_a_caller_of_an_sp_writing_callee_gets_no_sp_delta():
    from test_return_relations import _certs, _of

    certificate = _of(_certs(_framed(MAIN, CALLEE), *_sp_written("copy-x1")))
    assert all(row.sp_delta is None for row in certificate.exits), certificate


def _sp(results, key="1:1000"):
    unit = results[key].unit
    return unit, ByteSpan(StorageObjectId(StorageObjectKind.REGISTER_FILE, unit.scopes.program.scope, 0), SP, 8)


def test_the_independent_proof_crosses_a_link_call():
    results = _results(_framed(MAIN, CALLEE), _leaf())
    unit, span = _sp(results)
    normalized = results["1:1000"].normalized
    proof = derive_register_delta_proof(unit, span, dict(normalized.proven_call_effects), {})
    assert proof is not None and proof.delta == 0
    assert [(fact.kind, fact.delta, fact.observed_push_delta) for fact in proof.call_facts] == [("link-call", 0, None)]
    assert validate_proof_record(proof.record()) == proof


def test_a_link_call_without_proven_restoration_refuses_the_proof():
    results = _results(_framed(MAIN, CALLEE), _leaf())
    unit, span = _sp(results)
    (key, effect), = results["1:1000"].normalized.proven_call_effects
    for restoration in (StackRestoration.UNKNOWN, StackRestoration.DISPROVEN):
        assert derive_register_delta_proof(unit, span, {key: replace(effect, stack_restoration=restoration)},
                                           {}) is None


def test_a_tampered_link_call_receipt_is_refused():
    results = _results(_framed(MAIN, CALLEE), _leaf())
    unit, span = _sp(results)
    proof = derive_register_delta_proof(unit, span, dict(results["1:1000"].normalized.proven_call_effects), {})
    from tdo_v2.register_delta_proofs import _digest

    for field, value in (("delta", 8), ("observed_push_delta", -8)):
        record = proof.record()
        record["call_facts"][0][field] = value
        # re-hashed: the link-call rules themselves refuse it, not the digest
        record["content_sha256"] = _digest({key: item for key, item in record.items() if key != "content_sha256"})
        assert validate_proof_record(record) is None, field


def test_the_certificate_sp_delta_is_the_independent_proofs():
    from test_return_relations import _certs, _of

    certificate = _of(_certs(_framed(MAIN, CALLEE), _leaf()))
    assert certificate.status == "proven" and [row.sp_delta for row in certificate.exits] == [0]
    assert any(item.startswith("register-delta-proof:") for item in certificate.dependencies)


def test_an_unproven_sp_delta_leaves_a_proven_continuation_proven():
    """Continuation never reads the SP delta: SP copied from x1 (the proof
    refuses) while x30 is intact."""
    from test_return_relations import _certs, _of

    main = _a64().ins(copy(reg(SP, 8), reg(X1, 8))).ret()
    certificate = _of(_certs(main))
    assert certificate.status == "proven" and [row.sp_delta for row in certificate.exits] == [None]
