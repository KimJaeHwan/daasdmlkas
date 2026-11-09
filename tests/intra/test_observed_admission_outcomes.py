"""Scope refusals stay sealed outcomes, never names or admitted analyses."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from synthetic import FunctionBuilder, RAX, RCX, _Provider, copy, ram, reg, _naming_for
from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from tdo_v2.integration import observed_function_session as observed
from tdo_v2._scope_results import ConstructedFunctionScope


class _SealedProvider(_Provider):
    container_identity = SimpleNamespace(generation_id=b"g" * 32)

    @contextmanager
    def claim_function_transport(self, handle):
        member = SimpleNamespace(member_id=f"function-{handle}", sha256_digest=bytes([handle]) * 32)
        yield SimpleNamespace(
            transport_identity=SimpleNamespace(function_id=f"function-{handle}", observation_member=member),
            observation_candidate=lambda: self.function_candidate(handle),
            call_names_bytes=lambda: b"{}",
        )


def _provider():
    first = FunctionBuilder(entry=0x1000).ins(copy(reg(RAX), reg(RCX))).ret()
    # ADDRESS zero is not committed: retain the refusal, never recode it as a constant.
    bad = FunctionBuilder(entry=0x1100).ins(copy(reg(RAX), ram(0))).ret()
    last = FunctionBuilder(entry=0x1200).ins(copy(reg(RAX), reg(RCX))).ret()
    return _SealedProvider([first, bad, last])


def _session(monkeypatch, provider=None, *, decode=None):
    monkeypatch.setattr(observed, "read_configured_bundle", lambda snapshot: provider or _provider())
    calls = []

    def naming(raw, transport, binding, seeds, tails):
        calls.append(seeds.function_entry.byte_offset)
        if decode is not None:
            return decode()
        return _naming_for(None, seeds, {}, tails)

    monkeypatch.setattr(observed, "decode_configured_naming", naming)
    session = observed.open_observed_function_session(
        object(), naming_binding=NamingBindingExpectation(b"n" * 32, CALL_NAMING_GHIDRA_VERSION))
    return session, calls


def test_outcomes_preserve_scope_refusal_and_continue_without_decoding_names(monkeypatch):
    session, named = _session(monkeypatch)
    with session:
        values = list(session.iter_outcomes())
        assert [type(value) for value in values] == [
            observed.ObservedFunctionEvidence, observed.ObservedFunctionAdmissionFailure,
            observed.ObservedFunctionEvidence]
        failure = values[1]
        assert failure.generation_id == b"g" * 32
        assert (failure.function_id, failure.observation_member_id) == ("function-1", "function-1")
        assert failure.observation_sha256 == b"\1" * 32
        assert failure.reason == "invalid_function_observation"
        assert type(failure.unit.scopes.function) is not ConstructedFunctionScope
        assert failure.unit.observation is None
        assert named == [0x1000, 0x1200]
        with pytest.raises(RuntimeError, match="single-use"):
            session.iter_functions()
    with pytest.raises(RuntimeError, match="not active"):
        session.iter_outcomes()


def test_strict_iterator_keeps_original_failure_and_failed_iterator_behavior(monkeypatch):
    session, named = _session(monkeypatch)
    with session:
        rows = session.iter_functions()
        assert type(next(rows)) is observed.ObservedFunctionEvidence
        with pytest.raises(ValueError, match="scope could not be constructed"):
            next(rows)
        with pytest.raises(RuntimeError, match="iterator failed"):
            next(rows)
    assert named == [0x1000]


def test_naming_identity_failure_is_fatal_not_a_recoverable_scope_outcome(monkeypatch):
    def reject():
        raise ValueError("naming transport hash does not match")

    session, _ = _session(monkeypatch, decode=reject)
    with session:
        rows = session.iter_outcomes()
        with pytest.raises(ValueError, match="transport hash"):
            next(rows)
        with pytest.raises(RuntimeError, match="iterator failed"):
            next(rows)


def test_program_refusal_remains_fatal(monkeypatch):
    provider = _provider()
    provider.snapshot_complete = lambda: False
    session, _ = _session(monkeypatch, provider)
    with session:
        with pytest.raises(ValueError, match="program scope is unresolved"):
            next(session.iter_outcomes())


def test_transport_failure_is_fatal_and_does_not_become_a_scope_refusal(monkeypatch):
    provider = _provider()

    @contextmanager
    def broken(handle):
        raise OSError("sealed transport failed")
        yield  # pragma: no cover - contextmanager shape, never reached

    provider.claim_function_transport = broken
    session, _ = _session(monkeypatch, provider)
    with session:
        with pytest.raises((OSError, RuntimeError), match="transport|role capture"):
            next(session.iter_outcomes())


def test_public_observed_entry_preserves_refusals_but_never_normalizes_them(monkeypatch):
    from tdo_v2 import summary_engine
    from tdo_v2.boundary_rules import SymbolBoundaryProvider

    session, _ = _session(monkeypatch)
    with session:
        program = session.program_result
        outcomes = list(session.iter_outcomes())
    original = summary_engine.analyze_units
    counted = []

    def analyze(units, **options):
        counted.extend(unit.scopes.function.entry.byte_offset for unit in units)
        return original(units, **options)

    monkeypatch.setattr(summary_engine, "analyze_units", analyze)
    run = summary_engine.analyze_observed_with_summaries(
        program, outcomes, boundary_provider=SymbolBoundaryProvider(()))
    assert counted == [0x1000, 0x1200]
    assert run.admission_failures == (outcomes[1],)
    assert not run.failed_functions and not run.roots


def _bundle_entry(monkeypatch, tmp_path):
    from tdo_v2 import summary_engine
    from tdo_v2.boundary_rules import SymbolBoundaryProvider

    # the session is owner-thread confined: keep the analysis on this thread (the Linux large-stack
    # worker would otherwise run it elsewhere -- the test failed on Linux only)
    monkeypatch.setenv("TDO_V2_ANALYSIS_WORKER", "0")
    session, _ = _session(monkeypatch)
    monkeypatch.setattr(summary_engine, "open_observed_function_session", lambda *a, **k: session)
    monkeypatch.setattr(summary_engine, "load_image_info", lambda path: None)
    from tdo_v2.integration import configured_bundle

    monkeypatch.setattr(configured_bundle, "admit_frozen_bundle", lambda path: object())
    source = tmp_path / "naming.java"
    source.write_bytes(b"test naming binding")
    return lambda **options: summary_engine.analyze_frozen_bundle_with_summaries(
        tmp_path, naming_exporter_source=source, boundary_provider=SymbolBoundaryProvider(()), **options)


def test_public_bundle_entry_keeps_strict_refusal_by_default(monkeypatch, tmp_path):
    # (review fix, Astra P1-3) the existing failure channel: a refused member still raises by default
    analyze = _bundle_entry(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="scope could not be constructed"):
        analyze()


def test_public_bundle_entry_retains_refusals_when_asked(monkeypatch, tmp_path):
    run = _bundle_entry(monkeypatch, tmp_path)(retain_admission_failures=True)
    assert len(run.admission_failures) == 1
    assert run.admission_failures[0].observation_member_id == "function-1"


def test_all_refused_input_has_explicit_admission_failure_not_a_successful_function(monkeypatch):
    from tdo_v2 import summary_engine
    from tdo_v2.boundary_rules import SymbolBoundaryProvider

    provider = _provider()
    provider.functions = [provider.functions[1]]
    session, named = _session(monkeypatch, provider)
    with session:
        program, values = session.program_result, list(session.iter_outcomes())
    run = summary_engine.analyze_observed_with_summaries(
        program, values, boundary_provider=SymbolBoundaryProvider(()))
    assert len(run.admission_failures) == 1 and not named
    assert not run.roots and not run.failed_functions
