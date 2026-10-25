"""Summary scalar/address proofs obey the existing hard resource failures."""

import pytest

from synthetic import (
    DATA_BASE, R8, RAX, RCX, RDX, FunctionBuilder, add, const, copy, op, program_units, reg, store, tmp,
)
from tdo_v2 import relative_memory
from tdo_v2.constant_value import ExactConstant
from tdo_v2.interprocedural import analyze_units
from tdo_v2.normalize import NormalizationFailureReason, NormalizedFunction, UnresolvedNormalizedFunction
from tdo_v2.resource_limits import AnalysisBudgetExceeded


ROOT = "1:1000"


def _body(relations=1):
    body = FunctionBuilder().ins(store(const(DATA_BASE), const(0)))
    for index in range(relations):
        # A distinct source-width preoffset gives each original STORE a
        # different entry-bound address object, without any CALL or LOAD.
        start = 0x100 + 0x40 * index
        source, extended, scaled, address = tmp(start, 4), tmp(start + 8), tmp(start + 16), tmp(start + 24)
        body.ins(add(source, reg(RDX, 4), const(index, 4)),
                 op("INT_ZEXT", [source], extended),
                 op("INT_MULT", [extended, const(2)], scaled),
                 add(address, reg(RCX), scaled), store(address, reg(RAX, 2)))
    return body.ins(copy(reg(R8), const(7))).ret()


@pytest.mark.parametrize("hook", ("definition_constants", "indexed_relations"))
@pytest.mark.parametrize("scope", ("function", "run"))
def test_summary_proof_budget_exhaustion_is_a_typed_failure_without_publication(monkeypatch, hook, scope):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    attempts = []

    def exhausted(normalized, observation, *args):
        assert isinstance(normalized, NormalizedFunction)
        assert observation.instructions
        attempts.append(normalized)
        raise AnalysisBudgetExceeded("work", f"summary-{hook}", scope=scope)

    monkeypatch.setattr(relative_memory, hook, exhausted)
    provenance = {}
    result = analyze_units(program_units(_body()), record_provenance=provenance)[ROOT]
    assert len(attempts) == 1
    assert isinstance(result.normalized, UnresolvedNormalizedFunction)
    expected = NormalizationFailureReason.ANALYSIS_BUDGET if scope == "function" else \
        NormalizationFailureReason.ANALYSIS_RUN_BUDGET
    assert result.normalized.reason is expected
    # A directly injected run exception does not mark an active run ledger;
    # existing run finalization therefore records its detail as unknown.
    assert result.failure_detail == ("function:work" if scope == "function" else "run:unknown")
    assert result.summary is None and provenance == {}


def test_optional_indexed_relation_count_cap_drops_information_not_the_function(monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    before = analyze_units(program_units(_body()))[ROOT]
    assert before.summary is not None and len(before.summary.address_relations) == 1
    provenance = {}
    result = analyze_units(program_units(_body(65)), record_provenance=provenance)[ROOT]
    assert isinstance(result.normalized, NormalizedFunction)
    assert result.summary is not None and result.summary.address_relations == ()
    assert not result.failure_detail
    assert any(run.span.start == R8 and run.literal == ExactConstant(8, 7)
               for exit_ in result.summary.exits for run in exit_.runs)
    assert set(provenance) == {id(result)} and provenance[id(result)][0] is result
