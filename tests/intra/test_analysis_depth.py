"""Long chains of dependent values (docs 25.29): the analysis follows them
with a raised recursion bound; a function deeper still fails alone
(``NormalizationFailureReason.ANALYSIS_DEPTH``) -- its callers see an opaque
call, the run goes on. These run on the main thread
(TDO_V2_ANALYSIS_WORKER=0): the worker's bound is far larger
(``test_resource_limits``)."""

import sys

from synthetic import RAX, RDI, R8, FunctionBuilder, add, const, copy, program_units, reg
from tdo_v2 import interprocedural
from tdo_v2.interprocedural import analyze_units
from tdo_v2.normalize import NormalizationFailureReason, NormalizedFunction

LEAF = 0x1800


def _chain(length, entry=0x1000):
    builder = FunctionBuilder(entry=entry)
    for _ in range(length):
        builder.ins(add(reg(RAX), reg(RAX), const(1)))
    return builder.ret()


def test_a_chain_of_a_thousand_dependent_values_is_analyzed():
    previous = sys.getrecursionlimit()
    result = analyze_units(program_units(_chain(1000)))["1:1000"]
    assert type(result.normalized) is NormalizedFunction and result.summary is not None
    assert sys.getrecursionlimit() == previous   # restored


def test_a_function_deeper_than_the_bound_fails_alone(monkeypatch):
    monkeypatch.setenv("TDO_V2_ANALYSIS_WORKER", "0")
    monkeypatch.setattr(interprocedural, "ANALYSIS_RECURSION_LIMIT", 400)
    previous = sys.getrecursionlimit()
    sys.setrecursionlimit(400)
    try:
        caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RDI), reg(R8))).call(LEAF)
                  .ins(copy(reg(R8), reg(RAX))).add_rsp(0x28).ret())
        results = analyze_units(program_units(caller, _chain(300, LEAF)))
    finally:
        sys.setrecursionlimit(previous)
    leaf = results["1:1800"]
    assert leaf.summary is None and leaf.normalized.reason is NormalizationFailureReason.ANALYSIS_DEPTH
    assert type(results["1:1000"].normalized) is NormalizedFunction
    assert not results["1:1000"].proven   # the call to the failed leaf stays opaque


def _wide_chain(per, count):
    """``count`` instructions of ``per`` dependent additions each."""
    builder = FunctionBuilder()
    for _ in range(count):
        builder.ins(*[add(reg(RAX), reg(RAX), const(1)) for _ in range(per)])
    return builder.ret()


def test_six_thousand_dependent_values_analyze_without_exhausting_the_c_stack(monkeypatch):
    monkeypatch.setenv("TDO_V2_ANALYSIS_WORKER", "0")
    """The recursive evaluation crosses no generator frame (each would cost C
    stack: Antigravity, step A review 1, P0-1)."""
    result = analyze_units(program_units(_wide_chain(6, 1000)))["1:1000"]
    assert type(result.normalized) is NormalizedFunction and result.summary is not None


def test_a_chain_beyond_the_bound_fails_that_function_without_a_crash(monkeypatch):
    monkeypatch.setenv("TDO_V2_ANALYSIS_WORKER", "0")
    result = analyze_units(program_units(_wide_chain(10, 1000)))["1:1000"]
    assert result.summary is None and result.normalized.reason is NormalizationFailureReason.ANALYSIS_DEPTH
