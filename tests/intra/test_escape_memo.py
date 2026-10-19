"""The stack-escape memo of one normalization (docs 25.31 B0-4): with it
the results, the work units, the ledgers and every budget's exhaustion point
(function and run work limits, inside a computation and inside a replay) are
those of recomputing the escapes on every call; a policy built from the memo
equals one computed afresh under every assumption setting."""

import sys
from pathlib import Path

import pytest

from tdo_v2 import may_alias, resource_limits

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests" / "intra"))
sys.path.insert(0, str(REPO / "tools" / "graph_fidelity"))

LIMIT_VARIABLES = ("TDO_V2_FUNCTION_WORK", "TDO_V2_FUNCTION_SECONDS", "TDO_V2_RUN_WORK", "TDO_V2_RUN_SECONDS",
                   "TDO_V2_RUN_RSS_MB", "TDO_V2_REPORTING_SECONDS",
                   *(f"TDO_V2_LIMIT_{name.upper()}" for name in resource_limits.STRUCTURES))


@pytest.fixture(autouse=True)
def _no_limits(monkeypatch):
    for name in LIMIT_VARIABLES:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(scope="module")
def program():
    import scale_fixtures
    import synthetic

    fixture = scale_fixtures.realistic(1500, 0)
    inputs = synthetic.summary_inputs(fixture.functions, fixture.names, layout=fixture.layout,
                                      data=fixture.data, image=True)
    return fixture, inputs


def _run(program, monkeypatch, memo: bool, **options):
    from semantic_snapshot import encode
    from tdo_v2.summary_engine import analyze_observed_with_summaries

    fixture, inputs = program
    computed = []
    original = may_alias._stack_escapes

    def counted(*args):
        computed.append(1)
        return original(*args)

    with monkeypatch.context() as patch:
        patch.setattr(may_alias, "_stack_escapes", counted)
        if not memo:
            patch.setattr(may_alias.EscapeMemo, "holds", lambda self, *args: False)
        run = analyze_observed_with_summaries(
            inputs.program, inputs.evidences, image_info=inputs.image_info, readonly_image=inputs.readonly_image,
            boundary_provider=fixture.provider, pcodeop_models=fixture.pcodeop_models(inputs.evidences),
            **options)
    last = resource_limits.last_run()
    ledgers = {key: item.work for key, item in (getattr(last, "ledgers", {}) or {}).items()}
    return encode(run), getattr(last, "work", None), ledgers, len(computed)


def test_the_memo_is_used_and_changes_nothing(program, monkeypatch):
    with_memo = _run(program, monkeypatch, True)
    without = _run(program, monkeypatch, False)
    assert with_memo[:3] == without[:3]
    assert with_memo[3] < without[3]   # (rounds shared one computation)


@pytest.mark.parametrize("fraction", [0.05, 0.2, 0.35, 0.5, 0.65, 0.8, 0.95])
@pytest.mark.parametrize("scope", ["function", "run", "both"])
def test_budget_exhaustion_is_identical(program, monkeypatch, fraction, scope):
    _, total, ledgers, _ = _run(program, monkeypatch, False)
    largest = max(ledgers.values())
    if scope in ("function", "both"):
        monkeypatch.setenv("TDO_V2_FUNCTION_WORK", str(max(1, int(largest * fraction))))
    if scope in ("run", "both"):
        monkeypatch.setenv("TDO_V2_RUN_WORK", str(max(1, int((largest if scope == "both" else total) * fraction))))
    assert _run(program, monkeypatch, True)[:3] == _run(program, monkeypatch, False)[:3]


@pytest.mark.parametrize("entry_values", [True, False])
@pytest.mark.parametrize("opaque", [True, False])
def test_a_memo_policy_equals_a_fresh_one(program, monkeypatch, entry_values, opaque):
    """Every _stack_policy call made with a memo is checked against a fresh
    computation (same stack object, escapes, escapes without the opaque
    assumption, flags-to-be), under each assumption setting."""
    original = may_alias._stack_policy
    checked = []

    def both(*args, **kwargs):
        policy = original(*args, **kwargs)
        if kwargs.get("memo", args[10] if len(args) > 10 else None) is not None:
            plain = list(args[:10]) + [None]
            fresh = original(*plain)
            for name in ("stack_object", "bias", "escape", "escape_without_opaque", "globals_disjoint",
                         "private_above", "private_used", "opaque_used"):
                assert getattr(policy, name) == getattr(fresh, name), name
            checked.append(1)
        return policy

    monkeypatch.setattr(may_alias, "_stack_policy", both)
    _run(program, monkeypatch, True, assume_entry_values_not_frame=entry_values,
         assume_opaque_callees_leave_no_stack_addresses=opaque)
    assert checked


def test_another_input_is_computed_uncached(program):
    memo = may_alias.EscapeMemo(object(), object(), object(), object())
    assert not memo.holds(object(), *memo.held[1:])
    assert memo.holds(*memo.held)


def test_a_failed_computation_caches_nothing(monkeypatch):
    memo = may_alias.EscapeMemo("unit", "observation", "context", "spaces")

    def fails(*args):
        raise resource_limits.AnalysisBudgetExceeded("work")

    monkeypatch.setattr(may_alias, "_stack_escapes", fails)
    with pytest.raises(resource_limits.AnalysisBudgetExceeded):
        may_alias._stack_policy("unit", "observation", "context", "spaces", memo=memo)
    assert memo.found == {}
