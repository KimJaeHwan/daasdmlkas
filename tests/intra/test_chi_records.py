"""CallClobberRead records from the chi view (docs 25.83 S2b', D5'): the
default producer; under ``TDO_V2_CHI_RECORDS=check`` they must equal
``call_clobber``'s, row for row and in order; over V2's own bounds the
function uses ``call_clobber``'s rows, recorded per run."""

import pytest

from synthetic import FunctionBuilder, program_units
from test_chi_shadow import (
    _frame, _overwritten, _read, OPAQUE_A, OPAQUE_B, FLAG, RCX, RDX, RSI, const, op, reg,
)
from tdo_v2 import _chi_records, call_clobber, normalize
from tdo_v2.interprocedural import analyze_units
from tdo_v2.resource_limits import last_run


def _branchy():
    builder = _frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI))
    builder.cbranch("other", FLAG, op("INT_EQUAL", [reg(RCX), const(0)], FLAG)).call(OPAQUE_A).branch("join")
    builder.label("other").call(OPAQUE_B).label("join")
    builder = _frame(_read(builder, 0x10), 0x18, reg(RDX)).call(OPAQUE_A)
    return _read(_read(builder, 0x18), 0x10).add_rsp(0x48).ret()


def _call_free():
    builder = _frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI))
    return _read(builder, 0x10).add_rsp(0x48).ret()


CASES = (_branchy, lambda: _overwritten(True), lambda: _overwritten(False))


@pytest.fixture(autouse=True)
def _default_producer(monkeypatch):
    monkeypatch.delenv("TDO_V2_CHI_RECORDS", raising=False)


def _rows(builder):
    (item,) = [row for key, row in analyze_units(program_units(builder)).items() if key == "1:1000"]
    return item.normalized.call_clobber_reads


def _legacy_rows(builder, monkeypatch):
    monkeypatch.setenv("TDO_V2_CHI_RECORDS", "legacy")
    rows = _rows(builder)
    monkeypatch.delenv("TDO_V2_CHI_RECORDS")
    return rows


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("forward", ("0", "1"))
def test_the_chi_view_gives_call_clobbers_rows_in_order(case, forward, monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", forward)
    legacy = _legacy_rows(case(), monkeypatch)
    assert _rows(case()) == legacy and legacy   # (the default)
    monkeypatch.setenv("TDO_V2_CHI_RECORDS", "check")   # (raises on any difference)
    assert _rows(case()) == legacy
    assert _chi_records.fallbacks(last_run()) == {}


def test_the_chi_view_is_the_default_and_legacy_does_not_run_it(monkeypatch):
    """By default a V2 that drops the last row reaches the normalized
    function; under ``legacy`` V2 is not run."""
    full = _rows(_branchy())
    original = _chi_records.chi_records
    monkeypatch.setattr(_chi_records, "chi_records", lambda *args: original(*args)[:-1])
    assert _rows(_branchy()) == full[:-1]
    monkeypatch.setattr(_chi_records, "chi_records", lambda *args: pytest.fail("V2 ran under legacy"))
    assert _legacy_rows(_branchy(), monkeypatch) == full


def test_a_difference_is_a_failure(monkeypatch):
    monkeypatch.setenv("TDO_V2_CHI_RECORDS", "check")
    original = _chi_records.chi_records
    monkeypatch.setattr(_chi_records, "chi_records", lambda *args: tuple(reversed(original(*args))))
    with pytest.raises(_chi_records.ChiRecordsMismatch):
        _rows(_branchy())


def test_a_malformed_switch_is_an_error(monkeypatch):
    monkeypatch.setenv("TDO_V2_CHI_RECORDS", "0")
    with pytest.raises(ValueError):
        _chi_records.mode()


@pytest.mark.parametrize("forward", ("0", "1"))
def test_over_the_size_limit_falls_back_and_is_recorded_per_run(forward, monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", forward)
    legacy = _legacy_rows(_branchy(), monkeypatch)
    monkeypatch.setattr(_chi_records, "LIMIT", 0)
    assert _rows(_branchy()) == legacy
    found = _chi_records.fallbacks(last_run())
    assert found and set(found.values()) == {"limit"}
    monkeypatch.setattr(_chi_records, "LIMIT", 200_000)
    _rows(_branchy())
    assert _chi_records.fallbacks(last_run()) == {}   # (a new run: its own record)


@pytest.mark.parametrize("forward", ("0", "1"))
def test_over_its_work_bound_v2_stops_and_falls_back(forward, monkeypatch):
    """V2 runs out of its own units: ``call_clobber``'s rows, never an empty
    set, and the function is analyzed (no budget failure)."""
    monkeypatch.setenv("TDO_V2_FORWARD", forward)
    legacy = _legacy_rows(_branchy(), monkeypatch)
    monkeypatch.setattr(_chi_records, "WORK_BASE", 1)
    monkeypatch.setattr(_chi_records, "WORK_PER_ACTION", 0)
    assert _rows(_branchy()) == legacy and legacy
    found = _chi_records.fallbacks(last_run())
    assert found and set(found.values()) == {"work"}


def test_v2_is_charged_to_the_functions_budget(monkeypatch):
    """V2's units are the analysis's: with V2 alone over a function budget
    that the legacy engine fits, the function fails typed (never a silent
    empty row set)."""
    from tdo_v2.normalize import NormalizationFailureReason

    def work(mode):
        monkeypatch.setenv("TDO_V2_CHI_RECORDS", mode)
        analyze_units(program_units(_branchy()))
        return last_run().ledgers
    legacy, chi = work("legacy"), work("only")
    budget = {key: (legacy[key].work, chi[key].work) for key in chi if key in legacy}
    key, (low, high) = max(budget.items(), key=lambda item: item[1][1] - item[1][0])
    assert high > low
    monkeypatch.setenv("TDO_V2_FUNCTION_WORK", str(low + 1))
    monkeypatch.setenv("TDO_V2_CHI_RECORDS", "only")
    item = analyze_units(program_units(_branchy()))[key if isinstance(key, str) else "1:1000"]
    assert item.normalized.reason is NormalizationFailureReason.ANALYSIS_BUDGET
    assert item.failure_detail == "function:work"


def test_a_function_without_calls_has_no_rows_and_runs_neither_engine(monkeypatch):
    assert _rows(_call_free()) == ()
    monkeypatch.setattr(_chi_records, "chi_records", lambda *args: pytest.fail("V2 ran without a call"))
    monkeypatch.setattr(normalize, "derive_call_clobber_reads", lambda *args, **kwargs: pytest.fail("legacy ran"))
    assert _rows(_call_free()) == ()
    assert _chi_records.fallbacks(last_run()) == {}


def test_a_function_without_calls_has_no_legacy_rows_either(monkeypatch):
    """The justification of the empty result, checked: ``check`` compares it
    with ``call_clobber``'s."""
    monkeypatch.setenv("TDO_V2_CHI_RECORDS", "check")
    calls = []
    original = call_clobber.derive_call_clobber_reads

    def legacy(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(normalize, "derive_call_clobber_reads", legacy)
    assert _rows(_call_free()) == () and calls


def _probed(monkeypatch):
    """[0x10] = rsi; CALL A; read [0x10]: (normalized, the read's key, its span)."""
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    builder = _frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI)).call(OPAQUE_A)
    normalized = analyze_units(program_units(_read(builder, 0x10).add_rsp(0x48).ret()))["1:1000"].normalized
    ssa = normalized.memory_ssa
    read = next(row for row in ssa.reads if ssa.actions[row.action_id].operation_key.endswith(":LOAD")
                and row.span.object_id.kind.value == "function_relative")
    return normalized, ssa.actions[read.action_id].operation_key, read.span


def test_a_probe_consumes_the_chi_views_rows(monkeypatch):
    """The probe of the read is indebted by V2's row; a V2 without rows
    (patched after the analysis) leaves the probe the store's definition."""
    from tdo_v2.forward import probe

    normalized, key, span = _probed(monkeypatch)
    assert probe(normalized, key, (span,))[0][span] is None
    monkeypatch.setattr(_chi_records, "chi_records", lambda *args: ())
    assert probe(normalized, key, (span,))[0][span] is not None


def test_a_probes_fallback_is_recorded_in_its_run(monkeypatch):
    from tdo_v2.forward import probe
    from tdo_v2.resource_limits import run_analysis

    normalized, key, span = _probed(monkeypatch)
    monkeypatch.setattr(_chi_records, "LIMIT", 0)
    assert run_analysis(probe, normalized, key, (span,))[0][span] is None   # (call_clobber's row)
    found = _chi_records.fallbacks(last_run())
    assert found == {(normalized.memory_ssa.function_scope, "probe", key): "limit"}


def _producer_inputs(builder, monkeypatch):
    """The arguments ``records`` passed V2 for function 1:1000."""
    found = []
    original = _chi_records.chi_records

    def spy(*args):
        found.append(args)
        return original(*args)

    monkeypatch.setattr(_chi_records, "chi_records", spy)
    _rows(builder)
    monkeypatch.setattr(_chi_records, "chi_records", original)
    return found[0]


def _long_block(reads):
    builder = _frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI)).call(OPAQUE_A)
    for _ in range(reads):
        builder = _read(builder, 0x10, width=1)
    return builder.add_rsp(0x48).ret()


@pytest.mark.parametrize("case", (*CASES, lambda: _long_block(40)))
def test_the_indexed_value_before_is_the_prefix_scan(case, monkeypatch):
    """Every (block, action index, solved class): the last covering write
    before the action, else the block's entry value -- as the scan gave."""
    from tdo_v2._chi_shadow import LazySparse

    memory_unit, _, calls, preserved, keeping = _producer_inputs(case(), monkeypatch)
    lazy = LazySparse(memory_unit, frozenset(calls), preserved, frozenset(keeping))
    checked = 0
    for (block, item), entry in list(lazy.entry_values.items()):
        value = entry
        for index, (_, _, writes) in enumerate(lazy.actions[block] + [(None, None, ())]):
            assert lazy.value_before(block, index, item) == value
            checked += 1
            for definition, covered in writes:
                if item in covered:
                    value = frozenset((definition,))
    assert checked


def test_value_before_scans_no_block_prefix(monkeypatch):
    """A query reads no action rows: the prefix scan per read was quadratic
    in a block's length and uncharged (Astra r1 P2), so V2's work is what it
    charges. (Synthetic blocks are one instruction each: the check is that no
    row is read at all.)"""
    from tdo_v2._chi_shadow import LazySparse

    memory_unit, _, calls, preserved, keeping = _producer_inputs(_long_block(400), monkeypatch)
    lazy = LazySparse(memory_unit, frozenset(calls), preserved, frozenset(keeping))

    class Untouchable(dict):
        def __getitem__(self, key):
            raise AssertionError("value_before read a block's actions")

    expected = {(block, item): [lazy.value_before(block, index, item) for index in range(len(rows) + 1)]
                for (block, item) in list(lazy.entry_values) for rows in (lazy.actions[block],)}
    lengths = {block: len(rows) for block, rows in lazy.actions.items()}
    lazy.actions = Untouchable(lazy.actions)
    assert expected
    for (block, item), values in expected.items():
        assert [lazy.value_before(block, index, item) for index in range(lengths[block] + 1)] == values


def test_a_probes_work_fallback_is_recorded_in_its_run(monkeypatch):
    from tdo_v2.forward import probe
    from tdo_v2.resource_limits import run_analysis

    normalized, key, span = _probed(monkeypatch)
    monkeypatch.setattr(_chi_records, "WORK_BASE", 1)
    monkeypatch.setattr(_chi_records, "WORK_PER_ACTION", 0)
    assert run_analysis(probe, normalized, key, (span,))[0][span] is None   # (call_clobber's row)
    assert _chi_records.fallbacks(last_run()) == {(normalized.memory_ssa.function_scope, "probe", key): "work"}


def test_the_function_budget_still_binds_the_fallback(monkeypatch):
    """V2 over its own bound, then call_clobber over the function's budget:
    the function fails typed."""
    from tdo_v2.normalize import NormalizationFailureReason

    monkeypatch.setattr(_chi_records, "WORK_BASE", 1)
    monkeypatch.setattr(_chi_records, "WORK_PER_ACTION", 0)
    original = normalize.derive_call_clobber_reads

    def legacy(*args, **kwargs):
        from tdo_v2.resource_limits import step
        step(10_000_000)   # (an expensive fallback)
        return original(*args, **kwargs)

    monkeypatch.setattr(normalize, "derive_call_clobber_reads", legacy)
    monkeypatch.setenv("TDO_V2_FUNCTION_WORK", "1000000")
    item = analyze_units(program_units(_branchy()))["1:1000"]
    assert item.normalized.reason is NormalizationFailureReason.ANALYSIS_BUDGET
    assert item.failure_detail == "function:work"
