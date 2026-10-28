"""CallClobberRead records from the chi view (docs 25.83 S2b'): under
``TDO_V2_CHI_RECORDS=check`` they must equal ``call_clobber``'s, row for row
and in order; under ``only`` the consumers get them alone."""

import pytest

from synthetic import FunctionBuilder, program_units
from test_chi_shadow import (
    _frame, _overwritten, _read, OPAQUE_A, OPAQUE_B, FLAG, RCX, RDX, RSI, const, op, reg,
)
from tdo_v2 import _chi_records
from tdo_v2.interprocedural import analyze_units


def _branchy():
    builder = _frame(FunctionBuilder().sub_rsp(0x48), 0x10, reg(RSI))
    builder.cbranch("other", FLAG, op("INT_EQUAL", [reg(RCX), const(0)], FLAG)).call(OPAQUE_A).branch("join")
    builder.label("other").call(OPAQUE_B).label("join")
    builder = _frame(_read(builder, 0x10), 0x18, reg(RDX)).call(OPAQUE_A)
    return _read(_read(builder, 0x18), 0x10).add_rsp(0x48).ret()


CASES = (_branchy, lambda: _overwritten(True), lambda: _overwritten(False))


def _rows(builder):
    (item,) = [row for key, row in analyze_units(program_units(builder)).items() if key == "1:1000"]
    return item.normalized.call_clobber_reads


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("forward", ("0", "1"))
def test_the_chi_view_gives_call_clobbers_rows_in_order(case, forward, monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", forward)
    legacy = _rows(case())
    monkeypatch.setenv("TDO_V2_CHI_RECORDS", "check")   # (raises on any difference)
    assert _rows(case()) == legacy and legacy


def test_consumers_receive_the_chi_views_rows(monkeypatch):
    """``only``: a V2 that drops the last row reaches the normalized function."""
    monkeypatch.setenv("TDO_V2_CHI_RECORDS", "only")
    full = _rows(_branchy())
    original = _chi_records.chi_records
    monkeypatch.setattr(_chi_records, "chi_records", lambda *args: original(*args)[:-1])
    assert _rows(_branchy()) == full[:-1]


def test_a_difference_is_a_failure(monkeypatch):
    monkeypatch.setenv("TDO_V2_CHI_RECORDS", "check")
    original = _chi_records.chi_records
    monkeypatch.setattr(_chi_records, "chi_records", lambda *args: tuple(reversed(original(*args))))
    with pytest.raises(_chi_records.ChiRecordsMismatch):
        _rows(_branchy())


def test_over_the_limit_falls_back_explicitly(monkeypatch):
    legacy = _rows(_branchy())
    monkeypatch.setenv("TDO_V2_CHI_RECORDS", "only")
    monkeypatch.setattr(_chi_records, "LIMIT", 0)
    _chi_records.FALLBACKS.clear()
    assert _rows(_branchy()) == legacy
    assert set(_chi_records.FALLBACKS.values()) == {"limit"}
