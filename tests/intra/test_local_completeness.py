"""P0-0: local completeness is reported per root occurrence."""

import pytest

from synthetic import (
    RAX, RCX, RDI, RDX,
    add, const, load, normalize, op, operation_node_at, reg, slice_from, store,
    straight,
)
from tdo_v2.query_contracts import LocalCompleteness, local_completeness


def _results(builder, *indexes):
    function = normalize(builder)
    return tuple(
        slice_from(function, operation_node_at(function, index)).result
        for index in indexes
    )


def test_complete_slice_reports_no_debt():
    (result,) = _results(
        straight([store(reg(RDI), reg(RDX))], [load(reg(RAX), reg(RDI))]), 1
    )
    assert local_completeness((result,)) == LocalCompleteness(True, 0, 0)


def test_unresolved_address_is_reported_with_counts():
    """RCX = RDI*2; *(RCX) = RDX; RAX = *(RCX).

    The unknown-address read carries two debts (unresolved address, and the
    possible earlier unknown-address writer); the store is one write debt.
    """
    (result,) = _results(
        straight(
            [op("INT_MULT", [reg(RDI), const(2)], reg(RCX))],
            [store(reg(RCX), reg(RDX))],
            [load(reg(RAX), reg(RCX))],
        ),
        2,
    )
    assert local_completeness((result,)) == LocalCompleteness(False, 2, 1)


def test_one_incomplete_root_node_makes_the_occurrence_incomplete():
    builder = straight(
        [op("INT_MULT", [reg(RDI), const(2)], reg(RCX))],
        [load(reg(RAX), reg(RCX))],
        [add(reg(RDX), reg(RDI), const(1))],
    )
    clean, dirty = _results(builder, 2, 1)
    assert clean.reachable_unresolved_read_nodes == ()
    merged = local_completeness((clean, dirty))
    assert not merged.complete
    assert merged.reachable_unresolved_reads == 1


def test_shared_debt_nodes_are_counted_once():
    builder = straight(
        [op("INT_MULT", [reg(RDI), const(2)], reg(RCX))],
        [load(reg(RAX), reg(RCX))],
    )
    (result,) = _results(builder, 1)
    assert local_completeness((result, result)).reachable_unresolved_reads == 1


def test_rejects_empty_or_foreign_rows():
    with pytest.raises(TypeError):
        local_completeness(())
    with pytest.raises(TypeError):
        local_completeness((object(),))
