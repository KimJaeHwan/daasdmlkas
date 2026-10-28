"""Sparse call-clobber / may-alias engines reproduce the dense rows exactly,
and the chi view's call-clobber rows equal them (``TDO_V2_CHI_RECORDS=check``).

Every unit normalized here runs both engines (``TDO_V2_DATAFLOW_CROSSCHECK``)
and any difference raises ``DataflowEngineMismatch``. The random functions
contain calls (call-clobber), several pointer bases that alias, pushes and
pops (private frame), unknown addresses and loops (may-alias).
"""

import random

import pytest

import test_graph_fidelity
import test_robustness
from synthetic import normalize_with_observation
from tdo_v2 import call_clobber, may_alias
from tdo_v2._sparse_dataflow import (
    DATAFLOW_CROSSCHECK_ENV, DATAFLOW_ENGINE_ENV, DataflowEngineMismatch, run_dataflow,
)


@pytest.mark.parametrize("chunk", range(4))
def test_sparse_engines_match_dense_through_normalization(chunk, monkeypatch):
    monkeypatch.setenv(DATAFLOW_ENGINE_ENV, "sparse")
    monkeypatch.setenv(DATAFLOW_CROSSCHECK_ENV, "dense")
    # (the call-clobber rows the chi view produces must equal both engines': docs 25.83 D5')
    monkeypatch.setenv("TDO_V2_CHI_RECORDS", "check")
    counts = {"call-clobber": 0, "may-alias": 0}
    original = {"call-clobber": call_clobber._sparse_rows, "may-alias": may_alias._sparse_rows}

    def counted(kind):
        def run(*args):
            rows = original[kind](*args)
            counts[kind] += len(rows)
            return rows
        return run

    monkeypatch.setattr(call_clobber, "_sparse_rows", counted("call-clobber"))
    monkeypatch.setattr(may_alias, "_sparse_rows", counted("may-alias"))
    # the engine table captures the functions at call time through the module globals
    for seed in range(chunk * 100, (chunk + 1) * 100):
        for generate in (test_robustness._random_function, test_graph_fidelity._random_function):
            normalize_with_observation(generate(random.Random(seed)))
    assert counts["call-clobber"] > 0 and counts["may-alias"] > 0  # the check is not vacuous


def test_mismatch_is_reported():
    with pytest.raises(DataflowEngineMismatch, match=r"first difference at \[1\]"):
        import os
        os.environ[DATAFLOW_CROSSCHECK_ENV] = "b"
        try:
            run_dataflow("demo", {"a": lambda: (1, 2), "b": lambda: (1, 3)}, "a")
        finally:
            del os.environ[DATAFLOW_CROSSCHECK_ENV]


def test_unknown_engine_is_an_error(monkeypatch):
    monkeypatch.setenv(DATAFLOW_ENGINE_ENV, "no-such-engine")
    with pytest.raises(ValueError, match="unknown demo engine"):
        run_dataflow("demo", {"dense": lambda: ()}, "dense")
