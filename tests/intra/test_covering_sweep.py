"""K3-t6: the call-clobber signature sweep gives the same covering sets as
a scan of every span (random spans, repeated labels, ascending offsets)."""

import random

import pytest

from tdo_v2._call_clobber_sparse import _Covering


@pytest.mark.parametrize("seed", range(60))
def test_sweep_equals_scan(seed):
    rng = random.Random(7_000 + seed)
    spans = []
    for _ in range(rng.randrange(0, 25)):
        start = rng.randrange(0, 60)
        spans.append((start, start + rng.randrange(1, 20), f"w{rng.randrange(0, 8)}"))
    offsets = sorted(rng.sample(range(0, 90), rng.randrange(1, 40)))
    sweep = _Covering(spans)
    for offset in offsets:
        assert sweep.at(offset) == frozenset(label for s, e, label in spans if s <= offset < e)
