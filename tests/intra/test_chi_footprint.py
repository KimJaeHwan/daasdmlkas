"""The chi footprint (docs 25.83 D5'): every connected span minus a call's
preserved spans and own writes, by one sweep over the sorted holes, charged
per hole and per (span, hole of its object)."""

from types import SimpleNamespace

from memory_units import FUNCTION_SCOPE
from tdo_v2 import _chi_shadow
from tdo_v2.span_geometry import ByteSpan, StorageObjectId, StorageObjectKind


def _old_subtract(span, holes):
    """The per-hole fragment rebuild the sweep replaced (reference)."""
    pieces = [(span.start, span.end)]
    for hole in holes:
        if hole.object_id != span.object_id:
            continue
        pieces = [part for start, end in pieces for part in (
            ((start, min(end, hole.start)),) if hole.start > start else ()) + (
            ((max(start, hole.end), end),) if hole.end < end else ())
            if part[0] < part[1]]
    return [ByteSpan(span.object_id, start, end - start) for start, end in pieces]


def _call_action(writes=()):
    return SimpleNamespace(operation_key="1:1000:0:CALL", writes=tuple(writes))


def test_the_footprint_sweep_equals_the_fragment_rebuild():
    import random

    rng = random.Random(7)
    objects = [StorageObjectId(StorageObjectKind.FUNCTION_RELATIVE, FUNCTION_SCOPE, 7 + index) for index in range(2)]
    for _ in range(300):
        connected = tuple(ByteSpan(rng.choice(objects), rng.randrange(16, 144), rng.randrange(1, 40))
                          for _ in range(rng.randrange(1, 4)))
        holes = tuple(ByteSpan(rng.choice(objects), rng.randrange(0, 160), rng.randrange(1, 20))
                      for _ in range(rng.randrange(0, 8)))
        split = rng.randrange(len(holes) + 1)
        action = _call_action(holes[split:])
        preserved = {action.operation_key: holes[:split]}
        expected = tuple(piece for span in connected for piece in _old_subtract(span, holes))
        assert _chi_shadow._footprint(connected, action, preserved, frozenset()) == expected


def test_a_fragmented_preservation_is_swept_and_charged():
    """One span, 20000 alternating one-byte holes (Astra r2 P2): one sweep,
    charged per hole -- the fragment rebuild visits ~200 million pieces."""
    import time

    from tdo_v2.resource_limits import bounded

    whole = ByteSpan(StorageObjectId(StorageObjectKind.FUNCTION_RELATIVE, FUNCTION_SCOPE, 7), 0, 40000)
    holes = tuple(ByteSpan(whole.object_id, offset, 1) for offset in range(1, 40000, 2))
    action = _call_action()
    start = time.perf_counter()
    with bounded("footprint", 10**9) as bound:
        pieces = _chi_shadow._footprint((whole,), action, {action.operation_key: holes}, frozenset())
    elapsed = time.perf_counter() - start
    assert pieces == tuple(ByteSpan(whole.object_id, offset, 1) for offset in range(0, 40000, 2))
    assert len(holes) < bound.work <= 2 * len(holes) + 2
    assert elapsed < 1.0
