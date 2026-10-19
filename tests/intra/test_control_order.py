"""block_dominators as an immediate-dominator tree (docs 25.31 B0-1): the
same membership answers as the former greatest-fixed-point sets, on every
pair of blocks of random graphs with unreachable regions, self-loops, an
entry with predecessors, and keys outside the unit."""

import random
from types import SimpleNamespace

import pytest

from tdo_v2.integration.configured_control_order import block_dominators


def _old_block_dominators(unit):
    """The former implementation (blocks^2 sets), kept as the oracle."""
    blocks = {block.key: block for block in unit.blocks}
    all_keys = frozenset(blocks)
    dominators = {
        key: ({key} if key == unit.entry_block_key else set(all_keys))
        for key in blocks
    }
    changed = True
    while changed:
        changed = False
        for key, block in blocks.items():
            if key == unit.entry_block_key:
                continue
            shared = set(all_keys)
            for predecessor in block.predecessors:
                shared.intersection_update(dominators[predecessor])
            updated = {key} | shared
            if updated != dominators[key]:
                dominators[key] = updated
                changed = True
    return {key: frozenset(value) for key, value in dominators.items()}


def _unit(edges, count, entry="b0"):
    keys = [f"b{index}" for index in range(count)]
    predecessors = {key: [] for key in keys}
    for source, target in edges:
        predecessors[target].append(source)
    return SimpleNamespace(
        entry_block_key=entry,
        blocks=tuple(SimpleNamespace(key=key, predecessors=tuple(predecessors[key])) for key in keys),
    )


def _same(unit):
    old = _old_block_dominators(unit)
    new = block_dominators(unit)
    keys = [block.key for block in unit.blocks] + ["outside"]
    for lower in keys:
        if lower not in old:
            assert new.get(lower, ()) == ()
            continue
        view = new.get(lower, ())
        for upper in keys:
            assert (upper in view) == (upper in old[lower]), (lower, upper)


@pytest.mark.parametrize("seed", range(300))
def test_random_graphs_match_the_fixed_point(seed):
    rng = random.Random(seed)
    count = rng.randint(1, 12)
    edges = {(f"b{rng.randrange(count)}", f"b{rng.randrange(count)}")
             for _ in range(rng.randint(0, 3 * count))}
    _same(_unit(sorted(edges), count))


def test_unreachable_region_is_dominated_by_everything():
    unit = _unit([("b0", "b1"), ("b2", "b3"), ("b3", "b2"), ("b3", "b1")], 4)
    _same(unit)
    assert "b1" in block_dominators(unit).get("b2")


def test_entry_with_predecessors_keeps_only_itself():
    unit = _unit([("b0", "b1"), ("b1", "b0"), ("b0", "b0")], 2)
    _same(unit)
    view = block_dominators(unit).get("b0")
    assert "b0" in view and "b1" not in view


def test_an_outside_predecessor_of_the_entry_is_ignored():
    unit = _unit([("b0", "b1")], 2)
    unit.blocks[0].predecessors = ("elsewhere",)
    _same(unit)


def test_an_outside_predecessor_of_another_block_raises():
    unit = _unit([("b0", "b1")], 2)
    unit.blocks[1].predecessors = ("b0", "elsewhere")
    with pytest.raises(KeyError):
        _old_block_dominators(unit)
    with pytest.raises(KeyError):
        block_dominators(unit)


def test_an_entry_outside_the_unit_leaves_every_block_dominated_by_all():
    unit = _unit([("b0", "b1")], 2, entry="nowhere")
    _same(unit)


def test_the_views_are_membership_only():
    view = block_dominators(_unit([("b0", "b1")], 2)).get("b1")
    with pytest.raises(TypeError):
        iter(view)
