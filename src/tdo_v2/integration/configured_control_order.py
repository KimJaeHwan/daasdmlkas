"""Control-order primitives for configured interprocedural analysis."""

from __future__ import annotations


def block_dominators(unit):
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


__all__ = ["block_dominators"]
