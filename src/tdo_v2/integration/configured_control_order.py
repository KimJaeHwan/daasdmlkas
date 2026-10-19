"""Control-order primitives for configured interprocedural analysis."""

from __future__ import annotations


class _Dominated:
    """The dominators of one block, as a membership test only (iteration
    fails loudly: there is no stored set to walk)."""

    __slots__ = ("_tree", "_key")

    def __init__(self, tree: "_Dominators", key) -> None:
        self._tree = tree
        self._key = key

    def __contains__(self, other) -> bool:
        return self._tree._dominates(other, self._key)


class _Dominators:
    """``block_dominators``' result: ``.get(block, default)`` -> a membership
    view of the blocks dominating ``block`` (itself included).

    The same answers as the greatest fixed point of
    dom(b) = {b} | (intersection of dom(p) over the predecessors p), every
    block but the entry starting at ALL: a block reachable from the entry
    gets its true dominators (an unreachable predecessor stays ALL, neutral
    in the intersection), an unreachable block keeps ALL, the entry keeps
    {entry} whatever its predecessors. Stored as the immediate-dominator tree
    (pre / post numbers) -- linear in the blocks, where the sets were
    quadratic (docs 25.31 B0-1). Charges no work, like the sets did."""

    def __init__(self, unit) -> None:
        blocks = {block.key: block for block in unit.blocks}
        entry = unit.entry_block_key
        for key, block in blocks.items():
            if key != entry:
                for predecessor in block.predecessors:
                    blocks[predecessor]   # a predecessor outside the unit: KeyError, as before
        self._blocks = frozenset(blocks)
        self._entry = entry
        successors: dict = {key: [] for key in blocks}
        for key, block in blocks.items():
            for predecessor in set(block.predecessors):
                if predecessor in successors:
                    successors[predecessor].append(key)
        for targets in successors.values():
            targets.sort()
        # reverse postorder of the blocks reachable from the entry
        order: list = []
        if entry in blocks:
            seen = {entry}
            stack = [(entry, iter(successors[entry]))]
            while stack:
                node, children = stack[-1]
                for child in children:
                    if child not in seen:
                        seen.add(child)
                        stack.append((child, iter(successors[child])))
                        break
                else:
                    stack.pop()
                    order.append(node)
            order.reverse()
        rank = {node: index for index, node in enumerate(order)}
        # Cooper, Harvey, Kennedy: immediate dominators over reachable predecessors
        idom = {entry: entry} if order else {}

        def intersect(left, right):
            while left != right:
                while rank[left] > rank[right]:
                    left = idom[left]
                while rank[right] > rank[left]:
                    right = idom[right]
            return left

        changed = bool(order)
        while changed:
            changed = False
            for node in order[1:]:
                processed = [item for item in blocks[node].predecessors if item in idom and item in rank]
                candidate = processed[0]
                for item in processed[1:]:
                    candidate = intersect(item, candidate)
                if idom.get(node) != candidate:
                    idom[node] = candidate
                    changed = True
        children: dict = {node: [] for node in order}
        for node in order[1:]:
            children[idom[node]].append(node)
        self._pre: dict = {}
        self._post: dict = {}
        counter = 0
        stack = [(entry, False)] if order else []
        while stack:
            node, done = stack.pop()
            if done:
                self._post[node] = counter
                counter += 1
                continue
            self._pre[node] = counter
            counter += 1
            stack.append((node, True))
            for child in sorted(children[node], reverse=True):
                stack.append((child, False))

    def _dominates(self, upper, lower) -> bool:
        if lower not in self._pre:   # unreachable (the entry is always numbered): ALL
            return upper in self._blocks
        if upper not in self._pre:
            return False
        return self._pre[upper] <= self._pre[lower] and self._post[lower] <= self._post[upper]

    def get(self, key, default=None):
        if key not in self._blocks:
            return default
        return _Dominated(self, key)


def block_dominators(unit) -> _Dominators:
    return _Dominators(unit)


__all__ = ["block_dominators"]
