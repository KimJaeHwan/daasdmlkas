"""Persistent sparse state used by local memory SSA."""

from __future__ import annotations

from dataclasses import dataclass
import weakref


_RADIX_BITS = 8
_RADIX_MASK = (1 << _RADIX_BITS) - 1
_RADIX_LEVELS = 8


@dataclass(frozen=True, slots=True, weakref_slot=True)
class RadixNode:
    level: int
    bitmap: int
    children: tuple[RadixNode, ...]
    size: int
    token: int


def _child(node: RadixNode, digit: int) -> RadixNode | None:
    bit = 1 << digit
    if not node.bitmap & bit:
        return None
    ordinal = (node.bitmap & (bit - 1)).bit_count()
    return node.children[ordinal]


def _iter_values(node: RadixNode, prefix: int = 0):
    remaining = node.bitmap
    while remaining:
        bit = remaining & -remaining
        digit = bit.bit_length() - 1
        value = prefix | (digit << (_RADIX_BITS * node.level))
        if node.level:
            child = _child(node, digit)
            assert child is not None
            yield from _iter_values(child, value)
        else:
            yield value
        remaining ^= bit


@dataclass(frozen=True, slots=True, eq=False)
class IdSet:
    pool: DefinitionSetPool
    root: RadixNode | None = None

    def __bool__(self) -> bool:
        return self.root is not None

    def __len__(self) -> int:
        return 0 if self.root is None else self.root.size

    def __iter__(self):
        return iter(()) if self.root is None else _iter_values(self.root)

    def __eq__(self, other: object) -> bool:
        same_build = type(other) is IdSet and self.pool is other.pool
        return same_build and self.root is other.root

    def union(self, other: IdSet) -> IdSet:
        self._require_same_pool(other)
        root = self.pool._union(self.root, other.root)
        if root is self.root:
            return self
        if root is other.root:
            return other
        return IdSet(self.pool, root)

    def difference(self, other: IdSet) -> IdSet:
        self._require_same_pool(other)
        root = self.pool._difference(self.root, other.root)
        return self if root is self.root else IdSet(self.pool, root)

    def _require_same_pool(self, other: IdSet) -> None:
        if self.pool is not other.pool:
            raise ValueError("definition sets belong to different builds")


class DefinitionSetPool:
    def __init__(self) -> None:
        self._nodes = weakref.WeakValueDictionary()
        self._next_token = 0

    def intern(self, values) -> IdSet:
        if type(values) is IdSet:
            if values.pool is not self:
                raise ValueError("definition sets belong to different builds")
            return values
        root = None
        for value in values:
            root = self._union(root, self._singleton(value))
        return IdSet(self, root)

    def _intern(
        self,
        level: int,
        bitmap: int,
        children: tuple[RadixNode, ...],
    ) -> RadixNode | None:
        if not bitmap:
            return None
        key = (level, bitmap, *(child.token for child in children))
        node = self._nodes.get(key)
        if node is None:
            size = bitmap.bit_count() if level == 0 else sum(
                child.size for child in children
            )
            node = RadixNode(level, bitmap, children, size, self._next_token)
            self._next_token += 1
            self._nodes[key] = node
        return node

    def _singleton(self, value: int) -> RadixNode:
        if type(value) is not int or value < 0 or value.bit_length() > 64:
            raise ValueError("definition ID is outside the fixed radix domain")
        node = None
        for level in range(_RADIX_LEVELS):
            digit = (value >> (_RADIX_BITS * level)) & _RADIX_MASK
            children = () if node is None else (node,)
            node = self._intern(level, 1 << digit, children)
            assert node is not None
        return node

    def _union(
        self,
        left: RadixNode | None,
        right: RadixNode | None,
    ) -> RadixNode | None:
        if left is None or left is right:
            return right
        if right is None:
            return left
        if left.level == 0:
            return self._intern(0, left.bitmap | right.bitmap, ())
        bitmap = left.bitmap | right.bitmap
        children = []
        remaining = bitmap
        while remaining:
            bit = remaining & -remaining
            digit = bit.bit_length() - 1
            child = self._union(_child(left, digit), _child(right, digit))
            assert child is not None
            children.append(child)
            remaining ^= bit
        return self._intern(left.level, bitmap, tuple(children))

    def _difference(
        self,
        left: RadixNode | None,
        right: RadixNode | None,
    ) -> RadixNode | None:
        if left is None or left is right:
            return None
        if right is None:
            return left
        if left.level == 0:
            return self._intern(0, left.bitmap & ~right.bitmap, ())
        bitmap = 0
        children = []
        remaining = left.bitmap
        while remaining:
            bit = remaining & -remaining
            digit = bit.bit_length() - 1
            child = self._difference(_child(left, digit), _child(right, digit))
            if child is not None:
                bitmap |= bit
                children.append(child)
            remaining ^= bit
        return self._intern(left.level, bitmap, tuple(children))


@dataclass(frozen=True, slots=True)
class Run:
    start: int
    stop: int
    definitions: IdSet


@dataclass(frozen=True, slots=True)
class RunNode:
    run: Run
    left: RunNode | None
    right: RunNode | None
    height: int
    count: int


@dataclass(frozen=True, slots=True)
class State:
    root: RunNode | None


EMPTY_STATE = State(None)


def _height(node: RunNode | None) -> int:
    return 0 if node is None else node.height


def _count(node: RunNode | None) -> int:
    return 0 if node is None else node.count


def _node(
    run: Run,
    left: RunNode | None = None,
    right: RunNode | None = None,
) -> RunNode:
    return RunNode(
        run,
        left,
        right,
        max(_height(left), _height(right)) + 1,
        _count(left) + _count(right) + 1,
    )


def _balance(node: RunNode) -> RunNode:
    if _height(node.left) > _height(node.right) + 1:
        left = node.left
        assert left is not None
        if _height(left.left) < _height(left.right):
            pivot = left.right
            assert pivot is not None
            left = _node(left.run, left.left, pivot.left)
            node = _node(node.run, _node(pivot.run, left, pivot.right), node.right)
        pivot = node.left
        assert pivot is not None
        return _node(pivot.run, pivot.left, _node(node.run, pivot.right, node.right))
    if _height(node.right) > _height(node.left) + 1:
        right = node.right
        assert right is not None
        if _height(right.right) < _height(right.left):
            pivot = right.left
            assert pivot is not None
            right = _node(right.run, pivot.right, right.right)
            node = _node(node.run, node.left, _node(pivot.run, pivot.left, right))
        pivot = node.right
        assert pivot is not None
        return _node(pivot.run, _node(node.run, node.left, pivot.left), pivot.right)
    return node


def _join_with_run(
    left: RunNode | None,
    run: Run,
    right: RunNode | None,
) -> RunNode:
    if _height(left) > _height(right) + 1:
        assert left is not None
        return _balance(
            _node(left.run, left.left, _join_with_run(left.right, run, right))
        )
    if _height(right) > _height(left) + 1:
        assert right is not None
        return _balance(
            _node(right.run, _join_with_run(left, run, right.left), right.right)
        )
    return _node(run, left, right)


def _split(
    root: RunNode | None, position: int
) -> tuple[RunNode | None, RunNode | None]:
    if root is None:
        return None, None
    run = root.run
    if position <= run.start:
        left, remainder = _split(root.left, position)
        return left, _join_with_run(remainder, run, root.right)
    if position >= run.stop:
        remainder, right = _split(root.right, position)
        return _join_with_run(root.left, run, remainder), right
    return (
        _join_with_run(root.left, Run(run.start, position, run.definitions), None),
        _join_with_run(None, Run(position, run.stop, run.definitions), root.right),
    )


def _pop_first(root: RunNode) -> tuple[Run, RunNode | None]:
    if root.left is None:
        return root.run, root.right
    run, left = _pop_first(root.left)
    return run, _balance(_node(root.run, left, root.right))


def _pop_last(root: RunNode) -> tuple[RunNode | None, Run]:
    if root.right is None:
        return root.left, root.run
    right, run = _pop_last(root.right)
    return _balance(_node(root.run, root.left, right)), run


def iter_runs(root: RunNode | None):
    stack: list[RunNode] = []
    while stack or root is not None:
        while root is not None:
            stack.append(root)
            root = root.left
        root = stack.pop()
        yield root.run
        root = root.right


def iter_runs_from(root: RunNode | None, position: int):
    stack: list[RunNode] = []
    while root is not None:
        if root.run.stop > position:
            stack.append(root)
            root = root.left
        else:
            root = root.right
    while stack:
        root = stack.pop()
        yield root.run
        right = root.right
        while right is not None:
            stack.append(right)
            right = right.left


def _before(left: RunNode, right: RunNode) -> bool:
    while left.right is not None:
        left = left.right
    while right.left is not None:
        right = right.left
    return left.run.stop <= right.run.start


def _build_tree(runs: list[Run], start: int, stop: int) -> RunNode | None:
    if start == stop:
        return None
    middle = (start + stop) // 2
    return _node(
        runs[middle],
        _build_tree(runs, start, middle),
        _build_tree(runs, middle + 1, stop),
    )


def make_state(runs) -> State:
    merged: list[Run] = []
    for run in runs:
        if run.start == run.stop or not run.definitions:
            continue
        if (
            merged
            and merged[-1].stop == run.start
            and merged[-1].definitions == run.definitions
        ):
            previous = merged[-1]
            merged[-1] = Run(previous.start, run.stop, previous.definitions)
        else:
            merged.append(run)
    return State(_build_tree(merged, 0, len(merged)))


def _concat(left: RunNode | None, right: RunNode | None) -> RunNode | None:
    if left is None or right is None:
        return left or right
    left, previous = _pop_last(left)
    following, right = _pop_first(right)
    if (
        previous.stop == following.start
        and previous.definitions == following.definitions
    ):
        return _join_with_run(
            left,
            Run(previous.start, following.stop, previous.definitions),
            right,
        )
    left = _join_with_run(left, previous, None)
    return _join_with_run(left, following, right)


def replace(state: State, start: int, stop: int, definitions: IdSet) -> State:
    left, remainder = _split(state.root, start)
    _, right = _split(remainder, stop)
    middle = _node(Run(start, stop, definitions))
    return State(_concat(_concat(left, middle), right))


def _union_run(state: State, incoming: Run) -> State:
    left, remainder = _split(state.root, incoming.start)
    middle, right = _split(remainder, incoming.stop)
    runs: list[Run] = []
    cursor = incoming.start
    for current in iter_runs(middle):
        if cursor < current.start:
            runs.append(Run(cursor, current.start, incoming.definitions))
        runs.append(
            Run(
                current.start,
                current.stop,
                current.definitions.union(incoming.definitions),
            )
        )
        cursor = current.stop
    if cursor < incoming.stop:
        runs.append(Run(cursor, incoming.stop, incoming.definitions))
    middle = make_state(runs).root
    return State(_concat(_concat(left, middle), right))


def union(state: State, delta: State) -> State:
    if state.root is None:
        return delta
    if delta.root is None:
        return state
    if _before(state.root, delta.root):
        return State(_concat(state.root, delta.root))
    if _before(delta.root, state.root):
        return State(_concat(delta.root, state.root))
    if _count(state.root) < _count(delta.root):
        state, delta = delta, state
    for incoming in iter_runs(delta.root):
        state = _union_run(state, incoming)
    return state


def _left_combine(state: State, other: State, combine) -> State:
    runs: list[Run] = []
    for current in iter_runs(state.root):
        cursor = current.start
        for overlap in iter_runs_from(other.root, current.start):
            if overlap.start >= current.stop:
                break
            overlap_start = max(cursor, overlap.start)
            if cursor < overlap_start:
                runs.append(Run(cursor, overlap_start, current.definitions))
            overlap_stop = min(current.stop, overlap.stop)
            definitions = combine(current.definitions, overlap.definitions)
            if definitions:
                runs.append(Run(overlap_start, overlap_stop, definitions))
            cursor = overlap_stop
            if cursor == current.stop:
                break
        if cursor < current.stop:
            runs.append(Run(cursor, current.stop, current.definitions))
    return make_state(runs)


def subtract(delta: State, state: State) -> State:
    if delta.root is None or state.root is None:
        return delta
    if _before(delta.root, state.root) or _before(state.root, delta.root):
        return delta
    if _count(state.root) < _count(delta.root):
        for existing in iter_runs(state.root):
            left, remainder = _split(delta.root, existing.start)
            middle, right = _split(remainder, existing.stop)
            middle = make_state(
                Run(
                    run.start,
                    run.stop,
                    run.definitions.difference(existing.definitions),
                )
                for run in iter_runs(middle)
            ).root
            delta = State(_concat(_concat(left, middle), right))
        return delta
    return _left_combine(delta, state, IdSet.difference)


def mask(delta: State, writes: State) -> State:
    if delta.root is None or writes.root is None:
        return delta
    if _before(delta.root, writes.root) or _before(writes.root, delta.root):
        return delta
    for written in iter_runs(writes.root):
        left, remainder = _split(delta.root, written.start)
        _, right = _split(remainder, written.stop)
        delta = State(_concat(left, right))
    return delta


def overlay(state: State, writes: State) -> State:
    for run in iter_runs(writes.root):
        state = replace(state, run.start, run.stop, run.definitions)
    return state
