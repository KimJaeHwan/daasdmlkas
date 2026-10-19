"""Control dependence over the p-code block graph (Ferrante et al.).

An operation is control dependent on a branch when the branch's outcome
decides whether the operation executes. ``x = 0; if (s) x = 1; sink(x)``:
the write ``x = 1`` depends on the branch, whose condition reads ``s``, so a
slice that follows control edges reaches ``s``.

* Instruction level: postdominators on the observed CFG with a virtual EXIT.
  Instructions without local successors (RETURN, unresolved jumps) flow to
  EXIT; instructions that cannot reach EXIT (infinite loops) get a virtual
  edge to EXIT, the standard completion, so every node has a postdominator.
  For each branch A and successor B, the instructions on the postdominator
  tree path from B up to (excluding) ipdom(A) are control dependent on A.
  The deciding operation of A is its CBRANCH (with an address destination)
  or BRANCHIND.
* Instructions with internal p-code flow (cmov, rep loops) are split into
  p-code blocks (``pcode_blocks``), so the same algorithm covers branches
  inside an instruction, including conditional back edges.

Edges run decision operation -> dependent operation with kind
``control_dependence``; queries follow them only when asked.
"""

from __future__ import annotations

from .phases import count as phase_count, measured

from .resource_limits import step

from dataclasses import dataclass

from ._scope_contracts import AddressCoordinate, ValidatedFunctionObservation
from .call_seeds import _operation_key
from .pcode_blocks import build_pcode_block_graph
from .graph import CONTROL_DEPENDENCE_EDGE

_EXIT = "exit"


@dataclass(frozen=True, slots=True)
class ControlDependence:
    decision: str    # operation key of the CBRANCH / BRANCHIND
    dependent: str   # operation key whose execution the decision controls

    def __post_init__(self) -> None:
        for value in (self.decision, self.dependent):
            if type(value) is not str or not value:
                raise TypeError("control dependence requires exact operation keys")


@measured("control_dependence")
def derive_control_dependences(
    observation: ValidatedFunctionObservation,
    entry: AddressCoordinate,
) -> tuple[ControlDependence, ...]:
    """Ferrante control dependence on the p-code block graph (``pcode_blocks``):
    one block per instruction, split where an instruction has internal flow."""
    if type(observation) is not ValidatedFunctionObservation:
        raise TypeError("control dependence requires an exact observation")
    graph = build_pcode_block_graph(observation, entry)
    if graph.unsupported is not None:
        return ()
    instructions = {row.address: row for row in observation.instructions}
    blocks = {block.key: block for block in graph.blocks}
    successors: dict[object, tuple[object, ...]] = {}
    for block in graph.blocks:
        targets = tuple(target for target in block.successors if target in blocks)
        if block.exits or not targets:
            targets = (*targets, _EXIT)
        successors[block.key] = targets
    successors[_EXIT] = ()
    _connect_exitless(successors)
    immediate = _immediate_postdominators(successors)

    def operation_keys(block):
        row = instructions[block.instruction]
        return tuple(
            _operation_key(row.address, ordinal, row.operations[ordinal].opcode)
            for ordinal in range(block.start, block.stop)
        )

    rows: set[ControlDependence] = set()
    walked = 0   # (K2 sizes: postdominator walk steps, docs 25.31)
    for key, targets in successors.items():
        if key == _EXIT or len(set(targets)) < 2:
            continue
        block = blocks[key]
        row = instructions[block.instruction]
        last = row.operations[block.stop - 1]
        if last.opcode not in ("CBRANCH", "BRANCHIND"):
            continue
        decision = _operation_key(row.address, block.stop - 1, last.opcode)
        stop = immediate[key]
        for target in set(targets):
            node = target
            while node is not None and node != stop and node != _EXIT:
                rows.update(
                    ControlDependence(decision, dependent)
                    for dependent in operation_keys(blocks[node])
                )
                node = immediate[node]
                walked += 1
    phase_count("cd_walk_steps", walked)
    phase_count("cd_pairs", len(rows))
    return tuple(sorted(rows, key=lambda row: (row.decision, row.dependent)))


def _connect_exitless(successors) -> None:
    """Give every node that cannot reach EXIT a virtual edge to it."""
    reverse: dict[object, set] = {node: set() for node in successors}
    for node, targets in successors.items():
        for target in targets:
            reverse[target].add(node)
    reaches = set()
    pending = [_EXIT]
    while pending:
        step()   # (budget: docs 25.30 K1c)
        node = pending.pop()
        if node in reaches:
            continue
        reaches.add(node)
        pending.extend(reverse[node])
    for node in sorted((n for n in successors if n not in reaches), key=repr):
        successors[node] = (*successors[node], _EXIT)


def _immediate_postdominators(successors) -> dict[object, object]:
    """Cooper-Harvey-Kennedy dominators on the reversed graph rooted at EXIT
    (every node reaches EXIT after ``_connect_exitless``); EXIT maps to None."""
    predecessors: dict[object, list] = {node: [] for node in successors}
    for node, targets in successors.items():
        for target in targets:
            predecessors[target].append(node)
    # postorder of the reversed graph (edges target -> source) from EXIT
    order: list = []
    seen = {_EXIT}
    stack = [(_EXIT, iter(sorted(predecessors[_EXIT], key=repr)))]
    while stack:
        step()   # (budget: docs 25.30 K1c)
        node, children = stack[-1]
        for child in children:
            if child not in seen:
                seen.add(child)
                stack.append((child, iter(sorted(predecessors[child], key=repr))))
                break
        else:
            stack.pop()
            order.append(node)
    rank = {node: index for index, node in enumerate(order)}
    immediate: dict[object, object] = {_EXIT: _EXIT}

    def intersect(left, right):
        while left != right:
            while rank[left] < rank[right]:
                left = immediate[left]
            while rank[right] < rank[left]:
                right = immediate[right]
        return left

    changed = True
    while changed:
        step()   # (budget: docs 25.30 K1c)
        changed = False
        for node in reversed(order):
            if node == _EXIT:
                continue
            processed = [target for target in successors[node] if target in immediate]
            if not processed:
                continue
            candidate = processed[0]
            for target in processed[1:]:
                candidate = intersect(target, candidate)
            if immediate.get(node) != candidate:
                immediate[node] = candidate
                changed = True
    immediate[_EXIT] = None
    return {node: immediate.get(node) for node in successors}


__all__ = (
    "CONTROL_DEPENDENCE_EDGE",
    "ControlDependence",
    "derive_control_dependences",
)
