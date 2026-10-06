"""Control dependence over the observed instruction CFG (Ferrante et al.).

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
* Inside one instruction: operations an in-instruction branch may skip are
  control dependent on it (``in_instruction_skips``; ``normalize`` admits only
  forward CBRANCH over register/temporary writes).

Edges run decision operation -> dependent operation with kind
``control_dependence``; queries follow them only when asked.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._scope_contracts import AddressCoordinate, ValidatedFunctionObservation, VarnodeKindCode
from .call_seeds import _operation_key
from .control_projection import control_successor_coordinates
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


def derive_control_dependences(
    observation: ValidatedFunctionObservation,
    entry: AddressCoordinate,
) -> tuple[ControlDependence, ...]:
    if type(observation) is not ValidatedFunctionObservation:
        raise TypeError("control dependence requires an exact observation")
    instructions = {row.address: row for row in observation.instructions}
    successors: dict[object, tuple[object, ...]] = {}
    for address, instruction in instructions.items():
        raw = control_successor_coordinates(
            instruction, local_addresses=set(instructions), function_entry=entry
        )
        targets = tuple(target for target in raw if target in instructions)
        if not targets or len(targets) != len(raw):
            # a target outside the observed function leaves it (tail jump)
            targets = (*targets, _EXIT)
        successors[address] = targets
    successors[_EXIT] = ()
    _connect_exitless(successors)
    postdominators = _postdominators(successors)
    immediate = {node: _immediate(node, postdominators) for node in successors}

    rows: set[ControlDependence] = set()
    for address, targets in successors.items():
        if address == _EXIT or len(set(targets)) < 2:
            continue
        decision = _decision_key(instructions[address])
        if decision is None:
            continue
        stop = immediate[address]
        for target in set(targets):
            node = target
            while node is not None and node != stop and node != _EXIT:
                rows.update(
                    ControlDependence(decision, key)
                    for key in _operation_keys(instructions[node])
                )
                node = immediate[node]
    for instruction in instructions.values():
        rows.update(_in_instruction(instruction))
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
        node = pending.pop()
        if node in reaches:
            continue
        reaches.add(node)
        pending.extend(reverse[node])
    for node in sorted((n for n in successors if n not in reaches), key=repr):
        successors[node] = (*successors[node], _EXIT)


def _postdominators(successors) -> dict[object, frozenset]:
    nodes = tuple(successors)
    everything = frozenset(nodes)
    result = {node: everything for node in nodes}
    result[_EXIT] = frozenset({_EXIT})
    changed = True
    while changed:
        changed = False
        for node in nodes:
            if node == _EXIT:
                continue
            meet = frozenset.intersection(*(result[target] for target in successors[node]))
            updated = meet | {node}
            if updated != result[node]:
                result[node] = updated
                changed = True
    return result


def _immediate(node, postdominators):
    strict = postdominators[node] - {node}
    for candidate in strict:
        if postdominators[candidate] == strict:
            return candidate
    return None


def _decision_key(instruction) -> str | None:
    for ordinal, operation in enumerate(instruction.operations):
        if operation.opcode == "BRANCHIND" or (
            operation.opcode == "CBRANCH"
            and operation.inputs
            and operation.inputs[0].kind is not VarnodeKindCode.CONSTANT
        ):
            return _operation_key(instruction.address, ordinal, operation.opcode)
    return None


def _operation_keys(instruction) -> tuple[str, ...]:
    return tuple(
        _operation_key(instruction.address, ordinal, operation.opcode)
        for ordinal, operation in enumerate(instruction.operations)
    )


def in_instruction_skips(instruction) -> tuple[tuple[int, str, int], ...]:
    """(ordinal, opcode, stop): operations ordinal+1 .. stop-1 may be skipped.

    A relative branch jumps to ``ordinal + delta`` inside the instruction. A
    branch to an address that is not the last operation leaves the
    instruction early (Ghidra encodes ``cmovcc`` as ``CBRANCH <next
    instruction>`` followed by the move), skipping the rest.
    """
    operations = instruction.operations
    rows = []
    for ordinal, operation in enumerate(operations):
        if operation.opcode not in ("BRANCH", "CBRANCH") or not operation.inputs:
            continue
        destination = operation.inputs[0]
        if destination.kind is VarnodeKindCode.CONSTANT:
            bits = 8 * destination.byte_size
            delta = destination.coordinate.byte_offset
            if delta >> (bits - 1) & 1:
                delta -= 1 << bits
            rows.append((ordinal, operation.opcode, ordinal + delta))
        elif ordinal < len(operations) - 1:
            rows.append((ordinal, operation.opcode, len(operations)))
    return tuple(rows)


def _in_instruction(instruction):
    operations = instruction.operations
    for ordinal, opcode, stop in in_instruction_skips(instruction):
        if opcode != "CBRANCH":
            continue
        decision = _operation_key(instruction.address, ordinal, opcode)
        for index in range(ordinal + 1, min(stop, len(operations))):
            yield ControlDependence(
                decision,
                _operation_key(instruction.address, index, operations[index].opcode),
            )


__all__ = (
    "CONTROL_DEPENDENCE_EDGE",
    "ControlDependence",
    "derive_control_dependences",
    "in_instruction_skips",
)
