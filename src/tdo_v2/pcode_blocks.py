"""P-code-level basic blocks for instructions with internal control flow.

Most instructions are one straight block, keyed by the instruction address.
An instruction with internal p-code control flow -- a relative branch
(``CBRANCH +2``), a branch to its own address (Ghidra's ``rep`` loop shape:
``CBRANCH <next instruction>`` ... ``BRANCH <self>``), or any branch that is
not its last operation -- is split into sub-blocks at every branch target and
after every branch. The first sub-block keeps the instruction key (so other
instructions' edges are unchanged); later sub-blocks are keyed
``<instruction key>#<first operation ordinal>``.

Successors come from the p-code itself (Ghidra's flow targets do not list an
instruction's own address), from ``fallthrough``, and from the instruction's
observed successors when its last operation ends it. Blocks unreachable from
the function entry (operations after an unconditional branch) execute never
and are dropped. Unsupported shapes are reported, not guessed: a relative
branch outside its instruction, an indirect branch or a return that is not
last; and,
where the observed flow and the p-code could disagree (none occurs in the
corpus, ``.census6/graph_census.py``): a call with local flow targets
(exception landing pads) unless it is one straight block ending in its only
call operation (operations after it would seem to run before the exceptional
edge); a split instruction that is a call with such targets or carries a flow
override; a split instruction whose observed successors its reachable
sub-blocks do not all reach, or whose flow targets are not all destinations of
its reachable branches.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._scope_contracts import AddressCoordinate, ValidatedFunctionObservation, VarnodeKindCode
from .control_projection import control_successor_coordinates

_BRANCHES = ("BRANCH", "CBRANCH", "BRANCHIND")
_CALLS = ("CALL", "CALLIND")


@dataclass(frozen=True, slots=True)
class PcodeBlock:
    key: str
    instruction: AddressCoordinate
    start: int
    stop: int
    successors: tuple[str, ...]
    exits: bool = False  # control may leave the function here (return, tail jump)


@dataclass(frozen=True, slots=True)
class PcodeBlockGraph:
    entry: str
    blocks: tuple[PcodeBlock, ...]          # reachable blocks in address/ordinal order
    unsupported: str | None = None

    def block_of(self, address: AddressCoordinate, ordinal: int) -> PcodeBlock | None:
        for block in self.blocks:
            if block.instruction == address and block.start <= ordinal < block.stop:
                return block
        return None


def instruction_key(address: AddressCoordinate) -> str:
    return f"{address.space_id:x}:{address.byte_offset:x}"


def has_internal_flow(instruction) -> bool:
    operations = instruction.operations
    for ordinal, operation in enumerate(operations):
        if operation.opcode not in _BRANCHES or not operation.inputs:
            continue
        if ordinal < len(operations) - 1:
            return True
        destination = operation.inputs[0]
        if operation.opcode != "BRANCHIND" and (
            destination.kind is VarnodeKindCode.CONSTANT
            or destination.coordinate == instruction.address
        ):
            return True
    return False


def build_pcode_block_graph(
    observation: ValidatedFunctionObservation, entry: AddressCoordinate,
    straight: frozenset = frozenset(),
) -> PcodeBlockGraph:
    """``straight``: instruction addresses whose internal flow is modelled as
    one block (recognized ``rep`` string instructions, ``rep_strings``)."""
    instructions = {row.address: row for row in observation.instructions}
    local = set(instructions)
    blocks: dict[str, PcodeBlock] = {}
    for address in sorted(instructions):
        row = instructions[address]
        key = instruction_key(address)
        if any(item.opcode == "RETURN" for item in row.operations[:-1]):
            return PcodeBlockGraph(instruction_key(entry), (), "a return that is not last")
        if not has_internal_flow(row) or address in straight:
            raw = control_successor_coordinates(row, local_addresses=local, function_entry=entry)
            operations = row.operations
            if _landing_pads(row, local, entry) and not (
                operations and operations[-1].opcode in _CALLS
                and not any(item.opcode in _CALLS + ("CALLOTHER",) for item in operations[:-1])
            ):
                return PcodeBlockGraph(instruction_key(entry), (), "a call with landing pads that does not end in its call")
            successors = tuple(instruction_key(target) for target in raw if target in local)
            blocks[key] = PcodeBlock(
                key, address, 0, len(row.operations), tuple(sorted(set(successors))),
                exits=not successors or len(successors) != len(raw),
            )
            continue
        split = _split(row, local, entry)
        if isinstance(split, str):
            return PcodeBlockGraph(instruction_key(entry), (), split)
        for block in split:
            blocks[block.key] = block
    entry_key = instruction_key(entry)
    reachable, pending = set(), [entry_key]
    while pending:
        key = pending.pop()
        if key in reachable or key not in blocks:
            continue
        reachable.add(key)
        pending.extend(blocks[key].successors)
    ordered = tuple(
        blocks[key] for key in sorted(reachable, key=lambda k: (blocks[k].instruction, blocks[k].start))
    )
    return PcodeBlockGraph(entry_key, ordered)


def _split(row, local, entry):
    operations = row.operations
    count = len(operations)
    base = instruction_key(row.address)
    leaders = {0}
    targets: dict[int, object] = {}
    for ordinal, operation in enumerate(operations):
        if operation.opcode not in _BRANCHES or not operation.inputs:
            continue
        if ordinal + 1 < count:
            leaders.add(ordinal + 1)
        if operation.opcode == "BRANCHIND":
            if ordinal != count - 1:
                return "indirect branch inside an instruction"
            continue
        destination = operation.inputs[0]
        if destination.kind is VarnodeKindCode.CONSTANT:
            bits = 8 * destination.byte_size
            delta = destination.coordinate.byte_offset
            if delta >> (bits - 1) & 1:
                delta -= 1 << bits
            target = ordinal + delta
            if not 0 <= target <= count:
                return "relative branch outside its instruction"
            if target < count:
                leaders.add(target)
            targets[ordinal] = ("relative", target)
        elif destination.coordinate == row.address:
            targets[ordinal] = ("relative", 0)
        else:
            targets[ordinal] = ("address", destination.coordinate)
    starts = sorted(leaders)
    if _landing_pads(row, local, entry):
        return "a split call with landing pads"
    if row.flow.is_override:
        return "a split instruction with a flow override"

    def segment_key(start: int) -> str:
        return base if start == 0 else f"{base}#{start}"

    def after_instruction():
        fallthrough = row.fallthrough
        return (instruction_key(fallthrough),) if fallthrough in local else ()

    def resolve(ordinal):
        kind, value = targets[ordinal]
        if kind == "relative":
            return (segment_key(value),) if value < count else after_instruction()
        return (instruction_key(value),) if value in local else ()  # leaving the function

    def leaves(ordinal):
        kind, value = targets[ordinal]
        if kind == "relative":
            return value >= count and not after_instruction()
        return value not in local

    rows = []
    for index, start in enumerate(starts):
        stop = starts[index + 1] if index + 1 < len(starts) else count
        if stop == start:
            continue
        last = stop - 1
        opcode = operations[last].opcode
        falls = (segment_key(stop),) if stop < count else after_instruction()
        falls_out = stop >= count and not after_instruction()
        exits = False
        if opcode == "BRANCH" and last in targets:
            successors, exits = resolve(last), leaves(last)
        elif opcode == "CBRANCH" and last in targets:
            successors, exits = resolve(last) + falls, leaves(last) or falls_out
        elif opcode == "BRANCHIND":
            raw = control_successor_coordinates(row, local_addresses=local, function_entry=entry)
            successors = tuple(instruction_key(target) for target in raw if target in local)
            exits = not successors or len(successors) != len(raw)
        elif opcode == "RETURN" and last == count - 1:
            successors, exits = (), True
        else:
            successors, exits = falls, falls_out
        rows.append(PcodeBlock(
            segment_key(start), row.address, start, stop, tuple(sorted(set(successors))), exits
        ))
    # the observed flow must agree with the p-code's: every observed successor
    # reached from a sub-block that runs, every flow target a destination of a
    # branch that runs (a branch in an unreachable sub-block places none)
    by_key = {block.key: block for block in rows}
    reached, pending = set(), [base]
    while pending:
        key = pending.pop()
        if key in reached or key not in by_key:
            continue
        reached.add(key)
        pending.extend(by_key[key].successors)
    leaving = {successor for key in reached for successor in by_key[key].successors if successor not in by_key}
    observed = control_successor_coordinates(row, local_addresses=local, function_entry=entry)
    if {instruction_key(target) for target in observed if target in local} - leaving:
        return "observed successors the instruction's p-code does not reach"
    if operations[-1].opcode != "BRANCHIND":  # a terminal BRANCHIND takes the observed targets
        placed = {
            targets[block.stop - 1][1] for block in rows
            if block.key in reached and block.stop - 1 in targets and targets[block.stop - 1][0] == "address"
            and operations[block.stop - 1].opcode in ("BRANCH", "CBRANCH")
        }
        if {target for target in row.flow_targets if target in local} - placed:
            return "flow targets the instruction's branches do not place"
    return rows


def _landing_pads(row, local, entry) -> tuple:
    """A call instruction's local flow targets (``control_successor_coordinates``
    adds them; the fallthrough too when listed)."""
    if not row.flow.is_call:
        return ()
    return tuple(target for target in row.flow_targets if target in local and target != entry)


__all__ = ("PcodeBlock", "PcodeBlockGraph", "build_pcode_block_graph", "has_internal_flow", "instruction_key")
