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
branch outside its instruction, or an indirect branch that is not last.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._scope_contracts import AddressCoordinate, ValidatedFunctionObservation, VarnodeKindCode
from .control_projection import control_successor_coordinates

_BRANCHES = ("BRANCH", "CBRANCH", "BRANCHIND")


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
    observation: ValidatedFunctionObservation, entry: AddressCoordinate
) -> PcodeBlockGraph:
    instructions = {row.address: row for row in observation.instructions}
    local = set(instructions)
    blocks: dict[str, PcodeBlock] = {}
    for address in sorted(instructions):
        row = instructions[address]
        key = instruction_key(address)
        if not has_internal_flow(row):
            raw = control_successor_coordinates(row, local_addresses=local, function_entry=entry)
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
    return rows


__all__ = ("PcodeBlock", "PcodeBlockGraph", "build_pcode_block_graph", "has_internal_flow", "instruction_key")
