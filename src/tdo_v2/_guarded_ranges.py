"""Read-occurrence bounds from the ORIGINAL internal p-code CFG.

This does not solve a loop or change SSA. Every incoming path to a COPY
read must independently establish the same unique's unsigned range, by a
full-width literal write or a nonzero logical-right-shift guard. Uncovered
paths/cycles, writes, calls and unsupported flow refuse the optional bound.
The ordinary forward reader still carries its original debts and taint.
"""

from ._scope_contracts import VarnodeKindCode as Kind
from .pcode_blocks import build_pcode_block_graph, has_internal_flow
from .resource_limits import step

MAX_OPERATIONS = 128
MAX_WORK = 4096


def _overlaps(left, right):
    # Match the SSA's UNIQUE/REGISTER object geometry: nominal space IDs do
    # not split these storage objects into independent alias domains.
    return left is not None and left.kind == right.kind \
        and left.coordinate.byte_offset < right.coordinate.byte_offset + right.byte_size \
        and right.coordinate.byte_offset < left.coordinate.byte_offset + left.byte_size


def _destination(ordinal, operation):
    target = operation.inputs[0]
    if target.kind is not Kind.CONSTANT:
        return None
    bits = 8 * target.byte_size
    delta = target.coordinate.byte_offset
    if delta & (1 << (bits - 1)):
        delta -= 1 << bits
    return ordinal + delta


def _guard(operations, predecessors, ordinal, successor, target):
    """LShR_w(x,count) != 0 implies unsigned count < w on THIS edge.

    The adjacent producer chain must be the only way to reach the branch;
    jumping into its comparison with an old shift result is not evidence.
    """
    branch = operations[ordinal]
    if branch.opcode != "CBRANCH" or ordinal < 2 or len(branch.inputs) != 2 \
            or predecessors.get(ordinal) != (ordinal - 1,) \
            or predecessors.get(ordinal - 1) != (ordinal - 2,):
        return None
    destination = _destination(ordinal, branch)
    if destination is None or destination == ordinal + 1:
        return None
    taken = successor == destination
    if not taken and successor != ordinal + 1:
        return None
    compare, shift = operations[ordinal - 1], operations[ordinal - 2]
    if compare.opcode not in ("INT_EQUAL", "INT_NOTEQUAL") or compare.output != branch.inputs[1] \
            or len(compare.inputs) != 2 or shift.opcode != "INT_RIGHT" or len(shift.inputs) != 2 \
            or shift.output is None or shift.inputs[1] != target \
            or shift.output.byte_size != shift.inputs[0].byte_size \
            or _overlaps(shift.output, target) or _overlaps(compare.output, target):
        return None
    if not ((compare.opcode == "INT_NOTEQUAL") == taken):
        return None
    if not any(value == shift.output and other.kind is Kind.CONSTANT
               and other.coordinate.byte_offset == 0 and other.byte_size == value.byte_size
               for value, other in (compare.inputs, compare.inputs[::-1])):
        return None
    return 0, min((1 << (8 * target.byte_size)) - 1, 8 * shift.inputs[0].byte_size - 1)


def _bound(operations, predecessors, position, target):
    # An explicit DFS stack: no Python recursion and no unrolling of a cycle.
    values, active, pending, work = {}, set(), [(position, False)], 0
    edges = {}
    while pending:
        step()
        work += 1
        if work > MAX_WORK:
            return None
        point, finish = pending.pop()
        if point in values:
            continue
        if not finish:
            if point in active:
                return None
            active.add(point)
            inputs = []
            for previous in predecessors.get(point, ()):
                step()
                if previous is None:
                    return None
                operation = operations[previous]
                guarded = _guard(operations, predecessors, previous, point, target)
                if guarded is not None:
                    inputs.append((True, guarded))
                elif operation.opcode in ("CALL", "CALLIND", "CALLOTHER", "STORE"):
                    return None
                elif _overlaps(operation.output, target):
                    if operation.opcode != "COPY" or operation.output != target or len(operation.inputs) != 1:
                        return None
                    literal = operation.inputs[0]
                    if literal.kind is not Kind.CONSTANT or literal.byte_size != target.byte_size:
                        return None
                    number = literal.coordinate.byte_offset & ((1 << (8 * target.byte_size)) - 1)
                    inputs.append((True, (number, number)))
                else:
                    inputs.append((False, previous))
            if not inputs:
                return None
            edges[point] = inputs
            pending.append((point, True))
            for known, source in inputs:
                if not known and source not in values:
                    pending.append((source, False))
        else:
            found = [source if known else values[source] for known, source in edges[point]]
            values[point] = min(row[0] for row in found), max(row[1] for row in found)
            active.remove(point)
    return values.get(position)


def copy_read_ranges(unit, excluded_keys=()):
    """(original operation key, unique operand) -> proven unsigned hull.

    Intentionally local to an instruction's micro-CFG. Architectural state
    at instruction entry remains unknown; no ABI, ISA mnemonic, or binary
    address is a premise. All graph paths, not just a favorable branch, count.
    """
    excluded_instructions = {key.rsplit(":", 2)[0] for key in excluded_keys}
    instructions = [row for row in unit.observation.instructions
                    if has_internal_flow(row) and not row.flow.is_override
                    and f"{row.address.space_id:x}:{row.address.byte_offset:x}" not in excluded_instructions
                    and 0 < len(row.operations) <= MAX_OPERATIONS]
    if not instructions:
        return {}
    graph = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
    if graph.unsupported:
        return {}
    wanted = {row.address for row in instructions}
    by_instruction = {}
    for block in graph.blocks:
        step()
        if block.instruction in wanted:
            by_instruction.setdefault(block.instruction, {})[block.key] = block
    found = {}
    for instruction in instructions:
        step()
        operations = instruction.operations
        blocks = by_instruction.get(instruction.address, {})
        predecessors = {}
        for block in blocks.values():
            if block.start == 0:
                predecessors.setdefault(0, set()).add(None)
            for ordinal in range(block.start + 1, block.stop):
                predecessors.setdefault(ordinal, set()).add(ordinal - 1)
            for successor in block.successors:
                if successor in blocks:
                    predecessors.setdefault(blocks[successor].start, set()).add(block.stop - 1)
        predecessors = {key: tuple(sorted(rows, key=lambda value: -1 if value is None else value))
                        for key, rows in predecessors.items()}
        for ordinal, operation in enumerate(operations):
            if ordinal not in predecessors or operation.opcode != "COPY" or operation.output is None \
                    or len(operation.inputs) != 1:
                continue
            value = operation.inputs[0]
            if value.kind is not Kind.UNIQUE or operation.output.byte_size != value.byte_size:
                continue
            bound = _bound(operations, predecessors, ordinal, value)
            if bound is not None:
                key = f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}:{ordinal}:COPY"
                found[key, value] = bound
    return found
