"""Null tests of an allocator's result (docs 25.79): which operations run only
on the path where a CBRANCH proved the call's result row non-null.

A register-only chain over exact SSA definitions -- no memory read in it, so
no debt, no provisional copy, and no window can prove its own guard:
CBRANCH condition <- COPY / BOOL_NEGATE <- INT_EQUAL | INT_NOTEQUAL (x, 0) at
pointer width <- x through COPY / INT_AND (x, x) / INT_OR (x, x) / INT_ADD |
INT_SUB (x, 0) <- the call's result row. The branch needs two distinct
successors and an address target; the non-null successor S is not the entry
and its only predecessor is the branch block; an operation is guarded when S
dominates its block (as ``_allocation_outcomes._guard`` / ``_resize_outcome``).
"No debt" on the chain holds after ``subtract_copy_clobbers`` (``clobbered``:
the call-clobber reads left): a chain across a call rests on that existing,
conditional mechanism.
"""

from ._scope_contracts import VarnodeKindCode
from .memory_contracts import MemoryDefinitionKind
from .resource_limits import step
from .span_geometry import StorageObjectKind


def null_guarded(effect_unit, observation, memory_ssa, context, rows, clobbered, pointer_bytes: int) -> dict:
    """``rows``: result row keys to guard; ``clobbered``: operation keys with
    call-clobber debt. -> {row key: frozenset(operation keys guarded)}."""
    from ._sparse_dataflow import DominatorGraph
    from .relative_memory import _storage_ref
    from .model import ResolvedStorage
    from .storage import _resolve_validated_storage

    if not rows:
        return {}
    actions = {row.operation_key: index for index, row in enumerate(memory_ssa.actions)}
    reads: dict = {}
    for row in memory_ssa.reads:
        reads.setdefault(row.action_id, []).append(row)
    operations = {}
    for instruction in observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            key = f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}:{ordinal}:{operation.opcode}"
            operations[key] = operation

    def span_of(varnode):
        """Registers and temporaries only: a memory operand is no part of a
        guard chain (another write may change it)."""
        found = _resolve_validated_storage(_storage_ref(varnode), context)
        if type(found) is not ResolvedStorage or found.span.object_id.kind not in (
                StorageObjectKind.REGISTER_FILE, StorageObjectKind.FUNCTION_UNIQUE):
            return None
        return found.span

    def definition_of(key, varnode):
        """The single exact definition a register / temporary read at ``key`` sees."""
        span = span_of(varnode)
        if span is None or key in clobbered:
            return None
        found = [row for row in reads.get(actions.get(key), ()) if row.span == span]
        if not found or any(row.fragments != found[0].fragments for row in found) \
                or len(found[0].fragments) != 1 or found[0].fragments[0].span != span \
                or len(found[0].fragments[0].definition_ids) != 1:
            return None
        definition = memory_ssa.definitions[found[0].fragments[0].definition_ids[0]]
        if definition.kind is not MemoryDefinitionKind.DATA_WRITE or definition.span != span \
                or definition.operation_key is None:
            return None
        return definition

    def value_row(key, varnode, depth=0):
        """The guarded result row ``varnode`` at ``key`` is an exact copy of."""
        step()
        if depth > 16 or varnode.byte_size != pointer_bytes:
            return None
        definition = definition_of(key, varnode)
        if definition is None:
            return None
        origin = definition.operation_key
        if origin in rows:
            return origin
        operation = operations.get(origin)
        if operation is None or operation.output is None or operation.output.byte_size != pointer_bytes:
            return None
        if operation.opcode == "COPY":
            return value_row(origin, operation.inputs[0], depth + 1)
        if operation.opcode in ("INT_AND", "INT_OR") and len(operation.inputs) == 2 \
                and operation.inputs[0] == operation.inputs[1]:
            return value_row(origin, operation.inputs[0], depth + 1)
        if operation.opcode in ("INT_ADD", "INT_SUB") and len(operation.inputs) == 2:
            for ordinal, operand in enumerate(operation.inputs):
                if operand.kind is VarnodeKindCode.CONSTANT and operand.coordinate.byte_offset == 0 \
                        and (ordinal == 1 or operation.opcode == "INT_ADD"):
                    return value_row(origin, operation.inputs[1 - ordinal], depth + 1)
        return None

    def condition(key, varnode, negated=False, depth=0):
        """(row, True when the condition holding means the row is non-null)."""
        step()
        if depth > 16:
            return None
        definition = definition_of(key, varnode)
        if definition is None:
            return None
        origin = definition.operation_key
        operation = operations.get(origin)
        if operation is None:
            return None
        if operation.opcode in ("COPY", "BOOL_NEGATE") and len(operation.inputs) == 1:
            return condition(origin, operation.inputs[0], negated ^ (operation.opcode == "BOOL_NEGATE"), depth + 1)
        if operation.opcode in ("INT_EQUAL", "INT_NOTEQUAL") and len(operation.inputs) == 2:
            for ordinal, operand in enumerate(operation.inputs):
                if operand.kind is VarnodeKindCode.CONSTANT and operand.coordinate.byte_offset == 0 \
                        and operand.byte_size == pointer_bytes:
                    row = value_row(origin, operation.inputs[1 - ordinal])
                    if row is not None:
                        return row, (operation.opcode == "INT_NOTEQUAL") ^ negated
        return None

    blocks = {block.key: block for block in effect_unit.blocks}
    successors: dict = {key: [] for key in blocks}
    for block in effect_unit.blocks:
        for source in set(block.predecessors):
            if source in successors:
                successors[source].append(block.key)
    graph = DominatorGraph(effect_unit.entry_block_key, {key: block.predecessors for key, block in blocks.items()})
    found: dict = {}
    for block in effect_unit.blocks:
        for effect in block.effects:
            step()
            operation = operations.get(effect.operation_key)
            if operation is None or operation.opcode != "CBRANCH" or len(operation.inputs) != 2                     or effect is not block.effects[-1]:
                continue   # (the block's decision only: a CBRANCH before another branch decides no edge alone)
            target = operation.inputs[0]
            if target.kind is VarnodeKindCode.CONSTANT:
                continue   # (a p-code relative branch)
            taken = f"{target.coordinate.space_id:x}:{target.coordinate.byte_offset:x}"
            outs = sorted(set(successors.get(block.key, ())))
            if len(outs) != 2 or taken not in outs:
                continue
            guard = condition(effect.operation_key, operation.inputs[1])
            if guard is None:
                continue
            row, taken_is_nonnull = guard
            nonnull = taken if taken_is_nonnull else next(item for item in outs if item != taken)
            if nonnull == effect_unit.entry_block_key or set(blocks[nonnull].predecessors) != {block.key} \
                    or nonnull not in graph.reachable:
                continue
            for other in effect_unit.blocks:
                if other.key == nonnull or (other.key in graph.reachable and graph._dominates(nonnull, other.key)):
                    found.setdefault(row, set()).update(item.operation_key for item in other.effects)
    return {row: frozenset(keys) for row, keys in found.items()}
