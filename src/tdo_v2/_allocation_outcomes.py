"""One query-local resize outcome, using original SSA result and CFG edges.

This never makes a CALL effect unconditionally preserving. The successful
old/new epoch choice and copied content lineage remain separate obligations.
"""
from dataclasses import dataclass

from ._load_identity import definition_identity
from .memory_contracts import MemoryDefinitionKind
from .resource_limits import step
from .span_geometry import StorageObjectKind


@dataclass(frozen=True, slots=True)
class ResizeFailure:
    call: str
    query: str
    guard: str
    definitions: tuple
    failure_edge: tuple
    success_edge: tuple
    size: int
    contract: str
    requires: tuple


@dataclass(frozen=True, slots=True)
class ResizeSuccess(ResizeFailure):
    """Non-NULL result on every raw path to this query, not CALL-wide."""


def _result(analysis, key, value, active, witnesses):
    step()
    span = analysis.span(value)
    if span is None or span.size != 8:
        return None
    identifier = analysis.read_definition(key, span)
    if identifier is None or identifier in active:
        return None
    definition = analysis.ssa.definitions[identifier]
    if definition.kind is not MemoryDefinitionKind.DATA_WRITE or definition.span != span:
        return None
    witnesses.append(definition_identity(definition))
    active = active | {identifier}
    origin = definition.operation_key
    if origin is None:
        return None
    call = origin.split("~", 1)[0]
    contract = analysis.contracts.get(call)
    if "~" in origin and contract is not None and contract.kind == "resize" \
            and span == analysis.port(contract.result):
        return call
    operation = analysis.ops.get(origin)
    if operation is None:
        return None
    from ._allocation_lifetime import identity_operand
    transport = identity_operand(operation)
    if transport is not None:
        return _result(analysis, origin, transport, active, witnesses)
    if operation.opcode == "STORE" and operation.inputs[2].byte_size == 8:
        return _result(analysis, origin, operation.inputs[2], active, witnesses)
    if operation.opcode == "LOAD" and operation.output.byte_size == 8:
        reads = [row for row in analysis.reads.get(analysis.actions.get(origin), ())
                 if row.span.object_id.kind in (StorageObjectKind.FUNCTION_RELATIVE, StorageObjectKind.ADDRESS_SPACE)]
        if len(reads) == 1 and reads[0].span.size == 8:
            # Reuse the same original full-read validation, not a projected
            # address or a read whose alias/CALL debt was merely ignored.
            return _memory_result(analysis, origin, reads[0].span, active, witnesses)
    return None


def _memory_result(analysis, key, span, active, witnesses):
    step()
    identifier = analysis.read_definition(key, span)
    if identifier is None or identifier in active:
        return None
    definition = analysis.ssa.definitions[identifier]
    operation = analysis.ops.get(definition.operation_key)
    if definition.kind is MemoryDefinitionKind.DATA_WRITE and definition.span == span \
            and operation is not None and operation.opcode == "STORE" and operation.inputs[2].byte_size == 8:
        witnesses.append(definition_identity(definition))
        return _result(analysis, definition.operation_key, operation.inputs[2], active | {identifier}, witnesses)
    return None


def _guard(analysis, key, value, active, witnesses):
    step()
    from ._scope_contracts import VarnodeKindCode
    span = analysis.span(value)
    identifier = None if span is None else analysis.read_definition(key, span)
    if identifier is None or identifier in active:
        return None
    definition = analysis.ssa.definitions[identifier]
    operation = analysis.ops.get(definition.operation_key)
    if definition.kind is not MemoryDefinitionKind.DATA_WRITE or definition.span != span \
            or operation is None or operation.output is None or analysis.span(operation.output) != span:
        return None
    witnesses.append(definition_identity(definition))
    if operation.opcode in ("COPY", "BOOL_NEGATE"):
        result = _guard(analysis, definition.operation_key, operation.inputs[0], active | {identifier}, witnesses)
        return None if result is None else (result[0], not result[1] if operation.opcode == "BOOL_NEGATE" else result[1])
    if operation.opcode in ("INT_EQUAL", "INT_NOTEQUAL"):
        for ordinal, operand in enumerate(operation.inputs):
            if operand.kind is VarnodeKindCode.CONSTANT and operand.coordinate.byte_offset == 0 \
                    and all(part.byte_size == 8 for part in operation.inputs):
                call = _result(analysis, definition.operation_key, operation.inputs[1 - ordinal], frozenset(), witnesses)
                if call is not None:
                    return call, operation.opcode == "INT_NOTEQUAL"
    return None


def failed_resize(analysis, call, point):
    """All raw paths from this single resize to the query imply result==NULL."""
    return _resize_outcome(analysis, call, point, success=False)


def successful_resize(analysis, call, point):
    """All raw paths from this single resize to the query imply result!=NULL."""
    return _resize_outcome(analysis, call, point, success=True)


def _resize_outcome(analysis, call, point, *, success):
    from ._allocation_lifetime import AllocationRef
    from ._scope_contracts import VarnodeKindCode
    cache = call, point, success
    if cache in analysis._failures:
        return analysis._failures[cache]
    contract = analysis.contracts[call]
    if point is None or point not in analysis.positions or call not in analysis.once \
            or (not success and contract.failure != "retain"):
        return False
    allocation = AllocationRef(analysis.item.key, analysis.context, call, contract.result, "single", contract.canonical_digest)
    size, used = analysis.extent(allocation)
    if size is None:  # In particular, zero-size NULL is not failure-retain.
        return False
    edges = analysis.operation_edges()

    def reaches(starts, stop=None):
        pending, seen = list(starts), set()
        while pending:
            step()
            key = pending.pop()
            if key == stop or key in seen:
                continue
            if key == point:
                return True
            seen.add(key)
            pending.extend(edges[key])
        return False

    result = False
    for key, operation in analysis.ops.items():
        step()
        if operation.opcode != "CBRANCH" or operation.inputs[0].kind is not VarnodeKindCode.ADDRESS:
            continue
        witnesses = []
        guard = _guard(analysis, key, operation.inputs[1], frozenset(), witnesses)
        if guard is None or guard[0] != call or len(edges[key]) != 2:
            continue
        block = analysis.blocks[analysis.positions[key][0]]
        destinations = list(dict.fromkeys(entry for target in block.successors if target in analysis.blocks
                        and analysis.blocks[target].instruction == operation.inputs[0].coordinate
                        for entry in analysis.block_entries(target)))
        if len(destinations) != 1:
            continue
        true = destinations[0]
        others = [successor for successor in edges[key] if successor != true]
        if true not in edges[key] or len(others) != 1:
            continue  # Epsilon arms may reconverge; neither outcome dominates.
        false = others[0]
        failure_edge, success_edge = (false, true) if guard[1] else (true, false)
        wanted, other = (success_edge, failure_edge) if success else (failure_edge, success_edge)
        if not reaches(edges[call], stop=key) and reaches((wanted,)) and not reaches((other,)):
            record = ResizeSuccess if success else ResizeFailure
            result = record(call, point, key, tuple(dict.fromkeys(witnesses)),
                (key, failure_edge), (key, success_edge), size, contract.label,
                tuple(sorted(set(analysis.requires) | set(used) | {contract.label})))
            break
    analysis._failures[cache] = result
    return result
