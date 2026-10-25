"""Project an architect-owned conditional byte transfer into a diagnostic record.

The record keeps the original writer expression and the transfer's CALL,
branch and contract provenance.  It is deliberately not a numeric COPY: the
success branch and external contract are obligations of the original run.
"""

from collections import Counter

from .graph_contracts import EdgeKind, EdgeRecord, NodeKind
from .memory_contracts import MemoryDefinitionKind
from .model import ByteSpan


def _graph_ref(graph, identifier):
    row = graph.node(identifier)
    return {"id": identifier, "key": row.key}


def _result_definition(row):
    """JSON-safe original full-width result-definition witness, if present."""
    if type(row) is not tuple or len(row) != 5 or type(row[4]) is not ByteSpan \
            or type(row[0]) is not MemoryDefinitionKind:
        raise ValueError("transfer result definition is not original SSA evidence")
    kind, operation, ordinal, block, span = row
    return {"kind": kind.value, "operation": operation, "write_ordinal": ordinal,
            "block": block, "span": list(span.canonical_key)}


def _edge(edge):
    if type(edge) is not tuple or len(edge) != 2 or any(type(value) is not str for value in edge):
        raise ValueError("transfer outcome edge is not an original CFG edge")
    return list(edge)


def transfer_part(builder, read, fragment, depth):
    """Return one exact graph-owned transfer PartRef, or None for an ordinary read."""
    if len(fragment.definition_ids) != 1:
        return None
    definition_id = fragment.definition_ids[0]
    identity = definition_id, read.action_id, fragment.span
    node = builder.index.transfer_node.get(identity)
    if node is None:
        return None
    transfer = builder.index.transfer_of[node]
    if identity != (transfer.definition_id, transfer.action_id, transfer.span):
        raise ValueError("transfer binding changed its exact SSA fragment")
    graph, bindings, ssa = builder.graph, builder.normalized.memory_graph, builder.ssa
    source = bindings.definition_nodes[definition_id]
    reader = bindings.action_nodes[read.action_id]
    action_key = ssa.actions[read.action_id].operation_key
    call = graph.node_for_key("op:" + transfer.call)
    guard = graph.node_for_key("op:" + transfer.guard)
    from .memory_graph import _transfer_node_record

    namespace = (f"memory-v{ssa.contract_version}:{ssa.function_scope.digest.hex()}:"
                 f"{ssa.unit_digest.hex()}")
    ordinal = bindings.transfer_nodes.index(node)
    if call is None or guard is None \
            or graph.node(node) != _transfer_node_record(namespace, ordinal, transfer) \
            or graph.node(source).key != f"memory:{namespace}:definition:{definition_id}" \
            or any(graph.node(item).kind is not NodeKind.OPERATION or graph.node(item).key != "op:" + key
                   for item, key in ((reader, action_key), (call, transfer.call), (guard, transfer.guard))):
        raise ValueError("transfer graph owner or operation is missing")
    expected_in = Counter((
        (source, node, EdgeRecord(EdgeKind.MEMORY_TRANSFER, operation=action_key, span=fragment.span)),
        (call, node, EdgeRecord(EdgeKind.MEMORY_TRANSFER, operation=transfer.call, span=fragment.span)),
        (guard, node, EdgeRecord(EdgeKind.CONTROL_DEPENDENCE, operation=transfer.guard, span=fragment.span)),
    ))
    expected_out = Counter(((node, reader, EdgeRecord(
        EdgeKind.MEMORY_READ, operation=action_key, span=fragment.span)),))
    if Counter(graph.in_edges(node)) != expected_in or Counter(graph.out_edges(node)) != expected_out:
        raise ValueError("transfer record does not match graph-owned topology")
    if node in builder.id_of:
        return builder.id_of[node]
    if depth > builder.limits.depth:
        return builder._cut(graph.node(node).key, "depth")
    if builder._unexplored(node):
        return builder._cut(graph.node(node).key, "demand budget", builder._demand_text(node))

    success = getattr(transfer, "success_edge", ())
    failure = getattr(transfer, "failure_edge", ())
    result_definitions = getattr(transfer, "result_definitions", ())
    if bool(success) != bool(failure) or bool(success) != bool(result_definitions):
        raise ValueError("transfer success provenance must be complete or absent")
    record = builder._new(node, {
        "kind": "memory_transfer", "size": fragment.span.size,
        "span": list(fragment.span.canonical_key), "source_definition": definition_id,
        "source_operation": ssa.definitions[definition_id].operation_key,
        "reader": action_key, "action_id": read.action_id,
        "call": transfer.call, "guard": transfer.guard,
        "contract": transfer.contract, "requires": list(transfer.requires),
        "success_edge": _edge(success) if success else [],
        "failure_edge": _edge(failure) if failure else [],
        "result_definitions": [_result_definition(item) for item in result_definitions],
        "graph_nodes": {"source": _graph_ref(graph, source),
                        "transfer": _graph_ref(graph, node),
                        "reader": _graph_ref(graph, reader),
                        "call": _graph_ref(graph, call),
                        "guard": _graph_ref(graph, guard)},
        "parts": [],
    })
    builder.expanding.add(node)
    try:
        produced, base, loop = builder._definition_guarded(source, depth + 1)
        definition = ssa.definitions[definition_id]
        start = fragment.span.start - definition.span.start + base
        part = builder._named({"node": produced, "bytes": [start, start + fragment.span.size],
                               "at": [0, fragment.span.size]}, definition)
        if loop:
            part["loop"] = True
        record["parts"].append(part)
        builder._edge()
    finally:
        builder.expanding.discard(node)
    builder._done(record)
    return record["id"]
