"""Expose proven physical bindings as a query graph over original SSA nodes.

No candidate-only or unknown alias is an edge here. The receipt is produced
by the binder's checked current-STORE path, never reconstructed from source
labels. The original normalized graph and debts stay unchanged.
"""
from __future__ import annotations

from ..boundary import BoundaryKind
from ..resource_limits import step


def _span(span):
    obj = span.object_id
    return {"object": {"kind": str(obj.kind), "scope": obj.scope.digest.hex(), "space": obj.space_key},
            "start": span.start, "size": span.size}


def physical_binding_graph(analysis, rows, label, occurrence):
    graph = analysis.normalized.dependencies
    definitions = analysis.normalized.memory_ssa.definitions
    bindings = analysis.normalized.memory_graph
    definition_of = {node: index for index, node in enumerate(bindings.definition_nodes)}
    nodes, edges, proofs = {}, [], []
    for row in rows:
        if row.kind is not BoundaryKind.SINK or row.label != label or row.occurrence_ordinal != occurrence:
            continue
        for receipt in row.binding_receipts:
            step()
            identifier = len(proofs)
            source_definition = definition_of.get(row.node)
            store_node = graph.node_for_key("op:" + receipt.store_operation)
            consumer_node = graph.node_for_key("op:" + receipt.consuming_operation)
            if (source_definition is None or store_node is None or consumer_node is None
                    or not definitions[source_definition].span.contains(receipt.source_span)
                    or row.node not in graph.backward_reachable((store_node,))):
                raise ValueError("physical binding proof lost its original SSA graph authority")
            for node in (row.node, store_node, consumer_node):
                record = graph.node(node)
                nodes[f"ssa:{node}"] = {"id": f"ssa:{node}", "original_node": node,
                                      "key": record.key, "kind": str(record.kind)}
            demand = f"physical-demand:{identifier}"
            nodes[demand] = {"id": demand, "kind": "physical_memory_demand", "label": label,
                             "space": receipt.address_space_id, "root_definition": receipt.target_root_definition,
                             "root_span": _span(receipt.target_root_span), "offset": receipt.target_offset,
                             "width": receipt.byte_size, "before": receipt.consuming_operation}
            edges.extend((
                {"source": f"ssa:{row.node}", "target": f"ssa:{store_node}", "kind": "stored_value_bytes",
                 "source_span": _span(receipt.source_span),
                 "store_byte_offset": receipt.target_offset - receipt.store_offset, "width": receipt.byte_size,
                 "proof": identifier},
                {"source": f"ssa:{store_node}", "target": demand, "kind": "current_memory_bytes", "proof": identifier},
                {"source": demand, "target": f"ssa:{consumer_node}", "kind": "physical_consumption", "proof": identifier},
            ))
            proofs.append({"store": receipt.store_operation, "consumer": receipt.consuming_operation,
                           "before_position": receipt.before_position, "store_width": receipt.store_width,
                           "store_offset": receipt.store_offset,
                           "source_definition": source_definition,
                           "checks": ["store-dominates-consumer", "same-affine-root",
                                      "byte-range-contained", "source-definition-current",
                                      "no-intervening-call-or-possibly-overlapping-write"],
                           "intervening_operations": list(receipt.intervening_operations)})
    return ({} if not proofs else {"contract": "proven-physical-binding-graph", "version": 1,
                                   "edge_direction": "dependency_to_consumer", "candidate_only": False,
                                   "nodes": list(nodes.values()), "edges": edges, "proofs": proofs})
