"""Bounded diagnostic graphs with an explicit conditional CALL-byte overlay.

The original local graph remains untouched. Only independently certified
event-to-read attachments enter the optional call-corrected view.
"""

from __future__ import annotations

from collections import deque

from ..graph import RustworkxDependencyGraph
from ..normalize import NormalizedFunction
from .configured_call_register_overlay import SHARED_STATE_PROFILE
from .configured_interprocedural_contracts import (
    ObservedCallByteReplacement, ObservedDynamicAliasReplacement,
)


MAX_EXPLANATION_NODES = 16_384
MAX_EXPLANATION_EDGES = 131_072


def root_local_explanation(
    normalized: NormalizedFunction,
    reachable_nodes: tuple[int, ...],
    root_nodes: tuple[int, ...],
    interprocedural_proof_count: int,
) -> dict[str, object]:
    """Return exact induced edges and explicit unresolved/attachment gaps."""
    if type(normalized) is not NormalizedFunction:
        raise TypeError("explanation requires an exact normalized function")
    graph = normalized.dependencies
    if type(graph) is not RustworkxDependencyGraph:
        raise TypeError("explanation requires an exact dependency graph")
    if type(interprocedural_proof_count) is not int or interprocedural_proof_count < 0:
        raise ValueError("interprocedural proof count must be nonnegative")
    if (type(reachable_nodes) is not tuple
            or any(type(node) is not int or node < 0 for node in reachable_nodes)
            or type(root_nodes) is not tuple
            or any(type(node) is not int or node < 0 for node in root_nodes)
            or len(set(root_nodes)) != len(root_nodes)):
        raise ValueError("explanation nodes and roots require unique integer IDs")
    owned = set(reachable_nodes)
    if not owned or len(owned) != len(reachable_nodes):
        raise ValueError("explanation requires unique reachable nodes")
    if not root_nodes or any(root not in owned for root in root_nodes):
        raise ValueError("explanation roots must be reachable")
    if set(graph.backward_reachable(root_nodes)) != owned:
        raise ValueError("explanation nodes do not match root-local reachability")
    if len(owned) > MAX_EXPLANATION_NODES:
        raise ValueError("explanation node budget exceeded")
    if graph.edge_count > MAX_EXPLANATION_EDGES:
        raise ValueError("explanation graph edge budget exceeded")

    edges = []
    for source, target, record in graph.weighted_edges():
        if source not in owned or target not in owned:
            continue
        edges.append({
            "source": source,
            "target": target,
            "kind": record.kind,
            "operation_key": record.operation,
            "occurrence": record.occurrence,
            "span": _span_report(record.span),
        })
        if len(edges) > MAX_EXPLANATION_EDGES:
            raise ValueError("explanation induced edge budget exceeded")

    gaps = []
    for occurrence, node in zip(
        normalized.memory_ssa.unresolved_reads,
        normalized.memory_graph.unresolved_read_nodes,
        strict=True,
    ):
        if node not in owned:
            continue
        action = normalized.memory_ssa.actions[occurrence.action_id]
        gaps.append({
            "kind": "unresolved_memory_read",
            "node": node,
            "operation_key": action.operation_key,
            "occurrence": occurrence.occurrence_ordinal,
            "width": occurrence.access.width,
            "raw_address": (
                None if occurrence.access.raw_address is None
                else occurrence.access.raw_address.stable_key
            ),
        })
    for occurrence, node in zip(
        normalized.memory_ssa.unresolved_writes,
        normalized.memory_graph.unresolved_write_nodes,
        strict=True,
    ):
        if node in owned:
            action = normalized.memory_ssa.actions[occurrence.action_id]
            gaps.append({
                "kind": "unresolved_memory_write",
                "node": node,
                "operation_key": action.operation_key,
                "occurrence": occurrence.occurrence_ordinal,
                "width": occurrence.access.width,
                "raw_address": (
                    None if occurrence.access.raw_address is None
                    else occurrence.access.raw_address.stable_key
                ),
            })
    if interprocedural_proof_count:
        gaps.append({
            "kind": "unanchored_interprocedural_proofs",
            "count": interprocedural_proof_count,
        })
    return {
        "contract": "configured_root_local_explanation",
        "version": 1,
        "status": "partial" if gaps else "local_only",
        "edge_direction": "dependency_to_consumer",
        "root_nodes": list(root_nodes),
        "node_count": len(owned),
        "edge_count": len(edges),
        "edges": edges,
        "gaps": gaps,
    }


def _span_report(span):
    if span is None:
        return None
    return {
        "object_kind": span.object_id.kind.value,
        "scope_kind": span.object_id.scope.kind.value,
        "scope_digest": span.object_id.scope.digest.hex(),
        "space_key": span.object_id.space_key,
        "start": span.start,
        "size": span.size,
    }


def conditional_call_byte_overlay(
    normalized: NormalizedFunction,
    local_explanation: dict[str, object],
    replacements: tuple[ObservedCallByteReplacement, ...],
    proof_ordinals: dict[tuple[object, ...], int],
    dynamic_aliases: tuple[ObservedDynamicAliasReplacement, ...] = (),
) -> dict[str, object]:
    """Apply only certified memory versions, retaining the original local view.

    This is a conditional report projection, never a mutation of `normalized`
    or an evaluator input. Ambiguous/malformed certificates preserve old edges.
    """
    if (type(normalized) is not NormalizedFunction
            or type(replacements) is not tuple
            or any(type(row) is not ObservedCallByteReplacement for row in replacements)
            or type(dynamic_aliases) is not tuple
            or any(type(row) is not ObservedDynamicAliasReplacement
                   for row in dynamic_aliases)
            or type(proof_ordinals) is not dict):
        raise TypeError("conditional overlay requires exact evidence")
    local_edges = local_explanation["edges"]
    roots = tuple(local_explanation["root_nodes"])
    owned = {row for row in normalized.dependencies.backward_reachable(roots)}
    original = root_local_explanation(
        normalized, tuple(sorted(owned)), roots, len(proof_ordinals)
    )
    if (local_edges != original["edges"]
            or local_explanation["node_count"] != original["node_count"]
            or local_explanation["edge_count"] != original["edge_count"]):
        raise ValueError("conditional overlay requires the exact local graph")
    gaps = []
    accepted_aliases = []
    grouped_aliases: dict[int, list[ObservedDynamicAliasReplacement]] = {}
    for row in dynamic_aliases:
        grouped_aliases.setdefault(row.load_node, []).append(row)
    for load_node, rows in sorted(grouped_aliases.items()):
        if len(rows) != 1 or load_node not in owned:
            gaps.append({"kind": "ambiguous_dynamic_alias", "load_node": load_node})
            continue
        row = rows[0]
        matches = tuple(
            occurrence for occurrence, node in zip(
                normalized.memory_ssa.unresolved_reads,
                normalized.memory_graph.unresolved_read_nodes,
                strict=True,
            )
            if node == row.unresolved_read_node
            and normalized.memory_ssa.actions[occurrence.action_id].operation_key
            == row.load_operation_key
            and normalized.memory_graph.action_nodes[occurrence.action_id] == row.load_node
            and occurrence.access.width == row.width
        )
        stores = tuple(
            occurrence for occurrence in normalized.memory_ssa.unresolved_writes
            if normalized.memory_ssa.actions[occurrence.action_id].operation_key
            == row.store_operation_key
            and normalized.memory_graph.action_nodes[occurrence.action_id] == row.store_node
            and occurrence.access.width == row.width
        )
        debt_edges = tuple(
            edge for edge in local_edges
            if edge["kind"] == "unresolved_read"
            and edge["source"] == row.unresolved_read_node
            and edge["target"] == row.load_node
            and edge["operation_key"] == row.load_operation_key
        )
        if len(matches) != 1 or len(stores) != 1 or len(debt_edges) != 1:
            gaps.append({"kind": "invalid_dynamic_alias", "load_node": load_node})
            continue
        accepted_aliases.append(row)

    expanded = set(owned)
    for row in accepted_aliases:
        expanded.update(normalized.dependencies.backward_reachable((row.store_node,)))
    if len(expanded) > MAX_EXPLANATION_NODES:
        raise ValueError("conditional expanded graph node budget exceeded")
    removed_debt = {
        (row.unresolved_read_node, row.load_node, row.load_operation_key)
        for row in accepted_aliases
    }
    edges = []
    for source, target, record in normalized.dependencies.weighted_edges():
        if source not in expanded or target not in expanded:
            continue
        if (record.kind == "unresolved_read"
                and (source, target, record.operation) in removed_debt):
            continue
        edges.append({
            "source": source, "target": target, "kind": record.kind,
            "operation_key": record.operation,
            "occurrence": record.occurrence, "span": _span_report(record.span),
        })
    for row in accepted_aliases:
        edges.append({
            "source": row.store_node, "target": row.load_node,
            "kind": "conditional_dynamic_memory_transfer",
            "operation_key": row.load_operation_key,
            "occurrence": None, "span": None,
        })
    if len(edges) > MAX_EXPLANATION_EDGES:
        raise ValueError("conditional expanded graph edge budget exceeded")
    slots: dict[tuple[int, tuple[object, ...]], list[ObservedCallByteReplacement]] = {}
    for row in replacements:
        slots.setdefault((row.reader_node, row.read_span.canonical_key), []).append(row)
    suppress = set()
    accepted = []
    for (reader_node, _), rows in sorted(slots.items()):
        transfers = {
            (row.proof.caller_scope_digest,
             row.proof.call_operation_key,
             row.proof.callee_entry,
             row.proof.callee_scope_digest,
             row.proof.callee_write_operation_key,
             row.proof.pointer_dereferences,
             row.reader_operation_key)
            for row in rows
        }
        target_spans = sorted(
            (row.proof.target_span for row in rows),
            key=lambda span: (span.size, span.canonical_key),
        )
        nested_targets = all(
            containing.contains(contained)
            for contained, containing in zip(target_spans, target_spans[1:])
        )
        expected_nodes = {row.superseded_definition_nodes for row in rows}
        if (len(transfers) != 1 or not nested_targets
                or len(expected_nodes) != 1
                or reader_node not in expanded):
            gaps.append({"kind": "ambiguous_call_byte_replacement", "reader_node": reader_node})
            continue
        example = rows[0]
        span_key = _reported_span_key(_span_report(example.read_span))
        expected = {
            (node, reader_node, example.reader_operation_key,
             span_key)
            for node in example.superseded_definition_nodes
        }
        matched_rows = [
            (edge["source"], edge["target"], edge["operation_key"],
             span_key)
            for edge in edges
            if edge["kind"] == "memory_read"
            and edge["source"] in example.superseded_definition_nodes
            and edge["target"] == reader_node
            and edge["operation_key"] == example.reader_operation_key
            and edge["span"] == _span_report(example.read_span)
        ]
        if set(matched_rows) != expected or len(matched_rows) != len(expected):
            gaps.append({"kind": "missing_stale_edge", "reader_node": reader_node})
            continue
        if any(row.proof.canonical_key not in proof_ordinals for row in rows):
            gaps.append({"kind": "missing_origin_proof", "reader_node": reader_node})
            continue
        suppress.update(expected)
        accepted.extend(rows)

    remaining_edges = [
        edge for edge in edges
        if not (
            edge["kind"] == "memory_read"
            and edge["span"] is not None
            and (
                edge["source"], edge["target"], edge["operation_key"],
                _reported_span_key(edge["span"])
            ) in suppress
        )
    ]
    predecessors: dict[int, set[int]] = {}
    successors: dict[int, set[int]] = {}
    for edge in remaining_edges:
        predecessors.setdefault(edge["target"], set()).add(edge["source"])
        successors.setdefault(edge["source"], set()).add(edge["target"])
    reached = set(roots)
    pending = list(roots)
    while pending:
        node = pending.pop()
        for predecessor in predecessors.get(node, ()):
            if predecessor not in reached:
                reached.add(predecessor)
                pending.append(predecessor)
    attached = []
    for row in sorted(set(accepted), key=lambda item: item.canonical_key):
        path = _shortest_path_to_root(row.reader_node, roots, successors)
        if path is None or row.reader_node not in reached:
            gaps.append({"kind": "detached_call_byte_reader", "reader_node": row.reader_node})
            continue
        attached.append({
            "proof_ordinal": proof_ordinals[row.proof.canonical_key],
            "reader_operation_key": row.reader_operation_key,
            "reader_node": row.reader_node,
            "read_span": _span_report(row.read_span),
            "superseded_definition_nodes": list(row.superseded_definition_nodes),
            "reader_to_root_path": path,
        })
    attached_ordinals = {row["proof_ordinal"] for row in attached}
    unanchored = sorted(set(proof_ordinals.values()) - attached_ordinals)
    debt_nodes = set(normalized.memory_graph.unresolved_read_nodes)
    debt_nodes.update(normalized.memory_graph.unresolved_write_nodes)
    remaining_debt = sorted(debt_nodes & reached)
    return {
        "contract": "conditional_observed_call_byte_explanation",
        "version": 1,
        "premise": SHARED_STATE_PROFILE,
        "status": (
            "partial" if gaps or unanchored or remaining_debt else
            "dynamic_call_corrected_local" if accepted_aliases and attached else
            "dynamic_corrected_local" if accepted_aliases else
            "call_corrected_local" if attached else "local_only"
        ),
        "root_nodes": list(roots),
        "reachable_nodes": sorted(reached),
        "edges": [edge for edge in remaining_edges
                  if edge["source"] in reached and edge["target"] in reached],
        "suppressed_stale_edge_count": len(edges) - len(remaining_edges),
        "suppressed_unresolved_read_count": len(accepted_aliases),
        "certified_dynamic_aliases": [
            {
                "store_operation_key": row.store_operation_key,
                "load_operation_key": row.load_operation_key,
                "store_node": row.store_node,
                "load_node": row.load_node,
                "unresolved_read_node": row.unresolved_read_node,
                "width": row.width,
                "relative_offsets": list(row.relative_offsets),
            }
            for row in accepted_aliases
        ],
        "attached_proofs": attached,
        "unanchored_proof_ordinals": unanchored,
        "remaining_memory_debt_nodes": remaining_debt,
        "no_longer_sink_reachable_memory_debt_nodes": sorted((debt_nodes & owned) - reached),
        "gaps": gaps,
    }


def _reported_span_key(row: dict[str, object]) -> tuple[object, ...]:
    return (
        row["object_kind"], row["scope_kind"],
        row["scope_digest"], row["space_key"],
        row["start"], row["size"],
    )


def _shortest_path_to_root(start, roots, successors):
    pending = deque([(start, [start])])
    seen = {start}
    while pending:
        node, path = pending.popleft()
        if node in roots:
            return path
        for successor in sorted(successors.get(node, ())):
            if successor not in seen:
                seen.add(successor)
                pending.append((successor, path + [successor]))
    return None
