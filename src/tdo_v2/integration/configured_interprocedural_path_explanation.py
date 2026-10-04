"""Bounded, scope-explicit serialization of conditional source paths."""

from __future__ import annotations

from collections import deque
import json
from types import MappingProxyType

from ..call_contracts import DirectCallTarget
from ..boundary import BoundaryKind
from ..call_seeds import _operation_key
from ..memory_contracts import MemoryDefinitionKind
from ..model import ResolvedStorage, StorageObjectKind
from ..storage import _resolve_validated_storage
from .configured_call_byte_explanation import (
    certify_call_byte_replacement, certify_call_byte_cover_replacement,
)
from .configured_call_memory_read_bridge import (
    MemoryReadBridgeLimits, MemoryReadBridgeStatus,
    certify_call_memory_read_bridge, certify_local_call_memory_preservation,
    certify_call_memory_egress,
    certify_inner_source_memory_egress,
    certify_descendant_register_egress, _descendant_raw_output, _PriorReplay, _SavedValues, _Gap,
    _prepay_view_control, _prepay_graph_edges,
)
from .configured_call_register_overlay import SHARED_STATE_PROFILE
from .configured_explanation_graph import _span_report
from .configured_function_view import _FunctionView
from .configured_dynamic_alias_explanation import finite_index_transport_claim
from .configured_interprocedural_contracts import (
    ConfiguredFunctionAnalysis, InterproceduralOriginProof,
    InterproceduralTransferProof, ObservedCallByteReplacement,
)
from .configured_interprocedural_records import WriteEvent
from .configured_value_domain import storage_ref
from .configured_path_wire import wire


MAX_SEGMENT_NODES = 4096
MAX_SEGMENT_EDGES = 32768
MAX_SEGMENT_LENGTH = 256
MAX_ENTRY_CANDIDATES = 128
MAX_PRIOR_READS = 512
MAX_PRIOR_COMBINATIONS = 4096
MAX_CALLER_PRESERVATION_WORK = 100000


class _PreservationWorkGap(Exception):
    pass


class _CallerPreservationContext:
    """One admitted body inventory and immutable outcomes for one request."""

    def __init__(self, analyses_by_entry, maximum):
        self.maximum, self.used, self.cache = maximum, 0, {}
        self.nested_search_cache, self.nested_graph_indices = {}, {}
        self.charge_state_scans = False
        self.leaves, self.inventory_key = (), ()
        inventory = []
        seen = set()
        for entry, analysis in analyses_by_entry.items():
            self.count()
            if type(analysis) is not ConfiguredFunctionAnalysis:
                continue
            if analysis.entry != entry or analysis.entry in seen:
                raise _PreservationWorkGap("caller_preservation_inventory_invalid")
            seen.add(analysis.entry)
            inventory.append(analysis)
        inventory.sort(key=lambda row: (row.entry.space_id, row.entry.byte_offset))
        self.leaves = tuple(inventory)
        self.inventory_key = tuple((row.evidence.unit.scopes.function.scope.digest,
                                    row.evidence.unit.scopes.function.observation_digest)
                                   for row in self.leaves)

    def count(self, amount=1):
        if type(amount) is not int or amount <= 0:
            raise ValueError("preservation work requires a positive exact count")
        self.used += amount
        if self.used > self.maximum:
            raise _PreservationWorkGap("caller_preservation_budget_exhausted")

    def _between_calls(self, caller, start_key, read_key):
        calls = []
        for seed in caller.analysis.evidence.seeds.callsites:
            self.count()
            if self.charge_state_scans:
                self.count(1 + 2 * len(caller.normalized.memory_unit.blocks))
            key = seed.operation_key
            if (key != read_key and caller.may_precede(key, read_key)
                    and (start_key is None or caller.may_precede(start_key, key))):
                calls.append(key)
        return tuple(calls)

    def register_interval(self, caller, start_key, read_key, span):
        """Register CALL intervals need an exact continuation proof of their own."""
        if self._between_calls(caller, start_key, read_key):
            return "intervening_call_state_unknown"
        return None

    def segment(self, caller, segment):
        definitions = {}
        for index, definition in enumerate(caller.memory.definitions):
            self.count()
            definitions[caller.memory_graph.definition_nodes[index]] = definition
        for link in segment["edges"]:
            for edge in link["alternatives"]:
                self.count()
                if edge["kind"] != "memory_read":
                    continue
                definition = definitions.get(edge["source"])
                if definition is None or edge["span"] is None:
                    return "intervening_call_state_unknown"
                calls = self._between_calls(caller, definition.operation_key, edge["operation_key"])
                if not calls:
                    continue
                if definition.span.object_id.kind is StorageObjectKind.REGISTER_FILE:
                    gap = self.register_interval(caller, definition.operation_key,
                                                 edge["operation_key"], definition.span)
                    if gap is not None:
                        return gap
                    continue
                if definition.kind is not MemoryDefinitionKind.DATA_WRITE or definition.operation_key is None:
                    return "intervening_call_state_unknown"
                if self.charge_state_scans:
                    return "descendant_source_memory_replay_unavailable"
                gap = self.memory_edge(caller, definition, edge)
                if gap is not None:
                    return gap
        return None

    def memory_edge(self, caller, definition, edge):
        # The budget applicable to a cached result is part of its identity.
        remaining = self.maximum - self.used
        effective_steps = min(16384, remaining)
        key = (caller.scope_digest, caller.analysis.evidence.unit.scopes.function.observation_digest,
               self.inventory_key, edge["source"], edge["target"], definition.operation_key,
               definition.span, edge["operation_key"], tuple(sorted(edge["span"].items())), effective_steps)
        result = self.cache.get(key)
        if result is None:
            if remaining <= 0:
                raise _PreservationWorkGap("caller_preservation_budget_exhausted")
            result = certify_local_call_memory_preservation(
                caller.analysis, definition.operation_key, edge["operation_key"],
                leaf_analyses=self.leaves, limits=MemoryReadBridgeLimits(steps=effective_steps),
            )
            self.used += result.work_units
            self.cache[key] = result
        if self.used > self.maximum or "bridge_budget_exhausted" in result.gaps:
            raise _PreservationWorkGap("caller_preservation_budget_exhausted")
        if result.status is not MemoryReadBridgeStatus.VERIFIED_MAY:
            return result.gaps[0] if result.gaps else "intervening_call_state_unknown"
        witness = result.witness
        if (witness.source_definition_node != edge["source"]
                or witness.target_load_action_node != edge["target"]
                or witness.source_span != definition.span
                or _span_report(witness.read_span) != edge["span"]):
            return "caller_preservation_edge_identity_mismatch"
        return None

    def memory_bridge(self, caller, callee, call_key, definition_id, action_id, source, *, prefix_mode):
        definition = caller.memory.definitions[definition_id]
        load_key = callee.memory.actions[action_id].operation_key
        load = callee.operation(load_key)
        remaining = self.maximum - self.used
        effective_steps = min(16384, remaining)
        key = ("bridge", prefix_mode, caller.scope_digest,
               caller.analysis.evidence.unit.scopes.function.observation_digest, callee.scope_digest,
               callee.analysis.evidence.unit.scopes.function.observation_digest, self.inventory_key,
               None if prefix_mode else (source.evidence.unit.scopes.function.scope.digest,
                                         source.evidence.unit.scopes.function.observation_digest),
               call_key, definition.operation_key, load_key, caller.memory_graph.definition_nodes[definition_id],
               callee.memory_graph.action_nodes[action_id], definition.span,
               None if load is None or load.output is None else load.output.byte_size, effective_steps)
        result = self.cache.get(key)
        if result is None:
            if remaining <= 0:
                raise _PreservationWorkGap("caller_preservation_budget_exhausted")
            arguments = {"prefix_leaf_analyses": self.leaves} if prefix_mode else {"prior_leaf_analyses": (source,)}
            result = certify_call_memory_read_bridge(
                caller.analysis, callee.analysis, call_key, definition.operation_key, load_key,
                limits=MemoryReadBridgeLimits(steps=effective_steps), **arguments,
            )
            self.used += result.work_units
            self.cache[key] = result
        if self.used > self.maximum or "bridge_budget_exhausted" in result.gaps:
            raise _PreservationWorkGap("caller_preservation_budget_exhausted")
        return result

    def memory_egress(self, caller, callee, call_key, definition_id, action_id, *, continuation_mode=False):
        definition = callee.memory.definitions[definition_id]
        load_key = caller.memory.actions[action_id].operation_key
        remaining = self.maximum - self.used
        effective_steps = min(16384, remaining)
        key = ("egress", continuation_mode, caller.scope_digest, caller.analysis.evidence.unit.scopes.function.observation_digest,
               callee.scope_digest, callee.analysis.evidence.unit.scopes.function.observation_digest,
               self.inventory_key, self.inventory_key if continuation_mode else None,
               call_key, definition.operation_key, load_key,
               callee.memory_graph.definition_nodes[definition_id], caller.memory_graph.action_nodes[action_id],
               definition.span, caller.storage_actions[load_key].reads, effective_steps)
        result = self.cache.get(key)
        if result is None:
            if remaining <= 0:
                raise _PreservationWorkGap("caller_preservation_budget_exhausted")
            result = certify_call_memory_egress(caller.analysis, callee.analysis, call_key,
                definition.operation_key, load_key, prefix_leaf_analyses=self.leaves,
                continuation_leaf_analyses=self.leaves if continuation_mode else None,
                limits=MemoryReadBridgeLimits(steps=effective_steps))
            self.used += result.work_units
            if not continuation_mode or not any("budget_exhausted" in gap for gap in result.gaps):
                self.cache[key] = result
        if self.used > self.maximum or "bridge_budget_exhausted" in result.gaps:
            raise _PreservationWorkGap("caller_preservation_budget_exhausted")
        return result

    def descendant_egress(self, caller, wrapper, call_key, child_keys, definition_key, reader_key, operand,
                          *, charge_state_scans=False):
        if type(charge_state_scans) is not bool:
            raise TypeError("state scan charging requires an exact boolean")
        remaining = self.maximum - self.used
        effective_steps = min(16384, remaining)
        key = ("descendant", charge_state_scans, caller.scope_digest,
               caller.analysis.evidence.unit.scopes.function.observation_digest,
               wrapper.scope_digest, wrapper.analysis.evidence.unit.scopes.function.observation_digest,
               self.inventory_key, call_key, child_keys, definition_key, reader_key, operand, effective_steps)
        result = self.cache.get(key)
        if result is None:
            if remaining <= 0:
                raise _PreservationWorkGap("caller_preservation_budget_exhausted")
            result = certify_descendant_register_egress(caller.analysis, wrapper.analysis, call_key,
                child_keys, definition_key, reader_key, read_operand_index=operand,
                invocation_analyses=self.leaves, limits=MemoryReadBridgeLimits(steps=effective_steps),
                charge_state_scans=charge_state_scans)
            self.used += result.work_units
            if not any("budget_exhausted" in gap for gap in result.gaps):
                self.cache[key] = result
        if self.used > self.maximum or "bridge_budget_exhausted" in result.gaps:
            raise _PreservationWorkGap("caller_preservation_budget_exhausted")
        return result

    def inner_memory_egress(self, caller, writer, call_key, child_keys, definition_key, reader_key,
                            store_key, load_key, operand):
        self.count()
        remaining = self.maximum - self.used
        effective_steps = min(20000, remaining)
        key = ("inner_memory", 9, caller.scope_digest,
               caller.analysis.evidence.unit.scopes.function.observation_digest,
               writer.scope_digest, writer.analysis.evidence.unit.scopes.function.observation_digest,
               self.inventory_key, call_key, child_keys, definition_key, reader_key,
               store_key, load_key, operand, effective_steps)
        result = self.cache.get(key)
        if result is None:
            if effective_steps <= 0:
                raise _PreservationWorkGap("caller_preservation_budget_exhausted")
            result = certify_inner_source_memory_egress(caller.analysis, writer.analysis, call_key,
                child_keys, definition_key, reader_key, store_key, load_key, read_operand_index=operand,
                invocation_analyses=self.leaves, limits=MemoryReadBridgeLimits(steps=effective_steps))
            self.used += result.work_units
            if not any("budget_exhausted" in gap for gap in result.gaps):
                self.cache[key] = result
        if self.used > self.maximum or "bridge_budget_exhausted" in result.gaps:
            raise _PreservationWorkGap("caller_preservation_budget_exhausted")
        return result


def conditional_source_paths(
    caller: ConfiguredFunctionAnalysis,
    proofs: tuple[InterproceduralOriginProof, ...],
    replacements: tuple[ObservedCallByteReplacement, ...],
    overlay: dict[str, object],
    analyses_by_entry: dict,
    *, preservation_work_limit: int = MAX_CALLER_PRESERVATION_WORK,
    finite_index_transport: bool = False,
    finite_index_work: list | None = None,
) -> dict[str, object]:
    """Join only authentic local paths and an already certified CALL transfer."""
    if (type(caller) is not ConfiguredFunctionAnalysis
            or type(proofs) is not tuple
            or any(type(row) is not InterproceduralOriginProof for row in proofs)
            or type(replacements) is not tuple
            or any(type(row) is not ObservedCallByteReplacement
                   for row in replacements)
            or type(overlay) is not dict
            or type(analyses_by_entry) is not dict):
        raise TypeError("conditional paths require exact configured evidence")
    if (type(preservation_work_limit) is not int
            or not 0 < preservation_work_limit <= MAX_CALLER_PRESERVATION_WORK):
        raise ValueError("caller preservation work requires a positive exact bounded integer")
    if type(finite_index_transport) is not bool:
        raise TypeError("finite index publication requires an exact boolean")
    if finite_index_transport and finite_index_work is not None:
        _validate_finite_index_work(finite_index_work)
    caller_scope = caller.evidence.unit.scopes.function.scope.digest
    caller_view = _FunctionView(caller)
    attached = {}
    duplicates = set()
    for row in overlay["attached_proofs"]:
        ordinal = row["proof_ordinal"]
        if ordinal in attached:
            duplicates.add(ordinal)
        attached[ordinal] = row
    caller_edges = {}
    for edge in overlay["edges"]:
        caller_edges.setdefault((edge["source"], edge["target"]), []).append(edge)
    views = {}
    preservation = None
    preservation_gap = None
    rows = []
    for ordinal, proof in enumerate(proofs):
        gaps = []
        callee_segment = None
        transfer = None
        caller_segment = None
        prior_segments = []
        entry_transfer = None
        attachment = attached.get(ordinal)
        if ordinal in duplicates or attachment is None:
            gaps.append("unattached_call_reader")
        if proof.caller_scope_digest != caller_scope:
            gaps.append("caller_scope_mismatch")
        callee_analysis = analyses_by_entry.get(proof.callee_entry)
        if type(callee_analysis) is not ConfiguredFunctionAnalysis:
            gaps.append("callee_view_unavailable")
        else:
            try:
                if proof.callee_entry not in views:
                    views[proof.callee_entry] = _FunctionView(callee_analysis)
                callee = views[proof.callee_entry]
            except ValueError:
                callee = None
                gaps.append("callee_view_unavailable")
            if callee is not None:
                if not proof.prior_transfers:
                    callee_segment, callee_gap = _callee_segment(callee, proof)
                    if callee_gap is not None:
                        gaps.append(callee_gap)
                elif len(proof.prior_transfers) == 1:
                    try:
                        if preservation is None and preservation_gap is None:
                            preservation = _CallerPreservationContext(analyses_by_entry, preservation_work_limit)
                        if preservation_gap is not None:
                            raise _PreservationWorkGap(preservation_gap)
                        prior_segments, entry_transfer, callee_segment, chain_gap = (
                            _one_sequential_prior(
                                caller_view, callee, proof, analyses_by_entry, views, preservation,
                            )
                        )
                    except _PreservationWorkGap as error:
                        preservation_gap = str(error)
                        chain_gap = preservation_gap
                    if chain_gap is not None and preservation_gap is None:
                        try:
                            prior_segments, entry_transfer, callee_segment, memory_gap = (
                                _one_prior_memory(
                                    caller_view, callee, proof, analyses_by_entry, views, preservation,
                                )
                            )
                        except _PreservationWorkGap as error:
                            preservation_gap = memory_gap = str(error)
                            prior_segments, entry_transfer, callee_segment = [], None, None
                        if memory_gap is not None:
                            gaps.extend((chain_gap, memory_gap))
                    elif chain_gap is not None:
                        gaps.append(chain_gap)
                else:
                    gaps.append("prior_transfer_segment_unavailable")
        if callee_analysis is None and proof.prior_transfers:
            gaps.append("prior_transfer_segment_unavailable")
        if (type(callee_analysis) is ConfiguredFunctionAnalysis and proof.callee_entry in views
                and len(proof.prior_transfers) == 1 and proof.pointer_dereferences == 0
                and proof.target_span.object_id.kind is StorageObjectKind.REGISTER_FILE
                and preservation_gap is None):
            try:
                if preservation is None:
                    preservation = _CallerPreservationContext(analyses_by_entry, preservation_work_limit)
                nested_path, nested_gap = _one_prior_nested_egress(caller_view, views[proof.callee_entry],
                    proof, analyses_by_entry, views, preservation, overlay["root_nodes"])
            except _PreservationWorkGap as error:
                preservation_gap = nested_gap = str(error)
                nested_path = None
            if nested_path is not None:
                rows.append({"proof_ordinal": ordinal, "label": proof.label, "status": "complete",
                             **nested_path, "gaps": []})
                continue
            # Preserve old complete/gap wire when this function has no nested candidate.
            if nested_gap != "nested_call_chain_unavailable":
                gaps.append(nested_gap)
        if (type(callee_analysis) is ConfiguredFunctionAnalysis and proof.callee_entry in views
                and len(proof.prior_transfers) == 1
                and proof.pointer_dereferences == 0
                and proof.target_span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE
                and preservation_gap is None):
            try:
                if preservation is None:
                    preservation = _CallerPreservationContext(analyses_by_entry, preservation_work_limit)
                egress_path, egress_gap = _one_prior_memory_egress(caller_view, views[proof.callee_entry],
                    proof, analyses_by_entry, views, preservation, overlay["root_nodes"])
            except _PreservationWorkGap as error:
                preservation_gap = egress_gap = str(error)
                egress_path = None
            if egress_path is not None:
                rows.append({"proof_ordinal": ordinal, "label": proof.label, "status": "complete",
                             **egress_path, "gaps": []})
                continue
            gaps.append(egress_gap)
        if attachment is not None and ordinal not in duplicates:
            matching_replacements = tuple(
                row for row in replacements
                if (row.proof == proof
                    and row.reader_node == attachment["reader_node"]
                    and row.reader_operation_key == attachment["reader_operation_key"]
                    and _span_report(row.read_span) == attachment["read_span"])
            )
            if len(matching_replacements) != 1:
                gaps.append("call_attachment_identity_mismatch")
            reader_path = attachment["reader_to_root_path"]
            if (not reader_path
                    or attachment["reader_node"] != reader_path[0]
                    or reader_path[-1] not in overlay["root_nodes"]
                    or len(reader_path) > MAX_SEGMENT_LENGTH):
                gaps.append("invalid_caller_path")
            else:
                caller_links = _path_edges(reader_path, caller_edges)
                if caller_links is None:
                    gaps.append("missing_caller_path_edge")
                elif _has_memory_debt(caller_links):
                    gaps.append("caller_path_memory_debt")
                elif proof.caller_scope_digest == caller_scope:
                    caller_segment = {
                        "scope": caller_scope.hex(),
                        "nodes": list(reader_path),
                        "edges": caller_links,
                    }
                    if (callee_segment is not None
                            and len(matching_replacements) == 1):
                        transfer = {
                            "kind": "certified_observed_call_byte_transfer",
                            "caller_scope": caller_scope.hex(),
                            "call_operation_key": proof.call_operation_key,
                            "callee_scope": proof.callee_scope_digest.hex(),
                            "callee_write_operation_key": proof.callee_write_operation_key,
                            "source_definition_node": callee_segment["terminal_definition_node"],
                            "target_reader_node": attachment["reader_node"],
                            "target_span": _span_report(proof.target_span),
                        }
        if (gaps and not proof.prior_transfers and proof.callee_entry in views
                and preservation_gap is None):
            try:
                if preservation is None:
                    preservation = _CallerPreservationContext(analyses_by_entry, preservation_work_limit)
                covered = _direct_cover_path(caller_view, views[proof.callee_entry], proof,
                                             overlay["root_nodes"], preservation)
            except _PreservationWorkGap as error:
                preservation_gap = str(error)
                covered = None
                gaps.append(preservation_gap)
            if covered is not None:
                rows.append({"proof_ordinal": ordinal, "label": proof.label,
                             "status": "complete", **covered, "gaps": []})
                continue
        if (gaps and proof.callee_entry in views and preservation_gap is None
                and proof.pointer_dereferences == 0
                and proof.target_span.object_id.kind is StorageObjectKind.REGISTER_FILE):
            try:
                if preservation is None:
                    preservation = _CallerPreservationContext(analyses_by_entry, preservation_work_limit)
                preservation.charge_state_scans = True
                descendant_path, descendant_gap = _descendant_source_path(caller_view,
                    views[proof.callee_entry], proof, analyses_by_entry, views, preservation,
                    overlay["root_nodes"])
            except _PreservationWorkGap as error:
                preservation_gap = descendant_gap = str(error)
                descendant_path = None
            finally:
                if preservation is not None:
                    preservation.charge_state_scans = False
            if descendant_path is not None:
                rows.append({"proof_ordinal": ordinal, "label": proof.label,
                             "status": "complete", **descendant_path, "gaps": []})
                continue
            if descendant_gap != "descendant_source_unavailable":
                gaps.append(descendant_gap)
        if (gaps and proof.callee_entry in views and preservation_gap is None
                and proof.pointer_dereferences == 0
                and proof.target_span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE):
            try:
                if preservation is None:
                    preservation = _CallerPreservationContext(analyses_by_entry, preservation_work_limit)
                preservation.charge_state_scans = True
                inner_path, inner_gap = _inner_source_memory_path(caller_view, views[proof.callee_entry], proof,
                    analyses_by_entry, views, preservation, overlay["root_nodes"])
            except _PreservationWorkGap as error:
                preservation_gap = inner_gap = str(error)
                inner_path = None
            finally:
                if preservation is not None:
                    preservation.charge_state_scans = False
            if inner_path is not None:
                rows.append({"proof_ordinal": ordinal, "label": proof.label,
                             "status": "complete", **inner_path, "gaps": []})
                continue
            gaps.append(inner_gap)
        rows.append({
            "proof_ordinal": ordinal,
            "label": proof.label,
            "status": "complete" if not gaps else "gap",
            "callee": callee_segment,
            "transfer": transfer,
            "caller": caller_segment,
            "prior_segments": prior_segments,
            "entry_transfer": entry_transfer,
            "gaps": gaps,
        })
    if finite_index_transport:
        _publish_finite_index_claims(caller_view, rows, overlay, work=finite_index_work)
    return {
        "contract": "configured_conditional_segmented_source_paths",
        "version": 12 if any("finite_index_transport" in row for row in rows) else 9 if any("inner_source_memory_attachment" in row for row in rows) else 8 if any("descendant_source_attachment" in row for row in rows) else 7 if any(_has_cover_transfer(row) for row in rows) else 6 if any((row.get("transfer") or {}).get("kind") == "observed_leaf_call_memory_egress"
            and row["transfer"].get("version") == 2 and row["transfer"].get("continuation_leaf_calls")
            for row in rows) else 5 if any("nested_egress_attachment" in row for row in rows) else 4 if any("memory_egress_attachment" in row for row in rows) else 3 if any(
            type(row["entry_transfer"]) is dict
            and row["entry_transfer"].get("kind") == "observed_leaf_call_memory_read_bridge"
            for row in rows
        ) else 2,
        "premise": SHARED_STATE_PROFILE,
        "status": "partial" if any(row["gaps"] for row in rows)
                  else "complete" if rows else "no_interprocedural_sources",
        "paths": rows,
    }


def _validate_finite_index_work(work):
    if (type(work) is not list or len(work) != 2 or type(work[0]) is not int
            or not 0 <= work[0] <= 100000 or type(work[1]) is not bool):
        raise ValueError("finite publication requires an exact request work counter")


def _publish_finite_index_claims(caller_view, rows, overlay, *, work_limit=100000, work=None):
    """Prepay every index and nested collection before inspecting its members."""
    if type(work_limit) is not int or not 0 <= work_limit <= 100000:
        raise ValueError("finite publication requires an exact bounded work limit")
    if work is None:
        work = [work_limit, False]
    _validate_finite_index_work(work)
    if work[1]:
        return
    def pay(amount):
        if amount > work[0]:
            return False
        work[0] -= amount
        return True
    actions, reads = caller_view.memory.actions, caller_view.memory.reads
    if len(actions) > 2048 or not pay(len(actions) + len(reads) + len(rows)):
        return
    action_keys = {node: actions[action].operation_key
                   for action, node in enumerate(caller_view.memory_graph.action_nodes)}
    reads_by_action = {}
    for read in reads:
        if read.span.object_id.kind in (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE):
            reads_by_action.setdefault(read.action_id, []).append(read)
    roots = overlay.get("root_nodes", ())
    if len(roots) != 1 or not pay(1):
        return
    scope = caller_view.scope_digest.hex()
    for row in rows:
        if row.get("status") != "complete" or row.get("gaps") != []:
            continue
        prior = row.get("prior_segments", ())
        if not pay(3 + 4 * len(prior)):
            return
        segments = [row.get(name) for name in ("callee", "caller", "writer")]
        for part in prior:
            if type(part) is dict:
                segments.extend(part.get(name) for name in ("callee", "caller", "writer"))
        selected = None
        count = 0
        for segment in segments:
            if type(segment) is not dict:
                continue
            links = segment.get("edges", ())
            if not pay(len(links)):
                return
            for link in links:
                if type(link) is not dict:
                    continue
                alternatives = link.get("alternatives", ())
                if not pay(len(alternatives)):
                    return
                for edge in alternatives:
                    if type(edge) is dict and edge.get("kind", "").startswith("conditional_"):
                        selected = (segment, edge)
                        count += 1
        if count != 1 or selected[0].get("scope") != scope:
            continue
        if not pay(1):
            return
        # One deterministic opportunity per report, including failed attempts.
        work[1] = True
        claim = finite_index_transport_claim(caller_view, selected[1], roots[0],
            work=work, action_keys=action_keys, reads_by_action=reads_by_action)
        if claim is not None:
            row["finite_index_transport"] = claim
        return


def _has_cover_transfer(row):
    return ((row.get("transfer") or {}).get("kind") == "certified_observed_call_byte_cover_transfer"
            or any((part.get("transfer") or {}).get("kind") == "certified_observed_call_byte_cover_transfer"
                   for part in row.get("prior_segments", ())))


def _cover_source_transport(caller, source, prior, proof, read, reachable, preservation):
    if (proof.origin_entry != source.analysis.entry or proof.origin_scope_digest != source.scope_digest
            or prior.callee_entry != source.analysis.entry or prior.callee_scope_digest != source.scope_digest):
        return None
    event = WriteEvent(prior.caller_scope_digest, caller.position(prior.call_operation_key),
        prior.call_operation_key, prior.callee_entry, prior.callee_scope_digest,
        prior.callee_write_operation_key, prior.target_span, prior.pointer_dereferences, ())
    certificate = certify_call_byte_cover_replacement(caller, source, event, read, reachable,
                                                      charge=preservation.count)
    if certificate is None or certificate.original_transfer != prior:
        return None
    definition_id = certificate.source_definition_id
    definition = source.memory.definitions[definition_id]
    node = source.memory_graph.definition_nodes[definition_id]
    action = source.memory_graph.action_nodes[source.action_ids[definition.operation_key]]
    segment = _data_local_segment(source, proof.origin_node, node, preservation, charge_walk=True)
    if segment is None or preservation.segment(source, segment):
        return None
    returns = {}
    for instruction in source.observation.instructions:
        preservation.count(1 + len(instruction.operations))
        if instruction.flow is not None and instruction.flow.is_terminal and instruction.operations:
            key = _operation_key(instruction.address, len(instruction.operations) - 1,
                                 instruction.operations[-1].opcode)
            returns[source.operation_blocks[key]] = key
    exits = []
    for block, root, fragments in certificate.terminal_cover:
        preservation.count(1 + len(fragments))
        exits.append({"block_key": block, "root_node_id": root, "terminal_operation_key": returns[block],
            "fragments": [{"atom_id": i, "span": _span_report(span),
                           "definition_nodes": [source.memory_graph.definition_nodes[d] for d in ids]}
                          for i, span, ids in fragments]})
    cover = {"kind": "observed_terminal_byte_cover", "version": 1,
        "function_scope": source.scope_digest.hex(),
        "function_observation_digest": source.analysis.evidence.unit.scopes.function.observation_digest.hex(),
        "definition_node": node, "defining_action_node": action,
        "write_operation_key": definition.operation_key, "raw_write_span": _span_report(definition.span),
        "demanded_span": _span_report(certificate.demanded_span), "exits": exits}
    segment.update({"terminal_definition_node": node, "terminal_defining_action_node": action,
                    "terminal_write_operation_key": definition.operation_key,
                    "terminal_write_span": _span_report(certificate.demanded_span),
                    "terminal_write_cover": cover})
    transfer = {"kind": "certified_observed_call_byte_cover_transfer", "version": 1,
        "premise": SHARED_STATE_PROFILE, "caller_scope": caller.scope_digest.hex(),
        "callee_scope": source.scope_digest.hex(), "call_operation_key": prior.call_operation_key,
        "callee_write_operation_key": prior.callee_write_operation_key, "source_definition_node": node,
        "target_reader_node": certificate.reader_node, "hint_span": _span_report(prior.target_span),
        "demanded_span": _span_report(certificate.demanded_span),
        "original_transfer": {"caller_scope": prior.caller_scope_digest.hex(),
            "call_operation_key": prior.call_operation_key, "callee_scope": prior.callee_scope_digest.hex(),
            "callee_entry": {"space_id": prior.callee_entry.space_id, "byte_offset": prior.callee_entry.byte_offset},
            "callee_write_operation_key": prior.callee_write_operation_key,
            "target_span": _span_report(prior.target_span), "pointer_dereferences": prior.pointer_dereferences},
        "terminal_write_cover": cover, "superseded_fragments": [
            {"span": _span_report(span), "definition_nodes": list(nodes)}
            for span, nodes in certificate.superseded_fragments]}
    return segment, transfer


def _direct_cover_path(caller, source, proof, root_nodes, preservation):
    if (len(caller.memory.reads) > MAX_PRIOR_READS or len(root_nodes) > MAX_ENTRY_CANDIDATES
            or proof.pointer_dereferences != 0
            or caller.normalized.dependencies.node_count > MAX_SEGMENT_NODES
            or caller.normalized.dependencies.edge_count > MAX_SEGMENT_EDGES):
        return None
    successes = {}
    for root in root_nodes:
        preservation.count()
        preservation.count(1 + caller.normalized.dependencies.node_count + caller.normalized.dependencies.edge_count)
        reachable = frozenset(caller.normalized.dependencies.backward_reachable((root,)))
        for read in caller.memory.reads:
            preservation.count()
            if read.span.size <= proof.target_span.size or not read.span.contains(proof.target_span):
                continue
            prepared = _cover_source_transport(caller, source, proof.final_transfer, proof,
                                                read, reachable, preservation)
            if prepared is None:
                continue
            segment, transfer = prepared
            suffix = _data_local_segment(caller, transfer["target_reader_node"], root,
                                         preservation, charge_walk=True)
            if suffix is None or preservation.segment(caller, suffix):
                continue
            preservation.count(1 + len(segment["nodes"]) + len(segment["edges"])
                               + len(suffix["nodes"]) + len(suffix["edges"]))
            complete = {"callee": segment, "transfer": transfer, "caller": suffix,
                        "prior_segments": [], "entry_transfer": None}
            identity = wire(complete)
            successes[identity] = complete
            if len(successes) > 1:
                return None
    return next(iter(successes.values())) if successes else None


def _callee_segment(callee: _FunctionView, proof: InterproceduralOriginProof):
    return _transfer_segment(
        callee, proof.final_transfer, proof.origin_entry,
        proof.origin_scope_digest, proof.origin_node,
    )


def _span_subset(outer, inner):
    return (outer is not None and inner is not None
            and all(outer[key] == inner[key] for key in ("object_kind", "scope_kind", "scope_digest", "space_key"))
            and outer["start"] <= inner["start"] and inner["start"] + inner["size"] <= outer["start"] + outer["size"])


def _data_edge_allowed(view, edge):
    operation = view.operation(edge["operation_key"])
    if operation is None:
        return True
    if edge["kind"] == "value_input":
        return operation.opcode != "LOAD" and (operation.opcode != "STORE" or edge["occurrence"] == 2)
    if edge["kind"] != "memory_read":
        return True
    if operation.opcode == "LOAD":
        return edge["span"] is not None and edge["span"]["object_kind"] in {"function_relative", "address_space"}
    if operation.opcode == "STORE":
        if len(operation.inputs) != 3:
            return False
        resolved = _resolve_validated_storage(storage_ref(operation.inputs[2]),
            view.analysis.evidence.unit.scopes.resolution_context)
        return type(resolved) is ResolvedStorage and _span_subset(_span_report(resolved.span), edge["span"])
    return True


def _data_local_segment(view, start_node, target_node, preservation, first_edge=None, *, charge_walk=False):
    if charge_walk:
        return _cached_nested_data_segment(view, start_node, target_node, preservation, first_edge)
    graph = view.normalized.dependencies
    if graph.node_count > MAX_SEGMENT_NODES or graph.edge_count > MAX_SEGMENT_EDGES:
        return None
    edges, successors = {}, {}
    for source, target, record in graph.weighted_edges():
        preservation.count()
        edge = {"source": source, "target": target, "kind": record.kind, "operation_key": record.operation,
                "occurrence": record.occurrence, "span": _span_report(record.span)}
        if not _data_edge_allowed(view, edge):
            continue
        edges.setdefault((source, target), []).append(edge)
        successors.setdefault(source, set()).add(target)
    path_start = start_node if first_edge is None else first_edge["target"]
    if charge_walk:
        pending, seen, path = deque([(path_start, [path_start])]), {path_start}, None
        while pending:
            preservation.count()
            current, candidate = pending.popleft()
            if current == target_node:
                path = candidate
                break
            if len(candidate) >= MAX_SEGMENT_LENGTH:
                continue
            for following in sorted(successors.get(current, ())):
                preservation.count()
                if following not in seen:
                    seen.add(following)
                    pending.append((following, [*candidate, following]))
    else:
        path = _shortest_bounded_path(path_start, target_node, successors)
    if path is None:
        return None
    if first_edge is not None:
        if first_edge not in edges.get((start_node, path_start), ()):
            return None
        path = [start_node, *path]
    links = _path_edges(path, edges)
    if links is None or _has_memory_debt(links):
        return None
    if first_edge is not None:
        links[0] = {"source": start_node, "target": path_start, "alternatives": [first_edge]}
    return {"scope": view.scope_digest.hex(), "nodes": path, "edges": links}


def _nested_view_identity(view):
    return (view.scope_digest, view.analysis.evidence.unit.scopes.function.observation_digest,
            id(view.analysis.normalized))


def _cached_nested_data_segment(view, start, end, preservation, first):
    strict = preservation.charge_state_scans
    limits = (preservation.maximum, MAX_SEGMENT_NODES, MAX_SEGMENT_EDGES, MAX_SEGMENT_LENGTH,
              strict, preservation.inventory_key,
              min(16384, preservation.maximum - preservation.used) if strict else None)
    evidence = _nested_view_identity(view)
    key = ("data", evidence, start, end, None if first is None else wire(first), limits)
    if key in preservation.nested_search_cache:
        value = preservation.nested_search_cache[key]
        if strict and value is not None:
            preservation.count(1 + len(value) // 16)
        return None if value is None else json.loads(value)
    graph = view.normalized.dependencies
    if graph.node_count > MAX_SEGMENT_NODES or graph.edge_count > MAX_SEGMENT_EDGES:
        preservation.nested_search_cache[key] = None
        return None
    index_key = evidence, limits
    if index_key not in preservation.nested_graph_indices:
        edges, successors = {}, {}
        if strict:
            _prepay_graph_edges(graph, preservation.count)
        for source, target, record in graph.weighted_edges():
            preservation.count()
            edge = {"source": source, "target": target, "kind": record.kind, "operation_key": record.operation,
                    "occurrence": record.occurrence, "span": _span_report(record.span)}
            if _data_edge_allowed(view, edge):
                if strict:
                    _prepay_tree(preservation, edge)
                edges.setdefault((source, target), []).append(wire(edge))
                successors.setdefault(source, set()).add(target)
        if strict:
            preservation.count(1 + 2 * graph.edge_count + graph.node_count
                               + sum(len(rows) * max(1, len(rows).bit_length()) for rows in successors.values()))
        preservation.nested_graph_indices[index_key] = (
            MappingProxyType({pair: tuple(rows) for pair, rows in edges.items()}),
            MappingProxyType({node: tuple(sorted(rows)) for node, rows in successors.items()}))
    edges, successors = preservation.nested_graph_indices[index_key]
    path_start = start if first is None else first["target"]
    if first is not None and wire(first) not in edges.get((start, path_start), ()):
        preservation.nested_search_cache[key] = None
        return None
    pending, parents, depths, path = deque([path_start]), {path_start: None}, {path_start: 1}, None
    while pending:
        preservation.count()
        current = pending.popleft()
        if current == end:
            path = []
            while current is not None:
                if strict:
                    preservation.count()
                path.append(current)
                current = parents[current]
            path.reverse()
            break
        if depths[current] >= MAX_SEGMENT_LENGTH:
            continue
        for target in successors.get(current, ()):
            preservation.count()
            if target not in parents:
                parents[target] = current
                depths[target] = depths[current] + 1
                pending.append(target)
    if path is None:
        preservation.nested_search_cache[key] = None
        return None
    if first is not None:
        path = [start, *path]
    if len(path) > MAX_SEGMENT_LENGTH:
        preservation.nested_search_cache[key] = None
        return None
    if strict:
        preservation.count(len(path) + 1)
        for a, b in zip(path, path[1:]):
            for row in edges[a, b]:
                preservation.count(1 + len(row) // 16)
    links = [{"source": a, "target": b, "alternatives": [json.loads(row) for row in edges[a, b]]}
             for a, b in zip(path, path[1:])]
    if _has_memory_debt(links):
        preservation.nested_search_cache[key] = None
        return None
    if first is not None:
        links[0]["alternatives"] = [first]
    value = {"scope": view.scope_digest.hex(), "nodes": path, "edges": links}
    if strict:
        _prepay_tree(preservation, value)
    preservation.nested_search_cache[key] = wire(value)
    if strict:
        preservation.count(1 + len(preservation.nested_search_cache[key]) // 16)
    return json.loads(preservation.nested_search_cache[key])


def _nested_definition_segment(view, segment, definition_id):
    definition = view.memory.definitions[definition_id]
    segment.update({"terminal_definition_node": view.memory_graph.definition_nodes[definition_id],
        "terminal_defining_action_node": view.memory_graph.action_nodes[view.action_ids[definition.operation_key]],
        "terminal_write_operation_key": definition.operation_key, "terminal_write_span": _span_report(definition.span)})
    return segment


def _descendant_source_path(caller, wrapper, proof, analyses_by_entry, views, preservation, root_nodes):
    """ADR66 source-local DATA, then the existing exact physical unwind."""
    if (proof.caller_scope_digest != caller.scope_digest
            or proof.callee_scope_digest != wrapper.scope_digest
            or proof.callee_entry != wrapper.analysis.entry
            or len(proof.prior_transfers) > 8
            or any(type(row) is not InterproceduralTransferProof for row in proof.prior_transfers)):
        return None, "descendant_source_identity_unavailable"
    # Historical candidate is an exact raw wrapper attachment, not a definition.
    preservation.count(len(wrapper.operations) + len(proof.prior_transfers) + 1)
    if proof.callee_write_operation_key not in wrapper.operations:
        return None, "descendant_candidate_operation_unavailable"
    source_analysis = analyses_by_entry.get(proof.origin_entry)
    if (type(source_analysis) is not ConfiguredFunctionAnalysis
            or source_analysis.evidence.unit.scopes.function.scope.digest != proof.origin_scope_digest):
        return None, "descendant_source_unavailable"
    origins = []
    for boundary in source_analysis.boundaries.nodes:
        preservation.count()
        if (boundary.kind is BoundaryKind.SOURCE and boundary.label == proof.label
                and boundary.node == proof.origin_node):
            origins.append(boundary)
    if len(origins) != 1:
        return None, "descendant_source_unavailable"
    def view(analysis):
        if analysis.entry not in views:
            graph = analysis.normalized.dependencies
            preservation.count(graph.node_count + graph.edge_count + len(analysis.normalized.memory_ssa.definitions)
                               + len(analysis.normalized.memory_ssa.actions) + 1)
            for instruction in analysis.evidence.unit.observation.instructions:
                preservation.count(1 + len(instruction.operations))
            _prepay_view_control(analysis, preservation.count)
            views[analysis.entry] = _FunctionView(analysis)
        return views[analysis.entry]
    source = view(source_analysis)
    chains = []
    def walk(parent, keys, active):
        for seed in parent.analysis.evidence.seeds.callsites:
            preservation.count()
            if type(seed.target) is not DirectCallTarget:
                continue
            analysis = analyses_by_entry.get(seed.target.coordinate)
            if type(analysis) is not ConfiguredFunctionAnalysis or analysis.entry in active:
                continue
            child_keys = (*keys, seed.operation_key)
            if analysis.entry == proof.origin_entry and view(analysis).scope_digest == proof.origin_scope_digest:
                chains.append(child_keys)
                if len(chains) > MAX_ENTRY_CANDIDATES:
                    raise _PreservationWorkGap("descendant_candidate_budget_exhausted")
            if len(child_keys) < 2:
                walk(view(analysis), child_keys, active | {analysis.entry})
    walk(wrapper, (), frozenset({caller.analysis.entry, wrapper.analysis.entry}))
    if not chains:
        return None, "descendant_source_unavailable"
    roots = []
    preservation.count(1 + len(caller.analysis.boundaries.nodes))
    for root in caller.analysis.boundaries.query_roots:
        preservation.count()
        if root.node in root_nodes and len(root.physical_spans) == 1:
            roots.append(root)
    if not roots or len(roots) > MAX_ENTRY_CANDIDATES:
        return None, "descendant_exact_root_unavailable"
    successes, attempts, last_gap = {}, 0, "descendant_source_data_unavailable"
    for definition_id, definition in enumerate(source.memory.definitions):
        preservation.count()
        if (definition.kind is not MemoryDefinitionKind.DATA_WRITE or definition.operation_key is None
                or definition.span.object_id.kind is not StorageObjectKind.REGISTER_FILE
                or definition.span.object_id != proof.target_span.object_id
                or not definition.span.overlaps(proof.target_span)):
            continue
        definition_node = source.memory_graph.definition_nodes[definition_id]
        # The physical kernel independently authenticates raw output/defining edge,
        # including the source-scoped singleton case.
        segment = _data_local_segment(source, proof.origin_node, definition_node, preservation, charge_walk=True)
        if segment is None or preservation.segment(source, segment):
            continue
        _nested_definition_segment(source, segment, definition_id)
        for read in caller.memory.reads:
            preservation.count()
            reader_key = caller.memory.actions[read.action_id].operation_key
            operation = caller.operation(reader_key)
            preservation.count(len(caller.operations) + 1)
            if operation is None or not caller.definitely_precedes(proof.call_operation_key, reader_key):
                continue
            if operation.opcode in {"LOAD", "CALL", "CALLIND", "CALLOTHER", "RETURN", "BRANCH", "CBRANCH", "BRANCHIND"}:
                continue
            for operand_index, operand in enumerate(operation.inputs):
                preservation.count()
                if operation.opcode == "STORE" and operand_index != 2:
                    continue
                resolved = _resolve_validated_storage(storage_ref(operand), caller.analysis.evidence.unit.scopes.resolution_context)
                if (type(resolved) is not ResolvedStorage or resolved.span != read.span
                        or not proof.target_span.contains(resolved.span) or not definition.span.contains(resolved.span)):
                    continue
                for keys in chains:
                    preservation.count()
                    attempts += 1
                    if attempts > MAX_PRIOR_COMBINATIONS:
                        return None, "descendant_composition_budget_exceeded"
                    suffixes = []
                    for root in roots:
                        preservation.count()
                        suffix = _data_local_segment(caller, caller.memory_graph.action_nodes[read.action_id],
                                                     root.node, preservation, charge_walk=True)
                        if suffix is not None and not preservation.segment(caller, suffix):
                            suffixes.append((root, suffix))
                    if not suffixes:
                        continue
                    result = preservation.descendant_egress(caller, wrapper, proof.call_operation_key, keys,
                        definition.operation_key, reader_key, operand_index, charge_state_scans=True)
                    if result.status is not MemoryReadBridgeStatus.VERIFIED_MAY:
                        last_gap = result.gaps[0]
                        continue
                    preservation.count(1 + len(result.witness.receipt_bytes) // 16)
                    receipt = result.witness.report()
                    for root, suffix in suffixes:
                        preservation.count()
                        attachment = {"kind": "conditional_descendant_source_register_attachment", "version": 1,
                            "caller_scope": caller.scope_digest.hex(), "outer_call_operation_key": proof.call_operation_key,
                            "candidate_outer_write_operation_key": proof.callee_write_operation_key,
                            "source_scope": source.scope_digest.hex(),
                            "source_observation_digest": source.analysis.evidence.unit.scopes.function.observation_digest.hex(),
                            "source_node": proof.origin_node, "source_definition_node": definition_node,
                            "source_write_operation_key": definition.operation_key, "source_span": receipt["source_span"],
                            "selected_invocation_ordinal": receipt["selected_invocation_ordinal"],
                            "reader_operation_key": reader_key, "reader_action_node": receipt["target_read_action_node"],
                            "read_span": receipt["read_span"], "root_node": root.node,
                            "root_span": _span_report(root.physical_spans[0]), "reader_to_root_path": suffix["nodes"]}
                        composition = {"callee": segment, "transfer": receipt, "caller": suffix,
                                       "prior_segments": [], "entry_transfer": None,
                                       "descendant_source_attachment": attachment}
                        _prepay_tree(preservation, composition)
                        successes[wire(composition)] = composition
                        if len(successes) > 1:
                            return None, "descendant_composition_ambiguous"
    return (next(iter(successes.values())), None) if successes else (None, last_gap)


def _inner_source_memory_path(caller, writer, proof, analyses_by_entry, views, preservation, root_nodes):
    """Three independent DATA cuts joined by one full raw memory replay."""
    if (proof.caller_scope_digest != caller.scope_digest or proof.callee_scope_digest != writer.scope_digest
            or proof.callee_entry != writer.analysis.entry or len(proof.prior_transfers) > 8
            or any(type(row) is not InterproceduralTransferProof for row in proof.prior_transfers)):
        return None, "inner_source_identity_unavailable"
    source_analysis = analyses_by_entry.get(proof.origin_entry)
    if (type(source_analysis) is not ConfiguredFunctionAnalysis
            or source_analysis.evidence.unit.scopes.function.scope.digest != proof.origin_scope_digest):
        return None, "inner_source_unavailable"
    origins = []
    for boundary in source_analysis.boundaries.nodes:
        preservation.count()
        if boundary.kind is BoundaryKind.SOURCE and boundary.label == proof.label and boundary.node == proof.origin_node:
            origins.append(boundary)
    if len(origins) != 1:
        return None, "inner_source_unavailable"
    def view(analysis):
        if analysis.entry not in views:
            graph = analysis.normalized.dependencies
            preservation.count(graph.node_count + graph.edge_count + len(analysis.normalized.memory_ssa.definitions)
                               + len(analysis.normalized.memory_ssa.actions) + 1)
            for instruction in analysis.evidence.unit.observation.instructions:
                preservation.count(1 + len(instruction.operations))
            _prepay_view_control(analysis, preservation.count)
            views[analysis.entry] = _FunctionView(analysis)
        return views[analysis.entry]
    source = view(source_analysis)
    stores = []
    for i, definition in enumerate(writer.memory.definitions):
        preservation.count()
        if (definition.kind is MemoryDefinitionKind.DATA_WRITE
                and definition.operation_key == proof.callee_write_operation_key):
            stores.append((i, definition))
    store_operation = writer.operation(proof.callee_write_operation_key)
    preservation.count(len(writer.operations) + 1)
    if len(stores) != 1 or store_operation is None or store_operation.opcode != "STORE":
        return None, "inner_source_store_identity_unavailable"
    store_id, store = stores[0]
    chains = []
    def walk(parent, keys, active):
        for seed in parent.analysis.evidence.seeds.callsites:
            preservation.count()
            if type(seed.target) is not DirectCallTarget:
                continue
            analysis = analyses_by_entry.get(seed.target.coordinate)
            if type(analysis) is not ConfiguredFunctionAnalysis or analysis.entry in active:
                continue
            child_keys = (*keys, seed.operation_key)
            if analysis.entry == source_analysis.entry and view(analysis).scope_digest == proof.origin_scope_digest:
                chains.append(child_keys)
                if len(chains) > MAX_ENTRY_CANDIDATES:
                    raise _PreservationWorkGap("inner_source_candidate_budget_exhausted")
            if len(child_keys) < 2:
                walk(view(analysis), child_keys, active | {analysis.entry})
    walk(writer, (), frozenset({caller.analysis.entry, writer.analysis.entry}))
    if not chains:
        return None, "inner_source_unavailable"
    roots = []
    preservation.count(1 + len(caller.analysis.boundaries.nodes))
    for root in caller.analysis.boundaries.query_roots:
        preservation.count()
        if root.node in root_nodes and len(root.physical_spans) == 1:
            roots.append(root)
    if not roots or len(roots) > MAX_ENTRY_CANDIDATES:
        return None, "inner_source_exact_root_unavailable"
    definitions, readers, loads = [], [], []
    for i, definition in enumerate(source.memory.definitions):
        preservation.count()
        if (definition.kind is MemoryDefinitionKind.DATA_WRITE and definition.operation_key is not None
                and definition.span.object_id.kind is StorageObjectKind.REGISTER_FILE):
            definitions.append((i, definition))
            if len(definitions) > MAX_ENTRY_CANDIDATES:
                return None, "inner_source_definition_budget_exhausted"
    for read in writer.memory.reads:
        preservation.count()
        if read.span.object_id.kind is StorageObjectKind.REGISTER_FILE:
            readers.append(read)
            if len(readers) > MAX_PRIOR_READS:
                return None, "inner_source_reader_budget_exhausted"
    for read in caller.memory.reads:
        preservation.count()
        key = caller.memory.actions[read.action_id].operation_key
        operation = caller.operation(key)
        preservation.count(len(caller.operations) + 1)
        if (operation is not None and operation.opcode == "LOAD"
                and read.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE
                and read.span == proof.target_span
                and caller.definitely_precedes(proof.call_operation_key, key)):
            loads.append(read)
            if len(loads) > MAX_PRIOR_READS:
                return None, "inner_source_load_budget_exhausted"
    successes, attempts, last_gap = {}, 0, "inner_source_data_unavailable"
    for definition_id, definition in definitions:
        source_segment = _data_local_segment(source, proof.origin_node,
            source.memory_graph.definition_nodes[definition_id], preservation, charge_walk=True)
        if source_segment is None or preservation.segment(source, source_segment):
            continue
        _nested_definition_segment(source, source_segment, definition_id)
        for read in readers:
            preservation.count()
            reader_key = writer.memory.actions[read.action_id].operation_key
            operation = writer.operation(reader_key)
            preservation.count(len(writer.operations) + 1)
            if operation is None or not definition.span.contains(read.span):
                continue
            if reader_key != store.operation_key and not writer.definitely_precedes(reader_key, store.operation_key):
                continue
            for operand_index, operand in enumerate(operation.inputs):
                preservation.count()
                if operation.opcode in {"LOAD", "CALL", "CALLIND", "CALLOTHER", "RETURN", "BRANCH", "CBRANCH", "BRANCHIND"}:
                    continue
                if operation.opcode == "STORE" and operand_index != 2:
                    continue
                resolved = _resolve_validated_storage(storage_ref(operand), writer.analysis.evidence.unit.scopes.resolution_context)
                if type(resolved) is not ResolvedStorage or resolved.span != read.span:
                    continue
                for keys in chains:
                    for load in loads:
                        for root in roots:
                            preservation.count()
                            attempts += 1
                            if attempts > MAX_PRIOR_COMBINATIONS:
                                return None, "inner_source_composition_budget_exceeded"
                            writer_segment = _data_local_segment(writer, writer.memory_graph.action_nodes[read.action_id],
                                writer.memory_graph.definition_nodes[store_id], preservation, charge_walk=True)
                            if writer_segment is None or preservation.segment(writer, writer_segment):
                                continue
                            _nested_definition_segment(writer, writer_segment, store_id)
                            suffix = _data_local_segment(caller, caller.memory_graph.action_nodes[load.action_id],
                                root.node, preservation, charge_walk=True)
                            if suffix is None or preservation.segment(caller, suffix):
                                continue
                            load_key = caller.memory.actions[load.action_id].operation_key
                            result = preservation.inner_memory_egress(caller, writer, proof.call_operation_key, keys,
                                definition.operation_key, reader_key, store.operation_key, load_key, operand_index)
                            if result.status is not MemoryReadBridgeStatus.VERIFIED_MAY:
                                last_gap = result.gaps[0]
                                continue
                            preservation.count(1 + len(result.witness.receipt_bytes) // 16)
                            receipt = result.witness.report()
                            attachment = {"kind": "conditional_inner_source_memory_attachment", "version": 1,
                                "caller_scope": caller.scope_digest.hex(), "outer_call_operation_key": proof.call_operation_key,
                                "writer_scope": writer.scope_digest.hex(), "source_scope": source.scope_digest.hex(),
                                "source_node": proof.origin_node,
                                "source_definition_node": source.memory_graph.definition_nodes[definition_id],
                                "selected_source_invocation_ordinal": receipt["selected_source_invocation_ordinal"],
                                "selected_writer_invocation_ordinal": receipt["selected_writer_invocation_ordinal"],
                                "writer_reader": receipt["writer_reader"], "store_endpoint": receipt["store_endpoint"],
                                "load_endpoint": receipt["load_endpoint"], "root_node": root.node,
                                "root_span": _span_report(root.physical_spans[0]), "load_to_root_path": suffix["nodes"]}
                            composition = {"callee": source_segment, "writer": writer_segment, "transfer": receipt,
                                "caller": suffix, "prior_segments": [], "entry_transfer": None,
                                "inner_source_memory_attachment": attachment}
                            _prepay_tree(preservation, composition)
                            successes[wire(composition)] = composition
                            if len(successes) > 1:
                                return None, "inner_source_composition_ambiguous"
    return (next(iter(successes.values())), None) if successes else (None, last_gap)


def _prepay_tree(preservation, value):
    """Charge trusted bounded wire-tree traversal before copying/encoding it."""
    pending = [value]
    while pending:
        preservation.count()
        row = pending.pop()
        if type(row) is dict:
            preservation.count(len(row) + 1)
            pending.extend(row.values())
        elif type(row) is list:
            preservation.count(len(row) + 1)
            pending.extend(row)


def _nested_entry_guard(parent, child, call_key, state_key, span, preservation):
    key = ("entry_guard", _nested_view_identity(parent), _nested_view_identity(child),
           call_key, state_key, span, preservation.maximum)
    if key in preservation.nested_search_cache:
        return preservation.nested_search_cache[key]
    result = _derive_nested_entry_guard(parent, child, call_key, state_key, span, preservation)
    preservation.nested_search_cache[key] = result
    return result


def _derive_nested_entry_guard(parent, child, call_key, state_key, span, preservation):
    """ADR60/61 scoped raw-transient preparation; legacy ENTRY checking unchanged."""
    if preservation.register_interval(parent, state_key, call_key, span):
        return False
    class Budget:
        limits = MemoryReadBridgeLimits()
        def count(self):
            preservation.count()
        inspect = count
        def prepay(self, amount):
            pass
    budget = Budget()
    replay = _PriorReplay(parent, budget, _SavedValues(budget))
    calls = [row for row in parent.analysis.evidence.seeds.callsites if row.operation_key == call_key]
    if (len(calls) != 1 or type(calls[0].target) is not DirectCallTarget
            or calls[0].target.coordinate != child.analysis.entry
            or parent.operation_flow_targets.get(call_key) != (child.analysis.entry,)):
        return False
    for key, (_, operation) in parent.operations.items():
        preservation.count()
        if key == state_key or not parent.definitely_precedes(state_key, key) or not parent.may_precede(key, call_key):
            continue
        try:
            output = _descendant_raw_output(replay, key, operation)
        except _Gap:
            return False
        if output is not None and output.overlaps(span):
            return False
    return True


def _nested_entry_segments(parent, child, call_key, definition_id, preservation):
    key = ("entry_segments", _nested_view_identity(parent), _nested_view_identity(child), call_key,
           definition_id, preservation.maximum, MAX_ENTRY_CANDIDATES, MAX_PRIOR_READS,
           MAX_SEGMENT_NODES, MAX_SEGMENT_EDGES, MAX_SEGMENT_LENGTH)
    if key not in preservation.nested_search_cache:
        result = _derive_nested_entry_segments(parent, child, call_key, definition_id, preservation)
        preservation.nested_search_cache[key] = wire(result)
    return json.loads(preservation.nested_search_cache[key])


def _derive_nested_entry_segments(parent, child, call_key, definition_id, preservation):
    """Exact ENTRY data operands to actual definitions, without terminal fiction."""
    target = child.memory_graph.definition_nodes[definition_id]
    candidates = []
    if len(child.memory.reads) > MAX_PRIOR_READS:
        return candidates
    for read in child.memory.reads:
        preservation.count()
        key = child.memory.actions[read.action_id].operation_key
        operation = child.operation(key)
        if operation is None or operation.opcode in {"LOAD", "CALL", "CALLIND", "CALLOTHER", "RETURN", "BRANCH", "CBRANCH", "BRANCHIND"}:
            continue
        for index, operand in enumerate(operation.inputs):
            preservation.count()
            if operation.opcode == "STORE" and index != 2:
                continue
            resolved = _resolve_validated_storage(storage_ref(operand), child.analysis.evidence.unit.scopes.resolution_context)
            if type(resolved) is not ResolvedStorage or resolved.span.object_id.kind is not StorageObjectKind.REGISTER_FILE:
                continue
            physical = resolved.span
            if read.span != physical:
                continue
            for fragment in read.fragments:
                preservation.count()
                if fragment.span != physical or len(fragment.definition_ids) != 1:
                    continue
                entry_id = fragment.definition_ids[0]
                entry = child.memory.definitions[entry_id]
                if entry.kind is not MemoryDefinitionKind.ENTRY or not entry.span.contains(physical):
                    continue
                state_id = parent.state_definition(physical, parent.position(call_key))
                if state_id is None:
                    continue
                state = parent.memory.definitions[state_id]
                if (state.kind is not MemoryDefinitionKind.DATA_WRITE or state.operation_key is None
                        or not state.span.contains(physical)
                        or not _nested_entry_guard(parent, child, call_key, state.operation_key, physical, preservation)):
                    continue
                entry_node, read_node = child.memory_graph.definition_nodes[entry_id], child.memory_graph.action_nodes[read.action_id]
                first = []
                for a, b, edge in child.normalized.dependencies.weighted_edges():
                    preservation.count()
                    if a == entry_node and b == read_node and edge.kind == "memory_read" and edge.operation == key and edge.span == physical:
                        first.append({"source": a, "target": b, "kind": edge.kind,
                            "operation_key": edge.operation, "occurrence": edge.occurrence, "span": _span_report(edge.span)})
                if len(first) != 1:
                    continue
                segment = _data_local_segment(child, entry_node, target, preservation, first[0], charge_walk=True)
                if segment is None or preservation.segment(child, segment):
                    continue
                transfer = {"kind": "conditional_observed_call_entry_subspan_transfer", "version": 1,
                    "premise": SHARED_STATE_PROFILE, "caller_scope": parent.scope_digest.hex(), "callee_scope": child.scope_digest.hex(),
                    "caller_observation_digest": parent.analysis.evidence.unit.scopes.function.observation_digest.hex(),
                    "callee_observation_digest": child.analysis.evidence.unit.scopes.function.observation_digest.hex(),
                    "call_operation_key": call_key, "source_definition_node": parent.memory_graph.definition_nodes[state_id],
                    "target_entry_node": entry_node, "aggregate_entry_span": _span_report(entry.span), "physical_span": _span_report(physical),
                    "read_action_node": read_node, "read_operation_key": key, "read_operand_index": index, "entry_read_edge": first[0]}
                candidates.append((state_id, transfer, _nested_definition_segment(child, segment, definition_id)))
                if len(candidates) > MAX_ENTRY_CANDIDATES:
                    return []
    return candidates


def _one_prior_nested_egress(caller, wrapper, proof, analyses_by_entry, views, preservation, root_nodes):
    preservation.count()
    prior = proof.prior_transfers[0]
    if (proof.caller_scope_digest != caller.scope_digest or proof.callee_scope_digest != wrapper.scope_digest
            or prior.caller_scope_digest != caller.scope_digest or prior.pointer_dereferences != 0
            or prior.target_span.object_id.kind is not StorageObjectKind.REGISTER_FILE
            or not caller.definitely_precedes(prior.call_operation_key, proof.call_operation_key)
            or _has_control_cycle(caller)):
        return None, "nested_scope_or_order_unavailable"
    chains = []
    def walk(parent, keys, chain):
        for seed in parent.analysis.evidence.seeds.callsites:
            preservation.count()
            if type(seed.target) is not DirectCallTarget:
                continue
            analysis = analyses_by_entry.get(seed.target.coordinate)
            if type(analysis) is not ConfiguredFunctionAnalysis or analysis.entry in {v.analysis.entry for v in chain}:
                continue
            if analysis.entry not in views:
                for instruction in analysis.evidence.unit.observation.instructions:
                    preservation.count()
                    for _ in instruction.operations:
                        preservation.count()
                views[analysis.entry] = _FunctionView(analysis)
            child = views[analysis.entry]
            child_keys, child_chain = (*keys, seed.operation_key), (*chain, child)
            chains.append((child_keys, child_chain))
            if len(chains) > MAX_ENTRY_CANDIDATES:
                raise _PreservationWorkGap("nested_candidate_budget_exhausted")
            if len(child_keys) < 2:
                walk(child, child_keys, child_chain)
    walk(wrapper, (), (wrapper,))
    if not chains:
        return None, "nested_call_chain_unavailable"
    source_analysis = analyses_by_entry.get(prior.callee_entry)
    if type(source_analysis) is not ConfiguredFunctionAnalysis:
        return None, "nested_source_body_unavailable"
    if prior.callee_entry not in views:
        views[prior.callee_entry] = _FunctionView(source_analysis)
    source = views[prior.callee_entry]
    source_segment, gap = _transfer_segment(source, prior, proof.origin_entry, proof.origin_scope_digest, proof.origin_node)
    if gap:
        return None, gap
    if preservation.segment(source, source_segment):
        return None, "nested_source_data_call_state_unproven"
    roots = [r for r in caller.analysis.boundaries.query_roots if r.node in root_nodes]
    if not roots or len(roots) > MAX_ENTRY_CANDIDATES or any(len(r.physical_spans) != 1 for r in roots):
        return None, "nested_exact_root_unavailable"
    event = WriteEvent(prior.caller_scope_digest, caller.position(prior.call_operation_key), prior.call_operation_key,
        prior.callee_entry, prior.callee_scope_digest, prior.callee_write_operation_key, prior.target_span, 0, ())
    successes, attempts, last_gap = {}, 0, "nested_data_path_unavailable"
    for keys, chain in chains:
        descendant = chain[-1]
        for definition_id, definition in enumerate(descendant.memory.definitions):
            preservation.count()
            if (definition.kind is not MemoryDefinitionKind.DATA_WRITE or definition.operation_key is None
                    or definition.span.object_id.kind is not StorageObjectKind.REGISTER_FILE
                    or definition.span.object_id != proof.target_span.object_id
                    or not definition.span.overlaps(proof.target_span)):
                continue
            preparations = [(definition_id, [])]
            for level in range(len(chain) - 1, 0, -1):
                next_preparations = []
                for endpoint, nested in preparations:
                    for state_id, entry, segment in _nested_entry_segments(chain[level - 1], chain[level], keys[level - 1], endpoint, preservation):
                        preservation.count()
                        next_preparations.append((state_id, [{"entry_transfer": entry, "callee": segment}, *nested]))
                        attempts += 1
                        if attempts > MAX_PRIOR_COMBINATIONS:
                            return None, "nested_composition_budget_exceeded"
                preparations = next_preparations
            for endpoint, nested in preparations:
                for state_id, entry, wrapper_segment in _nested_entry_segments(caller, wrapper, proof.call_operation_key, endpoint, preservation):
                    state_node = caller.memory_graph.definition_nodes[state_id]
                    reachable = frozenset(caller.normalized.dependencies.backward_reachable((state_node,)))
                    for read in caller.memory.reads:
                        preservation.count()
                        read_key = caller.memory.actions[read.action_id].operation_key
                        if not caller.definitely_precedes(prior.call_operation_key, read_key):
                            continue
                        for fragment in read.fragments:
                            preservation.count()
                            if not prior.target_span.contains(fragment.span):
                                continue
                            certificate = certify_call_byte_replacement(caller, source, event, read, fragment, reachable)
                            if certificate is None:
                                continue
                            reader_node, _ = certificate
                            local = _data_local_segment(caller, reader_node, state_node, preservation, charge_walk=True)
                            if local is None or preservation.segment(caller, local):
                                continue
                            prior_transfer = {"kind": "certified_observed_call_byte_transfer", "caller_scope": caller.scope_digest.hex(),
                                "call_operation_key": prior.call_operation_key, "callee_scope": source.scope_digest.hex(),
                                "callee_write_operation_key": prior.callee_write_operation_key,
                                "source_definition_node": source_segment["terminal_definition_node"],
                                "target_reader_node": reader_node, "target_span": _span_report(prior.target_span)}
                            for target_read in caller.memory.reads:
                                preservation.count()
                                target_key = caller.memory.actions[target_read.action_id].operation_key
                                operation = caller.operation(target_key)
                                if operation is None or not caller.definitely_precedes(proof.call_operation_key, target_key):
                                    continue
                                for operand, node in enumerate(operation.inputs):
                                    preservation.count()
                                    resolved = _resolve_validated_storage(storage_ref(node), caller.analysis.evidence.unit.scopes.resolution_context)
                                    if type(resolved) is not ResolvedStorage or resolved.span != target_read.span or not proof.target_span.contains(resolved.span):
                                        continue
                                    attempts += 1
                                    if attempts > MAX_PRIOR_COMBINATIONS:
                                        return None, "nested_composition_budget_exceeded"
                                    target_node = caller.memory_graph.action_nodes[target_read.action_id]
                                    suffixes = []
                                    for root in roots:
                                        preservation.count()
                                        suffix = _data_local_segment(caller, target_node, root.node, preservation, charge_walk=True)
                                        if suffix is not None and not preservation.segment(caller, suffix):
                                            suffixes.append((root, suffix))
                                    if not suffixes:
                                        continue
                                    result = preservation.descendant_egress(caller, wrapper, proof.call_operation_key, keys,
                                        definition.operation_key, target_key, operand)
                                    if result.status is not MemoryReadBridgeStatus.VERIFIED_MAY:
                                        last_gap = result.gaps[0]
                                        continue
                                    receipt = result.witness.report()
                                    prior_records = [r for r in receipt["invocations"] if r["parent_invocation_ordinal"] == 0
                                        and r["call_operation_key"] == prior.call_operation_key and r["callee_scope"] == source.scope_digest.hex()
                                        and r["callee_observation_digest"] == source.analysis.evidence.unit.scopes.function.observation_digest.hex()]
                                    outer_records = [r for r in receipt["invocations"] if r["parent_invocation_ordinal"] == 0
                                                     and r["call_operation_key"] == proof.call_operation_key]
                                    if (len(prior_records) != 1 or len(outer_records) != 1
                                            or prior_records[0]["invocation_ordinal"] >= outer_records[0]["invocation_ordinal"]):
                                        continue
                                    for root, suffix in suffixes:
                                        preservation.count()
                                        if suffix["nodes"][0] != receipt["target_read_action_node"]:
                                            continue
                                        attachment = {"kind": "conditional_descendant_register_egress_attachment", "version": 1,
                                            "caller_scope": caller.scope_digest.hex(), "outer_call_operation_key": proof.call_operation_key,
                                            "candidate_outer_write_operation_key": proof.callee_write_operation_key,
                                            "reader_operation_key": target_key, "reader_action_node": receipt["target_read_action_node"],
                                            "read_span": receipt["read_span"], "root_node": root.node,
                                            "root_span": _span_report(root.physical_spans[0]), "reader_to_root_path": suffix["nodes"]}
                                        composition = {"callee": wrapper_segment, "entry_transfer": entry,
                                            "nested_segments": nested, "transfer": receipt, "caller": suffix,
                                            "prior_segments": [{"callee": source_segment, "transfer": prior_transfer, "caller": local}],
                                            "nested_egress_attachment": attachment}
                                        # Include every genuine ENTRY/read/operand/segment identity;
                                        # endpoint-only keys incorrectly overwrite distinct proofs.
                                        successes[wire(composition)] = composition
                                        if len(successes) > 1:
                                            return None, "nested_composition_ambiguous"
    return (next(iter(successes.values())), None) if successes else (None, last_gap)


def _one_prior_memory_egress(caller, callee, proof, analyses_by_entry, views, preservation, root_nodes):
    result, gap = _one_prior_memory_egress_attempt(caller, callee, proof, analyses_by_entry,
                                                 views, preservation, root_nodes, allow_cover=False)
    if result is not None:
        return result, gap
    covered, _ = _one_prior_memory_egress_attempt(caller, callee, proof, analyses_by_entry,
                                                views, preservation, root_nodes, allow_cover=True)
    return (covered, None) if covered is not None else (result, gap)


def _one_prior_memory_egress_attempt(caller, callee, proof, analyses_by_entry, views,
                                   preservation, root_nodes, *, allow_cover):
    preservation.count()
    prior = proof.prior_transfers[0]
    if (proof.caller_scope_digest != caller.scope_digest or prior.caller_scope_digest != caller.scope_digest
            or proof.callee_scope_digest != callee.scope_digest or proof.callee_entry != callee.analysis.entry
            or proof.pointer_dereferences != 0 or prior.pointer_dereferences != 0
            or prior.target_span.object_id.kind is not StorageObjectKind.REGISTER_FILE
            or not caller.definitely_precedes(prior.call_operation_key, proof.call_operation_key)
            or _has_control_cycle(caller)):
        return None, "egress_scope_or_order_unavailable"
    analysis = analyses_by_entry.get(prior.callee_entry)
    if type(analysis) is not ConfiguredFunctionAnalysis:
        return None, "egress_source_body_unavailable"
    if prior.callee_entry not in views:
        views[prior.callee_entry] = _FunctionView(analysis)
    source = views[prior.callee_entry]
    source_segment, gap = _transfer_segment(source, prior, proof.origin_entry, proof.origin_scope_digest, proof.origin_node)
    if gap is not None:
        return None, gap
    stores = []
    for i, row in enumerate(callee.memory.definitions):
        preservation.count()
        if (row.kind is MemoryDefinitionKind.DATA_WRITE and row.operation_key == proof.callee_write_operation_key
                and row.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE
                and callee.operation(row.operation_key) is not None and callee.operation(row.operation_key).opcode == "STORE"):
            stores.append((i, row))
    roots = []
    for root in caller.analysis.boundaries.query_roots:
        preservation.count()
        if root.node in root_nodes:
            roots.append(root)
    if not roots or len(roots) > MAX_ENTRY_CANDIDATES or any(len(root.physical_spans) != 1 for root in roots):
        return None, "egress_exact_root_unavailable"
    loads = []
    for i, row in enumerate(caller.memory.actions):
        preservation.count()
        if (caller.operation(row.operation_key) is not None and caller.operation(row.operation_key).opcode == "LOAD"
                and caller.definitely_precedes(proof.call_operation_key, row.operation_key)):
            loads.append((i, row))
    post_loads = set()
    for action_id, action in loads:
        for call in caller.analysis.evidence.seeds.callsites:
            preservation.count()
            if (caller.definitely_precedes(proof.call_operation_key, call.operation_key)
                    and caller.definitely_precedes(call.operation_key, action.operation_key)):
                post_loads.add(action_id)
    if len(stores) != 1 or len(loads) > MAX_ENTRY_CANDIDATES or len(callee.memory.reads) > MAX_PRIOR_READS:
        return None, "egress_candidates_unavailable"
    definition_id, definition = stores[0]
    new_source_segment = None
    if post_loads:
        new_source_segment = _data_local_segment(source, proof.origin_node,
            source_segment["terminal_definition_node"], preservation, charge_walk=True)
        if new_source_segment is not None:
            new_source_segment.update({key: value for key, value in source_segment.items()
                                       if key.startswith("terminal_")})
    store_node = callee.memory_graph.definition_nodes[definition_id]
    store_action = callee.memory_graph.action_nodes[callee.action_ids[definition.operation_key]]
    event = WriteEvent(prior.caller_scope_digest, caller.position(prior.call_operation_key), prior.call_operation_key,
        prior.callee_entry, prior.callee_scope_digest, prior.callee_write_operation_key, prior.target_span, 0, ())
    successes, attempts, last_gap = {}, 0, "egress_data_path_unavailable"
    for read in callee.memory.reads:
        preservation.count()
        read_key = callee.memory.actions[read.action_id].operation_key
        operation = callee.operation(read_key)
        if operation is None or operation.opcode == "LOAD":
            continue
        for operand_index, operand in enumerate(operation.inputs):
            preservation.count()
            if operation.opcode == "STORE" and operand_index != 2:
                continue
            resolved = _resolve_validated_storage(storage_ref(operand), callee.analysis.evidence.unit.scopes.resolution_context)
            if type(resolved) is not ResolvedStorage or resolved.span.object_id.kind is not StorageObjectKind.REGISTER_FILE:
                continue
            physical = resolved.span
            if read.span != physical:
                continue
            for fragment in read.fragments:
                if fragment.span != physical:
                    continue
                for entry_id in fragment.definition_ids:
                    preservation.count()
                    entry = callee.memory.definitions[entry_id]
                    if entry.kind is not MemoryDefinitionKind.ENTRY or not entry.span.contains(physical):
                        continue
                    state_id = caller.state_definition(physical, caller.position(proof.call_operation_key))
                    if state_id is None:
                        continue
                    state = caller.memory.definitions[state_id]
                    if (state.kind is not MemoryDefinitionKind.DATA_WRITE or state.operation_key is None
                            or not state.span.contains(physical)):
                        continue
                    legacy_entry = (_call_entry_preserved(caller, proof.call_operation_key, callee, physical, state.operation_key)
                        and not preservation.register_interval(caller, state.operation_key, proof.call_operation_key, physical))
                    new_entry = bool(post_loads) and _nested_entry_guard(caller, callee, proof.call_operation_key,
                                                                        state.operation_key, physical, preservation)
                    if not legacy_entry and not new_entry:
                        continue
                    entry_node, state_node = callee.memory_graph.definition_nodes[entry_id], caller.memory_graph.definition_nodes[state_id]
                    read_node = callee.memory_graph.action_nodes[read.action_id]
                    first_edges = []
                    for a, b, record in callee.normalized.dependencies.weighted_edges():
                        preservation.count()
                        if (a == entry_node and b == read_node and record.kind == "memory_read"
                                and record.operation == read_key and record.span == physical):
                            first_edges.append({"source": a, "target": b, "kind": record.kind,
                                "operation_key": record.operation, "occurrence": record.occurrence, "span": _span_report(record.span)})
                    if len(first_edges) != 1:
                        continue
                    callee_segment = _data_local_segment(callee, entry_node, store_node, preservation,
                                                        first_edges[0], charge_walk=bool(post_loads))
                    if callee_segment is None:
                        continue
                    callee_segment.update({"terminal_definition_node": store_node,
                        "terminal_defining_action_node": store_action, "terminal_write_operation_key": definition.operation_key,
                        "terminal_write_span": _span_report(definition.span)})
                    reachable = frozenset(caller.normalized.dependencies.backward_reachable((state_node,)))
                    for caller_read in caller.memory.reads:
                        if allow_cover:
                            preservation.count()
                        caller_read_key = caller.memory.actions[caller_read.action_id].operation_key
                        if not caller.definitely_precedes(prior.call_operation_key, caller_read_key):
                            continue
                        covered = (_cover_source_transport(caller, source, prior, proof,
                            caller_read, reachable, preservation) if allow_cover else None)
                        if allow_cover and covered is None:
                            continue
                        for caller_fragment in ((None,) if allow_cover else caller_read.fragments):
                            if not allow_cover and not prior.target_span.contains(caller_fragment.span):
                                continue
                            attempts += 1
                            if attempts > MAX_PRIOR_COMBINATIONS:
                                return None, "egress_composition_budget_exceeded"
                            if allow_cover:
                                selected_source, covered_transfer = covered
                                reader_node = covered_transfer["target_reader_node"]
                            else:
                                certificate = certify_call_byte_replacement(caller, source, event, caller_read, caller_fragment, reachable)
                                if certificate is None:
                                    continue
                                reader_node, _ = certificate
                                selected_source = new_source_segment if post_loads else source_segment
                            local = _data_local_segment(caller, reader_node, state_node, preservation,
                                                        charge_walk=bool(post_loads))
                            if local is None:
                                continue
                            gap = preservation.segment(caller, local)
                            if gap:
                                last_gap = gap
                                continue
                            for action_id, action in loads:
                                preservation.count()
                                continuation_mode = action_id in post_loads
                                if not (new_entry if continuation_mode else legacy_entry):
                                    continue
                                if continuation_mode:
                                    if selected_source is None:
                                        continue
                                    data_gap = (preservation.segment(source, selected_source)
                                                or preservation.segment(callee, callee_segment))
                                    if data_gap:
                                        last_gap = data_gap
                                        continue
                                rooted_suffixes = []
                                if continuation_mode:
                                    for root in roots:
                                        preservation.count()
                                        suffix = _data_local_segment(caller, caller.memory_graph.action_nodes[action_id],
                                                                     root.node, preservation, charge_walk=True)
                                        if suffix is not None:
                                            suffix_gap = preservation.segment(caller, suffix)
                                            if suffix_gap:
                                                last_gap = suffix_gap
                                            else:
                                                rooted_suffixes.append((root, suffix))
                                    if not rooted_suffixes:
                                        continue
                                attempts += 1
                                if attempts > MAX_PRIOR_COMBINATIONS:
                                    return None, "egress_composition_budget_exceeded"
                                result = preservation.memory_egress(caller, callee, proof.call_operation_key,
                                    definition_id, action_id, continuation_mode=continuation_mode)
                                if result.status is not MemoryReadBridgeStatus.VERIFIED_MAY:
                                    last_gap = result.gaps[0]
                                    continue
                                receipt = result.witness.report()
                                if not proof.target_span.contains(result.witness.read_span):
                                    continue
                                prior_records = [row for row in result.witness.prior_leaf_calls
                                                 if row.call_operation_key == prior.call_operation_key]
                                if (len(prior_records) != 1 or prior_records[0].callee_scope != source.scope_digest
                                        or prior_records[0].callee_observation_digest
                                            != source.analysis.evidence.unit.scopes.function.observation_digest):
                                    continue
                                for root, prepared_suffix in (rooted_suffixes if continuation_mode else [(root, None) for root in roots]):
                                    preservation.count()
                                    attempts += 1
                                    if attempts > MAX_PRIOR_COMBINATIONS:
                                        return None, "egress_composition_budget_exceeded"
                                    suffix = prepared_suffix if continuation_mode else _data_local_segment(caller, result.witness.target_load_action_node, root.node, preservation)
                                    if suffix is None or preservation.segment(caller, suffix):
                                        continue
                                    subspan = {"kind": "conditional_observed_call_entry_subspan_transfer", "version": 1,
                                        "premise": SHARED_STATE_PROFILE, "caller_scope": caller.scope_digest.hex(),
                                        "callee_scope": callee.scope_digest.hex(),
                                        "caller_observation_digest": caller.analysis.evidence.unit.scopes.function.observation_digest.hex(),
                                        "callee_observation_digest": callee.analysis.evidence.unit.scopes.function.observation_digest.hex(),
                                        "call_operation_key": proof.call_operation_key, "source_definition_node": state_node,
                                        "target_entry_node": entry_node, "aggregate_entry_span": _span_report(entry.span),
                                        "physical_span": _span_report(physical), "read_action_node": read_node,
                                        "read_operation_key": read_key, "read_operand_index": operand_index,
                                        "entry_read_edge": first_edges[0]}
                                    prior_transfer = {"kind": "certified_observed_call_byte_transfer", "caller_scope": caller.scope_digest.hex(),
                                        "call_operation_key": prior.call_operation_key, "callee_scope": source.scope_digest.hex(),
                                        "callee_write_operation_key": prior.callee_write_operation_key,
                                        "source_definition_node": source_segment["terminal_definition_node"],
                                        "target_reader_node": reader_node, "target_span": _span_report(prior.target_span)}
                                    if allow_cover:
                                        prior_transfer = covered_transfer
                                    attachment = {"kind": "conditional_observed_call_memory_egress_attachment", "version": 1,
                                        "caller_scope": caller.scope_digest.hex(), "call_operation_key": proof.call_operation_key,
                                        "load_operation_key": action.operation_key, "load_action_node": result.witness.target_load_action_node,
                                        "read_span": receipt["read_span"], "root_node": root.node,
                                        "root_span": _span_report(root.physical_spans[0]), "load_to_root_path": suffix["nodes"]}
                                    complete = {"callee": callee_segment, "transfer": receipt, "caller": suffix,
                                        "prior_segments": [{"callee": selected_source if allow_cover or continuation_mode else source_segment,
                                                            "transfer": prior_transfer, "caller": local}],
                                        "entry_transfer": subspan, "memory_egress_attachment": attachment}
                                    key = wire(complete) if continuation_mode else (state_node, entry_node, read_node, operand_index, reader_node, action_id, root.node)
                                    successes[key] = complete
                                    if len(successes) > 1:
                                        return None, "egress_composition_ambiguous"
    return (next(iter(successes.values())), None) if successes else (None, last_gap)


def _one_sequential_prior(caller, callee, proof, analyses_by_entry, views, preservation):
    """Rebuild one source CALL, caller state, and callee ENTRY chain."""
    preservation.count()
    prior = proof.prior_transfers[0]
    if (prior.caller_scope_digest != caller.scope_digest
            or proof.caller_scope_digest != caller.scope_digest
            or prior.callee_scope_digest == caller.scope_digest
            or not caller.definitely_precedes(
                prior.call_operation_key, proof.call_operation_key,
            )):
        return [], None, None, "prior_transfer_scope_or_order_mismatch"
    if _has_control_cycle(caller):
        return [], None, None, "prior_caller_cycle_unsupported"
    source_analysis = analyses_by_entry.get(prior.callee_entry)
    if type(source_analysis) is not ConfiguredFunctionAnalysis:
        return [], None, None, "prior_callee_view_unavailable"
    try:
        if prior.callee_entry not in views:
            views[prior.callee_entry] = _FunctionView(source_analysis)
        source = views[prior.callee_entry]
    except ValueError:
        return [], None, None, "prior_callee_view_unavailable"
    source_segment, source_gap = _transfer_segment(
        source, prior, proof.origin_entry, proof.origin_scope_digest,
        proof.origin_node,
    )
    if source_gap is not None:
        return [], None, None, source_gap
    if (prior.target_span.object_id.kind is not StorageObjectKind.REGISTER_FILE
            or prior.pointer_dereferences != 0):
        return [], None, None, "prior_nonregister_transfer_unsupported"
    final_position = caller.position(proof.call_operation_key)
    prior_position = caller.position(prior.call_operation_key)
    if final_position is None or prior_position is None:
        return [], None, None, "prior_call_position_unavailable"
    entry_definitions = tuple(
        (definition_id, definition)
        for definition_id, definition in enumerate(callee.memory.definitions)
        if (definition.kind is MemoryDefinitionKind.ENTRY
            and definition.span.object_id.kind in (
                StorageObjectKind.REGISTER_FILE,
                StorageObjectKind.ADDRESS_SPACE,
            ))
    )
    if (len(entry_definitions) > MAX_ENTRY_CANDIDATES
            or len(caller.memory.reads) > MAX_PRIOR_READS):
        return [], None, None, "prior_composition_budget_exceeded"
    candidates = {}
    event = WriteEvent(
        prior.caller_scope_digest, prior_position, prior.call_operation_key,
        prior.callee_entry, prior.callee_scope_digest,
        prior.callee_write_operation_key, prior.target_span,
        prior.pointer_dereferences, (),
    )
    attempts = 0
    progress = 0
    preservation_gap = None
    for entry_id, entry_definition in entry_definitions:
        entry_span = entry_definition.span
        state_id = caller.state_definition(entry_span, final_position)
        if state_id is None:
            continue
        progress = max(progress, 1)
        state_definition = caller.memory.definitions[state_id]
        if (state_definition.kind is not MemoryDefinitionKind.DATA_WRITE
                or state_definition.operation_key is None
                or not state_definition.span.contains(entry_span)):
            continue
        if not _call_entry_preserved(
            caller, proof.call_operation_key, callee, entry_span,
            state_definition.operation_key,
        ):
            continue
        if entry_span.object_id.kind is StorageObjectKind.REGISTER_FILE:
            interval_gap = preservation.register_interval(caller, state_definition.operation_key,
                                                          proof.call_operation_key, entry_span)
            if interval_gap is not None:
                preservation_gap = interval_gap
                continue
        if any(
            other_id != state_id
            and other.kind is MemoryDefinitionKind.DATA_WRITE
            and other.operation_key is not None
            and other.span.overlaps(entry_span)
            and caller.may_precede(
                state_definition.operation_key, other.operation_key,
            )
            and caller.may_precede(
                other.operation_key, proof.call_operation_key,
            )
            for other_id, other in enumerate(caller.memory.definitions)
        ):
            continue
        entry_node = callee.memory_graph.definition_nodes[entry_id]
        callee_segment, callee_gap = _transfer_segment(
            callee, proof.final_transfer, callee.analysis.entry,
            callee.scope_digest, entry_node,
        )
        if callee_gap is not None:
            continue
        progress = max(progress, 2)
        state_node = caller.memory_graph.definition_nodes[state_id]
        reachable = frozenset(
            caller.normalized.dependencies.backward_reachable((state_node,))
        )
        for read in caller.memory.reads:
            read_key = caller.memory.actions[read.action_id].operation_key
            if not caller.definitely_precedes(
                prior.call_operation_key, read_key,
            ) or not (
                read_key == state_definition.operation_key
                or caller.definitely_precedes(
                    read_key, state_definition.operation_key,
                )
            ):
                continue
            for fragment in read.fragments:
                if not prior.target_span.contains(fragment.span):
                    continue
                attempts += 1
                if attempts > MAX_PRIOR_COMBINATIONS:
                    return [], None, None, "prior_composition_budget_exceeded"
                certificate = certify_call_byte_replacement(
                    caller, source, event, read, fragment, reachable,
                )
                if certificate is None:
                    continue
                progress = max(progress, 3)
                reader_node, _ = certificate
                caller_segment, caller_gap = _local_segment(
                    caller, reader_node, state_node,
                )
                if caller_gap is not None:
                    continue
                checked_gap = preservation.segment(caller, caller_segment)
                if checked_gap is not None:
                    preservation_gap = checked_gap
                    continue
                progress = 4
                key = (entry_node, state_node, reader_node, read_key)
                candidates[key] = (
                    source_segment, caller_segment, callee_segment,
                    entry_span, reader_node, state_node, entry_node,
                )
    if len(candidates) != 1:
        return [], None, None, (
            "prior_composition_ambiguous" if candidates
            else preservation_gap or (
                "prior_state_definition_unavailable",
                "prior_callee_entry_path_unavailable",
                "prior_call_reader_unavailable",
                "prior_local_path_unavailable",
                "prior_composition_path_unavailable",
            )[progress]
        )
    (source_segment, caller_segment, callee_segment, entry_span,
     reader_node, state_node, entry_node) = next(iter(candidates.values()))
    prior_transfer = {
        "kind": "certified_observed_call_byte_transfer",
        "caller_scope": caller.scope_digest.hex(),
        "call_operation_key": prior.call_operation_key,
        "callee_scope": prior.callee_scope_digest.hex(),
        "callee_write_operation_key": prior.callee_write_operation_key,
        "source_definition_node": source_segment["terminal_definition_node"],
        "target_reader_node": reader_node,
        "target_span": _span_report(prior.target_span),
    }
    entry_transfer = {
        "kind": "conditional_observed_call_entry_byte_transfer",
        "caller_scope": caller.scope_digest.hex(),
        "call_operation_key": proof.call_operation_key,
        "callee_scope": callee.scope_digest.hex(),
        "source_definition_node": state_node,
        "target_entry_node": entry_node,
        "physical_span": _span_report(entry_span),
    }
    return [{
        "callee": source_segment,
        "transfer": prior_transfer,
        "caller": caller_segment,
    }], entry_transfer, callee_segment, None


def _one_prior_memory(caller, callee, proof, analyses_by_entry, views, preservation):
    """Join real source-CALL data flow to STORE, then raw STORE-to-LOAD bytes."""
    preservation.count()
    prior = proof.prior_transfers[0]
    if (prior.caller_scope_digest != caller.scope_digest
            or proof.caller_scope_digest != caller.scope_digest
            or prior.callee_scope_digest == caller.scope_digest
            or not caller.definitely_precedes(prior.call_operation_key, proof.call_operation_key)
            or _has_control_cycle(caller)):
        return [], None, None, "memory_prior_scope_or_order_unavailable"
    analysis = analyses_by_entry.get(prior.callee_entry)
    if type(analysis) is not ConfiguredFunctionAnalysis:
        return [], None, None, "memory_prior_callee_unavailable"
    try:
        if prior.callee_entry not in views:
            views[prior.callee_entry] = _FunctionView(analysis)
        source = views[prior.callee_entry]
    except ValueError:
        return [], None, None, "memory_prior_callee_unavailable"
    source_segment, gap = _transfer_segment(
        source, prior, proof.origin_entry, proof.origin_scope_digest, proof.origin_node,
    )
    if gap is not None:
        return [], None, None, gap
    if (prior.target_span.object_id.kind is not StorageObjectKind.REGISTER_FILE
            or prior.pointer_dereferences != 0):
        return [], None, None, "memory_prior_nonregister_transfer_unsupported"
    position = caller.position(prior.call_operation_key)
    if position is None:
        return [], None, None, "memory_prior_position_unavailable"
    prefix_calls = []
    final_position = caller.position(proof.call_operation_key)
    if final_position is None:
        return [], None, None, "memory_prior_position_unavailable"
    for key, (operation_position, operation) in caller.operations.items():
        preservation.count()
        if operation_position < final_position and operation.opcode in {"CALL", "CALLIND", "CALLOTHER"}:
            prefix_calls.append(key)
    prefix_mode = prefix_calls != [prior.call_operation_key]
    stores = tuple(
        (index, definition) for index, definition in enumerate(caller.memory.definitions)
        if (definition.kind is MemoryDefinitionKind.DATA_WRITE
            and definition.operation_key in caller.operations
            and caller.operations[definition.operation_key][1].opcode == "STORE"
            and caller.definitely_precedes(prior.call_operation_key, definition.operation_key)
            and caller.definitely_precedes(definition.operation_key, proof.call_operation_key))
    )
    loads = tuple(
        (index, action) for index, action in enumerate(callee.memory.actions)
        if (action.operation_key in callee.operations
            and callee.operations[action.operation_key][1].opcode == "LOAD")
    )
    if (len(stores) > MAX_ENTRY_CANDIDATES or len(loads) > MAX_ENTRY_CANDIDATES
            or len(caller.memory.reads) > MAX_PRIOR_READS
            or len(stores) * len(loads) > MAX_PRIOR_COMBINATIONS):
        return [], None, None, "memory_prior_composition_budget_exceeded"
    event = WriteEvent(
        prior.caller_scope_digest, position, prior.call_operation_key,
        prior.callee_entry, prior.callee_scope_digest, prior.callee_write_operation_key,
        prior.target_span, 0, (),
    )
    candidates, attempts, preservation_gap = {}, 0, None
    for definition_id, definition in stores:
        state_node = caller.memory_graph.definition_nodes[definition_id]
        reachable = frozenset(caller.normalized.dependencies.backward_reachable((state_node,)))
        data_paths = []
        for read in caller.memory.reads:
            read_key = caller.memory.actions[read.action_id].operation_key
            if not caller.definitely_precedes(prior.call_operation_key, read_key) or not (
                read_key == definition.operation_key
                or caller.definitely_precedes(read_key, definition.operation_key)
            ):
                continue
            for fragment in read.fragments:
                if not prior.target_span.contains(fragment.span):
                    continue
                attempts += 1
                if attempts > MAX_PRIOR_COMBINATIONS:
                    return [], None, None, "memory_prior_composition_budget_exceeded"
                certificate = certify_call_byte_replacement(
                    caller, source, event, read, fragment, reachable,
                )
                if certificate is not None:
                    reader_node, _ = certificate
                    local, local_gap = _local_segment(caller, reader_node, state_node)
                    if local_gap is None:
                        checked_gap = preservation.segment(caller, local)
                        if checked_gap is None:
                            data_paths.append((reader_node, read_key, local))
                        else:
                            preservation_gap = checked_gap
        if not data_paths:
            continue
        for action_id, action in loads:
            load_node = callee.memory_graph.action_nodes[action_id]
            final_segment, final_gap = _transfer_segment(
                callee, proof.final_transfer, callee.analysis.entry, callee.scope_digest, load_node,
            )
            if final_gap is not None:
                continue
            result = preservation.memory_bridge(
                caller, callee, proof.call_operation_key, definition_id, action_id, analysis,
                prefix_mode=prefix_mode,
            )
            if result.status is not MemoryReadBridgeStatus.VERIFIED_MAY:
                if result.gaps:
                    preservation_gap = result.gaps[0]
                continue
            witness = result.witness.report()
            records = [record for record in witness.get("prior_leaf_calls", ())
                       if record["call_operation_key"] == prior.call_operation_key]
            seeds = [seed for seed in caller.analysis.evidence.seeds.callsites
                     if seed.operation_key == prior.call_operation_key]
            if (witness["version"] != (3 if prefix_mode else 2) or len(records) != 1
                    or records[0]["callee_scope"] != prior.callee_scope_digest.hex()
                    or records[0]["callee_observation_digest"]
                        != analysis.evidence.unit.scopes.function.observation_digest.hex()
                    or len(seeds) != 1 or type(seeds[0].target) is not DirectCallTarget
                    or seeds[0].target.coordinate != prior.callee_entry
                    or (not prefix_mode and len(witness["prior_leaf_calls"]) != 1)):
                continue
            for reader_node, read_key, local in data_paths:
                candidates[(state_node, load_node, reader_node, read_key)] = (
                    local, final_segment, witness, reader_node,
                )
                if len(candidates) > 1:
                    return [], None, None, "memory_prior_composition_ambiguous"
    if len(candidates) != 1:
        return [], None, None, (
            "memory_prior_composition_ambiguous" if candidates
            else preservation_gap or "memory_prior_data_path_unavailable"
        )
    local, final_segment, witness, reader_node = next(iter(candidates.values()))
    transfer = {
        "kind": "certified_observed_call_byte_transfer",
        "caller_scope": caller.scope_digest.hex(),
        "call_operation_key": prior.call_operation_key,
        "callee_scope": prior.callee_scope_digest.hex(),
        "callee_write_operation_key": prior.callee_write_operation_key,
        "source_definition_node": source_segment["terminal_definition_node"],
        "target_reader_node": reader_node, "target_span": _span_report(prior.target_span),
    }
    return [{"callee": source_segment, "transfer": transfer, "caller": local}], witness, final_segment, None


def _call_entry_preserved(caller, call_key, callee, span, state_key):
    call_site = None
    for instruction in caller.observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            if _operation_key(instruction.address, ordinal, operation.opcode) == call_key:
                call_site = instruction, ordinal, operation
                break
        if call_site is not None:
            break
    if call_site is None:
        return False
    instruction, ordinal, operation = call_site
    if (operation.opcode != "CALL"
            or ordinal != len(instruction.operations) - 1
            or instruction.flow is None or not instruction.flow.is_call
            or instruction.flow_targets != (callee.analysis.entry,)):
        return False
    seeds = tuple(
        seed for seed in caller.analysis.evidence.seeds.callsites
        if seed.operation_key == call_key
    )
    if (len(seeds) != 1 or type(seeds[0].target) is not DirectCallTarget
            or seeds[0].target.coordinate != callee.analysis.entry):
        return False
    state_position = caller.position(state_key)
    if state_position is None:
        return False
    for key, (position, _) in caller.operations.items():
        if (position <= state_position
                or not caller.may_precede(state_key, key)
                or not caller.may_precede(key, call_key)):
            continue
        effect = caller.storage_actions.get(key)
        if (effect is None
                or any(write.overlaps(span) for write in effect.writes)
                or (span.object_id.kind is StorageObjectKind.ADDRESS_SPACE
                    and effect.unresolved_writes)):
            return False
    return True


def _has_control_cycle(view):
    successors = view._successors
    pending = {block: len(targets) for block, targets in successors.items()}
    predecessors = {block: set() for block in successors}
    for block, targets in successors.items():
        for target in targets:
            if target not in predecessors:
                return True
            predecessors[target].add(block)
    ready = [block for block, count in pending.items() if count == 0]
    removed = 0
    while ready:
        block = ready.pop()
        removed += 1
        for predecessor in predecessors[block]:
            pending[predecessor] -= 1
            if pending[predecessor] == 0:
                ready.append(predecessor)
    return removed != len(successors)


def _transfer_segment(
    callee: _FunctionView,
    transfer: InterproceduralTransferProof,
    start_entry,
    start_scope: bytes,
    start_node: int,
):
    if (start_entry != callee.analysis.entry
            or transfer.callee_entry != callee.analysis.entry
            or start_scope != callee.scope_digest
            or transfer.callee_scope_digest != callee.scope_digest):
        return None, "callee_scope_mismatch"
    graph = callee.normalized.dependencies
    if (graph.node_count > MAX_SEGMENT_NODES
            or graph.edge_count > MAX_SEGMENT_EDGES):
        return None, "callee_graph_budget_exceeded"
    if start_node >= graph.node_count:
        return None, "origin_node_unavailable"
    terminals = tuple(
        (definition_id, span)
        for definition_id, span in callee.terminal_data_writes()
        if (span.contains(transfer.target_span)
            and callee.memory.definitions[definition_id].operation_key
            == transfer.callee_write_operation_key
            and callee.memory.definitions[definition_id].kind
            is MemoryDefinitionKind.DATA_WRITE)
    )
    if len(terminals) != 1:
        return None, "terminal_write_absent_or_ambiguous"
    definition_id, terminal_span = terminals[0]
    terminal_node = callee.memory_graph.definition_nodes[definition_id]
    action_ids = tuple(
        action_id for action_id, action in enumerate(callee.memory.actions)
        if action.operation_key == transfer.callee_write_operation_key
    )
    if len(action_ids) != 1:
        return None, "terminal_action_absent_or_ambiguous"
    action_node = callee.memory_graph.action_nodes[action_ids[0]]
    edges = {}
    successors = {}
    defining = False
    for source, target, record in graph.weighted_edges():
        edge = {
            "source": source, "target": target, "kind": record.kind,
            "operation_key": record.operation, "occurrence": record.occurrence,
            "span": _span_report(record.span),
        }
        edges.setdefault((source, target), []).append(edge)
        successors.setdefault(source, set()).add(target)
        if (source == action_node and target == terminal_node
                and record.kind == "memory_defines"
                and record.operation == transfer.callee_write_operation_key):
            defining = True
    if not defining:
        return None, "terminal_definition_edge_missing"
    path = _shortest_bounded_path(start_node, terminal_node, successors)
    if path is None:
        return None, "callee_origin_to_write_path_missing"
    links = _path_edges(path, edges)
    if links is None:
        return None, "callee_origin_to_write_edge_missing"
    if _has_memory_debt(links):
        return None, "callee_path_memory_debt"
    return {
        "scope": callee.scope_digest.hex(),
        "nodes": path,
        "edges": links,
        "terminal_definition_node": terminal_node,
        "terminal_defining_action_node": action_node,
        "terminal_write_operation_key": transfer.callee_write_operation_key,
        "terminal_write_span": _span_report(terminal_span),
    }, None


def _local_segment(view, start_node, target_node):
    graph = view.normalized.dependencies
    if (graph.node_count > MAX_SEGMENT_NODES
            or graph.edge_count > MAX_SEGMENT_EDGES):
        return None, "local_graph_budget_exceeded"
    edges = {}
    successors = {}
    for source, target, record in graph.weighted_edges():
        edge = {
            "source": source, "target": target, "kind": record.kind,
            "operation_key": record.operation, "occurrence": record.occurrence,
            "span": _span_report(record.span),
        }
        edges.setdefault((source, target), []).append(edge)
        successors.setdefault(source, set()).add(target)
    path = _shortest_bounded_path(start_node, target_node, successors)
    if path is None:
        return None, "local_path_unavailable"
    links = _path_edges(path, edges)
    if links is None or _has_memory_debt(links):
        return None, "local_path_memory_debt"
    return {
        "scope": view.scope_digest.hex(),
        "nodes": path,
        "edges": links,
    }, None


def _shortest_bounded_path(start, target, successors):
    pending = deque(((start, (start,)),))
    seen = {start}
    while pending:
        node, path = pending.popleft()
        if node == target:
            return list(path)
        if len(path) >= MAX_SEGMENT_LENGTH:
            continue
        for successor in sorted(successors.get(node, ())):
            if successor not in seen:
                seen.add(successor)
                pending.append((successor, path + (successor,)))
    return None


def _path_edges(path, edges):
    links = []
    for source, target in zip(path, path[1:]):
        matches = edges.get((source, target), ())
        if not matches:
            return None
        links.append({"source": source, "target": target, "alternatives": matches})
    return links


def _has_memory_debt(links):
    return any(
        edge["kind"].startswith("unresolved_")
        for link in links for edge in link["alternatives"]
    )
