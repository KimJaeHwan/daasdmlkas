"""Query-independent physical call-entry relations over the original SSA.

An entry relation is NOT a return effect, a read-from proof, or a new SSA
activation. It links an exact caller state point to a context-qualified view
of an analyzed body. Unknown writers and unknown targets remain frontiers.
No callee ENTRY definition is equated globally with another call's ENTRY.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import nullcontext
from functools import wraps

from ._scope_contracts import VarnodeKindCode
from .call_seeds import _operation_key
from .memory_contracts import MemoryDefinitionKind
from .observed_call_state import observed_call_state_projections
from .resource_limits import step
from .span_geometry import ByteSpan, StorageObjectKind


@dataclass(frozen=True, slots=True)
class EntrySource:
    """A dependency on existing caller SSA bytes, not unconditional equality."""

    span: ByteSpan
    definition_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class EntryBinding:
    """One context's physical entry port and its original state dependencies.

    ``operation`` describes the entry transition, not an expression summary.
    A nonempty frontier prevents use as a complete value/read-from proof.
    Memory bindings always retain the separate memory-content obligation.
    """

    destination_definition: int
    span: ByteSpan
    operation: str
    sources: tuple[EntrySource, ...] = ()
    delta: int = 0
    literal: int | None = None
    caller_place: ByteSpan | None = None
    frontier: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EntryGraphEdge:
    """Cross-function edge between original dependency-graph node IDs.

    Node IDs are local to their side's exact analysis instance. ``context``
    qualifies the destination body view without copying its local graph.
    """

    context: tuple[str, ...]
    caller_node: int | None
    callee_node: int
    source_span: ByteSpan | None
    destination_span: ByteSpan
    kind: str
    delta: int = 0
    frontier: tuple[str, ...] = ()
    literal: int | None = None
    caller_state_root: int | None = None


def state_sources(ssa, state, requested):
    """Intersect one shared call-state root with tracked bytes; no RD solve."""
    if state is None or state.root_node_id is None:
        return ()
    found, pending = [], [state.root_node_id]
    object_key = requested.object_id
    while pending:
        step()
        node = ssa.call_state_nodes[pending.pop()]
        first, last = ssa.atomic_spans[node.start_atom], ssa.atomic_spans[node.stop_atom - 1]
        span = ByteSpan(first.object_id, first.start, last.end - first.start)
        current_key = span.object_id
        if span.overlaps(requested):
            found.append(EntrySource(span.intersection(requested), node.definition_ids))
        # The arena is an ordered run tree. Avoid visiting every tracked
        # byte when querying one register/slot out of a large function.
        if node.left_node_id is not None and (current_key > object_key
                or current_key == object_key and span.start > requested.start):
            pending.append(node.left_node_id)
        if node.right_node_id is not None and (current_key < object_key
                or current_key == object_key and span.end < requested.end):
            pending.append(node.right_node_id)
    return tuple(sorted(found, key=lambda row: row.span.start))


def _covered(parts, span):
    cursor = span.start
    for part in parts:
        if part.span.object_id != span.object_id or part.span.start != cursor:
            return False
        cursor = part.span.end
    return cursor == span.end


def _clobber_signature(normalized):
    calls, preserved, keeping = normalized.call_clobber_contract or ((), {}, ())
    return frozenset(calls), tuple(sorted((key, tuple(spans)) for key, spans in preserved.items())), frozenset(keeping)


class _EntryIndex:
    """One lazy lookup cache per exact caller, shared by all of its calls."""

    def __init__(self, caller, states, query_context=None):
        self.caller, self.states = caller, states
        self.query_context = query_context or nullcontext
        self.instructions = {row.address: row for row in caller.unit.observation.instructions}
        self.definitions = None
        self.projector = None
        self.clobbers = None
        self.clobber_signature = _clobber_signature(caller.normalized)

    def register_clobbers(self):
        """Query the existing gen/kill engine at the same pre-group phase.

        Only observation reads are added to this immutable view. No SSA
        values, writes, CFG edges, or original analysis result are changed.
        In particular the same static CALL can reach itself via a backedge.
        """
        if self.clobbers is not None:
            return self.clobbers
        from ._call_clobber_sparse import derive_sparse
        from .effects import EFFECT_DECODE_CONTRACT_VERSION, EffectKind, ObservedEffect, ObservedEffectBlock, ObservedEffectUnit
        from .model import ResolvedStorage

        normalized = self.caller.normalized
        snapshots = {state.first_action_key: state for state in normalized.memory_ssa.call_register_snapshots}
        blocks = []
        for block in normalized.memory_unit.blocks:
            effects = []
            for action in block.actions:
                reads = {span for span in action.reads if span.object_id.kind is StorageObjectKind.REGISTER_FILE}
                if action.operation_key in snapshots:
                    reads.update(fragment.span for fragment in snapshots[action.operation_key].fragments)
                effects.append(ObservedEffect(action.operation_key, EffectKind.READ,
                    reads=tuple(ResolvedStorage(span) for span in sorted(reads, key=lambda span: span.canonical_key)),
                    writes=tuple(ResolvedStorage(span) for span in action.writes
                                 if span.object_id.kind is StorageObjectKind.REGISTER_FILE), block_key=block.key))
            blocks.append(ObservedEffectBlock(block.key, block.predecessors, tuple(effects)))
        unit = ObservedEffectUnit(EFFECT_DECODE_CONTRACT_VERSION, normalized.memory_unit.function_scope,
            normalized.memory_unit.entry_block_key, tuple(blocks), normalized.memory_unit.observed_terminal_block_keys,
            effect_evidence_digest=normalized.memory_unit.effect_evidence_digest)
        found = {}

        def observe(effect, calls_at):
            snapshot = snapshots.get(effect.operation_key)
            if snapshot is not None:
                found[snapshot.boundary_key] = {
                    (fragment.span.object_id, offset): calls_at(fragment.span.object_id, offset)
                    for fragment in snapshot.fragments for offset in range(fragment.span.start, fragment.span.end)}

        calls, preserved, keeping = self.clobber_signature
        preserved = dict(preserved)
        derive_sparse(unit, calls, preserved, keeping, observe=observe)
        self.clobbers = found
        return found

    def address_projector(self):
        if self.projector is None:
            from .relative_memory import _Projector
            from .opaque_values import NullOpaqueValueEvidenceProvider, OpaqueValueEvidenceResolver

            unit = self.caller.unit
            operations = {_operation_key(row.address, ordinal, operation.opcode): operation
                          for row in self.instructions.values() for ordinal, operation in enumerate(row.operations)}
            self.projector = _Projector(unit.scopes.resolution_context,
                unit.scopes.program.evidence.address_spaces, self.caller.normalized.memory_ssa, operations,
                OpaqueValueEvidenceResolver(NullOpaqueValueEvidenceProvider()),
                unit.scopes.program.evidence.translation_namespace.language_id)
            self.projector._blocked = frozenset(key for key, operation in operations.items()
                                               if operation.opcode == "LOAD")
        return self.projector


def _in_query_context(method):
    """Base publications pin lazy address queries to their issuing policy.

    Legacy summary relations keep their existing query behavior without
    entering an additional context manager.
    """
    @wraps(method)
    def query(self, *args, **kwargs):
        if self._index.query_context is nullcontext:
            return method(self, *args, **kwargs)
        with self._index.query_context():
            return method(self, *args, **kwargs)
    return query


@dataclass(frozen=True, slots=True)
class CallEntryRelation:
    call: str
    target: str | None
    context: tuple[str, ...]
    body_role: str
    state: object
    projection: object
    frontier: tuple[str, ...]
    _caller: object = field(repr=False, compare=False)
    _callee: object = field(repr=False, compare=False)
    _normalized: object = field(repr=False, compare=False)
    _body_normalized: object = field(repr=False, compare=False)
    _pins: tuple = field(repr=False, compare=False)
    _index: object = field(repr=False, compare=False)

    def _check(self):
        if self._caller.normalized is not self._normalized \
                or self._callee is not None and self._callee.normalized is not self._body_normalized:
            raise ValueError("call entry relation source instance changed")
        current = (self._caller.unit, self._caller.calls.get(self.call),
                   tuple(self._caller.multi_candidates.get(self.call, ())),
                   None if self._callee is None else self._callee.unit,
                   None if self._callee is None else tuple(self._callee.anchors.items()),
                   self.call, self.target, self.context, self.body_role, self.frontier,
                   self.state, self.projection, self._index.query_context)
        if current != self._pins:
            raise ValueError("call entry relation source instance changed")
        if self._index.caller is not self._caller or self.state is not self._index.states.get(self.call):
            raise ValueError("call entry relation state is not the issued SSA boundary")
        if _clobber_signature(self._normalized) != self._index.clobber_signature:
            raise ValueError("call entry relation clobber contract changed")

    @_in_query_context
    def register_binding(self, definition_id, requested=None):
        """Map one callee register ENTRY to the caller state plus raw setup."""
        self._check()
        if self._callee is None or not hasattr(self._body_normalized, "memory_ssa"):
            raise ValueError("call entry body has no SSA")
        if type(definition_id) is not int or not 0 <= definition_id < len(self._body_normalized.memory_ssa.definitions):
            raise ValueError("call entry definition must be an in-range exact int")
        definition = self._body_normalized.memory_ssa.definitions[definition_id]
        span = definition.span if requested is None else requested
        if definition.kind is not MemoryDefinitionKind.ENTRY \
                or span.object_id.kind is not StorageObjectKind.REGISTER_FILE \
                or not definition.span.contains(span):
            raise ValueError("call entry register requires an original register ENTRY")
        requested, delta = span, 0
        if self.projection is not None:
            base = self.projection.memory_transition.caller_base
            stack = ByteSpan(span.object_id, base.byte_offset, base.byte_size)
            if stack.overlaps(span):
                if not stack.contains(span):
                    raise ValueError("entry port crosses a raw transition; use bindings() byte ports")
                # Carry from low bytes can affect any selected SP byte. Keep
                # the entire input, then select the requested output bytes.
                requested = stack
                delta = self.projection.memory_transition.displacement_delta
        sources = state_sources(self._normalized.memory_ssa, self.state, requested) if self.state else ()
        frontier = list(self.frontier)
        if not _covered(sources, requested):
            frontier.append("untracked caller register bytes")
        # A raw reaching definition is not a call-preservation receipt. The
        # graph keeps its dependency, with the unknown effect still visible.
        frontier.extend(self._register_barriers(requested))
        frontier.extend(self._setup_frontiers(requested))
        return EntryBinding(definition_id, span, "add-and-select" if delta else "identity", sources,
                            delta=delta, frontier=tuple(sorted(set(frontier))))

    def _setup_frontiers(self, requested):
        """Unprojected setup, including ARM's link write, must remain in SSA."""
        space, offset, ordinal = self.call.split(':')[:3]
        instruction = next(row for row in self._caller.unit.observation.instructions
                           if row.address.space_id == int(space, 16) and row.address.byte_offset == int(offset, 16))
        skipped = () if self.projection is None else self.projection.transient_operation_keys
        if self._index.definitions is None:
            self._index.definitions = {definition.operation_key
                                      for definition in self._normalized.memory_ssa.definitions
                                      if definition.kind is MemoryDefinitionKind.DATA_WRITE}
        definitions = self._index.definitions
        for index, operation in enumerate(instruction.operations[:int(ordinal)]):
            output = operation.output
            key = _operation_key(instruction.address, index, operation.opcode)
            if output is not None and output.kind is VarnodeKindCode.REGISTER \
                    and output.coordinate.byte_offset < requested.end \
                    and requested.start < output.coordinate.byte_offset + output.byte_size \
                    and key not in skipped and key not in definitions:
                return (f"raw call register setup unavailable at {key}",)
        return ()

    def _register_barriers(self, requested):
        observed = self._index.register_clobbers().get(self.call, {})
        calls = set()
        for offset in range(requested.start, requested.end):
            crossed = observed.get((requested.object_id, offset))
            if crossed is None:
                return ("register clobber observation unavailable",)
            calls.update(crossed)
        return tuple(f"register preservation unresolved at {call}" for call in sorted(calls))

    @_in_query_context
    def memory_binding(self, definition_id, requested=None):
        """Retain physical address/state linkage, separately from content proof."""
        self._check()
        if self._callee is None or not hasattr(self._body_normalized, "memory_ssa"):
            raise ValueError("call entry body has no SSA")
        if type(definition_id) is not int or not 0 <= definition_id < len(self._body_normalized.memory_ssa.definitions):
            raise ValueError("call entry definition must be an in-range exact int")
        definition = self._body_normalized.memory_ssa.definitions[definition_id]
        span = definition.span if requested is None else requested
        if definition.kind is not MemoryDefinitionKind.ENTRY \
                or span.object_id.kind not in (StorageObjectKind.ADDRESS_SPACE,
                                               StorageObjectKind.FUNCTION_RELATIVE) \
                or not definition.span.contains(span):
            raise ValueError("call entry memory requires an original memory ENTRY")
        frontier = list(self.frontier)
        place, literal = self._memory_place(span)
        if literal is not None:
            return EntryBinding(definition_id, span, "observed-call-store", literal=literal,
                                caller_place=place, frontier=tuple(sorted(set(frontier))))
        if place is None:
            frontier.append("entry memory address correspondence unresolved")
            return EntryBinding(definition_id, span, "memory-state", frontier=tuple(sorted(set(frontier))))
        sources = state_sources(self._normalized.memory_ssa, self.state, place) if self.state else ()
        if not _covered(sources, place):
            frontier.append("untracked caller memory bytes")
        # State observations do not remove may-alias writers, opaque calls,
        # open conditions, or partial-write debts from either original graph.
        frontier.append("memory content requires original writer/alias conditions")
        return EntryBinding(definition_id, span, "memory-state", sources,
                            caller_place=place, frontier=tuple(sorted(set(frontier))))

    def _upstream_debt(self, definition_ids) -> bool:
        """Any debt (call clobber, unresolved read, may-alias, ...) in the
        backward slice of the caller definitions that give the register."""
        from .graph_contracts import NodeKind

        graph, nodes = self._normalized.dependencies, self._normalized.memory_graph.definition_nodes
        seeds = tuple(nodes[identifier] for identifier in definition_ids)
        return any(graph.node(node).kind is NodeKind.MEMORY_DEBT for node in graph.backward_reachable(seeds))

    def _memory_place(self, span):
        if span.object_id.kind is StorageObjectKind.ADDRESS_SPACE:
            return span, None
        anchor = self._callee.anchors.get(span.object_id)
        if anchor is None or anchor[0].object_id.kind is not StorageObjectKind.REGISTER_FILE:
            return None, None
        register, space = anchor
        bits = 8 * register.size
        displacement = span.start - (1 << bits)
        # This literal is established by the raw call-local STORE even when
        # the caller's actual SP value has no materialized SSA source.
        if self.projection is not None:
            base = self.projection.memory_transition.callee_base
            width = base.byte_size
            if (register.start, register.size) == (base.byte_offset, width) \
                    and space == self.projection.transient_coordinate.coordinate.space_id \
                    and 0 <= displacement and displacement + span.size <= width:
                little = ":LE:" in self._caller.unit.scopes.program.evidence.translation_namespace.language_id
                shift = 8 * (displacement if little else width - displacement - span.size)
                value = self.projection.transient_coordinate.coordinate.byte_offset
                return None, (value >> shift) & ((1 << (8 * span.size)) - 1)
        if self._register_barriers(register):
            return None, None
        # Reuse the existing address-expression interpreter. All LOADs are
        # blocked here: their content proof belongs to the memory consumer.
        from .relative_memory import _AddressExpression, _relative_start, _unsigned_wrap
        from .model import StorageObjectId

        ssa, unit = self._normalized.memory_ssa, self._caller.unit
        sources = state_sources(ssa, self.state, register) if self.state else ()
        if len(sources) != 1 or not _covered(sources, register):
            return None, None
        if self._upstream_debt(sources[0].definition_ids):
            # (review fix, Astra P1-2) the register's own clobber is cleared by its last write, but that
            # write's inputs may come through an opaque call / unresolved read: no address correspondence
            return None, None
        projector = self._index.address_projector()
        expressions = [projector._expression_for_definition(identifier, register)
                       for identifier in sources[0].definition_ids]
        if not expressions or expressions[0] is None or any(value != expressions[0] for value in expressions):
            return None, None
        expression = expressions[0]
        delta = 0
        if self.projection is not None:
            base = self.projection.memory_transition.callee_base
            if (register.start, register.size) == (base.byte_offset, base.byte_size):
                delta = self.projection.memory_transition.displacement_delta
        total = expression.displacement + displacement + delta
        address = _AddressExpression(expression.atoms, total, expression.byte_size, expression.image)
        if not address.atoms:
            start = _unsigned_wrap(total, expression.byte_size)
            if start + span.size > 1 << bits:
                return None, None
            place = ByteSpan(StorageObjectId(StorageObjectKind.ADDRESS_SPACE,
                                             unit.scopes.program.scope, space), start, span.size)
        else:
            start = _relative_start(total, bits, span.size)
            if start is None:
                return None, None
            place = ByteSpan(projector._relative_object(address, space, width=span.size), start, span.size)
        # The raw x86 return-address STORE is the only synthetic literal
        # admitted here. Partial overlap is kept unresolved, never discarded.
        if self.projection is not None and delta:
            width = self.projection.memory_transition.callee_base.byte_size
            if displacement < width and 0 < displacement + span.size:
                return None, None
        return place, None

    @_in_query_context
    def bindings(self):
        """All original callee ENTRY ports, not a selected sink's demand."""
        self._check()
        if self._callee is None or not hasattr(self._body_normalized, "memory_ssa"):
            return ()
        rows = []
        for identifier, definition in enumerate(self._body_normalized.memory_ssa.definitions):
            if definition.kind is not MemoryDefinitionKind.ENTRY:
                continue
            if definition.span.object_id.kind is StorageObjectKind.REGISTER_FILE:
                cuts = [definition.span.start, definition.span.end]
                if self.projection is not None:
                    base = self.projection.memory_transition.callee_base
                    cuts.extend(point for point in (base.byte_offset, base.byte_offset + base.byte_size)
                                if definition.span.start < point < definition.span.end)
                points = sorted(set(cuts))
                rows.extend(self.register_binding(identifier, ByteSpan(definition.span.object_id, low, high - low))
                            for low, high in zip(points, points[1:]))
            elif definition.span.object_id.kind in (StorageObjectKind.ADDRESS_SPACE,
                                                    StorageObjectKind.FUNCTION_RELATIVE):
                cuts = [definition.span.start, definition.span.end]
                anchor = self._callee.anchors.get(definition.span.object_id)
                if self.projection is not None and anchor is not None:
                    base = self.projection.memory_transition.callee_base
                    if (anchor[0].start, anchor[0].size) == (base.byte_offset, base.byte_size):
                        bias = 1 << (8 * base.byte_size)
                        cuts.extend(point for point in (bias, bias + base.byte_size)
                                    if definition.span.start < point < definition.span.end)
                points = sorted(set(cuts))
                rows.extend(self.memory_binding(identifier, ByteSpan(definition.span.object_id, low, high - low))
                            for low, high in zip(points, points[1:]))
        return tuple(rows)

    @_in_query_context
    def edges(self):
        """Expose real SSA-to-SSA dependencies; memory edges are not read-from."""
        rows = []
        for binding in self.bindings():
            destination = self._body_normalized.memory_graph.definition_nodes[binding.destination_definition]
            # An untracked byte still has a physical input port. Keep the
            # state-point relation and its frontier instead of dropping the
            # callee ENTRY merely because no caller definition was observed.
            rows.append(EntryGraphEdge(self.context, None, destination, None, binding.span,
                "call-entry-state-point", frontier=binding.frontier,
                caller_state_root=None if self.state is None else self.state.root_node_id))
            if binding.literal is not None:
                witness = self.projection.transient_operation_keys[-1]
                node = self._normalized.dependencies.node_for_key(f"op:{witness}")
                if node is None:
                    node = self._normalized.dependencies.node_for_key(f"op:{self.call}")
                if node is not None:
                    rows.append(EntryGraphEdge(self.context, node, destination, None, binding.span,
                        "call-entry-observed-store", frontier=binding.frontier, literal=binding.literal))
            for source in binding.sources:
                destination_part, frontier = binding.span, binding.frontier
                if binding.operation == "identity":
                    destination_part = source.span
                    frontier = self.register_binding(binding.destination_definition, source.span).frontier
                elif binding.caller_place is not None:
                    destination_part = ByteSpan(binding.span.object_id,
                        binding.span.start + source.span.start - binding.caller_place.start, source.span.size)
                for identifier in source.definition_ids:
                    rows.append(EntryGraphEdge(self.context,
                        self._normalized.memory_graph.definition_nodes[identifier], destination,
                        source.span, destination_part,
                        "call-entry-register" if binding.span.object_id.kind is StorageObjectKind.REGISTER_FILE
                        else "call-entry-memory-state", binding.delta, frontier))
        return tuple(rows)


def connect_call_entries(results, *, query_context=None):
    """Publish a small graph overlay; no inlining, summary changes, or RAM copy."""
    from .interprocedural import _retained_instances
    from .normalize import NormalizedFunction
    from uuid import uuid4

    instances = _retained_instances(results)
    publication = uuid4().hex
    identities = {id(item): f"{publication}:{index}" for index, item in enumerate(instances)}
    for caller in instances:
        normalized = caller.normalized
        if type(normalized) is not NormalizedFunction:
            caller.entry_relations = ()
            continue
        states = {state.boundary_key: state for state in normalized.memory_ssa.call_memory_states}
        index = _EntryIndex(caller, states, query_context)
        projections = {row.call_operation_key: row for row in observed_call_state_projections(caller.unit.observation)}
        raw_calls = {_operation_key(row.address, ordinal, operation.opcode): operation
                     for row in caller.unit.observation.instructions for ordinal, operation in enumerate(row.operations)
                     if operation.opcode in ("CALL", "CALLIND")}
        rows = []
        for call in sorted(raw_calls):
            step()
            targets = (caller.calls[call],) if call in caller.calls else tuple(caller.multi_candidates.get(call, ()))
            raw = raw_calls[call]
            if not targets and raw.opcode == "CALL" and raw.inputs \
                    and raw.inputs[0].kind is VarnodeKindCode.ADDRESS:
                at = raw.inputs[0].coordinate
                targets = (f"{at.space_id:x}:{at.byte_offset:x}",)
            for target in targets or (None,):
                consumed = [item for item in caller.consumed.get(call, ())
                            if getattr(item, "key", None) == target]
                callee = consumed[0] if len(consumed) == 1 else results.get(target)
                body = None if callee is None else callee.normalized
                frontier = []
                if target is None:
                    frontier.append("call target unresolved")
                elif callee is None or type(body) is not NormalizedFunction:
                    frontier.append("analyzed callee body unavailable")
                if states.get(call) is None:
                    frontier.append("normalized call state unavailable")
                if len(targets) > 1:
                    frontier.append("conditional target alternative")
                context = (identities[id(caller)], caller.key, normalized.memory_ssa.unit_digest.hex(),
                           call, target or "unknown", identities.get(id(callee), "unavailable"),
                           body.memory_ssa.unit_digest.hex() if type(body) is NormalizedFunction else "unavailable")
                role = "consumed-body" if len(consumed) == 1 else "generic-entry-body"
                pins = (caller.unit, caller.calls.get(call), tuple(caller.multi_candidates.get(call, ())),
                        None if callee is None else callee.unit,
                        None if callee is None else tuple(callee.anchors.items()),
                        call, target, context, role, tuple(frontier), states.get(call), projections.get(call),
                        index.query_context)
                rows.append(CallEntryRelation(call, target, context,
                    role,
                    states.get(call), projections.get(call), tuple(frontier), caller, callee, normalized, body,
                    pins, index))
        caller.entry_relations = tuple(rows)
    return results


__all__ = ("CallEntryRelation", "EntryBinding", "EntryGraphEdge", "EntrySource", "connect_call_entries",
           "state_sources")
