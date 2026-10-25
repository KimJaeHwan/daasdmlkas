"""Structural loop recurrences over the ORIGINAL CFG and captured SSA edges.

No reaching definitions, execution, trip count or induction-variable algebra
is computed here. A JOIN's block is its read location, not a loop header.
Only a single-entry, single-latch cyclic region whose original header edges
separate one initial raw definition from one transition raw definition is
described. Missing evidence is a fallback, never an inferred predecessor.

Integration: add ``RecurrenceIndex.condition_seeds()`` before the record's
first lane_slice, retain that index as ``builder.recurrences``, then call
``annotate_recurrence`` after _phi_join's _condition and before _done.
The existing alternatives, loop flags and evaluation behavior stay intact.
"""

from __future__ import annotations

from collections import deque
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256

from ._sparse_dataflow import DominatorGraph
from .call_seeds import _operation_key
from .memory_contracts import MemoryDefinitionKind, MemoryFlowEdge
from .pcode_blocks import build_pcode_block_graph
from .resource_limits import step
from .span_geometry import ByteSpan


@dataclass(frozen=True, slots=True)
class RecurrenceCondition:
    operation: str
    block: str
    true_successor: str
    false_successor: str
    branch_node: int
    action_id: int


@dataclass(frozen=True, slots=True)
class RecurrenceMatch:
    span: ByteSpan
    header: str
    latch: str
    blocks: tuple[str, ...]
    read_block: str
    init_definition_id: int
    transition_definition_id: int
    init_edges: tuple[MemoryFlowEdge, ...]
    transition_edges: tuple[MemoryFlowEdge, ...]
    conditions: tuple[RecurrenceCondition, ...]
    exits: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class _Loop:
    header: str
    latch: str
    preheader: str
    blocks: tuple[str, ...]
    conditions: tuple[RecurrenceCondition, ...]
    exits: tuple[tuple[str, str], ...]


class _DominanceOnly(DominatorGraph):
    """The existing budgeted dominator tree, without unused SSA frontiers.

    No recurrence consumer may solve dataflow through this diagnostic view.
    """

    def _frontiers(self):
        return {}

    def solve(self, *args, **kwargs):
        raise AssertionError('recurrence metadata cannot solve dataflow')

    def dominates(self, upper, lower):
        step()
        return self._dominates(upper, lower)


class RecurrenceIndex:
    """Budgeted record-only correspondence; cached results include failures.

    ``for_join`` returns ``(match, None)``, ``(None, reason)`` for a related
    unsupported cycle, or ``(None, None)`` for an ordinary acyclic JOIN.
    Dominance reuses the existing dominator implementation, never its SSA or
    dataflow solve. All value definitions come from ssa.flow_edges/joins.
    """

    def __init__(self, normalized, unit, index):
        self.normalized, self.unit, self.index = normalized, unit, index
        self.ssa = index.ssa
        self._matches, self._loops = {}, {}
        self.blocks, self.predecessors, self._components, self._component_of = {}, {}, (), {}
        self._raw_blocks, self._conditions, self._condition_reasons = {}, {}, {}
        self._flow, self._reason, self._dominators = {}, None, None
        self._seeds = ()
        if not index.joins:
            return
        step(len(unit.observation.instructions) + sum(len(row.operations) for row in unit.observation.instructions))
        self.instructions = {row.address: row for row in unit.observation.instructions}
        graph = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
        self.entry = graph.entry
        self.blocks = {block.key: block for block in graph.blocks}
        if graph.unsupported is not None or not self.blocks:
            self._reason = 'unsupported original cfg'
            return
        self.predecessors = {key: set() for key in self.blocks}
        self._segments = {}
        for block in graph.blocks:
            step(1 + len(block.successors) + block.stop - block.start)
            for target in block.successors:
                self.predecessors[target].add(block.key)
            row = self.instructions[block.instruction]
            for ordinal in range(block.start, block.stop):
                self._segments[block.instruction, ordinal] = block.key
                self._raw_blocks[_operation_key(row.address, ordinal, row.operations[ordinal].opcode)] = block.key
        self._components = tuple(component for component in self._sccs()
                                 if len(component) > 1 or component[0] in self.blocks[component[0]].successors)
        for number, component in enumerate(self._components):
            for key in component:
                step()
                self._component_of[key] = number
        if not self._components:
            return
        memory = normalized.memory_unit
        if memory is None or memory.entry_block_key != self.entry \
                or {block.key for block in memory.blocks} != set(self.blocks):
            self._reason = 'ssa cfg does not match original cfg'
            return
        for block in memory.blocks:
            step(1 + len(block.predecessors))
            if set(block.predecessors) != self.predecessors[block.key]:
                self._reason = 'ssa cfg does not match original cfg'
                return
        # Existing work-budgeted dominance, not a new RD/SSA computation.
        # Frontiers are deliberately omitted: only dominates() is consumed.
        step(len(self.blocks) + sum(len(row.successors) for row in self.blocks.values()))
        self._dominators = _DominanceOnly(
            self.entry, {key: tuple(sorted(self.predecessors[key])) for key in self.blocks})
        seeds = []
        for number, component in enumerate(self._components):
            for key in component:
                block = self.blocks[key]
                row = self.instructions[block.instruction]
                if not block.stop or row.operations[block.stop - 1].opcode != 'CBRANCH':
                    continue
                match, reason = self._condition(block)
                if reason is not None:
                    self._condition_reasons[number] = reason
                else:
                    self._conditions[key] = match
                    seeds.append((match.branch_node, ()))
        self._seeds = tuple(sorted(set(seeds)))
        for edge in self.ssa.flow_edges:
            step()
            self._flow.setdefault((edge.block_key, edge.predecessor_key), []).append(edge)

    def _sccs(self):
        """Iterative linear graph walks, never a recursion over loop states."""
        order, seen = [], set()
        for start in self.blocks:
            if start in seen:
                continue
            seen.add(start)
            stack = [(start, iter(self.blocks[start].successors))]
            while stack:
                step()
                key, children = stack[-1]
                for target in children:
                    step()
                    if target not in seen:
                        seen.add(target)
                        stack.append((target, iter(self.blocks[target].successors)))
                        break
                else:
                    stack.pop()
                    order.append(key)
        assigned = set()
        for start in reversed(order):
            if start in assigned:
                continue
            component, pending = [], [start]
            while pending:
                step()
                key = pending.pop()
                if key in assigned:
                    continue
                assigned.add(key)
                component.append(key)
                pending.extend(sorted(self.predecessors[key] - assigned, reverse=True))
            yield tuple(sorted(component))

    def condition_seeds(self):
        """Original cyclic-region CBRANCH nodes for the existing lane walk."""
        return self._seeds

    def _condition(self, block):
        # Reuse exactly the existing p-code relative/address polarity decoder.
        from ._record_conditions import ConditionIndex

        operation = self.instructions[block.instruction].operations[block.stop - 1]
        yes = ConditionIndex._target(self, block, operation)
        no = ConditionIndex._fallthrough(self, block)
        if len(operation.inputs) != 2 or yes is None or no is None or yes == no \
                or set(block.successors) != {yes, no} or block.exits:
            return None, 'unresolved original loop condition'
        key = _operation_key(block.instruction, block.stop - 1, operation.opcode)
        node = self.normalized.dependencies.node_for_key('op:' + key)
        action = self.index.action_of.get(node)
        if node is None or action is None or self.index.operation(action) is None:
            return None, 'missing original loop condition'
        return RecurrenceCondition(key, block.key, yes, no, node, action), None

    def _loop(self, number):
        if number in self._loops:
            return self._loops[number]
        result = self._prove_loop(number)
        self._loops[number] = result
        return result

    def _prove_loop(self, number):
        component = self._components[number]
        members = frozenset(component)
        heads = {key for key in component if key == self.entry or self.predecessors[key] - members}
        if len(heads) != 1:
            return None, 'irreducible cyclic region'
        (header,) = heads
        if not all(self._dominators.dominates(header, key) for key in component):
            return None, 'loop header does not dominate region'
        latches = self.predecessors[header] & members
        if len(latches) != 1:
            return None, 'multiple loop latches'
        (latch,) = latches
        initial = self.predecessors[header] - members
        if not initial:
            return None, 'no original initial predecessor'
        if len(initial) != 1:
            return None, 'multiple initial predecessors'
        (preheader,) = initial
        # A single SCC may contain nested loops. Removing the sole admitted
        # backedge must leave a DAG; one natural-loop claim is not a summary
        # of another cyclic region.
        degree = {key: len(self.predecessors[key] & members) - int(key == header) for key in component}
        pending = deque(key for key in component if degree[key] == 0)
        visited = 0
        while pending:
            step()
            key = pending.popleft()
            visited += 1
            for target in self.blocks[key].successors:
                step()
                if target not in members or (key, target) == (latch, header):
                    continue
                degree[target] -= 1
                if degree[target] == 0:
                    pending.append(target)
        if visited != len(component):
            return None, 'nested cyclic region'
        if number in self._condition_reasons:
            return None, self._condition_reasons[number]
        conditions = tuple(self._conditions[key] for key in component if key in self._conditions)
        exits = tuple((key, target) for key in component for target in self.blocks[key].successors
                      if target not in members)
        if not conditions or not exits or any(self.blocks[key].exits for key in component):
            return None, 'no complete original conditional exit'
        if any(len(self.blocks[key].successors) > 1 and key not in self._conditions for key in component):
            return None, 'unsupported original loop control'
        return _Loop(header, latch, preheader, component, conditions, exits), None

    def for_join(self, definition_id):
        if definition_id in self._matches:
            return self._matches[definition_id]
        result = self._match(definition_id)
        self._matches[definition_id] = result
        return result

    def _match(self, definition_id):
        step()
        definition = self.ssa.definitions[definition_id]
        sources = self.index.joins.get(definition_id, ())
        if definition.kind is not MemoryDefinitionKind.JOIN or not sources:
            return None, None
        regions = {self._component_of[key] for key in (definition.block_key, *(
            self._raw_blocks.get(self.ssa.definitions[source].operation_key,
                                 self._raw_blocks.get((self.ssa.definitions[source].operation_key or '').partition('~')[0]))
            for source in sources)) if key in self._component_of}
        if not regions:
            return None, None
        if self._reason is not None:
            return None, self._reason
        if len(regions) != 1:
            return None, 'multiple cyclic source regions'
        loop, reason = self._loop(next(iter(regions)))
        if loop is None:
            return None, reason
        if definition.block_key not in self.blocks \
                or not self._dominators.dominates(loop.header, definition.block_key):
            return None, 'loop header does not dominate read'
        if len(sources) != 2:
            return None, 'nonbinary recurrence sources'
        edges = []
        for predecessor in (loop.preheader, loop.latch):
            if predecessor not in self.predecessors[loop.header]:
                return None, 'flow edge is not original cfg edge'
            rows = tuple(edge for edge in self._flow.get((loop.header, predecessor), ())
                         if edge.span.overlaps(definition.span))
            selected, reason = self._edge_source(rows, definition.span)
            if selected is None:
                return None, reason
            edges.append((selected, rows))
        initial, transition = edges[0][0], edges[1][0]
        if initial == transition or {initial, transition} != set(sources):
            return None, 'header source union mismatch'
        for source in (initial, transition):
            raw = self.ssa.definitions[source]
            if raw.kind not in (MemoryDefinitionKind.ENTRY, MemoryDefinitionKind.DATA_WRITE) \
                    or not raw.span.contains(definition.span):
                return None, 'unsupported recurrence definition'
        first, after = self.ssa.definitions[initial], self.ssa.definitions[transition]
        before_block = first.block_key if first.kind is MemoryDefinitionKind.ENTRY \
            else self._raw_blocks.get(first.operation_key)
        after_block = self._raw_blocks.get(after.operation_key)
        if before_block is None or before_block in loop.blocks \
                or not self._dominators.dominates(before_block, loop.preheader):
            return None, 'initial definition is not before loop'
        if after.kind is not MemoryDefinitionKind.DATA_WRITE or after_block not in loop.blocks \
                or not self._dominators.dominates(after_block, loop.latch):
            return None, 'transition definition is not on latch path'
        return RecurrenceMatch(definition.span, loop.header, loop.latch, loop.blocks, definition.block_key,
                               initial, transition, edges[0][1], edges[1][1], loop.conditions, loop.exits), None

    def _edge_source(self, rows, span):
        if not rows:
            return None, 'missing original header flow evidence'
        position, definitions = span.start, set()
        for edge in sorted(rows, key=lambda row: row.span.start):
            step()
            if edge.predecessor_key not in self.predecessors.get(edge.block_key, ()):
                return None, 'flow edge is not original cfg edge'
            start, end = max(edge.span.start, span.start), min(edge.span.end, span.end)
            if start != position or end <= start:
                return None, 'incomplete header flow span'
            position = end
            definitions.update(edge.definition_ids)
        if position != span.end:
            return None, 'incomplete header flow span'
        if len(definitions) != 1:
            return None, 'non-singleton header edge definitions'
        return next(iter(definitions)), None


def annotate_recurrence(builder, record, definition_id, depth):
    """Add evidence only; never rewrite existing phi or evaluation fields."""
    if 'recurrence' in record:
        return
    index = getattr(builder, 'recurrences', None)
    if index is None:
        index = builder.recurrences = RecurrenceIndex(builder.normalized, builder.unit, builder.index)
    match, reason = index.for_join(definition_id)
    if match is None:
        if reason is None and any(part.get('loop') for part in record['alternatives']):
            reason = index._reason or 'no proven original recurrence region'
        if reason is not None:
            record['recurrence_fallback'] = reason
        return
    alternatives = {part.get('definition_ref', {}).get('id'): part for part in record['alternatives']}
    if len(alternatives) != 2 or any(source not in alternatives for source in (
            match.init_definition_id, match.transition_definition_id)):
        record['recurrence_fallback'] = 'missing original recurrence alternatives'
        return
    scope, unit = builder.ssa.function_scope.digest.hex(), builder.ssa.unit_digest.hex()
    span_id = sha256('\0'.join(match.span.canonical_key).encode()).hexdigest()
    identity = '/'.join(('recurrence', scope, unit, *(call for _, call in builder.path), match.header, span_id))

    def relation(identifier, edges):
        builder._edge()
        rows = []
        for edge in edges:
            step()
            rows.append(dict(predecessor=edge.predecessor_key, block=edge.block_key,
                             span=list(edge.span.canonical_key), definition_ids=list(edge.definition_ids)))
        return dict(edges=rows, definition_ref=builder._definition_ref(identifier),
                    part=deepcopy(alternatives[identifier]))

    conditions = []
    cache = getattr(builder, '_recurrence_operands', None)
    if cache is None:
        cache = builder._recurrence_operands = {}
    for condition in match.conditions:
        step()
        operand = cache.get(condition.operation)
        if operand is None:
            operation, spans, _ = builder.index.operation(condition.action_id)
            # Install the shared holder before walking operands: that walk may
            # re-enter another JOIN of this same recurrence. Only node IDs,
            # not Python objects, point back into the value expression graph.
            operand = cache[condition.operation] = dict(width=operation.inputs[1].byte_size,
                                                        parts=[], unresolved=True)
            prior, builder.building_condition = builder.building_condition, True
            try:
                found = builder._operands(condition.branch_node, condition.action_id, operation, spans, depth + 1)
                selected = next(item for item in found if item['index'] == 1)
                operand.clear()
                operand.update(deepcopy(selected))
            finally:
                builder.building_condition = prior
                # This cache is reentry protection, not a persistent value
                # cache. A stitch transaction may roll its new nodes back;
                # no completed holder may retain their IDs for a later try.
                cache.pop(condition.operation, None)
        builder._edge()
        conditions.append(dict(operation=condition.operation, block=condition.block,
                               true_successor=condition.true_successor, false_successor=condition.false_successor,
                               operand=operand))
    record['recurrence'] = dict(
        id=identity, kind='single_latch', scope=scope, unit=unit, header=match.header, latch=match.latch,
        blocks=list(match.blocks), read_block=match.read_block, span=list(match.span.canonical_key),
        init=relation(match.init_definition_id, match.init_edges),
        transition=relation(match.transition_definition_id, match.transition_edges), conditions=conditions,
        exits=[dict(predecessor=source, successor=target) for source, target in match.exits],
        evaluation='structural_only')
