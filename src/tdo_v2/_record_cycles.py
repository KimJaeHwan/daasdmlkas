"""General finite cyclic expression graphs over the existing CFG and SSA.

This is a projection, not a loop recognizer or another dataflow solve. All
observed edges and captured predecessor definition sets survive. SCC and
entry-stripping hierarchy are structural views, never an execution schedule.
Predicates are per-visit expressions, not invariant Boolean assignments.
"""

from __future__ import annotations

from hashlib import sha256

from ._scope_contracts import VarnodeKindCode
from .call_seeds import _operation_key
from .memory_contracts import MemoryDefinitionKind
from .model import NonStorage, ResolvedStorage, StorageRef, UnresolvedStorage
from .pcode_blocks import build_pcode_block_graph
from .resource_limits import step


class CycleIndex:
    def __init__(self, normalized, unit, index):
        self.normalized, self.unit, self.index = normalized, unit, index
        self.ssa = index.ssa
        self.instructions = {row.address: row for row in unit.observation.instructions}
        step(len(self.instructions) + sum(len(row.operations) for row in self.instructions.values()))
        self.cfg = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
        self.blocks = {block.key: block for block in self.cfg.blocks}
        self.predecessors = {key: set() for key in self.blocks}
        self.raw, self.locations, self._segments = {}, {}, {}
        for block in self.cfg.blocks:
            step(1 + len(block.successors) + block.stop - block.start)
            for successor in block.successors:
                self.predecessors[successor].add(block.key)
            row = self.instructions[block.instruction]
            for ordinal in range(block.start, block.stop):
                operation = row.operations[ordinal]
                key = _operation_key(row.address, ordinal, operation.opcode)
                self.raw[key] = operation
                self.locations[key] = block.key
                self._segments[block.instruction, ordinal] = block.key
        self.components = tuple(self.sccs(frozenset(self.blocks)))
        self.cyclic = tuple(component for component in self.components if self.is_cyclic(component))
        memory = normalized.memory_unit
        self.ssa_matches = bool(memory is not None and memory.entry_block_key == self.cfg.entry
                                and {block.key for block in memory.blocks} == set(self.blocks))
        if self.ssa_matches:
            for block in memory.blocks:
                step(1 + len(block.predecessors))
                if set(block.predecessors) != self.predecessors[block.key]:
                    self.ssa_matches = False
                    break
        self.flow_by_edge = {}
        for flow in self.ssa.flow_edges:
            step()
            self.flow_by_edge.setdefault((flow.predecessor_key, flow.block_key), []).append(flow)

    def is_cyclic(self, component):
        return len(component) > 1 or bool(component and component[0] in self.blocks[component[0]].successors)

    def sccs(self, members):
        """Iterative SCC walk on an induced subgraph, charged to work budget."""
        seen, order = set(), []
        for start in sorted(members):
            if start in seen:
                continue
            seen.add(start)
            stack = [(start, iter(self.blocks[start].successors))]
            while stack:
                step()
                key, targets = stack[-1]
                for target in targets:
                    step()
                    if target in members and target not in seen:
                        seen.add(target)
                        stack.append((target, iter(self.blocks[target].successors)))
                        break
                else:
                    order.append(key)
                    stack.pop()
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
                step(len(self.predecessors[key]))
                assigned.add(key)
                component.append(key)
                pending.extend(sorted((self.predecessors[key] & members) - assigned, reverse=True))
            yield tuple(sorted(component))

    def seeds(self):
        """Full existing expression inputs for this function, not new SSA."""
        step(len(self.index.action_of) + len(self.index.definition_node))
        seeds = [(node, ()) for node in self.index.action_of]
        seeds.extend((node, ()) for node in self.index.definition_node)
        return seeds

    def outline(self, builder):
        from ._record_conditions import ConditionIndex

        scope, unit = self.ssa.function_scope.digest.hex(), self.ssa.unit_digest.hex()
        identity = '/'.join(('cycle', scope, unit, *(call for _, call in builder.path)))
        edges = []
        for block in self.cfg.blocks:
            for target in block.successors:
                step()
                edges.append(dict(source=block.key, target=target, outcomes=[]))
        edge_ids = {(row['source'], row['target']): i for i, row in enumerate(edges)}
        predicates = []
        for key, operation in self.raw.items():
            if operation.opcode != 'CBRANCH':
                continue
            block = self.blocks[self.locations[key]]
            # Reuse the existing raw relative/address polarity decoder. It
            # needs no acyclic reach computation or ControlPool assignment.
            yes = ConditionIndex._target(self, block, operation)
            no = ConditionIndex._fallthrough(self, block)
            predicate = dict(operation=key, block=block.key, true_target=yes, false_target=no,
                             operand=None, evaluation='per_visit_expression')
            for target, outcome in ((yes, True), (no, False)):
                edge = edge_ids.get((block.key, target))
                if edge is not None:
                    edges[edge]['outcomes'].append(dict(predicate=key, value=outcome))
            predicates.append(predicate)
        components = []
        component_of = {}
        for number, members in enumerate(self.components):
            for key in members:
                component_of[key] = number
            components.append(dict(id=number, blocks=list(members), cyclic=self.is_cyclic(members), successors=[]))
        for row in components:
            step(sum(1 + len(self.blocks[key].successors) for key in row['blocks']))
            row['successors'] = sorted({component_of[target] for key in row['blocks']
                                        for target in self.blocks[key].successors
                                        if component_of[target] != row['id']})
        hierarchy, pending = [], [(None, component) for component in reversed(self.cyclic)]
        while pending:
            step()
            parent, members_tuple = pending.pop()
            members = frozenset(members_tuple)
            step(3 * len(edges) + len(members))
            entrances = [i for i, row in enumerate(edges) if row['target'] in members and row['source'] not in members]
            exits = [i for i, row in enumerate(edges) if row['source'] in members and row['target'] not in members]
            points = {edges[i]['target'] for i in entrances}
            if self.cfg.entry in members:
                points.add(self.cfg.entry)
            # Every reachable SCC has an entry or includes function entry.
            # A deterministic pivot is only a decomposition aid, not a head.
            removed = points or {min(members)}
            identifier = len(hierarchy)
            region = dict(id=identifier, parent=parent, blocks=list(members_tuple),
                          entry_points=sorted(points), entry_edges=entrances, exit_edges=exits,
                          internal_edges=[i for i, row in enumerate(edges)
                                          if row['source'] in members and row['target'] in members],
                          children=[], removed_for_children=sorted(removed),
                          decomposition_basis='entry-stripping-scc')
            hierarchy.append(region)
            if parent is not None:
                hierarchy[parent]['children'].append(identifier)
            children = [component for component in self.sccs(members - removed) if self.is_cyclic(component)]
            pending.extend((identifier, component) for component in reversed(children))
        facts = {(row['source'], row['target']): [] for row in edges}
        for flow in self.ssa.flow_edges:
            step()
            if (flow.predecessor_key, flow.block_key) in facts:
                facts[flow.predecessor_key, flow.block_key].append(dict(
                    span=list(flow.span.canonical_key), definition_ids=list(flow.definition_ids), definitions=[]))
        states = [dict(edge=i, evidence='captured' if facts[row['source'], row['target']] else 'not_captured',
                       facts=facts[row['source'], row['target']]) for i, row in enumerate(edges)]
        digest = sha256(repr((self.cfg.entry, tuple(
            (block.key, block.start, block.stop, block.successors) for block in self.cfg.blocks),
            tuple(self.raw))).encode()).hexdigest()
        unresolved = []
        for access_kind, occurrences in (('read', self.ssa.unresolved_reads), ('write', self.ssa.unresolved_writes)):
            for occurrence in occurrences:
                step()
                access = occurrence.access
                unresolved.append(dict(kind=access_kind, action_id=occurrence.action_id,
                                       operation=self.ssa.actions[occurrence.action_id].operation_key,
                                       occurrence_ordinal=occurrence.occurrence_ordinal, width=access.width,
                                       address=_storage(access.address), raw_address=_storage(access.raw_address), node=None))
        unknowns = dict(entry_definitions=0, kill_definitions=0, unresolved_reads=len(self.ssa.unresolved_reads),
                        unresolved_writes=len(self.ssa.unresolved_writes), projection_debt_nodes=None)
        for definition in self.ssa.definitions:
            step()
            if definition.kind is MemoryDefinitionKind.ENTRY:
                unknowns['entry_definitions'] += 1
            elif definition.kind is MemoryDefinitionKind.KILL:
                unknowns['kill_definitions'] += 1
        return dict(id=identity, scope=scope, unit=unit, call_path=[call for _, call in builder.path],
                    cfg=dict(entry=self.cfg.entry, blocks=[dict(key=block.key, start=block.start, stop=block.stop,
                             instruction=f'{block.instruction.space_id:x}:{block.instruction.byte_offset:x}',
                             exits=block.exits) for block in self.cfg.blocks], edges=edges,
                             cfg_fingerprint=digest, scope='observed_function_cfg'),
                    components=components, cycle_hierarchy=hierarchy, predicates=predicates,
                    analysis_context=dict(
                        normalization_assumptions={name: getattr(self.normalized, name)
                                                  for name in self.normalized.__dataclass_fields__
                                                  if name.startswith('assumes_')},
                        run_assumptions=list(builder.stitch.assumptions)
                        if getattr(builder, 'stitch', None) is not None and builder.stitch.assumptions is not None else None,
                        partial_provenance='writer/debt-excluding assumptions require the original run-level list'),
                    operations=[], definitions=[], reads=[], writes=[], joins=[], edge_states=states,
                    unresolved_accesses=unresolved,
                    coverage=dict(cfg_complete=self.cfg.unsupported is None, ssa_cfg_matches=self.ssa_matches,
                                  expression_complete=False, expression_scope='whole_observed_function',
                                  edge_state_evidence='captured_sparse_phi_sites_only', unknown_inputs=unknowns,
                                  numeric_evaluation='not_provided'),
                    evaluation='structural_only')


def _varnode(varnode):
    if varnode is None:
        return None
    return dict(kind=varnode.kind.name.lower(), space=varnode.coordinate.space_id,
                offset=varnode.coordinate.byte_offset, size=varnode.byte_size)


def _storage(evidence):
    if evidence is None:
        return None
    if isinstance(evidence, StorageRef):
        return dict(kind='raw', storage_kind=evidence.kind.value, space=evidence.space, space_id=evidence.space_id,
                    offset=evidence.offset, size=evidence.size, register_name=evidence.register_name)
    if isinstance(evidence, ResolvedStorage):
        return dict(kind='resolved', span=list(evidence.span.canonical_key))
    if isinstance(evidence, UnresolvedStorage):
        return dict(kind='unresolved', reason=evidence.reason.value)
    if isinstance(evidence, NonStorage):
        return dict(kind='non_storage')
    raise TypeError('unexpected original storage evidence')


def _materialize(graph, view, index):
    from .operation_records import _slice_parts

    parts = {}
    for identifier, definition in enumerate(index.ssa.definitions):
        step()
        producer, base, loop = view._definition_guarded(index.index.definition_node[identifier], 0)
        part = view._named(dict(node=producer, bytes=[base, base + definition.span.size],
                                at=[0, definition.span.size]), definition)
        if loop:
            part['loop'] = True
        parts[identifier] = part
        graph['definitions'].append(dict(reference=view._definition_ref(identifier), part=part,
                                         value='unknown' if definition.kind is MemoryDefinitionKind.KILL else 'expression'))

    def selected(identifier, span):
        step()
        view._edge()
        definition = index.ssa.definitions[identifier]
        if not definition.span.contains(span):
            raise ValueError('cycle source does not cover original bytes')
        piece, = _slice_parts([parts[identifier]], span.start - definition.span.start, span.end - definition.span.start)
        return dict(reference=view._definition_ref(identifier), part=piece)

    step(len(index.ssa.actions))
    actions = {row.operation_key: i for i, row in enumerate(index.ssa.actions)}
    for key, operation in index.raw.items():
        step()
        node = index.normalized.dependencies.node_for_key('op:' + key)
        producer = view.operation(node, 0) if node is not None else None
        control_only = operation.output is None and operation.opcode in ('BRANCH', 'CALL') \
            and all(value.kind in (VarnodeKindCode.CONSTANT, VarnodeKindCode.ADDRESS) for value in operation.inputs)
        status = 'represented' if key in actions and producer is not None else 'control_only' if control_only else 'unrepresented'
        graph['operations'].append(dict(key=key, block=index.locations[key], opcode=operation.opcode,
                                        node=producer, status=status, inputs=[_varnode(value) for value in operation.inputs],
                                        output=_varnode(operation.output)))
    operations = {row['key']: row for row in graph['operations']}
    for occurrence in graph['unresolved_accesses']:
        step()
        occurrence['node'] = operations.get(occurrence['operation'], {}).get('node')
    for predicate in graph['predicates']:
        row = operations[predicate['operation']]
        node = view.records[row['node']] if row['node'] is not None else {}
        predicate['operand'] = next((operand for operand in node.get('operands', ()) if operand['index'] == 1), None)
    for read in index.ssa.reads:
        step()
        graph['reads'].append(dict(operation=index.ssa.actions[read.action_id].operation_key,
                                  read_ordinal=read.read_ordinal, span=list(read.span.canonical_key), fragments=[
            dict(span=list(fragment.span.canonical_key), definitions=[selected(identifier, fragment.span)
                 for identifier in fragment.definition_ids]) for fragment in read.fragments]))
    for action in index.ssa.actions:
        step()
        graph['writes'].append(dict(operation=action.operation_key, definitions=list(action.write_definition_ids)))
    for join in index.ssa.joins:
        step()
        definition = index.ssa.definitions[join.join_definition_id]
        graph['joins'].append(dict(reference=view._definition_ref(join.join_definition_id),
                                  read_block=definition.block_key, span=list(definition.span.canonical_key),
                                  part=parts[join.join_definition_id],
                                  sources=[selected(source, definition.span) for source in join.source_definition_ids]))
    for state in graph['edge_states']:
        source, target = graph['cfg']['edges'][state['edge']]['source'], graph['cfg']['edges'][state['edge']]['target']
        rows = index.flow_by_edge.get((source, target), ())
        for fact, flow in zip(state['facts'], rows, strict=True):
            fact['definitions'] = [selected(identifier, flow.span) for identifier in flow.definition_ids]
            view._edge()
    for values in (graph['operations'], graph['definitions'], graph['reads'], graph['writes'], graph['joins']):
        for _ in values:
            view._edge()


def publish_cycle_graph(builder):
    """Append an isolated full-demand projection without changing root values.

    The existing builder, SSA and graph implement all arithmetic/byte links.
    Diagnostic limits roll back only this added projection, leaving an
    explicit partial outline and the original root/eligibility untouched.
    """
    from .lane_slice import lane_slice
    from .operation_records import _Builder, _Truncated, _node_parts
    from ._record_calls import _checkpoint, _restore

    index = CycleIndex(builder.normalized, builder.unit, builder.index)
    if not index.cyclic and index.cfg.unsupported is None:
        return None
    graph = index.outline(builder)
    if index.cfg.unsupported is not None or not index.ssa_matches:
        graph['coverage']['expression_reason'] = index.cfg.unsupported or 'ssa cfg mismatch'
        return graph
    demands = lane_slice(builder.normalized, builder.unit, index.seeds(), index=builder.index,
                         budget=builder.limits.demand_steps, byte_budget=builder.limits.demand_bytes)
    if demands.exhausted:
        graph['coverage']['expression_reason'] = 'cycle expression demand budget'
        return graph
    view = _Builder(builder.normalized, builder.unit, index=builder.index, demands=demands,
                    origins=builder.origins, declared=builder.declared, limits=builder.limits,
                    provenance=builder.provenance, records=builder.records, ledger=builder.ledger,
                    path=builder.path, binding=builder.binding)
    view.controls = builder.controls
    view.physical_context = builder.physical_context
    view.cycle_projection = True
    checkpoint = _checkpoint(view)
    start = len(builder.records)
    try:
        _materialize(graph, view, index)
        nodes = builder.records[start:]
        incomplete = view.truncated or any(node.get('kind') == 'cut' or node.get('interrupted')
                                           or any(part.get('pruned') for part in _node_parts(node)) for node in nodes)
        missing = any(row['status'] == 'unrepresented' for row in graph['operations'])
        missing = missing or any(row['operand'] is None or row['operand'].get('unresolved') for row in graph['predicates'])
        graph['coverage']['expression_complete'] = not incomplete and not missing
        if incomplete or missing:
            graph['coverage']['expression_reason'] = 'cut, pruned or unrepresented original expression'
        for node in nodes:
            node['cycle_only'] = True
        graph['expression_nodes'] = [node['id'] for node in nodes]
        graph['coverage']['unknown_inputs']['projection_debt_nodes'] = sum(node['kind'] == 'debt' for node in nodes)
    except (_Truncated, RecursionError, ValueError) as error:
        _restore(view, checkpoint)
        for name in ('operations', 'definitions', 'reads', 'writes', 'joins'):
            graph[name] = []
        for predicate in graph['predicates']:
            predicate['operand'] = None
        for occurrence in graph['unresolved_accesses']:
            occurrence['node'] = None
        for state in graph['edge_states']:
            for fact in state['facts']:
                fact['definitions'] = []
        graph['coverage']['expression_reason'] = str(error) or 'cycle expression limit'
    from ._record_transitions import publish_transitions

    graph['transitions'] = publish_transitions(view, graph, index)
    return graph


def render_cycle_graph(graph, nodes, render_parts):
    """Expose original control edges and their existing expression links."""
    coverage = graph['coverage']
    lines = [f"cycle graph {graph['id']} [CFG complete={coverage['cfg_complete']}; "
             f"expression complete={coverage['expression_complete']}; structural only]"]
    if coverage.get('expression_reason'):
        lines.append('  partial: ' + coverage['expression_reason'])
    lines.append(f"  unknown inputs: {coverage['unknown_inputs']}; numeric evaluation not provided")
    for occurrence in graph['unresolved_accesses']:
        lines.append(f"  unresolved {occurrence['kind']} {occurrence['operation']} "
                     f"ordinal={occurrence['occurrence_ordinal']} width={occurrence['width']} "
                     f"address={occurrence['address']} raw={occurrence['raw_address']}")
    for region in graph['cycle_hierarchy']:
        lines.append(f"  region {region['id']} parent={region['parent']} "
                     f"entries={','.join(region['entry_points'])} blocks={','.join(region['blocks'])} "
                     '[entry-stripping SCC, not an execution schedule]')
    for predicate in graph['predicates']:
        operand = predicate['operand'] or {}
        value = '+'.join(render_parts(operand.get('parts', ()), nodes)) or '?'
        lines.append(f"  per-visit {predicate['operation']}: {value} != 0 "
                     f"T->{predicate['true_target']} F->{predicate['false_target']}")
    for state in graph['edge_states']:
        edge = graph['cfg']['edges'][state['edge']]
        lines.append(f"  edge {state['edge']} {edge['source']} -> {edge['target']} [{state['evidence']}]")
        for fact in state['facts']:
            parts = [row['part'] for row in fact['definitions']]
            value = ' | '.join(render_parts(parts, nodes)) or '?'
            lines.append(f"    {fact['span']}: defs={fact['definition_ids']} = {value}")
    for row in graph['definitions']:
        value = ' | '.join(render_parts([row['part']], nodes))
        lines.append(f"  definition d{row['reference']['id']} = {value} [{row['value']}]")
    for read in graph['reads']:
        for fragment in read['fragments']:
            value = ' | '.join(render_parts([row['part'] for row in fragment['definitions']], nodes))
            lines.append(f"  read {read['operation']} operand={read['read_ordinal']} "
                         f"{fragment['span']} = {value}")
    from ._record_transitions import render_transitions
    from .operation_records import _render_node

    lines.extend(render_transitions(graph, render_parts, _render_node))
    return lines
