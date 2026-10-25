"""One-visit state expressions derived from ORIGINAL cyclic CFG/SSA evidence.

No new SSA, global reaching definitions, instruction execution, trip count or
closed form. A bounded backwards correspondence validates each existing read
occurrence against ordered original writes, captured cut facts and CFG paths.
The original record is never edited; expression construction/interpretation
reuse the existing record builder, Boolean DAG and bit-vector evaluator.
"""

from __future__ import annotations

from collections import deque
import re
import sys

from ._record_conditions import ConditionIndex, ConditionMatch, _UnsupportedGuard
from ._scope_contracts import VarnodeKindCode
from .memory_contracts import MemoryDefinitionKind as Kind
from .operation_records import _Builder, _Evaluator, _Truncated, Ineligible, Limits, _node_parts
from .resource_limits import step
from .span_geometry import ByteSpan, StorageObjectKind as Storage


class _Partial(Exception):
    pass


class _StepConditions(ConditionIndex):
    """The existing BDD operations, scoped to one cut-DAG visit."""

    def __init__(self, index, region, edges):
        self.index, self.ssa = index.index, index.ssa
        self.graph, self.instructions = index.normalized.dependencies, index.instructions
        self.entry, = region['entry_points']
        self.blocks = {key: index.blocks[key] for key in region['blocks']}
        self._segments, self._raw_blocks = index._segments, index.locations
        self.actions = {row.operation_key: i for i, row in enumerate(self.ssa.actions)}
        self._locations = {}
        self.predecessors = {key: set() for key in self.blocks}
        self.cut_edges, self.terminals, self.inside = [], [], []
        for number in region['internal_edges']:
            edge = edges[number]
            if edge['target'] == self.entry:
                self.cut_edges.append(number)
            else:
                self.inside.append(number)
                self.predecessors[edge['target']].add(edge['source'])
        if not self.cut_edges:
            raise _Partial('no observed recurrence cut')
        self.terminals = [*self.cut_edges, *region['exit_edges']]
        indegree = {key: len(value) for key, value in self.predecessors.items()}
        pending = deque(sorted(key for key, degree in indegree.items() if degree == 0))
        self.order = []
        while pending:
            step()
            key = pending.popleft()
            self.order.append(key)
            for target in index.blocks[key].successors:
                if target in self.blocks and target != self.entry:
                    indegree[target] -= 1
                    if indegree[target] == 0:
                        pending.append(target)
        if len(self.order) != len(self.blocks) or not self.order or self.order[0] != self.entry:
            raise _Partial('cut does not produce a single-entry DAG')
        self.guard_nodes, self.decisions = [False, True], {}
        self._guard_intern, self._guard_apply_cache = {}, {}
        self._decision_rank, self._edge_guards, self._reach = {}, {}, {}
        self._reason = None
        for rank, key in enumerate(self.order):
            step()
            block = self.blocks[key]
            raw = index.instructions[block.instruction].operations[block.start:block.stop]
            last = raw[-1] if raw else None
            if last is not None and last.opcode == 'CBRANCH':
                yes, no = self._target(block, last), self._fallthrough(block)
                if yes is None or no is None or yes == no or set(block.successors) != {yes, no}:
                    raise _Partial('incomplete original branch outcomes')
                from .call_seeds import _operation_key

                operation = _operation_key(block.instruction, block.stop - 1, last.opcode)
                node, action = self.graph.node_for_key('op:' + operation), self.actions.get(operation)
                if node is None or action is None:
                    raise _Partial('missing original predicate')
                self.decisions[operation] = ConditionMatch(operation, 'one-visit', yes, no, (), node, action)
                self._decision_rank[operation] = rank
                self._edge_guards[key, yes] = self._guard_node(operation, 1, 0)
                self._edge_guards[key, no] = self._guard_node(operation, 0, 1)
            elif len(block.successors) == 1 and self._straight(block):
                self._edge_guards[key, block.successors[0]] = 1
            else:
                raise _Partial('unsupported one-visit control transfer')
            reach = int(key == self.entry)
            for previous in sorted(self.predecessors[key]):
                reach = self._boolean('or', reach, self._boolean(
                    'and', self._reach[previous], self._edge_guards[previous, key]))
            self._reach[key] = reach

    def _control(self):
        pass  # Already constructed over the cut DAG, never the cyclic CFG.

    def reach_guard(self, operation_or_block):
        key = self._raw_blocks.get(operation_or_block, operation_or_block)
        return self._reach[key], None


class _Correspondence:
    """Only query SSA-supplied candidates; never make another RD table."""

    def __init__(self, index, graph, region, conditions, limits, write_projection=None):
        self.index, self.graph, self.region, self.conditions = index, graph, region, conditions
        self.ssa = index.ssa
        self.defs, self.joins = self.ssa.definitions, index.index.joins
        self.actions = {row.operation_key: i for i, row in enumerate(self.ssa.actions)}
        self.locations, self.writes = {}, {}
        self.inputs, self.memo = {}, {}
        self.certificates, self.certificate_ids = [], {}
        self.evidence_items, self.evidence_limit = 0, limits.edges
        self.atoms = self.ssa.atomic_spans
        self.original_reads = {(row['operation'], row['read_ordinal']): i for i, row in enumerate(graph['reads'])}
        self.edge_ids = {(row['source'], row['target']): i for i, row in enumerate(graph['cfg']['edges'])}
        for block in index.normalized.memory_unit.blocks:
            if block.key not in conditions.blocks:
                continue
            writes = self.writes[block.key] = []
            for position, action in enumerate(block.actions):
                step()
                self.locations[action.operation_key] = (block.key, position)
                action_id = self.actions[action.operation_key]
                writes.extend((position, identifier) for identifier in self.ssa.actions[action_id].write_definition_ids)
                conditions._locations[action.operation_key] = (block.key, position)
        self.boundaries = [*region['entry_edges'], *conditions.cut_edges]
        self.projection_id = graph['id'] + ('/write-visit/' if write_projection else '/visit/') + str(region['id'])
        if not index.index.little:
            raise _Partial('one-visit evaluator requires original little-endian semantics')
        if not region['entry_edges']:
            raise _Partial('function-entry cut state is not captured')
        # Unknown alias/effect evidence is never discharged by this view.
        for occurrence in (*self.ssa.unresolved_reads, *self.ssa.unresolved_writes):
            if self.ssa.actions[occurrence.action_id].operation_key in self.locations:
                from ._record_cycles import _storage

                item = dict(kind='write' if occurrence in self.ssa.unresolved_writes else 'read',
                            action_id=occurrence.action_id,
                            operation=self.ssa.actions[occurrence.action_id].operation_key,
                            occurrence_ordinal=occurrence.occurrence_ordinal, width=occurrence.access.width,
                            address=_storage(occurrence.access.address), raw_address=_storage(occurrence.access.raw_address))
                expected = [{key: value for key, value in row.items() if key != 'node'}
                            for row in write_projection['occurrences']] if write_projection else []
                if item not in expected:
                    raise _Partial('unresolved memory access in one visit')
        for rows in (index.normalized.may_alias_reads, index.normalized.call_clobber_reads):
            if any(row.operation_key in self.locations for row in rows):
                raise _Partial('original alias or clobber debt in one visit')
        for key, raw in index.raw.items():
            if index.locations[key] not in conditions.blocks:
                continue
            if raw.opcode in ('CALL', 'CALLIND', 'CALLOTHER'):
                raise _Partial('opaque call or user operation in one visit')
            values = (*raw.inputs[1:], raw.output) if raw.opcode in ('BRANCH', 'CBRANCH') else (*raw.inputs, raw.output)
            if any(value is not None and value.kind is VarnodeKindCode.ADDRESS for value in values):
                raise _Partial('direct-address memory action is not in the LOAD/STORE effect contract')
        for key in self.locations:
            if '~' in key or key in dict(index.normalized.operation_overrides):
                raise _Partial('staged or overridden action in one visit')

    def charge(self, amount=1):
        step(amount)
        self.evidence_items += amount
        if self.evidence_items > self.evidence_limit:
            raise _Partial('one-visit correspondence evidence budget')

    def atoms_of(self, span):
        atoms = []
        for atom in self.atoms:
            step()
            overlap = atom.intersection(span)
            if overlap is not None:
                if overlap != atom:
                    raise _Partial('read boundary splits an original atomic span')
                atoms.append(overlap)
        atoms.sort(key=lambda atom: atom.start)
        if not atoms or atoms[0].start != span.start or atoms[-1].end != span.end \
                or any(a.end != b.start for a, b in zip(atoms, atoms[1:])):
            raise _Partial('incomplete original atomic byte coverage')
        return atoms

    def raw_sources(self, identifiers, span):
        pending, seen, result = list(identifiers), set(), set()
        while pending:
            step()
            identifier = pending.pop()
            if identifier in seen:
                continue
            seen.add(identifier)
            definition = self.defs[identifier]
            if not definition.span.contains(span):
                raise _Partial('source does not cover requested bytes')
            if definition.kind is Kind.JOIN:
                pending.extend(self.joins[identifier])
            elif definition.kind in (Kind.DATA_WRITE, Kind.ENTRY):
                result.add(identifier)
            else:
                raise _Partial('killed source in one-visit correspondence')
        if not result:
            raise _Partial('empty original source set')
        return frozenset(result)

    def flow(self, edge_number, span):
        edge = self.graph['cfg']['edges'][edge_number]
        rows = [row for row in self.index.flow_by_edge.get((edge['source'], edge['target']), ())
                if row.span.contains(span)]
        if len(rows) != 1:
            raise _Partial('missing or partial captured cut state')
        return rows[0]

    def input(self, span, allowed):
        key = span.canonical_key
        step(sum(len(rows) for rows in self.writes.values()))
        mutable = any(self.defs[identifier].span.overlaps(span)
                      for rows in self.writes.values() for _, identifier in rows)
        evidence = []
        union = set()
        if mutable:
            for number in self.boundaries:
                flow = self.flow(number, span)
                union.update(self.raw_sources(flow.definition_ids, span))
                evidence.append(dict(edge=number, span=list(flow.span.canonical_key),
                                     definition_ids=list(flow.definition_ids)))
                self.charge(1 + len(flow.definition_ids))
            if not union <= allowed:
                raise _Partial('cut state is not contained in original read sources')
            basis = 'captured_cut_state_and_no_prior_write'
        else:
            # A current snapshot of a region-invariant value, not a constant
            # and not fabricated missing predecessor evidence.
            union = set(allowed)
            if any(self.defs[identifier].block_key in self.conditions.blocks for identifier in union):
                raise _Partial('invariant source is internal to the visit')
            basis = 'original_external_sources_and_no_region_write'
        if key not in self.inputs:
            if any(ByteSpan.from_canonical_key(tuple(row['span'])).overlaps(span) for row in self.inputs.values()):
                raise _Partial('overlapping one-visit input byte identities')
            self.inputs[key] = dict(id=f's{len(self.inputs)}', span=list(key), mutable=mutable,
                                    basis=basis, definition_ids=sorted(union), cut_evidence=evidence)
            self.charge(1 + len(union))
        elif set(self.inputs[key]['definition_ids']) != union:
            raise _Partial('inconsistent input byte identity')
        return self.inputs[key]['id']

    def query(self, span, identifiers, block, stop=None):
        allowed = self.raw_sources(identifiers, span)
        control = self.conditions

        def trace(key, before):
            identity = span, allowed, key, before
            if identity in self.memo:
                return self.memo[identity]
            step()
            last = None
            predecessors = []
            for position, identifier in self.writes[key]:
                step()
                if before is not None and position >= before:
                    break
                if self.defs[identifier].span.overlaps(span):
                    last = identifier
            if last is not None:
                definition = self.defs[last]
                if definition.kind is not Kind.DATA_WRITE or not definition.span.contains(span):
                    raise _Partial('partial or killed last write')
                if last not in allowed:
                    raise _Partial('actual last write is outside original source candidates')
                result = {('definition', last): control._reach[key]}
            elif key == control.entry:
                result = {('state', self.input(span, allowed)): 1}
            else:
                result = {}
                for predecessor in sorted(control.predecessors[key]):
                    edge_guard = control._edge_guards[predecessor, key]
                    child = trace(predecessor, None)
                    predecessors.append(dict(block=predecessor,
                                             edge=self.edge_ids[predecessor, key],
                                             proof=self.certificate_ids[span, allowed, predecessor, None]))
                    for origin, guard in child.items():
                        proof_ids = {origin[1]} if origin[0] == 'definition' else set(next(
                            row['definition_ids'] for row in self.inputs.values() if row['id'] == origin[1]))
                        # Recorded evidence is a constraint, not an optional
                        # new source table. Absence remains absence.
                        for row in self.index.flow_by_edge.get((predecessor, key), ()):
                            step()
                            if row.span.overlaps(span) and (not row.span.contains(span)
                                    or not proof_ids <= self.raw_sources(row.definition_ids, span)):
                                raise _Partial('captured predecessor source mismatch')
                        combined = control._boolean('and', guard, edge_guard)
                        result[origin] = control._boolean('or', result.get(origin, 0), combined)
            result = {origin: guard for origin, guard in result.items() if guard}
            self.memo[identity] = result
            self.charge(1 + len(allowed) + len(predecessors))
            self.certificate_ids[identity] = len(self.certificates)
            self.certificates.append(dict(id=len(self.certificates), span=list(span.canonical_key),
                                          candidate_definitions=sorted(allowed), block=key,
                                          before_position=before, last_definition=last,
                                          predecessors=predecessors,
                                          input=next((value for kind, value in result if kind == 'state'), None)
                                          if key == control.entry and last is None else None))
            return result

        result = trace(block, stop)
        union = 0
        for guard in result.values():
            if control._boolean('and', union, guard):
                raise _Partial('overlapping one-visit sources')
            union = control._boolean('or', union, guard)
        if union != control._reach[block]:
            raise _Partial('incomplete one-visit source paths')
        return result

    def certificate(self, span, identifiers, block, stop=None):
        return self.certificate_ids[span, self.raw_sources(identifiers, span), block, stop]


class _StepBuilder(_Builder):
    def __init__(self, original, proof, conditions):
        super().__init__(original.normalized, original.unit, index=original.index, demands=original.demands,
                         limits=original.limits, conditions=conditions)
        self.proof = proof
        self.cycle_projection = True
        self.original_nodes = {row['key']: row['node'] for row in proof.graph['operations']}
        self.read_bindings = {}

    def _selection(self, decision):
        return self.proof.projection_id + '/' + decision

    def _new(self, key, record):
        if record.get('kind') == 'op' and record.get('key') in self.original_nodes:
            record['original_node'] = self.original_nodes[record['key']]
        return super()._new(key, record)

    def source_parts(self, span, origins, depth, reach):
        alternatives, guards, sources = [], [], []
        for (kind, identifier), guard in sorted(origins.items()):
            if kind == 'state':
                key = 'transition-input', identifier
                producer = self.id_of.get(key)
                if producer is None:
                    producer = self._new(key, dict(kind='entry', name=f'state({identifier})',
                                                   span=str(span.canonical_key), size=span.size,
                                                   transition_input=identifier))['id']
                part = dict(node=producer, bytes=[0, span.size], at=[0, span.size])
                source = dict(kind='input', input=identifier)
            else:
                definition = self.ssa.definitions[identifier]
                producer, base, loop = self._definition_guarded(self.index.definition_node[identifier], depth + 1)
                if loop:
                    raise _Partial('unbroken one-visit value cycle')
                offset = base + span.start - definition.span.start
                part = dict(node=producer, bytes=[offset, offset + span.size], at=[0, span.size])
                source = dict(kind='definition', definition=identifier)
            self._edge()
            alternatives.append(part)
            guards.append(self._guard_ref(guard))
            sources.append(dict(**source, guard=guards[-1], part=part))
        if len(alternatives) == 1:
            return alternatives[0], sources
        node = self._new(None, dict(kind='phi', reason='one-visit guarded existing sources', size=span.size,
                                    alternatives=alternatives,
                                    guarded_sources=dict(guards=guards, reach=self._guard_ref(reach))))
        self._done(node)
        return dict(node=node['id'], bytes=[0, span.size], at=[0, span.size]), sources

    def _fragments(self, read, wanted, depth):
        operation = self.ssa.actions[read.action_id].operation_key
        # One-visit source reconstruction must not bypass a graph-owned
        # conditional allocation transfer by reading the old SSA writer.
        if any((identifier, read.action_id, fragment.span) in self.index.transfer_node
               for fragment in read.fragments for identifier in fragment.definition_ids):
            raise _Partial('conditional memory transfer is not a one-visit value identity')
        key = operation, read.read_ordinal
        if key in self.read_bindings:
            return self.read_bindings[key]['parts']
        block, stop = self.proof.locations[operation]
        parts, atoms = [], []
        for fragment in read.fragments:
            for atom in self.proof.atoms_of(fragment.span):
                origins = self.proof.query(atom, fragment.definition_ids, block, stop)
                part, sources = self.source_parts(atom, origins, depth, self.conditions._reach[block])
                placed = {**part, 'at': [atom.start - read.span.start, atom.end - read.span.start]}
                parts.append(placed)
                atoms.append(dict(span=list(atom.canonical_key), original_definition_ids=list(fragment.definition_ids),
                                  sources=sources, proof=self.proof.certificate(atom, fragment.definition_ids, block, stop)))
                self.proof.charge(1 + len(sources))
        self.read_bindings[key] = dict(operation=operation, read_ordinal=read.read_ordinal,
                                       span=list(read.span.canonical_key),
                                       original_read=self.proof.original_reads[key], atoms=atoms, parts=parts)
        return parts


def _build(original, graph, index, region, *, write_projection=None):
    if write_projection is not None:
        from ._record_write_effects import policy

        if write_projection != policy(graph, region):
            raise _Partial('STORE projection policy mismatch')
    if len(region['entry_points']) != 1:
        raise _Partial('one-visit view requires one actual entry')
    conditions = _StepConditions(index, region, graph['cfg']['edges'])
    proof = _Correspondence(index, graph, region, conditions, original.limits, write_projection)
    builder = _StepBuilder(original, proof, conditions)
    operations = []
    effects = []
    for block in conditions.order:
        raw = index.instructions[index.blocks[block].instruction].operations
        for ordinal in range(index.blocks[block].start, index.blocks[block].stop):
            step()
            from .call_seeds import _operation_key

            key = _operation_key(index.blocks[block].instruction, ordinal, raw[ordinal].opcode)
            source = index.normalized.dependencies.node_for_key('op:' + key)
            if source is None:
                raise _Partial('missing original action node')
            node = builder.operation(source, 0)
            # The shared operand builder reuses the first matching span for
            # repeated storage operands. Preserve every ORIGINAL occurrence,
            # with its own ordinal and checked read certificate, as well.
            for read in builder.index.reads.get(proof.actions.get(key), ()):
                if (key, read.read_ordinal) not in builder.read_bindings:
                    builder._fragments(read, None, 0)
            operations.append(dict(operation=key, node=node, original_node=builder.original_nodes[key],
                                    block=block, guard=builder._guard_ref(conditions._reach[block])))
            if raw[ordinal].opcode in ('LOAD', 'STORE'):
                action_id = proof.actions[key]
                effects.append(dict(kind=raw[ordinal].opcode.lower(), operation=key, node=node,
                                    original_node=builder.original_nodes[key], guard=builder._guard_ref(conditions._reach[block]),
                                    write_definitions=list(index.ssa.actions[action_id].write_definition_ids)))
    # Required state: observed concrete RAM writes, plus mutable read inputs.
    output_atoms = {}
    for rows in proof.writes.values():
        for _, identifier in rows:
            definition = proof.defs[identifier]
            if write_projection is None and definition.span.object_id.kind in (Storage.ADDRESS_SPACE, Storage.FUNCTION_RELATIVE):
                for atom in proof.atoms_of(definition.span):
                    output_atoms[atom.canonical_key] = atom
    for row in list(proof.inputs.values()):
        if row['mutable']:
            output_atoms[tuple(row['span'])] = ByteSpan.from_canonical_key(tuple(row['span']))
    outcomes = []
    for number in conditions.terminals:
        edge = graph['cfg']['edges'][number]
        source = edge['source']
        local_guard = conditions._boolean('and', conditions._reach[source],
                                         conditions._edge_guards[source, edge['target']])
        updates = []
        for atom in output_atoms.values():
            exit_evidence = None
            if number in conditions.cut_edges:
                identifiers = proof.flow(number, atom).definition_ids
            elif proof.index.flow_by_edge.get((source, edge['target'])):
                # Reuse only this ORIGINAL exit's captured poststate. A
                # partial/ambiguous overlapping fact cannot become absence.
                flows = [row for row in proof.index.flow_by_edge[source, edge['target']]
                         if row.span.overlaps(atom)]
                if len(flows) != 1 or not flows[0].span.contains(atom):
                    raise _Partial('missing or partial captured exit state')
                flow, = flows
                identifiers = flow.definition_ids
                exit_evidence = dict(edge=number, span=list(flow.span.canonical_key),
                                     definition_ids=list(identifiers))
            else:
                # An unrecorded exit can preserve only an already captured
                # input, and only when every path has no preceding write.
                identifiers = set()
                for boundary in proof.boundaries:
                    identifiers.update(proof.flow(boundary, atom).definition_ids)
                origins = proof.query(atom, identifiers, source)
                if any(kind != 'state' for kind, _ in origins):
                    raise _Partial('exit poststate evidence is not captured')
            origins = proof.query(atom, identifiers, source)
            part, sources = builder.source_parts(atom, origins, 0, conditions._reach[source])
            updates.append(dict(span=list(atom.canonical_key), part=part, sources=sources,
                                proof=proof.certificate(atom, identifiers, source)))
            if exit_evidence is not None:
                updates[-1]['captured_exit_evidence'] = exit_evidence
            proof.charge(1 + len(sources))
        outcomes.append(dict(kind='continue' if number in conditions.cut_edges else 'exit', edge=number,
                             guard=builder._guard_ref(local_guard), updates=updates))
    for certificate in proof.certificates:
        certificate['reach'] = builder._guard_ref(conditions._reach[certificate['block']])
        for predecessor in certificate['predecessors']:
            predecessor['guard'] = builder._guard_ref(conditions._edge_guards[predecessor['block'], certificate['block']])
    control = builder._control_record()
    expected_reads = {(index.ssa.actions[row.action_id].operation_key, row.read_ordinal)
                      for row in index.ssa.reads if index.ssa.actions[row.action_id].operation_key in proof.locations}
    if set(builder.read_bindings) != expected_reads:
        raise _Partial('not every original read occurrence was represented')
    for node in builder.records:
        node.pop('condition_only', None)
        if node.get('kind') in ('cut', 'debt', 'call') or node.get('interrupted') or node.get('debts') \
                or any(part.get('pruned') or part.get('loop') for part in _node_parts(node)):
            raise _Partial('incomplete one-visit expression or original debt')
    if builder.truncated:
        raise _Partial('one-visit expression budget')
    result = dict(complete=True, evaluation='one_visit_expression', entry=conditions.entry,
                cut_edges=conditions.cut_edges, entry_edges=region['entry_edges'],
                blocks=conditions.order, inputs=list(proof.inputs.values()),
                operations=operations, reads=list(builder.read_bindings.values()), effects=effects, outcomes=outcomes,
                proofs=proof.certificates,
                normalization_assumptions={name: getattr(index.normalized, name)
                                           for name in index.normalized.__dataclass_fields__ if name.startswith('assumes_')},
                assumption_scope='original run-level assumption list remains authoritative',
                output_scope='loop_carried_inputs_and_observed_RAM_writes_not_full_machine',
                endianness='little', analysis_context=graph['analysis_context'],
                record=dict(record='one-visit expressions', nodes=builder.records, control=control,
                            root=[], truncated=False, limits={'depth': builder.limits.depth}))
    if write_projection is not None:
        result.update(write_projection=write_projection, output_scope=write_projection['output_scope'])
    return result


def publish_transitions(original, graph, index):
    """Independent derived views; failure never changes the authority graph."""
    result = []
    for region in graph['cycle_hierarchy']:
        row = dict(id=graph['id'] + '/visit/' + str(region['id']), region=region['id'], complete=False)
        try:
            if not graph['coverage']['expression_complete']:
                raise _Partial('original expression projection is incomplete')
            row.update(_build(original, graph, index, region))
        except (_Partial, _UnsupportedGuard, _Truncated, RecursionError) as error:
            row['reason'] = str(error) or 'one-visit expression limit'
        result.append(row)
    return result


class _StepEvaluator(_Evaluator):
    def _located_part(self, part, space, address):
        if self.nodes[part['node']].get('transition_input') is not None:
            return self.part(part)
        return super()._located_part(part, space, address)


def render_transitions(graph, render_parts, render_node):
    """The existing text view, with a distinct namespace for derived nodes."""
    lines = []
    for view in graph.get('transitions', ()):
        lines.append(f"one-visit {view['id']} [complete={view['complete']}; original graph retained]")
        if not view['complete']:
            lines.append('  partial: ' + view['reason'])
            continue
        prefix = ('w' if 'write_projection' in view else 't') + str(view['region']) + '.'

        def local(text):
            return re.sub(r'\b([ng]\d+)\b', lambda match: prefix + match[1], text)

        nodes = {node['id']: node for node in view['record']['nodes']}
        lines.append(f"  output scope: {view['output_scope']}; conditional on original analysis")
        assumptions = view['analysis_context']['run_assumptions']
        lines.append(f"  run assumptions: {assumptions if assumptions is not None else 'unattributed (numeric opt-in required)'}")
        for row in view['inputs']:
            lines.append(f"  state {row['id']} {row['span']} [{row['basis']}; original defs={row['definition_ids']}]")
        control = view['record']['control']
        for key, decision in control['decisions'].items():
            value = local('+'.join(render_parts(decision['operand']['parts'], nodes)))
            lines.append(f"  decision {key} = {value} != 0 [shared within THIS visit]")
        lines.append(f"  {prefix}g0=false; {prefix}g1=true")
        for reference, item in enumerate(control['nodes'][2:], 2):
            lines.append(f"  {prefix}g{reference} = {item['decision']} ? {prefix}g{item['true']} : {prefix}g{item['false']}")
        for effect in view['effects']:
            lines.append(f"  ordered {effect['kind']} {effect['operation']} = {prefix}n{effect['node']} "
                         f"if {prefix}g{effect['guard']} [original n{effect['original_node']}]")
        for outcome in view['outcomes']:
            lines.append(f"  {outcome['kind']} edge {outcome['edge']} if {prefix}g{outcome['guard']}:")
            for row in outcome['updates']:
                lines.append(f"    next {row['span']} = " + local('+'.join(render_parts([row['part']], nodes))))
        for node in nodes.values():
            original = f" [original n{node['original_node']}]" if 'original_node' in node else ''
            lines.append(f"  {prefix}n{node['id']} = {local(render_node(node, nodes))}{original}")
    return lines


def evaluate_transition(record, identity, inputs, *, accept_unattributed_assumptions=False):
    """Evaluate ONE visit with concrete slot values, not a loop interpreter.

    ``inputs`` maps the view's input IDs to byte-vector integers. Call again
    with a new boundary snapshot to evaluate another visit; no cache survives.
    Missing inputs/unknown effects fail closed. Original eligibility is intact.
    """
    previous = sys.getrecursionlimit()
    depth = record.get('limits', {}).get('depth', Limits.depth)
    sys.setrecursionlimit(max(previous, 16 * depth + 2000))
    try:
        return _evaluate_transition(record, identity, inputs, accept_unattributed_assumptions)
    except RecursionError:
        raise Ineligible('one-visit recursion limit') from None
    finally:
        sys.setrecursionlimit(previous)


def _evaluate_transition(record, identity, inputs, accept_unattributed_assumptions):
    from .operation_records import _choice_contract, _NeedChoice, _Unknown, _Infeasible

    rows = [*record.get('cycle_graph', {}).get('transitions', ()), *record.get('write_effect_transitions', ())]
    view = next((row for row in rows if row['id'] == identity), None)
    if view is None or not view['complete']:
        raise Ineligible('incomplete one-visit view')
    from ._record_transition_contract import validate

    if 'write_projection' in view:
        from ._record_write_effects import validate
    validate(record, view)
    context = view['analysis_context']
    attributed = context['run_assumptions'] is not None
    if not attributed and not accept_unattributed_assumptions:
        raise Ineligible('one-visit run assumptions are unattributed; explicit opt-in required')
    local = view['record']
    nodes = {node['id']: node for node in local['nodes']}
    choices, control = _choice_contract(local, nodes, list(nodes.values()), 'injected')
    evaluator = _StepEvaluator(nodes, lambda node: inputs.get(node.get('transition_input'))
                               if isinstance(node, dict) else None, None, {}, choice_keys=choices, control=control)
    try:
        outcomes = [row for row in view['outcomes'] if evaluator.guard(row['guard'])]
        if len(outcomes) != 1:
            raise Ineligible('one-visit outcome correspondence')
        outcome, = outcomes
        updates = [dict(span=row['span'], value=evaluator.part(row['part'])) for row in outcome['updates']]
        effects = []
        for event in view['effects']:
            if not evaluator.guard(event['guard']):
                continue
            node = nodes[event['node']]
            address = evaluator.operand(next(item for item in node['operands'] if item['index'] == 1))
            width = node['output']['size'] if event['kind'] == 'load' else next(
                item['width'] for item in node['operands'] if item['index'] == 2)
            effects.append(dict(operation=event['operation'], kind=event['kind'], space=node['space'],
                                address=address, width=width, value=evaluator.value(node['id'])))
            if event['kind'] == 'load':
                selected = []
                for binding in view['reads']:
                    if binding['operation'] != event['operation'] or binding['span'][1] not in ('address_space', 'function_relative'):
                        continue
                    for atom in binding['atoms']:
                        sources = [source for source in atom['sources'] if evaluator.guard(source['guard'])]
                        if len(sources) != 1:
                            raise Ineligible('one-visit read source correspondence')
                        chosen, = sources
                        selected.append(dict(span=atom['span'], **{key: chosen[key] for key in ('kind', 'input', 'definition')
                                                                  if key in chosen}))
                effects[-1]['read_sources'] = selected
        decisions = {row['operation']: evaluator._decision(control['decisions'][row['operation']]) == 0
                     for row in view['operations'] if row['operation'] in control['decisions']
                     and evaluator.guard(row['guard'])}
        return dict(kind=outcome['kind'], edge=outcome['edge'], updates=updates, effects=effects, decisions=decisions,
                    conditional_on_original_analysis=True, assumptions_complete=attributed,
                    analysis_context=context)
    except (_NeedChoice, _Unknown, _Infeasible, RecursionError):
        raise Ineligible('unknown or unsupported one-visit inputs') from None
