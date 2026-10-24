"""Actual x64 raw-pcode cyclic expressions, not native/loop-evaluator runs.

TDO_GENERAL_CYCLE_BUNDLE selects the sealed Ghidra 12.0.4 export of
tests/corpus/intra/general_cycle_expression.c, compiled with clang -O0
-fno-stack-protector -fno-optimize-sibling-calls -nostdlib -dynamiclib
-target x86_64-apple-macos11 -lSystem. The original image SHA is pinned below.
Source lines 18/33/47/65/92/107 correspond to entries 320/3a0/430/4b0/560/5f0
in original address space 1b1: nested, several updates, several backedges,
irreducible two-entry, sequential, and two-cell memory loops respectively.

The 216 terminating executions observe every original CFG edge and every
LOAD byte writer. Entry register values are test inputs, never injected
results, branch flips, filtered writer sets, or fabricated loop exits.
"""

from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path

import pytest
import rustworkx as rx

from program_oracle import _place
from synthetic import RAX, RCX, RDI, RDX, RSI, RSP
from test_indirect_physical_binary import _ObservedMemory
from test_multi_target_memory_binary import _load, _operations, _value
from test_recurrence_register_binary import _raw_block_edges
from tdo_v2._sparse_dataflow import DominatorGraph
from tdo_v2.call_summary_effects import anchored_span
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.operation_records import Ineligible, _node_parts, eligibility, evaluate, root_record
from tdo_v2.pcode_blocks import build_pcode_block_graph
from tdo_v2.span_geometry import ByteSpan, StorageObjectKind


IMAGE_SHA = '7545efc08975f6c38b99ab97016049e3af102d36be32118d2df2fbc2b5ddee55'
MASK = (1 << 64) - 1
CASES = {
    'nested': ('1b1:320', 36, 37, (22,), 2,
               {'1b1:35b:2:STORE', '1b1:36e:2:STORE', '1b1:37a:2:STORE',
                '1b1:388:2:STORE', '1b1:394:2:STORE'}),
    'multi_update': ('1b1:3a0', 37, 38, (23,), 1,
                     {'1b1:3e9:2:STORE', '1b1:3fe:2:STORE', '1b1:40a:2:STORE', '1b1:416:2:STORE'}),
    'multi_backedge': ('1b1:430', 35, 36, (21,), 2,
                       {'1b1:47f:2:STORE', '1b1:48b:2:STORE', '1b1:499:2:STORE', '1b1:4a5:2:STORE'}),
    'irreducible': ('1b1:4b0', 50, 54, (28,), 2,
                    {'1b1:4fb:2:STORE', '1b1:507:2:STORE', '1b1:52e:2:STORE', '1b1:53a:2:STORE'}),
    'sequential': ('1b1:560', 37, 38, (9, 11), 2,
                   {'1b1:597:2:STORE', '1b1:5a3:2:STORE', '1b1:5cb:2:STORE', '1b1:5d7:2:STORE'}),
    'memory': ('1b1:5f0', 41, 42, (22,), 1,
               {'1b1:633:2:STORE', '1b1:654:2:STORE', '1b1:662:2:STORE', '1b1:66e:2:STORE'}),
}


@pytest.fixture(scope='module')
def general_cycle_binary():
    with pytest.MonkeyPatch.context() as patch:
        case = _load('TDO_GENERAL_CYCLE_BUNDLE', patch, require_calls=False)
        generation = Path(os.environ['TDO_GENERAL_CYCLE_BUNDLE'])
        manifest = json.loads((generation / 'manifest.json').read_text())
        original = next(row for row in manifest['members'] if row['id'] == manifest['original_member_id'])
        assert original['sha256'] == IMAGE_SHA
        assert sha256((generation / original['path']).read_bytes()).hexdigest() == IMAGE_SHA
        assert set(case['names']) == {f'case_cycle_{suffix}' for suffix in CASES}
        yield case


def _sccs(blocks, members=None):
    """Independent library SCC oracle on the original observed CFG."""
    members = set(blocks) if members is None else set(members)
    graph = rx.PyDiGraph()
    nodes = {key: graph.add_node(key) for key in sorted(members)}
    for key in sorted(members):
        for target in blocks[key].successors:
            if target in members:
                graph.add_edge(nodes[key], nodes[target], None)
    return {frozenset(graph[index] for index in component)
            for component in rx.strongly_connected_components(graph)}


def _cyclic(blocks, component):
    return len(component) > 1 or any(key in blocks[key].successors for key in component)


def _raw_shape(item, suffix):
    entry, block_count, edge_count, component_sizes, backedge_count, stores = CASES[suffix]
    cfg = build_pcode_block_graph(item.unit.observation, item.unit.scopes.function.entry)
    assert cfg.unsupported is None and cfg.entry == item.key == entry
    blocks = {block.key: block for block in cfg.blocks}
    edges = {(block.key, target) for block in cfg.blocks for target in block.successors}
    assert len(blocks) == block_count and len(edges) == edge_count
    predecessors = {key: tuple(source for source, target in edges if target == key) for key in blocks}
    dominance = DominatorGraph(cfg.entry, predecessors)
    backedges = {(source, target) for source, target in edges if dominance._dominates(target, source)}
    assert len(backedges) == backedge_count
    components = _sccs(blocks)
    cyclic = {component for component in components if _cyclic(blocks, component)}
    assert sorted(map(len, cyclic)) == list(component_sizes)
    locations = {key: block for key, (block, _) in _raw_block_edges(item, ())[1].items()}
    operations = dict(_operations(item))
    assert not any(operation.opcode in ('CALL', 'CALLIND') for operation in operations.values())
    members = set().union(*cyclic)
    assert {key for key, operation in operations.items()
            if operation.opcode == 'STORE' and locations[key] in members} == stores
    if suffix == 'irreducible':
        (component,) = cyclic
        points = {target for source, target in edges if target in component and source not in component}
        assert points == {'1b1:4ea', '1b1:51d'}
        assert all(not all(dominance._dominates(point, key) for key in component) for point in points)
    elif suffix == 'nested':
        (component,) = cyclic
        assert backedges == {('1b1:37e', '1b1:35f'), ('1b1:398', '1b1:348')}
        assert any(_cyclic(blocks, child) for child in _sccs(blocks, component - {'1b1:348'}))
    elif suffix == 'multi_backedge':
        assert backedges == {('1b1:48f', '1b1:458'), ('1b1:4a9', '1b1:458')}
    elif suffix == 'multi_update':
        # Both conditional writes and the unconditional addition write the
        # same original volatile value; the counter write is separate.
        writes = {action.operation_key: action.write_definition_ids for action in item.normalized.memory_ssa.actions}
        spans = [item.normalized.memory_ssa.definitions[writes[key][0]].span
                 for key in ('1b1:3e9:2:STORE', '1b1:3fe:2:STORE', '1b1:40a:2:STORE')]
        assert spans[0] == spans[1] == spans[2]
    elif suffix == 'memory':
        writes = {action.operation_key: action.write_definition_ids for action in item.normalized.memory_ssa.actions}
        cells = [item.normalized.memory_ssa.definitions[writes[key][0]].span
                 for key in ('1b1:633:2:STORE', '1b1:654:2:STORE', '1b1:662:2:STORE')]
        assert cells[0] == cells[2] and not cells[0].overlaps(cells[1])
    return cfg, blocks, edges, components


def _root(item):
    (ex,) = item.summary.exits
    (run,) = [row for row in ex.runs
              if row.span.object_id.kind is StorageObjectKind.REGISTER_FILE and row.span.start == RAX]
    return root_record(item.normalized, item.unit,
                       [(item.normalized.memory_graph.definition_nodes[identifier], (run.span,))
                        for identifier in run.definitions])


def _reference(ssa, identifier):
    definition = ssa.definitions[identifier]
    return dict(scope=ssa.function_scope.digest.hex(), unit=ssa.unit_digest.hex(), id=identifier,
                kind=definition.kind.value, operation=definition.operation_key,
                write_ordinal=definition.write_ordinal, span=list(definition.span.canonical_key))


def _part(record, part, width):
    assert type(part['node']) is int and 0 <= part['node'] < len(record['nodes'])
    assert record['nodes'][part['node']]['id'] == part['node']
    assert part['at'] == [0, width]
    assert 0 <= part['bytes'][0] < part['bytes'][1]
    assert part['bytes'][1] - part['bytes'][0] == width
    assert not part.get('pruned') and not part.get('unresolved')


def _projection(record, item):
    """Every original SSA reference, byte slice, read and update survives."""
    graph, ssa = record['cycle_graph'], item.normalized.memory_ssa
    assert graph['scope'] == ssa.function_scope.digest.hex() and graph['unit'] == ssa.unit_digest.hex()
    assert graph['call_path'] == [] and graph['evaluation'] == 'structural_only'
    assert graph['coverage'] == dict(cfg_complete=True, ssa_cfg_matches=True, expression_complete=True,
                                   expression_scope='whole_observed_function',
                                   edge_state_evidence='captured_sparse_phi_sites_only',
                                   numeric_evaluation='not_provided', unknown_inputs=dict(
                                       entry_definitions=sum(row.kind is MemoryDefinitionKind.ENTRY for row in ssa.definitions),
                                       kill_definitions=0, unresolved_reads=0, unresolved_writes=0,
                                       projection_debt_nodes=0))
    assert graph['unresolved_accesses'] == []
    definitions = {row['reference']['id']: row for row in graph['definitions']}
    assert set(definitions) == set(range(len(ssa.definitions)))
    for identifier, row in definitions.items():
        assert row['reference'] == _reference(ssa, identifier)
        _part(record, row['part'], ssa.definitions[identifier].span.size)
        source = record['nodes'][row['part']['node']]
        definition = ssa.definitions[identifier]
        if definition.kind is MemoryDefinitionKind.DATA_WRITE:
            assert source['kind'] == 'op' and source['key'] == definition.operation_key
        elif definition.kind is MemoryDefinitionKind.JOIN:
            assert source['kind'] == 'phi' and source['reason'] == 'join'
        else:
            assert definition.kind is MemoryDefinitionKind.ENTRY and source['kind'] == 'entry'

    def selected(row, identifier, span):
        assert row['reference'] == _reference(ssa, identifier)
        whole = definitions[identifier]['part']
        definition = ssa.definitions[identifier]
        assert definition.span.contains(span)
        _part(record, row['part'], span.size)
        assert row['part']['node'] == whole['node']
        offset = span.start - definition.span.start
        assert row['part']['bytes'] == [whole['bytes'][0] + offset, whole['bytes'][0] + offset + span.size]

    assert len(graph['reads']) == len(ssa.reads)
    for row, read in zip(graph['reads'], ssa.reads, strict=True):
        assert (row['operation'], row['read_ordinal'], row['span']) == (
            ssa.actions[read.action_id].operation_key, read.read_ordinal, list(read.span.canonical_key))
        assert len(row['fragments']) == len(read.fragments)
        for output, fragment in zip(row['fragments'], read.fragments, strict=True):
            assert output['span'] == list(fragment.span.canonical_key)
            assert len(output['definitions']) == len(fragment.definition_ids)
            for source, identifier in zip(output['definitions'], fragment.definition_ids, strict=True):
                selected(source, identifier, fragment.span)
    assert graph['writes'] == [dict(operation=action.operation_key, definitions=list(action.write_definition_ids))
                               for action in ssa.actions]
    assert len(graph['joins']) == len(ssa.joins)
    for row, join in zip(graph['joins'], ssa.joins, strict=True):
        definition = ssa.definitions[join.join_definition_id]
        assert row['reference'] == _reference(ssa, join.join_definition_id)
        assert row['read_block'] == definition.block_key
        assert row['span'] == list(definition.span.canonical_key)
        assert row['part'] == definitions[join.join_definition_id]['part']
        assert len(row['sources']) == len(join.source_definition_ids)
        for source, identifier in zip(row['sources'], join.source_definition_ids, strict=True):
            selected(source, identifier, definition.span)

    edge_pairs = [(row['source'], row['target']) for row in graph['cfg']['edges']]
    assert [row['edge'] for row in graph['edge_states']] == list(range(len(edge_pairs)))
    captured = 0
    for state in graph['edge_states']:
        pair = edge_pairs[state['edge']]
        original = [flow for flow in ssa.flow_edges if (flow.predecessor_key, flow.block_key) == pair]
        assert state['evidence'] == ('captured' if original else 'not_captured')
        assert len(state['facts']) == len(original)
        for fact, flow in zip(state['facts'], original, strict=True):
            assert fact['span'] == list(flow.span.canonical_key)
            assert fact['definition_ids'] == list(flow.definition_ids)
            assert len(fact['definitions']) == len(flow.definition_ids)
            for source, identifier in zip(fact['definitions'], flow.definition_ids, strict=True):
                selected(source, identifier, flow.span)
            captured += 1
    assert captured and any(row['evidence'] == 'not_captured' for row in graph['edge_states'])

    projected = set(graph['expression_nodes'])
    assert projected and projected == {node['id'] for node in record['nodes'] if node.get('cycle_only')}
    for node in record['nodes']:
        for part in _node_parts(node):
            if 'node' in part:
                assert 0 <= part['node'] < len(record['nodes'])
    assert json.loads(json.dumps(record))['cycle_graph'] == graph


def _topology(record, item, cfg, blocks, edges, components):
    graph = record['cycle_graph']
    assert graph['cfg']['entry'] == cfg.entry
    assert graph['cfg']['scope'] == 'observed_function_cfg'
    assert graph['cfg']['blocks'] == [dict(key=block.key, start=block.start, stop=block.stop,
                                          instruction=f'{block.instruction.space_id:x}:{block.instruction.byte_offset:x}',
                                          exits=block.exits) for block in cfg.blocks]
    rows = graph['cfg']['edges']
    assert len(rows) == len(edges) and {(row['source'], row['target']) for row in rows} == edges
    assert {frozenset(row['blocks']) for row in graph['components']} == components
    component_of = {key: row['id'] for row in graph['components'] for key in row['blocks']}
    for row in graph['components']:
        members = frozenset(row['blocks'])
        assert row['cyclic'] == _cyclic(blocks, members)
        assert set(row['successors']) == {component_of[target] for source, target in edges
                                          if source in members and target not in members}
    regions = {row['id']: row for row in graph['cycle_hierarchy']}
    assert {frozenset(row['blocks']) for row in regions.values() if row['parent'] is None} == {
        component for component in components if _cyclic(blocks, component)}
    for identifier, region in regions.items():
        members = set(region['blocks'])
        assert region['decomposition_basis'] == 'entry-stripping-scc'
        assert _sccs(blocks, members) == {frozenset(members)} and _cyclic(blocks, members)
        assert region['entry_edges'] == [i for i, edge in enumerate(rows)
                                        if edge['source'] not in members and edge['target'] in members]
        assert region['exit_edges'] == [i for i, edge in enumerate(rows)
                                       if edge['source'] in members and edge['target'] not in members]
        assert region['internal_edges'] == [i for i, edge in enumerate(rows)
                                           if edge['source'] in members and edge['target'] in members]
        points = {rows[i]['target'] for i in region['entry_edges']}
        if cfg.entry in members:
            points.add(cfg.entry)
        assert set(region['entry_points']) == points
        assert set(region['removed_for_children']) == (points or {min(members)})
        assert {frozenset(regions[child]['blocks']) for child in region['children']} == {
            component for component in _sccs(blocks, members - set(region['removed_for_children']))
            if _cyclic(blocks, component)}
        for child in region['children']:
            assert regions[child]['parent'] == identifier and set(regions[child]['blocks']) < members
        if region['parent'] is not None:
            assert identifier in regions[region['parent']]['children']

    operations = dict(_operations(item))
    locations = _raw_block_edges(item, ())[1]
    assert [row['key'] for row in graph['operations']] == list(operations)
    for row in graph['operations']:
        operation = operations[row['key']]
        assert row['block'] == locations[row['key']][0] and row['opcode'] == operation.opcode
        varnode = lambda value: (dict(kind=value.kind.name.lower(), space=value.coordinate.space_id,
                                      offset=value.coordinate.byte_offset, size=value.byte_size) if value else None)
        assert row['inputs'] == [varnode(value) for value in operation.inputs]
        assert row['output'] == varnode(operation.output)
        if row['status'] == 'represented':
            node = record['nodes'][row['node']]
            assert node['kind'] == 'op' and node['key'] == row['key'] and node['opcode'] == operation.opcode
        else:
            assert row['status'] == 'control_only' and operation.opcode == 'BRANCH'

    predicates = {row['operation']: row for row in graph['predicates']}
    assert set(predicates) == {key for key, operation in operations.items() if operation.opcode == 'CBRANCH'}
    instructions = {row.address: row for row in item.unit.observation.instructions}
    starts = {block.instruction: block.key for block in cfg.blocks if block.start == 0}
    outcomes = {pair: [] for pair in edges}
    for key, predicate in predicates.items():
        operation = operations[key]
        block = blocks[locations[key][0]]
        # These real machine branches have absolute ADDRESS targets, not
        # synthetic relative p-code jumps or guessed source-level polarity.
        assert operation.inputs[0].kind.name == 'ADDRESS'
        yes, no = starts[operation.inputs[0].coordinate], starts[instructions[block.instruction].fallthrough]
        assert (predicate['block'], predicate['true_target'], predicate['false_target']) == (block.key, yes, no)
        assert predicate['evaluation'] == 'per_visit_expression'
        operand = predicate['operand']
        assert operand['index'] == 1 and operand['width'] == operation.inputs[1].byte_size
        assert operand['parts'] and not operand.get('unresolved')
        for target, value in ((yes, True), (no, False)):
            outcomes[block.key, target].append(dict(predicate=key, value=value))
    for row in rows:
        assert row['outcomes'] == outcomes[row['source'], row['target']]


def _writer_candidates(graph, identifiers, logical):
    definitions = {row['reference']['id']: row['reference'] for row in graph['definitions']}
    joins = {row['reference']['id']: row['sources'] for row in graph['joins']}
    pending, seen, candidates = list(identifiers), set(), set()
    while pending:
        identifier = pending.pop()
        if identifier in seen:
            continue
        seen.add(identifier)
        definition = definitions[identifier]
        span = ByteSpan.from_canonical_key(tuple(definition['span']))
        assert span.start <= logical < span.end
        if definition['kind'] == 'join':
            pending.extend(row['reference']['id'] for row in joins[identifier])
        elif definition['kind'] == 'entry':
            candidates.add(('entry', None))
        else:
            assert definition['kind'] == 'data_write'
            candidates.add((definition['operation'], logical - span.start))
    return candidates


def _physical_place(case, item, span, vm):
    kind = span.object_id.kind
    if kind is StorageObjectKind.REGISTER_FILE:
        return case['ids'][1], span.start, span.size
    if kind is StorageObjectKind.FUNCTION_UNIQUE:
        return case['ids'][2], span.start, span.size
    anchored = anchored_span(span, item.anchors)
    assert anchored is not None
    # Anchors are original function-ENTRY pointers, not the current RSP/RBP.
    place = _place(anchored, {}, vm.entry_values, case['ids'][1], moduli=vm._moduli)
    assert place is not None and place[2] == span.size
    return place


class _ObservedFlow(_ObservedMemory):
    """Observe captured spans at real block entry, without changing p-code."""

    def __init__(self, case, item, record, **kwargs):
        self.case, self.item, self.graph = case, item, record['cycle_graph']
        cfg = build_pcode_block_graph(item.unit.observation, item.unit.scopes.function.entry)
        self.blocks = {block.key: block for block in cfg.blocks}
        self.locations = _raw_block_edges(item, ())[1]
        self.edge_states = {(edge['source'], edge['target']): state
                            for edge, state in zip(self.graph['cfg']['edges'], self.graph['edge_states'], strict=True)}
        self.previous, self.flow_bytes, self.edge_visits = None, 0, Counter()
        super().__init__(item.unit.observation, constant_space=case['ids'][0], seed=0,
                         image=case['image'], address_bits=case['address_bits'], **kwargs)

    def _execute(self, key, operation, run):
        current, first = self.locations[key]
        if self.previous is not None and (current != self.previous or first):
            paths = []
            for successor in self.blocks[self.previous].successors:
                path, seen = [self.previous, successor], {self.previous}
                while path[-1] != current:
                    block = self.blocks[path[-1]]
                    if block.key in seen or block.start != block.stop or len(block.successors) != 1:
                        break
                    seen.add(block.key)
                    path.append(block.successors[0])
                if path[-1] == current:
                    paths.append(path)
            assert len(paths) == 1, 'only original unique NOP chains may be bridged'
            for edge in zip(paths[0], paths[0][1:]):
                self.edge_visits[edge] += 1
                state = self.edge_states[edge]
                for fact in state['facts']:
                    span = ByteSpan.from_canonical_key(tuple(fact['span']))
                    space, address, size = _physical_place(self.case, self.item, span, self)
                    for byte in range(size):
                        actual = self.raw_last_writers.get(self._key(space, address + byte), ('entry', None))
                        assert actual in _writer_candidates(self.graph, fact['definition_ids'], span.start + byte), (
                            edge, fact['span'], byte, actual, fact['definition_ids'])
                        self.flow_bytes += 1
        self.previous = current
        return super()._execute(key, operation, run)


def _expected(suffix, seed, step, count, selector):
    value, remaining = seed, count & 7
    if suffix == 'nested':
        while remaining:
            for _ in range((selector & 3) + 1):
                value = (value + step) & MASK
            value ^= remaining
            remaining -= 1
    elif suffix == 'multi_update':
        while remaining:
            value = ((value + step) if (selector ^ remaining) & 1 else value ^ ((step + remaining) & MASK)) & MASK
            value = (value + remaining) & MASK
            remaining -= 1
    elif suffix == 'multi_backedge':
        while remaining:
            value = ((value + step) if (selector ^ remaining) & 1 else value ^ step) & MASK
            remaining -= 1
    elif suffix == 'irreducible':
        right = bool(selector & 1)
        while remaining:
            value = (value ^ step) if right else (value + step) & MASK
            remaining -= 1
            if remaining & 1:
                right = not right
    elif suffix == 'sequential':
        for _ in range(remaining):
            value = (value + step) & MASK
        for remaining in range(selector & 7, 0, -1):
            value ^= (step + remaining) & MASK
    else:
        assert suffix == 'memory'
        shadow = (seed + 1) & MASK
        while remaining:
            value = (value + step) & MASK
            if (selector ^ remaining) & 1:
                shadow = value ^ shadow
            else:
                value = (shadow + step) & MASK
            remaining -= 1
        value ^= shadow
    return value


def _all_load_writers(vm, graph):
    reads = {}
    for row in graph['reads']:
        if row['span'][1] in ('address_space', 'function_relative'):
            reads.setdefault(row['operation'], []).append(row)
    checked = 0
    for key, samples in vm.raw_load_sources.items():
        (read,) = reads[key]
        span = ByteSpan.from_canonical_key(tuple(read['span']))
        for sources in samples:
            assert len(sources) == span.size
            for byte, source in enumerate(sources):
                assert source['at'] == byte
                logical = span.start + byte
                (fragment,) = [row for row in read['fragments']
                               if (part := ByteSpan.from_canonical_key(tuple(row['span']))).start <= logical < part.end]
                actual = (source['writer'], source['offset']) if 'writer' in source else ('entry', None)
                assert actual in _writer_candidates(graph, [row['reference']['id'] for row in fragment['definitions']], logical), (
                    key, byte, actual, fragment)
                checked += 1
    assert checked
    return checked


@pytest.mark.parametrize('suffix', CASES)
def test_actual_general_cycle_graph_retains_cfg_ssa_and_every_observed_writer(general_cycle_binary, monkeypatch, suffix):
    case = general_cycle_binary
    item = case['results'][case['names'][f'case_cycle_{suffix}']]
    cfg, blocks, edges, components = _raw_shape(item, suffix)
    record = _root(item)
    assert not record['truncated'] and record['demand_complete']
    _topology(record, item, cfg, blocks, edges, components)
    _projection(record, item)
    # This added structural view neither replaces the old root nor grants
    # concrete loop evaluation, a trip count, or an invariant predicate.
    import tdo_v2._record_cycles as module
    with monkeypatch.context() as patch:
        patch.setattr(module, 'publish_cycle_graph', lambda builder: None)
        original = _root(item)
    # Optional derived views do not exist when their original graph is
    # disabled. Compare the unchanged primary record, not these additions.
    assert {key: value for key, value in record.items() if key not in ('nodes', 'cycle_graph', 'loop_summaries')} == {
        key: value for key, value in original.items() if key != 'nodes'}
    assert [node for node in record['nodes'] if not node.get('cycle_only')] == original['nodes']
    for route in ('injected', 'stitched'):
        assert eligibility(record, route=route) == eligibility(original, route=route) == 'loop'
        with pytest.raises(Ineligible, match='loop'):
            evaluate(record, lambda _: pytest.fail('structural graph must not execute a loop'), route=route)

    visited, visited_loads, load_bytes, flow_bytes, runs = set(), set(), 0, 0, 0
    (return_key, return_operation), = [(key, operation) for key, operation in _operations(item)
                                       if operation.opcode == 'RETURN']
    for seed, step in ((0, 7), (0x1122334455667788, 0x1000000000000001), (MASK, 1)):
        for count in (0, 1, 3, 5):
            for selector in (0, 1, 2):
                vm = _ObservedFlow(case, item, record)
                for offset, value in ((RSP, 0x70000000), (RDI, seed), (RSI, step), (RDX, count), (RCX, selector)):
                    vm.preset(case['ids'][1], offset, 8, value)
                # Real outer RETURN reads this entry-memory address. There
                # are no callees/scheduler-forced returns in this fixture.
                vm.preset(item.unit.scopes.function.entry.space_id, 0x70000000, 8, 0x2000)
                observed = vm.run()
                assert observed.completed and observed.executed and not vm.opaque_opcodes
                assert _value(vm, case['ids'][1], RAX, 8) == _expected(suffix, seed, step, count, selector)
                assert observed.executed.count(return_key) == 1
                ip = return_operation.inputs[0]
                assert _value(vm, ip.coordinate.space_id, ip.coordinate.byte_offset, ip.byte_size) == 0x2000
                assert _value(vm, case['ids'][1], RSP, 8) == 0x70000008
                actual_edges, _ = _raw_block_edges(item, observed.executed)
                assert actual_edges == vm.edge_visits
                visited.update(actual_edges)
                visited_loads.update(vm.raw_load_sources)
                load_bytes += _all_load_writers(vm, record['cycle_graph'])
                flow_bytes += vm.flow_bytes
                runs += 1
    assert runs == 36 and visited == edges
    assert visited_loads == {key for key, operation in _operations(item) if operation.opcode == 'LOAD'}
    assert load_bytes and flow_bytes
