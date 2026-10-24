"""Local certificate/inventory checks on engine-built one-visit views.

The separate receipts detect modification relative to the trusted engine
output. They do NOT authenticate arbitrary unsigned JSON. Local certificate
checks additionally verify original write stops and CFG/SSA byte references;
they are not another reaching-definition solve or instruction interpreter.
"""

from __future__ import annotations

from hashlib import sha256
import json

from .memory_contracts import MemoryDefinitionKind
from ._record_conditions import ConditionIndex
from .operation_records import Ineligible, _node_parts
from .resource_limits import step
from .span_geometry import ByteSpan


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _authority(record):
    return dict(graph={key: value for key, value in record['cycle_graph'].items()
                       if key not in ('transitions', 'transition_contracts')},
                nodes=record['nodes'], endianness=record['endianness'])


def seal(record):
    graph = record['cycle_graph']
    complete = [row for row in graph.get('transitions', ()) if row['complete']]
    source = _digest(_authority(record)) if complete else None
    graph['transition_contracts'] = {row['id']: dict(source=source, derived=_digest(row)) for row in complete}


def _require(value, message):
    if not value:
        raise Ineligible('one-visit contract: ' + message)


def _span(value):
    return ByteSpan.from_canonical_key(tuple(value))


def _union(spans):
    grouped = {}
    for span in spans:
        grouped.setdefault(span.object_id, []).append((span.start, span.end))
    result = {}
    for identity, intervals in grouped.items():
        merged = []
        for low, high in sorted(intervals):
            if merged and low <= merged[-1][1]:
                merged[-1] = merged[-1][0], max(merged[-1][1], high)
            else:
                merged.append((low, high))
        result[identity] = merged
    return result


def _validate(record, view, *, write_projection=None):
    graph = record['cycle_graph']
    receipts = record.get('write_effect_contracts', {}) if write_projection is not None else graph['transition_contracts']
    receipt = receipts.get(view['id'])
    _require(receipt is not None and receipt['source'] == _digest(_authority(record))
             and receipt['derived'] == _digest(view), 'derivation receipt mismatch')
    _require(view['endianness'] == record['endianness'] == 'little', 'unsupported endianness')
    scope = write_projection['output_scope'] if write_projection is not None else 'loop_carried_inputs_and_observed_RAM_writes_not_full_machine'
    _require(view['output_scope'] == scope and ('write_projection' in view) == (write_projection is not None), 'output projection scope')
    _require(view['analysis_context'] == graph['analysis_context'], 'analysis context mismatch')
    _require(view['normalization_assumptions'] == graph['analysis_context']['normalization_assumptions'],
             'normalization policy mismatch')
    region = graph['cycle_hierarchy'][view['region']]
    _require(region['id'] == view['region'] and region['entry_points'] == [view['entry']], 'region identity')
    _require(view['entry_edges'] == region['entry_edges'], 'entry edge inventory')
    edges = graph['cfg']['edges']
    cut = [number for number in region['internal_edges'] if edges[number]['target'] == view['entry']]
    _require(view['cut_edges'] == cut and cut, 'cut edge inventory')
    members = set(region['blocks'])
    order = {key: i for i, key in enumerate(view['blocks'])}
    _require(set(order) == members and len(order) == len(view['blocks']) and order[view['entry']] == 0,
             'block inventory')
    predecessors = {key: set() for key in members}
    for number in region['internal_edges']:
        if number in cut:
            continue
        edge = edges[number]
        _require(order[edge['source']] < order[edge['target']], 'not a cut DAG')
        predecessors[edge['target']].add(edge['source'])
    operations = {row['key']: row for row in graph['operations']}
    original = {node['id']: node for node in record['nodes']}
    nodes = {node['id']: node for node in view['record']['nodes']}
    _require(set(nodes) == set(range(len(nodes))), 'local node identities')
    local_operations = {row['operation']: row for row in view['operations']}
    expected_operations = [row for row in graph['operations'] if row['block'] in members]
    _require(len(local_operations) == len(view['operations']) == len(expected_operations)
             and set(local_operations) == {row['key'] for row in expected_operations}, 'operation inventory')
    dag_order = sorted(expected_operations, key=lambda row: (order[row['block']],
                                                             int(row['key'].rsplit(':', 2)[1])))
    _require([row['operation'] for row in view['operations']] == [row['key'] for row in dag_order], 'operation order')
    _require({node['id'] for node in nodes.values() if node['kind'] == 'op'}
             == {row['node'] for row in local_operations.values()}, 'closed local operation inventory')
    for key, row in local_operations.items():
        raw = operations[key]
        node = nodes[row['node']]
        authority = original[raw['node']]
        _require(node['kind'] == 'op' and row['original_node'] == raw['node'] and node['original_node'] == raw['node']
                 and node['key'] == key and node['opcode'] == raw['opcode'] and row['block'] == raw['block'],
                 'original operation correspondence')
        _require(all(node.get(field) == authority.get(field) and (field in node) == (field in authority)
                     for field in ('output', 'space', 'writes', 'value', 'override')),
                 'original operation semantics')
        _require([(item['index'], item['width'], item['role'], item.get('value')) for item in node['operands']]
                 == [(item['index'], item['width'], item['role'], item.get('value'))
                     for item in original[raw['node']]['operands']], 'original operand shape')
        for item, old in zip(node['operands'], authority['operands'], strict=True):
            _require(set(item) == set(old) and all(item[field] == old[field] for field in old if field != 'parts'),
                     'original operand form')
    for node in nodes.values():
        step()
        _require(node['kind'] in ('op', 'const', 'entry', 'phi') and 'execution_guard' not in node
                 and not node.get('interrupted') and not node.get('debts'), 'unsupported local evaluation behavior')
        _require(all(not operand.get('pruned') and not operand.get('unresolved') for operand in node.get('operands', ())),
                 'pruned or unresolved local operand')
        for part in _node_parts(node):
            _require(part.get('node') in nodes and not part.get('pruned') and not part.get('loop'), 'local part reference')
            low, high = part['bytes']
            start, stop = part['at']
            target = nodes[part['node']]
            size = target.get('size') or target.get('output', {}).get('size')
            if target.get('opcode') == 'STORE':
                size = next(item['width'] for item in target['operands'] if item['index'] == 2)
            _require(type(low) is int and type(high) is int and 0 <= low < high and size is not None and high <= size
                     and 0 <= start < stop and high - low == stop - start, 'local part byte bounds')
    actions = {row['operation']: row for row in graph['writes']}
    definitions = {row['reference']['id']: row['reference'] for row in graph['definitions']}
    joins = {row['reference']['id']: [item['reference']['id'] for item in row['sources']] for row in graph['joins']}

    def raw_sources(identifiers, span):
        pending, seen, found = list(identifiers), set(), set()
        while pending:
            step()
            identifier = pending.pop()
            if identifier in seen:
                continue
            seen.add(identifier)
            definition = definitions[identifier]
            _require(_span(definition['span']).contains(span), 'source byte coverage')
            if definition['kind'] == MemoryDefinitionKind.JOIN.value:
                pending.extend(joins[identifier])
            else:
                _require(definition['kind'] in ('entry', 'data_write'), 'killed source')
                found.add(identifier)
        _require(found, 'empty original source set')
        return found

    def captured_sources(number, span):
        state = graph['edge_states'][number]
        facts = [fact for fact in state['facts'] if _span(fact['span']).contains(span)]
        _require(state['evidence'] == 'captured' and len(facts) == 1, 'missing original cut state')
        return raw_sources(facts[0]['definition_ids'], span)

    ordered_actions = {key: [row for row in dag_order if row['block'] == key and row['key'] in actions]
                       for key in members}
    step(len(members) * len(dag_order))
    # Reuse the Boolean canonicalizer to check submitted edge/reach guards,
    # not an additional path search or dataflow solve.
    logic = ConditionIndex.__new__(ConditionIndex)
    logic.guard_nodes, logic._guard_intern, logic._guard_apply_cache = [False, True], {}, {}
    local_control = view['record']['control']
    decisions = local_control['decisions']
    selections = {row['decision']: key for key, row in decisions.items()}
    predicate_rows = {row['operation']: row for row in graph['predicates'] if row['block'] in members}
    _require(set(selections) == set(predicate_rows), 'predicate inventory')
    logic._decision_rank = {selections[row['key']]: i for i, row in enumerate(dag_order)
                            if row['key'] in selections}
    decoded = [0, 1]
    for i, row in enumerate(local_control['nodes'][2:], 2):
        step()
        _require(isinstance(row, dict) and row['decision'] in logic._decision_rank
                 and type(row['true']) is int and type(row['false']) is int
                 and 0 <= row['true'] < i and 0 <= row['false'] < i, 'Boolean certificate DAG')
        decoded.append(logic._guard_node(row['decision'], decoded[row['true']], decoded[row['false']]))

    def guard(reference):
        _require(type(reference) is int and 0 <= reference < len(decoded), 'guard reference')
        return decoded[reference]

    edge_guards = {}
    for number in [*region['internal_edges'], *region['exit_edges']]:
        edge = edges[number]
        outcomes = edge['outcomes']
        _require(len(outcomes) <= 1, 'ambiguous edge outcome')
        edge_guards[number] = logic._guard_node(selections[outcomes[0]['predicate']],
                                                int(outcomes[0]['value']), int(not outcomes[0]['value'])) if outcomes else 1
    reaches = {}
    step(len(view['blocks']) * len(region['internal_edges']))
    for block in view['blocks']:
        reach = int(block == view['entry'])
        for number in region['internal_edges']:
            edge = edges[number]
            if number not in cut and edge['target'] == block:
                reach = logic._boolean('or', reach, logic._boolean('and', reaches[edge['source']], edge_guards[number]))
        reaches[block] = reach
    for row in local_operations.values():
        _require(guard(row['guard']) == reaches[row['block']], 'operation reach guard')
    for raw, selection in selections.items():
        row, predicate = decisions[selection], predicate_rows[raw]
        branch = nodes[local_operations[raw]['node']]
        operand, = [item for item in branch['operands'] if item['index'] == 1]
        _require(row['selection'] == view['id'] + '/' + raw and row['decision'] == raw
                 and (row['true_successor'], row['false_successor'])
                 == (predicate['true_target'], predicate['false_target'])
                 and row['operand'] == {**operand, 'role': 'condition'},
                 'original shared predicate operand')
    input_ids = {row['id']: row for row in view['inputs']}
    _require(len(input_ids) == len(view['inputs']), 'duplicate inputs')
    spans = [_span(row['span']) for row in view['inputs']]
    _require(not any(a.overlaps(b) for i, a in enumerate(spans) for b in spans[i + 1:]), 'overlapping inputs')
    for row in input_ids.values():
        span = _span(row['span'])
        if row['mutable']:
            _require([fact['edge'] for fact in row['cut_evidence']] == [*region['entry_edges'], *cut], 'cut input coverage')
            union = set()
            for fact in row['cut_evidence']:
                state = graph['edge_states'][fact['edge']]
                _require(state['evidence'] == 'captured' and any(
                    original_fact['span'] == fact['span'] and original_fact['definition_ids'] == fact['definition_ids']
                    for original_fact in state['facts']), 'original cut fact')
                _require(_span(fact['span']).contains(span), 'cut byte coverage')
                union.update(raw_sources(fact['definition_ids'], span))
            _require(union == set(row['definition_ids']), 'cut source union')
        else:
            _require(not row['cut_evidence'], 'fabricated invariant edge evidence')
            _require(raw_sources(row['definition_ids'], span) == set(row['definition_ids']),
                     'invariant raw byte sources')
            _require(all(definitions[identifier]['operation'] not in local_operations for identifier in row['definition_ids']),
                     'internal invariant source')
            _require(not any(_span(definitions[identifier]['span']).overlaps(span)
                             for action in dag_order if action['key'] in actions
                             for identifier in actions[action['key']]['definitions']), 'written invariant input')
    proofs = view['proofs']
    proof_origins = []
    for i, proof in enumerate(proofs):
        step()
        _require(proof['id'] == i and proof['block'] in members, 'certificate identity')
        span, allowed = _span(proof['span']), set(proof['candidate_definitions'])
        _require(raw_sources(allowed, span) == allowed, 'certificate raw candidates')
        block_actions = ordered_actions[proof['block']]
        step(1 + len(block_actions) + sum(len(actions[action['key']]['definitions']) for action in block_actions))
        stop = proof['before_position']
        _require(stop is None or type(stop) is int and 0 <= stop < len(block_actions), 'certificate stop')
        before = block_actions if stop is None else block_actions[:stop]
        matching = [identifier for action in before for identifier in actions[action['key']]['definitions']
                    if _span(definitions[identifier]['span']).overlaps(span)]
        last = matching[-1] if matching else None
        _require(last == proof['last_definition'], 'certificate last write')
        _require(guard(proof['reach']) == reaches[proof['block']], 'certificate reach guard')
        if last is not None:
            _require(last in allowed and definitions[last]['kind'] == 'data_write'
                     and _span(definitions[last]['span']).contains(span)
                     and not proof['predecessors'] and proof['input'] is None, 'certificate writer leaf')
            origins = {('definition', last): reaches[proof['block']]}
        elif proof['block'] == view['entry']:
            input_row = input_ids[proof['input']]
            _require(input_row['span'] == proof['span'] and set(input_row['definition_ids']) <= allowed
                     and not proof['predecessors'], 'certificate header state leaf')
            if not input_row['mutable']:
                _require(set(input_row['definition_ids']) == allowed, 'invariant query source identity')
            origins = {('input', proof['input']): 1}
        else:
            _require({child['block'] for child in proof['predecessors']} == predecessors[proof['block']]
                     and len(proof['predecessors']) == len(predecessors[proof['block']])
                     and proof['input'] is None, 'certificate predecessor inventory')
            origins = {}
            for child in proof['predecessors']:
                _require(type(child['proof']) is int and 0 <= child['proof'] < i, 'certificate DAG')
                parent = proofs[child['proof']]
                _require(parent['block'] == child['block'] and parent['span'] == proof['span']
                         and parent['candidate_definitions'] == proof['candidate_definitions']
                         and parent['before_position'] is None, 'certificate predecessor correspondence')
                number = child['edge']
                _require(number in region['internal_edges'] and number not in cut
                         and edges[number]['source'] == child['block'] and edges[number]['target'] == proof['block']
                         and guard(child['guard']) == edge_guards[number], 'certificate original edge guard')
                for origin, reference in proof_origins[child['proof']].items():
                    identifiers = {origin[1]} if origin[0] == 'definition' else set(input_ids[origin[1]]['definition_ids'])
                    for fact in graph['edge_states'][number]['facts']:
                        step()
                        fact_span = _span(fact['span'])
                        if fact_span.overlaps(span):
                            _require(fact_span.contains(span) and identifiers <= raw_sources(fact['definition_ids'], span),
                                     'captured predecessor source correspondence')
                    combined = logic._boolean('and', reference, edge_guards[number])
                    origins[origin] = logic._boolean('or', origins.get(origin, 0), combined)
        proof_origins.append({origin: reference for origin, reference in origins.items() if reference})

    def check_value(part, sources, proof_id, span):
        expected = proof_origins[proof_id]
        _require(len(sources) == len(expected), 'guarded origin inventory')
        actual = {}
        for source in sources:
            origin = (source['kind'], source['input'] if source['kind'] == 'input' else source['definition'])
            _require(origin not in actual, 'duplicate guarded origin')
            actual[origin] = guard(source['guard'])
            selected = source['part']
            target = nodes[selected['node']]
            _require(selected['at'] == [0, span.size], 'origin byte destination')
            if origin[0] == 'input':
                _require(target['kind'] == 'entry' and target['transition_input'] == origin[1]
                         and input_ids[origin[1]]['span'] == list(span.canonical_key)
                         and target['size'] == span.size
                         and selected['bytes'] == [0, span.size], 'bound input byte part')
            else:
                definition = definitions[origin[1]]
                original_part = graph['definitions'][origin[1]]['part']
                offset = original_part['bytes'][0] + span.start - _span(definition['span']).start
                _require(target.get('original_node') == original_part['node']
                         and selected['node'] == local_operations[definition['operation']]['node']
                         and selected['bytes'] == [offset, offset + span.size], 'current definition byte part')
        _require(actual == expected, 'guarded origin/condition correspondence')
        if len(sources) == 1:
            _require(part['node'] == sources[0]['part']['node'] and part['bytes'] == sources[0]['part']['bytes'],
                     'single origin expression part')
        else:
            target = nodes[part['node']]
            _require(target['kind'] == 'phi' and target['alternatives'] == [row['part'] for row in sources]
                     and target['size'] == span.size
                     and target['guarded_sources']['guards'] == [row['guard'] for row in sources]
                     and guard(target['guarded_sources']['reach']) == reaches[proofs[proof_id]['block']]
                     and part['bytes'] == [0, span.size], 'guarded expression part')
    expected_reads = {i: row for i, row in enumerate(graph['reads']) if row['operation'] in local_operations}
    _require({row['original_read'] for row in view['reads']} == set(expected_reads)
             and len(view['reads']) == len(expected_reads), 'read occurrence inventory')
    for row in view['reads']:
        old = expected_reads[row['original_read']]
        _require((row['operation'], row['read_ordinal'], row['span'])
                 == (old['operation'], old['read_ordinal'], old['span']), 'original read occurrence')
        block = operations[row['operation']]['block']
        position = next(i for i, action in enumerate(ordered_actions[block]) if action['key'] == row['operation'])
        atom_spans = [_span(atom['span']) for atom in row['atoms']]
        _require(_union(atom_spans) == _union([_span(old['span'])]) and not any(
            a.overlaps(b) for i, a in enumerate(atom_spans) for b in atom_spans[i + 1:]), 'read byte coverage')
        _require(len(row['parts']) == len(row['atoms']), 'read part inventory')
        for atom in row['atoms']:
            proof, span = proofs[atom['proof']], _span(atom['span'])
            fragment, = [item for item in old['fragments'] if _span(item['span']).contains(span)]
            _require(atom['original_definition_ids'] == [item['reference']['id'] for item in fragment['definitions']],
                     'original read candidates')
            _require(proof['block'] == block and proof['before_position'] == position and proof['span'] == atom['span']
                     and set(proof['candidate_definitions']) == raw_sources(atom['original_definition_ids'], span),
                     'read certificate root')
            placed, = [part for part in row['parts'] if part['at'] == [span.start - _span(old['span']).start,
                                                                      span.end - _span(old['span']).start]]
            check_value(placed, atom['sources'], atom['proof'], span)
    bindings = {(row['operation'], row['read_ordinal']): row for row in view['reads']}
    for key, operation in local_operations.items():
        node, raw = nodes[operation['node']], operations[key]
        for operand in node['operands']:
            if 'parts' not in operand:
                continue
            varnode = raw['inputs'][operand['index']]
            if varnode['kind'] == 'constant':
                part, = operand['parts']
                constant = nodes[part['node']]
                _require(constant['kind'] == 'const' and constant['value'] == varnode['offset']
                         and constant['size'] == varnode['size'] and part['bytes'] == [0, varnode['size']]
                         and part['at'] == [0, varnode['size']], 'original constant')
            else:
                kind = {'register': 'register_file', 'unique': 'function_unique'}[varnode['kind']]
                matches = [row for row in view['reads'] if row['operation'] == key and row['span'][1] == kind
                           and int(row['span'][-2], 16) == varnode['offset'] and int(row['span'][-1], 16) == varnode['size']]
                _require(matches and operand['parts'] == matches[0]['parts'], 'original operand read binding')
        if raw['opcode'] == 'LOAD':
            memory = [row for row in view['reads'] if row['operation'] == key
                      and row['span'][1] in ('address_space', 'function_relative')]
            _require(len(node['memory']) == len(memory), 'LOAD memory inventory')
            original_memory = original[raw['node']]['memory']
            for place, binding, old_place in zip(node['memory'], memory, original_memory, strict=True):
                _require(place['parts'] == binding['parts'] and place['span'] == old_place['span']
                         and place.get('place') == old_place.get('place'), 'LOAD memory binding')
    expected_effects = [row for row in dag_order if row['opcode'] in ('LOAD', 'STORE')]
    _require(len(view['effects']) == len(expected_effects), 'complete effect inventory')
    for event, raw in zip(view['effects'], expected_effects, strict=True):
        row = local_operations[raw['key']]
        _require((event['operation'], event['kind'], event['node'], event['original_node'], event['guard'])
                 == (raw['key'], raw['opcode'].lower(), row['node'], raw['node'], row['guard'])
                 and event['write_definitions'] == actions[raw['key']]['definitions'], 'effect correspondence/order')
    outcomes = [*cut, *region['exit_edges']]
    _require([row['edge'] for row in view['outcomes']] == outcomes, 'outcome inventory')
    required = [_span(definitions[identifier]['span']) for row in dag_order if row['key'] in actions
                for identifier in actions[row['key']]['definitions']
                if write_projection is None and definitions[identifier]['span'][1] in ('address_space', 'function_relative')]
    required.extend(_span(row['span']) for row in input_ids.values() if row['mutable'])
    for outcome in view['outcomes']:
        updates = [_span(row['span']) for row in outcome['updates']]
        _require(_union(updates) == _union(required) and not any(
            a.overlaps(b) for i, a in enumerate(updates) for b in updates[i + 1:]), 'complete nonoverlapping output scope')
        _require(outcome['kind'] == ('continue' if outcome['edge'] in cut else 'exit'), 'outcome kind')
        edge = edges[outcome['edge']]
        _require(guard(outcome['guard']) == logic._boolean('and', reaches[edge['source']], edge_guards[outcome['edge']]),
                 'outcome guard')
        for row in outcome['updates']:
            proof = proofs[row['proof']]
            _require(proof['block'] == edges[outcome['edge']]['source'] and proof['before_position'] is None
                     and proof['span'] == row['span'], 'output certificate root')
            span = _span(row['span'])
            candidates = set()
            for number in ([outcome['edge']] if outcome['kind'] == 'continue' else [*region['entry_edges'], *cut]):
                candidates.update(captured_sources(number, span))
            _require(set(proof['candidate_definitions']) == candidates, 'output original cut sources')
            if outcome['kind'] == 'exit':
                _require(all(source['kind'] == 'input' for source in row['sources']), 'uncaptured exit update')
            check_value(row['part'], row['sources'], row['proof'], _span(row['span']))


def validate(record, view):
    """No input values or callbacks are accessed before this returns."""
    try:
        _validate(record, view)
    except (KeyError, TypeError, ValueError, IndexError, StopIteration) as error:
        raise Ineligible('one-visit contract: malformed correspondence') from error
