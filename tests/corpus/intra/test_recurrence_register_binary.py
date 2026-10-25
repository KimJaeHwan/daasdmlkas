"""Sealed compiled conditional bytes and structural loops, not native runs."""

from collections import Counter

import pytest

from synthetic import RAX, RDI, RDX, RSI, RSP
from test_indirect_physical_binary import _ObservedMemory, _all_load_byte_writers, _physical, _return_witness
from test_multi_target_memory_binary import _entry, _execute, _load, _operations, _value
from tdo_v2.operation_records import Ineligible, eligibility, evaluate, evaluate_physical, root_record
from tdo_v2.pcode_blocks import build_pcode_block_graph


@pytest.mark.parametrize('suffix,offset,size,replacement', (
    ('al', 0, 1, 0xaa), ('ah', 1, 1, 0xbb), ('ax', 0, 2, 0xccdd), ('from_call', 1, 1, 0xbb),
))
def test_compiled_conditional_registers_share_original_branch_and_call_memory(
        monkeypatch, suffix, offset, size, replacement):
    case = _load('TDO_CONDITIONAL_REGISTER_BUNDLE', monkeypatch)
    caller = case['results'][case['names'][f'case_conditional_{suffix}']]
    operations = _operations(caller)
    (branch,) = [key for key, operation in operations if operation.opcode == 'CBRANCH']
    (call, function), = caller.calls.items()
    after = operations[next(index for index, (key, _) in enumerate(operations) if key == call) + 1:]
    (write_key, _), = [(key, operation) for key, operation in after
                      if operation.opcode == 'COPY' and operation.output is not None
                      and operation.output.kind.name == 'REGISTER'
                      and operation.output.coordinate.byte_offset == RAX + offset
                      and operation.output.byte_size == size
                      and operation.inputs[0].kind.name == 'CONSTANT'
                      and operation.inputs[0].coordinate.byte_offset == replacement]
    (exit_summary,) = caller.summary.exits
    (run,) = [row for row in exit_summary.runs
              if row.span.object_id.kind.value == 'register_file' and row.span.start == RAX]
    (definition,) = run.definitions
    record = _physical(case, caller, definition, run.span)
    assert not record['truncated']
    nodes = {node['id']: node for node in record['nodes']}
    (consumer,) = [node for node in record['nodes'] if node.get('key') in {key for key, _ in after}
                   and node.get('opcode') == 'INT_ADD'
                   and node.get('output', {}).get('kind') == 'register_file'
                   and node['output']['start'] == RAX and node['output']['size'] == 8]
    (value_read,) = [operand for operand in consumer['operands'] if operand['index'] == 0]
    (write_node,) = [node for node in record['nodes'] if node.get('key') == write_key]

    def byte_sources(parts):
        sources = {}
        for part in parts:
            low, high = part['at']
            source_low, source_high = part['bytes']
            assert high - low == source_high - source_low
            for byte in range(low, high):
                assert byte not in sources
                sources[byte] = (part['node'], source_low + byte - low)
        assert set(sources) == set(range(8))
        return sources

    control = record['control']
    assert set(control['decisions']) == {branch}
    decision = control['decisions'][branch]
    assert decision['decision'] == branch
    if suffix == 'from_call':
        # A physical CALL execution does not turn its static predicate into
        # an independently supported numeric/condition contract.
        assert decision['evaluation'].startswith('fallback:')
    else:
        assert decision['evaluation'] == 'supported'

    context = record['physical_calls'][call]
    assert context['function'] == function
    callee_outputs = [row for row in context['outputs'] if 0 <= row['offset'] < 8]
    callee_bytes = byte_sources([{**row['part'], 'at': [row['offset'], row['offset'] + row['size']]}
                                 for row in callee_outputs])
    (terminal_id,) = {producer for producer, _ in callee_bytes.values()}
    terminal = nodes[terminal_id]
    assert terminal['physical_context'] == call and terminal['function'] == function
    assert terminal['key'] in dict(_operations(case['results'][function]))
    assert terminal['output']['kind'] == 'register_file'
    assert terminal['output']['start'] == RAX and terminal['output']['size'] == 8
    assert all(callee_bytes[byte] == (terminal_id, byte) for byte in range(8))

    written_bytes = set(range(offset, offset + size))
    unchanged_bytes = set(range(8)) - written_bytes
    debt = any(row.operation_key == consumer['key'] and call in row.intervening_calls
               for row in caller.normalized.call_clobber_reads)
    choices = [node for node in record['nodes'] if 'physical_register_choice' in node]
    if debt:
        # The older unresolved-debt route overlays the original guarded phi.
        assert len(choices) == 1
        relation = value_read['physical_register_fragments']
        parts = relation['parts']
        assert relation['read'] == consumer['key']
        assert all(piece['call'] == call for piece in relation['overrides'])
        assert {byte for piece in relation['overrides']
                for byte in range(piece['offset'], piece['offset'] + piece['size'])} == set(range(8))
    else:
        # Forward resolution leaves the exact original SSA CALL/COPY join.
        assert not choices and 'physical_register_fragments' not in value_read
        parts = value_read['parts']
        (call_row,) = [node for node in record['nodes'] if node.get('kind') == 'call'
                       and node.get('call') == call and 'register:rax' in node['output']['writes']]
        (stitched,) = [item for item in call_row['physical_stitched']
                       if item['output']['kind'] == 'register_file'
                       and item['output']['start'] == RAX and item['output']['size'] == 8]
        assert stitched['context'] == call and stitched['part']['node'] == terminal_id
        assert stitched['part']['bytes'] == [0, 8]

    sources = byte_sources(parts)
    (protected,) = [part for part in parts if part['at'] == [offset, offset + size]]
    phi = nodes[protected['node']]
    assert phi['kind'] == 'phi' and phi['size'] == size
    assert all(sources[byte] == (phi['id'], byte - offset) for byte in written_bytes)
    if debt:
        choice = phi['physical_register_choice']
        original = nodes[choice['source']['node']]
        assert original['kind'] == 'phi' and original['reason'] == 'join'
        assert choice['call'] == choice['context'] == call
        assert [(item['kind'], item['operation']) for item in choice['sources']] == [
            ('call', None), ('retained', write_key)]
        assert all(sources[byte] == callee_bytes[byte] for byte in unchanged_bytes)
        assert phi['guarded_sources'] == original['guarded_sources']
    else:
        assert phi['reason'] == 'join'
        assert all(sources[byte] == (call_row['id'], byte) for byte in unchanged_bytes)
        assert all(part.get('output') == stitched['output'] for part in parts
                   if part['node'] == call_row['id'])
    assert phi['guarded_sources']['reach'] == 1
    guards = phi['guarded_sources']['guards']
    assert len(guards) == len(phi['alternatives']) == 2
    assert [(control['nodes'][guard]['decision'], control['nodes'][guard]['true'],
             control['nodes'][guard]['false']) for guard in guards] == [
                 (branch, 1, 0), (branch, 0, 1)]
    call_arm, write_arm = phi['alternatives']
    assert call_arm['at'] == write_arm['at'] == [0, size]
    assert call_arm['bytes'] == [offset, offset + size]
    assert write_arm['bytes'] == [0, size] and write_arm['node'] == write_node['id']
    assert call_arm['node'] == (terminal_id if debt else call_row['id'])
    if not debt:
        assert call_arm['defined_by'] == call_row['key']
        assert write_arm['defined_by'] == write_key
    if suffix == 'from_call':
        (condition_part,) = decision['operand']['parts']
        predicate = nodes[condition_part['node']]
        assert predicate['opcode'] == 'INT_EQUAL'
        (and_part,) = predicate['operands'][0]['parts']
        masked = nodes[and_part['node']]
        assert masked['opcode'] == 'INT_AND'
        source = masked['operands'][0]
        if debt:
            binding = source['physical_register']
            assert binding['call'] == binding['context'] == call
            assert binding['part']['node'] == terminal_id
        else:
            assert source['parts'][0]['node'] == call_row['id']
            assert source['parts'][0]['output'] == stitched['output']
    seeds = (0, 1, 0xff, 0xffff, 0x1122334455667788, 0x8000000000000000,
             0xfffffffffffffffe, 0xffffffffffffffff)
    mask = (1 << 64) - 1
    visited = set()
    for seed in seeds:
        for flag in ((0,) if suffix == 'from_call' else (0, 1)):
            vm = _execute(case, caller, {RSP: 0x70000000, RDI: seed, RSI: flag},
                          interpreter_type=_ObservedMemory)
            value = (seed + 1) & mask
            selected = value & 1 if suffix == 'from_call' else flag & 1
            visited.add(bool(selected))
            assert (write_key in vm.fixture_run.executed) == bool(selected)
            if selected:
                bits = ((1 << (8 * size)) - 1) << (8 * offset)
                value = (value & ~bits) | replacement << (8 * offset)
            interpreted = evaluate_physical(record, _entry(vm, case['ids'][1]))
            assert interpreted.value == _value(vm, case['ids'][1], RAX, 8) == (value + 5) & mask
            decisions = [row for row in interpreted.evidence if row['kind'] == 'decision']
            assert decisions and {(row['decision'], row['taken']) for row in decisions} == {
                (branch, not bool(selected))}
            _return_witness(case, vm, caller, call, function)
            _all_load_byte_writers(vm, interpreted)
    assert visited == {False, True}


def _raw_block_edges(item, executed):
    cfg = build_pcode_block_graph(item.unit.observation, item.unit.scopes.function.entry)
    instructions = {row.address: row for row in item.unit.observation.instructions}
    locations = {}
    for block in cfg.blocks:
        row = instructions[block.instruction]
        for ordinal in range(block.start, block.stop):
            key = f'{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:{row.operations[ordinal].opcode}'
            locations[key] = (block.key, ordinal == block.start)
    trace = []
    for operation in executed:
        block, first = locations[operation]
        if not trace or trace[-1] != block or first:
            trace.append(block)
    blocks = {block.key: block for block in cfg.blocks}
    edges = Counter()
    for previous, current in zip(trace, trace[1:]):
        paths = []
        for successor in blocks[previous].successors:
            path, seen = [previous, successor], {previous}
            while path[-1] != current:
                empty = blocks[path[-1]]
                if empty.key in seen or empty.start != empty.stop or len(empty.successors) != 1:
                    break
                seen.add(empty.key)
                path.append(empty.successors[0])
            if path[-1] == current:
                paths.append(path)
        # NOP-only instructions have no executed p-code key. Admit only
        # their unique raw CFG chain, not an inferred value/control path.
        assert len(paths) == 1
        edges.update(zip(paths[0], paths[0][1:]))
    return edges, locations


@pytest.mark.parametrize('suffix', ('register', 'memory'))
def test_compiled_recurrence_uses_actual_initial_and_backedge_definitions(monkeypatch, suffix):
    case = _load('TDO_RECURRENCE_BUNDLE', monkeypatch, require_calls=False)
    item = case['results'][case['names'][f'case_{suffix}_recurrence']]
    (exit_summary,) = item.summary.exits
    (run,) = [row for row in exit_summary.runs
              if row.span.object_id.kind.value == 'register_file' and row.span.start == RAX]
    record = root_record(item.normalized, item.unit,
                         [(item.normalized.memory_graph.definition_nodes[definition], (run.span,))
                          for definition in run.definitions])
    assert not record['truncated'] and record['demand_complete']
    assert eligibility(record) == 'loop'
    candidates = [node['recurrence'] for node in record['nodes'] if 'recurrence' in node]
    wanted = 'register_file' if suffix == 'register' else 'function_relative'
    relation = next(row for row in candidates if row['span'][1] == wanted and
                    (suffix == 'memory' or row['span'][-2] == '0'))
    assert relation['evaluation'] == 'structural_only'
    assert relation['conditions'] and all(not condition['operand'].get('unresolved')
                                         for condition in relation['conditions'])
    init = relation['init']['definition_ref']['operation']
    transition = relation['transition']['definition_ref']['operation']
    assert init is not None and transition is not None
    mask = (1 << 64) - 1
    for initial, step in ((0, 7), (0x1122334455667788, 0x1000000000000001), (mask, 1)):
        for count in (0, 1, 3, 7):
            # Reuse the raw interpreter directly: this fixture has no CALL,
            # so it needs no observed call-stack selector or ABI model.
            vm = _ObservedMemory(item.unit.observation, constant_space=case['ids'][0], seed=0,
                                 image=case['image'], address_bits=case['address_bits'])
            for offset, value in ((RSP, 0x70000000), (RDI, initial), (RSI, step), (RDX, count)):
                vm.preset(case['ids'][1], offset, 8, value)
            observed = vm.run()
            assert observed.completed and not vm.opaque_opcodes
            assert _value(vm, case['ids'][1], RAX, 8) == (initial + count * step) & mask
            edges, locations = _raw_block_edges(item, observed.executed)
            for edge in relation['init']['edges']:
                assert edges[edge['predecessor'], edge['block']] == int(count > 0)
            for edge in relation['transition']['edges']:
                assert edges[edge['predecessor'], edge['block']] == max(count - 1, 0)
            assert observed.executed.count(init) == 1
            assert observed.executed.count(transition) == count
            if suffix == 'memory' and count:
                loads = [(key, samples) for key, samples in vm.raw_load_sources.items()
                         if locations[key][0] == relation['header']]
                assert loads
                for key, samples in loads:
                    assert len(samples) == count
                    before_store = int(key.split(':')[2]) < int(transition.split(':')[2])
                    for iteration, sources in enumerate(samples):
                        writer = init if iteration == 0 and before_store else transition
                        assert sources == [{'at': byte, 'writer': writer, 'offset': byte} for byte in range(8)]
    with pytest.raises(Ineligible, match='loop'):
        evaluate(record, lambda _: pytest.fail('a structural recurrence is not a concrete loop evaluator'))
