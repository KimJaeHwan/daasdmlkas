"""Compiled x64 partial-register CALLs, executed as original extracted p-code.

TDO_PARTIAL_REGISTER_BUNDLE selects a sealed export of partial_register_call.c.
This is not native execution. No call result or source provenance is injected.
"""

import pytest

from synthetic import RAX, RDI, RSP
from test_indirect_physical_binary import _ObservedMemory, _all_load_byte_writers, _physical, _return_witness
from test_multi_target_memory_binary import _entry, _execute, _load, _operations, _value
from tdo_v2.operation_records import evaluate_physical


@pytest.mark.parametrize('suffix,offset,size,replacement', (
    ('al', 0, 1, 0xaa), ('ah', 1, 1, 0xbb), ('ax', 0, 2, 0xccdd),
    ('eax', 0, 8, 0xabcdef01),  # actual Ghidra COPY already includes upper zeroes
))
def test_compiled_partial_registers_keep_call_memory_and_original_byte_writes(
        monkeypatch, suffix, offset, size, replacement):
    case = _load('TDO_PARTIAL_REGISTER_BUNDLE', monkeypatch)
    caller = case['results'][case['names'][f'case_partial_{suffix}']]
    (call, function), = caller.calls.items()
    operations = _operations(caller)
    after = operations[next(i for i, (key, _) in enumerate(operations) if key == call) + 1:]
    (write_key, write), = [(key, operation) for key, operation in after if operation.opcode == 'COPY'
                         and operation.output.coordinate.byte_offset == RAX + offset
                         and operation.output.byte_size == size
                         and operation.inputs[0].kind.name == 'CONSTANT'
                         and operation.inputs[0].coordinate.byte_offset == replacement]
    assert write.output.kind.name == 'REGISTER'
    (exit_summary,) = caller.summary.exits
    (run,) = [row for row in exit_summary.runs
              if row.span.object_id.kind.value == 'register_file' and row.span.start == RAX]
    (definition,) = run.definitions
    record = _physical(case, caller, definition, run.span)
    assert not record['truncated'] and record['demand_complete']
    nodes = {node['id']: node for node in record['nodes']}
    post_call_keys = {key for key, _ in after}
    (consumer,) = [node for node in record['nodes'] if node.get('key') in post_call_keys
                   and node.get('opcode') == 'INT_ADD'
                   and node.get('output', {}).get('kind') == 'register_file'
                   and node['output']['start'] == RAX and node['output']['size'] == 8]
    (value_read,) = [operand for operand in consumer['operands'] if operand['index'] == 0]

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

    (write_node,) = [node for node in record['nodes'] if node.get('key') == write_key]
    relations = [item['physical_register_fragments'] for node in record['nodes']
                 for item in node.get('operands', ()) if 'physical_register_fragments' in item]
    if suffix != 'eax':
        written_bytes = set(range(offset, offset + size))
        expected_bytes = set(range(8)) - written_bytes
        if relations:
            # An unresolved call-clobber debt requires the physical overlay.
            relation = value_read['physical_register_fragments']
            assert relation in relations
            assert all({byte for piece in row['overrides']
                        for byte in range(piece['offset'], piece['offset'] + piece['size'])} == expected_bytes
                       for row in relations)
            assert all(piece['call'] == call for piece in relation['overrides'])
            assert all(piece['call'] == call and piece['operation'] == write_key
                       and set(range(piece['offset'], piece['offset'] + piece['size'])) <= written_bytes
                       for piece in relation['retained'])
            sources = byte_sources(relation['parts'])
            assert all(sources[byte] == (write_node['id'], byte - offset) for byte in written_bytes)
            assert all(nodes[sources[byte][0]].get('physical_context') == call
                       and nodes[sources[byte][0]].get('function') == function
                       and sources[byte][1] == byte
                       for byte in expected_bytes)
        else:
            # When the forward pass resolves the debt, original SSA already
            # combines the post-CALL byte write with the CALL output bytes.
            assert not any(row.operation_key == consumer['key'] and call in row.intervening_calls
                           for row in caller.normalized.call_clobber_reads)
            sources = byte_sources(value_read['parts'])
            assert all(sources[byte] == (write_node['id'], byte - offset) for byte in written_bytes)
            (call_row,) = [node for node in record['nodes'] if node.get('kind') == 'call'
                           and node.get('call') == call and 'register:rax' in node['output']['writes']]
            assert all(sources[byte] == (call_row['id'], byte) for byte in expected_bytes)
            (stitched,) = [item for item in call_row['physical_stitched']
                           if item['output']['kind'] == 'register_file'
                           and item['output']['start'] == RAX and item['output']['size'] == 8]
            assert stitched['context'] == call and stitched['part']['bytes'] == [0, 8]
            terminal = nodes[stitched['part']['node']]
            assert terminal['physical_context'] == call and terminal['function'] == function
            assert terminal['output'] == stitched['output']
            assert terminal['key'] in dict(_operations(case['results'][function]))
            assert all(part.get('output') == stitched['output'] for part in value_read['parts']
                       if part['node'] == call_row['id'])
    else:
        assert not relations, 'the raw whole-register COPY is authoritative'
        assert byte_sources(value_read['parts']) == {
            byte: (write_node['id'], byte) for byte in range(8)}
    mask = (1 << 64) - 1
    seeds = (0, 1, 0xff, 0xffff, 0x1122334455667788, 0x8000000000000000,
             0xfffffffffffffffe, mask)
    for seed in seeds:
        vm = _execute(case, caller, {RSP: 0x70000000, RDI: seed}, interpreter_type=_ObservedMemory)
        value = (seed + 1) & mask
        bits = ((1 << (8 * size)) - 1) << (8 * offset)
        expected = (((value & ~bits) | replacement << (8 * offset)) + 5) & mask
        interpreted = evaluate_physical(record, _entry(vm, case['ids'][1]))
        assert interpreted.value == _value(vm, case['ids'][1], RAX, 8) == expected
        if suffix != 'eax':
            _return_witness(case, vm, caller, call, function)
            _all_load_byte_writers(vm, interpreted)
            assert any(row['kind'] == ('register_fragments' if relations else 'call')
                       for row in interpreted.evidence)
