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
    relations = [item['physical_register_fragments'] for node in record['nodes']
                 for item in node.get('operands', ()) if 'physical_register_fragments' in item]
    if suffix != 'eax':
        assert relations
        expected_bytes = set(range(8)) - set(range(offset, offset + size))
        assert all({byte for piece in relation['overrides']
                    for byte in range(piece['offset'], piece['offset'] + piece['size'])} == expected_bytes
                   for relation in relations)
        assert any(node.get('key') == write_key for node in record['nodes'])
    else:
        assert not relations, 'the raw whole-register COPY is authoritative'
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
            assert any(row['kind'] == 'register_fragments' for row in interpreted.evidence)
