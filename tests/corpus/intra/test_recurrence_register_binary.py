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
    assert any(operation.opcode == 'CBRANCH' for _, operation in _operations(caller))
    (call, function), = caller.calls.items()
    (exit_summary,) = caller.summary.exits
    (run,) = [row for row in exit_summary.runs
              if row.span.object_id.kind.value == 'register_file' and row.span.start == RAX]
    (definition,) = run.definitions
    record = _physical(case, caller, definition, run.span)
    assert not record['truncated']
    assert any('physical_register_choice' in node for node in record['nodes'])
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
            if selected:
                bits = ((1 << (8 * size)) - 1) << (8 * offset)
                value = (value & ~bits) | replacement << (8 * offset)
            interpreted = evaluate_physical(record, _entry(vm, case['ids'][1]))
            assert interpreted.value == _value(vm, case['ids'][1], RAX, 8) == (value + 5) & mask
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
