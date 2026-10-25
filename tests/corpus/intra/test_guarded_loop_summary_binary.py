"""Actual unmodified p-code checks for invariant choices and strided writes."""

from hashlib import sha256
import json
import os
from pathlib import Path

import pytest

from synthetic import RAX, RDI, RSI, RDX, RSP
from test_general_cycle_binary import MASK, _root, _raw_block_edges
from test_multi_target_memory_binary import _load, _value
from test_loop_summary_binary import _run, _SummaryVisits


IMAGE_SHA = 'ba1fa527387a9bdf63cd7bbc69d98ccc11a49e4f0dcfb265d97cbeceff141897'


@pytest.fixture(scope='module')
def guarded_summary_binary():
    with pytest.MonkeyPatch.context() as patch:
        case = _load('TDO_GUARDED_SUMMARY_BUNDLE', patch, require_calls=False)
        generation = Path(os.environ['TDO_GUARDED_SUMMARY_BUNDLE'])
        manifest = json.loads((generation / 'manifest.json').read_text())
        original = next(row for row in manifest['members'] if row['id'] == manifest['original_member_id'])
        assert original['sha256'] == IMAGE_SHA
        assert sha256((generation / original['path']).read_bytes()).hexdigest() == IMAGE_SHA
        yield case


def test_actual_shared_invariant_choice_matches_all_raw_memory_effects(guarded_summary_binary):
    case = guarded_summary_binary
    item = case['results'][case['names']['case_summary_branch']]
    record = json.loads(json.dumps(_root(item)))
    summary, = record['loop_summaries']
    assert summary['complete'] and len(summary['cases']) == 2, summary
    runs = visits = 0
    for initial in (0, MASK, 0x1122334455667788):
        for selector in (0, 1, 256):
            for count in (0, 1, 3, 9):
                vm = _run(case, item, record, initial, 7, count, selector, no=11)
                assert _value(vm, case['ids'][1], RAX, 8) == (initial + count * (7 if selector else 11)) & MASK
                assert len(vm.invocations) == 1
                runs += 1
                visits += len(vm.visits)
    assert (runs, visits) == (36, 153)


def test_actual_feedback_condition_keeps_original_graph_without_false_summary(guarded_summary_binary):
    case = guarded_summary_binary
    record = _root(case['results'][case['names']['case_summary_feedback']])
    summary, = record['loop_summaries']
    assert not summary['complete'] and 'mutable' in summary['reason']
    assert record['cycle_graph']['transitions'][0]['complete']


@pytest.mark.parametrize('suffix,offset', (('store', 0), ('after', 8)))
def test_actual_strided_store_footprint_and_untouched_bytes(guarded_summary_binary, suffix, offset):
    case = guarded_summary_binary
    item = case['results'][case['names']['case_strided_' + suffix]]
    record = json.loads(json.dumps(_root(item)))
    assert not record['cycle_graph']['transitions'][0]['complete']
    assert record['cycle_graph']['unresolved_accesses']
    runs = visits = writes = 0
    for base in (0x81000000, 0x81000003):
        for value in (0, MASK, 0x1122334455667788):
            for count in (0, 1, 3, 7, 19):
                vm = _SummaryVisits(case, item, record, collection='write_effect_transitions')
                for register, val in ((RSP, 0x70000000), (RDI, base), (RSI, value), (RDX, count)):
                    vm.preset(case['ids'][1], register, 8, val)
                space = item.unit.scopes.function.entry.space_id
                vm.preset(space, 0x70000000, 8, 0x2000)
                expected = {address: (address * 37) & 255 for address in range(base - 8, base + 8 * count + 24)}
                for address, byte in expected.items():
                    vm.preset(space, address, 1, byte)
                run = vm.run()
                assert run.completed and not vm.opaque_opcodes and vm.pending is vm.active is None
                result, = vm.invocations
                memory = result['memory_transform']
                assert memory['count'] == count and memory['width'] == memory['stride'] == 8
                assert memory['value'] == (value if count else None)
                assert memory['first_address'] == (base + offset if count else None)
                for i in range(count):
                    for byte in range(8):
                        expected[memory['first_address'] + i * memory['stride'] + byte] = (memory['value'] >> (8 * byte)) & 255
                assert all(_value(vm, space, address, 1) == byte for address, byte in expected.items())
                assert _value(vm, case['ids'][1], RAX, 8) == base + 8 * count
                edges, _ = _raw_block_edges(item, run.executed)
                graph_edges = record['cycle_graph']['cfg']['edges']
                back, exit = graph_edges[vm.summary['continue_edge']], graph_edges[vm.summary['exit_edge']]
                assert edges[back['source'], back['target']] == count
                assert edges[exit['source'], exit['target']] == 1
                assert sum(len(row['writes']) for row in vm.visits) == count
                writes += count
                visits += len(vm.visits)
                runs += 1
    assert (runs, visits, writes) == (30, 210, 180)


@pytest.mark.parametrize('suffix,reason', (('load', 'LOAD'), ('mutable', 'value varies'), ('overlap', 'overlapping')))
def test_actual_unsupported_memory_variants_remain_explicit(guarded_summary_binary, suffix, reason):
    case = guarded_summary_binary
    record = _root(case['results'][case['names']['case_strided_' + suffix]])
    view, = record['write_effect_transitions']
    if suffix == 'load':
        assert not view['complete'] and reason in view['reason']
    else:
        summary, = [row for row in record['loop_summaries'] if row['transition'] == view['id']]
        assert not summary['complete'] and reason in summary['reason']
    assert not record['cycle_graph']['transitions'][0]['complete']
