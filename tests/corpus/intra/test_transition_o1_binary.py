"""Captured exit poststates against the existing sealed optimized x64 image.

TDO_EXPRESSION_O1_BUNDLE selects the Ghidra 12.0.4 export of the optimized
local_expression_views.c fixture, before its later optnone annotation. The
original image hash is pinned below. These tests execute every original
p-code instruction through the existing observer; each visit checks values,
shared decisions, ordered effects and every LOAD byte's writer epoch.
"""

from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path

import pytest

from synthetic import RAX, RCX, RDI, RDX, RSI, RSP
from test_general_cycle_binary import MASK, _root
from test_multi_target_memory_binary import _load, _value
from test_transition_chain_binary import _ChainVisits
from tdo_v2._record_transition_contract import seal, validate
from tdo_v2.operation_records import (Ineligible, eligibility, evaluate_transition,
    derive_transition_chain, evaluate_expression_consumer)


IMAGE_SHA = 'b27e76ddfc39f0bcee27d8c73f1e06ee305b57aa487b98b450adcdb365684707'


@pytest.fixture(scope='module')
def expression_o1_binary():
    with pytest.MonkeyPatch.context() as patch:
        case = _load('TDO_EXPRESSION_O1_BUNDLE', patch, require_calls=False)
        generation = Path(os.environ['TDO_EXPRESSION_O1_BUNDLE'])
        manifest = json.loads((generation / 'manifest.json').read_text())
        original = next(row for row in manifest['members'] if row['id'] == manifest['original_member_id'])
        assert original['sha256'] == IMAGE_SHA
        assert sha256((generation / original['path']).read_bytes()).hexdigest() == IMAGE_SHA
        yield case


def test_actual_o1_exit_reuses_exact_original_edge_facts(expression_o1_binary):
    case = expression_o1_binary
    item = case['results'][case['names']['case_view_shared']]
    record = _root(item)
    view, = record['cycle_graph']['transitions']
    assert view['complete'] and view['entry'] == '1b1:382' and view['cut_edges'] == [20]
    validate(record, view)
    outcome, = [row for row in view['outcomes'] if row['kind'] == 'exit']
    assert outcome['edge'] == 21
    graph = record['cycle_graph']
    edge = graph['cfg']['edges'][21]
    assert (edge['source'], edge['target']) == ('1b1:380', '1b1:3a6')
    assert [(row['span'][-2], row['captured_exit_evidence']['definition_ids']) for row in outcome['updates']] == [
        ('ffffffffffffffe8', [69, 146]), ('fffffffffffffff0', [99]), ('10', [101])]
    for update in outcome['updates']:
        evidence = update['captured_exit_evidence']
        fact, = [row for row in graph['edge_states'][21]['facts'] if row['span'] == evidence['span']]
        assert evidence == dict(edge=21, span=fact['span'], definition_ids=fact['definition_ids'])
        flow, = [row for row in item.normalized.memory_ssa.flow_edges
                 if (row.predecessor_key, row.block_key, list(row.span.canonical_key))
                 == (edge['source'], edge['target'], evidence['span'])]
        assert list(flow.definition_ids) == evidence['definition_ids']
        proof = view['proofs'][update['proof']]
        assert (proof['block'], proof['before_position'], proof['span']) == (edge['source'], None, update['span'])
    repeated = [row for row in view['reads'] if row['operation'] == '1b1:386:2:INT_AND']
    assert {row['read_ordinal'] for row in repeated} == {0, 1} and len(repeated) == 2
    assert eligibility(record) == 'loop'


def test_actual_o1_every_visit_matches_raw_updates_effects_and_writer_epochs(expression_o1_binary):
    case = expression_o1_binary
    item = case['results'][case['names']['case_view_shared']]
    record = json.loads(json.dumps(_root(item)))
    before = deepcopy(record)
    counts, paths, checked_bytes, runs = Counter(), set(), 0, 0
    for seed, delta in ((0, 7), (MASK, 1), (0x1122334455667788, 0x1000000000000001)):
        for count in (0, 1, 3, 7):
            for selector in (0, 1, 256):
                # This observer extends the existing _Visits oracle; no chain
                # construction or new interpreter is used in this test.
                vm = _ChainVisits(case, item, record)
                for offset, value in ((RSP, 0x70000000), (RDI, seed), (RSI, delta),
                                      (RDX, count), (RCX, selector)):
                    vm.preset(case['ids'][1], offset, 8, value)
                vm.preset(item.unit.scopes.function.entry.space_id, 0x70000000, 8, 0x2000)
                observed = vm.run()
                assert observed.completed and not vm.opaque_opcodes and vm.active is None
                step = delta if selector else delta ^ 0x55
                expected = ((seed + count * step) & MASK) ^ ((seed + 3 + count * step) & MASK)
                assert _value(vm, case['ids'][1], RAX, 8) == expected
                # This optimized loop exits outside the region at count=0;
                # every entered visit executes the body before its exit test.
                assert len(vm.raw_visits) == count
                assert [row['kind'] for row in vm.raw_visits] == ['continue'] * max(0, count - 1) + (['exit'] if count else [])
                for raw, visit in zip(vm.raw_visits, vm.visits, strict=True):
                    counts[raw['kind']] += 1
                    paths.add((raw['kind'], visit['writes']))
                    result = evaluate_transition(record, vm.view['id'], raw['inputs'],
                                                 accept_unattributed_assumptions=True)
                    assert (result['edge'], result['decisions']) == (raw['edge'], raw['decisions'])
                    assert {next(row['id'] for row in vm.view['inputs'] if row['span'] == update['span']):
                            update['value'] for update in result['updates']} == raw['state']
                    if raw['kind'] == 'exit':
                        assert raw['state'] != {key: raw['inputs'][key] for key in raw['state']}
                        assert len(visit['writes']) == 2  # The exit includes both actual stores.
                for previous, current in zip(vm.raw_visits, vm.raw_visits[1:]):
                    assert previous['state'] == {key: current['inputs'][key] for key in previous['state']}
                checked_bytes += vm.checked_load_bytes
                runs += 1
    assert runs == 36 and counts == {'continue': 72, 'exit': 27} and checked_bytes == 2376
    writers = {('1b1:363:2:STORE', '1b1:379:2:STORE'),
               ('1b1:399:2:STORE', '1b1:379:2:STORE')}
    assert paths == {(kind, writes) for kind in ('continue', 'exit') for writes in writers}
    assert record == before and eligibility(record) == 'loop'


def test_actual_o1_chain_keeps_nonidentity_exit_updates_and_absorbs_later_visits(expression_o1_binary):
    case = expression_o1_binary
    item = case['results'][case['names']['case_view_shared']]
    record = _root(item)
    view, = record['cycle_graph']['transitions']
    chains = {bound: derive_transition_chain(record, view['id'], bound) for bound in (1, 2, 4, 8)}
    evaluated = 0
    for count in (1, 3, 7):
        for selector in (0, 256):
            vm = _ChainVisits(case, item, record)
            for offset, value in ((RSP, 0x70000000), (RDI, MASK), (RSI, 1), (RDX, count), (RCX, selector)):
                vm.preset(case['ids'][1], offset, 8, value)
            vm.preset(item.unit.scopes.function.entry.space_id, 0x70000000, 8, 0x2000)
            assert vm.run().completed and not vm.opaque_opcodes and vm.active is None
            for bound, chain in chains.items():
                result = evaluate_expression_consumer(record, chain, vm.initial_inputs,
                                                     accept_unattributed_assumptions=True)
                expected = vm.raw_visits[:bound]
                assert result['evaluated_visits'] == min(bound, count)
                assert result['status'] == ('exit' if bound >= count else 'bound_exhausted')
                assert result['state'] == expected[-1]['state']
                for step, raw in zip(result['steps'], expected, strict=True):
                    assert (step['edge'], step['kind'], step['decisions']) == (raw['edge'], raw['kind'], raw['decisions'])
                    assert [{key: value for key, value in event.items() if key != 'read_sources'}
                            for event in step['effects']] == [
                        {key: value for key, value in event.items() if key != 'writers'} for event in raw['effects']]
                evaluated += 1
    assert evaluated == 24


@pytest.mark.parametrize('change', ('partial', 'missing', 'edge', 'definitions'))
def test_actual_o1_exit_fact_tamper_fails_before_input_access(expression_o1_binary, change):
    case = expression_o1_binary
    record = _root(case['results'][case['names']['case_view_shared']])
    view, = record['cycle_graph']['transitions']
    outcome, = [row for row in view['outcomes'] if row['kind'] == 'exit']
    update = outcome['updates'][0]
    if change == 'partial':
        update['captured_exit_evidence']['span'][-1] = '4'
    elif change == 'missing':
        del update['captured_exit_evidence']
    elif change == 'edge':
        update['captured_exit_evidence']['edge'] = 20
    else:
        update['captured_exit_evidence']['definition_ids'] = [69]
    seal(record)

    class Unreadable(dict):
        def get(self, *args):
            pytest.fail('captured exit correspondence must be checked before input access')

    with pytest.raises(Ineligible, match='contract'):
        evaluate_transition(record, view['id'], Unreadable(), accept_unattributed_assumptions=True)
