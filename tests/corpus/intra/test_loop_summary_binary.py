"""Closed forms checked against unmodified extracted p-code, not native runs."""

from hashlib import sha256
import json
import os
from pathlib import Path

import pytest

from synthetic import RAX, RCX, RDI, RDX, RSI, RSP
from test_general_cycle_binary import MASK, _expected, _physical_place, _root, general_cycle_binary
from test_multi_target_memory_binary import _load, _value
from test_recurrence_register_binary import _raw_block_edges
from test_transition_binary import _Visits
from tdo_v2.operation_records import Ineligible, eligibility, evaluate_loop_summary
from tdo_v2.span_geometry import ByteSpan


IMAGE_SHA = '1b5c1c4c9e68e4e86c56f795fc6264293998ca6a117280b65b8ce91df5cda8ff'


@pytest.fixture(scope='module')
def loop_summary_binary():
    with pytest.MonkeyPatch.context() as patch:
        case = _load('TDO_LOOP_SUMMARY_BUNDLE', patch, require_calls=False)
        generation = Path(os.environ['TDO_LOOP_SUMMARY_BUNDLE'])
        manifest = json.loads((generation / 'manifest.json').read_text())
        original = next(row for row in manifest['members'] if row['id'] == manifest['original_member_id'])
        assert original['sha256'] == IMAGE_SHA
        assert sha256((generation / original['path']).read_bytes()).hexdigest() == IMAGE_SHA
        yield case


class _SummaryVisits(_Visits):
    """Keep v12's all-effects/writer-epoch oracle and add loop boundaries."""

    def __init__(self, case, item, record, *, region=0):
        super().__init__(case, item, record, region=region)
        self.summary, = [row for row in record['loop_summaries'] if row['transition'] == self.view['id']]
        assert self.summary['complete'], self.summary
        self.pending, self.invocations = None, []

    def _snapshot(self):
        visit = super()._snapshot()
        if self.pending is None:
            result = evaluate_loop_summary(self.record, self.summary['id'], visit['inputs'],
                                           accept_unattributed_assumptions=True)
            self.pending = dict(result=result, first_visit=len(self.visits))
        return visit

    def _finish(self, kind):
        super()._finish(kind)  # Every actual branch, LOAD/STORE and byte writer.
        if kind != 'exit':
            return
        result = self.pending['result']
        assert len(self.visits) - self.pending['first_visit'] == result['iterations'] + 1
        for update in result['updates']:
            span = ByteSpan.from_canonical_key(tuple(update['span']))
            space, address, size = _physical_place(self.case, self.item, span, self)
            assert update['value'] == _value(self, space, address, size)
        assert result['exit_edge'] == self.view['outcomes'][1]['edge']
        assert not result['effect_template']['full_trace_materialized']
        assert result['effect_template']['includes_terminal_zero_visit']
        self.invocations.append(result)
        self.pending = None


def _run(case, item, record, initial, delta, count, selector=0, *, region=0):
    vm = _SummaryVisits(case, item, record, region=region)
    for offset, value in ((RSP, 0x70000000), (RDI, initial), (RSI, delta), (RDX, count), (RCX, selector)):
        vm.preset(case['ids'][1], offset, 8, value)
    vm.preset(item.unit.scopes.function.entry.space_id, 0x70000000, 8, 0x2000)
    observed = vm.run()
    assert observed.completed and not vm.opaque_opcodes and vm.pending is None and vm.active is None
    # Independent actual raw edge counts, not a source signature or derived n.
    edges, _ = _raw_block_edges(item, observed.executed)
    raw = record['cycle_graph']['cfg']['edges']
    back = raw[vm.summary['continue_edge']]
    exit = raw[vm.summary['exit_edge']]
    assert edges[back['source'], back['target']] == sum(row['iterations'] for row in vm.invocations)
    assert edges[exit['source'], exit['target']] == len(vm.invocations)
    return vm


@pytest.mark.parametrize('suffix', ('register', 'memory'))
def test_compiled_register_and_memory_terminal_summaries_match_original_loops(loop_summary_binary, suffix):
    case = loop_summary_binary
    item = case['results'][case['names'][f'case_summary_{suffix}']]
    record = json.loads(json.dumps(_root(item)))
    assert eligibility(record) == 'loop'
    checked, visits, runs = 0, 0, 0
    for initial, delta in ((0, 7), (MASK, 1), (0x1122334455667788, 0x1000000000000001)):
        for count in (0, 1, 3, 7, 19):
            vm = _run(case, item, record, initial, delta, count)
            assert _value(vm, case['ids'][1], RAX, 8) == (initial + count * delta) & MASK
            assert len(vm.invocations) == 1 and vm.invocations[0]['iterations'] == count
            checked += vm.checked_load_bytes
            visits += len(vm.visits)
            runs += 1
    assert runs == 15 and visits == 105
    assert checked > 0 or suffix == 'register'


@pytest.mark.parametrize('suffix,region', (('sequential', 0), ('nested', 1)))
def test_existing_actual_regions_use_their_own_boundary_counter(general_cycle_binary, suffix, region):
    case = general_cycle_binary
    item = case['results'][case['names'][f'case_cycle_{suffix}']]
    record = _root(item)
    checked, invocations, visits, runs = 0, 0, 0, 0
    for initial, delta in ((0, 7), (MASK, 1), (0x1122334455667788, 0x1000000000000001)):
        for count in (0, 1, 3, 10):
            for selector in (0, 1, 2):
                vm = _run(case, item, record, initial, delta, count, selector, region=region)
                assert _value(vm, case['ids'][1], RAX, 8) == _expected(suffix, initial, delta, count, selector)
                for result in vm.invocations:
                    assert result['iterations'] == ((count & 7) if suffix == 'sequential' else (selector & 3) + 1)
                checked += vm.checked_load_bytes
                invocations += len(vm.invocations)
                visits += len(vm.visits)
                runs += 1
    assert runs == 36 and checked > 0
    assert invocations == (36 if suffix == 'sequential' else 54)
    assert visits == (90 if suffix == 'sequential' else 162)


def test_actual_narrow_promotions_are_explicit_partial_not_a_wide_translation(loop_summary_binary):
    case = loop_summary_binary
    record = _root(case['results'][case['names']['case_summary_narrow']])
    summary, = record['loop_summaries']
    assert not summary['complete'] and summary['reason']
    assert record['cycle_graph']['coverage']['expression_complete']
    with pytest.raises(Ineligible, match='incomplete'):
        evaluate_loop_summary(record, summary['id'], {})


def test_existing_nontranslation_regions_keep_graph_and_one_visit(general_cycle_binary):
    case = general_cycle_binary
    for name, region in (('case_cycle_memory', 0), ('case_cycle_multi_update', 0),
                         ('case_cycle_multi_backedge', 0), ('case_cycle_sequential', 1)):
        record = _root(case['results'][case['names'][name]])
        summary = record['loop_summaries'][region]
        assert not summary['complete'] and summary['reason']
        assert record['cycle_graph']['transitions'][region]['complete']
