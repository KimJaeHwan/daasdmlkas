"""Bounded visit chains against the sealed original x64 raw-pcode oracle.

The inherited observer still checks every LOAD byte's original writer epoch.
These tests capture raw visit edges, decisions, effects and physical state;
the chain evaluator receives only the initial captured input snapshot.
"""

from collections import Counter
from copy import deepcopy
import json

import pytest

from synthetic import RAX, RCX, RDI, RDX, RSI, RSP
from test_general_cycle_binary import (
    MASK, _expected, _physical_place, _root, general_cycle_binary,
)
from test_multi_target_memory_binary import _value
from test_transition_binary import _Visits
from tdo_v2.operation_records import derive_transition_chain, evaluate_expression_consumer
from tdo_v2.span_geometry import ByteSpan


class _ChainVisits(_Visits):
    """Extend the existing instruction observer, without interpreting p-code."""

    def __init__(self, *args, **kwargs):
        self.initial_inputs, self.raw_visits = None, []
        self.previous_block, self.next_block = None, None
        super().__init__(*args, **kwargs)

    def _snapshot(self):
        snapshot = super()._snapshot()
        if self.initial_inputs is None:
            self.initial_inputs = dict(snapshot['inputs'])
        return snapshot

    def _finish(self, kind):
        visit = self.active
        edge, = [index for index, row in enumerate(self.record['cycle_graph']['cfg']['edges'])
                 if (row['source'], row['target']) == (self.previous_block, self.next_block)]
        state = {}
        for row in self.view['inputs']:
            if row['mutable']:
                span = ByteSpan.from_canonical_key(tuple(row['span']))
                state[row['id']] = _value(self, *_physical_place(self.case, self.item, span, self))
        self.raw_visits.append(dict(kind=kind, edge=edge, inputs=dict(visit['inputs']), state=state,
                                    effects=deepcopy(visit['effects']), decisions=dict(visit['decisions']),
                                    writers=dict(visit['writers']), instances=dict(visit['instances'])))
        # Preserve the existing raw LOAD byte and same-operation/different-visit
        # writer-epoch assertions, as well as its physical update checks.
        super()._finish(kind)
        assert self.visits[-1]['edge'] == edge

    def _execute(self, key, operation, run):
        self.next_block = self.locations[key][0]
        result = super()._execute(key, operation, run)
        self.previous_block = self.next_block
        return result


def _check_chain_load_epochs(vm, visit, expected, observed):
    """Compare the chain's own read-source result with raw per-byte epochs."""
    if expected['kind'] != 'load':
        return
    assert sum(int(source['span'][-1], 16) for source in expected['read_sources']) == observed['width']
    for source in expected['read_sources']:
        span = ByteSpan.from_canonical_key(tuple(source['span']))
        space, address, width = _physical_place(vm.case, vm.item, span, vm)
        for byte in range(width):
            index = address + byte - observed['address']
            assert 0 <= index < observed['width']
            writer = observed['writers'][index]
            if source['kind'] == 'input':
                assert writer == visit['writers'][vm._key(space, address + byte)]
            else:
                definition = vm.item.normalized.memory_ssa.definitions[source['definition']]
                assert writer == (definition.operation_key, span.start + byte - definition.span.start,
                                  visit['instances'][definition.operation_key])


def _check_original_recipe(record, view, chain, bound):
    assert chain['max_visits'] == bound and len(chain['rounds']) == bound
    assert chain['source_transition'] == view['id']
    assert chain['inputs'] == view['inputs']
    tracked = {row['id'] for row in view['inputs'] if row['mutable']}
    assert set(chain['tracked']) == tracked
    assert chain['analysis_context'] == view['analysis_context']
    originals = {row['operation']: row for row in view['effects']}
    definitions = record['cycle_graph']['definitions']
    for number, visit in enumerate(chain['rounds']):
        assert visit['visit'] == number
        assert visit['input_versions'] == {
            row['id']: f"initial:{row['id']}" if number == 0 or not row['mutable']
            else f"v{number - 1}:{row['id']}" for row in view['inputs']}
        assert [(row['kind'], row['edge']) for row in visit['outcomes']] == [
            (row['kind'], row['edge']) for row in view['outcomes']]
        assert [row['operation'] for row in visit['effects']] == list(originals)
        for event in visit['effects']:
            original = originals[event['operation']]
            assert event['kind'] == original['kind']
            assert event['definition_version'] == f'v{number}'
            assert event['state_version'] == ('initial' if number == 0 else f'v{number - 1}')
            assert event['source_reads'] == [
                read for read in view['reads'] if read['operation'] == event['operation']
                and read['span'][1] in ('address_space', 'function_relative')]
            # Original definition ids and original STORE identities survive;
            # visit scoping must never rename a STORE into a new SSA writer.
            for read in event['source_reads']:
                for atom in read['atoms']:
                    for source in atom['sources']:
                        if source['kind'] == 'definition':
                            reference = definitions[source['definition']]['reference']
                            assert reference['operation'] in originals
                            assert originals[reference['operation']]['kind'] == 'store'
                        else:
                            assert source['kind'] == 'input'
                            assert source['input'] in {row['id'] for row in view['inputs']}


INPUTS = (
    (0, 7, 0, 0),
    (MASK, 1, 1, 0),
    (MASK, 1, 1, 1),
    (0x1122334455667788, 0x1000000000000001, 3, 0),
    (0x1122334455667788, 0x1000000000000001, 3, 1),
    (0, 7, 5, 2),
    (MASK, 1, 7, 0),
    (MASK, 1, 7, 1),
)


@pytest.mark.parametrize('suffix', ('memory', 'multi_backedge'))
def test_actual_bounded_chains_match_raw_visits_state_effects_and_writer_epochs(general_cycle_binary, suffix):
    case = general_cycle_binary
    item = case['results'][case['names'][f'case_cycle_{suffix}']]
    record = json.loads(json.dumps(_root(item)))
    view, = record['cycle_graph']['transitions']
    assert view['complete'] and 'write_projection' not in view
    bounds = (0, 1, 2, 4, 8)
    chains = {bound: derive_transition_chain(record, view['id'], bound) for bound in bounds}
    for bound, chain in chains.items():
        _check_original_recipe(record, view, chain, bound)
    counts, raw_visits, checked_bytes, steps, paths, outcomes = Counter(), 0, 0, 0, set(), set()
    for seed, step, count, selector in INPUTS:
        vm = _ChainVisits(case, item, record)
        for offset, value in ((RSP, 0x70000000), (RDI, seed), (RSI, step), (RDX, count), (RCX, selector)):
            vm.preset(case['ids'][1], offset, 8, value)
        vm.preset(item.unit.scopes.function.entry.space_id, 0x70000000, 8, 0x2000)
        observed = vm.run()
        assert observed.completed and not vm.opaque_opcodes and vm.active is None
        assert _value(vm, case['ids'][1], RAX, 8) == _expected(suffix, seed, step, count, selector)
        assert len(vm.raw_visits) == count + 1  # The terminating header check is a visit.
        assert [row['kind'] for row in vm.raw_visits] == ['continue'] * count + ['exit']
        outcomes.update((row['kind'], row['edge']) for row in vm.raw_visits)
        for previous, current in zip(vm.raw_visits, vm.raw_visits[1:]):
            assert previous['state'] == {key: current['inputs'][key] for key in previous['state']}
        for bound, chain in chains.items():
            accesses = Counter()

            class InitialSnapshot(dict):
                def get(self, key, default=None):
                    accesses[key] += 1
                    assert accesses[key] == 1, 'initial values must be captured once across all visits'
                    if bound == 0:
                        assert key in chain['tracked'], 'zero visits must inspect only identity state'
                    return super().get(key, default)

            result = evaluate_expression_consumer(
                record, chain, InitialSnapshot(vm.initial_inputs), accept_unattributed_assumptions=True)
            expected = vm.raw_visits[:bound]
            assert result['max_visits'] == bound
            assert result['evaluated_visits'] == len(expected) == min(bound, count + 1)
            assert len(result['steps']) == len(expected)
            status = 'exit' if expected and expected[-1]['kind'] == 'exit' else 'bound_exhausted'
            assert result['status'] == status
            assert result['conditional_on_original_analysis'] and not result['assumptions_complete']
            assert result['trip_count'] == result['termination'] == 'not_proven'
            assert result['original_debt'] == 'retained'
            assert result['state'] == (expected[-1]['state'] if expected else {
                key: vm.initial_inputs[key] for key in chain['tracked']})
            for number, (actual, raw) in enumerate(zip(result['steps'], expected, strict=True)):
                assert actual['visit'] == number
                assert (actual['kind'], actual['edge'], actual['decisions']) == (
                    raw['kind'], raw['edge'], raw['decisions'])
                assert {next(row['id'] for row in view['inputs'] if row['span'] == update['span']):
                        update['value'] for update in actual['updates']} == raw['state']
                assert [{key: value for key, value in event.items() if key != 'read_sources'}
                        for event in actual['effects']] == [
                    {key: value for key, value in event.items() if key != 'writers'} for event in raw['effects']]
                for actual_event, raw_event in zip(actual['effects'], raw['effects'], strict=True):
                    _check_chain_load_epochs(vm, raw, actual_event, raw_event)
                paths.add((raw['kind'], tuple(event['operation'] for event in raw['effects']
                                             if event['kind'] == 'store')))
            counts[status] += 1
            steps += len(expected)
        raw_visits += len(vm.raw_visits)
        checked_bytes += vm.checked_load_bytes
    assert counts == {'exit': 17, 'bound_exhausted': 23}
    assert raw_visits == 35 and steps == 83 and checked_bytes > 0
    assert len(paths) == 3  # Exit and both actual conditional writer paths.
    assert outcomes == {(row['kind'], row['edge']) for row in view['outcomes']}
