"""Every real loop visit, including intermediate effects and writer epochs.

Observes unmodified original p-code. No forced branch, injected result,
candidate-filtered writer oracle, or new instruction interpreter is used.
"""

from collections import Counter
import json

import pytest

from synthetic import RAX, RCX, RDI, RDX, RSI, RSP
from test_general_cycle_binary import (
    MASK, _expected, _physical_place, _raw_block_edges, _root, general_cycle_binary,
)
from test_indirect_physical_binary import _ObservedMemory
from test_multi_target_memory_binary import _value
from tdo_v2.operation_records import Ineligible, evaluate_transition
from tdo_v2.span_geometry import ByteSpan


def _read_varnode(vm, varnode):
    return varnode.coordinate.byte_offset if varnode.kind.name == 'CONSTANT' else vm._peek(
        varnode.coordinate.space_id, varnode.coordinate.byte_offset, varnode.byte_size)[0]


class _Visits(_ObservedMemory):
    def __init__(self, case, item, record, *, region=0, collection='transitions'):
        self.case, self.item, self.record = case, item, record
        rows = record['cycle_graph']['transitions'] if collection == 'transitions' else record[collection]
        self.view, = [row for row in rows if row['region'] == region]
        assert self.view['complete'], self.view
        self.members = set(self.view['blocks'])
        self.locations = _raw_block_edges(item, ())[1]
        self.active, self.visits = None, []
        self.writer_instances, self.instances, self.serial = {}, {}, 0
        self.checked_load_bytes = 0
        super().__init__(item.unit.observation, constant_space=case['ids'][0], seed=0,
                         image=case['image'], address_bits=case['address_bits'])

    def _write(self, writer, space, address, size, value):
        self.serial += 1
        self.instances[writer] = self.serial
        for offset in range(size):
            self.writer_instances[self._key(space, address + offset)] = writer, offset, self.serial
        return super()._write(writer, space, address, size, value)

    def _snapshot(self):
        values = {}
        writers = {}
        for row in self.view['inputs']:
            span = ByteSpan.from_canonical_key(tuple(row['span']))
            space, address, size = _physical_place(self.case, self.item, span, self)
            values[row['id']] = _value(self, space, address, size)
            for byte in range(size):
                key = self._key(space, address + byte)
                writers[key] = self.writer_instances.get(key, ('entry', key[1], 0))
        return dict(inputs=values, writers=writers, effects=[], decisions={})

    def _finish(self, kind):
        visit = self.active
        result = evaluate_transition(self.record, self.view['id'], visit['inputs'],
                                     accept_unattributed_assumptions=True)
        assert result['kind'] == kind and result['decisions'] == visit['decisions']
        assert result['conditional_on_original_analysis'] and not result['assumptions_complete']
        assert len(result['effects']) == len(visit['effects'])
        for expected, observed in zip(result['effects'], visit['effects'], strict=True):
            assert {key: value for key, value in expected.items() if key != 'read_sources'} == {
                key: value for key, value in observed.items() if key != 'writers'}
            if expected['kind'] != 'load':
                continue
            sources = expected['read_sources']
            assert sum(int(row['span'][-1], 16) for row in sources) == observed['width']
            for source in sources:
                span = ByteSpan.from_canonical_key(tuple(source['span']))
                space, address, size = _physical_place(self.case, self.item, span, self)
                for byte in range(size):
                    index = address + byte - observed['address']
                    assert 0 <= index < observed['width']
                    actual = observed['writers'][index]
                    if source['kind'] == 'input':
                        # Epoch is part of the oracle: the same STORE key
                        # in the previous/current iteration is not the same
                        # write, even if it produced the same byte value.
                        assert actual == visit['writers'][self._key(space, address + byte)]
                    else:
                        definition = self.item.normalized.memory_ssa.definitions[source['definition']]
                        assert actual == (definition.operation_key, span.start + byte - definition.span.start,
                                          visit['instances'][definition.operation_key])
                    self.checked_load_bytes += 1
        for update in result['updates']:
            span = ByteSpan.from_canonical_key(tuple(update['span']))
            space, address, size = _physical_place(self.case, self.item, span, self)
            assert update['value'] == _value(self, space, address, size)
        self.visits.append(dict(kind=kind, edge=result['edge'], effects=len(result['effects']),
                                writes=tuple(row['operation'] for row in result['effects'] if row['kind'] == 'store')))
        self.active = None

    def _execute(self, key, operation, run):
        block, first = self.locations[key]
        if block == self.view['entry'] and first:
            if self.active is not None:
                self.active['instances'] = dict(self.instances)
                self._finish('continue')
            self.active = self._snapshot()
        elif block not in self.members and self.active is not None:
            self.active['instances'] = dict(self.instances)
            self._finish('exit')
        event = None
        if self.active is not None and operation.opcode in ('LOAD', 'STORE'):
            space = operation.inputs[0].coordinate.byte_offset
            address = _read_varnode(self, operation.inputs[1])
            width = operation.output.byte_size if operation.opcode == 'LOAD' else operation.inputs[2].byte_size
            event = dict(operation=key, kind=operation.opcode.lower(), space=space, address=address, width=width)
            if operation.opcode == 'LOAD':
                event['writers'] = [self.writer_instances.get(self._key(space, address + byte),
                                                             ('entry', self._key(space, address + byte)[1], 0))
                                    for byte in range(width)]
            else:
                event['value'] = _read_varnode(self, operation.inputs[2])
        before_decisions = len(run.branch_decisions)
        result = super()._execute(key, operation, run)
        if self.active is not None:
            for decision, value in run.branch_decisions[before_decisions:]:
                assert decision not in self.active['decisions'], 'one visit must not silently unroll an inner cycle'
                self.active['decisions'][decision] = value
            if event is not None:
                if operation.opcode == 'LOAD':
                    event['value'] = _read_varnode(self, operation.output)
                self.active['effects'].append(event)
        return result


def test_actual_memory_transition_matches_every_visit_state_effect_and_writer_epoch(general_cycle_binary):
    case = general_cycle_binary
    item = case['results'][case['names']['case_cycle_memory']]
    record = json.loads(json.dumps(_root(item)))
    view, = record['cycle_graph']['transitions']
    assert view['complete'] and len(view['inputs']) == 6
    assert view['entry'] == '1b1:624' and view['entry_edges'] == [13] and view['cut_edges'] == [37]
    originals = {row['key']: row for row in record['cycle_graph']['operations']}
    for operation in view['operations']:
        assert operation['original_node'] == originals[operation['operation']]['node']
        assert view['record']['nodes'][operation['node']]['key'] == operation['operation']
    counts, paths, checked, runs = Counter(), set(), 0, 0
    for seed, step in ((0, 7), (0x1122334455667788, 0x1000000000000001), (MASK, 1)):
        for count in (0, 1, 3, 5):
            for selector in (0, 1, 2):
                vm = _Visits(case, item, record)
                for offset, value in ((RSP, 0x70000000), (RDI, seed), (RSI, step), (RDX, count), (RCX, selector)):
                    vm.preset(case['ids'][1], offset, 8, value)
                vm.preset(item.unit.scopes.function.entry.space_id, 0x70000000, 8, 0x2000)
                observed = vm.run()
                assert observed.completed and not vm.opaque_opcodes and vm.active is None
                assert _value(vm, case['ids'][1], RAX, 8) == _expected('memory', seed, step, count, selector)
                assert len(vm.visits) == count + 1
                assert [row['kind'] for row in vm.visits] == ['continue'] * count + ['exit']
                for visit in vm.visits:
                    counts[visit['kind']] += 1
                    paths.add((visit['kind'], visit['writes']))
                checked += vm.checked_load_bytes
                runs += 1
    assert runs == 36 and counts == {'continue': 81, 'exit': 36}
    assert paths == {('exit', ()),
                     ('continue', ('1b1:633:2:STORE', '1b1:654:2:STORE', '1b1:66e:2:STORE')),
                     ('continue', ('1b1:633:2:STORE', '1b1:662:2:STORE', '1b1:66e:2:STORE'))}
    assert checked > 0


def test_actual_post_store_read_is_not_replaced_by_header_state(general_cycle_binary):
    case = general_cycle_binary
    record = _root(case['results'][case['names']['case_cycle_memory']])
    view, = record['cycle_graph']['transitions']
    before, = [row for row in view['reads'] if row['operation'] == '1b1:62b:1:LOAD'
               and row['span'][1] == 'function_relative']
    after, = [row for row in view['reads'] if row['operation'] == '1b1:649:1:LOAD'
              and row['span'][1] == 'function_relative']
    assert before['atoms'][0]['sources'][0]['kind'] == 'input'
    assert after['atoms'][0]['sources'][0]['kind'] == 'definition'
    assert after['atoms'][0]['sources'][0]['definition'] == 100
    assert record['cycle_graph']['definitions'][100]['reference']['operation'] == '1b1:633:2:STORE'


def test_actual_zero_visit_does_not_evaluate_the_inactive_step_or_selector(general_cycle_binary):
    case = general_cycle_binary
    record = _root(case['results'][case['names']['case_cycle_memory']])
    view, = record['cycle_graph']['transitions']
    values = {row['id']: {0x28: 0x6ffffff8, 0xffffffffffffffc0: 0,
                          0xffffffffffffffd0: 10, 0xffffffffffffffc8: 11}.get(int(row['span'][-2], 16))
              for row in view['inputs']}
    result = evaluate_transition(record, view['id'], values, accept_unattributed_assumptions=True)
    assert result['kind'] == 'exit' and len(result['decisions']) == 1
    assert len(result['effects']) == 1 and result['effects'][0]['kind'] == 'load'


def test_actual_effect_deletion_is_rejected_before_reading_inputs(general_cycle_binary):
    case = general_cycle_binary
    record = _root(case['results'][case['names']['case_cycle_memory']])
    view, = record['cycle_graph']['transitions']
    view['effects'] = []

    class Unreadable(dict):
        def get(self, *args):
            pytest.fail('changed effect inventory must fail before input access')

    with pytest.raises(Ineligible, match='receipt'):
        evaluate_transition(record, view['id'], Unreadable(), accept_unattributed_assumptions=True)


@pytest.mark.parametrize('suffix,region,visits', (('nested', 1, 243), ('multi_update', 0, 117),
                                                ('multi_backedge', 0, 117), ('sequential', 0, 117),
                                                ('sequential', 1, 72)))
def test_other_actual_qualifying_regions_match_original_visits(general_cycle_binary, suffix, region, visits):
    case = general_cycle_binary
    item = case['results'][case['names'][f'case_cycle_{suffix}']]
    record = _root(item)
    checked, observed_visits = 0, 0
    for seed, step in ((0, 7), (0x1122334455667788, 0x1000000000000001), (MASK, 1)):
        for count in (0, 1, 3, 5):
            for selector in (0, 1, 2):
                vm = _Visits(case, item, record, region=region)
                for offset, value in ((RSP, 0x70000000), (RDI, seed), (RSI, step), (RDX, count), (RCX, selector)):
                    vm.preset(case['ids'][1], offset, 8, value)
                vm.preset(item.unit.scopes.function.entry.space_id, 0x70000000, 8, 0x2000)
                observed = vm.run()
                assert observed.completed and not vm.opaque_opcodes and vm.active is None
                assert _value(vm, case['ids'][1], RAX, 8) == _expected(suffix, seed, step, count, selector)
                checked += vm.checked_load_bytes
                observed_visits += len(vm.visits)
    assert observed_visits == visits and checked > 0
