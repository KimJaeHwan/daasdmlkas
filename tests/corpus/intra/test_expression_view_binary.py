"""Derived local formulas versus unmodified extracted actual binary p-code.

TDO_EXPRESSION_VIEW_BUNDLE is the Ghidra 12.0.4 sealed export of
local_expression_views.c, clang -target x86_64-apple-macos11 -O1
-fno-stack-protector -fno-optimize-sibling-calls -nostdlib -dynamiclib -lSystem.
The older O0 fixtures exercise stack RAM, branch correlation and width casts.
All existing effect/order/byte-writer oracles still run; no result injection.
"""

import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import random

import pytest

from synthetic import RAX, RCX, RDI, RDX, RSI, RSP
from test_general_cycle_binary import MASK, _root
from test_guarded_loop_summary_binary import guarded_summary_binary
from test_indirect_physical_binary import _ObservedMemory
from test_loop_summary_binary import loop_summary_binary
from test_multi_target_memory_binary import _load, _value
from test_transition_binary import _Visits
from tdo_v2.operation_records import (Ineligible, attach_expression_view, eligibility, evaluate_expression_view,
                                    evaluate_loop_summary, evaluate_transition, select_expression, simplify_expression)


IMAGE_SHA = '65d60c897de58fc5fa0e37bcc9a1d840e781a7afac09d32b66fe23e911f46569'


@pytest.fixture(scope='module')
def expression_view_binary():
    with pytest.MonkeyPatch.context() as patch:
        case = _load('TDO_EXPRESSION_VIEW_BUNDLE', patch, require_calls=False)
        generation = Path(os.environ['TDO_EXPRESSION_VIEW_BUNDLE'])
        manifest = json.loads((generation / 'manifest.json').read_text())
        original = next(row for row in manifest['members'] if row['id'] == manifest['original_member_id'])
        assert original['sha256'] == IMAGE_SHA
        assert sha256((generation / original['path']).read_bytes()).hexdigest() == IMAGE_SHA
        yield case


def test_actual_mba_root_simplifies_and_matches_original_pcode(expression_view_binary):
    case = expression_view_binary
    item = case['results'][case['names']['case_view_mba']]
    record = _root(item)
    before = copy.deepcopy(record)
    view = simplify_expression(record)
    assert view['proof']['status'] == 'equivalent', view['proof']
    assert any(row.get('opcode') == 'INT_XOR' for row in record['nodes'])
    assert not any(row.get('op') in ('bvxor', 'bvand', 'bvmul', 'bvshl') for row in view['graph']['nodes'])
    attached = attach_expression_view(record, view)
    rng = random.Random(73)
    pairs = [(0, 0), (MASK, 1), (0x1122334455667788, 0xfedcba9876543210)]
    pairs += [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(29)]
    for x, y in pairs:
        vm = _ObservedMemory(item.unit.observation, constant_space=case['ids'][0], seed=0,
                             image=case['image'], address_bits=case['address_bits'])
        for offset, value in ((RSP, 0x70000000), (RDI, x), (RSI, y)):
            vm.preset(case['ids'][1], offset, 8, value)
        vm.preset(item.unit.scopes.function.entry.space_id, 0x70000000, 8, 0x2000)
        inputs = {row['id']: _value(vm, case['ids'][1], record['nodes'][row['node']]['register']['offset'], row['width'])
                  for row in view['bindings']}
        result = evaluate_expression_view(attached, view['id'], inputs, accept_unattributed_assumptions=True)
        raw = vm.run()
        assert raw.completed and not vm.opaque_opcodes
        assert result['outputs']['root'] == _value(vm, case['ids'][1], RAX, 8) == (x + y) & MASK
    assert record == before


class _ViewVisits(_Visits):
    """Existing raw all-effects oracle plus selected multi-output formulas."""

    def __init__(self, case, item, record):
        super().__init__(case, item, record)
        self.expression_views = {}
        self.original = copy.deepcopy(record)
        self.simplified_outputs = 0
        for outcome in self.view['outcomes']:
            outputs = [dict(name=str(i), width=row['part']['at'][1], parts=[row['part']], guard=outcome['guard'])
                       for i, row in enumerate(outcome['updates'])]
            selection = select_expression(record, outputs, namespace=self.view['id'])
            derived = simplify_expression(record, selection)
            assert derived['proof']['status'] == 'equivalent', derived['proof']
            self.expression_views[outcome['kind']] = derived
            self.record = attach_expression_view(self.record, derived)

    def _finish(self, kind):
        derived = self.expression_views[kind]
        values = self.active['inputs']
        inputs = {row['id']: values[row['transition_input']] for row in derived['bindings']}
        result = evaluate_expression_view(self.record, derived['id'], inputs, accept_unattributed_assumptions=True)
        original = evaluate_transition(self.record, self.view['id'], values, accept_unattributed_assumptions=True)
        assert result['outputs'] == {str(i): row['value'] for i, row in enumerate(original['updates'])}
        self.simplified_outputs += len(result['outputs'])
        # Existing loop recipes remain consumable, identical and untouched.
        for summary in self.original.get('loop_summaries', ()):
            if summary['complete']:
                assert evaluate_loop_summary(self.record, summary['id'], values, accept_unattributed_assumptions=True) == \
                    evaluate_loop_summary(self.original, summary['id'], values, accept_unattributed_assumptions=True)
        super()._finish(kind)  # raw values, shared branch decisions, LOAD/STORE, byte writer epochs
        assert {key: value for key, value in self.record.items() if key != 'expression_views'} == self.original


def _run_views(case, name, *, shared=False):
    item = case['results'][case['names'][name]]
    record = json.loads(json.dumps(_root(item)))
    original_eligibility = eligibility(record)
    visits, output_count, load_bytes = 0, 0, 0
    for initial, delta in ((0, 7), (MASK, 1), (0x1122334455667788, 0x1000000000000001)):
        for count in (0, 1, 3, 7):
            for selector in (0, 1, 256):
                vm = _ViewVisits(case, item, record)
                for offset, value in ((RSP, 0x70000000), (RDI, initial), (RSI, delta), (RDX, count), (RCX, selector)):
                    vm.preset(case['ids'][1], offset, 8, value)
                vm.preset(item.unit.scopes.function.entry.space_id, 0x70000000, 8, 0x2000)
                raw = vm.run()
                assert raw.completed and not vm.opaque_opcodes and vm.active is None
                if shared:
                    step = delta if selector else delta ^ 0x55
                    expected = ((initial + count * step) & MASK) ^ ((initial + 3 + count * step) & MASK)
                    assert _value(vm, case['ids'][1], RAX, 8) == expected
                visits += len(vm.visits)
                output_count += vm.simplified_outputs
                load_bytes += vm.checked_load_bytes
                assert eligibility(vm.record) == original_eligibility
    assert visits == 135 and output_count >= visits
    assert load_bytes > 0 or name == 'case_summary_register'


def test_actual_shared_branch_memory_and_mba_keep_all_effects(expression_view_binary):
    _run_views(expression_view_binary, 'case_view_shared', shared=True)


@pytest.mark.parametrize('suffix', ('register', 'memory', 'narrow'))
def test_existing_actual_memory_and_width_views_leave_loop_summaries_unchanged(loop_summary_binary, suffix):
    _run_views(loop_summary_binary, 'case_summary_' + suffix)


def test_existing_actual_branch_memory_views_share_original_choice(guarded_summary_binary):
    _run_views(guarded_summary_binary, 'case_summary_branch')


def test_actual_optimized_exit_is_captured_without_promoting_original_cyclic_root(monkeypatch):
    case = _load('TDO_EXPRESSION_VIEW_OPTIMIZED_BUNDLE', monkeypatch, require_calls=False)
    generation = Path(os.environ['TDO_EXPRESSION_VIEW_OPTIMIZED_BUNDLE'])
    manifest = json.loads((generation / 'manifest.json').read_text())
    original = next(row for row in manifest['members'] if row['id'] == manifest['original_member_id'])
    expected = 'b27e76ddfc39f0bcee27d8c73f1e06ee305b57aa487b98b450adcdb365684707'
    assert original['sha256'] == sha256((generation / original['path']).read_bytes()).hexdigest() == expected
    record = _root(case['results'][case['names']['case_view_shared']])
    before = copy.deepcopy(record)
    visit, = record['cycle_graph']['transitions']
    assert visit['complete']
    exit, = [row for row in visit['outcomes'] if row['kind'] == 'exit']
    assert all('captured_exit_evidence' in update for update in exit['updates'])
    update = exit['updates'][0]
    assert select_expression(record, [dict(name='exit_cell', width=int(update['span'][-1], 16),
        parts=[update['part']], guard=exit['guard'])], namespace=visit['id'])['namespace'] == visit['id']
    # Captured exit support is not a global cyclic-root simplification claim.
    assert simplify_expression(record)['proof']['status'] == 'partial'
    assert record == before
