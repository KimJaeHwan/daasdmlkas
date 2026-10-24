"""Occurrence-bound one-visit views, never global phi replacement."""

import copy as copying
import json
import sys

import pytest

from synthetic import CF, RAX, RBX, RCX, RDX, RDI, RSI, R9, FunctionBuilder, add, const, copy, load, op, ram, reg, store
from test_operation_records import _analyzed
from test_record_recurrence import _loop, _unsupported
from tdo_v2 import _record_cycles, _record_transitions
from tdo_v2._record_transition_contract import seal, validate
from tdo_v2.operation_records import Ineligible, Limits, StitchContext, eligibility, evaluate_transition, render, root_record
from tdo_v2.span_geometry import ByteSpan


def _record(builder=None, *, known=False, limits=None):
    analyzed = _analyzed(builder or _loop())
    run, = [row for row in analyzed.summary.exits[0].runs
             if row.span.object_id.kind.value == 'register_file' and row.span.start == RBX]
    record = root_record(analyzed.normalized, analyzed.unit,
                         [(analyzed.normalized.memory_graph.definition_nodes[i], (run.span,)) for i in run.definitions],
                         stitch=StitchContext({}, assumptions=()) if known else None, limits=limits)
    return record


def _view(record):
    row, = record['cycle_graph']['transitions']
    assert row['complete'], row
    return row


def _values(view, **registers):
    return {row['id']: registers.get(str(int(row['span'][-2], 16))) for row in view['inputs']}


@pytest.mark.parametrize('initial,limit,expected,kind', ((0, 0, 0, 'exit'), (3, 5, 4, 'continue'),
                                                      (5, 5, 5, 'exit'), (9, 5, 9, 'exit')))
def test_one_visit_reuses_original_ops_and_evaluates_current_state(initial, limit, expected, kind):
    record = _record(known=True)
    view = _view(record)
    result = evaluate_transition(record, view['id'], _values(view, **{str(RAX): initial, str(RDX): limit}))
    assert result['kind'] == kind
    assert result['assumptions_complete'] and result['conditional_on_original_analysis']
    update, = result['updates']
    assert update['value'] == expected and int(update['span'][-2], 16) == RAX
    assert eligibility(record) == 'loop'
    assert all(node['key'] == record['nodes'][node['original_node']]['key']
               for node in view['record']['nodes'] if node['kind'] == 'op')
    validate(record, view)


@pytest.mark.parametrize('right,expected', ((0, 11), (1, 12)))
def test_two_backedges_and_shared_original_branch(right, expected):
    record = _record(_unsupported('multi_latch'), known=True)
    view = _view(record)
    assert len(view['cut_edges']) == 2
    values = _values(view, **{str(RAX): 10, str(R9): 0, str(CF): right})
    result = evaluate_transition(record, view['id'], values)
    assert result['kind'] == 'continue' and result['updates'][0]['value'] == expected


def test_exit_does_not_demand_inactive_body_condition():
    record = _record(_unsupported('multi_latch'), known=True)
    view = _view(record)
    values = _values(view, **{str(RAX): 10, str(R9): 1})  # CF deliberately unknown
    result = evaluate_transition(record, view['id'], values)
    assert result['kind'] == 'exit' and result['updates'][0]['value'] == 10
    assert len(result['decisions']) == 1


def test_each_evaluation_has_a_fresh_decision_and_value_cache():
    record = _record(_unsupported('multi_latch'), known=True)
    view = _view(record)
    for right, expected in ((0, 11), (1, 12), (0, 11), (1, 12)):
        result = evaluate_transition(record, view['id'], _values(view, **{str(RAX): 10, str(R9): 0, str(CF): right}))
        assert result['updates'][0]['value'] == expected


def test_existing_renderer_exposes_scoped_transition_nodes_and_guarded_outputs():
    record = _record(known=True)
    view = _view(record)
    text = render(record)
    assert 'one-visit ' + view['id'] in text
    assert 'original graph retained' in text and 'shared within THIS visit' in text
    assert 'continue edge ' in text and 'exit edge ' in text and 'next [' in text
    for node in view['record']['nodes']:
        assert f"t0.n{node['id']} = " in text
    assert 'state(s0)' in text and 't0.g0=false; t0.g1=true' in text


def test_transition_evaluation_restores_recursion_limit_on_success_and_failure():
    previous = sys.getrecursionlimit()
    record = _record(known=True)
    view = _view(record)
    evaluate_transition(record, view['id'], _values(view, **{str(RAX): 3, str(RDX): 5}))
    assert sys.getrecursionlimit() == previous
    with pytest.raises(Ineligible):
        evaluate_transition(record, view['id'], {})
    assert sys.getrecursionlimit() == previous


class _Unreadable(dict):
    def get(self, *args):
        pytest.fail('inputs must not be accessed before the contract is accepted')


def test_unknown_run_assumptions_are_not_an_empty_known_list():
    record = _record()
    view = _view(record)
    assert view['analysis_context']['run_assumptions'] is None
    with pytest.raises(Ineligible, match='unattributed'):
        evaluate_transition(record, view['id'], _Unreadable())
    values = _values(view, **{str(RAX): 3, str(RDX): 5})
    result = evaluate_transition(record, view['id'], values, accept_unattributed_assumptions=True)
    assert result['updates'][0]['value'] == 4
    assert not result['assumptions_complete'] and result['conditional_on_original_analysis']


def test_json_roundtrip_preserves_the_local_contract_and_guards():
    record = json.loads(json.dumps(_record(known=True)))
    view = _view(record)
    result = evaluate_transition(record, view['id'], _values(view, **{str(RAX): 3, str(RDX): 5}))
    assert result['updates'][0]['value'] == 4


@pytest.mark.parametrize('change', ('effects', 'outcomes', 'part', 'proof', 'input', 'guard', 'policy', 'source'))
def test_changed_derivation_or_authority_is_rejected_before_input_access(change):
    record = copying.deepcopy(_record(known=True))
    view = _view(record)
    if change == 'effects':
        view['effects'].append({'kind': 'load'})
    elif change == 'outcomes':
        view['outcomes'].pop()
    elif change == 'part':
        view['outcomes'][0]['updates'][0]['part']['node'] = 0
    elif change == 'proof':
        view['proofs'][0]['last_definition'] = -1
    elif change == 'input':
        view['inputs'][0]['definition_ids'] = []
    elif change == 'guard':
        view['outcomes'][0]['guard'] = 0
    elif change == 'policy':
        view['normalization_assumptions'] = {}
    else:
        record['cycle_graph']['edge_states'][view['cut_edges'][0]]['facts'] = []
    with pytest.raises(Ineligible, match='contract'):
        evaluate_transition(record, view['id'], _Unreadable())


@pytest.mark.parametrize('change', ('last_write', 'predecessors', 'stop', 'span', 'read'))
def test_local_certificates_are_checked_even_with_a_recomputed_receipt(change):
    record = copying.deepcopy(_record(known=True))
    view = _view(record)
    if change == 'last_write':
        row = next(row for row in view['proofs'] if row['last_definition'] is not None)
        row['last_definition'] = -1
    elif change == 'predecessors':
        row = next(row for row in view['proofs'] if row['predecessors'])
        row['predecessors'] = []
    elif change == 'stop':
        row = next(row for row in view['proofs'] if row['before_position'] is not None)
        row['before_position'] = 100000
    elif change == 'span':
        view['proofs'][0]['span'][-1] = 'ff'
    else:
        view['reads'][0]['read_ordinal'] += 1
    seal(record)  # Not authentication: independent local checks must still run.
    with pytest.raises(Ineligible, match='contract'):
        evaluate_transition(record, view['id'], _Unreadable())


def test_continue_certificate_candidates_must_equal_original_cut_fact():
    record = _record(known=True)
    view = _view(record)
    update, = view['outcomes'][0]['updates']
    pending = [update['proof']]
    while pending:
        row = view['proofs'][pending.pop()]
        row['candidate_definitions'] = [4, 6]  # d4 is valid RAX bytes, but not this backedge's [d6].
        pending.extend(child['proof'] for child in row['predecessors'])
    seal(record)
    with pytest.raises(Ineligible, match='output original cut sources'):
        evaluate_transition(record, view['id'], _Unreadable())


def test_invariant_input_cannot_have_an_empty_original_source_set():
    record = _record(known=True)
    view = _view(record)
    next(row for row in view['inputs'] if not row['mutable'])['definition_ids'] = []
    seal(record)
    with pytest.raises(Ineligible, match='empty original source'):
        evaluate_transition(record, view['id'], _Unreadable())


def test_captured_predecessor_fact_constrains_submitted_origin_sources():
    record = _record(known=True)
    view = _view(record)
    original = record['cycle_graph']
    child = next(row for row in view['proofs'] if row['predecessors'])['predecessors'][0]
    state = original['edge_states'][child['edge']]
    # A captured fact may constrain a state input whose boundary union is
    # wider. Do not ignore it merely because source and derived receipts agree.
    state['evidence'] = 'captured'
    state['facts'] = copying.deepcopy(original['edge_states'][view['entry_edges'][0]]['facts'])
    seal(record)
    with pytest.raises(Ineligible, match='captured predecessor source'):
        evaluate_transition(record, view['id'], _Unreadable())


def test_derived_projection_does_not_edit_any_original_node_or_relation(monkeypatch):
    record = _record(known=True)
    monkeypatch.setattr(_record_transitions, 'publish_transitions', lambda *args: [])
    baseline = _record(known=True)
    assert record['nodes'] == baseline['nodes'] and record['root'] == baseline['root']
    assert {key: value for key, value in record['cycle_graph'].items()
            if key not in ('transitions', 'transition_contracts')} == {
                key: value for key, value in baseline['cycle_graph'].items()
                if key not in ('transitions', 'transition_contracts')}
    assert eligibility(record) == eligibility(baseline) == 'loop'


@pytest.mark.parametrize('shape', ('nested', 'irreducible'))
def test_no_single_visit_is_invented_for_an_uncut_nested_or_multi_entry_region(shape):
    record = _record(_unsupported(shape))
    assert record['cycle_graph']['coverage']['expression_complete']
    row = record['cycle_graph']['transitions'][0]
    assert not row['complete'] and row['reason']
    with pytest.raises(Ineligible, match='incomplete'):
        evaluate_transition(record, row['id'], _Unreadable())


def test_missing_cut_evidence_is_not_filled_in(monkeypatch):
    original = _record_transitions._Correspondence.flow

    def missing(self, edge, span):
        if edge in self.conditions.cut_edges:
            raise _record_transitions._Partial('missing cut evidence injection')
        return original(self, edge, span)

    monkeypatch.setattr(_record_transitions._Correspondence, 'flow', missing)
    record = _record()
    row, = record['cycle_graph']['transitions']
    assert not row['complete'] and 'missing cut' in row['reason']
    assert record['cycle_graph']['coverage']['expression_complete']


def test_direct_address_memory_effects_are_explicit_partial_not_silent():
    builder = (FunctionBuilder().ins(copy(reg(RAX), reg(RCX))).label('top')
               .cbranch('end', reg(R9, 1)).ins(copy(ram(0x4010), reg(RAX)))
               .ins(add(reg(RAX), reg(RAX), const(1))).branch('top')
               .label('end').ins(copy(reg(RBX), reg(RAX))).ret())
    record = _record(builder)
    row, = record['cycle_graph']['transitions']
    assert not row['complete'] and 'direct-address' in row['reason']


@pytest.mark.parametrize('kind', ('nodes', 'edges', 'depth'))
def test_transition_resource_failure_keeps_the_original_record(monkeypatch, kind):
    original_build = _record_transitions._build

    def limited(original, graph, index, region):
        original = copying.copy(original)
        original.limits = Limits(**{kind: 0 if kind == 'depth' else 1})
        return original_build(original, graph, index, region)

    monkeypatch.setattr(_record_transitions, '_build', limited)
    record = _record()
    row, = record['cycle_graph']['transitions']
    assert not row['complete'] and row['reason']
    assert record['cycle_graph']['coverage']['expression_complete'] and eligibility(record) == 'loop'


def test_non_little_endian_transition_is_not_claimed_supported(monkeypatch):
    original = _record_transitions._Correspondence.__init__

    def not_little(self, index, *args):
        index = copying.copy(index)
        index.index = copying.copy(index.index)
        index.index.little = False
        return original(self, index, *args)

    monkeypatch.setattr(_record_transitions._Correspondence, '__init__', not_little)
    record = _record()
    row, = record['cycle_graph']['transitions']
    assert not row['complete'] and 'little-endian' in row['reason']


@pytest.mark.parametrize('change', ('effects', 'output_part', 'outcome_guard', 'constant', 'operand', 'edge_guard', 'input_node',
                                  'op_value', 'op_kind', 'op_width', 'pruned_operand', 'constant_slice',
                                  'missing_parts', 'pruned_decision', 'duplicate_operation'))
def test_recomputed_receipt_does_not_replace_independent_semantic_checks(change):
    record = copying.deepcopy(_record(known=True))
    view = _view(record)
    if change == 'effects':
        view['effects'].append({'kind': 'load'})
    elif change == 'output_part':
        view['outcomes'][0]['updates'][0]['part']['node'] = 0
    elif change == 'outcome_guard':
        view['outcomes'][0]['guard'] = view['outcomes'][1]['guard']
    elif change == 'constant':
        node = next(node for node in view['record']['nodes'] if node['kind'] == 'const')
        node['value'] += 1
    elif change == 'operand':
        node = next(node for node in view['record']['nodes'] if node.get('opcode') == 'INT_ADD')
        node['operands'][0]['parts'] = node['operands'][1]['parts']
    elif change == 'edge_guard':
        proof = next(row for row in view['proofs'] if row['predecessors'])
        proof['predecessors'][0]['guard'] = 0
    elif change == 'input_node':
        node = next(node for node in view['record']['nodes'] if node['kind'] == 'entry')
        node['transition_input'] = 'not-a-slot'
    elif change == 'pruned_decision':
        next(iter(view['record']['control']['decisions'].values()))['operand']['pruned'] = True
    elif change == 'duplicate_operation':
        update, = view['outcomes'][0]['updates']
        node = copying.deepcopy(view['record']['nodes'][update['part']['node']])
        node.update(id=len(view['record']['nodes']), value=999)
        view['record']['nodes'].append(node)
        update['part']['node'] = update['sources'][0]['part']['node'] = node['id']
    else:
        node = next(node for node in view['record']['nodes'] if node.get('opcode') == 'INT_ADD')
        if change == 'op_value':
            node['value'] = 999
        elif change == 'op_kind':
            node.update(kind='const', value=999, size=8)
        elif change == 'op_width':
            node['output']['size'] = 1
        elif change == 'pruned_operand':
            node['operands'][0]['pruned'] = True
        elif change == 'missing_parts':
            del node['operands'][0]['parts']
        else:
            node['operands'][1]['parts'][0].update(bytes=[1, 2], at=[0, 1])
    seal(record)
    with pytest.raises(Ineligible, match='contract'):
        evaluate_transition(record, view['id'], _Unreadable())


def test_different_pointer_anchors_do_not_discharge_original_alias_uncertainty():
    builder = (FunctionBuilder().ins(copy(reg(RAX), reg(RCX))).label('top')
               .cbranch('end', reg(R9, 1)).ins(store(reg(RDI), reg(RAX)))
               .ins(load(reg(RAX), reg(RSI))).branch('top')
               .label('end').ins(copy(reg(RBX), reg(RAX))).ret())
    record = _record(builder)
    row, = record['cycle_graph']['transitions']
    assert not row['complete'] and any(word in row['reason'] for word in ('alias', 'unresolved', 'debt'))


def test_atomic_byte_state_preserves_narrow_write_and_wide_read():
    builder = (FunctionBuilder().ins(copy(reg(RAX), reg(RCX))).label('top')
               .cbranch('end', reg(R9, 1)).ins(add(reg(RAX, 1), reg(RAX, 1), const(1, 1)))
               .ins(copy(reg(RDX), reg(RAX))).branch('top')
               .label('end').ins(copy(reg(RBX), reg(RAX))).ret())
    record = _record(builder, known=True)
    view = _view(record)
    values = {row['id']: (0 if int(row['span'][-2], 16) == R9 else
                          0xff if int(row['span'][-1], 16) == 1 else 0x11223344556677)
              for row in view['inputs']}
    result = evaluate_transition(record, view['id'], values)
    assert result['kind'] == 'continue'
    low, = [row for row in result['updates'] if int(row['span'][-2], 16) == RAX]
    assert int(low['span'][-1], 16) == 1 and low['value'] == 0
