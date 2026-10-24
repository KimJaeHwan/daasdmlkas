"""Bounded composition is an original-visit overlay, not a trip-count claim."""

import copy
import json

import pytest
import z3

from synthetic import (CF, DATA_BASE, RAX, RBX, RCX, RDX, RDI, RSI, R8, R9,
    FunctionBuilder, const, copy as move, load, op, reg, store, tmp)
from test_transition_records import _record, _view, _values, _Unreadable
from test_record_recurrence import _unsupported
from test_loop_summary_branches import _branch_loop
from test_loop_summary_records import _loop
from test_loop_summary_writes import _strided
from tdo_v2.operation_records import (Ineligible, derive_transition_chain, evaluate_expression_consumer,
    attach_expression_consumer, eligibility, render)
from tdo_v2._record_expression_consumers import _identity
from tdo_v2._record_expression_views import _fingerprint


def _chain(record, visits):
    return derive_transition_chain(record, _view(record)['id'], visits)


def _run(record, chain, **registers):
    return evaluate_expression_consumer(record, chain, _values(_view(record), **registers))


@pytest.mark.parametrize('bound', (0, 1, 2, 4, 8))
@pytest.mark.parametrize('initial,limit', ((0, 3), (7, 7), (9, 5)))
def test_bound_counts_original_visits_including_exit_check_not_body_iterations(bound, initial, limit):
    record = _record(known=True)
    chain = _chain(record, bound)
    result = _run(record, chain, **{str(RAX): initial, str(RDX): limit})
    bodies = max(limit-initial, 0)
    assert result['evaluated_visits'] == min(bound, bodies+1)
    assert result['status'] == ('exit' if bound > bodies else 'bound_exhausted')
    assert list(result['state'].values()) == [initial+min(bound, bodies)]
    assert [step['kind'] for step in result['steps']] == ['continue']*min(bound, bodies) + (
        ['exit'] if bound > bodies else [])
    assert result['trip_count'] == result['termination'] == 'not_proven'


@pytest.mark.parametrize('bound', (1, 4, 8))
def test_immediate_exit_does_not_access_unknown_inactive_body_condition(bound):
    record = _record(_unsupported('multi_latch'), known=True)
    view = _view(record)
    condition = next(row['id'] for row in view['inputs'] if int(row['span'][-2], 16) == CF)
    reads = []
    class Inputs(dict):
        def get(self, key):
            assert key != condition, 'inactive branch selector is not an input demand'
            assert key not in reads, 'formula verification must use only original replay cache'
            reads.append(key)
            return super().get(key)
    result = evaluate_expression_consumer(record, _chain(record, bound),
        Inputs(_values(view, **{str(RAX): 10, str(R9): 1})))
    assert result['status'] == 'exit' and result['evaluated_visits'] == 1
    assert list(result['state'].values()) == [10]


def test_zero_visits_is_identity_without_condition_delta_or_effect_observation():
    record = _record(_loop(), known=True)
    view = _view(record)
    initial = {row['id']: 10 if int(row['span'][-2], 16) == RAX else 3
               for row in view['inputs'] if row['mutable']}
    class Inputs(dict):
        def get(self, key):
            assert key in initial, 'k=0 must not inspect an invariant body delta'
            return super().get(key)
    result = evaluate_expression_consumer(record, _chain(record, 0), Inputs(initial))
    assert result['state'] == initial and result['steps'] == []
    assert result['status'] == 'bound_exhausted' and result['evaluated_visits'] == 0


@pytest.mark.parametrize('right,delta', ((0, 1), (1, 2)))
def test_two_original_continue_edges_keep_their_own_update(right, delta):
    record = _record(_unsupported('multi_latch'), known=True)
    chain = _chain(record, 4)
    result = _run(record, chain, **{str(RAX): 10, str(R9): 0, str(CF): right})
    assert result['status'] == 'bound_exhausted'
    assert list(result['state'].values()) == [10+4*delta]
    assert len({row['edge'] for row in result['steps']}) == 1
    assert len({row['edge'] for row in chain['rounds'][0]['outcomes'] if row['kind'] == 'continue'}) == 2


@pytest.mark.parametrize('selector,delta', ((0, 11), (256, 7)))
def test_shared_branch_keeps_multiple_state_updates_correlated_and_wraps(selector, delta):
    record = _record(_branch_loop(shared=True, nested=True), known=True)
    result = _run(record, _chain(record, 8), **{str(RAX): (1<<64)-2, str(RDI): 20,
        str(RDX): 3, str(R9): selector, str(R8): 11, str(RSI): 7})
    view = _view(record)
    actual = {int(row['span'][-2], 16): result['state'][row['id']] for row in view['inputs'] if row['mutable']}
    # The nested selected branch adds RSI (7), not an independent choice per output.
    assert actual[RAX] == ((1<<64)-2+3*delta) & ((1<<64)-1)
    assert actual[RDI] == 20+3*delta and actual[RDX] == 0
    assert result['evaluated_visits'] == 4 and result['status'] == 'exit'


def test_state_dependent_branch_and_nonlinear_update_need_no_closed_form():
    stop, choice = tmp(0x300, 1), tmp(0x310)
    builder = (FunctionBuilder().ins(move(reg(RAX), reg(RCX))).label('header')
        .cbranch('exit', stop, op('INT_EQUAL', [reg(RDX), const(0)], stop))
        .cbranch('odd', choice, op('INT_AND', [reg(RDX), const(1)], choice))
        .ins(op('INT_XOR', [reg(RAX), const(0x55)], reg(RAX))).branch('join')
        .label('odd').ins(op('INT_ADD', [reg(RAX), reg(RDX)], reg(RAX)))
        .label('join').ins(op('INT_SUB', [reg(RDX), const(1)], reg(RDX))).branch('header')
        .label('exit').ins(move(reg(RBX), reg(RAX))).ret())
    record = _record(builder, known=True)
    assert not record['loop_summaries'][0]['complete']
    result = _run(record, _chain(record, 8), **{str(RAX): 10, str(RDX): 5})
    expected = 10
    for count in (5, 4, 3, 2, 1):
        expected = expected+count if count & 1 else expected ^ 0x55
    assert result['state'][next(row['id'] for row in _view(record)['inputs']
                              if int(row['span'][-2], 16) == RAX)] == expected
    assert result['status'] == 'exit' and result['evaluated_visits'] == 6
    assert len({tuple(step['decisions'].items()) for step in result['steps']}) >= 3


def _memory():
    flag = tmp(0x300, 1)
    builder = (FunctionBuilder().ins(move(reg(RAX), reg(RCX))).label('header')
        .cbranch('exit', flag, op('INT_EQUAL', [reg(RDX), const(0)], flag))
        .ins(load(tmp(0x400), const(DATA_BASE)),
             op('INT_XOR', [reg(RAX), tmp(0x400)], reg(RAX)),
             store(const(DATA_BASE), reg(RAX)), load(reg(RAX), const(DATA_BASE)),
             op('INT_SUB', [reg(RDX), const(1)], reg(RDX))).branch('header')
        .label('exit').ins(move(reg(RBX), reg(RAX))).ret())
    return _record(builder, known=True)


def test_fixed_ram_bytes_and_before_after_store_writer_links_survive_each_visit():
    record = _memory()
    view = _view(record)
    chain = _chain(record, 4)
    values = {row['id']: (0x55 if row['span'][1] == 'address_space' else
              3 if int(row['span'][-2], 16) == RDX else 10) for row in view['inputs']}
    result = evaluate_expression_consumer(record, chain, values)
    assert result['status'] == 'exit' and result['evaluated_visits'] == 4
    assert [len(step['effects']) for step in result['steps']] == [3, 3, 3, 0]
    for number, step in enumerate(result['steps'][:-1]):
        before, write, after = step['effects']
        assert before['read_sources'][0]['kind'] == 'input'
        assert after['read_sources'][0]['kind'] == 'definition'
        assert after['value'] == write['value']
        recipe = chain['rounds'][number]
        assert all(effect['definition_version'] == f'v{number}' for effect in recipe['effects'])
        assert all(effect['state_version'] == ('initial' if number == 0 else f'v{number-1}')
                   for effect in recipe['effects'])
        assert recipe['input_versions'] == {row['id']: ('initial:'+row['id'] if number == 0 or not row['mutable']
            else f'v{number-1}:'+row['id']) for row in view['inputs']}


def test_zero_visit_does_not_invent_missing_initial_ram_bytes():
    record = _memory()
    values = {row['id']: 0 for row in _view(record)['inputs'] if row['span'][1] != 'address_space'}
    with pytest.raises(Ineligible, match='initial input'):
        evaluate_expression_consumer(record, _chain(record, 0), values)


@pytest.mark.parametrize('bad', (None, -1, 9, True, 1.0, '2'))
def test_invalid_query_bound_is_not_an_iteration_claim(bad):
    with pytest.raises(Ineligible, match='max_visits'):
        _chain(_record(known=True), bad)


@pytest.mark.parametrize('shape', ('nested', 'irreducible'))
def test_incomplete_visit_is_not_promoted_by_a_bound(shape):
    record = _record(_unsupported(shape), known=True)
    with pytest.raises(Ineligible):
        derive_transition_chain(record, record['cycle_graph']['transitions'][0]['id'], 4)


def test_store_only_projection_is_not_a_closed_ram_state_or_general_visit():
    record = _record(_strided(), known=True)
    with pytest.raises(Ineligible, match='general one-visit'):
        derive_transition_chain(record, record['write_effect_transitions'][0]['id'], 4)


def test_mutable_memory_address_is_independently_rejected(monkeypatch):
    from tdo_v2 import _record_transition_chains as chains
    record = _memory()
    original = chains._namespace
    def mutable(*args):
        local, view = copy.deepcopy(original(*args))
        counter = next(row['id'] for row in view['inputs'] if int(row['span'][-2], 16) == RDX
                       and row['span'][1] == 'register_file')
        node = next(row for row in local['nodes'] if row.get('transition_input') == counter)
        load = next(row for row in local['nodes'] if row.get('opcode') == 'LOAD')
        next(arg for arg in load['operands'] if arg['index'] == 1)['parts'] = [
            dict(node=node['id'], bytes=[0, 8], at=[0, 8])]
        return local, view
    monkeypatch.setattr(chains, '_namespace', mutable)
    with pytest.raises(Ineligible, match='mutable memory address'):
        _chain(record, 4)


def test_unknown_assumptions_require_optin_before_input_access():
    record = _record()
    chain = _chain(record, 1)
    with pytest.raises(Ineligible, match='unattributed'):
        evaluate_expression_consumer(record, chain, _Unreadable())
    result = evaluate_expression_consumer(record, chain, _values(_view(record), **{str(RAX): 0, str(RDX): 3}),
        accept_unattributed_assumptions=True)
    assert not result['assumptions_complete']


@pytest.mark.parametrize('change', ('formula', 'proof', 'edge', 'state_link', 'writer', 'input', 'source', 'scope', 'bound'))
def test_recomputed_identity_cannot_replace_formula_and_original_recipe_validation(change):
    record = _record(known=True)
    chain = _chain(record, 2)
    if change == 'formula':
        node = next(node for node in chain['graph']['nodes'] if node['kind'] == 'literal' and node['bits'] == 64)
        node['value'] = str(int(node['value'])+7)
    elif change == 'proof': chain['proof']['termination'] = 'proven'
    elif change == 'edge': chain['rounds'][0]['outcomes'][0]['edge'] = -1
    elif change == 'state_link': chain['rounds'][1]['input_versions'][chain['tracked'][0]] = 'initial:s0'
    elif change == 'writer': chain['original_effects'] = 'no effects'
    elif change == 'input': chain['inputs'][0]['mutable'] = not chain['inputs'][0]['mutable']
    elif change == 'source': record['cycle_graph']['transitions'][0]['effects'] = [{'kind': 'load'}]
    elif change == 'scope': chain['scope'] = 'whole_machine'
    else: chain['max_visits'] = 3
    chain['id'] = _identity(chain)
    with pytest.raises(Ineligible):
        evaluate_expression_consumer(record, chain, _Unreadable())


def test_equivalent_stored_dag_is_reproved_instead_of_trusting_generator_order():
    record = _record(known=True)
    chain = _chain(record, 2)
    node = next(node for node in chain['graph']['nodes'] if node.get('op') == 'bvadd')
    node['args'].reverse()
    chain['id'] = _identity(chain)
    assert _run(record, chain, **{str(RAX): 0, str(RDX): 5})['evaluated_visits'] == 2


def test_unknown_solver_and_exhausted_budget_do_not_publish_a_chain(monkeypatch):
    from tdo_v2 import _record_transition_chains as chains, _record_expression_consumers as consumers
    record = _record(known=True)
    monkeypatch.setattr(chains._Budget, 'query', lambda *args: z3.unknown)
    with pytest.raises(Ineligible, match='unproven'):
        _chain(record, 4)
    monkeypatch.undo()
    ticks = iter((0, 100))
    monkeypatch.setattr(consumers.time, 'monotonic', lambda: next(ticks, 100))
    with pytest.raises(Ineligible, match='budget'):
        _chain(record, 4)


def test_wrong_candidate_generator_is_independently_rejected(monkeypatch):
    from tdo_v2 import _record_transition_chains as chains
    record = _record(known=True)
    original = chains.encode
    monkeypatch.setattr(chains, 'encode', lambda values, symbols, limits: original({key:
        z3.BoolVal(False) if z3.is_bool(value) else z3.BitVecVal(0, value.size())
        for key, value in values.items()}, symbols, limits))
    with pytest.raises(Ineligible):
        _chain(record, 4)


@pytest.mark.parametrize('change', ('guard', 'update', 'effect', 'decision', 'binding'))
def test_stored_local_visit_is_reproved_before_it_can_be_composed(change):
    record = _memory()
    chain = _chain(record, 2)
    graph = chain['visit_graph']
    if change == 'binding':
        node = next(row for row in graph['nodes'] if row['kind'] == 'input')
        node['binding'] = 'not-an-original-state'
    else:
        prefix = {'guard': 'o0:guard', 'update': 'o0:state:', 'effect': 'e0:value',
                  'decision': 'd0:value'}[change]
        key = next(key for key in graph['outputs'] if key.startswith(prefix))
        if change == 'effect':
            del graph['outputs'][key]
        else:
            old = graph['outputs'][key]
            bits = graph['nodes'][old]['bits']
            graph['nodes'].append(dict(id=len(graph['nodes']), kind='literal', bits=bits,
                                      value=False if bits == 0 else '123'))
            graph['outputs'][key] = len(graph['nodes'])-1
    chain['id'] = _identity(chain)
    with pytest.raises(Ineligible):
        evaluate_expression_consumer(record, chain, _Unreadable())


@pytest.mark.parametrize('case', ('false', 'conditional', 'unknown'))
def test_local_domain_lemma_never_promotes_a_conditional_empty_or_unknown_domain(monkeypatch, case):
    from tdo_v2 import _record_transition_chains as chains
    record = _record(known=True)
    original = chains._model
    def model(*args):
        row = original(*args)
        if case == 'unknown':
            return row
        defined = z3.BoolVal(False) if case == 'false' else next(iter(row[3].symbols.values())) == 0
        return (*row[:-2], defined, row[-1])
    monkeypatch.setattr(chains, '_model', model)
    if case == 'false':
        with pytest.raises(Ineligible, match='empty or unproven'):
            _chain(record, 1)
        return
    if case == 'unknown':
        query, calls = chains._Budget.query, []
        def unknown_first(self, *formulas):
            calls.append(True)
            return z3.unknown if len(calls) == 1 else query(self, *formulas)
        monkeypatch.setattr(chains._Budget, 'query', unknown_first)
    chain = _chain(record, 1)
    assert chain['proof']['one_visit_domain'] == 'retained_per_active_visit'


@pytest.mark.parametrize('width', (1, 2, 4, 8))
def test_exact_original_byte_state_width_wraps_without_inventing_high_bytes(width):
    record = _record(_loop(value_width=width), known=True)
    chain = _chain(record, 4)
    result = _run(record, chain, **{str(RAX): (1 << (8*width))-1, str(RDX): 3, str(RSI): 7})
    state = next(row for row in _view(record)['inputs'] if row['mutable'] and int(row['span'][-2], 16) == RAX)
    assert int(state['span'][-1], 16) == width
    assert result['state'][state['id']] == 20 and result['status'] == 'exit'


def test_overlay_and_json_roundtrip_preserve_all_originals_and_render_actual_formula_nodes():
    record = _record(known=True)
    before = copy.deepcopy(record)
    chain = _chain(record, 2)
    attached = attach_expression_consumer(record, json.loads(json.dumps(chain)))
    assert record == before
    assert {key: value for key, value in attached.items() if key != 'expression_consumers'} == before
    assert _fingerprint(attached) == _fingerprint(record) and eligibility(attached) == eligibility(record) == 'loop'
    result = evaluate_expression_consumer(attached, chain['id'], _values(_view(record), **{str(RAX): 0, str(RDX): 3}))
    assert result['evaluated_visits'] == 2
    text = render(attached)
    assert 'transition chain ' + chain['id'] in text and 'trip count/termination not proven' in text
    assert 'c0.n' in text and 'v0:active = c0.n' in text and 'state:' in text
