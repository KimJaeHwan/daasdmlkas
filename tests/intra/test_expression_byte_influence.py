"""One-byte interventions are proof overlays, never provenance pruning."""

import copy
import json
import pytest
import z3

from synthetic import RAX, RCX, RDI, RSI, RDX, FunctionBuilder, add, const, op, reg, tmp, copy as move
from test_operation_records import _analyzed, _record
from test_expression_views import _simple, _Unreadable
from test_expression_loop_consumers import _prepared
from tdo_v2.operation_records import (Ineligible, select_expression, prove_byte_influence, validate_byte_influence,
    attach_byte_influence, evaluate_expression_consumer, eligibility, render)
from tdo_v2._record_expression_views import _build, _fingerprint
from tdo_v2._record_expression_consumers import _identity, attach_expression_consumer
from tdo_v2._record_expression_influence import InfluenceLimits


def _pair(node=1, byte=0, name='root', out=0):
    return dict(input=dict(node=node, byte=byte), output=dict(name=name, byte=out))


def _prove(record, pairs=None, selection=None, **kwargs):
    return prove_byte_influence(record, selection or select_expression(record), pairs or [_pair()],
                                accept_unattributed_assumptions=True, **kwargs)


@pytest.mark.parametrize('byte,out,status', [(0,0,'may_influence'), (0,1,'may_influence'),
    (0,7,'may_influence'), (1,0,'independent_when_both_defined'), (8,1,'may_influence'),
    (15,0,'independent_when_both_defined')])
def test_addition_preserves_whole_merged_binding_and_carries(byte,out,status):
    record = _simple()
    proof = _prove(record, [_pair(byte=byte,out=out)])
    row, = proof['results']
    assert proof['bindings'] == [dict(id='n1',node=1,width=16,transition_input=None)]
    assert row['value'] == status
    assert all(row[key]=='stable_in_comparison_context' for key in ('Q','R','A'))
    for witness in row['witnesses'].values():
        first, second = witness['first']['n1'], witness['second']['n1']
        assert first != second and not (first ^ second) & ~(255 << (byte*8))
    validate_byte_influence(record, proof, accept_unattributed_assumptions=True)


@pytest.mark.parametrize('width',(1,2,4,8))
def test_original_mba_cancellation_is_proved_without_removing_source(width):
    a,b,c,d = [tmp(0x300+i*0x10,width) for i in range(4)]
    record = _record(_analyzed(FunctionBuilder().ins(op('INT_XOR',[reg(RDI,width),reg(RSI,width)],a),
        op('INT_AND',[reg(RDI,width),reg(RSI,width)],b),op('INT_MULT',[b,const(2,width)],c),
        add(d,a,c),op('INT_SUB',[d,reg(RSI,width)],reg(RAX,width))).ret()),RAX,width)
    selected = select_expression(record)
    adapter,*_ = _build(record,selected)
    # Entry producers can be merged or separate: locate RSI's actual byte.
    node = next(n for n in record['nodes'] if n['kind']=='entry' and n['register']['offset']<=RSI<
                n['register']['offset']+n['register']['size'])
    byte = RSI-node['register']['offset']
    assert 'n'+str(node['id']) in adapter.bindings
    before=copy.deepcopy(record)
    proof=_prove(record,[_pair(node['id'],byte)],selected)
    assert proof['results'][0]['value']=='independent_when_both_defined'
    assert record==before and any(n.get('opcode')=='INT_AND' for n in record['nodes'])


def test_body_value_independence_does_not_hide_changed_reach():
    record,visit,view=_prepared()
    state=next(row['id'] for row in visit['inputs'] if int(row['span'][-2],16)==RDX)
    binding=next(row for row in view['bindings'] if row['transition_input']==state)
    proof=_prove(record,[_pair(binding['node'],0,'1')],view['selection'])
    row,=proof['results']
    assert row['value']=='independent_when_both_defined'
    assert row['R']=='may_change' and 'R_change' in row['witnesses']
    assert row['address_effects']['termination']=='not_proven'


def _guarded(*, zero_only=False, guard_defined=False, value_defined=False):
    record=_simple()
    entry=dict(width=1,parts=[dict(node=1,bytes=[0,1],at=[0,1])])
    def decision(key,operand):
        return dict(selection=key,decision=key,merge='test',true_successor='yes',false_successor='no',operand=operand)
    record['control']=dict(nodes=[False,True,dict(decision='entry',true=0 if zero_only else 1,false=1 if zero_only else 0)],
                           decisions={'entry':decision('entry',entry)})
    if guard_defined:
        record['nodes'][0]['execution_guard']=2
        record['control']['decisions']['op']=decision('op',dict(width=8,parts=copy.deepcopy(record['root'])))
        record['control']['nodes'].append(dict(decision='op',true=1,false=0))
    if value_defined:
        record['nodes'][0]['execution_guard']=2
        output=dict(name='root',width=8,parts=copy.deepcopy(record['root']))
    else:
        output=dict(name='root',width=1,parts=[dict(node=1,bytes=[8,9],at=[0,1])],guard=3 if guard_defined else 2)
    return record,select_expression(record,[output])


def test_no_defined_pair_is_not_vacuous_independence():
    record,selection=_guarded(zero_only=True)
    proof=_prove(record,selection=selection)
    row,=proof['results']
    assert row['comparable']=='unsat' and row['value']=='no_comparable_defined_pair'
    assert row['R']=='may_change' and row['A']=='not_comparable'


def test_guard_evaluability_and_value_definedness_are_separate_observations():
    record,selection=_guarded(guard_defined=True)
    row,=_prove(record,selection=selection)['results']
    assert row['value']=='independent_when_both_defined' and row['Q']=='may_change'
    record,selection=_guarded(value_defined=True)
    row,=_prove(record,selection=selection)['results']
    assert row['A']=='may_change' and row['R']=='stable_in_comparison_context'


def test_hypothesis_fixed_byte_and_empty_hypotheses_are_not_independence():
    record=_simple()
    fixed=_prove(record,conditions=[dict(binding='n1',equals=17)])
    assert fixed['hypotheses']=='sat' and fixed['results'][0]['value']=='fixed_by_hypothesis'
    empty=_prove(record,conditions=[dict(binding='n1',equals=0),dict(binding='n1',equals=1)])
    assert empty['hypotheses']=='unsat' and empty['results'][0]['value']=='inconsistent_hypotheses'


def test_overlay_roundtrip_authority_and_numeric_refusal_before_input_reads():
    record=_simple()
    before=copy.deepcopy(record)
    proof=_prove(record)
    proof=json.loads(json.dumps(proof))
    attached=attach_byte_influence(record,proof,accept_unattributed_assumptions=True)
    assert record==before and _fingerprint(attached)==_fingerprint(record)
    assert eligibility(attached)==eligibility(record)
    with pytest.raises(Ineligible,match='attach_byte_influence'):
        attach_expression_consumer(record,proof)
    assert attach_byte_influence(attached,proof,accept_unattributed_assumptions=True)==attached
    assert 'proof-only' in render(attached) and 'value=may_influence' in render(attached)
    with pytest.raises(Ineligible,match='proof-only'):
        evaluate_expression_consumer(attached,proof['id'],_Unreadable(),accept_unattributed_assumptions=True)
    with pytest.raises(Ineligible,match='unattributed'):
        validate_byte_influence(record,proof)
    with pytest.raises(Ineligible,match='unattributed'):
        prove_byte_influence(record,select_expression(record),[_pair()])


@pytest.mark.parametrize('change',('value','Q','R','A','hypotheses','source','selection','binding_id',
    'effect','witness_value','witness_other_byte','witness_other_input','missing_witness','authority','proof'))
def test_recomputed_hash_does_not_authorize_forged_proof_or_witness(change):
    record=_simple()
    proof=_prove(record)
    row=proof['results'][0]
    if change in ('value','Q','R','A'): row[change]='independent_when_both_defined'
    elif change=='hypotheses': proof['hypotheses']='unsat'
    elif change=='source': record['nodes'][0]['opcode']='INT_SUB'
    elif change=='selection': proof['selection']['outputs'][0]['guard']=0
    elif change=='binding_id': proof['bindings'][0]['id']='n999'
    elif change=='effect': row['address_effects']['effects']='independent'
    elif change=='witness_value': row['witnesses']['value']['first_observation']['byte_value']^=1
    elif change=='witness_other_byte': row['witnesses']['value']['second']['n1']^=256
    elif change=='witness_other_input': row['witnesses']['value']['second']['extra']=1
    elif change=='missing_witness': row['witnesses'].pop('value')
    elif change=='authority': proof['authority']='trust_me'
    else: proof['proof']['method']='assume'
    proof['id']=_identity(proof)
    with pytest.raises(Ineligible):
        validate_byte_influence(record,proof,accept_unattributed_assumptions=True)


def test_different_valid_sat_model_is_accepted_not_compared_to_solver_choice():
    record=_simple()
    proof=_prove(record)
    # A second valid model of add: RSI low byte changes 1 -> 2, RDI=0.
    witness=proof['results'][0]['witnesses']['value']
    witness['first']={'n1':1}
    witness['second']={'n1':2}
    for side,value in (('first',1),('second',2)):
        witness[side+'_observation']=dict(Q=True,R=True,A=True,byte_value=value,observable=True)
    proof['id']=_identity(proof)
    validate_byte_influence(record,proof,accept_unattributed_assumptions=True)


@pytest.mark.parametrize('pairs',([_pair(node=0)],[_pair(byte=True)],[_pair(byte=16)],[_pair(out=8)],
    [_pair(name='missing')],[_pair(),_pair()],[]))
def test_only_existing_original_boundary_byte_queries_are_accepted(pairs):
    record=_simple()
    with pytest.raises(Ineligible):
        prove_byte_influence(record,select_expression(record),pairs,accept_unattributed_assumptions=True)


def test_query_cap_keeps_every_requested_pair_and_unknowns_not_proofs():
    record=_simple()
    proof=_prove(record,[_pair(byte=0),_pair(byte=1),_pair(byte=2)],limits=InfluenceLimits(queries=2))
    assert proof['incomplete'] and len(proof['results'])==3
    assert all(row['value']=='unknown' for row in proof['results'])
    assert proof['results'][-1]['variability']=='unknown'


def test_solver_unknown_and_deadline_never_become_independent(monkeypatch):
    from tdo_v2 import _record_expression_influence as influence
    record=_simple()
    monkeypatch.setattr(influence._Budget,'query',lambda *args:('unknown',None))
    proof=_prove(record)
    assert proof['hypotheses']=='unknown' and proof['incomplete'] and proof['results'][0]['value']=='unknown'
    monkeypatch.undo()
    ticks=iter((0,100))
    monkeypatch.setattr(influence.time,'monotonic',lambda:next(ticks,100))
    proof=_prove(record)
    assert proof['incomplete'] and proof['results'][0]['value']=='unknown'


def test_mid_pair_solver_unknown_is_explicitly_incomplete(monkeypatch):
    from tdo_v2 import _record_expression_influence as influence
    original=influence._Budget.query
    def query(budget,formula):
        if budget.count==3:  # H, variation, comparable succeeded; value unproven.
            budget.count+=1
            return 'unknown',None
        return original(budget,formula)
    monkeypatch.setattr(influence._Budget,'query',query)
    proof=_prove(_simple())
    assert proof['incomplete'] and proof['results'][0]['value']=='unknown'


def test_shared_original_branch_is_not_two_independent_phi_selectors():
    condition=tmp(0x300,1)
    builder=(FunctionBuilder().cbranch('yes',condition,op('INT_NOTEQUAL',[reg(RDI),const(0)],condition))
        .ins(move(reg(RAX),const(7)),move(reg(RCX),const(7))).branch('join').label('yes')
        .ins(move(reg(RAX),const(9)),move(reg(RCX),const(9))).label('join')
        .ins(op('INT_SUB',[reg(RAX),reg(RCX)],reg(RAX))).ret())
    record=_record(_analyzed(builder),RAX)
    assert sum(node['kind']=='phi' for node in record['nodes'])==2
    entry=next(node for node in record['nodes'] if node['kind']=='entry')
    proof=_prove(record,[_pair(entry['id'])])
    assert proof['results'][0]['value']=='independent_when_both_defined'


def test_witness_cannot_change_another_existing_transition_binding():
    record,visit,view=_prepared()
    counter=next(row for row in view['bindings'] if row['node']==1)
    proof=_prove(record,[_pair(counter['node'],0,'1')],view['selection'])
    witness=proof['results'][0]['witnesses']['R_change']
    other=next(key for key in witness['second'] if key!=counter['id'])
    witness['second'][other]^=1
    proof['id']=_identity(proof)
    with pytest.raises(Ineligible,match='other input'):
        validate_byte_influence(record,proof,accept_unattributed_assumptions=True)


@pytest.mark.parametrize('limits',(InfluenceLimits(pairs=17),InfluenceLimits(queries=193),InfluenceLimits(solver_ms=2001),
    InfluenceLimits(total_ms=20001),InfluenceLimits(pairs=True),InfluenceLimits(queries=0)))
def test_caller_cannot_expand_or_disable_resource_ceilings(limits):
    with pytest.raises(Ineligible,match='limits'):
        _prove(_simple(),limits=limits)


@pytest.mark.parametrize('reason',('debt','call','cycle','division'))
def test_unsupported_original_semantics_fail_closed_not_independent(reason):
    record=_simple()
    if reason=='debt': record['nodes'][0]['debts']=['unresolved']
    elif reason=='call': record['nodes'][0]['kind']='call'
    elif reason=='division': record['nodes'][0]['opcode']='INT_DIV'
    else: record['nodes'][0]['operands'][0]['parts'][0]['node']=0
    with pytest.raises(Ineligible): _prove(record)


def test_observation_api_preserves_previous_value_and_domain_ast_order():
    record,visit,view=_prepared()
    adapter,values,domain,*_=_build(record,view['selection'])
    old_values,old_domain={},[]
    for row in view['selection']['outputs']:
        value,defined=adapter.assemble(row['parts'],row['width'])
        guard,gd=adapter.guard(row['guard'])
        old_values[row['name']]=value
        old_domain.extend((defined,guard,gd))
    assert all(z3.eq(values[key],old_values[key]) for key in values)
    assert z3.eq(domain,z3.And(*old_domain))
