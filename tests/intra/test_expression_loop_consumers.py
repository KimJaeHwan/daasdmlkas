"""Invariant delta recipes do not widen original countdown/effect contracts."""

import copy as copying
import json
import pytest

from synthetic import RAX,RBX,RCX,RDI,RDX,RSI,R9,RSP,FunctionBuilder,const,copy,add,op,reg,tmp,load,store
from test_transition_records import _record,_values,_Unreadable
from tdo_v2.operation_records import (Ineligible,select_expression,simplify_expression,attach_expression_view,
    derive_loop_consumer,evaluate_expression_consumer,attach_expression_consumer,evaluate_transition,eligibility)


def _loop(*,mutable=False,address=False,exit_write=False):
    cond,choice=tmp(0x300,1),tmp(0x310,1)
    a,b,c,d=tmp(0x320),tmp(0x330),tmp(0x340),tmp(0x350)
    builder=(FunctionBuilder().ins(copy(reg(RAX),reg(RCX))).label('header')
             .cbranch('exit',cond,op('INT_EQUAL',[reg(RDX),const(0)],cond)))
    if address:
        builder.ins(add(tmp(0x360),reg(RSP),reg(RDX)),store(tmp(0x360),reg(RAX)))
    builder.cbranch('yes',choice,op('INT_NOTEQUAL',[reg(R9),const(0)],choice))
    builder.ins(op('INT_XOR',[reg(RAX) if mutable else reg(RSI),const(0x55)],d),
                add(reg(RAX),reg(RAX),d)).branch('join').label('yes')
    builder.ins(op('INT_XOR',[reg(RAX),reg(RSI)],a),op('INT_AND',[reg(RAX),reg(RSI)],b),
                op('INT_MULT',[b,const(2)],c),add(reg(RAX),a,c))
    builder.label('join').ins(op('INT_SUB',[reg(RDX),const(1)],reg(RDX))).branch('header').label('exit')
    if exit_write:
        builder.ins(add(reg(RAX),reg(RAX),const(1)))
    return builder.ins(copy(reg(RBX),reg(RAX))).ret()


def _prepared(builder=None,*,known=True,conditions=()):
    record=_record(builder or _loop(),known=known)
    visit,=record['cycle_graph']['transitions']
    assert visit['complete'],visit
    body,=[row for row in visit['outcomes'] if row['kind']=='continue']
    outputs=[dict(name=str(i),width=int(row['span'][-1],16),parts=[row['part']],guard=body['guard'])
             for i,row in enumerate(body['updates'])]
    view=simplify_expression(record,select_expression(record,outputs,namespace=visit['id']),conditions=conditions)
    assert view['proof']['status']=='equivalent',view['proof']
    return attach_expression_view(record,view),visit,view


@pytest.mark.parametrize('selector', (0,1,256))
@pytest.mark.parametrize('count',(0,1,3,9))
def test_pure_invariant_delta_dag_matches_original_visits(selector,count):
    record,visit,view=_prepared()
    before=copying.deepcopy(record)
    assert not record['loop_summaries'][0]['complete']
    consumer=derive_loop_consumer(record,visit['id'],[view['id']])
    record=attach_expression_consumer(record,consumer)
    values=_values(visit,**{str(RAX):(1<<64)-2,str(RDX):count,str(RSI):7,str(R9):selector})
    result=evaluate_expression_consumer(json.loads(json.dumps(record)),consumer['id'],values)
    delta=7 if selector else 7^0x55
    assert result['iterations']==count
    assert next(row['value'] for row in result['updates'] if int(row['span'][-2],16)==RAX)==((1<<64)-2+count*delta)% (1<<64)
    for _ in range(count):
        raw=evaluate_transition(record,visit['id'],values)
        assert raw['kind']=='continue'
        for update in raw['updates']:
            state,=[row for row in visit['inputs'] if row['span']==update['span']]
            values[state['id']]=update['value']
    assert evaluate_transition(record,visit['id'],values)['updates']==result['updates']
    assert {k:v for k,v in record.items() if k!='expression_consumers'}==before
    assert eligibility(record)==eligibility(before)


def test_huge_counter_is_formula_not_unrolling():
    from tdo_v2.operation_records import render
    record,visit,view=_prepared()
    consumer=derive_loop_consumer(record,visit['id'],[view['id']])
    n=(1<<64)-1
    values=_values(visit,**{str(RAX):17,str(RDX):n,str(RSI):0x1000000000000001,str(R9):1})
    result=evaluate_expression_consumer(record,consumer,values)
    assert result['iterations']==n
    assert next(row['value'] for row in result['updates'] if int(row['span'][-2],16)==RAX)==(17+n*0x1000000000000001)% (1<<64)
    assert not result['effect_template']['full_trace_materialized']
    text=render(attach_expression_consumer(record,consumer))
    assert 'counter]' in text and 'case0.n' in text and 'tracked region state only' in text


def test_zero_iterations_do_not_read_body_delta_or_selector():
    record,visit,view=_prepared()
    consumer=derive_loop_consumer(record,visit['id'],[view['id']])
    values=_values(visit,**{str(RAX):17,str(RDX):0})
    allowed={key for key,value in values.items() if value is not None}
    class Inputs(dict):
        def get(self,key):
            assert key in allowed, 'inactive body input was demanded'
            return super().get(key)
    result=evaluate_expression_consumer(record,consumer,Inputs(values))
    assert result['iterations']==0 and result['selected_choices']==[]


def test_mutable_delta_is_not_a_translation():
    record,visit,view=_prepared(_loop(mutable=True))
    with pytest.raises(Ineligible,match='invariant translation'):
        derive_loop_consumer(record,visit['id'],[view['id']])


def test_first_visit_only_counter_assumption_is_refused():
    record,visit,view=_prepared()
    counter=next(row['id'] for row in visit['inputs'] if int(row['span'][-2],16)==RDX)
    binding=next(row['id'] for row in view['bindings'] if row['transition_input']==counter)
    restricted=simplify_expression(record,view['selection'],conditions=[dict(binding=binding,equals=1)])
    record=attach_expression_view(record,restricted)
    with pytest.raises(Ineligible,match='does not imply'):
        derive_loop_consumer(record,visit['id'],[restricted['id']])


@pytest.mark.parametrize('change',('delta','exit','effect','counter','reference','source','authority'))
def test_changed_recipe_refused_before_inputs_even_with_recomputed_hash(change):
    from tdo_v2._record_expression_consumers import _identity
    record,visit,view=_prepared()
    consumer=derive_loop_consumer(record,visit['id'],[view['id']])
    if change=='delta': consumer['summary']['cases'][0]['updates'][0]['delta']['constant']+=1
    elif change=='exit': consumer['summary']['exit_edge']+=1
    elif change=='effect': consumer['summary']['effect_template']['header_repetitions']='n'
    elif change=='counter': consumer['summary']['counter']['input']='s999'
    elif change=='reference': consumer['views']=[consumer['id']]
    elif change=='source': record['cycle_graph']['cfg']['edges'][0]['target']='unknown'
    else: consumer['authority']='unversioned'
    consumer['id']=_identity(consumer)
    with pytest.raises(Ineligible):
        evaluate_expression_consumer(record,consumer,_Unreadable())


def test_unattributed_assumptions_default_refusal():
    record,visit,view=_prepared(known=False)
    consumer=derive_loop_consumer(record,visit['id'],[view['id']])
    with pytest.raises(Ineligible,match='unattributed'):
        evaluate_expression_consumer(record,consumer,_Unreadable())


def test_serialized_delta_candidate_is_reproved(monkeypatch):
    import z3
    from tdo_v2 import _record_expression_loops as loops
    original=loops.encode
    record,visit,view=_prepared()
    def broken(outputs,symbols,limits):
        return original({key:z3.BitVecVal(0,value.size()) for key,value in outputs.items()},symbols,limits)
    monkeypatch.setattr(loops,'encode',broken)
    with pytest.raises(Ineligible,match='final delta'):
        derive_loop_consumer(record,visit['id'],[view['id']])


def test_dead_partial_operation_in_original_body_is_still_rejected():
    from test_loop_summary_records import _loop as original_loop
    record,visit,view=_prepared(original_loop(extra_opcode='INT_DIV'))
    with pytest.raises(Ineligible,match='potentially partial'):
        derive_loop_consumer(record,visit['id'],[view['id']])


def test_original_mutable_branch_condition_is_not_promoted_to_invariant():
    from test_loop_summary_branches import _branch_loop
    record,visit,view=_prepared(_branch_loop(feedback=True))
    with pytest.raises(Ineligible,match='mutable'):
        derive_loop_consumer(record,visit['id'],[view['id']])


def test_existing_incomplete_moving_address_view_cannot_be_bypassed():
    from test_loop_summary_records import _loop as original_loop
    record=_record(original_loop(address_changes=True),known=True)
    visit,=record['cycle_graph']['transitions']
    assert not visit['complete']
    with pytest.raises(Ineligible,match='incomplete'):
        derive_loop_consumer(record,visit['id'],[])


@pytest.mark.parametrize('changed',('address','exit'))
def test_original_structural_checks_remain_after_verified_form_hook(changed):
    from tdo_v2 import _record_loop_summaries as summaries
    from test_loop_summary_records import _loop as original_loop
    record=_record(original_loop(),known=True)
    view=copying.deepcopy(record['cycle_graph']['transitions'][0])
    # Local policy fixture only. Public consumers additionally validate all raw
    # certificates. Exercise the existing policy WITH the new update hook.
    normal=summaries._Normalizer(view,record['limits'])
    forms={tuple(row['span']):normal.part(row['part']) for row in view['outcomes'][0]['updates']}
    if changed=='address':
        counter=record['loop_summaries'][0]['counter']['input']
        source=next(node for node in view['record']['nodes'] if node.get('transition_input')==counter)
        node=dict(id=len(view['record']['nodes']),kind='op',opcode='LOAD',
                  operands=[dict(index=1,width=8,parts=[dict(node=source['id'],bytes=[0,8],at=[0,8])])])
        view['record']['nodes'].append(node)
        view['effects'].append(dict(kind='load',node=node['id'],guard=1))
        reason='address varies'
    else:
        view['outcomes'][1]['updates'][0]['part']=view['outcomes'][0]['updates'][0]['part']
        reason='zero-exit'
    with pytest.raises(summaries._Partial,match=reason):
        summaries._derive(view,record['limits'],update_forms=lambda *args:forms)
