"""Explicit regional inputs are assumptions, never new source/entry facts."""

import copy
import json
import pytest
import z3

from synthetic import RAX,RBX,RCX,RDI,RDX,RSI,DATA_BASE,FunctionBuilder,add,const,op,reg,tmp,ram,copy as move,load
from test_operation_records import _analyzed,_record
from test_expression_views import _Unreadable
from tdo_v2.operation_records import (Ineligible,derive_expression_island,validate_expression_island,attach_expression_island,
    evaluate_expression_island,select_expression,simplify_expression,derive_expression_consumer,attach_expression_consumer,
    evaluate_expression_consumer,prove_byte_influence,eligibility,render)
from tdo_v2._record_expression_views import _fingerprint,ViewLimits,_build
from tdo_v2._record_expression_consumers import _identity


def _mba_region(*,opaque=False,width=8,shift=False):
    a,b,x,y,z=[tmp(0x300+i*0x10,width) for i in range(5)]
    builder=FunctionBuilder()
    if opaque: builder.call(0x1800)
    builder.ins(move(a,reg(RAX,width)),move(b,reg(RDI,width)),op('INT_XOR',[a,b],x),
        op('INT_AND',[a,b],y),op('INT_LEFT' if shift else 'INT_MULT',[y,const(1 if shift else 2,width)],z),
        add(reg(RAX,width),x,z)).ret()
    record=_record(_analyzed(builder),RAX,width)
    ports=[node['id'] for node in record['nodes'] if node.get('opcode')=='COPY']
    assert len(ports)==2
    return record,ports


def _evaluate(record,island,values,validity=None,**kwargs):
    return evaluate_expression_island(record,island,values,validity if validity is not None else {
        row['port']:True for row in island['external_obligations']},accept_conditional_boundaries=True,
        accept_unattributed_assumptions=True,**kwargs)


@pytest.mark.parametrize('opaque',(False,True))
@pytest.mark.parametrize('width',(1,2,4,8))
@pytest.mark.parametrize('shift',(False,True))
def test_mba_reuses_original_producers_and_separates_local_proof_from_source_connection(opaque,width,shift):
    record,ports=_mba_region(opaque=opaque,width=width,shift=shift)
    before=copy.deepcopy(record)
    island=derive_expression_island(record,boundaries=ports)
    assert island['proof']['status']=='equivalent_given_available_boundaries'
    assert island['connection']['status']==('unresolved' if opaque else 'linked_under_original_domain')
    assert not any(row.get('op') in ('bvxor','bvand','bvmul','bvshl') for row in island['graph']['nodes'])
    for x,y in ((0,0),(255,1),((1<<(width*8))-1,7),(0x1122334455667788,0xfedcba9876543210)):
        mask=(1<<(width*8))-1
        values={'p'+str(ports[0]):x&mask,'p'+str(ports[1]):y&mask}
        assert _evaluate(record,island,values)['outputs']=={'root':(x+y)&mask}
    attached=attach_expression_island(record,json.loads(json.dumps(island)),accept_unattributed_assumptions=True)
    assert record==before and {key:value for key,value in attached.items() if key!='expression_consumers'}==before
    assert eligibility(attached)==eligibility(before) and _fingerprint(attached)==_fingerprint(record)
    assert attach_expression_island(attached,island,accept_unattributed_assumptions=True)==attached
    assert 'source obligation retained' in render(attached)
    if opaque:
        assert eligibility(record)=='debt' and all(row['debt_nodes'] for row in island['external_obligations'])
        assert all(row['debt_nodes'][0]['calls'] for row in island['external_obligations'])
        assert simplify_expression(record)['proof']['status']=='partial'


def test_overlapping_bytes_are_extracts_of_one_whole_original_port():
    record,ports=_mba_region()
    port=ports[0]
    outputs=[dict(name='wide',width=2,parts=[dict(node=port,bytes=[3,5],at=[0,2])]),
             dict(name='overlap',width=1,parts=[dict(node=port,bytes=[4,5],at=[0,1])])]
    island=derive_expression_island(record,outputs,boundaries=[port])
    assert len(island['bindings'])==1 and island['bindings'][0]['width']==8
    result=_evaluate(record,island,{'p'+str(port):0x1122334455667788})
    assert result['outputs']==dict(wide=0x4455,overlap=0x44)


def test_original_shared_choice_is_not_replaced_by_independent_booleans():
    a=tmp(0x380)
    condition=tmp(0x390,1)
    builder=(FunctionBuilder().ins(move(a,reg(RDI)))
        .cbranch('yes',condition,op('INT_NOTEQUAL',[reg(RDX),const(0)],condition))
        .ins(add(reg(RAX),a,const(7)),add(reg(RCX),a,const(7))).branch('join').label('yes')
        .ins(add(reg(RAX),a,const(9)),add(reg(RCX),a,const(9))).label('join')
        .ins(op('INT_SUB',[reg(RAX),reg(RCX)],reg(RAX))).ret())
    record=_record(_analyzed(builder),RAX)
    port=next(node['id'] for node in record['nodes'] if node.get('opcode')=='COPY')
    assert sum(node['kind']=='phi' for node in record['nodes'])==2
    island=derive_expression_island(record,boundaries=[port])
    for selector in (0,1,256):
        values={row['id']:17 if row.get('role') else selector for row in island['bindings']}
        assert _evaluate(record,island,values)['outputs']==dict(root=0)


@pytest.mark.parametrize('validity',({},None,False,0,1))
def test_boundary_availability_is_mandatory_not_inferred_from_a_number(validity):
    record,ports=_mba_region(opaque=True)
    island=derive_expression_island(record,boundaries=ports)
    values={'p'+str(key):7 for key in ports}
    flags={} if validity=={} else {key:validity for key in values}
    with pytest.raises(Ineligible,match='explicitly available'):
        _evaluate(record,island,values,flags)


def test_value_for_every_port_is_required_even_when_candidate_cancels_it():
    record,ports=_mba_region()
    port=ports[0]
    record['nodes'][0]['opcode']='INT_SUB'
    record['nodes'][0]['operands'][1]=copy.deepcopy(record['nodes'][0]['operands'][0])
    island=derive_expression_island(record,boundaries=[port])
    assert island['graph']['nodes'][-1]['value']=='0'
    with pytest.raises(Ineligible,match='missing declared boundary value'):
        _evaluate(record,island,{})


def test_conditional_and_run_assumption_optins_are_checked_before_input_reads():
    record,ports=_mba_region()
    island=derive_expression_island(record,boundaries=ports)
    with pytest.raises(Ineligible,match='conditional boundary opt-in'):
        evaluate_expression_island(record,island,_Unreadable(),_Unreadable())
    with pytest.raises(Ineligible,match='unattributed'):
        evaluate_expression_island(record,island,_Unreadable(),_Unreadable(),accept_conditional_boundaries=True)
    with pytest.raises(Ineligible,match='unattributed'):
        attach_expression_island(record,island)
    with pytest.raises(Ineligible,match='unattributed'):
        validate_expression_island(record,island)


def test_ordinary_view_consumer_and_p2_cannot_automatically_consume_regional_cuts():
    record,ports=_mba_region()
    island=derive_expression_island(record,boundaries=ports)
    record=attach_expression_island(record,island,accept_unattributed_assumptions=True)
    with pytest.raises(Ineligible,match='attach_expression_island'):
        attach_expression_consumer(record,island)
    with pytest.raises(Ineligible,match='dedicated evaluation'):
        evaluate_expression_consumer(record,island['id'],_Unreadable(),accept_unattributed_assumptions=True)
    with pytest.raises(Ineligible): _build(record,island['selection'])
    with pytest.raises(Ineligible): derive_expression_consumer(record,select_expression(record),[island['id']])
    with pytest.raises(Ineligible):
        prove_byte_influence(record,island['selection'],[dict(input=dict(node=ports[0],byte=0),output=dict(name='root',byte=0))])


@pytest.mark.parametrize('change',('candidate','port_id','port_width','namespace','source','effect','source_parts','debt',
    'connection','available','selection','conditions','proof','limits','authority','island_namespace'))
def test_forged_contract_is_rejected_before_either_input_map_even_with_new_identity(change):
    record,ports=_mba_region(opaque=True)
    island=derive_expression_island(record,boundaries=ports)
    if change=='candidate': island['graph']['nodes'][-1]['op']='bvsub'
    elif change=='port_id': island['bindings'][0]['id']='p999'
    elif change=='port_width': island['bindings'][0]['width']=4
    elif change=='namespace': island['namespace']='other'
    elif change=='source': record['nodes'][0]['opcode']='INT_SUB'
    elif change=='effect': island['original_effects']='removed'
    elif change=='source_parts': island['external_obligations'][0]['source_parts']=[]
    elif change=='debt': island['external_obligations'][0]['debt_nodes']=[]
    elif change=='connection': island['connection']['status']='linked_under_original_domain'
    elif change=='available': island['boundary_validity']='proven'
    elif change=='selection': island['selection']['outputs'][0]['parts'][0]['bytes']=[1,9]
    elif change=='conditions': island['conditions']=[dict(binding='fake',equals=0)]
    elif change=='proof': island['proof']['original_debt']='resolved'
    elif change=='limits': island['selection']['limits']['solver_ms']=2001
    elif change=='authority': island['authority']='trust_me'
    else: island['island_namespace']='original'
    island['id']=_identity(island)
    with pytest.raises(Ineligible):
        evaluate_expression_island(record,island,_Unreadable(),_Unreadable(),accept_conditional_boundaries=True,
                                    accept_unattributed_assumptions=True)


def test_region_only_assumption_cannot_be_promoted_to_original_domain_connection():
    record,ports=_mba_region()
    island=derive_expression_island(record,boundaries=ports,conditions=[dict(binding='p'+str(ports[0]),equals=7)])
    assert island['proof']['status']=='equivalent_given_available_boundaries'
    assert island['connection']['status']=='unresolved'
    assert island['connection']['reason']=='original_domain_does_not_prove_region_premises'
    with pytest.raises(Ineligible,match='outside region domain'):
        _evaluate(record,island,{'p'+str(key):8 for key in ports})


def test_equivalent_alternative_serialized_candidate_is_reproved_not_generator_trusted():
    record,ports=_mba_region()
    island=derive_expression_island(record,boundaries=ports)
    island['graph']['nodes'][-1]['args'].reverse()  # Commutative add is a different but valid DAG.
    island['id']=_identity(island)
    validate_expression_island(record,island,accept_unattributed_assumptions=True)


@pytest.mark.parametrize('kind',('entry','debt','load','division','interrupted','override','phi','call'))
def test_boundary_cannot_disguise_nonvalue_effect_or_partial_producers(kind):
    record,ports=_mba_region()
    node=record['nodes'][ports[0]]
    if kind in ('entry','debt','phi','call'): node['kind']=kind
    elif kind=='load': node['opcode']='LOAD'
    elif kind=='division': node['opcode']='INT_DIV'
    elif kind=='interrupted': node['interrupted']=True
    else: node['override']=0
    with pytest.raises(Ineligible,match='existing total integer producer'):
        derive_expression_island(record,boundaries=ports)


@pytest.mark.parametrize('kind',('division','load','debt','call'))
def test_unsupported_inside_the_region_is_not_a_new_free_input(kind):
    record,ports=_mba_region()
    node=record['nodes'][0]
    if kind=='division': node['opcode']='INT_DIV'
    elif kind=='load': node['opcode']='LOAD'
    elif kind=='debt': node['debts']=[ports[0]]
    else: node['kind']='call'
    with pytest.raises(Ineligible): derive_expression_island(record,boundaries=ports)


def test_loop_and_onevisit_boundaries_are_explicitly_outside_initial_scope():
    from test_transition_records import _record as loop
    record=loop(known=True)
    port=next(node['id'] for node in record['nodes'] if node.get('opcode')=='COPY')
    with pytest.raises(Ineligible,match='loop/one-visit'):
        derive_expression_island(record,boundaries=[port])
    with pytest.raises(Ineligible,match='loop/one-visit'):
        derive_expression_island(record,boundaries=[port],namespace=record['cycle_graph']['transitions'][0]['id'])


@pytest.mark.parametrize('boundaries',([], [True], [999], [0,0], list(range(17))))
def test_bad_boundary_declarations_fail_closed(boundaries):
    record,_=_mba_region()
    with pytest.raises(Ineligible): derive_expression_island(record,boundaries=boundaries)


def test_original_guard_cannot_be_replaced_by_free_boolean_or_availability():
    record,ports=_mba_region(opaque=True)
    condition=next(node['id'] for node in record['nodes'] if node.get('opcode')=='INT_XOR')
    record['control']=dict(nodes=[False,True,dict(decision='d',true=1,false=0)],decisions={
        'd':dict(selection='d',decision='d',merge='test',true_successor='yes',false_successor='no',
                 operand=dict(width=8,parts=[dict(node=condition,bytes=[0,8],at=[0,8])]))})
    record['nodes'][condition]['debts']=[next(node['id'] for node in record['nodes'] if node['kind']=='debt')]
    outputs=[dict(name='root',width=8,parts=copy.deepcopy(record['root']),guard=2)]
    with pytest.raises(Ineligible,match='debt'):
        derive_expression_island(record,outputs,boundaries=ports)


def test_unknown_solver_and_exhausted_aggregate_budget_do_not_publish_a_region(monkeypatch):
    from tdo_v2 import _record_expression_islands as islands, _record_expression_consumers as consumers
    record,ports=_mba_region()
    monkeypatch.setattr(islands._Budget,'query',lambda *args:z3.unknown)
    with pytest.raises(Ineligible,match='unproven'):
        derive_expression_island(record,boundaries=ports)
    monkeypatch.undo()
    ticks=iter((0,100))
    monkeypatch.setattr(consumers.time,'monotonic',lambda:next(ticks,100))
    with pytest.raises(Ineligible,match='budget'):
        derive_expression_island(record,boundaries=ports)


def test_wrong_candidate_generator_and_empty_domain_are_not_success(monkeypatch):
    from tdo_v2 import _record_expression_islands as islands
    record,ports=_mba_region()
    monkeypatch.setattr(islands,'simplify',lambda value,**kwargs:z3.BitVecVal(0,value.size()))
    with pytest.raises(Ineligible,match='not equivalent'):
        derive_expression_island(record,boundaries=ports)
    monkeypatch.undo()
    with pytest.raises(Ineligible,match='unproven'):
        derive_expression_island(record,boundaries=ports,conditions=[dict(binding='p'+str(ports[0]),equals=0),
            dict(binding='p'+str(ports[0]),equals=1)])


@pytest.mark.parametrize('mode',('write_port','read_port','internal_read','load_through_copy'))
def test_raw_address_memory_cannot_be_disguised_as_pure_copy_or_upstream_value(mode):
    if mode=='write_port':
        builder=FunctionBuilder().ins(move(ram(DATA_BASE),reg(RDI))).ins(move(reg(RAX),ram(DATA_BASE))).ret()
    elif mode=='load_through_copy':
        builder=FunctionBuilder().ins(load(tmp(0x500),reg(RDI)),move(tmp(0x510),tmp(0x500)),
            move(tmp(0x520),tmp(0x510)),add(reg(RAX),tmp(0x520),const(7))).ret()
    else:
        builder=FunctionBuilder().ins(move(tmp(0x500),reg(RDI)),move(reg(RAX),ram(DATA_BASE))).ret()
    record=_record(_analyzed(builder),RAX)
    if mode=='write_port': port=next(node['id'] for node in record['nodes'] if node.get('output',{}).get('kind')=='address_space')
    elif mode=='load_through_copy': port=next(node['id'] for node in record['nodes'] if node.get('opcode')=='COPY')
    else: port=record['root'][0]['node']
    with pytest.raises(Ineligible,match='memory'):
        derive_expression_island(record,boundaries=[port])


def test_missing_cycle_graph_does_not_turn_cyclic_fallback_into_acyclic_evidence():
    from test_record_recurrence import _loop
    record=_record(_analyzed(_loop()),RBX)
    record.pop('cycle_graph')
    assert record['execution_fallback']=='cyclic cfg'
    with pytest.raises(Ineligible,match='cyclic/unsupported control'):
        derive_expression_island(record,boundaries=[record['root'][0]['node']])


def test_loop_partref_and_unverified_upstream_provenance_are_not_cut_away():
    record,ports=_mba_region()
    record['nodes'][ports[0]]['operands'][0]['parts'][0]['loop']=True
    with pytest.raises(Ineligible,match='loop or incomplete boundary'):
        derive_expression_island(record,boundaries=ports)
    builder=FunctionBuilder().ins(move(tmp(0x500),reg(RDI)))
    for i in range(1,25): builder.ins(move(tmp(0x500+i*0x10),tmp(0x500+(i-1)*0x10)))
    builder.ins(add(reg(RAX),tmp(0x500+24*0x10),const(7))).ret()
    record=_record(_analyzed(builder),RAX)
    port=record['nodes'][record['root'][0]['node']]['operands'][0]['parts'][0]['node']
    with pytest.raises(Ineligible,match='provenance unverified within limit'):
        derive_expression_island(record,boundaries=[port],limits=ViewLimits(nodes=12))


@pytest.mark.parametrize('kind',('physical_write','physical_memory','physical_read','physical_read_source'))
def test_physical_memory_evidence_is_not_ignored_even_on_integer_copy(kind):
    record,ports=_mba_region()
    node=record['nodes'][ports[0]]
    if kind.startswith('physical_read'): node['operands'][0][kind]={}
    else: node[kind]={}
    with pytest.raises(Ineligible,match='memory'):
        derive_expression_island(record,boundaries=ports)


def _memory_guard_port():
    flag,other,value=tmp(0x500,1),tmp(0x510,1),tmp(0x520)
    builder=(FunctionBuilder().cbranch('one',flag,op('INT_NOTEQUAL',[ram(DATA_BASE),const(0)],flag))
        .cbranch('two',other,op('INT_NOTEQUAL',[reg(RDX),const(0)],other))
        .ins(move(reg(RBX),const(3))).branch('join').label('two')
        .ins(move(reg(RBX),const(2))).branch('join').label('one')
        .ins(move(reg(RBX),const(1))).label('join').ins(move(value,reg(RBX)),add(reg(RAX),value,const(7))).ret())
    record=_record(_analyzed(builder),RAX)
    port=record['nodes'][record['root'][0]['node']]['operands'][0]['parts'][0]['node']
    assert record['nodes'][port]['opcode']=='COPY'
    assert any(node['kind']=='phi' and len(node.get('guarded_sources',{}).get('guards',()))==3 for node in record['nodes'])
    return record,port


def test_upstream_phi_control_memory_origin_is_not_hidden_behind_register_alternatives():
    record,port=_memory_guard_port()
    with pytest.raises(Ineligible,match='memory'):
        derive_expression_island(record,boundaries=[port])


def test_upstream_execution_guard_and_incomplete_decision_share_provenance_budget():
    record,ports=_mba_region()
    dependency=record['nodes'][ports[0]]['operands'][0]['parts'][0]['node']
    record['nodes'][dependency]['execution_guard']=2
    record['control']=dict(nodes=[False,True,dict(decision='d',true=1,false=0)],decisions={
        'd':dict(selection='d',decision='d',merge='test',true_successor='yes',false_successor='no',
                 operand=dict(width=1,parts=[dict(node=dependency,bytes=[0,1],at=[0,1])],unresolved=True))})
    with pytest.raises(Ineligible,match='incomplete operand'):
        derive_expression_island(record,boundaries=ports)
