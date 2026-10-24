"""Proof-carrying reuse never narrows the consumer's original domain."""

import copy
import json
import pytest

from synthetic import RAX, RDI, RSI, FunctionBuilder, add, const, op, reg, tmp
from test_expression_views import _mba, _simple, _binding_values, _Unreadable
from test_operation_records import _analyzed, _record
from tdo_v2.operation_records import (Ineligible, select_expression, simplify_expression, attach_expression_view,
    derive_expression_consumer, attach_expression_consumer, evaluate_expression_consumer, evaluate_expression_view)
from tdo_v2._record_expression_views import _fingerprint


def _chain():
    a,b,c = tmp(0x300),tmp(0x310),tmp(0x320)
    record=_record(_analyzed(FunctionBuilder().ins(op('INT_XOR',[reg(RDI),reg(RSI)],a),
        op('INT_AND',[reg(RDI),reg(RSI)],b),op('INT_MULT',[b,const(2)],c),
        add(reg(RAX),a,c),add(reg(RAX),reg(RAX),const(9))).ret()),RAX)
    producer=next(row for row in record['nodes'] if row.get('opcode')=='INT_ADD' and row['id']!=record['root'][0]['node'])
    selection=select_expression(record,[dict(name='mba',width=8,parts=[dict(node=producer['id'],bytes=[0,8],at=[0,8])])])
    view=simplify_expression(record,selection)
    return attach_expression_view(record,view),view


def test_downstream_reuses_verified_mba_ports_and_keeps_original_authority():
    record,view=_chain()
    before=copy.deepcopy(record)
    consumer=derive_expression_consumer(record,select_expression(record),[view['id']])
    assert consumer['proof']['status']=='equivalent'
    attached=attach_expression_consumer(record,consumer)
    assert record==before and _fingerprint(attached)==_fingerprint(record)
    values=_binding_values(record,view,{RDI:(1<<64)-1,RSI:7})
    assert evaluate_expression_consumer(attached,consumer['id'],values,accept_unattributed_assumptions=True)['outputs']=={'root':15}
    assert evaluate_expression_view(attached,view['id'],values,accept_unattributed_assumptions=True)['outputs']=={'mba':6}
    assert attach_expression_consumer(attached,consumer)==attached
    assert json.loads(json.dumps(consumer))==consumer


def test_derived_collection_order_cannot_change_old_p0_source_hash():
    from tdo_v2._record_expression_views import _digest
    record,view=_chain()
    source=_fingerprint(record)
    # Exact authority algorithm used before the consumer collection existed.
    assert source==_digest({key:value for key,value in record.items() if key!='expression_views'})
    record['expression_consumers']=[{'id':'a'},{'id':'b'}]
    assert _fingerprint(record)==source
    record['expression_consumers'].reverse()
    assert _fingerprint(record)==source
    record['nodes'][0]['opcode']='INT_SUB'
    assert _fingerprint(record)!=source


def test_view_assumption_must_follow_from_original_consumer_not_narrow_it():
    record=_simple()
    view=simplify_expression(record,conditions=[dict(binding='n1',equals=0)])
    assert view['proof']['status']=='equivalent'
    record=attach_expression_view(record,view)
    with pytest.raises(Ineligible,match='does not imply'):
        derive_expression_consumer(record,select_expression(record),[view['id']])


@pytest.mark.parametrize('change',('source','bytes','namespace','graph','views','cycle','authority'))
def test_changed_consumer_is_rejected_before_input_access_even_if_identity_recomputed(change):
    from tdo_v2._record_expression_consumers import _identity
    record,view=_chain()
    consumer=derive_expression_consumer(record,select_expression(record),[view['id']])
    if change=='source': record['nodes'][0]['opcode']='INT_SUB'
    elif change=='bytes': consumer['selection']['outputs'][0]['parts'][0]['bytes']=[1,9]
    elif change=='namespace': consumer['namespace']='other'
    elif change=='graph': consumer['graph']['nodes'][-1]['op']='bvsub'
    elif change=='views': consumer['views']=['unknown']
    elif change=='cycle': consumer['views']=[consumer['id']]
    else: consumer['authority']='trust_me'
    consumer['id']=_identity(consumer)
    with pytest.raises(Ineligible):
        evaluate_expression_consumer(record,consumer,_Unreadable(),accept_unattributed_assumptions=True)


def test_unattributed_assumptions_refused_before_reads():
    record,view=_chain()
    consumer=derive_expression_consumer(record,select_expression(record),[view['id']])
    with pytest.raises(Ineligible,match='unattributed'):
        evaluate_expression_consumer(record,consumer,_Unreadable())


def test_byte_port_replacement_preserves_untouched_upper_bytes_and_placement():
    record=_mba()
    node=record['root'][0]['node']
    selection=select_expression(record,[dict(name='low',width=2,parts=[dict(node=node,bytes=[0,2],at=[0,2])])])
    view=simplify_expression(record,selection)
    record=attach_expression_view(record,view)
    consumer=derive_expression_consumer(record,select_expression(record),[view['id']])
    values=_binding_values(record,view,{RDI:0x112233445566ffff,RSI:7})
    actual=evaluate_expression_consumer(record,consumer,values,accept_unattributed_assumptions=True)
    assert actual['outputs']=={'root':0x1122334455670006}


def test_final_candidate_generator_is_not_trusted(monkeypatch):
    import z3
    from tdo_v2 import _record_expression_consumers as consumers
    record,view=_chain()
    monkeypatch.setattr(consumers,'simplify',lambda value,**kwargs:z3.BitVecVal(0,value.size()))
    with pytest.raises(Ineligible,match='final candidate'):
        derive_expression_consumer(record,select_expression(record),[view['id']])


def test_nonoverlapping_byte_port_is_not_reported_as_reused():
    record=_mba()
    node=record['root'][0]['node']
    low=select_expression(record,[dict(name='low',width=1,parts=[dict(node=node,bytes=[0,1],at=[0,1])])])
    view=simplify_expression(record,low)
    record=attach_expression_view(record,view)
    high=select_expression(record,[dict(name='high',width=1,parts=[dict(node=node,bytes=[1,2],at=[0,1])])])
    with pytest.raises(Ineligible,match='not used'):
        derive_expression_consumer(record,high,[view['id']])


def test_unproven_or_exhausted_proof_cannot_publish_a_consumer(monkeypatch):
    import z3
    from tdo_v2 import _record_expression_consumers as consumers
    record,view=_chain()
    monkeypatch.setattr(consumers._Budget,'query',lambda *args:z3.unknown)
    with pytest.raises(Ineligible,match='unproven'):
        derive_expression_consumer(record,select_expression(record),[view['id']])
    monkeypatch.undo()
    monkeypatch.setattr(consumers.time,'monotonic',iter((0,100)).__next__)
    with pytest.raises(Ineligible,match='budget'):
        derive_expression_consumer(record,select_expression(record),[view['id']])
