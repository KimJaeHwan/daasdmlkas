"""P0 views actually consumed downstream and by an unchanged real loop.

TDO_EXPRESSION_CONSUMER_BUNDLE: expression_consumer_chain.c compiled clang
-target x86_64-apple-macos11 -O1 -fno-stack-protector
-fno-optimize-sibling-calls -nostdlib -dynamiclib -lSystem, Ghidra12.0.4 export.
The loop uses the EXISTING pinned P0 bundle, not an easier replacement.
"""

import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import pytest

from synthetic import RAX,RCX,RDI,RDX,RSI,RSP
from test_multi_target_memory_binary import _load,_value
from test_general_cycle_binary import MASK,_root
from test_expression_view_binary import expression_view_binary
from test_indirect_physical_binary import _ObservedMemory
from test_transition_binary import _Visits
from test_recurrence_register_binary import _raw_block_edges
from tdo_v2.operation_records import (select_expression,simplify_expression,attach_expression_view,
    derive_expression_consumer,derive_loop_consumer,attach_expression_consumer,evaluate_expression_consumer)
from tdo_v2.span_geometry import ByteSpan
from test_general_cycle_binary import _physical_place


IMAGE_SHA='9461f72b5475a9203303b3f00e1504f54bb5f4c6933cd50872e4fbc19b8c6d0a'


@pytest.fixture(scope='module')
def consumer_chain_binary():
    with pytest.MonkeyPatch.context() as patch:
        case=_load('TDO_EXPRESSION_CONSUMER_BUNDLE',patch,require_calls=False)
        generation=Path(os.environ['TDO_EXPRESSION_CONSUMER_BUNDLE'])
        manifest=json.loads((generation/'manifest.json').read_text())
        original=next(row for row in manifest['members'] if row['id']==manifest['original_member_id'])
        assert original['sha256']==sha256((generation/original['path']).read_bytes()).hexdigest()==IMAGE_SHA
        yield case


def test_actual_mba_island_is_consumed_by_later_xor_and_add(consumer_chain_binary):
    case=consumer_chain_binary
    item=case['results'][case['names']['case_consumer_chain']]
    record=_root(item)
    before=copy.deepcopy(record)
    producers=[node for node in record['nodes'] if node.get('opcode')=='INT_ADD'
               and {'INT_XOR','INT_MULT'} <= {record['nodes'][p['node']].get('opcode')
                   for operand in node['operands'] for p in operand.get('parts',()) if 'node' in p}]
    assert len(producers)==1
    port=dict(node=producers[0]['id'],bytes=[0,8],at=[0,8])
    selected=select_expression(record,[dict(name='middle',width=8,parts=[port])])
    view=simplify_expression(record,selected)
    record=attach_expression_view(record,view)
    consumer=derive_expression_consumer(record,select_expression(record),[view['id']])
    record=attach_expression_consumer(record,consumer)
    assert not any(row.get('op') in ('bvand','bvmul') for row in consumer['graph']['nodes'])
    rng=random.Random(48)
    pairs=[(0,0),(MASK,1),(0x1122334455667788,0xfedcba9876543210)]
    pairs += [(rng.getrandbits(64),rng.getrandbits(64)) for _ in range(29)]
    for x,y in pairs:
        vm=_ObservedMemory(item.unit.observation,constant_space=case['ids'][0],seed=0,
                           image=case['image'],address_bits=case['address_bits'])
        for offset,value in ((RSP,0x70000000),(RDI,x),(RSI,y)):
            vm.preset(case['ids'][1],offset,8,value)
        vm.preset(item.unit.scopes.function.entry.space_id,0x70000000,8,0x2000)
        inputs={row['id']:_value(vm,case['ids'][1],record['nodes'][row['node']]['register']['offset'],row['width'])
                for row in consumer['bindings']}
        result=evaluate_expression_consumer(record,consumer['id'],inputs,accept_unattributed_assumptions=True)
        observed=vm.run()
        assert observed.completed and not vm.opaque_opcodes
        assert result['outputs']['root']==_value(vm,case['ids'][1],RAX,8)==((((x+y)&MASK)^0x91)+9)&MASK
    assert {k:v for k,v in record.items() if k not in ('expression_views','expression_consumers')}==before


def _prepare_shared(case):
    item=case['results'][case['names']['case_view_shared']]
    record=_root(item)
    before=copy.deepcopy(record)
    assert not record['loop_summaries'][0]['complete']
    visit,=record['cycle_graph']['transitions']
    body=visit['outcomes'][0]
    outputs=[dict(name=str(i),width=int(row['span'][-1],16),parts=[row['part']],guard=body['guard'])
             for i,row in enumerate(body['updates'])]
    view=simplify_expression(record,select_expression(record,outputs,namespace=visit['id']))
    record=attach_expression_view(record,view)
    consumer=derive_loop_consumer(record,visit['id'],[view['id']])
    record=attach_expression_consumer(record,consumer)
    assert {k:v for k,v in record.items() if k not in ('expression_views','expression_consumers')}==before
    return item,record,consumer


class _ConsumerVisits(_Visits):
    def __init__(self,case,item,record,consumer):
        super().__init__(case,item,record)
        self.consumer,self.pending,self.invocations=consumer,None,[]
    def _snapshot(self):
        visit=super()._snapshot()
        if self.pending is None:
            result=evaluate_expression_consumer(self.record,self.consumer['id'],visit['inputs'],
                                                accept_unattributed_assumptions=True)
            self.pending=dict(result=result,first=len(self.visits),inputs=visit['inputs'])
        return visit
    def _finish(self,kind):
        super()._finish(kind)  # original raw guards/ALL effects/value/order/byte writer epochs
        if kind!='exit':
            return
        result=self.pending['result']
        assert len(self.visits)-self.pending['first']==result['iterations']+1
        assert len(result['updates'])==3
        for row in result['updates']:
            span=ByteSpan.from_canonical_key(tuple(row['span']))
            space,address,size=_physical_place(self.case,self.item,span,self)
            assert row['value']==_value(self,space,address,size)
        assert result['effect_template']['includes_terminal_zero_visit']
        assert not result['effect_template']['full_trace_materialized']
        self.invocations.append(self.pending)
        self.pending=None


def test_existing_shared_memory_loop_uses_verified_delta_for_full_result(expression_view_binary):
    case=expression_view_binary
    item,record,consumer=_prepare_shared(case)
    before=copy.deepcopy(record)
    runs=visits=bytes_checked=0
    for initial,delta in ((0,7),(MASK,1),(0x1122334455667788,0x1000000000000001)):
        for count in (0,1,3,7,19):
            for selector in (0,1,256):
                vm=_ConsumerVisits(case,item,record,consumer)
                for offset,value in ((RSP,0x70000000),(RDI,initial),(RSI,delta),(RDX,count),(RCX,selector)):
                    vm.preset(case['ids'][1],offset,8,value)
                vm.preset(item.unit.scopes.function.entry.space_id,0x70000000,8,0x2000)
                raw=vm.run()
                assert raw.completed and not vm.opaque_opcodes and vm.pending is vm.active is None
                result,=vm.invocations
                assert result['result']['iterations']==count
                step=delta if selector else delta^0x55
                expected=((initial+count*step)&MASK)^((initial+3+count*step)&MASK)
                assert _value(vm,case['ids'][1],RAX,8)==expected
                edges,_=_raw_block_edges(item,raw.executed)
                cfg=record['cycle_graph']['cfg']['edges']
                back=cfg[consumer['summary']['continue_edge']]
                exit=cfg[consumer['summary']['exit_edge']]
                assert edges[back['source'],back['target']]==count
                assert edges[exit['source'],exit['target']]==1
                runs+=1
                visits+=len(vm.visits)
                bytes_checked+=vm.checked_load_bytes
    assert (runs,visits)==(45,315) and bytes_checked>0
    assert record==before and not record['loop_summaries'][0]['complete']
