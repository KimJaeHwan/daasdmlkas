"""Original compiled instructions: carry/cancellation, narrow RAM, shared guards.

TDO_EXPRESSION_INFLUENCE_BUNDLE: expression_byte_influence.c, clang x64
Mach-O -O1 -fno-stack-protector -fno-optimize-sibling-calls -nostdlib
-dynamiclib -lSystem; Ghidra 12.0.4. Existing narrow/shared Bundles unchanged.
SAT models below are abstract boundary witnesses, NOT general entry feasibility.
"""

import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import pytest

from synthetic import RAX, RCX, RDI, RDX, RSI, RSP
from test_multi_target_memory_binary import _load, _value
from test_general_cycle_binary import MASK, _root
from test_indirect_physical_binary import _ObservedMemory
from test_transition_binary import _Visits
from test_expression_view_binary import expression_view_binary
from test_loop_summary_binary import loop_summary_binary
from tdo_v2.operation_records import select_expression, prove_byte_influence, attach_byte_influence, validate_byte_influence
from tdo_v2._record_expression_views import _build, _fingerprint


IMAGE_SHA='04ae572c6764719635514571378092d97bd67016fd88c93294063671e076b1e9'


@pytest.fixture(scope='module')
def influence_binary():
    with pytest.MonkeyPatch.context() as patch:
        case=_load('TDO_EXPRESSION_INFLUENCE_BUNDLE',patch,require_calls=False)
        generation=Path(os.environ['TDO_EXPRESSION_INFLUENCE_BUNDLE'])
        manifest=json.loads((generation/'manifest.json').read_text())
        original=next(row for row in manifest['members'] if row['id']==manifest['original_member_id'])
        assert original['sha256']==sha256((generation/original['path']).read_bytes()).hexdigest()==IMAGE_SHA
        yield case


def _pair(node,byte,name='root',out=0):
    return dict(input=dict(node=node,byte=byte),output=dict(name=name,byte=out))


def _prove(record,selection,pairs):
    before=copy.deepcopy(record)
    proof=prove_byte_influence(record,selection,pairs,accept_unattributed_assumptions=True)
    assert not proof['incomplete'] and proof['hypotheses']=='sat'
    attached=attach_byte_influence(record,json.loads(json.dumps(proof)),accept_unattributed_assumptions=True)
    assert record==before and {k:v for k,v in attached.items() if k!='expression_consumers'}==before
    assert _fingerprint(attached)==_fingerprint(record)
    return proof


def _original_register_run(case,item,record,bindings):
    vm=_ObservedMemory(item.unit.observation,constant_space=case['ids'][0],seed=0,
                       image=case['image'],address_bits=case['address_bits'])
    for name,value in bindings.items():
        node=record['nodes'][int(name[1:])]
        descriptor=node['register']
        vm.preset(descriptor['space'],descriptor['offset'],descriptor['size'],value)
    stack=_value(vm,case['ids'][1],RSP,8)
    vm.preset(item.unit.scopes.function.entry.space_id,stack,8,0x2000)
    raw=vm.run()
    assert raw.completed and not vm.opaque_opcodes
    return _value(vm,case['ids'][1],RAX,8)


@pytest.mark.parametrize('suffix',('add','cancel'))
def test_actual_integer_carries_and_original_mba_source_cancellation(influence_binary,suffix):
    case=influence_binary
    item=case['results'][case['names']['case_influence_'+suffix]]
    record=_root(item)
    entry=next(node for node in record['nodes'] if node['kind']=='entry' and
               node['register']['offset']<=RSI<node['register']['offset']+node['register']['size'])
    low=RSI-entry['register']['offset']
    if suffix=='add':
        pairs=[_pair(entry['id'],low, out=1),_pair(entry['id'],low+1),_pair(entry['id'],low,out=7)]
        expected=['may_influence','independent_when_both_defined','may_influence']
    else:
        assert {'INT_XOR','INT_AND','INT_MULT','INT_SUB'} <= {node.get('opcode') for node in record['nodes']}
        pairs=[_pair(entry['id'],low+i) for i in range(8)]+[_pair(entry['id'],RDI-entry['register']['offset'])]
        expected=['independent_when_both_defined']*8+['may_influence']
    proof=_prove(record,select_expression(record),pairs)
    assert [row['value'] for row in proof['results']]==expected
    # Replay each positive value witness directly on unmodified original p-code.
    for row in proof['results']:
        witness=row['witnesses'].get('value')
        if witness is None: continue
        for side in ('first','second'):
            result=_original_register_run(case,item,record,witness[side])
            assert (result>>(8*row['pair']['output']['byte']))&255==witness[side+'_observation']['byte_value']
    # Independent raw executions cover overflow and both source operands too.
    rng=random.Random(53)
    for x,y in [(0,0),(MASK,1),(255,1)]+[(rng.getrandbits(64),rng.getrandbits(64)) for _ in range(13)]:
        base=entry['register']['offset']
        number=(x<<(8*(RDI-base))) | (y<<(8*(RSI-base))) | (0x70000000<<(8*(RSP-base)))
        result=_original_register_run(case,item,record,{'n'+str(entry['id']):number})
        assert result==((x+y)&MASK if suffix=='add' else x)


def _body(record):
    visit,=record['cycle_graph']['transitions']
    assert visit['complete']
    body=next(row for row in visit['outcomes'] if row['kind']=='continue')
    outputs=[dict(name=str(i),width=int(row['span'][-1],16),parts=[row['part']],guard=body['guard'])
             for i,row in enumerate(body['updates'])]
    selection=select_expression(record,outputs,namespace=visit['id'])
    adapter,*_=_build(record,selection)
    return visit,body,selection,adapter


def _loop_run(case,item,record,initial,delta,count,selector=0):
    vm=_Visits(case,item,record)
    for offset,value in ((RSP,0x70000000),(RDI,initial),(RSI,delta),(RDX,count),(RCX,selector)):
        vm.preset(case['ids'][1],offset,8,value)
    vm.preset(item.unit.scopes.function.entry.space_id,0x70000000,8,0x2000)
    raw=vm.run()
    assert raw.completed and not vm.opaque_opcodes and vm.active is None
    assert len(vm.visits)==count+1 and vm.checked_load_bytes>0
    return vm


def test_existing_actual_narrow_memory_high_bytes_do_not_affect_byte_result(loop_summary_binary):
    case=loop_summary_binary
    item=case['results'][case['names']['case_summary_narrow']]
    record=_root(item)
    visit,body,selection,adapter=_body(record)
    # Full-width original step stack slot, not eight freshly invented inputs.
    step=next(row for row in visit['inputs'] if not row['mutable'] and row['span'][1]=='function_relative')
    binding=next(row for row in adapter.bindings.values() if row['transition_input']==step['id'])
    output=next(str(i) for i,row in enumerate(body['updates']) if int(row['span'][-1],16)==1)
    proof=_prove(record,selection,[_pair(binding['node'],i,output) for i in range(8)])
    assert [row['value'] for row in proof['results']]==['may_influence']+['independent_when_both_defined']*7
    assert all(row['address_effects']['effects']=='not_proven' for row in proof['results'])
    for initial in (0,255):
        for low in (1,128):
            for high in (0,0xff00000000000000):
                vm=_loop_run(case,item,record,initial,low|high,3)
                assert _value(vm,case['ids'][1],RAX,8)==(initial+3*low)&255
    assert record['loop_summaries'][0]['complete']


def test_existing_actual_shared_ram_preserves_reach_address_and_provenance_warnings(expression_view_binary):
    case=expression_view_binary
    item=case['results'][case['names']['case_view_shared']]
    record=_root(item)
    visit,body,selection,adapter=_body(record)
    counter_span=body['updates'][-1]['span']
    counter=next(row for row in visit['inputs'] if row['span']==counter_span)
    base=next(row for row in visit['inputs'] if row['span'][1]=='register_file')
    binding=lambda state:next(row['node'] for row in adapter.bindings.values() if row['transition_input']==state['id'])
    pairs=[_pair(binding(counter),0,name) for name in ('0','1')]
    pairs += [_pair(binding(base),0,name) for name in ('0','1')]
    proof=_prove(record,selection,pairs)
    for row in proof['results'][:2]:
        assert row['value']=='independent_when_both_defined' and row['R']=='may_change'
    for row in proof['results'][2:]:
        assert row['value']=='independent_when_both_defined'
        assert any(access['status']=='may_depend' for access in row['address_effects']['accesses'])
        assert row['address_effects']['concrete_memory_correspondence']=='not_claimed'
    for initial in (0,MASK):
        for delta in (1,0x1000000000000001):
            for count in (0,3):
                for selector in (0,1,256):
                    vm=_loop_run(case,item,record,initial,delta,count,selector)
                    step=delta if selector else delta^0x55
                    expected=((initial+count*step)&MASK)^((initial+3+count*step)&MASK)
                    assert _value(vm,case['ids'][1],RAX,8)==expected
    assert not record['loop_summaries'][0]['complete']
