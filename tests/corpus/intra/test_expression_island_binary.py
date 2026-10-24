"""Actual instructions, captured regional inputs, no fabricated CALL result.

clang -target x86_64-apple-macos11 -O1 -fno-stack-protector
-fno-optimize-sibling-calls -nostdlib -dynamiclib -lSystem; Ghidra 12.0.4.
Only the ENGINE is denied the source callee. The raw oracle executes its
unchanged sealed body. This deliberately tests partial-program analysis.
"""

import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import random
import pytest
import z3

from synthetic import RAX,RDI,RDX,RSI,RSP
from test_multi_target_memory_binary import _load,_value
from test_general_cycle_binary import MASK,_root
from test_indirect_physical_binary import _ObservedMemory
from tdo_v2.interprocedural import analyze_units
from tdo_v2.operation_records import (derive_expression_island,attach_expression_island,evaluate_expression_island,
    validate_expression_island,simplify_expression,eligibility)
from tdo_v2._record_expression_views import _fingerprint
from tdo_v2._record_expression_islands import _build_region


IMAGE_SHA='b4b827573fd073cd39d08b83488a4bcbd2ac823d35eae9a9565566edf4ba811e'
SOURCE_XOR=0x8e71b3d49526a0cf


@pytest.fixture(scope='module')
def island_binary():
    with pytest.MonkeyPatch.context() as patch:
        case=_load('TDO_EXPRESSION_ISLAND_BUNDLE',patch,require_calls=False)
        generation=Path(os.environ['TDO_EXPRESSION_ISLAND_BUNDLE'])
        manifest=json.loads((generation/'manifest.json').read_text())
        original=next(row for row in manifest['members'] if row['id']==manifest['original_member_id'])
        assert original['sha256']==sha256((generation/original['path']).read_bytes()).hexdigest()==IMAGE_SHA
        source=case['names']['island_unavailable_source']
        case['partial_results']=analyze_units([item.unit for key,item in case['results'].items() if key!=source])
        assert source not in case['partial_results']
        assert case['program'][tuple(int(part,16) for part in source.split(':'))] is not None
        yield case


def _ports(record):
    # Exact existing full-width COPYs of the compiler's inline-asm inputs.
    # They are shared ORIGINAL producers of both XOR and AND, not fresh args.
    result=[]
    for node in record['nodes']:
        if node.get('opcode')!='COPY' or node['output'].get('kind')!='register_file': continue
        if len(node['operands'])!=1 or len(node['operands'][0]['parts'])!=1: continue
        part,=node['operands'][0]['parts']
        source=record['nodes'][part['node']]
        if source['kind']=='entry' and 'register' in source:
            offset=source['register']['offset']+part['bytes'][0]
            if offset in (RDI,RSI,RAX) and part['bytes'][1]-part['bytes'][0]==8:
                result.append(node['id'])
        elif node.get('debts') and source.get('opcode')=='COPY':
            result.append(node['id'])  # Original post-call saved-register read.
    # An older save before CALL is not the boundary. Pick the pair nearest
    # the region's first original XOR/AND (or the only two COPYs for diamond).
    ands=[node for node in record['nodes'] if node.get('opcode')=='INT_AND']
    for node in ands:
        candidates={part['node'] for operand in node['operands'] for part in operand['parts']}
        shared=[key for key in result if key in candidates]
        if len(shared)==2:
            result=shared
            break
    assert len(result)==2 and len(set(result))==2
    return sorted(result)


class _CapturedRegion(_ObservedMemory):
    def __init__(self,case,item,record,island):
        self.ports={record['nodes'][row['node']]['key']:row for row in island['bindings'] if row.get('role')}
        self.captured={}
        super().__init__(item.unit.observation,constant_space=case['ids'][0],seed=0,program=case['program'],
                         image=case['image'],address_bits=case['address_bits'])

    def _execute(self,key,operation,run):
        result=super()._execute(key,operation,run)
        if key in self.ports:
            row=self.ports[key]
            assert operation.opcode=='COPY' and operation.output.byte_size==row['width']
            assert row['id'] not in self.captured, 'a static boundary was executed more than once'
            self.captured[row['id']]=_value(self,operation.output.coordinate.space_id,
                operation.output.coordinate.byte_offset,operation.output.byte_size)
        return result


def _run(case,item,record,island,x,y,selector=0):
    vm=_CapturedRegion(case,item,record,island)
    for offset,value in ((RSP,0x70000000),(RDI,x),(RSI,y),(RDX,selector)):
        vm.preset(case['ids'][1],offset,8,value)
    vm.preset(item.unit.scopes.function.entry.space_id,0x70000000,8,0x2000)
    values={row['id']:_value(vm,record['nodes'][row['node']]['register']['space'],
                            record['nodes'][row['node']]['register']['offset'],row['width'])
            for row in island['bindings'] if not row.get('role')}
    raw=vm.run()
    assert raw.completed and not vm.opaque_opcodes and vm._havoc is None and not vm._externals
    assert set(vm.captured)=={row['port'] for row in island['external_obligations']}
    values.update(vm.captured)
    validity={key:True for key in vm.captured}
    result=evaluate_expression_island(record,island,values,validity,accept_conditional_boundaries=True,
                                       accept_unattributed_assumptions=True)
    adapter,original,domain,_,_=_build_region(record,island['selection'])
    substitutions=[(symbol,z3.BitVecVal(values[key],symbol.size())) for key,symbol in adapter.symbols.items()]
    substitutions += [(flag,z3.BoolVal(True)) for flag in adapter.availability.values()]
    assert z3.is_true(z3.simplify(z3.substitute(domain,*substitutions)))
    assert z3.simplify(z3.substitute(original['root'],*substitutions)).as_long()==result['outputs']['root']
    assert result['outputs']['root']==_value(vm,case['ids'][1],RAX,8)
    return result,vm


@pytest.mark.parametrize('suffix',('pure','opaque'))
def test_actual_mba_region_reuses_ssa_and_keeps_unresolved_call_sources(island_binary,suffix):
    case=island_binary
    item=case['partial_results'][case['names']['case_island_'+suffix]]
    record=_root(item)
    before=copy.deepcopy(record)
    ports=_ports(record)
    island=derive_expression_island(record,boundaries=ports)
    assert island['proof']['status']=='equivalent_given_available_boundaries'
    assert island['connection']['status']==('unresolved' if suffix=='opaque' else 'linked_under_original_domain')
    assert not any(node.get('op') in ('bvand','bvmul') for node in island['graph']['nodes'])
    attached=attach_expression_island(record,json.loads(json.dumps(island)),accept_unattributed_assumptions=True)
    assert record==before and {k:v for k,v in attached.items() if k!='expression_consumers'}==before
    assert _fingerprint(attached)==_fingerprint(record) and eligibility(attached)==eligibility(record)
    if suffix=='opaque':
        assert eligibility(record)=='debt'
        assert island['selection']['boundary_provenance']['opaque_calls']
        assert all(row['debt_nodes'] for row in island['external_obligations'])
        assert simplify_expression(record)['proof']['status']=='partial'
    rng=random.Random(54)
    samples=[(0,0),(MASK,1),(255,1)]+[(rng.getrandbits(64),rng.getrandbits(64)) for _ in range(29)]
    for x,y in samples:
        result,vm=_run(case,item,attached,island,x,y)
        first=((x^SOURCE_XOR)+17)&MASK if suffix=='opaque' else x
        assert result['outputs']['root']==((first+y)&MASK)^0x91
        if suffix=='opaque':
            assert vm.activation_snapshots and vm.activation_returns, 'real callee CALL and RETURN must execute'
            assert result['connection']['status']=='unresolved' and result['original_debt']=='retained'
    assert record==before


def test_actual_shared_diamond_uses_one_original_choice_for_both_phis(island_binary):
    case=island_binary
    item=case['partial_results'][case['names']['case_island_shared']]
    record=_root(item)
    ports=_ports(record)
    phis=[node for node in record['nodes'] if node['kind']=='phi']
    assert len(phis)==2 and phis[0]['condition']==phis[1]['condition']
    before=copy.deepcopy(record)
    island=derive_expression_island(record,boundaries=ports)
    assert island['connection']['status']=='linked_under_original_domain'
    for x,y in ((0,0),(MASK,1),(0x1122334455667788,0xffeeddccbbaa9988),(255,256)):
        for selector in (0,1,256):
            result,vm=_run(case,item,record,island,x,y,selector)
            assert result['outputs']['root']==(x-y)&MASK
    assert record==before
