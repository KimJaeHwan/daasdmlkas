"""Real ARM64/x64 STORE8, STORE1, LOAD8 and two adjacent counterexamples.

Build sources/local_memory_fragments.c with clang -arch arm64 (or x86_64)
-O1 -ffreestanding -fno-stack-protector -dynamiclib, then use export_bundle.py
with _local_byte_patch, _local_conditional_patch, _local_unknown_patch.
Set TDO_LOCAL_MEMORY_FRAGMENTS_DATA to the arm64/x64 bundle parent directory.
Concrete checks execute the unchanged original p-code, not native programs.
"""

from hashlib import sha256
import os
from pathlib import Path

import pytest

from pcode_interpreter import Interpreter
from tdo_v2._memory_read_sources import read_source
from tdo_v2.configured_naming_contracts import NamingBindingExpectation
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.lane_slice import lane_slice
from tdo_v2.normalize import FunctionNormalizer


REPO = Path(__file__).resolve().parents[3]
PINS = {
    'arm64': ('d9fee1448f63f04ad6c52653d8c983b4aefd73b9579942c2f5cf6d3de2a47246',
              'aa1bc6d8f48c68ca3089a2bdf50131fd067fc8e7a72bcf79f57871c53a2c2375',
              ('1fbe9f0136a8b52081093a9958764f4380654f459dc2a2f80716dce8caa559cb',
               '4a47f7e51feb89b517b77162297d8aa7b2bc812f3c41938824a706b465092d54',
               'ea6eb21c3116d5214faa3abae1407ec121147236b2d8bcacd2c4db959364ff1e')),
    'x64': ('067eb561a539151ddbc9df0527b104b28ade26fd221bc6f35635db755e1066b6',
            '572dd4579e61957fcebc13f91c34fd4b317eaf68922b931c741bb99f93fd451d',
            ('52eeebc7762b0a64793d7d53a00e4d442332812d14686735921464c6b15e1328',
             '4e1587dc1e2147e0e41a3f500dc4e9eee4afea7015d14e8732735908fbc52a51',
             'a01b3317474d4060da803331802f0ed96995287f414cc126849b1f36c58638c9')),
}


@pytest.fixture(scope='module', params=('arm64','x64'))
def actual(request):
    root = os.environ.get('TDO_LOCAL_MEMORY_FRAGMENTS_DATA')
    if not root:
        pytest.skip('set TDO_LOCAL_MEMORY_FRAGMENTS_DATA to the original compiled fixture Bundles')
    arch = request.param
    gen, image, observations = PINS[arch]
    producer = sha256((REPO/'ghidra/GhidraV2CallNaming.java').read_bytes().replace(b'\r\n',b'\n')).digest()
    with open_observed_function_session(admit_frozen_bundle(Path(root)/arch/'bundles'/gen),
            naming_binding=NamingBindingExpectation(producer,'12.0.4')) as session:
        units = tuple(row.unit for row in session.iter_functions())
    assert len(units)==3
    assert tuple(u.scopes.function.observation_digest.hex() for u in units)==observations
    assert all(u.scopes.program.evidence.executable_sha256.hex()==image for u in units)
    assert sha256((REPO/'tests/corpus/sources/local_memory_fragments.c').read_bytes()).hexdigest() == \
        'b492c9554176b0cb0bddeaf018b07166fd6c8efbcdbdb1d646821d6ea64ebea7'
    return arch,units


@pytest.mark.parametrize('engine',('sparse','dense'))
@pytest.mark.parametrize('kind',(0,1,2))
def test_original_partial_writes_preserve_exact_bytes_or_keep_conditional_alias_alternatives(actual,monkeypatch,engine,kind):
    arch,units=actual
    unit=units[kind]
    monkeypatch.setenv('TDO_V2_MEMORY_SSA_ENGINE',engine)
    monkeypatch.setenv('TDO_V2_DATAFLOW_ENGINE',engine)
    n=FunctionNormalizer().normalize(unit)
    raw=[(f'{ins.address.space_id:x}:{ins.address.byte_offset:x}:{j}:{op.opcode}',op)
         for ins in unit.observation.instructions for j,op in enumerate(ins.operations)]
    writer,= [k for k,op in raw if op.opcode=='STORE' and op.inputs[2].byte_size==8][-1:]
    patch,= [k for k,op in raw if op.opcode=='STORE' and op.inputs[2].byte_size==1]
    reader,read=next((k,op) for k,op in raw if op.opcode=='LOAD' and op.output.byte_size==8)
    local=n.memory_graph.local_reads
    row=next((r for r in local.plan.reads if r.reader==reader),None) if local else None
    if kind==0:
        assert row is not None and row.complete
        assert [(p.output_offset,p.width,p.writer) for p in row.parts]==[(0,3,writer),(3,1,patch),(4,4,writer)]
        assert read_source(n,reader).local==row
    elif kind==1:
        assert row is not None and not row.complete
        assert [(p.output_offset,p.width) for p in row.parts]==[(0,3),(4,4)]
        assert read_source(n,reader) is None
    else:
        assert row is None and read_source(n,reader) is None
        seeds=[(n.memory_graph.definition_nodes[i],(d.span,)) for i,d in enumerate(n.memory_ssa.definitions)
               if d.operation_key==reader]
        lane=lane_slice(n,unit,seeds)
        debts={node for r,node in zip(n.may_alias_reads,n.may_alias_nodes) if r.operation_key==reader}
        assert debts and debts<=lane.nodes
    spaces=unit.scopes.program.evidence.address_spaces
    constant=next(s.space_id for s in spaces if s.is_constant_space)
    register=next(s.space_id for s in spaces if s.is_register_space)
    memory=read.inputs[0].coordinate.byte_offset
    base,value,byte=0x50000000,0x0123456789abcdef,0xa5
    for flag in (0,1):
        vm=Interpreter(unit.observation,constant_space=constant,seed=0)
        if arch=='arm64':
            values={0x4000:base,0x4008:value,0x4010:base+3 if kind==2 else byte,
                    0x4018:byte if kind==2 else flag,0x40f0:0}
        else:
            values={32:0x70000000,56:base,48:value,16:base+3 if kind==2 else byte,
                    8:byte if kind==2 else flag}
        for offset,bits in values.items():
            vm.preset(register,offset,8,bits)
        run=vm.run()
        assert run.completed and not vm.opaque_opcodes
        observed={(d.offset,d.writer) for d in run.dependencies if d.reader==reader and d.space_id==memory}
        patched=kind!=1 or flag!=0
        expected={(base+i,patch if patched and i==3 else writer) for i in range(8)}
        assert observed==expected
        result = (value & ~(255 << 24)) | (byte << 24) if patched else value
        output = read.output.coordinate
        assert sum(vm.final_bytes()[output.space_id,output.byte_offset+i][0] << (8*i)
                   for i in range(8)) == result
        if row is not None:
            proven={(base+p.output_offset+i,p.writer or row.writer) for p in row.parts for i in range(p.width)}
            assert proven<=observed
