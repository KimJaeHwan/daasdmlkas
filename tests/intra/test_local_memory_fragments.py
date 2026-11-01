"""Original byte writers compose; partial evidence cannot clear LOAD debts."""

import pytest

from synthetic import (CONST, RAM, REG, RAX, RBX, RCX, RDI, RDX, RSI, RSP,
                       DATA_BASE, FunctionBuilder, add, const, copy, load, op, program_units, reg, store, tmp)
from pcode_interpreter import Interpreter
from tdo_v2._memory_read_sources import read_source
from tdo_v2.forward import _analyze
from tdo_v2.lane_slice import lane_slice
from tdo_v2.normalize import FunctionNormalizer
from tdo_v2.operation_records import root_record


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def engine(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)


def _case(kind="patch", *, base=0x50000000):
    b, keys = FunctionBuilder(), {}
    address, patch = tmp(0x9100), tmp(0x9110)

    def ins(name, *ops):
        keys[name] = f"1:{b.entry + len(b._rows)*b.stride:x}:{len(ops)-1}:{ops[-1][0]}"
        b.ins(*ops)

    ins("address", add(address, reg(RDI), const(16)))
    old_width = 4 if kind == "halves" else 8
    ins("old", store(address, const(0x0123456789abcdef % (1 << (8 * old_width)), old_width)))
    if kind == "unknown":
        ins("other", store(reg(RSI), const(0xaa)))
    if kind == "conditional":
        b.cbranch("read", reg(RCX, 1))
    shift, width = (4, 4) if kind == "halves" else (3, 1)
    if kind == "outside":
        shift, width = 20, 4
    ins("patch", add(patch, address, const(shift)), store(patch, const(0x765432aa % (1 << (8 * width)), width)))
    b.label("read")
    ins("read", load(reg(RAX), address))
    b.ret()
    unit, = program_units(b)
    normalized = FunctionNormalizer().normalize(unit)
    return normalized, unit, keys, base


def _row(n, key):
    rows = n.memory_graph.local_reads
    return next((row for row in rows.plan.reads if row.reader == key), None) if rows else None


def _seeds(n, reader):
    return [(n.memory_graph.definition_nodes[i], (d.span,))
            for i, d in enumerate(n.memory_ssa.definitions) if d.operation_key == reader]


@pytest.mark.parametrize("kind", ("patch", "halves", "outside"))
@pytest.mark.parametrize("base", (0x50000000, (1 << 64) - 20))
def test_complete_multiple_store_parts_match_actual_original_byte_writers(kind, base):
    n, unit, keys, base = _case(kind, base=base)
    row = _row(n, keys["read"])
    assert row is not None and row.complete
    assert sum(p.width for p in row.parts) == 8
    view = read_source(n, keys["read"])
    assert view is not None and view.local == row
    vm = Interpreter(unit.observation, constant_space=CONST, seed=0)
    for register, value in ((RSP,0x70000000),(RDI,base),(RSI,base+16),(RCX,0)):
        vm.preset(REG,register,8,value)
    run = vm.run()
    assert run.completed and not vm.opaque_opcodes
    expected = {(d.offset,d.writer) for d in run.dependencies if d.reader == keys["read"] and d.space_id == RAM}
    actual = {((base+16+p.output_offset+i)%(1<<64),p.writer or row.writer)
              for p in row.parts for i in range(p.width)}
    assert actual == expected
    value = sum(((p.constant[1]>>(8*(p.value_offset+i)))&255) << (8*(p.output_offset+i))
                for p in row.parts for i in range(p.width))
    assert sum(vm.final_bytes()[REG,RAX+i][0]<<(8*i) for i in range(8)) == value
    # A later exact STORE can consume the complete assembled numeric value.
    analysis = _analyze(n, unit)
    assert analysis is not None
    graph, binding = n.dependencies, n.memory_graph.local_reads
    start = sum(len(r.parts) for r in binding.plan.reads[:binding.plan.reads.index(row)])
    for i,p in enumerate(row.parts,start):
        node = binding.effect_nodes[i]
        assert any(source == graph.node_for_key('op:'+(p.writer or row.writer))
                   and edge.kind == 'local_read_from_witness' for source,_,edge in graph.in_edges(node))
    record = root_record(n,unit,_seeds(n,keys['read']))
    loaded = next(r for r in record['nodes'] if r.get('key')==keys['read'] and not r.get('cycle_only'))
    assert sum(p['at'][1]-p['at'][0] for p in loaded['memory'][0]['parts']) == 8
    assert not loaded.get('debts')


@pytest.mark.parametrize("kind,coverage", (("conditional",7),("unknown",1)))
def test_partial_meet_and_unknown_writes_keep_raw_reads_and_all_load_debts(kind,coverage):
    n,unit,keys,_ = _case(kind)
    row = _row(n,keys['read'])
    assert row is not None and not row.complete
    assert sum(p.width for p in row.parts)==coverage
    assert read_source(n,keys['read']) is None
    if kind=='conditional':
        assert all(p.writer==keys['old'] for p in row.parts)
        assert not any(p.output_offset <= 3 < p.output_offset+p.width for p in row.parts)
    else:
        assert all(p.writer==keys['patch'] for p in row.parts)
    lane=lane_slice(n,unit,_seeds(n,keys['read']))
    debts={node for claim,node in zip(n.may_alias_reads,n.may_alias_nodes)
           if claim.operation_key==keys['read']}
    assert debts <= lane.nodes
    if kind == 'unknown':
        assert debts
    else:
        assert any(n.memory_graph.definition_nodes[j.join_definition_id] in lane.nodes for j in n.memory_ssa.joins)
    assert n.dependencies.node_for_key('op:'+keys['old']) in lane.nodes


def test_joined_store_operand_keeps_original_ssa_choice_not_one_branch():
    b=FunctionBuilder()
    b.cbranch('right',reg(RCX,1)).ins(copy(reg(RBX),reg(RDX))).branch('join')
    b.label('right').ins(copy(reg(RBX),reg(RSI))).label('join')
    b.ins(store(reg(RDI),reg(RBX)))
    patch=f'1:{b.entry+len(b._rows)*b.stride:x}:1:STORE'
    b.ins(add(tmp(0x9100),reg(RDI),const(3)),store(tmp(0x9100),const(0xaa,1)))
    reader=f'1:{b.entry+len(b._rows)*b.stride:x}:0:LOAD'
    b.ins(load(reg(RAX),reg(RDI))).ret()
    unit,=program_units(b)
    n=FunctionNormalizer().normalize(unit)
    row=_row(n,reader)
    assert row is not None and row.complete
    joined=[p for p in row.parts if p.writer != patch]
    assert joined and all(n.memory_ssa.definitions[p.source_definition_id].kind.value=='join' for p in joined)
    assert {p.output_offset for p in joined}=={0,4}


def test_later_call_tainted_fragment_survives_early_nonconstant_fragment_and_masking():
    b=FunctionBuilder()
    low,high,address=tmp(0x9200,4),tmp(0x9210,4),tmp(0x9220)
    b.call(0x1f00)
    # The integer-only forward domain leaves this real scalar opcode TOP,
    # independently of the later source's CALL debt.
    b.ins(op('FLOAT_ADD',[const(0x3f800000,4),const(0x3f800000,4)],low))
    b.ins(copy(high,reg(RDX,4)),copy(reg(RDI),const(DATA_BASE+0x300)))
    b.ins(store(const(DATA_BASE+0x400),const(0x520000)))
    b.ins(store(reg(RDI),low))
    b.ins(add(address,reg(RDI),const(4)),store(address,high))
    reader=f'1:{b.entry+len(b._rows)*b.stride:x}:0:LOAD'
    b.ins(load(reg(RAX),reg(RDI)))
    b.ins(op('INT_AND',[reg(RAX),const(0)],reg(RAX)),
          add(reg(RAX),reg(RAX),const(DATA_BASE+0x400)))
    b.ins(load(reg(RSI),reg(RAX)))
    use=f'1:{b.entry+len(b._rows)*b.stride:x}:0:LOAD'
    b.ins(load(reg(RCX),reg(RSI))).ret()
    unit,=program_units(b)
    n=FunctionNormalizer().normalize(unit)
    row=_row(n,reader)
    assert row is not None and row.complete and len(row.parts)==2
    assert n.memory_ssa.definitions[row.parts[1].source_definition_id].operation_key.endswith(':0:COPY')
    assert any(r.operation_key==n.memory_ssa.definitions[row.parts[1].source_definition_id].operation_key
               for r in n.call_clobber_reads)
    facts=_analyze(n,unit).facts
    assert not any(f.operation==use for f in facts)


@pytest.mark.parametrize('barrier',('call','excluded','cycle','actions','blocks'))
def test_fallback_barriers_and_caps_never_restore_the_old_wide_writer(barrier):
    from tdo_v2._memory_read_sources import derive_local_read_sources

    b,keys=FunctionBuilder(),{}
    keys['old']=f'1:{b.entry:x}:0:STORE'
    b.ins(store(const(DATA_BASE+0x300),const(0x0123456789abcdef)))
    excluded=frozenset()
    if barrier=='call':
        b.call(0x1f00)
    elif barrier=='excluded':
        key=f'1:{b.entry+len(b._rows)*b.stride:x}:0:COPY'
        b.ins(copy(tmp(0x9400),const(1)))
        excluded=frozenset({key})
    elif barrier=='cycle':
        b.label('spin').ins(copy(tmp(0x9400),const(1))).cbranch('spin',reg(RCX,1))
    elif barrier=='actions':
        b.ins(*(copy(tmp(0x9400),const(i)) for i in range(1025)))
    else:
        for i in range(130):
            b.branch(f'next{i}').label(f'next{i}')
    patch=f'1:{b.entry+len(b._rows)*b.stride:x}:0:STORE'
    b.ins(store(const(DATA_BASE+0x303),const(0xaa,1)))
    reader=f'1:{b.entry+len(b._rows)*b.stride:x}:0:LOAD'
    b.ins(load(reg(RAX),const(DATA_BASE+0x300))).ret()
    unit,=program_units(b)
    n=FunctionNormalizer().normalize(unit)
    if excluded:
        plan=derive_local_read_sources(n.memory_unit,n.memory_ssa,unit.observation,unit.scopes.function.entry,
             unit.scopes.resolution_context,unit.scopes.program.evidence.address_spaces,
             unit.scopes.program.evidence.translation_namespace,n.call_clobber_reads,excluded)
        rows=() if plan is None else [r for r in plan.reads if r.reader==reader]
    else:
        row=_row(n,reader)
        rows=() if row is None else (row,)
        assert read_source(n,reader) is None
    assert not any(row.complete for row in rows)
    assert all(p.writer==patch for row in rows for p in row.parts)


def test_no_match_readers_have_a_function_wide_bounded_fallback_cost(monkeypatch):
    from tdo_v2 import _local_memory_fragments

    calls=[]
    original=_local_memory_fragments.derive_fragments
    def counted(*args,**kw):
        calls.append(1)
        return original(*args,**kw)
    monkeypatch.setattr(_local_memory_fragments,'derive_fragments',counted)
    b=FunctionBuilder()
    for i in range(20):
        b.ins(add(tmp(0x9500),reg(RDI),const(i*8)),store(tmp(0x9500),const(i)))
    for i in range(80):
        b.ins(add(tmp(0x9500),reg(RSI),const(i*8)),load(reg(RAX),tmp(0x9500)))
    b.ret()
    unit,=program_units(b)
    n=FunctionNormalizer().normalize(unit)
    assert len(calls)==16
    assert n.memory_graph.local_reads is None


def test_repeated_partial_writes_do_not_spend_the_no_match_allowance():
    b=FunctionBuilder()
    readers=[]
    for i in range(20):
        b.ins(add(tmp(0x9500),reg(RDI),const(i*16)),store(tmp(0x9500),const(i)))
        b.ins(add(tmp(0x9510),tmp(0x9500),const(3)),store(tmp(0x9510),const(7,1)))
        readers.append(f'1:{b.entry+len(b._rows)*b.stride:x}:0:LOAD')
        b.ins(load(reg(RAX),tmp(0x9500)))
    b.ret()
    unit,=program_units(b)
    n=FunctionNormalizer().normalize(unit)
    assert all(read_source(n,key) is not None for key in readers)
