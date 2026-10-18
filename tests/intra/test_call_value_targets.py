"""Physical pointer copies across calls must retain target values, not ABIs."""

import pytest

from synthetic import (RAX, RCX, RDI, RDX, R9, RSP, FunctionBuilder, add, const,
                       copy, load, program_units, reg, store)
from tdo_v2.call_expressions import RecordProvider
from tdo_v2.interprocedural import analyze_units
from tdo_v2.operation_records import evaluate, run_records
from test_call_expressions import entry


@pytest.mark.parametrize('opaque_between', [False, True])
def test_registered_pointer_copy_resolves_only_without_intervening_clobber(opaque_between):
    register = FunctionBuilder(entry=0x1600).ins(store(const(0x4000), reg(RDI))).ret()
    target = FunctionBuilder(entry=0x1800).ins(add(reg(RAX), reg(RCX), const(10))).ret()
    caller = FunctionBuilder().ins(copy(reg(RDI), const(0x1800))).call(0x1600)
    if opaque_between:
        caller.call(0x1f00)
    caller.ins(load(reg(RDX), const(0x4000))).ins(copy(reg(RCX), const(32)))
    caller.call_indirect(RDX).ins(copy(reg(R9), reg(RAX))).ret()
    provider = RecordProvider()
    results = analyze_units(program_units(caller, register, target), record_provider=provider,
                            assume_globals_disjoint_from_stack=True)
    item = results['1:1000']
    indirect = {call: callee for call, callee in item.calls.items() if call.endswith(':CALLIND')}
    if opaque_between:
        assert not indirect
    else:
        assert set(indirect.values()) == {'1:1800'}
        record = next(r for r in run_records(item.normalized, item.unit, item.summary, provider=provider)
                      if r['place']['kind'] == 'register_file' and r['place']['start'] == R9)
        assert evaluate(record, entry({RSP: 0x70000000})) == {42}
        assert any(n['kind'] == 'op' and n['function'] == '1:1800' and n['opcode'] == 'INT_ADD'
                   for n in record['nodes'])


@pytest.mark.parametrize('readonly,overwrite,expected', [(False, False, None),
                                                       (True, False, '1:1800'), (True, True, '1:1900')])
def test_readonly_target_facts_reach_resolution_but_do_not_override_real_stores(readonly, overwrite, expected):
    class Image:
        def value(self, space, offset, size):
            return 0x1800 if (space, offset, size) == (1, 0x4000, 8) else None

    first = FunctionBuilder(entry=0x1800).ins(copy(reg(RAX), const(13))).ret()
    second = FunctionBuilder(entry=0x1900).ins(copy(reg(RAX), const(29))).ret()
    caller = FunctionBuilder()
    if overwrite:
        caller.ins(store(const(0x4000), const(0x1900)))
    caller.ins(load(reg(RDX), const(0x4000))).call_indirect(RDX).ins(copy(reg(R9), reg(RAX))).ret()
    results = analyze_units(program_units(caller, first, second), readonly_image=Image() if readonly else None,
                            assume_globals_disjoint_from_stack=True)
    indirect = {call: callee for call, callee in results['1:1000'].calls.items() if call.endswith(':CALLIND')}
    assert set(indirect.values()) == (set() if expected is None else {expected})
