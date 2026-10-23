"""Physical context construction refunds graph/control/export mutations."""

from synthetic import REG, R8, RAX, RCX, RDX, RIP, RSP, FunctionBuilder, add, const, copy, load, reg, store
from test_physical_call_records import _case, _record, _execute
from record_oracle import entry_reader, final_register
from tdo_v2 import _record_calls
from tdo_v2.operation_records import _StitchCut, eligibility, evaluate_physical, render


def test_later_failed_context_restores_prior_context_lazy_exports_and_caches(monkeypatch):
    first = (FunctionBuilder(entry=0x1800)
             .ins(store(reg(RDX), const(41)), load(reg(RAX), reg(RCX))).ret())
    second = FunctionBuilder(entry=0x1a00).ins(store(reg(RCX), reg(RAX))).ret()
    caller = (FunctionBuilder().sub_rsp(0x28)
              .ins(store(reg(RCX), const(7)), copy(reg(RDX), reg(RCX)))
              .call(0x1800).call(0x1a00).ins(copy(reg(R8), const(5))).add_rsp(0x28).ret())
    case = _case(caller, first, second)
    original = _record_calls._context
    saved = {}

    def fail_after_new_export(builder, base, identity):
        if base == '1:100c:2:CALL':
            previous, = builder.physical_calls.values()
            child, _, _ = builder.physical_call_builders[previous['id']]
            saved.update(builder=builder, context=previous, exports=list(previous['outputs']),
                         cache=dict(child.id_of), child=child)
            original(builder, base, identity)
            assert len(previous['outputs']) > len(saved['exports'])
            raise _StitchCut('test: reject later context after prior terminal export')
        return original(builder, base, identity)

    monkeypatch.setattr(_record_calls, '_context', fail_after_new_export)
    result = _record(case, '1:1010:0:COPY')
    assert not result['truncated']
    assert saved['context']['outputs'] == saved['exports']
    assert saved['child'].id_of == saved['cache']
    assert len(result['physical_calls']) == 1
    assert result['physical_call_cuts']['1:100c:2:CALL'].startswith('test: reject later context')
    assert all(node.get('physical_context') != '1:100c:2:CALL' for node in result['nodes'])
    assert all(part['node'] < len(result['nodes']) for context in result['physical_calls'].values()
               for output in context['outputs'] for part in (output['part'],))


def test_second_call_reads_the_first_calls_unknown_register_result_not_old_entry():
    first = (FunctionBuilder(entry=0x1800)
             .ins(store(reg(RDX), const(41)), load(reg(RAX), reg(RCX))).ret())
    second = (FunctionBuilder(entry=0x1a00)
              .ins(add(reg(RAX), reg(RAX), const(2)), store(reg(RCX), reg(RAX))).ret())
    caller = (FunctionBuilder().sub_rsp(0x28)
              .ins(store(reg(RCX), const(7)), copy(reg(RDX), reg(RCX)))
              .call(0x1800).call(0x1a00)
              .ins(load(reg(R8), reg(RCX)), add(reg(R8), reg(R8), const(5))).add_rsp(0x28).ret())
    case = _case(caller, first, second)
    plain = _record(case, '1:1010:1:INT_ADD', physical=False)
    result = _record(case, '1:1010:1:INT_ADD')
    assert eligibility(result) == eligibility(plain) == 'debt'
    vm = _execute(case, registers=((RAX, 0xdead),))
    assert final_register(vm, R8, 8) == 48
    # The VM schedules saved continuations; verify each actual RETURN too.
    for serial, (call, _) in vm.activation_snapshots.items():
        expected = 0x100c if call == '1:1008:2:CALL' else 0x1010
        state = vm.activation_returns[serial]
        def value(offset):
            return sum(state[(REG, offset + byte)] << (8 * byte) for byte in range(8))
        assert value(RIP) == expected and value(RSP) == 0x70000000 - 0x28
    found = evaluate_physical(result, entry_reader(vm))
    assert found.value == 48
    assert {event['call'] for event in found.evidence if event['kind'] == 'call'} == {
        '1:1008:2:CALL', '1:100c:2:CALL'}
    text = render(result)
    assert 'physical call 1:1008:2:CALL -> 1:1800' in text
    assert 'physical call 1:100c:2:CALL -> 1:1a00' in text
    assert 'requires RETURN/SP validation' in text and 'entry RAM =' in text
    assert 'body writes =' in text and ':RETURN if g' in text
