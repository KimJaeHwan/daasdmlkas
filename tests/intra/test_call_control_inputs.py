"""Original pre-call SSA bytes bind guard-only callee inputs, without an ABI.

The existing program interpreter executes the caller's assignments and both
callee arms. Unknown-input checks withhold entry bytes, never branch choices
or call results. Mutated SSA snapshots below test conservative absence and
the precedence of original staged reads; they are not executable fixtures.
"""

from dataclasses import replace
from unittest.mock import patch

import pytest

from pcode_interpreter import Interpreter
from record_oracle import entry_reader, final_register
from synthetic import (
    CONST, REG, R8, R9, RAX, RBX, RCX, RDX, RSP, FunctionBuilder, add, const, copy,
    op, program_units, reg, tmp,
)
from test_record_stitching import F, G, ROOT, _caller, _entry
from tdo_v2.interprocedural import analyze_units
from tdo_v2.operation_records import Ineligible, StitchContext, _Binding, evaluate, root_record


def _predicate(*, value_input=False):
    flag = tmp(0x300, 1)
    function = FunctionBuilder(entry=F).cbranch(
        'other', flag, op('INT_NOTEQUAL', [reg(R9), const(0)], flag))
    function.ins(add(reg(RAX), reg(R9), const(7)) if value_input else copy(reg(RAX), const(7))).ret()
    return (function.label('other')
            .ins(add(reg(RAX), reg(R9), const(9)) if value_input else copy(reg(RAX), const(9))).ret())


def _analyze(*functions):
    units, table = program_units(*functions), {}
    item = analyze_units(units, record_provenance=table)[ROOT]
    program = {(unit.scopes.function.entry.space_id, unit.scopes.function.entry.byte_offset): unit.observation
               for unit in units}
    return item, table, program


def _root(item, table):
    normalized = item.normalized
    run = next(run for exit_summary in item.summary.exits for run in exit_summary.runs
               if run.span.object_id.kind.value == 'register_file' and run.span.start == RAX)
    return root_record(normalized, item.unit,
                       [(normalized.memory_graph.definition_nodes[index], (run.span,)) for index in run.definitions],
                       declared=item.declared, provenance=table[id(item)][1], stitch=StitchContext(table))


def _execute(item, program, registers, seed=0):
    vm = Interpreter(item.unit.observation, constant_space=CONST, seed=seed, program=program)
    for offset, value in {RSP: 0x70000000, **registers}.items():
        vm.preset(REG, offset, 8, value)
    run = vm.run()
    assert run.completed and run.executed and not vm.opaque_opcodes
    return vm


def _unknown(registers, offset):
    known = _entry(registers)

    def entry(node):
        if isinstance(node, dict) and 'register' in node:
            span = node['register']
            if span['offset'] < offset + 8 and offset < span['offset'] + span['size']:
                return None
        return known(node)

    return entry


def _imported_decisions(record):
    assert not record['truncated']
    return [decision for decision in record['control']['decisions'].values() if 'import' in decision]


def _binding_snapshot(mode):
    original = _Binding.__init__

    def initialize(binding, *args, **kwargs):
        original(binding, *args, **kwargs)
        if binding.snapshot is not None:
            binding.snapshot = None if mode == 'missing' else replace(
                binding.snapshot, first_action_key=binding.snapshot.boundary_key + '~absent')

    return patch.object(_Binding, '__init__', initialize)


def test_guard_only_input_is_the_callers_write_not_its_entry_register():
    item, table, program = _analyze(_caller(copy(reg(R9), reg(RCX))), _predicate())
    record = _root(item, table)
    (decision,) = _imported_decisions(record)
    assert decision['evaluation'] == 'supported'
    assert any(node.get('key') == '1:1004:0:COPY' for node in record['nodes'])
    assert not any(node.get('boundary_entry') for node in record['nodes'])
    observed = set()
    for selector in (0, 1, 9, 0xffffffffffffffff):
        vm = _execute(item, program, {RCX: selector, R9: int(selector == 0)})
        actual = final_register(vm, RAX, 8)
        assert actual == (9 if selector else 7)
        assert evaluate(record, entry_reader(vm), route='stitched') == {actual}
        observed.add(actual)
    assert observed == {7, 9}
    assert evaluate(record, _unknown({RSP: 0x70000000, R9: 0}, RCX), route='stitched') == {7, 9}


def test_guard_only_wide_input_assembles_mixed_partial_register_definitions():
    calling = _caller(copy(reg(R9), const(0)), copy(reg(R9, 1), reg(RCX, 1)),
                      copy(reg(R9 + 1, 1), reg(RBX, 1)))
    item, table, program = _analyze(calling, _predicate())
    record = _root(item, table)
    assert all(decision['evaluation'] == 'supported' for decision in _imported_decisions(record))
    (snapshot,) = item.normalized.memory_ssa.call_register_snapshots
    fragments = [part for part in snapshot.fragments if R9 <= part.span.start < R9 + 8]
    assert [(part.span.start - R9, part.span.size) for part in fragments] == [(0, 1), (1, 1), (2, 6)]
    ssa = item.normalized.memory_ssa
    assert [ssa.definitions[part.definition_ids[0]].operation_key for part in fragments] == [
        '1:1004:1:COPY', '1:1004:2:COPY', '1:1004:0:COPY']
    for seed, (low, high) in enumerate(((0, 0), (1, 0), (0, 1), (0x100, 0x100), (0xff, 0xff))):
        vm = _execute(item, program, {RCX: low, RBX: high, R9: 0xffffffffffffffff}, seed)
        actual = final_register(vm, RAX, 8)
        assert actual == (9 if (low & 0xff) | ((high & 0xff) << 8) else 7)
        assert evaluate(record, entry_reader(vm), route='stitched') == {actual}


def test_conditional_caller_definitions_keep_their_original_pre_call_guards():
    flag = tmp(0x380, 1)
    calling = (FunctionBuilder().sub_rsp(0x28)
               .cbranch('other', flag, op('INT_NOTEQUAL', [reg(RCX), const(0)], flag))
               .ins(copy(reg(R9), const(0))).branch('done')
               .label('other').ins(copy(reg(R9), const(5)))
               .label('done').call(F).add_rsp(0x28).ret())
    item, table, program = _analyze(calling, _predicate())
    record = _root(item, table)
    assert all(decision['evaluation'] == 'supported' for decision in record['control']['decisions'].values())
    (snapshot,) = item.normalized.memory_ssa.call_register_snapshots
    (fragment,) = [part for part in snapshot.fragments if part.span.start == R9]
    assert len(fragment.definition_ids) == 2
    assert {item.normalized.memory_ssa.definitions[index].operation_key for index in fragment.definition_ids} == {
        '1:1008:0:COPY', '1:1010:0:COPY'}
    (phi,) = [node for node in record['nodes'] if node.get('reason') == 'several definitions']
    assert 'condition' in phi or 'guarded_sources' in phi
    assert {part['definition_ref']['id'] for part in phi['alternatives']} == set(fragment.definition_ids)
    assert all(part['definition_ref']['scope'] == item.normalized.memory_ssa.function_scope.digest.hex()
               for part in phi['alternatives'])
    for selector in (0, 1, 9):
        vm = _execute(item, program, {RCX: selector, R9: int(selector == 0)})
        actual = final_register(vm, RAX, 8)
        assert actual == (9 if selector else 7)
        assert evaluate(record, entry_reader(vm), route='stitched') == {actual}
    assert evaluate(record, _unknown({RSP: 0x70000000}, RCX), route='stitched') == {7, 9}


def test_two_calls_to_one_guard_only_callee_bind_different_actual_inputs():
    calling = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(R9), reg(RCX)))
               .call(F).ins(op('INT_MULT', [reg(RAX), const(10)], reg(RBX)), copy(reg(R9), reg(RDX)))
               .call(F).ins(add(reg(RAX), reg(RAX), reg(RBX))).add_rsp(0x28).ret())
    item, table, program = _analyze(calling, _predicate())
    record = _root(item, table)
    decisions = _imported_decisions(record)
    assert len(decisions) == 2 and {decision['decision'] for decision in decisions} == {'1:1800:1:CBRANCH'}
    assert len({decision['selection'] for decision in decisions}) == 2
    assert {decision['import'] for decision in decisions} == set(item.calls)
    assert all(decision['evaluation'] == 'supported' for decision in decisions)
    for seed, (first, second) in enumerate(((0, 1), (1, 0), (0, 0), (1, 1))):
        vm = _execute(item, program, {RCX: first, RDX: second, R9: 0xffffffffffffffff}, seed)
        actual = final_register(vm, RAX, 8)
        assert actual == (9 if first else 7) * 10 + (9 if second else 7)
        assert evaluate(record, entry_reader(vm), route='stitched') == {actual}


def test_untouched_guard_only_register_requires_an_explicit_preservation_proof():
    item, table, program = _analyze(_caller(), _predicate())
    record = _root(item, table)
    (decision,) = _imported_decisions(record)
    assert decision['evaluation'] == 'supported'
    (entry,) = [node for node in record['nodes'] if node.get('boundary_entry')]
    (snapshot,) = item.normalized.memory_ssa.call_register_snapshots
    assert entry['register']['offset'] == R9 and entry['register']['size'] == 8
    assert entry['boundary_entry']['call'] == snapshot.boundary_key
    assert entry['boundary_entry']['before'] == snapshot.first_action_key
    assert entry['boundary_entry']['scope'] == item.normalized.memory_ssa.function_scope.digest.hex()
    assert entry['boundary_entry']['unit'] == item.normalized.memory_ssa.unit_digest.hex()
    for selector in (0, 1):
        vm = _execute(item, program, {R9: selector})
        assert evaluate(record, entry_reader(vm), route='stitched') == {final_register(vm, RAX, 8)}


def test_an_intermediate_unknown_call_does_not_turn_absent_bytes_into_entry():
    calling = FunctionBuilder().sub_rsp(0x28).call(G).call(F).add_rsp(0x28).ret()
    item, table, _ = _analyze(calling, _predicate())
    record = _root(item, table)
    (decision,) = _imported_decisions(record)
    assert decision['evaluation'] == 'fallback: unbound predicate'
    assert not any(node.get('boundary_entry') for node in record['nodes'])
    assert any(node.get('gaps') == [{'at': [0, 8], 'reason': 'unbound register'}]
               for node in record['nodes'] if node.get('import'))
    for selector in (0, 1):
        assert evaluate(record, _entry({RSP: 0x70000000, R9: selector}), route='stitched') == {7, 9}


@pytest.mark.parametrize('snapshot_mode', ('missing', 'stale'))
def test_missing_call_boundary_snapshot_is_not_a_license_to_use_caller_entry(snapshot_mode):
    item, table, _ = _analyze(_caller(copy(reg(R9), reg(RCX))), _predicate())
    with _binding_snapshot(snapshot_mode):
        record = _root(item, table)
    (decision,) = _imported_decisions(record)
    assert decision['evaluation'] == 'fallback: unbound predicate'
    assert not any(node.get('boundary_entry') for node in record['nodes'])
    for selector in (0, 1):
        assert evaluate(record, _entry({RSP: 0x70000000, RCX: selector, R9: 1 - selector}),
                        route='stitched') == {7, 9}


@pytest.mark.parametrize('snapshot_mode', ('missing', 'stale'))
def test_original_staged_input_has_priority_over_snapshot_and_snapshot_absence(snapshot_mode):
    item, table, program = _analyze(_caller(copy(reg(R9), const(0)), copy(reg(R9), reg(RCX))),
                                   _predicate(value_input=True))
    with _binding_snapshot(snapshot_mode):
        record = _root(item, table)
    assert all(decision['evaluation'] == 'supported' for decision in _imported_decisions(record))
    for selector in (0, 1, 9):
        vm = _execute(item, program, {RCX: selector, R9: 0xffffffffffffffff})
        actual = final_register(vm, RAX, 8)
        assert actual == selector + (9 if selector else 7)
        assert evaluate(record, entry_reader(vm), route='stitched') == {actual}


@pytest.mark.parametrize('read_before_call', (False, True))
def test_tracked_register_definition_before_an_unknown_call_is_not_preserved(read_before_call):
    calling = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(R9), const(1)))
    if read_before_call:
        calling.ins(copy(reg(RBX), reg(R9)))
    calling.call(G).call(F).add_rsp(0x28).ret()
    item, table, _ = _analyze(calling, _predicate())
    ssa = item.normalized.memory_ssa
    final_call = next(call for call, target in item.calls.items() if target == '1:1800')
    (snapshot,) = [state for state in ssa.call_register_snapshots if state.boundary_key == final_call]
    (fragment,) = [part for part in snapshot.fragments if part.span.start == R9]
    assert {ssa.definitions[index].operation_key for index in fragment.definition_ids} == {'1:1004:0:COPY'}
    record = _root(item, table)
    (decision,) = _imported_decisions(record)
    assert decision['evaluation'] == 'fallback: unbound predicate'
    assert not any(node.get('boundary_entry') for node in record['nodes'])
    for selector in (0, 1):
        assert evaluate(record, _entry({RSP: 0x70000000, R9: selector}), route='stitched') == {7, 9}


@pytest.mark.parametrize('selector', (0, 1))
def test_a_real_redefinition_after_an_unknown_call_supplies_the_guard(selector):
    calling = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(R9), const(1 - selector)))
               .call(G).ins(copy(reg(R9), const(selector))).call(F).add_rsp(0x28).ret())
    item, table, _ = _analyze(calling, _predicate())
    ssa = item.normalized.memory_ssa
    final_call = next(call for call, target in item.calls.items() if target == '1:1800')
    (snapshot,) = [state for state in ssa.call_register_snapshots if state.boundary_key == final_call]
    (fragment,) = [part for part in snapshot.fragments if part.span.start == R9]
    assert {ssa.definitions[index].operation_key for index in fragment.definition_ids} == {'1:100c:0:COPY'}
    record = _root(item, table)
    (decision,) = _imported_decisions(record)
    assert decision['evaluation'] == 'supported'
    assert not any(node.get('boundary_entry') for node in record['nodes'])
    assert evaluate(record, _entry({RSP: 0x70000000, R9: 1 - selector}), route='stitched') == {
        9 if selector else 7}


def test_unexecuted_inner_callee_guard_is_lazy_and_does_not_spend_a_choice():
    outer, inner = tmp(0x300, 1), tmp(0x301, 1)
    called = (FunctionBuilder(entry=F)
              .cbranch('outer_true', outer, op('INT_NOTEQUAL', [reg(R8), const(0)], outer))
              .ins(copy(reg(RAX), const(7))).ret()
              .label('outer_true').cbranch('inner_true', inner,
                                          op('INT_NOTEQUAL', [reg(R9), const(0)], inner))
              .ins(copy(reg(RAX), const(9))).ret()
              .label('inner_true').ins(copy(reg(RAX), const(11))).ret())
    item, table, program = _analyze(_caller(copy(reg(R8), reg(RCX)), copy(reg(R9), reg(RDX))), called)
    record = _root(item, table)
    decisions = _imported_decisions(record)
    assert len(decisions) == 2 and all(decision['evaluation'] == 'supported' for decision in decisions)
    for outer_value, inner_value, expected in ((0, 123, 7), (1, 0, 9), (1, 1, 11)):
        vm = _execute(item, program, {RCX: outer_value, RDX: inner_value})
        assert final_register(vm, RAX, 8) == expected
        assert evaluate(record, entry_reader(vm), route='stitched') == {expected}

    demanded = []
    outer_value = 0

    def entry(node):
        if isinstance(node, dict) and 'register' in node:
            span = node['register']
            if span['offset'] < RDX + 8 and RDX < span['offset'] + span['size']:
                demanded.append('inner')
                return None
        return _entry({RSP: 0x70000000, RCX: outer_value})(node)

    assert evaluate(record, entry, route='stitched', max_choices=1) == {7}
    assert demanded == []
    outer_value = 1
    assert evaluate(record, entry, route='stitched', max_choices=2) == {9, 11}
    assert demanded


def test_shared_register_and_ram_selection_rejects_a_different_valid_guard_operand():
    from test_conditional_records import _diamond
    from test_operation_records import _analyzed, _record

    record = _record(_analyzed(_diamond(memory=True)), R8)
    phis = [node for node in record['nodes'] if 'condition' in node]
    assert len(phis) >= 2 and len({node['condition']['selection'] for node in phis}) == 1
    assert evaluate(record, _entry({RSP: 0x70000000, R9: 0})) == {11}
    assert evaluate(record, _entry({RSP: 0x70000000, R9: 1})) == {22}
    constant = next(node['id'] for node in record['nodes'] if node['kind'] == 'const' and node['value'] == 0)
    # Keep selection, shape, and reference validity intact: only one output's
    # predicate expression changes. Shared selection must not trust its label.
    phis[1]['condition']['operand']['parts'][0]['node'] = constant
    for route in ('injected', 'stitched'):
        with pytest.raises(Ineligible, match='choice mismatch'):
            evaluate(record, _entry({RSP: 0x70000000, R9: 1}), route=route)
