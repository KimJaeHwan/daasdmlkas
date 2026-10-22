"""Expression-layer conditions reuse raw SSA definitions and observed CFG.

These are not engine path proofs: unsupported shapes retain their original
alternatives. Concrete entry predicates select a side; an unknown entry
predicate retains the correlated union, not a Cartesian product.
"""

import copy as copying
import json

import pytest

from synthetic import (
    R8, R9, RAX, RBX, RCX, RDI, RDX, RSI, RSP, FunctionBuilder, add, const, copy,
    load, op, reg, store, tmp,
)
from test_operation_records import _analyzed, _record
from tdo_v2.operation_records import Ineligible, Limits, eligibility, evaluate, render


def _diamond(*, memory=False, before=False, predicate=None):
    flag, slot = tmp(0x300, 1), tmp(0x100)
    builder = FunctionBuilder().sub_rsp(0x40) if memory else FunctionBuilder()
    if before:
        builder.ins(copy(reg(RAX), const(1)), copy(reg(RBX), const(10)))
    if predicate is None:
        builder.cbranch('true', flag, op('INT_NOTEQUAL', [reg(R9 if memory else RDX), const(0)], flag))
    else:
        builder.cbranch('true', predicate)
    if not before:
        builder.ins(copy(reg(RAX), const(1)), copy(reg(RBX), const(10)))
    if memory:
        builder.ins(add(slot, reg(RSP), const(16)), store(slot, const(10)))
    builder.branch('merge').label('true')
    builder.ins(copy(reg(RAX), const(2)), copy(reg(RBX), const(20)))
    if memory:
        builder.ins(add(slot, reg(RSP), const(16)), store(slot, const(20)))
    builder.label('merge')
    if memory:
        builder.ins(add(slot, reg(RSP), const(16)), load(reg(RBX), slot))
    builder.ins(add(reg(R8), reg(RAX), reg(RBX)))
    return builder.add_rsp(0x40).ret() if memory else builder.ret()


def _entry(values):
    def entry(node):
        if type(node) is tuple:
            return None
        if 'register' not in node:
            return None
        offset, size = node['register']['offset'], node['register']['size']
        found = 0
        for byte in range(size):
            for base, value in values.items():
                if base <= offset + byte < base + 8:
                    if value is None:
                        return None
                    found |= ((value >> (8 * (offset + byte - base))) & 255) << (8 * byte)
                    break
        return found
    return entry


def _phis(record):
    return [node for node in record['nodes'] if 'condition' in node]


@pytest.mark.parametrize('route', ['injected', 'stitched'])
@pytest.mark.parametrize('memory', [False, True])
def test_known_and_unknown_guards_keep_one_choice_for_every_output(route, memory):
    record = _record(_analyzed(_diamond(memory=memory)), R8)
    phis = _phis(record)
    assert len(phis) >= 2
    assert len({node['condition']['selection'] for node in phis}) == 1
    assert all(node['choices'] == [True, False] for node in phis)
    assert all(node['condition_evaluation'] == 'supported' for node in phis)
    for node in phis:
        assert len(node['alternatives']) == 2
        assert all(part['definition_ref']['scope'] and part['definition_ref']['unit'] for part in node['alternatives'])
    predicate = R9 if memory else RDX
    assert evaluate(record, _entry({predicate: 0, RSP: 0x70000000}), route=route) == {11}
    assert evaluate(record, _entry({predicate: 123, RSP: 0x70000000}), route=route) == {22}
    assert evaluate(record, _entry({predicate: None, RSP: 0x70000000}), route=route) == {11, 22}
    text = render(record)
    assert 'T,F' in text and 'decision=' in text and 'shared=' in text


def test_a_value_before_the_branch_is_the_unchanged_alternative():
    record = _record(_analyzed(_diamond(before=True)), R8)
    assert len(_phis(record)) == 2
    assert evaluate(record, _entry({RDX: None})) == {11, 22}


def test_an_entry_definition_is_kept_only_on_the_nonwriting_arm():
    flag = tmp(0x300, 1)
    builder = (FunctionBuilder().cbranch('merge', flag, op('INT_EQUAL', [reg(RDX), const(0)], flag))
               .ins(copy(reg(RAX), const(7))).label('merge').ins(copy(reg(R8), reg(RAX))).ret())
    record = _record(_analyzed(builder), R8)
    assert len(_phis(record)) == 1
    assert evaluate(record, _entry({RDX: 0, RAX: 99})) == {99}
    assert evaluate(record, _entry({RDX: 1, RAX: 99})) == {7}
    assert evaluate(record, _entry({RDX: None, RAX: 99})) == {7, 99}


def test_a_later_straight_read_still_refers_to_the_original_merge():
    builder = _diamond()
    # Unrelated work after the merge must not turn the read block into the
    # branch's real merge identity.
    builder._rows.insert(-2, type(builder._rows[0])([copy(reg(R9), const(99))]))
    # Label indexes preceding the insertion are unchanged.
    record = _record(_analyzed(builder), R8)
    assert len(_phis(record)) == 2
    assert evaluate(record, _entry({RDX: None})) == {11, 22}


def test_overwriting_after_the_merge_does_not_keep_the_old_value_choice():
    builder = _diamond()
    builder._rows.insert(-2, type(builder._rows[0])([copy(reg(RAX), const(100))]))
    record = _record(_analyzed(builder), R8)
    assert len(_phis(record)) == 1
    assert evaluate(record, _entry({RDX: None})) == {110, 120}


def test_unknown_value_is_not_confused_with_unknown_guard():
    flag = tmp(0x300, 1)
    builder = (FunctionBuilder().cbranch('true', flag, op('INT_NOTEQUAL', [reg(RDX), const(0)], flag))
               .ins(copy(reg(RAX), reg(RDI))).branch('merge')
               .label('true').ins(copy(reg(RAX), const(7)))
               .label('merge').ins(copy(reg(R8), reg(RAX))).ret())
    record = _record(_analyzed(builder), R8)
    assert evaluate(record, _entry({RDX: 1, RDI: None})) == {7}
    with pytest.raises(Ineligible, match='unknown inputs'):
        evaluate(record, _entry({RDX: None, RDI: None}))


def test_condition_demand_restores_bytes_pruned_by_the_value_root():
    flag, wide = tmp(0x300, 1), tmp(0x400)
    builder = (FunctionBuilder().ins(op('PIECE', [reg(RDI, 4), reg(RCX, 4)], wide))
               .cbranch('true', flag, op('INT_NOTEQUAL', [wide, const(0)], flag))
               .ins(copy(reg(RAX), const(1))).branch('merge')
               .label('true').ins(copy(reg(RAX), const(2)))
               .label('merge').ins(op('SUBPIECE', [wide, const(0, 4)], reg(RBX, 4)),
                                   add(reg(R8), reg(RAX), reg(RBX))).ret())
    record = _record(_analyzed(builder), R8)
    (piece,) = [node for node in record['nodes'] if node.get('opcode') == 'PIECE']
    assert not any(item.get('pruned') for item in piece['operands'])
    assert evaluate(record, _entry({RDI: 1, RCX: 0, RBX: 0})) == {2}


def test_internal_relative_cbranch_is_a_condition_not_a_new_value_operator():
    from test_graph_fidelity import _cmov_fixed

    record = _record(_analyzed(FunctionBuilder().ins(*_cmov_fixed())
                               .ins(copy(reg(R8), reg(RAX))).ret()), R8)
    assert _phis(record)
    assert not any(node.get('opcode') == 'CBRANCH' for node in record['nodes'])
    assert eligibility(record) is None


def test_json_round_trip_and_shared_guard_mismatch_are_checked():
    record = json.loads(json.dumps(_record(_analyzed(_diamond()), R8)))
    assert evaluate(record, _entry({RDX: None})) == {11, 22}
    for field in ('decision', 'merge', 'true_successor', 'false_successor'):
        broken = copying.deepcopy(record)
        _phis(broken)[1]['condition'][field] += ':corrupt'
        with pytest.raises(Ineligible, match='choice mismatch'):
            evaluate(broken, _entry({RDX: None}))
    broken = copying.deepcopy(record)
    _phis(broken)[1]['condition']['operand']['parts'][0]['node'] = 999999
    with pytest.raises(Ineligible, match='condition reference'):
        evaluate(broken, _entry({RDX: None}))


def test_an_unsupported_guard_is_explicit_fallback_not_an_unknown_value():
    flag = tmp(0x300, 1)
    builder = (FunctionBuilder().cbranch('true', flag, op('FLOAT_EQUAL', [reg(RDX), reg(RCX)], flag))
               .ins(copy(reg(RAX), const(1))).branch('merge')
               .label('true').ins(copy(reg(RAX), const(2)))
               .label('merge').ins(copy(reg(R8), reg(RAX))).ret())
    record = _record(_analyzed(builder), R8)
    (phi,) = _phis(record)
    assert phi['condition_evaluation'] == 'fallback: unsupported FLOAT_EQUAL'
    assert evaluate(record, _entry({RDX: 0, RCX: 0})) == {1, 2}
    # The same predicate used AS VALUE must no longer be excluded, even if
    # a consumer received forged serialized predicate-only flags.
    broken = copying.deepcopy(record)
    floating = next(node for node in broken['nodes'] if node.get('opcode') == 'FLOAT_EQUAL')
    broken['root'] = [{'node': floating['id'], 'bytes': [0, 1], 'at': [0, 1]}]
    with pytest.raises(Ineligible, match='unsupported FLOAT_EQUAL'):
        evaluate(broken, _entry({RDX: 0, RCX: 0}))


@pytest.mark.parametrize('route', ['injected', 'stitched'])
def test_a_guard_only_load_never_defaults_to_its_first_memory_candidate(route):
    from tdo_v2.operation_records import _finish_conditions

    record = _record(_analyzed(_diamond()), R8)
    predicate = _phis(record)[0]['condition']['operand']['parts'][0]['node']
    zero = next(node['id'] for node in record['nodes'] if node.get('kind') == 'const' and node['value'] == 0)
    one = next(node['id'] for node in record['nodes'] if node.get('kind') == 'const' and node['value'] == 1)
    record['nodes'][predicate] = {
        'id': predicate, 'kind': 'op', 'opcode': 'LOAD', 'condition_only': True,
        'output': {'size': 1}, 'space': 1,
        'operands': [{'index': 1, 'width': 8, 'role': 'address',
                      'parts': [{'node': zero, 'bytes': [0, 8], 'at': [0, 8]}]}],
        'memory': [{'parts': [{'node': identifier, 'bytes': [0, 1], 'at': [0, 1]}]}
                   for identifier in (zero, one)],
    }
    _finish_conditions(record)
    assert all(node['condition_evaluation'] == 'fallback: ambiguous memory' for node in _phis(record))
    assert evaluate(record, _entry({}), route=route) == {11, 22}


def test_two_separate_diamonds_do_not_share_a_selection():
    flag = tmp(0x300, 1)
    builder = (FunctionBuilder().cbranch('a', flag, op('INT_NOTEQUAL', [reg(RDX), const(0)], flag))
               .ins(copy(reg(RAX), const(1))).branch('join_a')
               .label('a').ins(copy(reg(RAX), const(2))).label('join_a')
               .ins(copy(reg(RBX), reg(RAX)))
               .cbranch('b', flag, op('INT_NOTEQUAL', [reg(RCX), const(0)], flag))
               .ins(copy(reg(RAX), const(10))).branch('join_b')
               .label('b').ins(copy(reg(RAX), const(20))).label('join_b')
               .ins(add(reg(R8), reg(RAX), reg(RBX))).ret())
    record = _record(_analyzed(builder), R8)
    assert len({node['condition']['selection'] for node in _phis(record)}) == 2
    assert evaluate(record, _entry({RDX: None, RCX: None})) == {11, 12, 21, 22}


def test_two_calls_of_the_same_body_do_not_share_a_cfg_selection():
    from test_record_stitching import _record as stitched_record

    flag = tmp(0x300, 1)
    helper = (FunctionBuilder(entry=0x1800)
              .cbranch('true', flag, op('INT_NOTEQUAL', [reg(RCX), const(0)], flag))
              .ins(add(reg(RAX), reg(RCX), const(1))).branch('merge')
              .label('true').ins(add(reg(RAX), reg(RCX), const(2))).label('merge')
              .ins(copy(reg(RAX), reg(RAX))).ret())
    caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), reg(RDI))).call(0x1800)
              .ins(copy(reg(RBX), reg(RAX)), copy(reg(RCX), reg(RSI))).call(0x1800)
              .ins(add(reg(RAX), reg(RAX), reg(RBX))).add_rsp(0x28).ret())
    record = stitched_record([caller, helper])
    assert len({node['condition']['selection'] for node in _phis(record)}) == 2
    assert evaluate(record, _entry({RDI: 0, RSI: 1, RSP: 0x70000000}), route='stitched') == {4}
    assert evaluate(record, _entry({RDI: 1, RSI: 0, RSP: 0x70000000}), route='stitched') == {4}


def test_a_condition_limit_is_explicit_truncation_not_a_partial_success():
    from tdo_v2.operation_records import run_records

    analyzed = _analyzed(_diamond())
    records = run_records(analyzed.normalized, analyzed.unit, analyzed.summary, limits=Limits(nodes=5))
    assert any(record['truncated'] for record in records)
    assert all(eligibility(record) == 'truncated' for record in records if record['truncated'])
