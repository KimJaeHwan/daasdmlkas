"""One physical indirect call chooses one target/exit for every output."""

import copy as copying

import pytest

from record_oracle import check_stitched
from synthetic import (
    RAX, RBX, RCX, RDX, R8, R9, RSP, FunctionBuilder, add, const, copy,
    load, op, program_units, reg, store, tmp,
)
from tdo_v2.interprocedural import analyze_units
from tdo_v2.operation_records import Ineligible, Limits, StitchContext, evaluate, root_record

ROOT, A, B = '1:1000', 0x1800, 0x1900


def caller(*, memory=True):
    slot, index = tmp(0x100), tmp(0x180)
    result = (FunctionBuilder().sub_rsp(0x60)
              .ins(add(reg(RDX), reg(RSP), const(0x10)), store(reg(RDX), const(99)))
              .ins(add(slot, reg(RSP), const(0x30)), store(slot, const(A)))
              .ins(add(slot, reg(RSP), const(0x38)), store(slot, const(B)))
              .ins(op('INT_AND', [reg(R9), const(1)], index),
                   op('INT_MULT', [index, const(8)], index),
                   add(index, index, reg(RSP)), add(index, index, const(0x30)),
                   load(reg(RAX), index), copy(reg(RCX), const(7)))
              .call_indirect(RAX))
    if memory:
        result.ins(load(reg(R8), reg(RDX)), add(reg(RAX), reg(RAX), reg(R8)))
    return result.add_rsp(0x60).ret()


def target(address, increment, returned):
    value = tmp(0x200)
    return (FunctionBuilder(entry=address).ins(add(value, reg(RCX), const(increment)),
                                              store(reg(RDX), value), copy(reg(RAX), const(returned))).ret())


def record(monkeypatch, *functions, limits=None, stitch=True):
    monkeypatch.setenv('TDO_V2_FORWARD', '1')
    units, provenance = program_units(*functions), {}
    results = analyze_units(units, record_provenance=provenance)
    item = results[ROOT]
    exit_summary, run = next((exit_summary, run) for exit_summary in item.summary.exits
                             for run in exit_summary.runs if run.span.object_id.kind.value == 'register_file'
                             and run.span.start == RAX)
    seeds = [(item.normalized.memory_graph.definition_nodes[index], (run.span,)) for index in run.definitions]
    found = root_record(item.normalized, item.unit, seeds, limits=limits,
                        provenance=provenance[id(item)][1], stitch=StitchContext(provenance) if stitch else None)
    program = {(unit.scopes.function.entry.space_id, unit.scopes.function.entry.byte_offset): unit.observation
               for unit in units}
    return item, found, program, exit_summary.block_key


def entry(node):
    if type(node) is tuple:
        return 0
    if 'register' in node:
        offset, size = node['register']['offset'], node['register']['size']
        return sum(((0x70000000 >> (8 * (offset + index - RSP))) & 255) << (8 * index)
                   for index in range(size) if RSP <= offset + index < RSP + 8)
    return 0


def test_two_targets_stitch_their_real_arithmetic(monkeypatch):
    item, found, _, _ = record(monkeypatch, caller(memory=False), target(A, 1, 10), target(B, 2, 20))
    assert item.multi_calls
    assert evaluate(found, entry, route='stitched') == {10, 20}
    imported = {node.get('key') for node in found['nodes'] if node.get('import') and node['kind'] == 'op'}
    assert any(key.startswith('1:1800:') for key in imported if key)
    assert any(key.startswith('1:1900:') for key in imported if key)


def test_register_and_ram_share_one_target_choice(monkeypatch):
    item, found, program, exit_key = record(monkeypatch, caller(), target(A, 1, 10), target(B, 2, 20))
    effect = next(effect for call, effect in item.proven.items() if call.endswith(':CALLIND'))
    assert effect.memory_runs and not effect.unknown_memory
    # A gives 10 + 8, B gives 20 + 9. Cross-target 19/28 are not executions.
    assert evaluate(found, entry, route='stitched') == {18, 29}
    report = check_stitched(item, program, found, register=RAX, exit_key=exit_key, seeds=range(8),
                            register_pools=lambda seed: {RSP: 0x70000000, R9: seed & 1})
    assert report.runs == report.evaluated == report.through_stitched == 8
    assert not report.failures and not report.skipped
    stores = [node for node in found['nodes'] if node.get('import') and node.get('opcode') == 'STORE']
    assert len(stores) >= 2


def test_different_exit_counts_still_share_one_legal_pair(monkeypatch):
    flag = tmp(0x300, 1)
    a = (FunctionBuilder(entry=A).cbranch('other', flag, op('INT_NOTEQUAL', [reg(R8), const(0)], flag))
         .ins(store(reg(RDX), const(8)), copy(reg(RAX), const(10))).ret()
         .label('other').ins(store(reg(RDX), const(9)), copy(reg(RAX), const(20))).ret())
    b = FunctionBuilder(entry=B).ins(store(reg(RDX), const(10)), copy(reg(RAX), const(30))).ret()
    _, found, _, _ = record(monkeypatch, caller(), a, b)
    assert evaluate(found, entry, route='stitched') == {18, 29, 40}


def test_a_target_that_keeps_memory_uses_the_callers_actual_old_value(monkeypatch):
    b = FunctionBuilder(entry=B).ins(copy(reg(RAX), const(20))).ret()
    _, found, _, _ = record(monkeypatch, caller(), target(A, 1, 10), b)
    assert evaluate(found, entry, route='stitched') == {18, 119}
    kept = [node for node in found['nodes'] if node.get('unchanged') and node.get('function') == '1:1900']
    assert any(node.get('callee_entry', '').startswith('unchanged: ') for node in kept)


def test_single_target_memory_keeps_its_original_entry_span_label():
    from test_record_stitching import _caller, _record

    called = FunctionBuilder(entry=A).ins(load(reg(RAX), reg(RCX))).ret()
    found = _record([_caller(add(reg(RCX), reg(RSP), const(16)), store(reg(RCX), const(7))), called])
    loaded = [node for node in found['nodes'] if node.get('loaded_by')]
    assert loaded and all(isinstance(node.get('callee_entry'), str) and node['callee_entry'] for node in loaded)
    assert all(node['callee_entry'] != 'globals-disjoint-from-stack' for node in loaded)


def test_split_memory_outputs_keep_both_bytes_and_target_choice(monkeypatch):
    a = FunctionBuilder(entry=A).ins(store(reg(RDX), const(0x22, 4)), copy(reg(RAX), const(10))).ret()
    wide = 0x1122334455667788
    b = FunctionBuilder(entry=B).ins(store(reg(RDX), const(wide)), copy(reg(RAX), const(20))).ret()
    _, found, _, _ = record(monkeypatch, caller(), a, b)
    assert evaluate(found, entry, route='stitched') == {0x22 + 10, wide + 20}


def test_a_nonreturning_target_has_no_normal_output_alternative(monkeypatch):
    from test_noreturn_models import ABORT, MODELS, ImageInfo, ImportedSymbol, load_external_models

    monkeypatch.setenv('TDO_V2_FORWARD', '1')
    functions = (caller(), target(A, 1, 10), FunctionBuilder(entry=B).call(ABORT).ret())
    units, provenance = program_units(*functions), {}
    # The model states non-return; no ABI is inferred by the core.
    image = ImageInfo('synthetic', (), (ImportedSymbol('CRT', 'abort', None, (), ((1, ABORT),)),), (), ())
    results = analyze_units(units, record_provenance=provenance, image_info=image,
                            external_models=load_external_models(MODELS, 'x86:LE:64:default', 'win64'))
    item = results[ROOT]
    run = next(run for exit_summary in item.summary.exits for run in exit_summary.runs
               if run.span.object_id.kind.value == 'register_file' and run.span.start == RAX)
    found = root_record(item.normalized, item.unit,
                        [(item.normalized.memory_graph.definition_nodes[index], (run.span,)) for index in run.definitions],
                        provenance=provenance[id(item)][1], stitch=StitchContext(provenance))
    assert evaluate(found, entry, route='stitched') == {18}
    assert all(choice['function'] != '1:1900' for node in found['nodes'] for choice in node.get('choices', ()))


def test_record_collection_does_not_change_the_composed_effect(monkeypatch):
    functions = (caller(), target(A, 1, 10), target(B, 2, 20))
    item, _, _, _ = record(monkeypatch, *functions)
    plain = analyze_units(program_units(*functions))[ROOT]
    assert plain.summary == item.summary and plain.proven == item.proven


def test_an_unsupported_target_is_not_dropped_from_the_alternatives(monkeypatch):
    b = FunctionBuilder(entry=B).ins(op('FLOAT_ADD', [reg(RCX), reg(RCX)], reg(RAX))).ret()
    _, found, _, _ = record(monkeypatch, caller(memory=False), target(A, 1, 10), b)
    with pytest.raises(Ineligible, match='unsupported'):
        evaluate(found, entry, route='stitched')


def test_nested_helper_exit_choices_are_scoped_to_the_selected_target(monkeypatch):
    helper_address = 0x1b00
    flag = tmp(0x300, 1)
    helper = (FunctionBuilder(entry=helper_address)
              .cbranch('other', flag, op('INT_NOTEQUAL', [reg(R8), const(0)], flag))
              .ins(copy(reg(RAX), const(11))).ret()
              .label('other').ins(copy(reg(RAX), const(22))).ret())
    a = (FunctionBuilder(entry=A).sub_rsp(0x28).call(helper_address)
         .ins(add(reg(RAX), reg(RAX), const(100))).add_rsp(0x28).ret())
    b = (FunctionBuilder(entry=B).sub_rsp(0x28).call(helper_address)
         .ins(add(reg(RAX), reg(RAX), const(200))).add_rsp(0x28).ret())
    _, found, _, _ = record(monkeypatch, caller(memory=False), a, b, helper)
    assert evaluate(found, entry, route='stitched') == {111, 122, 211, 222}
    nested_instances = {node['instance'] for node in found['nodes'] if node.get('reason') == 'callee exits'}
    assert len(nested_instances) == 2
    assert any('@1:1800' in instance for instance in nested_instances)
    assert any('@1:1900' in instance for instance in nested_instances)


def test_mismatched_choice_domains_are_refused(monkeypatch):
    _, found, _, _ = record(monkeypatch, caller(), target(A, 1, 10), target(B, 2, 20))
    phis = [node for node in found['nodes'] if node.get('reason') == 'call targets and exits']
    assert len(phis) >= 2
    changed = copying.deepcopy(found)
    node = changed['nodes'][phis[0]['id']]
    node['choices'] = list(reversed(node['choices']))
    with pytest.raises(Ineligible, match='choice'):
        evaluate(changed, entry, route='stitched')


def test_stitch_limit_does_not_publish_half_the_target_set(monkeypatch):
    _, plain, _, _ = record(monkeypatch, caller(memory=False), target(A, 1, 10), target(B, 2, 20), stitch=False)
    _, found, _, _ = record(monkeypatch, caller(memory=False), target(A, 1, 10), target(B, 2, 20),
                             limits=Limits(nodes=len(plain['nodes']) + 1))
    calls = [node for node in found['nodes'] if node['kind'] == 'call']
    assert calls and all('stitched' not in node for node in calls)
    assert any(node.get('stitch_cut') == 'limit' for node in calls)
    assert not any(node.get('import') for node in found['nodes'])
