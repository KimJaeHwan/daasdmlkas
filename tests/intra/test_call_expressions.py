"""Call body expressions, checked against concrete raw-pcode executions."""

import pytest

from synthetic import (
    RAX, RBX, RCX, RDI, RDX, R9, RSP, ZF, FunctionBuilder, add, const, copy,
    load, op, program_units, reg, store, sub, tmp,
)
from tdo_v2.call_expressions import RecordProvider
from tdo_v2.interprocedural import analyze_units
from tdo_v2.operation_records import Ineligible, Limits, evaluate, evaluate_joint, root_record, run_records


LEAF = 0x1800


def analyze(caller, leaf, **options):
    provider = RecordProvider()
    results = analyze_units(program_units(caller, leaf), record_provider=provider, **options)
    return results, provider


def output(results, provider, register, limits=None):
    item = results['1:1000']
    return next(record for record in run_records(item.normalized, item.unit, item.summary,
                                                 provider=provider, limits=limits)
                if record['place']['kind'] == 'register_file' and record['place']['start'] == register)


def entry(registers):
    def read(node):
        if isinstance(node, tuple):
            return None
        span = node.get('register')
        if span:
            base = span['offset'] - span['offset'] % 8
            value = registers.get(base, 0)
            return (value >> (8 * (span['offset'] - base))) & ((1 << (8 * span['size'])) - 1)
        return None
    return read


def test_same_dependencies_do_not_merge_output_expressions():
    leaf = (FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RDI), const(1)))
            .ins(add(reg(RBX), reg(RDI), const(2))).ret())
    caller = FunctionBuilder().call(LEAF).ins(sub(reg(R9), reg(RAX), reg(RBX))).ret()
    results, provider = analyze(caller, leaf)
    effect = next(iter(results['1:1000'].proven.values()))
    assert any(len(run.writes) > 1 for run in effect.runs)  # deliberately grouped by dependencies
    record = output(results, provider, R9)
    for value in (0, 1, 255, 2**64 - 2):
        assert evaluate(record, entry({RDI: value})) == {2**64 - 1}


def test_two_call_sites_have_distinct_contexts_and_input_values():
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    caller = (FunctionBuilder().ins(copy(reg(RDI), const(5))).call(LEAF)
              .ins(copy(reg(RCX), reg(RAX))).ins(copy(reg(RDI), const(17))).call(LEAF)
              .ins(sub(reg(R9), reg(RAX), reg(RCX))).ret())
    results, provider = analyze(caller, leaf)
    record = output(results, provider, R9)
    assert evaluate(record, entry({})) == {12}
    assert len({node['choice_group'] for node in record['nodes'] if node['kind'] == 'call_output'}) == 2


def test_outputs_share_exit_choice_inside_and_across_records():
    leaf = (FunctionBuilder(entry=LEAF).cbranch('other', reg(ZF, 1))
            .ins(copy(reg(RAX), const(1)), copy(reg(RBX), const(10))).ret()
            .label('other').ins(copy(reg(RAX), const(2)), copy(reg(RBX), const(20))).ret())
    caller = (FunctionBuilder().call(LEAF).ins(op('INT_MULT', [reg(RAX), const(10)], reg(RCX)))
              .ins(sub(reg(R9), reg(RBX), reg(RCX))).ret())
    results, provider = analyze(caller, leaf)
    assert evaluate(output(results, provider, R9), entry({})) == {0}
    records = [output(results, provider, register) for register in (RAX, RBX)]
    assert evaluate_joint(records, entry({})) == {(1, 10), (2, 20)}


def test_callee_memory_arithmetic_reaches_callers_post_call_load():
    pointer, left, right = tmp(0x100), tmp(0x108, 4), tmp(0x110, 4)
    leaf = (FunctionBuilder(entry=LEAF).ins(load(left, reg(RDI)))
            .ins(add(pointer, reg(RDI), const(4)), load(right, pointer))
            .ins(add(left, left, right)).ins(add(pointer, reg(RDI), const(8)), store(pointer, left)).ret())
    caller = (FunctionBuilder().ins(copy(reg(RDI), const(0x4000)))
              .ins(store(reg(RDI), const(13, 4))).ins(store(const(0x4004), const(29, 4)))
              .call(LEAF).ins(load(reg(R9, 4), const(0x4008))).ret())
    results, provider = analyze(caller, leaf, assume_globals_disjoint_from_stack=True)
    record = output(results, provider, R9)
    assert evaluate(record, entry({RSP: 0x70000000})) == {42}
    assert any(node['kind'] == 'op' and node['opcode'] == 'STORE' and node['function'] == '1:1800'
               for node in record['nodes'])
    assert any(node['kind'] == 'binding' and node['span'].startswith('relative:') for node in record['nodes'])


def test_entry_memory_is_bound_before_overwrite():
    leaf = (FunctionBuilder(entry=LEAF).ins(load(reg(RAX, 4), reg(RDI)))
            .ins(store(reg(RDI), const(999, 4))).ret())
    caller = (FunctionBuilder().ins(copy(reg(RDI), const(0x4000)))
              .ins(store(reg(RDI), const(17, 4))).call(LEAF)
              .ins(copy(reg(R9, 4), reg(RAX, 4))).ret())
    results, provider = analyze(caller, leaf, assume_globals_disjoint_from_stack=True)
    assert evaluate(output(results, provider, R9), entry({RSP: 0x70000000})) == {17}


def test_stack_spill_and_call_push_delta_are_composed_once():
    leaf = (FunctionBuilder(entry=LEAF).push(RBX).sub_rsp(16)
            .ins(store(reg(RSP), reg(RDI))).ins(load(reg(RAX), reg(RSP)))
            .add_rsp(16).pop(RBX).ret())
    caller = FunctionBuilder().call(LEAF).ins(copy(reg(R9), reg(RAX))).ret()
    results, provider = analyze(caller, leaf, assume_globals_disjoint_from_stack=True)
    record = output(results, provider, R9)
    assert evaluate(record, entry({RDI: 77, RSP: 0x70000000})) == {77}
    deltas = [row['addend'] for node in record['nodes'] for row in node.get('adjustments', ())]
    assert deltas and set(deltas) == {-8}


def test_missing_provider_witness_is_explicit_not_guessed():
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    caller = FunctionBuilder().call(LEAF).ins(copy(reg(R9), reg(RAX))).ret()
    results, _ = analyze(caller, leaf)
    record = output(results, RecordProvider(), R9)
    assert any(node['kind'] == 'unavailable' for node in record['nodes'])
    with pytest.raises(Ineligible, match='unavailable'):
        evaluate(record, entry({RDI: 7}))


def test_expansion_uses_one_global_limit():
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    caller = FunctionBuilder().call(LEAF).ins(copy(reg(R9), reg(RAX))).ret()
    results, provider = analyze(caller, leaf)
    record = output(results, provider, R9, Limits(nodes=5))
    assert record['truncated']
    with pytest.raises(Ineligible):
        evaluate(record, entry({RDI: 7}))


def test_observers_do_not_change_analysis_semantics_and_publish_no_trials():
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    caller = FunctionBuilder().call(LEAF).ins(copy(reg(R9), reg(RAX))).ret()
    units = program_units(caller, leaf)
    ordinary = analyze_units(units)
    provider = RecordProvider()
    observed = analyze_units(units, record_provider=provider)
    for key in ordinary:
        assert ordinary[key].summary == observed[key].summary
        assert ordinary[key].proven == observed[key].proven
        assert ordinary[key].origins == observed[key].origins
        assert ordinary[key].declared == observed[key].declared
        assert ordinary[key].normalized.memory_ssa == observed[key].normalized.memory_ssa
        assert ordinary[key].normalized.effects == observed[key].normalized.effects
        old, new = ordinary[key].normalized.dependencies, observed[key].normalized.dependencies
        assert old.node_count == new.node_count
        assert tuple(old.node(i) for i in range(old.node_count)) == tuple(new.node(i) for i in range(new.node_count))
        assert old.weighted_edges() == new.weighted_edges()
    from tdo_v2.summary_engine import run_assumptions
    assert run_assumptions(ordinary) == run_assumptions(observed)
    assert not provider._selected and not provider._normalizations
    # An equal-but-different normalized object is not the final snapshot.
    from dataclasses import replace
    item = observed['1:1000']
    assert provider.view(item.unit, replace(item.normalized)) is None


def test_entry_pointer_memory_without_a_prior_caller_store():
    leaf = FunctionBuilder(entry=LEAF).ins(load(reg(RAX, 4), reg(RDI))).ret()
    caller = FunctionBuilder().call(LEAF).ins(copy(reg(R9, 4), reg(RAX, 4))).ret()
    results, provider = analyze(caller, leaf, assume_globals_disjoint_from_stack=True)
    registers = entry({RDI: 0x4000, RSP: 0x70000000})
    def read(node):
        if isinstance(node, tuple):
            return 17 if node == ('memory', 1, 0x4000, 4) else None
        return registers(node)
    assert evaluate(output(results, provider, R9), read) == {17}


def test_may_write_memory_identity_exit_keeps_entry_memory():
    leaf = (FunctionBuilder(entry=LEAF).cbranch('keep', reg(ZF, 1))
            .ins(store(reg(RDI), const(7, 4))).ret().label('keep').ret())
    caller = FunctionBuilder().call(LEAF).ins(load(reg(R9, 4), reg(RDI))).ret()
    results, provider = analyze(caller, leaf, assume_globals_disjoint_from_stack=True)
    registers = entry({RDI: 0x4000, RSP: 0x70000000})
    def read(node):
        if isinstance(node, tuple):
            return 17 if node == ('memory', 1, 0x4000, 4) else None
        return registers(node)
    assert evaluate(output(results, provider, R9), read) == {7, 17}


def test_pointer_slot_uses_pre_call_contents_even_after_callee_overwrites_it():
    leaf = (FunctionBuilder(entry=LEAF).ins(load(reg(RBX), reg(RDI)))
            .ins(load(reg(RAX, 4), reg(RBX))).ins(store(reg(RDI), const(0x4500))).ret())
    caller = (FunctionBuilder().ins(copy(reg(RDI), const(0x4000)))
              .ins(store(reg(RDI), const(0x4100))).ins(store(const(0x4100), const(123, 4)))
              .call(LEAF).ins(copy(reg(R9, 4), reg(RAX, 4))).ret())
    results, provider = analyze(caller, leaf, assume_globals_disjoint_from_stack=True)
    assert evaluate(output(results, provider, R9), entry({RSP: 0x70000000})) == {123}


def test_loop_flags_in_new_binding_and_exit_parts_block_evaluation():
    from tdo_v2.operation_records import eligibility
    for node in (
        {'kind': 'binding', 'parts': [{'node': 0, 'loop': True}]},
        {'kind': 'call_output', 'alternatives': [{'exit': 'x', 'parts': [{'node': 0, 'loop': True}]}]},
    ):
        assert eligibility({'nodes': [node]}) == 'loop'


def test_unknown_exit_is_not_silently_dropped():
    leaf = (FunctionBuilder(entry=LEAF).cbranch('keep', reg(ZF, 1))
            .ins(copy(reg(RAX), const(7))).ret().label('keep').ret())
    caller = FunctionBuilder().call(LEAF).ins(copy(reg(R9), reg(RAX))).ret()
    results, provider = analyze(caller, leaf)
    record = output(results, provider, R9)
    # One exit is known 7; the other needs an entry byte not supplied.
    with pytest.raises(Ineligible, match='unknown inputs'):
        evaluate(record, lambda node: None)


def test_diagnostic_allocation_errors_are_not_hidden():
    class FailingProvider(RecordProvider):
        def normalized(self, unit, *args):
            if unit.scopes.function.entry.byte_offset == 0x1000:
                raise MemoryError('diagnostic allocation')
            super().normalized(unit, *args)
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    caller = FunctionBuilder().call(LEAF).ret()
    provider = FailingProvider()
    with pytest.raises(MemoryError, match='diagnostic allocation'):
        analyze_units(program_units(caller, leaf), record_provider=provider)
    assert not provider._selected and not provider._normalizations


def test_entry_memory_address_wraps_at_the_declared_space_width():
    pointer = tmp(0x100)
    leaf = (FunctionBuilder(entry=LEAF).cbranch('keep', reg(ZF, 1))
            .ins(add(pointer, reg(RDI), const(8)), store(pointer, const(7, 4)))
            .ret().label('keep').ret())
    caller = (FunctionBuilder().call(LEAF).ins(add(pointer, reg(RDI), const(8)))
              .ins(load(reg(R9, 4), pointer)).ret())
    results, provider = analyze(caller, leaf, assume_globals_disjoint_from_stack=True)
    registers = entry({RDI: 2**64 - 4, RSP: 0x70000000})
    def read(node):
        if isinstance(node, tuple):
            return 17 if node == ('memory', 1, 4, 4) else 99
        return registers(node)
    assert evaluate(output(results, provider, R9), read) == {7, 17}


def test_outputs_from_different_analysis_snapshots_are_not_correlated():
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    caller = FunctionBuilder().call(LEAF).ins(copy(reg(R9), reg(RAX))).ret()
    first, p1 = analyze(caller, leaf)
    second, p2 = analyze(caller, leaf)
    with pytest.raises(Ineligible, match='different analysis snapshots'):
        evaluate_joint([output(first, p1, R9), output(second, p2, R9)], entry({RDI: 7}))


def test_mermaid_contains_every_record_node_and_dependency():
    from tdo_v2.operation_records import mermaid, record_edges
    leaf = FunctionBuilder(entry=LEAF).ins(add(reg(RAX), reg(RDI), const(1))).ret()
    caller = FunctionBuilder().call(LEAF).ins(copy(reg(R9), reg(RAX))).ret()
    results, provider = analyze(caller, leaf)
    record = output(results, provider, R9)
    graph = mermaid(record)
    assert sum(line.startswith('  n') and '["n' in line for line in graph.splitlines()) == len(record['nodes'])
    assert sum(' -->|' in line or ' -.->|' in line for line in graph.splitlines()) == len(record_edges(record))
    assert all(f'n{source} ' in graph and f' n{target}' in graph
               for source, target, _ in record_edges(record))


def test_memory_expressions_match_concrete_program_runs_without_call_injection():
    import random
    from pcode_interpreter import Interpreter
    from record_oracle import entry_reader, final_register

    for number in range(20):
        rng = random.Random(number)
        opcode = rng.choice(('INT_ADD', 'INT_SUB', 'INT_MULT', 'INT_XOR', 'INT_AND', 'INT_OR'))
        pointer, left, right = tmp(0x100), tmp(0x108, 4), tmp(0x110, 4)
        leaf = (FunctionBuilder(entry=LEAF).ins(load(left, reg(RDI)))
                .ins(add(pointer, reg(RDI), const(4)), load(right, pointer))
                .ins(op(opcode, [left, right], left)).ins(store(reg(RDI), left)).ret())
        caller = (FunctionBuilder().ins(copy(reg(RDI), const(0x4000)))
                  .ins(store(reg(RDI), reg(RCX, 4))).ins(store(const(0x4004), reg(RDX, 4)))
                  .call(LEAF).call(LEAF).ins(load(reg(R9, 4), reg(RDI))).ret())
        results, provider = analyze(caller, leaf, assume_globals_disjoint_from_stack=True)
        record = output(results, provider, R9)
        program = {(1, item.unit.scopes.function.entry.byte_offset): item.unit.observation
                   for item in results.values()}
        for seed in range(5):
            vm = Interpreter(results['1:1000'].unit.observation, constant_space=0, seed=seed,
                             program=program, havoc_calls=(2, RSP, 8))
            vm.preset(2, 0, 0x300, 0)
            vm.preset(2, RSP, 8, 0x70000000)
            vm.preset(2, RCX, 4, rng.getrandbits(32))
            vm.preset(2, RDX, 4, rng.getrandbits(32))
            assert vm.run().completed
            assert evaluate(record, entry_reader(vm)) == {final_register(vm, R9, 4)}
