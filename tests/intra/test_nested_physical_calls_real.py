"""Original suite09 nested helpers: physical inputs, no summary result injection.

These execute extracted machine p-code, not native code. The selected roots
are the compiled helpers of DFB051/055, not a claim for all suite09 cases.
The existing admitted Bundle and its original observations remain unchanged.
"""

import pytest

from pcode_interpreter import Interpreter
from test_conditional_records_real import _entry, _execute, _load
from test_ue_core_conditional_records import _operation_record
from tdo_v2.operation_records import StitchContext, eligibility, evaluate_physical, root_record


NESTED, DEEP = '1b1:104d83', '1b1:104f77'
SHA = '759c776096d7454feadfbe92b4645b4a825450cce099b732363b1d9cc7238e29'
STACK, POINTER, SAVED = 0x70000000, 0x71000000, 0x74000000


class _ActualWitnessInterpreter(Interpreter):
    """Passive per-depth observation; the original interpreter executes all.

    Its ordinary activation table groups nested calls into the outermost
    activation, so it cannot alone witness each nested RETURN operand.
    """

    def __init__(self, observation, **options):
        super().__init__(observation, **options)
        self.register_space = next(varnode.coordinate.space_id
                                   for row in observation.instructions for operation in row.operations
                                   for varnode in (*operation.inputs, operation.output)
                                   if varnode is not None and varnode.kind.name == 'REGISTER')
        self.witness_stack, self.nested_witnesses = [], []

    def _execute(self, key, operation, run):
        jump = super()._execute(key, operation, run)

        def register(offset):
            return sum(self._bytes[self.register_space, offset + byte][0] << (8 * byte) for byte in range(8))

        if jump is not None and jump[0] == 'call':
            witness = dict(call=key, entered_stack=register(0x20))
            self.witness_stack.append(witness)
            self.nested_witnesses.append(witness)
        elif jump is not None and jump[0] == 'return' and self.witness_stack:
            assert operation.inputs[0].kind.name == 'REGISTER'
            self.witness_stack.pop().update(target=register(operation.inputs[0].coordinate.byte_offset),
                                            stack=register(0x20))
        return jump


@pytest.fixture(scope='module')
def actual_nested():
    case = _load('TDO_CONDITIONAL_SUITE09_BUNDLE', (NESTED, DEEP), analysis_options=dict(
        assume_import_slots_hold_exports=False, assume_globals_disjoint_from_stack=False,
        assume_entry_values_not_frame=False, assume_opaque_callees_leave_no_stack_addresses=False,
        private_frame_above=0))
    assert case['image_sha'] == SHA
    for item in case['results'].values():
        assert not item.declared and not item.inherited_assumptions
        assert not item.normalized.assumes_globals_disjoint_from_stack
        assert not item.normalized.assumes_entry_values_not_frame
        assert not item.normalized.assumes_opaque_callees_leave_no_stack_addresses
        assert not item.normalized.assumes_import_slots_hold_exports
    return case


def _physical(case, key, *, register=None, operation=None, physical=True):
    item = case['results'][key]
    options = dict(declared=item.declared, provenance=case['provenance'][id(item)][1],
                   stitch=StitchContext(case['provenance']), physical_memory=physical)
    if operation is not None:
        return _operation_record(item, operation, **options)
    seeds = []
    for exit_summary in item.summary.exits:
        for run in exit_summary.runs:
            if run.span.object_id.kind.value == 'register_file' and run.span.start == register:
                seeds.extend((item.normalized.memory_graph.definition_nodes[identifier], (run.span,))
                             for identifier in run.definitions)
    assert seeds
    return root_record(item.normalized, item.unit, seeds, **options)


def _value(case, state, offset, size=8):
    values = (state[(case['register'], offset + byte)] for byte in range(size))
    return sum((value[0] if isinstance(value, tuple) else value) << (8 * byte)
               for byte, value in enumerate(values))


def _returns(case, vm):
    observations = case['program']
    calls = {f'{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:CALL': row
             for observation in observations.values() for row in observation.instructions
             for ordinal, operation in enumerate(row.operations) if operation.opcode == 'CALL'}
    found = set()
    assert not vm.witness_stack
    for witness in vm.nested_witnesses:
        call = witness['call']
        row = calls[call]
        # Original x86 CALL decrements SP by eight and pushes its fallthrough.
        assert witness['target'] == row.fallthrough.byte_offset
        assert witness['stack'] == witness['entered_stack'] + 8
        found.add(call)
    return found


def test_actual_dfb051_helpers_preserve_nested_arithmetic_and_stack_memory(actual_nested):
    case = actual_nested
    item = case['results'][NESTED]
    result = _physical(case, NESTED, register=0)
    saved = _physical(case, NESTED, operation='1b1:104d98:1:LOAD')
    ordinary = (_physical(case, NESTED, register=0, physical=False),
                _physical(case, NESTED, operation='1b1:104d98:1:LOAD', physical=False))
    assert not result['truncated'] and len(result['physical_calls']) == 2
    assert sorted(context['parent_context'] is None for context in result['physical_calls'].values()) == [False, True]
    for seed, value in enumerate((0, 1, 41, 0x7fffffff, 0xffffffff)):
        vm, run = _execute(case, item, ((0x20, 8, STACK), (0x28, 8, SAVED), (0x38, 4, value)),
                           ((item.unit.scopes.function.entry.space_id, STACK, 8, 0x200000),), seed,
                           interpreter_type=_ActualWitnessInterpreter)
        calls = _returns(case, vm)
        expected = (value * 7 + 1) & 0xffffffff
        assert _value(case, vm._bytes, 0, 4) == expected
        evaluation = evaluate_physical(result, _entry(case, vm))
        assert evaluation.value == expected
        assert {row['call'] for row in evaluation.evidence if row['kind'] == 'call'} == calls
        assert evaluate_physical(saved, _entry(case, vm)).value == SAVED
        assert run.completed
        assert (eligibility(result), eligibility(saved)) == tuple(map(eligibility, ordinary))


@pytest.mark.parametrize('pointer,expected', ((POINTER, SAVED), (STACK - 12, 0x600000004)))
def test_actual_dfb055_three_nested_calls_keep_original_byte_writers(actual_nested, pointer, expected):
    case = actual_nested
    item = case['results'][DEEP]
    record = _physical(case, DEEP, operation='1b1:104fa6:1:LOAD')
    assert not record['truncated'] and len(record['physical_calls']) == 3
    space = item.unit.scopes.function.entry.space_id
    vm, _ = _execute(case, item, ((0x20, 8, STACK), (0x28, 8, SAVED), (0x38, 8, pointer)),
                     ((space, STACK, 8, 0x200000), (space, pointer, 4, 42)),
                     interpreter_type=_ActualWitnessInterpreter)
    calls = _returns(case, vm)
    assert _value(case, vm._bytes, 0x28) == expected
    evaluation = evaluate_physical(record, _entry(case, vm))
    assert evaluation.value == expected
    assert {row['call'] for row in evaluation.evidence if row['kind'] == 'call'} == calls
    (loaded,) = [row for row in evaluation.evidence if row.get('key') == '1b1:104fa6:1:LOAD']
    if pointer == POINTER:
        assert {source['writer'] for source in loaded['sources']} == {'1b1:104f77:2:STORE'}
    else:
        assert [(source['writer'], source['offset']) for source in loaded['sources']] == [
            *(('1b1:104f56:2:STORE', byte) for byte in range(4)),
            *(('1b1:104f61:2:STORE', byte) for byte in range(4))]
    assert eligibility(record) == 'debt'
