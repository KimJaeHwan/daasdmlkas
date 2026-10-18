"""A mask bounds an index, not an arbitrary/untrusted replacement for it."""

import pytest

from graph_oracle import check
from synthetic import (RAX, RCX, RDI, RSI, RSP, R9, FunctionBuilder, add, const,
                       load, normalize_with_observation, op, program_units, reg, store, tmp)
from tdo_v2.normalize import FunctionNormalizer


def indexed(mask, overwrite=False):
    slot, base, index, wide, address = tmp(0x100), tmp(0x108), tmp(0x110, 4), tmp(0x118), tmp(0x120)
    caller = (FunctionBuilder().sub_rsp(0x30)
              .ins(add(slot, reg(RSP), const(24))).ins(add(base, reg(RSP), const(8)))
              .ins(op('INT_AND', [reg(RSI, 4), const(mask, 4)], index)).ins(store(slot, index)))
    if overwrite:
        # Derived from this frame, not an entry pointer forbidden from the
        # new frame by the existing entry-values-not-frame assumption.
        caller.ins(add(reg(RDI), reg(RSP), reg(RCX))).ins(store(reg(RDI), const(4, 4)))
    caller.ins(load(index, slot)).ins(op('INT_SEXT', [index], wide))
    caller.ins(op('INT_MULT', [wide, const(4)], address), add(address, base, address))
    caller.ins(store(address, const(29, 4))).ins(load(reg(RAX, 4), slot))
    caller.ins(load(reg(R9, 4), address)).add_rsp(0x30).ret()
    return caller


@pytest.mark.parametrize('mask,overwrite,alias_expected', [(3, False, False), (7, False, True), (3, True, True)])
def test_masked_stack_index_does_not_alias_outside_its_proven_range(mask, overwrite, alias_expected):
    normalized, observation = normalize_with_observation(indexed(mask, overwrite))
    # Query the LOAD of the index slot after the indexed STORE, not a source tag.
    loads = [f'{ins.address.space_id:x}:{ins.address.byte_offset:x}:{i}:LOAD'
             for ins in observation.instructions for i, operation in enumerate(ins.operations)
             if operation.opcode == 'LOAD' and operation.output.coordinate.byte_offset == RAX
             and operation.output.byte_size == 4]
    assert len(loads) == 1
    aliases = [row for row in normalized.may_alias_reads if row.operation_key == loads[0]]
    assert bool(aliases) is alias_expected
    report = check(normalized, observation, seeds=range(8), register_pools=lambda seed: {
        RSP: 0x70000000, RSI: seed, RCX: 24,
    })
    assert report.runs and report.silent == []


@pytest.mark.parametrize('mask,alias_expected', [(3, False), (0xffff, True)])
def test_finite_index_outside_the_observed_frame_may_still_hit_a_global(mask, alias_expected):
    index, wide, address = tmp(0x100, 4), tmp(0x108), tmp(0x110)
    caller = (FunctionBuilder().sub_rsp(0x30).ins(store(reg(RSP), const(0, 4)))
              .ins(op('INT_AND', [reg(RSI, 4), const(mask, 4)], index))
              .ins(op('INT_SEXT', [index], wide)).ins(op('INT_MULT', [wide, const(4)], address))
              .ins(add(address, reg(RSP), address)).ins(store(address, reg(RCX, 4)))
              .ins(load(reg(RAX, 4), const(0x4800))).add_rsp(0x30).ret())
    (unit,) = program_units(caller)
    normalized = FunctionNormalizer().normalize(unit, assume_globals_disjoint_from_stack=True)
    key = next(action.operation_key for action in normalized.memory_ssa.actions
               if action.operation_key.endswith(':LOAD') and any(
                   read.span.object_id.kind.value == 'address_space' and read.span.start == 0x4800
                   for read in normalized.memory_ssa.reads if read.action_id ==
                   normalized.memory_ssa.actions.index(action)))
    assert any(row.operation_key == key for row in normalized.may_alias_reads) is alias_expected
    report = check(normalized, unit.observation, seeds=range(2), register_pools=lambda seed: {
        RSP: 0x1000, RSI: (0x4800 - (0x1000 - 0x30)) // 4, RCX: 29,
    })
    assert report.runs and report.silent == []
