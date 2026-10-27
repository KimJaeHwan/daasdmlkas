"""Original-entry indexed call places agree with actual callee executions."""

from dataclasses import replace

import pytest

from forward_oracle import _Recording
from program_oracle import _place, check_program
from synthetic import (
    CODE_BASE, CONST, RAM, R8, RAX, RBX, RCX, RDI, RDX, REG, RSI, RSP, FunctionBuilder,
    add, const, copy, load, op, program_units, reg, slice_from, store, tmp,
)
from tdo_v2.interprocedural import analyze_units
from tdo_v2.call_summary_effects import call_load_keys
from tdo_v2.forward import Interval, Value, forward_facts
from tdo_v2.relative_memory import _final_projector, stale_reads


LEAF, WRAPPER = CODE_BASE + 0x800, CODE_BASE + 0xA00
MASK = (1 << 64) - 1
INDICES = (0, 1, 2, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF, 7)


def _address(builder, base, index, output, *, extension="INT_SEXT", preoffset=0, scale=3):
    narrow, wide = tmp(0x300, 4), tmp(0x310)
    return builder.ins(add(narrow, index, const(preoffset, 4)), op(extension, [narrow], wide),
                       op("INT_MULT", [wide, const(scale & MASK)], wide), add(output, base, wide))


def _fixture(source="register", *, extension="INT_SEXT", preoffset=0, scale=3, partial=False,
             wrapper=False, condition=None, different_index=False):
    base, index, address, slot = tmp(0x100), tmp(0x110, 4), tmp(0x120), tmp(0x130)
    leaf = FunctionBuilder(entry=LEAF)
    if condition is not None:
        leaf.ins(store(reg(RDX), reg(RBX, 4)))
    if source == "register":
        original_base, original_index = reg(RDI), reg(RDX, 4)
    elif source == "memory":
        leaf.ins(load(index, reg(RCX)))
        original_base, original_index = reg(RDI), index
    else:
        leaf.ins(load(base, reg(RCX)), add(slot, reg(RCX), const(8)), load(index, slot))
        original_base, original_index = base, index
    _address(leaf, original_base, original_index, address, extension=extension, preoffset=preoffset, scale=scale)
    writer = f"1:{leaf._address(len(leaf._rows)):x}:0:STORE"
    leaf.ins(store(address, reg(RAX, 2)))
    if source == "register":
        leaf.ins(copy(reg(RDX, 4), const(19, 4)), copy(reg(RDI), const(0x44000000)))
    elif source == "memory":
        leaf.ins(store(reg(RCX), const(19, 4)))
    else:
        leaf.ins(store(reg(RCX), const(0x44000000)), store(slot, const(19, 4)))
    leaf.ret()
    caller = FunctionBuilder().sub_rsp(0x48)
    if different_index:
        caller.ins(op("INT_AND", [reg(RDX, 4), const(3, 4)], reg(RDX, 4)),
                   op("INT_AND", [reg(R8, 4), const(3, 4)], reg(R8, 4)))
    if source != "register":
        caller.ins(add(reg(RCX), reg(RSP), const(0x20)))
        if source == "pointer-memory":
            caller.ins(store(reg(RCX), reg(RDI)), add(slot, reg(RCX), const(8)), store(slot, reg(R8, 4)))
        else:
            caller.ins(store(reg(RCX), reg(R8, 4)))
        if condition == "disjoint":
            caller.ins(add(reg(RDX), reg(RSP), const(0x30)))
        elif condition == "overlap":
            caller.ins(copy(reg(RDX), reg(RCX)))
    caller_index = reg(R8, 4) if source != "register" or different_index else reg(RDX, 4)
    _address(caller, reg(RDI), caller_index, reg(RSI), extension=extension, preoffset=preoffset, scale=scale)
    caller.call(WRAPPER if wrapper else LEAF)
    if partial:
        caller.ins(add(reg(RSI), reg(RSI), const(1)))
    reader = f"1:{caller._address(len(caller._rows)):x}:0:LOAD"
    caller.ins(load(reg(RAX, 2), reg(RSI))).add_rsp(0x48).ret()
    bodies = [caller, leaf]
    if wrapper:
        bodies.append(FunctionBuilder(entry=WRAPPER).sub_rsp(0x28).call(LEAF).add_rsp(0x28).ret())
    return bodies, writer, reader


def _analyze(monkeypatch, engine, **options):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    bodies, writer, reader = _fixture(**options)
    units = program_units(*bodies)
    results = analyze_units(units)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    return results, program, writer, reader


def _pools(seed):
    return {RSP: 0x70000000, RDI: (0x71000000, MASK - 2)[seed % 2],
            RDX: INDICES[seed], R8: INDICES[seed], RAX: 0xA15B + seed,
            RBX: 5 + seed}


def _target(base, index, extension, preoffset, scale):
    index = (index + preoffset) & 0xFFFFFFFF
    if extension == "INT_SEXT" and index & 0x80000000:
        index -= 1 << 32
    return (base + scale * index) & MASK


def _oracle(item, program, pools=_pools):
    report = check_program(item.normalized, item.unit.observation, program, seeds=range(8),
                           register_pools=pools, havoc_calls=(REG, RSP, 8), address_bits={RAM: 64})
    assert report.runs == 8 and report.checked and not report.unsupported and not report.silent
    assert not report.place_failed and not report.place_unlocated_only and not report.footprint_unlocated
    return report


@pytest.mark.parametrize("engine", ["sparse", "dense"])
@pytest.mark.parametrize("source", ["register", "memory", "pointer-memory"])
def test_later_register_index_memory_index_or_pointer_slot_updates_do_not_rebind_entry_place(monkeypatch,
                                                                                           engine, source):
    results, program, writer, reader = _analyze(monkeypatch, engine, source=source)
    item = results["1:1000"]
    call, effect = item.normalized.proven_call_effects[0]
    indexed = [run.write for run in effect.memory_runs if run.write.index is not None]
    assert len(indexed) == 1
    assert results[f"1:{LEAF:x}"].summary.address_relations
    report = _oracle(item, program)
    assert report.through_calls and report.place_covered
    for seed in range(8):
        expected = _target(_pools(seed)[RDI], INDICES[seed], "INT_SEXT", 0, 3)
        vm = _Recording(item.unit.observation, constant_space=CONST, seed=seed, subjects={},
                        contexts={(call, writer): 1}, program=program, havoc_calls=(REG, RSP, 8),
                        address_bits={RAM: 64})
        for offset, value in _pools(seed).items():
            vm.preset(REG, offset, 8, value)
        run = vm.run()
        assert run.completed and vm.seen[(call, writer)] == [expected]
        (_, snapshot), = vm.activation_snapshots.values()
        assert _place(indexed[0], snapshot, vm.entry_values, REG, moduli=vm._moduli) == (RAM, expected, 2)
        dependencies = [row for row in run.dependencies if row.reader == reader and row.space_id == RAM]
        assert {(row.offset, row.writer) for row in dependencies} == {
            ((expected + byte) & MASK, call) for byte in range(2)}


@pytest.mark.parametrize("engine", ["sparse", "dense"])
@pytest.mark.parametrize("extension", ["INT_SEXT", "INT_ZEXT"])
def test_sign_boundary_preoffset_source_wrap_address_wrap_and_partial_byte_overlap(monkeypatch, engine, extension):
    results, program, writer, reader = _analyze(monkeypatch, engine, extension=extension,
                                               preoffset=0xFFFFFFFF, scale=-5, partial=True)
    item = results["1:1000"]
    call, effect = item.normalized.proven_call_effects[0]
    (indexed,) = [run.write for run in effect.memory_runs if run.write.index is not None]
    assert (indexed.index.extend, indexed.index.preoffset, indexed.index.scale) == (extension[4:].lower(), 0xFFFFFFFF, -5)
    report = _oracle(item, program)
    assert report.through_calls and report.place_covered
    for seed in range(8):
        expected = _target(_pools(seed)[RDI], INDICES[seed], extension, 0xFFFFFFFF, -5)
        vm = _Recording(item.unit.observation, constant_space=CONST, seed=seed, subjects={},
                        contexts={(call, writer): 1}, program=program, havoc_calls=(REG, RSP, 8),
                        address_bits={RAM: 64})
        for offset, value in _pools(seed).items():
            vm.preset(REG, offset, 8, value)
        run = vm.run()
        assert run.completed and vm.seen[(call, writer)] == [expected]
        dependencies = [row for row in run.dependencies if row.reader == reader and row.space_id == RAM]
        assert any(row.offset == (expected + 1) & MASK and row.writer == call for row in dependencies)
        assert not any(row.offset == (expected + 2) & MASK and row.writer == call for row in dependencies)


@pytest.mark.parametrize("engine", ["sparse", "dense"])
def test_one_wrapper_resummary_retains_original_index_relation(monkeypatch, engine):
    results, program, _, _ = _analyze(monkeypatch, engine, wrapper=True)
    wrapper = results[f"1:{WRAPPER:x}"]
    assert wrapper.summary.address_relations
    assert any(run.write.index is not None for _, effect in results["1:1000"].normalized.proven_call_effects
               for run in effect.memory_runs)
    report = _oracle(results["1:1000"], program)
    assert report.place_covered and report.through_calls


@pytest.mark.parametrize("engine", ["sparse", "dense"])
def test_same_finite_index_range_does_not_replace_an_independent_index(monkeypatch, engine):
    results, program, _, reader = _analyze(monkeypatch, engine, different_index=True)
    item = results["1:1000"]
    def pools(seed):
        return {**_pools(seed), RDI: 0x71000000, RDX: seed & 3, R8: (seed + 1) & 3}
    view = slice_from(item.normalized, item.normalized.dependencies.node_for_key("op:" + reader))
    assert not view.is_complete
    assert any(row.operation_key == reader for row in item.normalized.may_alias_reads)
    (_, effect), = item.normalized.proven_call_effects
    assert next(run.write.index.register for run in effect.memory_runs if run.write.index is not None).start == RDX
    facts = {row.operation: row for row in forward_facts(item.normalized, item.unit)}
    assert facts[reader].claim == Value(64, ((("entry", RDI, 8), Interval(0, 9, 3, 64, True)),))
    _oracle(item, program, pools)


@pytest.mark.parametrize("engine", ["sparse", "dense"])
@pytest.mark.parametrize("binding", ["disjoint", "overlap", "unknown"])
def test_index_memory_writer_conditions_are_preloaded_and_not_assumed_disjoint(monkeypatch, engine, binding):
    results, program, _, reader = _analyze(monkeypatch, engine, source="memory", condition=binding)
    leaf, item = results[f"1:{LEAF:x}"], results["1:1000"]
    assert leaf.summary.writer_conditions
    _, effect = item.normalized.proven_call_effects[0]
    if binding == "disjoint":
        assert effect.preserves_memory and effect.writer_conditions
        assert any(run.write.index is not None for run in effect.memory_runs)
    else:
        assert not effect.preserves_memory
        view = slice_from(item.normalized, item.normalized.dependencies.node_for_key("op:" + reader))
        assert not view.is_complete
    _oracle(item, program)


@pytest.mark.parametrize("engine", ["sparse", "dense"])
@pytest.mark.parametrize("binding", ["disjoint", "overlap"])
def test_indexed_condition_side_loads_its_entry_memory_index_before_any_outputs(monkeypatch, engine, binding):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    first, second, address = tmp(0x100, 4), tmp(0x110, 4), tmp(0x120)
    leaf = FunctionBuilder(entry=LEAF).ins(load(first, reg(RDX)))
    _address(leaf, reg(RDI), first, address, scale=2)
    leaf.ins(store(address, reg(RBX, 2))).ins(load(second, reg(RCX)))
    _address(leaf, reg(RDI), second, address, scale=3)
    leaf.ins(store(address, reg(RAX, 2))).ins(store(reg(RDX), const(0, 4))).ret()
    caller = (FunctionBuilder().sub_rsp(0x48)
              .ins(add(reg(RCX), reg(RSP), const(0x20)), store(reg(RCX), reg(R8, 4)))
              .ins(add(reg(RDX), reg(RSP), const(0x28)), store(reg(RDX), const(2, 4)))
              .ins(add(reg(RDI), reg(RSP), const(0x30 if binding == "disjoint" else 0x1C))))
    _address(caller, reg(RDI), reg(R8, 4), reg(RSI))
    caller.call(LEAF).ins(load(reg(RAX, 2), reg(RSI))).add_rsp(0x48).ret()
    units = program_units(caller, leaf)
    results = analyze_units(units)
    item, callee = results["1:1000"], results[f"1:{LEAF:x}"]
    relation_objects = dict(callee.summary.address_relations)
    assert any(side.object_id in relation_objects for pair in callee.summary.writer_conditions for side in pair)
    (call, effect), = item.normalized.proven_call_effects
    if binding == "disjoint":
        sides = [side for pair in effect.writer_conditions for side in pair if side.index is not None]
        assert sides and all(side.index.memory is not None for side in sides)
        planned = call_load_keys(call, effect)
        # SSA action IDs are sorted by key, not execution order. The shared
        # effect unit retains the actual pre-stage-before-output order.
        sequence = [row for block in item.normalized.forward_inputs.effect_unit.blocks for row in block.effects]
        actions = {action.operation_key: i for i, action in enumerate(sequence)}
        outputs = [index for key, index in actions.items() if key.startswith(call + "~")
                   and key[len(call) + 1:].isdigit()]
        assert outputs and planned and all(actions[key] < min(outputs) for key in planned.values())
        assert all(side.index.memory in planned for side in sides)
    else:
        assert not effect.preserves_memory
        assert item.normalized.call_clobber_reads or item.normalized.may_alias_reads
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    _oracle(item, program, lambda seed: {**_pools(seed), R8: seed & 3})


@pytest.mark.parametrize("engine", ["sparse", "dense"])
@pytest.mark.parametrize("source", ["unbound-base", "unknown-index-read"])
def test_new_or_unbound_base_and_unknown_index_read_are_not_exported_as_entry_relations(monkeypatch, engine, source):
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    base, index, address = tmp(0x100), tmp(0x110, 4), tmp(0x120)
    leaf = FunctionBuilder(entry=LEAF)
    if source == "unbound-base":
        leaf.call(CODE_BASE + 0xE00)
        base_input, index_input = reg(RAX), reg(RDX, 4)
    else:
        leaf.ins(op("INT_MULT", [reg(RCX), reg(RCX)], base), load(index, base))
        base_input, index_input = reg(RDI), index
    _address(leaf, base_input, index_input, address)
    leaf.ins(store(address, reg(RBX, 2))).ret()
    caller = FunctionBuilder().sub_rsp(0x28).call(LEAF).ins(load(reg(RAX, 2), reg(RDI))).add_rsp(0x28).ret()
    units = program_units(caller, leaf)
    results = analyze_units(units)
    callee = results[f"1:{LEAF:x}"]
    assert not callee.summary.address_relations
    assert callee.summary.unknown_writers
    _, effect = results["1:1000"].normalized.proven_call_effects[0]
    assert not effect.preserves_memory and not any(run.write.index is not None for run in effect.memory_runs)


@pytest.mark.parametrize("engine", ["sparse", "dense"])
@pytest.mark.parametrize("offset,width", [(0, 4), (-2, 4), (4, 8), (8, 4)])
def test_index_preload_cannot_read_pre_push_bytes_overlaid_by_the_return_address(monkeypatch, engine, offset, width):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    slot, index, address = tmp(0x100), tmp(0x110, width), tmp(0x120)
    leaf = (FunctionBuilder(entry=LEAF).ins(add(slot, reg(RSP), const(offset & MASK)), load(index, slot)))
    if width == 4:
        _address(leaf, reg(RDI), index, address)
    else:
        leaf.ins(op("INT_MULT", [index, const(3)], address), add(address, reg(RDI), address))
    leaf.ins(store(address, reg(RAX, 2))).ret()
    caller = (FunctionBuilder().sub_rsp(0x48)
              .ins(add(slot, reg(RSP), const((-16) & MASK)), store(slot, const(0x1122334455667788)),
                   add(slot, reg(RSP), const((-8) & MASK)), store(slot, const(0x12345678)),
                   store(reg(RSP), const(2)))
              .ins(add(reg(RSI), reg(RDI), const(6))).call(LEAF))
    reader = f"1:{caller._address(len(caller._rows)):x}:0:LOAD"
    caller.ins(load(reg(RAX, 2), reg(RSI))).add_rsp(0x48).ret()
    units = program_units(caller, leaf)
    results = analyze_units(units)
    item = results["1:1000"]
    assert results[f"1:{LEAF:x}"].summary.address_relations
    references = [(evaluation, reference) for _, evaluation, reference in item.normalized.call_anchors
                  if type(reference) is tuple and reference[0] == "indexed"]
    projector = _final_projector(item.normalized, item.unit.observation)
    if offset == 8:
        assert references and all(projector._anchored_expression(key, reference, 8) is not None
                                  for key, reference in references)
        assert any(run.write.index is not None for _, effect in item.normalized.proven_call_effects
                   for run in effect.memory_runs)
    else:
        assert not references or all(projector._anchored_expression(key, reference, 8) is None
                                     for key, reference in references)
        view = slice_from(item.normalized, item.normalized.dependencies.node_for_key("op:" + reader))
        assert not view.is_complete
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    _oracle(item, program)


@pytest.mark.parametrize("engine", ["sparse", "dense"])
def test_two_level_entry_memory_index_preloads_pointer_then_value_before_slot_updates(monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    pointer, index, address = tmp(0x100), tmp(0x110, 4), tmp(0x120)
    leaf = FunctionBuilder(entry=LEAF).ins(load(pointer, reg(RCX)), load(index, pointer))
    _address(leaf, reg(RDI), index, address)
    leaf.ins(store(address, reg(RAX, 2))).ins(store(reg(RCX), const(0)), store(pointer, const(19, 4))).ret()
    caller = (FunctionBuilder().sub_rsp(0x48)
              .ins(add(reg(RCX), reg(RSP), const(0x20)), add(pointer, reg(RSP), const(0x30)),
                   store(reg(RCX), pointer), store(pointer, reg(R8, 4))))
    _address(caller, reg(RDI), reg(R8, 4), reg(RSI))
    caller.call(LEAF).ins(load(reg(RAX, 2), reg(RSI))).add_rsp(0x48).ret()
    units = program_units(caller, leaf)
    results = analyze_units(units)
    item = results["1:1000"]
    (call, effect), = item.normalized.proven_call_effects
    (access,) = [run.write for run in effect.memory_runs if run.write.index is not None]
    assert access.index.memory is not None and access.index.memory.pointer is not None
    planned = call_load_keys(call, effect)
    assert list(planned).index(access.index.memory.pointer) < list(planned).index(access.index.memory)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    report = _oracle(item, program)
    assert report.place_covered and report.through_calls


@pytest.mark.parametrize("engine", ["sparse", "dense"])
@pytest.mark.parametrize("source", ["index-memory", "base-pointer"])
@pytest.mark.parametrize("overlay", [False, True])
def test_indirect_register_anchor_cannot_hide_return_address_overlay(monkeypatch, engine, source, overlay):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    base, index, address = tmp(0x100), tmp(0x110, 4), tmp(0x120)
    leaf = FunctionBuilder(entry=LEAF)
    if source == "index-memory":
        leaf.ins(load(index, reg(RCX)))
        _address(leaf, reg(RDI), index, address)
        old, width = 2, 4
    else:
        leaf.ins(load(base, reg(RCX)))
        _address(leaf, base, reg(RDX, 4), address)
        old, width = 0x71000000, 8
    leaf.ins(store(address, reg(RAX, 2))).ret()
    caller = (FunctionBuilder().sub_rsp(0x48)
              .ins(add(reg(RCX), reg(RSP), const((-8 if overlay else 0) & MASK)),
                   store(reg(RCX), const(old, width))))
    # A CALL pushes exactly the next instruction address. Demand the real
    # target, not the stale pre-call bytes, so a false binding is observable.
    return_address = caller._address(len(caller._rows) + 2)
    if source == "index-memory":
        _address(caller, reg(RDI), const(return_address if overlay else old, 4), reg(RSI))
    else:
        _address(caller, const(return_address if overlay else old), reg(RDX, 4), reg(RSI))
    caller.call(LEAF)
    reader = f"1:{caller._address(len(caller._rows)):x}:0:LOAD"
    caller.ins(load(reg(RAX, 2), reg(RSI))).add_rsp(0x48).ret()
    units = program_units(caller, leaf)
    results = analyze_units(units)
    item = results["1:1000"]
    assert results[f"1:{LEAF:x}"].summary.address_relations
    references = [(evaluation, reference) for _, evaluation, reference in item.normalized.call_anchors
                  if type(reference) is tuple and reference[0] == "indexed"]
    projector = _final_projector(item.normalized, item.unit.observation)
    view = slice_from(item.normalized, item.normalized.dependencies.node_for_key("op:" + reader))
    if overlay and source == "base-pointer":
        # the base is the pushed return address itself: the push's literal
        # (``normalize._push_row``, an image address) places the write at
        # exactly the demanded bytes -- bound, and complete
        assert view.is_complete
    elif overlay:
        assert not references or all(projector._anchored_expression(key, reference, 8) is None
                                     for key, reference in references)
        assert not view.is_complete
    else:
        assert references and all(projector._anchored_expression(key, reference, 8) is not None
                                  for key, reference in references)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    report = _oracle(item, program)
    if not overlay or source == "base-pointer":
        assert report.place_covered and report.through_calls


def _indexed_references(item):
    return [(evaluation, reference) for _, evaluation, reference in item.normalized.call_anchors
            if type(reference) is tuple and reference[0] == "indexed"]


@pytest.mark.parametrize("engine", ["sparse", "dense"])
def test_independent_entry_anchor_cannot_be_assumed_disjoint_from_the_call_push(monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    index, address = tmp(0x100, 4), tmp(0x110)
    leaf = FunctionBuilder(entry=LEAF).ins(load(index, reg(RCX)))
    _address(leaf, reg(RDI), index, address)
    leaf.ins(store(address, reg(RAX, 2))).ret()
    caller = (FunctionBuilder().sub_rsp(0x48).ins(store(reg(RCX), const(2, 4)),
                                                add(reg(RSI), reg(RDI), const(6)))
              .call(LEAF))
    reader = f"1:{caller._address(len(caller._rows)):x}:0:LOAD"
    caller.ins(load(reg(RAX, 2), reg(RSI))).add_rsp(0x48).ret()
    units = program_units(caller, leaf)
    # Not without a named assumption: entry RCX may be the pushed slot -- the
    # CALL's push is a definition (``normalize._push_row``), so with
    # entry-values-do-not-address-the-new-frame off the index load through
    # RCX carries may-alias debt for it, and the indexed write through it is
    # not exact (docs 25.73). With the assumption (on by default) the index
    # load is exact and the use is reported.
    item = analyze_units(units, assume_entry_values_not_frame=False)["1:1000"]
    call = next(key for key in item.proven if key.endswith(":CALL"))
    assert any(row.operation_key.startswith(call + "~ld") and call + "~push" in row.writers
               for row in item.normalized.may_alias_reads)
    assert not slice_from(item.normalized, item.normalized.dependencies.node_for_key("op:" + reader)).is_complete
    assert not item.normalized.assumes_entry_values_not_frame
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    _oracle(item, program, lambda seed: {**_pools(seed), RCX: 0x73000000 + seed * 0x100})
    assumed = analyze_units(units)["1:1000"]
    assert assumed.normalized.assumes_entry_values_not_frame
    _oracle(assumed, program, lambda seed: {**_pools(seed), RCX: 0x73000000 + seed * 0x100})


@pytest.mark.parametrize("engine", ["sparse", "dense"])
def test_constant_near_zero_stack_and_wrapping_preload_have_no_exact_reuse(monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    index, address = tmp(0x100, 4), tmp(0x110)
    leaf = FunctionBuilder(entry=LEAF).ins(load(index, reg(RCX)))
    _address(leaf, reg(RDI), index, address)
    leaf.ins(store(address, reg(RAX, 2))).ret()
    caller = (FunctionBuilder().ins(copy(reg(RSP), const(4)),
                                   add(reg(RCX), reg(RSP), const((-8) & MASK)),
                                   store(reg(RCX), const(0x12345678)))
              .ins(add(reg(RSI), reg(RDI), const(6))).call(LEAF))
    reader = f"1:{caller._address(len(caller._rows)):x}:0:LOAD"
    caller.ins(load(reg(RAX, 2), reg(RSI))).ret()
    units = program_units(caller, leaf)
    item = analyze_units(units)["1:1000"]
    # (the stack pointer is the constant 4: the push lands at a constant
    # address below zero -- wrapping -- and the index load through RCX = 4 - 8
    # reads it; no exact reuse of the preload through the wrapped index)
    assert not slice_from(item.normalized, item.normalized.dependencies.node_for_key("op:" + reader)).is_complete
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    # Keep the demanded buffer outside the raw push bytes: this test concerns
    # the rejected wrapping index preload, not reading a removed transient
    # return-slot write through an unrelated escaped pointer.
    _oracle(item, program, lambda seed: {**_pools(seed), RDI: 0x71000000})


@pytest.mark.parametrize("engine", ["sparse", "dense"])
@pytest.mark.parametrize("rewrite_before_address_read", [False, True])
def test_memory_derived_index_slot_address_keeps_its_read_epoch_and_stale_validation(monkeypatch, engine,
                                                                                  rewrite_before_address_read):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    pointer, target, index, address = tmp(0x100), tmp(0x108), tmp(0x110, 4), tmp(0x120)
    leaf = FunctionBuilder(entry=LEAF).ins(load(index, reg(RCX)))
    _address(leaf, reg(RDI), index, address)
    leaf.ins(store(address, reg(RAX, 2))).ret()
    # P holds &X; PP holds &P. The indirect *PP=&Y store is resolved through
    # memory, and happens either before or after RCX reads P. The latter
    # must not retarget an already-read entry address to the new P contents.
    caller = (FunctionBuilder().sub_rsp(0x60)
              .ins(add(pointer, reg(RSP), const(0x20)), add(target, reg(RSP), const(0x30)), store(pointer, target))
              .ins(add(pointer, reg(RSP), const(0x28)), add(target, reg(RSP), const(0x20)), store(pointer, target))
              .ins(add(pointer, reg(RSP), const(0x30)), store(pointer, const(2, 4)),
                   add(pointer, reg(RSP), const(0x38)), store(pointer, const(5, 4)))
              .ins(add(pointer, reg(RSP), const(0x28)), load(pointer, pointer)))
    if rewrite_before_address_read:
        caller.ins(add(target, reg(RSP), const(0x38)), store(pointer, target))
    address_reader = f"1:{caller._address(len(caller._rows)):x}:1:LOAD"
    caller.ins(add(target, reg(RSP), const(0x20)), load(reg(RCX), target))
    if not rewrite_before_address_read:
        caller.ins(add(target, reg(RSP), const(0x38)), store(pointer, target))
    expected_index = 5 if rewrite_before_address_read else 2
    caller.ins(add(reg(RSI), reg(RDI), const(3 * expected_index))).call(LEAF)
    caller.ins(load(reg(RAX, 2), reg(RSI))).add_rsp(0x60).ret()
    units = program_units(caller, leaf)
    item = analyze_units(units)["1:1000"]
    projector = _final_projector(item.normalized, item.unit.observation)
    projector.used_reads = {}
    # The overlay guard evaluates the *address* of each preload too. Merely
    # re-reading its already-projected final SSA span would bypass that path.
    for _, evaluation, reference in item.normalized.call_anchors:
        projector._anchored_expression(evaluation, reference, 8)
    expressions = [projector._anchored_expression(key, reference, 8) for key, reference in _indexed_references(item)]
    assert expressions and all(value is None or value.displacement == 3 * expected_index for value in expressions)
    assert (address_reader, 8) in projector.used_reads
    used = projector.used_reads
    inputs = item.normalized.forward_inputs
    options = dict(bare=True, translation_namespace="x86:LE:64:default",
                   operation_overrides=dict(item.normalized.operation_overrides))
    assert not stale_reads(inputs.effect_unit, item.unit.observation, inputs.context, inputs.address_spaces,
                           item.normalized.memory_ssa, used, **options)
    wrong = {key: set(values) for key, values in used.items()}
    wrong[(address_reader, 8)] = {replace(value, displacement=value.displacement + 8)
                                  for value in wrong[(address_reader, 8)]}
    assert address_reader in stale_reads(inputs.effect_unit, item.unit.observation, inputs.context,
                                         inputs.address_spaces, item.normalized.memory_ssa, wrong, **options)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    report = _oracle(item, program)
    assert report.place_covered and report.through_calls
