"""Real call execution checks the scalar-literal consumer, not a second summary."""

from dataclasses import replace

import pytest

from forward_oracle import check_forward
from pcode_interpreter import Interpreter
from program_oracle import check_program
from synthetic import (
    CODE_BASE, CONST, RAM, RAX, RBX, RCX, RDI, RDX, REG, RSP, FunctionBuilder, add, const,
    load, op, program_units, reg, slice_from, store, tmp,
)
from tdo_v2.constant_value import ExactConstant
from tdo_v2.forward import Interval, Value, forward_facts
from tdo_v2.interprocedural import analyze_units
from tdo_v2.normalize import FunctionNormalizer
from tdo_v2.relative_memory import _AddressExpression, _final_projector
from tdo_v2.span_geometry import ByteSpan, StorageObjectKind


CALLEE = CODE_BASE + 0x800
LITERAL = 0x00000003FFFFFFFE
FRAME = 0x48
SLOT = 0x20
MASK = (1 << 64) - 1


def _fixture(extension="INT_SEXT", value=LITERAL):
    slot, part, wide, address = tmp(0x100), tmp(0x110, 4), tmp(0x120), tmp(0x130)
    caller = (FunctionBuilder().sub_rsp(FRAME)
              .ins(add(reg(RCX), reg(RSP), const(SLOT)))
              .call(CALLEE))
    keys = {}

    def ins(name, ordinal, *operations):
        keys[name] = f"1:{caller._address(len(caller._rows)):x}:{ordinal}:{operations[ordinal][0]}"
        caller.ins(*operations)

    parts = {"low": part, "high": tmp(0x114, 4)}
    for name, offset in (("low", 0), ("high", 4)):
        part = parts[name]
        ins(name + "_part", 1, add(slot, reg(RSP), const(SLOT + offset)), load(part, slot))
    for name, offset, data in (("low", 0, RDX), ("high", 4, RBX)):
        part = parts[name]
        caller.ins(op(extension, [part], wide), op("INT_MULT", [wide, const(4)], address),
                   add(address, reg(RDI), address))
        ins(name + "_store", 0, store(address, reg(data, 4)))
        ins(name + "_load", 0, load(reg(RAX, 4), address))
    caller.add_rsp(FRAME).ret()
    callee = FunctionBuilder(entry=CALLEE).ins(store(reg(RCX), const(value))).ret()
    return caller, callee, keys


def _analyze(monkeypatch, engine="sparse", forward=True, extension="INT_SEXT", value=LITERAL):
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_FORWARD", "1" if forward else "0")
    caller, callee, keys = _fixture(extension, value)
    units = program_units(caller, callee)
    item = analyze_units(units)["1:1000"]
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    return item, program, keys


def _pools(seed):
    return {RSP: 0x70000000, RDI: 0x30000000 + seed * 0x100,
            RDX: 0x10203040 + seed, RBX: 0xA0B0C0D0 + seed}


def _offset(value, offset, extension):
    part = (value >> (8 * offset)) & 0xFFFFFFFF
    if extension == "INT_SEXT" and part & 0x80000000:
        part -= 1 << 32
    return 4 * part


def _literal_definition(item):
    normalized = item.normalized
    rows = dict(normalized.pointer_rows)
    return next((identifier, definition) for identifier, definition in enumerate(normalized.memory_ssa.definitions)
                if rows.get(definition.operation_key, (None,))[0] == "const"
                and definition.span.object_id.kind is not StorageObjectKind.REGISTER_FILE
                and definition.span.size == 8)


@pytest.mark.parametrize("engine,forward", [("sparse", False), ("sparse", True), ("dense", False), ("dense", True)])
@pytest.mark.parametrize("extension", ["INT_SEXT", "INT_ZEXT"])
def test_full_call_literal_drives_both_four_byte_addresses_and_keeps_actual_writers(monkeypatch, engine,
                                                                                  forward, extension):
    item, program, keys = _analyze(monkeypatch, engine, forward, extension)
    normalized = item.normalized
    ((call, effect),) = normalized.proven_call_effects
    assert [run.literal for run in effect.memory_runs] == [ExactConstant(8, LITERAL)]
    facts = forward_facts(normalized, item.unit)
    by_key = {fact.operation: fact for fact in facts}
    for name, offset in (("low", 0), ("high", 4)):
        displacement = _offset(LITERAL, offset, extension)
        assert by_key[keys[name + "_load"]].claim == Value(
            64, ((("entry", RDI, 8), Interval.offset(displacement, 64)),))
        read = next(read for read in normalized.memory_ssa.reads
                    if normalized.memory_ssa.actions[read.action_id].operation_key == keys[name + "_part"]
                    and read.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE)
        assert read.span.size == 4 and len(read.fragments) == 1
        (identifier,) = read.fragments[0].definition_ids
        assert dict(normalized.pointer_rows)[normalized.memory_ssa.definitions[identifier].operation_key] \
            == ("const", 8, LITERAL)
    report = check_program(normalized, item.unit.observation, program, seeds=range(8),
                           register_pools=_pools, havoc_calls=(REG, RSP, 8))
    assert report.runs == 8 and report.checked and report.place_checked and not report.unsupported
    assert not report.silent and not report.place_failed and not report.place_unlocated_only
    checked = check_forward(item.unit, facts, seeds=range(8), register_pools=_pools,
                            program=program, havoc_calls=(REG, RSP, 8))
    assert checked.runs == 8 and checked.checked and not checked.failures and not checked.skipped
    for seed in range(8):
        machine = Interpreter(item.unit.observation, constant_space=CONST, seed=seed, program=program,
                              havoc_calls=(REG, RSP, 8), track_provenance=True)
        for register, value in _pools(seed).items():
            machine.preset(REG, register, 8, value)
        run = machine.run()
        assert run.completed
        written = machine.final_bytes()
        slot = _pools(seed)[RSP] - FRAME + SLOT
        assert [written[(RAM, slot + byte)][0] for byte in range(8)] == list(LITERAL.to_bytes(8, "little"))
        assert {written[(RAM, slot + byte)][1] for byte in range(8)} == {call}
        for name, offset, data in (("low", 0, RDX), ("high", 4, RBX)):
            address = (_pools(seed)[RDI] + _offset(LITERAL, offset, extension)) & MASK
            dependencies = [row for row in run.dependencies
                            if row.reader == keys[name + "_load"] and row.space_id == RAM]
            assert {(row.offset, row.writer) for row in dependencies} == {
                (address + byte, keys[name + "_store"]) for byte in range(4)}
            assert [written[(RAM, address + byte)][0] for byte in range(4)] == \
                list(_pools(seed)[data].to_bytes(4, "little"))


@pytest.mark.parametrize("change", ["BE", "overrun", "wrong-width", "bool-width", "bool-value", "negative",
                                    "overflow", "extra-field"])
def test_direct_literal_projector_rejects_unproven_metadata_or_slices(monkeypatch, change):
    item, _, _ = _analyze(monkeypatch)
    identifier, definition = _literal_definition(item)
    projector = _final_projector(item.normalized, item.unit.observation)
    projector._pointer_rows = dict(item.normalized.pointer_rows)
    low = ByteSpan(definition.span.object_id, definition.span.start, 4)
    assert projector._literal_row(definition, low) == _AddressExpression((), LITERAL & 0xFFFFFFFF, 4)
    high = replace(low, start=low.start + 4)
    assert projector._literal_row(definition, high) == _AddressExpression((), LITERAL >> 32, 4)
    if change == "BE":
        projector._translation_namespace = "x86:BE:64:default"
    elif change == "overrun":
        low = replace(low, start=low.start + 6)
    else:
        rows = {"wrong-width": ("const", 4, 0), "bool-width": ("const", True, 0),
                "bool-value": ("const", 8, False), "negative": ("const", 8, -1),
                "overflow": ("const", 8, 1 << 64), "extra-field": ("const", 8, 0, "fresh")}
        projector._pointer_rows[definition.operation_key] = rows[change]
    assert projector._literal_row(definition, low) is None
    assert not projector._fresh_atoms and not projector._nonstack_atoms


def test_zero_literal_is_a_number_not_a_fresh_allocation(monkeypatch):
    item, _, _ = _analyze(monkeypatch, value=0)
    identifier, definition = _literal_definition(item)
    projector = _final_projector(item.normalized, item.unit.observation)
    projector._pointer_rows = dict(item.normalized.pointer_rows)
    assert projector._expression_for_definition(identifier, definition.span) == _AddressExpression((), 0, 8)
    assert not projector._fresh_atoms and not projector._nonstack_atoms
    (_, effect), = item.normalized.proven_call_effects
    assert not effect.fresh_registers and not effect.same_object_registers
    assert effect.memory_runs[0].value is None


def test_conditional_literal_has_no_const_metadata_until_its_condition_is_resolved(monkeypatch):
    item, _, keys = _analyze(monkeypatch)
    (call, effect), = item.normalized.proven_call_effects
    memory = effect.memory_runs[0]
    # The place pair is intentionally overlapping: this is not an added
    # assumption, and a consumer must not turn its conditional bits into an
    # unconditional exact address before deciding it.
    pair = (memory.write, memory.write)
    for conditional in (replace(effect, memory_runs=(replace(memory, conditions=(pair,)),)),
                        replace(effect, writer_conditions=(pair,))):
        normalized = FunctionNormalizer().normalize(item.unit, proven_call_effects={call: conditional})
        assert not any(row[0] == "const" for _, row in normalized.pointer_rows)
        assert dict(normalized.proven_call_effects)[call] == conditional
        facts = {fact.operation: fact for fact in forward_facts(normalized, item.unit)}
        for name, offset in (("low", 0), ("high", 4)):
            fact = facts.get(keys[name + "_load"])
            expected = Value(64, ((("entry", RDI, 8), Interval.offset(_offset(LITERAL, offset, "INT_SEXT"), 64)),))
            assert fact is None or fact.claim != expected


def test_unknown_write_debt_is_not_erased_by_a_previous_exact_call_literal(monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    slot, unknown = tmp(0x100), tmp(0x108)
    caller = (FunctionBuilder().sub_rsp(FRAME)
              .ins(add(reg(RCX), reg(RSP), const(SLOT))).call(CALLEE)
              .ins(op("INT_MULT", [reg(RDI), reg(RDI)], unknown), store(unknown, const(9)))
              .ins(add(slot, reg(RSP), const(SLOT)), load(reg(RAX, 4), slot)).add_rsp(FRAME).ret())
    callee = FunctionBuilder(entry=CALLEE).ins(store(reg(RCX), const(LITERAL))).ret()
    units = program_units(caller, callee)
    item = analyze_units(units)["1:1000"]
    key = "1:1010:1:LOAD"
    assert any(row.operation_key == key for row in item.normalized.may_alias_reads)
    view = slice_from(item.normalized, item.normalized.dependencies.node_for_key("op:" + key))
    assert not view.is_complete
    assert any(run.literal is None for exit in item.summary.exits for run in exit.runs
               if run.span.object_id.kind is StorageObjectKind.REGISTER_FILE and run.span.start == RAX)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    report = check_program(item.normalized, item.unit.observation, program, seeds=range(8),
                           register_pools=_pools, havoc_calls=(REG, RSP, 8))
    assert report.runs == 8 and report.checked and not report.silent and not report.unsupported
