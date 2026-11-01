"""Original pre-call value ports, not the one-byte staging dependency token."""

from dataclasses import fields, replace
from types import SimpleNamespace

import pytest

from forward_oracle import check_forward
from synthetic import (REG, RAX, RCX, RDI, RDX, RSP, FunctionBuilder,
                       add, const, copy, load, op, program_units, reg, store, tmp)
from tdo_v2._call_value_ports import scalar_call_rows
from tdo_v2.forward import forward_facts
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.interprocedural import analyze_units
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.normalize import FunctionNormalizer
from tdo_v2.relative_memory import _final_projector, constant_values


CALLEE, VALUE, REPLACEMENT = 0x1800, 0x520000, 0x999999


@pytest.fixture(params=("sparse", "dense"), autouse=True)
def _engine(monkeypatch, request):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    # Explicit forward consumers are checked independently of indirect rounds.
    monkeypatch.setenv("TDO_V2_FORWARD", "0")


def _fixture(kind="reg", *, value=VALUE, barrier=None):
    caller = FunctionBuilder().sub_rsp(0x28)
    if kind == "mem":
        caller.ins(add(reg(RCX), reg(RSP), const(0x10)), store(reg(RCX), const(value)))
    else:
        caller.ins(copy(reg(RCX), const(value)))
    if barrier == "source-call":
        caller.call(0x1f00)
    elif barrier == "source-memory":
        address = tmp(0x500)
        caller.ins(op("INT_MULT", [reg(RDI), reg(RDI)], address), store(address, const(7)))
    call = f"1:{caller._address(len(caller._rows)):x}:2:CALL"
    caller.call(CALLEE)
    key = f"1:{caller._address(len(caller._rows)):x}:0:LOAD"
    caller.ins(load(reg(RDX), reg(RAX))).add_rsp(0x28).ret()
    callee = FunctionBuilder(entry=CALLEE)
    if kind == "reg":
        callee.ins(copy(reg(RAX), reg(RCX)), copy(reg(RCX), const(REPLACEMENT)))
    elif kind == "off":
        callee.ins(add(reg(RAX), reg(RCX), const(0x20)), copy(reg(RCX), const(REPLACEMENT)))
    elif kind == "mem":
        callee.ins(load(reg(RAX), reg(RCX)), store(reg(RCX), const(REPLACEMENT)))
    elif kind == "const":
        callee.ins(copy(reg(RAX), const(value)))
    else:
        raise AssertionError(kind)
    callee.ret()
    units = program_units(caller, callee)
    item = analyze_units(units)["1:1000"]
    return item, units, call, key


def _facts(normalized, unit):
    return {fact.operation: fact for fact in forward_facts(normalized, unit)}


def _request(unit, key):
    operation = next(operation for instruction in unit.observation.instructions
                     for ordinal, operation in enumerate(instruction.operations)
                     if f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}:{ordinal}:{operation.opcode}" == key)
    return key, operation.inputs[1]


@pytest.mark.parametrize("kind", ("reg", "off", "mem", "const"))
@pytest.mark.parametrize("value", (VALUE, (1 << 64) - 16))
def test_original_full_width_call_value_drives_later_address_after_source_is_overwritten(kind, value):
    item, units, call, key = _fixture(kind, value=value)
    normalized = item.normalized
    port = scalar_call_rows(normalized)[call + "~0"]
    assert port.width == 8 and port.row[0] == kind
    action = next(action for action in normalized.memory_ssa.actions if action.operation_key == call + "~in0")
    assert len(action.write_definition_ids) == 1
    token = normalized.memory_ssa.definitions[action.write_definition_ids[0]]
    assert token.span.size == 1  # dependency aggregation is not the scalar's width
    expected = (value + (0x20 if kind == "off" else 0)) & ((1 << 64) - 1)
    fact = _facts(normalized, item.unit)[key]
    assert fact.claim.single_number() == expected and fact.input == 1
    request = _request(item.unit, key)
    assert constant_values(normalized, item.unit.observation, [request], addresses=True) == {request: expected}
    # Other projector consumers do not globally acquire a new interpretation.
    assert _final_projector(normalized, item.unit.observation)._pointer_rows == {}
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    report = check_forward(item.unit, [fact], seeds=range(3),
                           register_pools=lambda _: {RSP: 0x70000000, RDI: 0x30000000},
                           program=program, havoc_calls=(REG, RSP, 8))
    assert report.checked == 3 and not report.failures and not report.skipped


@pytest.mark.parametrize("kind", ("reg", "off", "mem"))
def test_disabling_only_the_call_value_port_reproduces_the_missing_consumer(monkeypatch, kind):
    from tdo_v2 import _call_value_ports

    item, _, _, key = _fixture(kind)
    before = item.normalized
    assert key in _facts(before, item.unit)
    with monkeypatch.context() as patch:
        patch.setattr(_call_value_ports, "scalar_call_rows", lambda _: {})
        assert key not in _facts(before, item.unit)
        assert not constant_values(before, item.unit.observation, [_request(item.unit, key)], addresses=True)
    # Consumer-only: no rebuilding or weakening of the original SSA/debts.
    assert item.normalized is before


@pytest.mark.parametrize("change", ("condition", "writer-condition", "null-fresh", "wrong-width", "overlap"))
def test_unproved_or_incompatible_output_is_not_an_unconditional_scalar_port(change):
    item, _, call, key = _fixture()
    effect = dict(item.normalized.proven_call_effects)[call]
    run = effect.runs[0]
    anchor = next(run for run in effect.runs if run.loads).loads[0]
    if change == "condition":
        effect = replace(effect, runs=(replace(run, conditions=((anchor, anchor),)), *effect.runs[1:]))
    elif change == "writer-condition":
        effect = replace(effect, writer_conditions=((anchor, anchor),))
    elif change == "null-fresh":
        effect = replace(effect, runs=(replace(run, value=(*run.value[:2], True)), *effect.runs[1:]))
    elif change == "wrong-width":
        effect = replace(effect, runs=(replace(run, writes=(replace(run.writes[0], size=4),)), *effect.runs[1:]))
    else:
        unknown = replace(run, writes=(replace(run.writes[0], size=4),), reads=(), value=None)
        effect = replace(effect, runs=(*effect.runs, unknown))
    normalized = FunctionNormalizer().normalize(item.unit, proven_call_effects={call: effect})
    assert call + "~0" not in scalar_call_rows(normalized)
    assert key not in _facts(normalized, item.unit)
    assert not constant_values(normalized, item.unit.observation, [_request(item.unit, key)], addresses=True)
    if change == "overlap":
        assert run.writes[0].overlaps(unknown.writes[0])


@pytest.mark.parametrize("kind,barrier", (("reg", "source-call"), ("off", "source-call"),
                                         ("mem", "source-memory")))
def test_independent_source_debt_is_not_healed_by_the_call_value_contract(kind, barrier):
    item, _, call, key = _fixture(kind, barrier=barrier)
    normalized = item.normalized
    assert call + "~0" in scalar_call_rows(normalized)
    assert key not in _facts(normalized, item.unit)
    if barrier == "source-call":
        assert any(row.operation_key == call + "~in0" for row in normalized.call_clobber_reads)
    else:
        port = scalar_call_rows(normalized)[call + "~0"]
        assert port.row[0] == "mem"
        assert any(row.operation_key == port.row[1] for row in normalized.may_alias_reads)


@pytest.mark.parametrize("change", ("stage", "source", "width", "fresh", "tag"))
def test_pointer_metadata_without_matching_original_run_is_not_a_value_proof(change):
    item, _, call, _ = _fixture()
    rows = dict(item.normalized.pointer_rows)
    row = rows[call + "~0"]
    if change == "stage":
        row = (row[0], call + "~in1", *row[2:])
    elif change == "source":
        row = (*row[:2], replace(row[2], coordinate=replace(row[2].coordinate, byte_offset=RDX)), *row[3:])
    elif change == "width":
        row = (*row[:2], replace(row[2], byte_size=4), *row[3:])
    elif change == "fresh":
        row = (*row[:3], True, row[4])
    else:
        row = ("const", 8, VALUE)
    rows[call + "~0"] = row
    normalized = replace(item.normalized, pointer_rows=tuple(rows.items()))
    assert call + "~0" not in scalar_call_rows(normalized)


@pytest.mark.parametrize("width", (1, 4))
@pytest.mark.parametrize("extend", (False, True))
def test_narrow_scalar_covers_only_its_original_bytes_without_implicit_upper_zeroing(width, extend):
    value = (1 << (8 * width)) - 2
    caller = FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX, width), const(value, width))).call(CALLEE)
    address = reg(RAX)
    if extend:
        address = tmp(0x600)
        caller.ins(op("INT_ZEXT", [reg(RAX, width)], address))
    key = f"1:{caller._address(len(caller._rows)):x}:0:LOAD"
    caller.ins(load(reg(RDX), address)).add_rsp(0x28).ret()
    callee = FunctionBuilder(entry=CALLEE).ins(copy(reg(RAX, width), reg(RCX, width))).ret()
    item = analyze_units(program_units(caller, callee))["1:1000"]
    call, effect = item.normalized.proven_call_effects[0]
    run = effect.runs[0]
    # The original COPY body now produces this exact narrow identity itself;
    # its consumer still may not invent an implicit zero-upper write.
    assert run.writes[0].size == run.reads[0].size == width
    assert run.value == ("same_reg", run.reads[0], False)
    normalized = item.normalized
    assert any(port.width == width and port.row[0] == "reg" for port in scalar_call_rows(normalized).values())
    fact = _facts(normalized, item.unit).get(key)
    if extend:
        assert fact is not None and fact.claim.single_number() == value
    else:
        # Synthetic raw register COPY is not an ISA-specific zero-upper write.
        assert fact is None or fact.claim.single_number() is None


@pytest.mark.parametrize("forward", (False, True))
def test_cold_numeric_candidate_cannot_bypass_source_call_clobber_target_gate(monkeypatch, forward):
    monkeypatch.setenv("TDO_V2_FORWARD", "1" if forward else "0")
    target = 0x1a00
    caller = (FunctionBuilder().sub_rsp(0x28).ins(copy(reg(RCX), const(target))).call(0x1f00)
              .call(CALLEE))
    indirect = f"1:{caller._address(len(caller._rows)):x}:3:CALLIND"
    caller.call_indirect(RAX).add_rsp(0x28).ret()
    callee = FunctionBuilder(entry=CALLEE).ins(copy(reg(RAX), reg(RCX))).ret()
    results = analyze_units(program_units(caller, callee, FunctionBuilder(entry=target).ret()))
    item = results["1:1000"]
    assert indirect not in item.calls and indirect not in item.multi_calls
    assert indirect not in _facts(item.normalized, item.unit)
    graph = item.normalized.dependencies
    snapshot = indirect.rsplit(":", 2)[0] + ":0:COPY"
    reachable = graph.backward_reachable((graph.node_for_key("op:" + snapshot),))
    assert any(graph.node(node).kind is NodeKind.MEMORY_DEBT for node in reachable)


@pytest.mark.parametrize("boundary", ("unresolved", "unknown-address", "wild"))
def test_unplaced_unknown_address_or_wild_memory_source_is_not_a_scalar_port(boundary):
    if boundary == "unresolved":
        caller = (FunctionBuilder().sub_rsp(0x28)
                  .ins(op("INT_MULT", [reg(RDI), reg(RDI)], reg(RCX)), store(reg(RCX), const(VALUE)))
                  .call(CALLEE))
        key = f"1:{caller._address(len(caller._rows)):x}:0:LOAD"
        caller.ins(load(reg(RDX), reg(RAX))).add_rsp(0x28).ret()
        callee = FunctionBuilder(entry=CALLEE).ins(load(reg(RAX), reg(RCX))).ret()
        item = analyze_units(program_units(caller, callee))["1:1000"]
        normalized = item.normalized
        call = normalized.proven_call_effects[0][0]
        stage = dict(normalized.pointer_rows)[call + "~0"][1]
        assert any(normalized.memory_ssa.actions[row.action_id].operation_key == stage
                   for row in normalized.memory_ssa.unresolved_reads)
    else:
        item, _, call, key = _fixture("mem", barrier="source-memory")
        normalized = item.normalized
        stage = dict(normalized.pointer_rows)[call + "~0"][1]
        row = next(row for row in normalized.may_alias_reads if row.operation_key == stage)
        assert row.spans and not row.unknown_address
        # State-boundary defense: retain the original debt/node identity but
        # mark the staged source unavailable. Neither change is a raw run.
        if boundary == "unknown-address":
            changed = replace(row, spans=(), unknown_address=True)
            normalized = replace(normalized, may_alias_reads=tuple(
                changed if original is row else original for original in normalized.may_alias_reads))
        else:
            normalized = replace(normalized, wild_objects=normalized.wild_objects | {row.spans[0].object_id})
    assert call + "~0" not in scalar_call_rows(normalized)
    assert key not in _facts(normalized, item.unit)


@pytest.mark.parametrize("conflicting", (False, True))
def test_repeated_staging_source_reads_require_identical_original_fragments(conflicting):
    item, _, call, key = _fixture()
    effect = dict(item.normalized.proven_call_effects)[call]
    run = effect.runs[0]
    effect = replace(effect, runs=(replace(run, reads=run.reads * 2), *effect.runs[1:]))
    normalized = FunctionNormalizer().normalize(item.unit, proven_call_effects={call: effect})
    ssa = normalized.memory_ssa
    source = [read for read in ssa.reads if ssa.actions[read.action_id].operation_key == call + "~in0"]
    assert len(source) == 2 and source[0].span == source[1].span and source[0].fragments == source[1].fragments
    if conflicting:
        entry = next(i for i, definition in enumerate(ssa.definitions)
                     if definition.kind is MemoryDefinitionKind.ENTRY and definition.span.contains(source[0].span))
        altered = replace(source[1], fragments=(replace(source[1].fragments[0], definition_ids=(entry,)),))
        assert altered.fragments != source[0].fragments
        # Malformed-SSA defense only: normal SSA never gives two different
        # values to the same pre-call span at one staging action.
        changed = replace(ssa, reads=tuple(altered if read is source[1] else read for read in ssa.reads))
        with pytest.raises(ValueError, match="exact artifact chain"):
            replace(normalized, memory_ssa=changed)
        assert normalized.memory_graph.local_reads is None and normalized.memory_graph.image_reads is None
        # The public constructor already refused it. A non-authoritative
        # stand-in separately checks the lower scalar consumer's defense;
        # it is never returned as an authentic normalized function.
        normalized = SimpleNamespace(**{field.name: getattr(normalized, field.name) for field in fields(normalized)})
        normalized.memory_ssa = changed
    assert call + "~0" in scalar_call_rows(normalized)
    fact = _facts(normalized, item.unit).get(key)
    if conflicting:
        assert fact is None
    else:
        assert fact is not None and fact.claim.single_number() == VALUE
