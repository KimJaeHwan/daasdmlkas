"""Byte-lane slices (``tdo_v2.lane_slice``, docs 25.6 B2a): fixtures, the
bit-flip table test of the lane maps, and the lane oracle on random functions."""

import random
from types import SimpleNamespace

import pytest

import test_graph_fidelity as fidelity
from lane_oracle import check_lanes
from pcode_interpreter import Interpreter
from synthetic import (
    RAX, RBX, RCX, RDI, RDX, RSI, RSP, FunctionBuilder, add, const, copy, load, normalize_with_observation, op,
    program_units, reg, store, tmp,
)
from tdo_v2.interprocedural import analyze_units
from tdo_v2.lane_slice import FULL, lane_slice, reached_bytes
from tdo_v2.span_geometry import ByteSpan


def _analyzed(builder):
    (unit,) = program_units(builder)
    results = analyze_units([unit])
    return results["1:1000"].normalized, unit


def _seed_register(normalized, unit, opcode_suffix, register, size):
    """The definition node of the last operation ``opcode_suffix`` writing ``register``."""
    from lane_oracle import _output_definition
    from tdo_v2.model import ResolvedStorage
    from tdo_v2.normalize import _storage_ref
    from tdo_v2.storage import _resolve_validated_storage

    found = None
    for instruction in unit.observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            output = operation.output
            if operation.opcode == opcode_suffix and output is not None and output.coordinate.byte_offset == register \
                    and output.byte_size == size:
                resolved = _resolve_validated_storage(_storage_ref(output), unit.scopes.resolution_context)
                assert type(resolved) is ResolvedStorage
                key = f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}:{ordinal}:{operation.opcode}"
                found = (_output_definition(normalized, key, resolved.span), resolved.span)
    return found


def _copy_then_read(offset):
    """[rsp+0x10] = esi (A); [rsp+0x14] = edx (B); rax = [rsp+0x10] (8 bytes);
    [rdi] = rax; ecx = [rdi + offset] (4 bytes)."""
    t = tmp(0x100)
    return (FunctionBuilder().sub_rsp(0x40)
            .ins(add(t, reg(RSP), const(0x10)), store(t, reg(RSI, 4)))
            .ins(add(t, reg(RSP), const(0x14)), store(t, reg(RDX, 4)))
            .ins(add(t, reg(RSP), const(0x10)), load(reg(RAX), t))
            .ins(store(reg(RDI), reg(RAX)))
            .ins(add(t, reg(RDI), const(offset)), load(reg(RCX, 4), t))
            .add_rsp(0x40).ret())


@pytest.mark.parametrize("offset, kept, dropped", [(0, RSI, RDX), (4, RDX, RSI)])
def test_a_half_read_of_a_copied_pair_reaches_only_its_half(offset, kept, dropped):
    normalized, unit = _analyzed(_copy_then_read(offset))
    node, span = _seed_register(normalized, unit, "LOAD", RCX, 4)
    lanes = lane_slice(normalized, unit, [(node, (span,))])
    registers = reached_bytes(lanes, normalized)
    assert set(range(kept, kept + 4)) <= registers
    assert not registers & set(range(dropped, dropped + 4))
    # the node slice reaches both (today's behaviour)
    from synthetic import slice_from
    assert set(range(dropped, dropped + 4)) <= slice_from(normalized, node).register_bytes


def test_a_full_seed_reaches_what_the_node_slice_reaches():
    normalized, unit = _analyzed(_copy_then_read(0))
    node, _ = _seed_register(normalized, unit, "LOAD", RCX, 4)
    lanes = lane_slice(normalized, unit, [(node, ())])
    assert lanes.demands[node] is FULL
    from synthetic import slice_from
    assert reached_bytes(lanes, normalized) == {b for b in slice_from(normalized, node).register_bytes
                                                if b in reached_bytes(lanes, normalized)}


@pytest.mark.parametrize("opcode, maps", [
    ("SUBPIECE", None), ("PIECE", None), ("INT_ZEXT", None), ("INT_SEXT", None),
    ("INT_AND", None), ("INT_OR", None), ("INT_XOR", None), ("INT_NEGATE", None), ("COPY", None),
])
def test_the_lane_maps_hold_for_the_concrete_operations(opcode, maps):
    """Flip one input byte the map says an output byte does not depend on: that
    output byte never changes (bit-flip table test against the interpreter's
    arithmetic)."""
    from tdo_v2.lane_slice import _operand_demands

    rng = random.Random(hash(opcode) & 0xFFFF)

    def varnode(size, constant=None):
        if constant is not None:
            return SimpleNamespace(byte_size=size, kind=SimpleNamespace(name="CONSTANT"),
                                   coordinate=SimpleNamespace(byte_offset=constant))
        return SimpleNamespace(byte_size=size, kind=SimpleNamespace(name="REGISTER"),
                               coordinate=SimpleNamespace(byte_offset=0))

    from tdo_v2._scope_contracts import VarnodeKindCode
    shapes = []
    for size in (1, 2, 4, 8):
        if opcode == "SUBPIECE":
            for out in (1, 2, 4):
                for shift in range(0, size - out + 1) if out < size else ():
                    shapes.append(([size, ("const", shift)], out))
        elif opcode == "PIECE" and size <= 4:
            shapes.append(([size, size], 2 * size))
        elif opcode in ("INT_ZEXT", "INT_SEXT"):
            for wide in (2, 4, 8):
                if wide > size:
                    shapes.append(([size], wide))
        elif opcode in ("INT_AND", "INT_OR", "INT_XOR"):
            shapes.append(([size, size], size))
        elif opcode in ("INT_NEGATE", "COPY"):
            shapes.append(([size], size))
    assert shapes
    for input_shapes, out_size in shapes:
        inputs = []
        for shape in input_shapes:
            if type(shape) is tuple:
                node = SimpleNamespace(byte_size=4, kind=VarnodeKindCode.CONSTANT,
                                       coordinate=SimpleNamespace(byte_offset=shape[1]))
            else:
                node = SimpleNamespace(byte_size=shape, kind=VarnodeKindCode.REGISTER,
                                       coordinate=SimpleNamespace(byte_offset=0))
            inputs.append(node)
        output = SimpleNamespace(byte_size=out_size)
        operation = SimpleNamespace(opcode=opcode, inputs=inputs, output=output)
        for out_byte in range(out_size):
            demand = _operand_demands((operation, (), None), frozenset({out_byte}))
            for _ in range(40):
                values = [node.coordinate.byte_offset if node.kind is VarnodeKindCode.CONSTANT
                          else rng.getrandbits(8 * node.byte_size) for node in inputs]
                base = Interpreter._compute(opcode, values, inputs, output) >> (8 * out_byte) & 0xFF
                for position, node in enumerate(inputs):
                    if node.kind is VarnodeKindCode.CONSTANT:
                        continue
                    used = demand.get(position, frozenset())
                    for byte in range(node.byte_size):
                        if byte in used:
                            continue
                        flipped = list(values)
                        flipped[position] ^= rng.randrange(1, 256) << (8 * byte)
                        after = Interpreter._compute(opcode, flipped, inputs, output) >> (8 * out_byte) & 0xFF
                        assert after == base, (opcode, input_shapes, out_size, out_byte, position, byte)


@pytest.mark.parametrize("chunk", range(4))
def test_random_functions_lane_slices_cover_the_concrete_lanes(chunk):
    missing, unclassified, checked, not_subset = [], 0, 0, 0
    for seed in range(chunk * 50, chunk * 50 + 50):
        builder = fidelity._random_function(random.Random(90_000 + seed))
        try:
            normalized, unit = _analyzed(builder)
        except AssertionError:
            continue
        report = check_lanes(normalized, unit, seeds=range(3), register_pools=fidelity._inputs_with_bounded_loop)
        missing += [(seed, item) for item in report.missing]
        unclassified += report.unclassified
        checked += report.checked
        not_subset += report.not_subset
    assert checked > 0
    assert not_subset == 0
    assert missing == [], missing[:5]


def test_a_seed_whose_selector_is_another_object_demands_everything():
    """x86-32 sink argument: the selector is the stack slot, the definition the
    temporary holding the value -- the slot's bytes say nothing about the
    temporary's lanes: FULL (an empty demand would lose every origin)."""
    normalized, unit = _analyzed(_copy_then_read(0))
    node, span = _seed_register(normalized, unit, "LOAD", RCX, 4)
    elsewhere = ByteSpan(normalized.memory_ssa.definitions[0].span.object_id, 0x7FFF_0000, 4)
    if elsewhere.object_id == span.object_id:
        elsewhere = ByteSpan(elsewhere.object_id, span.end + 0x100, 4)
    lanes = lane_slice(normalized, unit, [(node, (elsewhere,))])
    assert lanes.demands[node] is FULL
    # FULL on the 4-byte definition: all of its own bytes (the A half)
    assert set(range(RSI, RSI + 4)) <= reached_bytes(lanes, normalized)
    # an empty demand (the bug this guards against) would reach no input at all
    assert lane_slice(normalized, unit, [(node, ())]).nodes == lanes.nodes


def test_a_source_row_on_an_operation_node_counts_as_spanless():
    """Absolute storage bytes and an operation's result-byte indices are
    different coordinates: a SOURCE row with spans bound to an operation node
    counts whenever that node is reached (never lost to a wrong comparison)."""
    from types import SimpleNamespace as Row
    from tdo_v2.boundary import BoundaryKind
    from tdo_v2.summary_engine import _lane_origin_labels

    normalized, unit = _analyzed(_copy_then_read(0))
    node, span = _seed_register(normalized, unit, "LOAD", RCX, 4)
    lanes = lane_slice(normalized, unit, [(node, (span,))])
    operation_nodes = [item for item in lanes.nodes if normalized.dependencies.node(item).kind.name == "OPERATION"]
    assert operation_nodes
    far = ByteSpan(span.object_id, span.start + 0x1000, 4)   # coordinates no result byte index equals
    rows = [Row(kind=BoundaryKind.SINK, label="sink", occurrence_ordinal=0, node=node, physical_spans=(span,)),
            Row(kind=BoundaryKind.SOURCE, label="src", occurrence_ordinal=0, node=operation_nodes[0],
                physical_spans=(far,))]
    found = _lane_origin_labels(Row(normalized=normalized), unit, rows, "sink", 0, {"src"})
    assert found == {"src"}


def test_a_join_byte_no_source_covers_demands_every_source_fully():
    from types import SimpleNamespace as NS
    from tdo_v2.lane_slice import _definition
    from tdo_v2.memory_contracts import MemoryDefinitionKind

    normalized, _ = _analyzed(_copy_then_read(0))
    obj = normalized.memory_ssa.definitions[0].span.object_id
    join = NS(kind=MemoryDefinitionKind.JOIN, span=ByteSpan(obj, 0x100, 8))
    narrow = NS(kind=MemoryDefinitionKind.DATA_WRITE, span=ByteSpan(obj, 0x100, 4))
    index = NS(definition_of={10: 0}, ssa=NS(definitions=[join, narrow]), joins={0: (1,)}, definition_node=[10, 11],
               graph=NS(in_edges=lambda node: []))
    added = []
    _definition(index, 10, frozenset({0x105}), lambda node, demand: added.append((node, demand)))
    assert added == [(11, FULL)]
    added.clear()
    _definition(index, 10, frozenset({0x101}), lambda node, demand: added.append((node, demand)))
    assert added == [(11, frozenset({0x101}))]


def _nested_call_program():
    """callee: call leaf (opaque to the analysis, havoced in the run: writes
    rax); rbx = rax; ret. caller: call callee; r9 = rbx; ret -- the value the
    caller reads was produced by a call nested in the callee and moved by it
    before returning."""
    from synthetic import CODE_BASE, R9

    callee_entry, leaf_entry = CODE_BASE + 0x800, CODE_BASE + 0xC00
    leaf = FunctionBuilder(entry=leaf_entry).ret()
    callee = (FunctionBuilder(entry=callee_entry).sub_rsp(0x28)
              .call(leaf_entry)
              .ins(copy(reg(RBX), reg(RAX)))
              .add_rsp(0x28).ret())
    caller = (FunctionBuilder().sub_rsp(0x28)
              .ins(copy(reg(RAX), reg(RCX)))   # the run havocs the registers the caller names
              .call(callee_entry)
              .ins(copy(reg(R9), reg(RBX)))
              .add_rsp(0x28).ret())
    units = program_units(caller, callee, leaf)
    results = analyze_units(units[:2])   # the leaf: no summary (an opaque call)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units[:2]}
    return results["1:1000"], program


def _nested_report(analyzed, program):
    from synthetic import REG

    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    return check_lanes(analyzed.normalized, analyzed.unit, seeds=range(3), register_pools=pools,
                       havoc_calls=(REG, RSP, 8), program=program)


def test_a_byte_a_nested_call_produced_is_checked_where_the_callee_left_it(monkeypatch):
    """When the outermost call returns, every byte its activation left written
    is that call's product at its current place (rbx, not the inner call's
    rax): the exact register-byte check applies -- a wrong byte map on the
    caller's own copy is caught, not hidden behind "the call is reached"."""
    import tdo_v2.lane_slice as lane_slice_module

    analyzed, program = _nested_call_program()
    report = _nested_report(analyzed, program)
    assert report.checked > 0 and report.nested == 0
    assert report.missing == []
    original = lane_slice_module._operand_demands

    def shifted(found, demand):
        result = original(found, demand)
        if result is not None and found[0].opcode == "COPY":
            return {0: frozenset(byte + 1 for byte in result[0])}
        return result

    monkeypatch.setattr(lane_slice_module, "_operand_demands", shifted)
    assert _nested_report(analyzed, program).missing


def test_an_occurrence_canonicalization_partly_dropped_keeps_all_its_root_nodes():
    """Occurrence 0 binds node A; occurrence 1 binds A and B -- canonicalization
    keeps one row per (kind, label, node), so occurrence 1's slices hold only
    B. Its root is A and B, with A's slice and origins (Astra round 2)."""
    from types import SimpleNamespace as NS
    from tdo_v2.boundary import BoundaryKind
    from tdo_v2.summary_engine import _raw_root_groups

    def item(node, occurrence, origins):
        return NS(root=NS(node=node, label="sink", occurrence_ordinal=occurrence), result=f"r{node}",
                  reached_origin_labels=origins)

    analysis = NS(slices=[item(1, 0, ("a",)), item(2, 1, ("b",))], normalized=None)
    rows = [NS(kind=BoundaryKind.SINK, label="sink", occurrence_ordinal=0, node=1),
            NS(kind=BoundaryKind.SINK, label="sink", occurrence_ordinal=1, node=1),
            NS(kind=BoundaryKind.SINK, label="sink", occurrence_ordinal=1, node=2)]
    found = {(label, occurrence): (nodes, results, labels)
             for label, occurrence, nodes, results, labels in _raw_root_groups(analysis, rows)}
    assert found[("sink", 0)] == ((1,), ("r1",), {"a"})
    assert found[("sink", 1)] == ((1, 2), ("r2", "r1"), {"a", "b"})


def test_a_register_the_callee_pushes_and_pops_keeps_its_pre_call_lanes():
    """callee: push rdi; rdi = rcx; pop rdi; ret. The caller's rdi after the
    call is its own value (the interpreter restores its writer by provenance);
    the stack address the push and pop used is not a source of it."""
    from synthetic import CODE_BASE, R9, REG

    callee_entry = CODE_BASE + 0x800
    callee = (FunctionBuilder(entry=callee_entry).push(RDI)
              .ins(copy(reg(RDI), reg(RCX)))
              .pop(RDI).ret())
    t = tmp(0x100)
    caller = (FunctionBuilder().sub_rsp(0x28)
              .ins(copy(reg(RDI), reg(RSI)))
              .ins(add(reg(RCX), reg(RSP), const(0x10)))
              .call(callee_entry)
              .ins(copy(reg(R9), reg(RDI)))
              .add_rsp(0x28).ret())
    units = program_units(caller, callee)
    results = analyze_units(units)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    analyzed = results["1:1000"]
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    report = check_lanes(analyzed.normalized, analyzed.unit, seeds=range(3), register_pools=pools,
                         havoc_calls=(REG, RSP, 8), program=program)
    assert report.checked > 0
    assert report.missing == []


def test_a_push_pop_restore_is_seen_when_one_call_site_runs_twice():
    """One call site in a loop: the first activation produces rdi (rdi = rdx),
    the second pushes it, uses it for a stack address (rdi = rcx) and pops it -- the restored writer text equals the
    first activation's, so the restore is recognized by the activation serial
    (Astra round 3)."""
    from synthetic import CODE_BASE, R8, R9, REG

    callee_entry = CODE_BASE + 0x800
    flag = tmp(0x300, 1)
    callee = (FunctionBuilder(entry=callee_entry)
              .cbranch("keep", flag, op("INT_NOTEQUAL", [reg(R8), const(0)], flag))
              .ins(copy(reg(RDI), reg(RDX)))
              .ret()
              .label("keep").push(RDI)
              .ins(copy(reg(RDI), reg(RCX)))
              .pop(RDI).ret())
    again = tmp(0x308, 1)
    caller = (FunctionBuilder().sub_rsp(0x28)
              .ins(copy(reg(R8), const(0)), add(reg(RCX), reg(RSP), const(0x10)))
              .label("top").call(callee_entry)
              .ins(add(reg(R8), reg(R8), const(1)))
              .cbranch("top", again, op("INT_EQUAL", [reg(R8), const(1)], again))
              .ins(copy(reg(R9), reg(RDI)))
              .add_rsp(0x28).ret())
    units = program_units(caller, callee)
    results = analyze_units(units)
    program = {(1, unit.scopes.function.entry.byte_offset): unit.observation for unit in units}
    analyzed = results["1:1000"]
    pools = lambda seed: {**fidelity._register_inputs(seed), RSP: 0x7000_0000}
    report = check_lanes(analyzed.normalized, analyzed.unit, seeds=range(3), register_pools=pools,
                         havoc_calls=(REG, RSP, 8), program=program)
    assert report.runs and report.checked > 0
    assert report.missing == []
