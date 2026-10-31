"""Actual compiled ARM64 testbed, not external-library or native-run evidence.

Set TDO_LOOP_PREVIOUS_BUNDLE to the sealed generation. Reproduction:

  clang -arch arm64 -O1 -fno-stack-protector -fno-inline -fno-unroll-loops \
    -fno-vectorize -fno-slp-vectorize -ffreestanding -dynamiclib \
    tests/corpus/sources/loop_memory_previous.c \
    -o output/loop-memory-previous/arm64/loop_memory_previous.dylib
  .venv/bin/python tools/bundle_export/export_bundle.py <binary> \
    --function-name _previous_slot --function-name _previous_partial \
    --function-name _previous_bypass --ghidra /opt/homebrew/opt/ghidra/libexec \
    --java-home /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
    --output-root output/loop-memory-previous/arm64/bundles

The frozen pre-feature engine produced zero previous-visit relations: slot
and bypass had no read-from rows; partial had only its current patch byte.
Original p-code is always executed from entry, without branch flips or
modified observations. A passive, test-local operation observer distinguishes
successive executions of the same static STORE; aggregated dependency keys
alone cannot demonstrate a one-visit difference.
"""

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path

import pytest

from pcode_interpreter import Entry, Interpreter
from test_loop_memory_read_from_binary import _place, _spaces
from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction
from tdo_v2.span_geometry import ByteSpan


REPO = Path(__file__).resolve().parents[3]
SOURCE_SHA = "4f35c3e26349a405fc5bdebc1b8f8221927a76824c159164e8ada6c379cf70cd"
IMAGE_SHA = "db798289f327f554a433603c5618c7002c284930b31478e0d7c636726acccf78"
BASE, STACK, MASK = 0x50000000, 0x70000000, (1 << 64) - 1
COUNTS = (0, 1, 2, 5)
VALUES = (0x0123456789abcdef, 0xffffffffffffffff)
CASES = {
    "slot": dict(entry=0x2b0,
        observation="d9f62501ace582fa0285187d0e2d46a4cc15604c272f5d371ae12cc93819b0f2",
        read="1b1:2c4:1:LOAD", store="1b1:2cc:3:STORE", patch=None,
        fragments=((0, 8, -1),)),
    "partial": dict(entry=0x2e8,
        observation="8d123eaf2f8ab4371ec3b8e9ab289bc5cc98de9ab1b717bf6a3d7cdbdad1bba9",
        read="1b1:300:1:LOAD", store="1b1:308:3:STORE", patch="1b1:2fc:2:STORE",
        fragments=((0, 3, -1), (3, 1, 0), (4, 4, -1))),
    "bypass": dict(entry=0x324,
        observation="bc010fe09c4caf8c8a7ef6822a4c9ab6623327f9792bccb369ed1efd822b0d9a",
        read="1b1:344:1:LOAD", store="1b1:350:1:STORE", patch=None, fragments=()),
}


@pytest.fixture(scope="module")
def compiled_units():
    location = os.environ.get("TDO_LOOP_PREVIOUS_BUNDLE")
    if not location:
        pytest.skip("set TDO_LOOP_PREVIOUS_BUNDLE to the sealed ARM64 previous-slot testbed")
    assert sha256((REPO / "tests/corpus/sources/loop_memory_previous.c").read_bytes()).hexdigest() == SOURCE_SHA
    source = (REPO / "ghidra/GhidraV2CallNaming.java").read_bytes().replace(b"\r\n", b"\n")
    binding = NamingBindingExpectation(sha256(source).digest(), CALL_NAMING_GHIDRA_VERSION)
    with open_observed_function_session(admit_frozen_bundle(Path(location)), naming_binding=binding) as session:
        units = {row.unit.scopes.function.entry.byte_offset: row.unit for row in session.iter_functions()}
    assert set(units) == {case["entry"] for case in CASES.values()}
    for case in CASES.values():
        unit = units[case["entry"]]
        assert unit.scopes.function.observation_digest.hex() == case["observation"]
        evidence = unit.scopes.program.evidence
        assert evidence.executable_sha256.hex() == IMAGE_SHA
        assert evidence.translation_namespace.language_id == "AARCH64:LE:64:AppleSilicon"
    return units


@dataclass(frozen=True)
class _Event:
    key: str
    occurrence: int
    address: int
    width: int
    value: int
    writers: tuple
    store_serials: tuple


class _Observer(Interpreter):
    """Observe unchanged _execute calls; no p-code semantics or input changes."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events, self.last_store, self.occurrences = [], {}, Counter()

    def _execute(self, key, operation, run):
        if operation.opcode not in ("LOAD", "STORE"):
            return super()._execute(key, operation, run)
        space = operation.inputs[0].coordinate.byte_offset
        address_operand = operation.inputs[1]
        # These pinned raw addresses are already-defined UNIQUE values.
        # Refuse an unwritten byte rather than let observation initialize it.
        assert address_operand.kind.name == "UNIQUE"
        coord = address_operand.coordinate
        assert all((coord.space_id, coord.byte_offset + i) in self._bytes
                   for i in range(address_operand.byte_size))
        address = self._peek(coord.space_id, coord.byte_offset, address_operand.byte_size)[0]
        width = operation.output.byte_size if operation.opcode == "LOAD" else operation.inputs[2].byte_size
        result = super()._execute(key, operation, run)
        original = tuple(self._bytes[space, address + i] for i in range(width))
        value = sum(byte << (8 * i) for i, (byte, _) in enumerate(original))
        if operation.opcode == "LOAD":
            output = operation.output
            assert self._peek(output.coordinate.space_id, output.coordinate.byte_offset, width)[0] == value
        serials = tuple(self.last_store.get((space, address + i)) for i in range(width))
        self.events.append(_Event(key, self.occurrences[key], address, width, value,
                                  tuple(writer for _, writer in original), serials))
        self.occurrences[key] += 1
        if operation.opcode == "STORE":
            for i in range(width):
                self.last_store[space, address + i] = len(self.events) - 1
        return result


def _graph(normalized, unit, case):
    graph, binding, ssa = normalized.dependencies, normalized.memory_graph, normalized.memory_ssa
    loop = binding.loop_memory
    assert loop is not None and len(loop.plan.families) == 1
    family, = loop.plan.families
    assert family.stride == 8 and family.address_bits == 64
    accesses = {row.operation_key: row for row in loop.plan.accesses}
    assert accesses[case["read"]].offset == (1 << 64) - 8
    assert accesses[case["read"]].width == accesses[case["store"]].width == 8
    assert accesses[case["store"]].offset == 0
    if case["patch"]:
        assert accesses[case["patch"]].offset == (1 << 64) - 5
        assert accesses[case["patch"]].width == 1
    rows = loop.plan.read_from
    assert [(row.read_offset, row.width, row.visit_delta) for row in rows] == list(case["fragments"])
    assert len(rows) == len(loop.read_from_nodes) == len(loop.read_from_source_nodes)
    operations = {f"{ins.address.space_id:x}:{ins.address.byte_offset:x}:{i}:{op.opcode}": op
                  for ins in unit.observation.instructions for i, op in enumerate(ins.operations)}
    actions = {row.operation_key: i for i, row in enumerate(ssa.actions)}
    for row, node, source in zip(rows, loop.read_from_nodes, loop.read_from_source_nodes, strict=True):
        writer, reader = (loop.plan.accesses[i] for i in (row.writer_access, row.reader_access))
        previous = row.visit_delta == -1
        assert row.requires_backedge is previous
        assert writer.operation_key == (case["store"] if previous else case["patch"])
        assert reader.operation_key == case["read"] and writer.family_index == reader.family_index
        assert graph.node(node).label == ("loop_previous_visit_read_from_if_backedge" if previous else "loop_same_visit_read_from")
        value_kind = "loop_previous_read_from_value" if previous else "loop_read_from_value"
        output_kind = "loop_previous_read_from" if previous else "loop_read_from"
        assert row.constant is None and row.source_definition_id is not None
        operand = _place(operations[writer.operation_key].inputs[2], unit)
        output = _place(operations[reader.operation_key].output, unit)
        assert row.source_span == ByteSpan(operand.object_id, operand.start + row.write_offset, row.width)
        assert row.output_span == ByteSpan(output.object_id, output.start + row.read_offset, row.width)
        read, = [r for r in ssa.reads if r.action_id == actions[writer.operation_key] and r.span == operand]
        assert any(f.span.contains(row.source_span) and f.definition_ids == (row.source_definition_id,)
                   for f in read.fragments)
        assert source == binding.definition_nodes[row.source_definition_id]
        assert graph.node(source).kind is NodeKind.MEMORY_DEFINITION
        assert [(s, edge.span, edge.occurrence) for s, _, edge in graph.in_edges(node)
                if edge.kind == value_kind] == [(source, row.source_span, row.write_offset)]
        assert any(t == graph.node_for_key("op:" + case["read"]) and edge.kind == output_kind
                   and edge.span == row.output_span and edge.occurrence == row.read_offset
                   for _, t, edge in graph.out_edges(node))
        assert any(s == graph.node_for_key("op:" + writer.operation_key) and edge.kind == "loop_read_from_witness"
                   for s, _, edge in graph.in_edges(node))
        if previous:
            assert not any(edge.kind in ("loop_read_from_value", "loop_read_from")
                           for *_, edge in (*graph.in_edges(node), *graph.out_edges(node)))
    for access in loop.plan.accesses:
        original = ssa.unresolved_reads if access.direction == "read" else ssa.unresolved_writes
        assert any(ssa.actions[row.action_id].operation_key == access.operation_key for row in original)
        if access.direction == "write":
            assert ssa.actions[actions[access.operation_key]].write_definition_ids == ()


def _concrete(normalized, unit, name, case):
    constant, register, _, memory = _spaces(unit)
    for count in COUNTS:
        for value in VALUES:
            for patch in ((0, 0xa6, 0xff) if case["patch"] else (0xa6,)):
                def image(space, address):
                    return (0x9e + address - BASE) & 255 if space == memory and BASE <= address < BASE + 64 else None

                vm = _Observer(unit.observation, constant_space=constant, seed=count, image=image)
                # Physical input placement only for this compiled fixture.
                for offset, number in ((8, STACK), (0x4000, BASE + 8), (0x4008, count), (0x4010, value), (0x4018, patch)):
                    vm.preset(register, offset, 8, number)
                run = vm.run()
                assert run.completed and not vm.opaque_opcodes
                expected = {BASE + i: ((0x9e + i) & 255, Entry(memory, BASE + i), None) for i in range(64)}
                at, result, read_events, touched = 0, 0, [], set()
                for visit in range(count):
                    address = BASE + 8 * visit
                    if case["patch"]:
                        event = vm.events[at]
                        assert (event.key, event.address, event.width, event.value) == (case["patch"], address + 3, 1, patch)
                        expected[address + 3] = patch, case["patch"], at
                        touched.add(address + 3)
                        at += 1
                    event = vm.events[at]
                    loaded = sum(expected[address + i][0] << (8 * i) for i in range(8))
                    assert (event.key, event.occurrence, event.address, event.width, event.value) == (case["read"], visit, address, 8, loaded)
                    assert event.writers == tuple(expected[address + i][1] for i in range(8))
                    assert event.store_serials == tuple(expected[address + i][2] for i in range(8))
                    read_events.append(event)
                    touched.update(range(address, address + 8))
                    result ^= loaded
                    at += 1
                    if name != "bypass" or (count - visit) & 1:
                        stored = (value + count - visit) & MASK
                        event = vm.events[at]
                        assert (event.key, event.address, event.width, event.value) == (case["store"], address + 8, 8, stored)
                        for i in range(8):
                            expected[address + 8 + i] = (stored >> (8 * i) & 255, case["store"], at)
                        touched.update(range(address + 8, address + 16))
                        at += 1
                assert len(vm.events) == at and vm._peek(register, 0x4000, 8)[0] == result
                final = vm.final_bytes()
                assert {(address, vm._bytes[memory, address]) for address in touched} == \
                       {(address, expected[address][:2]) for address in touched}
                assert {address: (byte, writer) for (space, address), (byte, writer, _) in final.items()
                        if space == memory} == {address: row[:2] for address, row in expected.items()
                                                if not isinstance(row[1], Entry)}
                assert {d.offset: d.writer for d in run.dependencies if d.reader == case["read"] and d.space_id == memory} == \
                       {event.address + i: writer for event in read_events for i, writer in enumerate(event.writers)}
                for visit, event in enumerate(read_events):
                    for row in normalized.memory_graph.loop_memory.plan.read_from:
                        for i in range(row.width):
                            serial = event.store_serials[row.read_offset + i]
                            if visit == 0 and row.requires_backedge:
                                assert serial is None and isinstance(event.writers[row.read_offset + i], Entry)
                                continue
                            source = vm.events[serial]
                            assert source.occurrence == visit + row.visit_delta
                            assert source.key == normalized.memory_graph.loop_memory.plan.accesses[row.writer_access].operation_key
                            assert source.value >> (8 * (row.write_offset + i)) & 255 == event.value >> (8 * (row.read_offset + i)) & 255


@pytest.mark.parametrize("engine", ("sparse", "dense"))
@pytest.mark.parametrize("name", CASES)
def test_original_previous_slot_value_and_occurrence(compiled_units, monkeypatch, engine, name):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    case = CASES[name]
    unit = compiled_units[case["entry"]]
    normalized = FunctionNormalizer().normalize(unit)
    assert isinstance(normalized, NormalizedFunction)
    _graph(normalized, unit, case)
    _concrete(normalized, unit, name, case)
