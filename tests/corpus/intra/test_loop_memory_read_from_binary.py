"""Real compiled C testbed, not evidence of external-library coverage.

Original ARM64 Mach-O bytes are lifted by the ordinary sealed exporter;
neither instructions nor p-code are replaced. Rebuild on the generating Mac:

  clang -arch arm64 -O1 -fno-stack-protector -fno-inline -fno-vectorize \
    -fno-slp-vectorize -fno-unroll-loops -ffreestanding -dynamiclib \
    tests/corpus/sources/loop_memory_read_from.c \
    -o output/loop-memory-read-from-testbed/loop_memory_read_from.dylib
  .venv/bin/python tools/bundle_export/export_bundle.py \
    output/loop-memory-read-from-testbed/loop_memory_read_from.dylib \
    --function-name _loop_rf_write_read --function-name _loop_rf_partial \
    --function-name _loop_rf_conditional --function-name _loop_rf_read_first \
    --ghidra /opt/homebrew/opt/ghidra/libexec \
    --java-home /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
    --output-root output/loop-memory-read-from-testbed/bundles

Set TDO_LOOP_READ_FROM_BUNDLE to the sealed generation directory. The hash
and offsets below pin this particular clang 21 output, not an engine rule.
Finite concrete byte/writer checks complement, but do not replace, the
synthetic same-visit/previous-occurrence counterexamples.
"""

from hashlib import sha256
import os
from pathlib import Path

import pytest

from graph_oracle import check
from pcode_interpreter import Entry, Interpreter
from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.model import ResolvedStorage
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction, _storage_ref
from tdo_v2.span_geometry import ByteSpan
from tdo_v2.storage import _resolve_validated_storage


REPO = Path(__file__).resolve().parents[3]
IMAGE_SHA = "ca90387599c516a8c6e4fd783c852b9d5bd510fa42abb6047956dac8e20a5d5a"
BASE, VALUE, PATCH = 0x50000000, 0x0123456789abcdef, 0xa6
COUNTS = (0, 1, 2, 5)
CASES = {
    "write_read": (0x2b8, "1b1:2d0:2:LOAD", ("1b1:2cc:1:STORE",)),
    "partial": (0x2f0, "1b1:300:2:LOAD", ("1b1:2f8:1:STORE", "1b1:2fc:2:STORE")),
    "conditional": (0x318, "1b1:328:2:LOAD", ("1b1:33c:1:STORE",)),
    "read_first": (0x344, "1b1:358:1:LOAD", ("1b1:360:3:STORE",)),
}


@pytest.fixture(scope="module")
def compiled_units():
    location = os.environ.get("TDO_LOOP_READ_FROM_BUNDLE")
    if not location:
        pytest.skip("set TDO_LOOP_READ_FROM_BUNDLE to the sealed compiled C testbed")
    source = (REPO / "ghidra/GhidraV2CallNaming.java").read_bytes().replace(b"\r\n", b"\n")
    binding = NamingBindingExpectation(sha256(source).digest(), CALL_NAMING_GHIDRA_VERSION)
    with open_observed_function_session(admit_frozen_bundle(Path(location)), naming_binding=binding) as session:
        units = {item.unit.scopes.function.entry.byte_offset: item.unit for item in session.iter_functions()}
    assert set(units) == {case[0] for case in CASES.values()}
    for unit in units.values():
        evidence = unit.scopes.program.evidence
        assert evidence.executable_sha256.hex() == IMAGE_SHA
        assert evidence.translation_namespace.language_id == "AARCH64:LE:64:AppleSilicon"
    return units


def _place(varnode, unit):
    result = _resolve_validated_storage(_storage_ref(varnode), unit.scopes.resolution_context)
    assert type(result) is ResolvedStorage
    return result.span


def _graph_sources(normalized, unit):
    loop, graph, ssa = normalized.memory_graph.loop_memory, normalized.dependencies, normalized.memory_ssa
    assert loop is not None and len(loop.plan.families) == 1
    assert loop.plan.families[0].stride == 8
    assert len(loop.read_from_nodes) == len(loop.read_from_source_nodes) == len(loop.plan.read_from)
    operations = {f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}:{ordinal}:{operation.opcode}":
                  operation for instruction in unit.observation.instructions
                  for ordinal, operation in enumerate(instruction.operations)}
    for row, node, source in zip(loop.plan.read_from, loop.read_from_nodes, loop.read_from_source_nodes):
        writer, reader = (loop.plan.accesses[index] for index in (row.writer_access, row.reader_access))
        assert writer.direction == "write" and reader.direction == "read" and row.visit_delta == 0
        assert writer.family_index == reader.family_index
        value = operations[writer.operation_key].inputs[2]
        output = _place(operations[reader.operation_key].output, unit)
        assert row.output_span == ByteSpan(output.object_id, output.start + row.read_offset, row.width)
        if row.constant is None:
            operand = _place(value, unit)
            assert row.source_span == ByteSpan(operand.object_id, operand.start + row.write_offset, row.width)
            assert ssa.definitions[row.source_definition_id].span.contains(row.source_span)
            assert source == normalized.memory_graph.definition_nodes[row.source_definition_id]
            (read,) = [read for read in ssa.reads
                       if ssa.actions[read.action_id].operation_key == writer.operation_key and read.span == operand]
            assert len(read.fragments) == 1 and read.fragments[0].definition_ids == (row.source_definition_id,)
        else:
            assert row.constant == (value.coordinate.space_id, value.coordinate.byte_offset, value.byte_size)
            assert graph.node(source).kind is NodeKind.CONSTANT
        assert source != graph.node_for_key("op:" + writer.operation_key)
        incoming = [(s, edge) for s, _, edge in graph.in_edges(node) if edge.kind == "loop_read_from_value"]
        assert len(incoming) == 1 and incoming[0][0] == source
        assert incoming[0][1].span == row.source_span and incoming[0][1].occurrence == row.write_offset
        assert any(target == graph.node_for_key("op:" + reader.operation_key) and edge.kind == "loop_read_from"
                   and edge.span == row.output_span and edge.occurrence == row.read_offset
                   for _, target, edge in graph.out_edges(node))
        assert any(s == graph.node_for_key("op:" + writer.operation_key) and edge.kind == "loop_read_from_witness"
                   for s, _, edge in graph.in_edges(node))
    # Same-visit value evidence is additive: no exact RAM object, kill or
    # removal of the original unresolved-access evidence is authorized.
    for access in loop.plan.accesses:
        occurrences = ssa.unresolved_reads if access.direction == "read" else ssa.unresolved_writes
        assert any(ssa.actions[row.action_id].operation_key == access.operation_key for row in occurrences)
        if access.direction == "write":
            assert not next(row for row in ssa.actions if row.operation_key == access.operation_key).write_definition_ids


def _spaces(unit):
    evidence = unit.scopes.program.evidence.address_spaces
    constant = next(row.space_id for row in evidence if row.is_constant_space)
    register = next(row.space_id for row in evidence if row.is_register_space)
    unique = next(row.space_id for row in evidence if row.is_unique_space)
    memory, = {operation.inputs[0].coordinate.byte_offset for instruction in unit.observation.instructions
               for operation in instruction.operations if operation.opcode in ("LOAD", "STORE")}
    return constant, register, unique, memory


def _initial(index):
    return 0xa0b0c0d000000000 + index


def _image(memory):
    def byte(space, address):
        if space == memory and BASE <= address < BASE + 64:
            word, lane = divmod(address - BASE, 8)
            return (_initial(word) >> (8 * lane)) & 0xff
        return None
    return byte


def _args(count):
    # Test harness input placement, not an engine calling-convention rule.
    return {8: 0x70000000, 0x4000: BASE, 0x4008: count, 0x4010: VALUE, 0x4018: PATCH}


def _concrete(normalized, unit, case):
    _, reader_key, writers = CASES[case]
    constant, register, unique, memory = _spaces(unit)
    loop = normalized.memory_graph.loop_memory
    for count in COUNTS:
        vm = Interpreter(unit.observation, constant_space=constant, seed=count, image=_image(memory))
        for offset, value in _args(count).items():
            vm.preset(register, offset, 8, value)
        run = vm.run()
        assert run.completed and not vm.opaque_opcodes
        assert run.executed.count(reader_key) == count
        actual_reads = {row.offset: row.writer for row in run.dependencies
                        if row.reader == reader_key and row.space_id == memory}
        expected_reads, expected_memory, result = {}, {}, 0
        for visit in range(count):
            remaining, address = count - visit, BASE + 8 * visit
            old = _initial(visit)
            if case == "write_read":
                read_value = final_value = VALUE + remaining
            elif case == "partial":
                read_value = final_value = (VALUE & ~(0xff << 24)) | (PATCH << 24)
            elif case == "conditional":
                read_value = final_value = VALUE if remaining & 1 else old
            else:
                read_value, final_value = old, VALUE + remaining
            result ^= read_value
            for byte in range(8):
                writer = (None if case == "read_first" or case == "conditional" and not remaining & 1 else
                          writers[1] if case == "partial" and byte == 3 else writers[0])
                expected_reads[address + byte] = Entry(memory, address + byte) if writer is None else writer
                if case != "conditional" or remaining & 1:
                    final_writer = writers[1] if case == "partial" and byte == 3 else writers[0]
                    expected_memory[memory, address + byte] = ((final_value >> (8 * byte)) & 0xff, final_writer)
            for row in loop.plan.read_from:
                writer = loop.plan.accesses[row.writer_access].operation_key
                for byte in range(row.read_offset, row.read_offset + row.width):
                    assert actual_reads[address + byte] == writer
        assert actual_reads == expected_reads
        final = vm.final_bytes()
        assert {(space, offset): (value, writer) for (space, offset), (value, writer, _) in final.items()
                if space == memory} == expected_memory
        assert sum(final[register, 0x4000 + byte][0] << (8 * byte) for byte in range(8)) == result
    report = check(normalized, unit.observation, seeds=COUNTS, register_pools=_args,
                   spaces=(constant, register, unique), image=_image(memory))
    assert report.runs == len(COUNTS) and report.checked and not report.unsupported
    assert not report.opaque_opcodes and not report.silent


@pytest.mark.parametrize("engine", ("sparse", "dense"))
@pytest.mark.parametrize("case", CASES)
def test_compiled_same_visit_store_load_fragments(compiled_units, monkeypatch, engine, case):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    entry, reader, writers = CASES[case]
    unit = compiled_units[entry]
    normalized = FunctionNormalizer().normalize(unit)
    assert isinstance(normalized, NormalizedFunction)
    _graph_sources(normalized, unit)
    plan = normalized.memory_graph.loop_memory.plan
    assert {access.direction for access in plan.accesses} == {"read", "write"}
    assert {access.operation_key for access in plan.accesses} == {reader, *writers}
    actual = {(plan.accesses[row.writer_access].operation_key, row.write_offset, row.read_offset, row.width)
              for row in plan.read_from}
    expected = ({(writers[0], 0, 0, 8)} if case == "write_read" else
                {(writers[0], 0, 0, 3), (writers[1], 0, 3, 1), (writers[0], 4, 4, 4)} if case == "partial" else set())
    assert actual == expected
    _concrete(normalized, unit, case)
