"""Actual ARM64 C/asm source fragments, not external-library/native evidence.

Set TDO_LOOP_SOURCE_FRAGMENTS_BUNDLE to this fixture's sealed generation.
Rebuild the original machine code, without modifying extracted observations:

  clang -arch arm64 -O1 -fno-stack-protector -fno-inline -fno-unroll-loops \
    -fno-vectorize -fno-slp-vectorize -ffreestanding -dynamiclib \
    tests/corpus/sources/loop_memory_source_fragments.c \
    -o output/loop-memory-source-fragments/arm64/loop_memory_source_fragments.dylib
  .venv/bin/python tools/bundle_export/export_bundle.py <binary> \
    --function-name _loop_source_fragments \
    --function-name _loop_source_fragments_partial \
    --ghidra /opt/homebrew/opt/ghidra/libexec \
    --java-home /opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home \
    --output-root output/loop-memory-source-fragments/arm64/bundles

FMOV writes D0[0:8], INS writes only D0[0:1], and STR consumes D0 directly.
The x64 source branch is only an exploratory re-packaging control: its STOSQ
copies RAX to a whole-value temporary and is not counted as this positive.
Concrete checks execute original p-code from entry; no branch flips, fake
STORE values, partial observations, ABI engine rules or native runs are used.
"""

from collections import defaultdict
from hashlib import sha256
import os
from pathlib import Path

import pytest

from pcode_interpreter import Interpreter
from test_loop_memory_read_from_binary import _place, _spaces
from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction
from tdo_v2.span_geometry import ByteSpan


REPO = Path(__file__).resolve().parents[3]
SOURCE_SHA = "d99e64aaf92e12621365cab4cd5c5fe69f88c9a3edc4a91607d8dae065deb916"
IMAGE_SHA = "42107a8b5dd31c153ad74cbc5b41d26eb7ea386a235a252a7e05dd8efa1d3b94"
BASE, STACK, D0 = 0x50000000, 0x70000000, 0x5000
COUNTS = (0, 1, 2, 5)
SEEDS = (0x0123456789abcdef, 0xfedcba9876543210)
PATCHES = (0, 0xa6, 0xff)
CASES = {
    "whole": dict(entry=0x2c0,
        observation="c92f349bf89cf907776acf80cb2580a4ddad913e80c443cd3f110c2e6808ed6d",
        seed="1b1:2c8:0:COPY", patch="1b1:2cc:0:COPY",
        store="1b1:2d0:1:STORE", overwrite=None, read="1b1:2d4:2:LOAD",
        intervals=((0, 1), (1, 7))),
    "partial": dict(entry=0x2ec,
        observation="4584be37774c87e414093afa955df5579a1f501010ed1246a0234deb8dabf266",
        seed="1b1:300:0:COPY", patch="1b1:304:0:COPY",
        store="1b1:308:1:STORE", overwrite="1b1:30c:2:STORE", read="1b1:310:2:LOAD",
        intervals=((0, 1), (1, 2), (3, 1), (4, 4))),
}


@pytest.fixture(scope="module")
def compiled_units():
    location = os.environ.get("TDO_LOOP_SOURCE_FRAGMENTS_BUNDLE")
    if not location:
        pytest.skip("set TDO_LOOP_SOURCE_FRAGMENTS_BUNDLE to the sealed ARM64 source-fragment fixture")
    assert sha256((REPO / "tests/corpus/sources/loop_memory_source_fragments.c").read_bytes()).hexdigest() == SOURCE_SHA
    source = (REPO / "ghidra/GhidraV2CallNaming.java").read_bytes().replace(b"\r\n", b"\n")
    binding = NamingBindingExpectation(sha256(source).digest(), CALL_NAMING_GHIDRA_VERSION)
    with open_observed_function_session(admit_frozen_bundle(Path(location)), naming_binding=binding) as session:
        units = {row.unit.scopes.function.entry.byte_offset: row.unit for row in session.iter_functions()}
    assert set(units) == {row["entry"] for row in CASES.values()}
    for case in CASES.values():
        unit = units[case["entry"]]
        assert unit.scopes.program.evidence.executable_sha256.hex() == IMAGE_SHA
        assert unit.scopes.program.evidence.translation_namespace.language_id == "AARCH64:LE:64:AppleSilicon"
        assert unit.scopes.function.observation_digest.hex() == case["observation"]
    return units


def _original_sources(normalized, unit, case):
    graph, ssa, binding = normalized.dependencies, normalized.memory_ssa, normalized.memory_graph
    loop = binding.loop_memory
    assert loop is not None and len(loop.plan.families) == 1
    family, = loop.plan.families
    assert family.stride == 8 and family.address_bits == 64
    operations = {f"{ins.address.space_id:x}:{ins.address.byte_offset:x}:{i}:{op.opcode}": op
                  for ins in unit.observation.instructions for i, op in enumerate(ins.operations)}
    actions = {row.operation_key: i for i, row in enumerate(ssa.actions)}
    value = operations[case["store"]].inputs[2]
    value_span = _place(value, unit)
    assert value.kind.name == "REGISTER" and value.coordinate.byte_offset == D0 and value.byte_size == 8
    source_read, = [row for row in ssa.reads if row.action_id == actions[case["store"]]
                   and row.span == value_span]
    assert [(fragment.span.start - D0, fragment.span.size) for fragment in source_read.fragments] == [(0, 1), (1, 7)]
    for fragment, producer, width in zip(source_read.fragments, (case["patch"], case["seed"]), (1, 8), strict=True):
        identifier, = fragment.definition_ids
        definition = ssa.definitions[identifier]
        assert definition.operation_key == producer
        assert operations[producer].output.byte_size == width  # not a DWORD write/upper-zero shortcut
        assert _place(operations[producer].output, unit).contains(fragment.span)

    rows = loop.plan.read_from
    assert [(row.read_offset, row.width) for row in rows] == list(case["intervals"])
    assert len(rows) == len(loop.read_from_nodes) == len(loop.read_from_source_nodes)
    output_span = _place(operations[case["read"]].output, unit)
    for row, node, source in zip(rows, loop.read_from_nodes, loop.read_from_source_nodes, strict=True):
        writer, reader = (loop.plan.accesses[i] for i in (row.writer_access, row.reader_access))
        assert reader.operation_key == case["read"] and row.visit_delta == 0
        assert writer.operation_key == (case["overwrite"] if row.read_offset == 3 else case["store"])
        assert row.constant is None and row.source_definition_id is not None
        operand = _place(operations[writer.operation_key].inputs[2], unit)
        assert row.source_span == ByteSpan(operand.object_id, operand.start + row.write_offset, row.width)
        assert row.output_span == ByteSpan(output_span.object_id, output_span.start + row.read_offset, row.width)
        reads = [r for r in ssa.reads if r.action_id == actions[writer.operation_key] and r.span == operand]
        read, = reads
        assert any(fragment.span.contains(row.source_span) and fragment.definition_ids == (row.source_definition_id,)
                   for fragment in read.fragments)
        assert ssa.definitions[row.source_definition_id].span.contains(row.source_span)
        assert source == binding.definition_nodes[row.source_definition_id]
        assert graph.node(source).kind is NodeKind.MEMORY_DEFINITION
        assert source != graph.node_for_key("op:" + writer.operation_key)
        assert [(s, edge.span, edge.occurrence) for s, _, edge in graph.in_edges(node)
                if edge.kind == "loop_read_from_value"] == [(source, row.source_span, row.write_offset)]
        assert any(t == graph.node_for_key("op:" + case["read"]) and edge.kind == "loop_read_from"
                   and edge.span == row.output_span and edge.occurrence == row.read_offset
                   for _, t, edge in graph.out_edges(node))
        assert any(s == graph.node_for_key("op:" + writer.operation_key) and edge.kind == "loop_read_from_witness"
                   for s, _, edge in graph.in_edges(node))
    for access in loop.plan.accesses:
        original = ssa.unresolved_reads if access.direction == "read" else ssa.unresolved_writes
        assert any(ssa.actions[row.action_id].operation_key == access.operation_key for row in original)
        if access.direction == "write":
            assert ssa.actions[actions[access.operation_key]].write_definition_ids == ()
    return operations


def _concrete(normalized, unit, case, operations):
    constant, register, _, memory = _spaces(unit)
    loop, ssa = normalized.memory_graph.loop_memory, normalized.memory_ssa

    def image(space, address):
        if space == memory and BASE <= address < BASE + 64:
            return (0x9e + address - BASE) & 255
        return None

    for count in COUNTS:
        for seed in SEEDS:
            for patch in PATCHES:
                vm = Interpreter(unit.observation, constant_space=constant, seed=count, image=image)
                # Physical input placement for this compiled fixture only.
                for offset, number in ((8, STACK), (0x4000, BASE), (0x4008, count), (0x4010, seed), (0x4018, patch)):
                    vm.preset(register, offset, 8, number)
                run = vm.run()
                assert run.completed and not vm.opaque_opcodes
                assert run.executed.count(case["store"]) == run.executed.count(case["read"]) == count
                if case["overwrite"]:
                    assert run.executed.count(case["overwrite"]) == count
                stored = (seed & ~255) | patch
                if case["overwrite"]:
                    stored = (stored & ~(255 << 24)) | ((patch ^ 0x5a) << 24)
                expected_reads, expected_writes = {}, {}
                for visit in range(count):
                    for byte in range(8):
                        address = BASE + visit * 8 + byte
                        writer = case["overwrite"] if byte == 3 and case["overwrite"] else case["store"]
                        expected_reads[address] = writer
                        expected_writes[memory, address] = (stored >> (8 * byte) & 255, writer)
                assert {r.offset: r.writer for r in run.dependencies if r.reader == case["read"]
                        and r.space_id == memory} == expected_reads
                final = vm.final_bytes()
                assert {(space, address): (value, writer) for (space, address), (value, writer, _) in final.items()
                        if space == memory and BASE <= address < BASE + 64} == expected_writes
                assert vm._peek(register, 0x4000, 8)[0] == (stored if count & 1 else 0)
                if count == 0:
                    continue
                # Check the raw STORE's actual byte writers AND values, not
                # just whether graph nodes with the expected keys exist.
                dependencies = defaultdict(set)
                for dep in run.dependencies:
                    dependencies[dep.reader, dep.space_id, dep.offset].add(dep.writer)
                for row in loop.plan.read_from:
                    writer = loop.plan.accesses[row.writer_access].operation_key
                    operand = operations[writer].inputs[2]
                    producer = ssa.definitions[row.source_definition_id].operation_key
                    for byte in range(row.width):
                        source_address = row.source_span.start + byte
                        assert dependencies[writer, operand.coordinate.space_id, source_address] == {producer}
                        assert vm._peek(operand.coordinate.space_id, source_address, 1)[0] == \
                               stored >> (8 * (row.read_offset + byte)) & 255


@pytest.mark.parametrize("engine", ("sparse", "dense"))
@pytest.mark.parametrize("name", CASES)
def test_original_fragmented_sources_reach_real_load_bytes(compiled_units, monkeypatch, engine, name):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    case = CASES[name]
    unit = compiled_units[case["entry"]]
    normalized = FunctionNormalizer().normalize(unit)
    assert isinstance(normalized, NormalizedFunction)
    operations = _original_sources(normalized, unit, case)
    _concrete(normalized, unit, case, operations)
