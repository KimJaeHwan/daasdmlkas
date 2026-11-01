"""Original ncnn/zlib value paths; exact candidates are not unique writers.

Set TDO_LOADED_POINTER_DATA to the private sealed field-case directory.
Original producer LF/CRLF bytes are bound in memory, never rewritten on disk.
"""

from hashlib import sha256
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from pcode_interpreter import Entry, Interpreter
from test_loaded_pointer_bit_indices_binary import GENERATIONS
from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.model import ResolvedStorage
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction, _storage_ref
from tdo_v2.storage import _resolve_validated_storage


REPO = Path(__file__).resolve().parents[3]
CASES = {
    0x548970: ("1b1:548c78:1:STORE", "1b1:548c7c:1:LOAD", 8, None),
    0x10c040: ("1b1:10c34b:2:STORE", "1b1:10c356:1:LOAD", 4, "1b1:10c352:3:STORE"),
    0x107360: ("1b1:10739f:2:STORE", "1b1:1073a7:1:LOAD", 8, "1b1:1073a3:3:STORE"),
}
OBSERVATIONS = {
    0x548970: "86f9ff45756cfa1671cc2b804618cf4378f5fdf16de2a061256799ed9c0b95fa",
    0x10c040: "83a0ec80a30cd6c859aaa68ddd6bbcb76935c3c00fe097bf94d79efbcb4ff911",
    0x107360: "ed0ec208b9f4e03d468a0675f8c72bee0e114d92ef4d09c22903c5f93fa3e15a",
}
PRODUCERS = {0x548970: "1b1:548c74:6:COPY", 0x10c040: "1b1:10c34b:1:COPY", 0x107360: "1b1:10739f:1:COPY"}
ZLIB_IMAGE = "fbf56b0e59287033b6579bbbeae2f9de2fe86ad5bf2bd44d44aad67a15109318"


@pytest.fixture(scope="module")
def external_units():
    location = os.environ.get("TDO_LOADED_POINTER_DATA")
    if not location:
        pytest.skip("set TDO_LOADED_POINTER_DATA to the sealed ncnn/zlib field cases")
    source = (REPO / "ghidra/GhidraV2CallNaming.java").read_bytes().replace(b"\r\n", b"\n")
    ncnn_generation, ncnn_digest, _ = GENERATIONS["ncnn"]
    bundles = (("tdo_bundles_so_mac_loaded/ncnn/" + ncnn_generation, source, {0x548970}),
               ("tdo_bundles3/zlib/53a9289fedd5be67f18aa42e359ffbae4d9376dc1297f0624e0d2f776e1b51b2",
                source.replace(b"\n", b"\r\n"), {0x10c040, 0x107360}))
    units = {}
    for relative, producer, selected in bundles:
        binding = NamingBindingExpectation(sha256(producer).digest(), CALL_NAMING_GHIDRA_VERSION)
        with open_observed_function_session(admit_frozen_bundle(Path(location) / relative),
                                            naming_binding=binding) as session:
            for item in session.iter_functions():
                unit = item.unit
                if unit.scopes.function.entry.byte_offset in selected:
                    expected = ncnn_digest if selected == {0x548970} else ZLIB_IMAGE
                    assert unit.scopes.program.evidence.executable_sha256.hex() == expected
                    assert unit.scopes.function.observation_digest.hex() == OBSERVATIONS[unit.scopes.function.entry.byte_offset]
                    units[unit.scopes.function.entry.byte_offset] = unit
    assert set(units) == set(CASES)
    return units


@pytest.fixture(scope="module", params=("sparse", "dense"))
def external_cases(external_units, request):
    with pytest.MonkeyPatch.context() as setting:
        setting.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
        setting.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
        cases = {entry: FunctionNormalizer().normalize(unit) for entry, unit in external_units.items()}
    assert all(isinstance(item, NormalizedFunction) for item in cases.values())
    return cases


def _operations(unit):
    return {f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}:{ordinal}:{operation.opcode}":
            operation for instruction in unit.observation.instructions
            for ordinal, operation in enumerate(instruction.operations)}


def _span(varnode, unit):
    resolved = _resolve_validated_storage(_storage_ref(varnode), unit.scopes.resolution_context)
    assert type(resolved) is ResolvedStorage
    return resolved.span


def _edge(graph, source, target, kind, span):
    assert any(actual == target and edge.kind == kind and edge.span == span
               for _, actual, edge in graph.out_edges(source))


@pytest.mark.parametrize("entry", CASES)
def test_original_external_memory_store_value_candidate_reaches_load(external_units, external_cases, entry):
    unit = external_units[entry]
    normalized = external_cases[entry]
    writer, reader, width, alias = CASES[entry]
    raw, ssa, graph = _operations(unit), normalized.memory_ssa, normalized.dependencies
    actions = {row.operation_key: (number, row) for number, row in enumerate(ssa.actions)}
    (write_definition,) = actions[writer][1].write_definition_ids
    memory = ssa.definitions[write_definition].span
    assert memory.object_id.kind.value == "function_relative" and memory.size == width
    assert raw[writer].inputs[2].byte_size == raw[reader].output.byte_size == width
    value = _span(raw[writer].inputs[2], unit)
    (source_read,) = [row for row in ssa.reads if row.action_id == actions[writer][0] and row.span == value]
    (source_fragment,) = source_read.fragments
    (source_definition,) = source_fragment.definition_ids
    assert source_fragment.span == value and ssa.definitions[source_definition].span.contains(value)
    assert ssa.definitions[source_definition].operation_key == PRODUCERS[entry]
    (memory_read,) = [row for row in ssa.reads if row.action_id == actions[reader][0] and row.span == memory]
    assert any(fragment.span == memory and write_definition in fragment.definition_ids for fragment in memory_read.fragments)
    (output_definition,) = actions[reader][1].write_definition_ids
    output = _span(raw[reader].output, unit)
    assert ssa.definitions[output_definition].span == output and output.size == width
    write_node, read_node = (graph.node_for_key("op:" + key) for key in (writer, reader))
    nodes = normalized.memory_graph.definition_nodes
    for source, target, kind, span in ((nodes[source_definition], write_node, "memory_read", value),
                                      (write_node, nodes[write_definition], "memory_defines", memory),
                                      (nodes[write_definition], read_node, "memory_read", memory),
                                      (read_node, nodes[output_definition], "memory_defines", output)):
        _edge(graph, source, target, kind, span)
    assert normalized.may_alias_reads  # candidate coverage is not last-writer uniqueness
    claims = [(row, node) for row, node in zip(normalized.may_alias_reads, normalized.may_alias_nodes)
              if row.operation_key == reader]
    assert claims
    for claim, debt in claims:
        if entry == 0x548970:
            assert {graph.node(source).key for source, _, edge in graph.in_edges(debt) if edge.kind == "may_alias_write"} == \
                {"op:" + key for key in claim.writers}
        assert any(target == read_node and edge.kind == "may_alias_read" for _, target, edge in graph.out_edges(debt))
    if alias is not None:
        (claim, debt), = [(row, node) for row, node in zip(normalized.may_alias_reads, normalized.may_alias_nodes)
                         if row.operation_key == reader and alias in row.writers]
        assert claim.spans and raw[alias].inputs[2].byte_size == 1
        alias_node = graph.node_for_key("op:" + alias)
        assert any(target == debt and edge.kind == "may_alias_write" for _, target, edge in graph.out_edges(alias_node))
        assert any(target == read_node and edge.kind == "may_alias_read" for _, target, edge in graph.out_edges(debt))
    # No loop address recurrence is necessary for this relative-memory path.
    # A local last-write proof, if issued, is separate from loop read-from.
    loop = normalized.memory_graph.loop_memory
    assert loop is None or all(loop.plan.accesses[row.reader_access].operation_key != reader for row in loop.plan.read_from)
    if entry == 0x548970:
        # FUNCTION_RELATIVE encodes displacement zero at its modular bias;
        # this is not a claim about physical RAM address zero.
        assert memory.start == 1 << (8 * raw[writer].inputs[1].byte_size) and value.start == 0x4040
        assert output.object_id.kind.value == "function_unique" and output.start == 0x48400
        key = "1b1:548c74:3:INT_ADD"
        arithmetic = _span(raw[key].output, unit)
        (identifier,) = [i for i, row in enumerate(ssa.definitions) if row.operation_key == key and row.span == arithmetic]
        _edge(graph, graph.node_for_key("op:" + key), nodes[identifier], "memory_defines", arithmetic)
        _edge(graph, nodes[identifier], graph.node_for_key("op:" + PRODUCERS[entry]), "memory_read", arithmetic)


@pytest.mark.parametrize("diagnostic", (False, True))
def test_ncnn_load_expression_keeps_real_eight_byte_value_path_but_refuses_numeric_loop(external_units, external_cases,
                                                                                    diagnostic):
    from tdo_v2.operation_records import Ineligible, Limits, eligibility, evaluate, root_record

    normalized, unit = external_cases[0x548970], external_units[0x548970]
    writer, reader, _, _ = CASES[0x548970]
    seeds = [(normalized.memory_graph.definition_nodes[i], (definition.span,))
             for i, definition in enumerate(normalized.memory_ssa.definitions) if definition.operation_key == reader]
    assert len(seeds) == 1
    limits = Limits(writers=64, nodes=12000, edges=60000, depth=512) if diagnostic else None
    record = root_record(normalized, unit, seeds, limits=limits)
    nodes = {node["id"]: node for node in record["nodes"]}
    load = next(node for node in record["nodes"] if node.get("key") == reader and not node.get("cycle_only"))
    (memory,) = load["memory"]
    (part,) = memory["parts"]
    # The validated port directly references the original STORE operand
    # bytes, without pretending the whole STORE/address is the loaded value.
    assert load["local_read"]["writer"] == writer
    copied = nodes[part["node"]]
    (copy_part,) = copied["operands"][0]["parts"]
    arithmetic = nodes[copy_part["node"]]
    assert copied["key"] == PRODUCERS[0x548970]
    assert arithmetic["key"] == "1b1:548c74:3:INT_ADD" and arithmetic["opcode"] == "INT_ADD"
    assert all(item["bytes"] == item["at"] == [0, 8] for item in (part, copy_part))
    assert not load.get("debts") and normalized.may_alias_reads
    assert sum(len(row.writers) for row in normalized.may_alias_reads if row.operation_key == reader) == 56
    assert any(node["kind"] == "debt" and node.get("debt") == "call_clobber_read"
               for node in record["nodes"])  # Independent original address/value debts remain.
    assert record["truncated"] is not diagnostic
    assert any(node.get("writers_truncated") for node in record["nodes"]) is not diagnostic
    reason = "loop" if diagnostic else "truncated"
    assert eligibility(record) == reason
    if diagnostic:
        assert record["cycle_graph"]["coverage"]["expression_complete"]

    def unreadable(_):
        raise AssertionError("incomplete/loop record must refuse before any numeric input")

    with pytest.raises(Ineligible, match=reason):
        evaluate(record, unreadable)


@pytest.mark.parametrize("value", (0, (1 << 64) - 1, 0x01020304ffffffff))
def test_original_ncnn_three_instruction_window_conditionally_preserves_both_loads(external_units, value):
    unit = external_units[0x548970]
    addresses = (0x548c74, 0x548c78, 0x548c7c)
    originals = tuple(next(row for row in unit.observation.instructions if row.address.byte_offset == address)
                      for address in addresses)
    assert all(before.fallthrough == after.address for before, after in zip(originals, originals[1:]))
    assert originals[-1].fallthrough.byte_offset == 0x548c80
    assert all(not (row.flow.is_call or row.flow.is_jump or row.flow.is_terminal or row.flow_targets) for row in originals)
    assert all(operation.opcode not in ("CALL", "CALLIND", "CALLOTHER", "BRANCH", "CBRANCH", "BRANCHIND", "RETURN")
               for row in originals for operation in row.operations)
    window = SimpleNamespace(instructions=originals)
    assert window.instructions is originals
    spaces = unit.scopes.program.evidence.address_spaces
    constant = next(row.space_id for row in spaces if row.is_constant_space)
    register = next(row.space_id for row in spaces if row.is_register_space)
    memory = originals[1].operations[1].inputs[0].coordinate.byte_offset
    base, upper = 0x50000000, 0xa1b2c3d4e5f60718

    def image(space, address):
        return (upper >> (8 * (address - base - 8))) & 0xff \
            if space == memory and base + 8 <= address < base + 16 else None

    # This is a conditional LOCAL entry-state test, not entry-to-window
    # reachability or a function-return proof. The whole-function attempt
    # encounters unresolved strncmp/internal-parser CALLs before this window.
    # No instruction, p-code operation, coordinate, branch, or order is edited.
    vm = Interpreter(window, constant_space=constant, seed=0, image=image)
    assert all(vm._instructions[(row.address.space_id, row.address.byte_offset)] is row for row in originals)
    vm.preset(register, 0x4098, 8, base)  # x19, supplied at local window entry
    vm.preset(register, 0x40c8, 8, value)  # x25, supplied at local window entry
    run = vm.run()
    expected_keys = [f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:{operation.opcode}"
                     for row in originals for ordinal, operation in enumerate(row.operations)]
    assert run.completed and not vm.opaque_opcodes and run.executed == expected_keys
    first, second = "1b1:548c7c:1:LOAD", "1b1:548c7c:3:LOAD"
    for reader, start, writer in ((first, base, CASES[0x548970][0]), (second, base + 8, None)):
        dependencies = [row for row in run.dependencies if row.reader == reader and row.space_id == memory]
        assert len(dependencies) == 8
        assert {(row.offset, row.writer) for row in dependencies} == \
            {(start + byte, writer if writer is not None else Entry(memory, start + byte)) for byte in range(8)}
    final, low = vm.final_bytes(), (value + 1) % (1 << 64)
    assert {(address, number, writer) for (space, address), (number, writer, _) in final.items() if space == memory} == \
        {(base + byte, low >> (8 * byte) & 0xff, CASES[0x548970][0]) for byte in range(8)}
    for operation, expected in ((originals[-1].operations[1], low), (originals[-1].operations[3], upper)):
        output = operation.output
        assert sum(final[(output.coordinate.space_id, output.coordinate.byte_offset + byte)][0] << (8 * byte)
                   for byte in range(8)) == expected
