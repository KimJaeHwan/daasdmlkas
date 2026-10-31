"""Optional sealed ARM64 field cases; no third-party binary is in Git.

Set TDO_LOADED_POINTER_DATA to the transported tdo_data_2026-10-30 directory.
These are local graph/target assertions, not whole-program completeness claims.
"""

from hashlib import sha256
import os
from pathlib import Path

import pytest

from graph_oracle import check
from pcode_interpreter import Interpreter
from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction


REPO = Path(__file__).resolve().parents[3]
GENERATIONS = {
    "layout": ("4e70c1f11490b82a2f4bca81cb7aae9127f5bd941487425e327f67dfb9ba67d2",
               "7ccffded6a1098eec90481f048daa157ea9e9da53849702fcce457265819d79d", (0x143bf0, 0x143fe8)),
    "mmkv-focused": ("111b0f3ea6da96d97ff215b1442a51d05a974e970a0403bb0b1cdab015f16c76",
                     "e638aba4aef5db1cc74f6accd29c5dc7849edeba7eee9eb4327c25a409d24be8",
                     (0x166600, 0x187b4c, 0x13fac0)),
    "ncnn": ("5a97cb942ac377c0f9617247f0b6d54f1787f1ab3bbfe6ee1ddd5a45b50a3cad",
             "4a91e5cc48471beb3471b42220188b07fc2fc9659b1e909b499fc0696858a9aa", (0x1dc83c,)),
}


@pytest.fixture(scope="module")
def actual_units():
    location = os.environ.get("TDO_LOADED_POINTER_DATA")
    if not location:
        pytest.skip("set TDO_LOADED_POINTER_DATA to the sealed ARM64 field-case data")
    # The transported Mac Bundles sealed this producer's LF bytes. Preserve
    # that exact binding even on a Windows checkout using CRLF line endings.
    source = (REPO / "ghidra/GhidraV2CallNaming.java").read_bytes().replace(b"\r\n", b"\n")
    binding = NamingBindingExpectation(sha256(source).digest(), CALL_NAMING_GHIDRA_VERSION)
    units = {}
    for library, (generation, digest, selected) in GENERATIONS.items():
        directory = Path(location) / "tdo_bundles_so_mac_loaded" / library / generation
        with open_observed_function_session(admit_frozen_bundle(directory), naming_binding=binding) as session:
            for evidence in session.iter_functions():
                unit = evidence.unit
                if unit.scopes.function.entry.byte_offset in selected:
                    assert unit.scopes.program.evidence.executable_sha256.hex() == digest
                    units[unit.scopes.function.entry.byte_offset] = unit
    assert len(units) == 6
    return units


def _normalize(actual_units, entry, monkeypatch, engine):
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    normalized = FunctionNormalizer().normalize(actual_units[entry])
    assert isinstance(normalized, NormalizedFunction)
    return normalized


def _target(normalized, key, width):
    ssa, graph = normalized.memory_ssa, normalized.dependencies
    (action,) = [row for row in ssa.actions if row.operation_key == key]
    (identifier,) = action.write_definition_ids
    definition = ssa.definitions[identifier]
    assert definition.span.size == width and definition.span.object_id.kind.value == "function_relative"
    node = normalized.memory_graph.definition_nodes[identifier]
    assert any(target == node and edge.kind == "memory_defines" and edge.span == definition.span
               for _, target, edge in graph.out_edges(graph.node_for_key("op:" + key)))
    assert not any(ssa.actions[row.action_id].operation_key == key for row in ssa.unresolved_writes)
    return definition


def _reaches(graph, source, target):
    pending, seen = [source], set()
    while pending:
        node = pending.pop()
        if node == target:
            return True
        if node not in seen:
            seen.add(node)
            pending.extend(t for _, t, edge in graph.out_edges(node)
                           if edge.kind in ("memory_defines", "memory_read", "join_input"))
    return False


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_layout_two_loads_mask_shift_guard_reach_the_real_store_target(actual_units, monkeypatch, engine):
    normalized = _normalize(actual_units, 0x143bf0, monkeypatch, engine)
    definition = _target(normalized, "1b1:143ca0:1:STORE", 4)
    graph = normalized.dependencies
    target = graph.node_for_key("op:1b1:143ca0:1:STORE")
    # Pin the final operand to raw STORE's address temporary, not s0 (its
    # stored value), and never accept a path made only of alias/control edges.
    address_sources = [source for source, _, edge in graph.in_edges(target)
                       if edge.kind == "memory_read" and edge.span.start == 0xc700
                       and edge.span.size == 8 and edge.span.object_id.kind.value == "function_unique"]
    assert len(address_sources) == 1
    for key in ("1b1:143c84:1:LOAD", "1b1:143c8c:1:LOAD", "1b1:143c00:0:INT_AND",
                "1b1:143c50:0:INT_RIGHT", "1b1:143c9c:4:INT_ADD"):
        assert _reaches(graph, graph.node_for_key("op:" + key), address_sources[0]), key
    assert graph.node_for_key("op:1b1:143c98:0:CBRANCH") is not None
    assert definition.span.object_id in normalized.wild_objects
    # An explicit relative target is not a new disjointness/lifetime proof.
    assert normalized.may_alias_reads


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_layout_loaded_vector_with_bitwise_index_has_a_target(actual_units, monkeypatch, engine):
    normalized = _normalize(actual_units, 0x143fe8, monkeypatch, engine)
    _target(normalized, "1b1:144060:6:STORE", 8)
    assert normalized.may_alias_reads


def test_original_layout_pcode_executes_the_guarded_two_load_store(actual_units):
    unit = actual_units[0x143bf0]
    program = unit.scopes.program.evidence
    constant = next(row.space_id for row in program.address_spaces if row.is_constant_space)
    register = next(row.space_id for row in program.address_spaces if row.is_register_space)
    unique = next(row.space_id for row in program.address_spaces if row.is_unique_space)
    (memory,) = {operation.inputs[0].coordinate.byte_offset for instruction in unit.observation.instructions
                 for operation in instruction.operations if operation.opcode in ("LOAD", "STORE")}

    def image(space, address):
        if space != memory:
            return None
        for start, value, width in ((0x50000020, 0x50001000, 8), (0x50001000, 0x50002000, 8),
                                    (0x50001008, 0x50002040, 8), (0x50003000, 0, 2)):
            if start <= address < start + width:
                return (value >> (8 * (address - start))) & 255
        return None

    def inputs(seed):
        return {8: 0x70000000, 0x4000: 0x50000000, 0x4008: 0x50003000,
                0x4010: ((seed + 4) << 4) | 8, 0x5000: 0x3f800000 + seed}

    # Run original instructions (no replaced source, call, or memory op).
    for seed in range(8):
        vm = Interpreter(unit.observation, constant_space=constant, seed=seed, image=image)
        for offset, value in inputs(seed).items():
            vm.preset(register, offset, 8, value)
        run = vm.run()
        assert run.completed and not vm.opaque_opcodes
        assert run.executed.count("1b1:143ca0:1:STORE") == 1
        assert ("1b1:143c98:0:CBRANCH", False) in run.branch_decisions
    normalized = FunctionNormalizer().normalize(unit)
    report = check(normalized, unit.observation, seeds=range(8), register_pools=inputs,
                   spaces=(constant, register, unique), image=image)
    assert report.runs == 8 and report.checked and not report.unsupported
    assert not report.opaque_opcodes and not report.silent


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_mmkv_existing_pointer_field_string_choice_and_spill_targets_survive(actual_units, monkeypatch, engine):
    for entry, sites in ((0x166600, (("1b1:166614:1:STORE", 8),)),
                         (0x187b4c, (("1b1:187b8c:3:STORE", 1), ("1b1:187b9c:6:STORE", 1))),
                         (0x13fac0, (("1b1:13facc:2:STORE", 8), ("1b1:13fad0:2:STORE", 8)))):
        normalized = _normalize(actual_units, entry, monkeypatch, engine)
        for key, width in sites:
            _target(normalized, key, width)


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_loop_carried_pointer_is_not_frozen_to_one_activation_value(actual_units, monkeypatch, engine):
    normalized = _normalize(actual_units, 0x1dc83c, monkeypatch, engine)
    ssa = normalized.memory_ssa
    key = "1b1:1dc864:2:STORE"
    (action,) = [row for row in ssa.actions if row.operation_key == key]
    assert not action.write_definition_ids
    assert any(ssa.actions[row.action_id].operation_key == key for row in ssa.unresolved_writes)


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_ue_stale_content_does_not_erase_the_once_load_output_target(monkeypatch, engine):
    location = os.environ.get("TDO_LOADED_POINTER_DATA")
    if not location:
        pytest.skip("set TDO_LOADED_POINTER_DATA to include the original company UE Bundle")
    generation = Path(location) / "tdo_bundles3/ue-dll-debuggame" / \
        "f86ff7a719eb2f741e1e537ab3489bee514ae81ff3722b45399e15168d56dfc4"
    # This company Bundle sealed the CRLF producer. Match those exact source
    # bytes on either checkout platform, rather than weakening admission.
    source = (REPO / "ghidra/GhidraV2CallNaming.java").read_bytes().replace(b"\r\n", b"\n")
    binding = NamingBindingExpectation(sha256(source.replace(b"\n", b"\r\n")).digest(),
                                       CALL_NAMING_GHIDRA_VERSION)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        units = [row.unit for row in session.iter_functions()
                 if row.unit.scopes.function.entry.byte_offset == 0x180006e00]
    (unit,) = units
    normalized = FunctionNormalizer().normalize(unit)
    assert isinstance(normalized, NormalizedFunction)
    first = _target(normalized, "1b1:1800071e4:1:STORE", 4)
    _target(normalized, "1b1:1800071f2:1:STORE", 4)
    assert first.span.object_id in normalized.wild_objects
    assert any(text.startswith("captured LOAD output 1b1:1800071ca:1:LOAD ")
               for _, text in normalized.address_atoms)
    graph = normalized.dependencies
    assert _reaches(graph, graph.node_for_key("op:1b1:1800071ca:1:LOAD"),
                    graph.node_for_key("op:1b1:1800071e4:1:STORE"))
    assert normalized.may_alias_reads and normalized.call_clobber_reads


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_ncnn_all_four_stores_keep_occurrence_qualified_memory_targets(actual_units, monkeypatch, engine):
    normalized = _normalize(actual_units, 0x1dc83c, monkeypatch, engine)
    binding = normalized.memory_graph.loop_memory
    assert binding is not None
    plan, graph = binding.plan, normalized.dependencies
    assert len(plan.families) == 3 and len(plan.accesses) == 4
    assert [(row.header, row.stride) for row in plan.families] == [
        ("1b1:1dc85c", 16), ("1b1:1dc8bc", 32), ("1b1:1dc8d8", 4)]
    expected = {"1b1:1dc864:2:STORE": (0, 16, 0),
                "1b1:1dc8bc:1:STORE": (1, 16, (1 << 64) - 16),
                "1b1:1dc8bc:3:STORE": (1, 16, 0),
                "1b1:1dc8dc:2:STORE": (2, 4, 0)}
    for access, node in zip(plan.accesses, binding.access_nodes, strict=True):
        assert (access.family_index, access.width, access.offset) == expected[access.operation_key]
        assert access.direction == "write"
        operation = graph.node_for_key("op:" + access.operation_key)
        assert any(source == operation and edge.kind == "loop_possible_write" for source, _, edge in graph.in_edges(node))
        assert any(source == binding.family_nodes[access.family_index] and edge.kind == "loop_memory_address"
                   for source, _, edge in graph.in_edges(node))
    # The scalar loop starts with one of two actual preceding COPY values,
    # not a global fixed pointer or two supposedly equivalent definitions.
    scalar = plan.families[2]
    assert {normalized.memory_ssa.definitions[d].operation_key for edge in scalar.entry_edges
            for d in edge.definition_ids} == {"1b1:1dc898:0:COPY", "1b1:1dc8b4:7:COPY"}
    assert {normalized.memory_ssa.actions[row.action_id].operation_key
            for row in normalized.memory_ssa.unresolved_writes} == set(expected)
    assert all(not action.write_definition_ids for action in normalized.memory_ssa.actions
               if action.operation_key in expected)


def test_original_ncnn_fills_real_bytes_without_freezing_loop_pointer(actual_units):
    unit = actual_units[0x1dc83c]
    program = unit.scopes.program.evidence
    constant = next(row.space_id for row in program.address_spaces if row.is_constant_space)
    register = next(row.space_id for row in program.address_spaces if row.is_register_space)
    (memory,) = {o.inputs[0].coordinate.byte_offset for i in unit.observation.instructions
                 for o in i.operations if o.opcode in ("LOAD", "STORE")}
    normalized = FunctionNormalizer().normalize(unit)
    all_stores = {row.operation_key for row in normalized.memory_graph.loop_memory.plan.accesses}
    # Normal nonnegative dimensions exercise the four-float and scalar paths.
    # The other vector pair is structurally proved above, not claimed reached
    # by these concrete samples or forced by replacing an original branch.
    for count, base in [(n, 0x60000000) for n in (0, 1, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31)] \
            + [(5, (1 << 64) - 8)]:
        value = 0x3f800000 + count

        def image(space, address):
            if space == memory:
                for start, number, width in ((0x50000000, base, 8), (0x50000038, count, 4), (0x50000040, 1, 4)):
                    if start <= address < start + width:
                        return (number >> (8 * (address - start))) & 255
            return None

        vm = Interpreter(unit.observation, constant_space=constant, seed=count, image=image,
                         address_bits={memory: 64})
        for offset, number in ((8, 0x70000000), (0x4000, 0x50000000), (0x5000, value)):
            vm.preset(register, offset, 8, number)
        run = vm.run()
        assert run.completed and not vm.opaque_opcodes
        assert run.executed.count("1b1:1dc864:2:STORE") == count // 4
        assert run.executed.count("1b1:1dc8dc:2:STORE") == count % 4
        actual = {address: byte for (space, address), (byte, writer, _) in vm.final_bytes().items()
                  if space == memory and writer in all_stores}
        expected = {(base + byte) % (1 << 64): (value >> (8 * (byte % 4))) & 255 for byte in range(count * 4)}
        assert actual == expected
