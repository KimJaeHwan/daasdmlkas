"""Original Suite10 indexed halfword STORE, summary and caller binding.

TDO_INDEXED_CALL_MEMORY_BUNDLE selects a fresh bounded export of the original
Suite10 ELF's TV2C687_write_lane and TV2C687_write_lane_thunk, not a test-only
replacement binary. The original interpreter executes both bodies unchanged.
Source: tdo_testbed_UE/cpp_like/src/cases_fusion.cpp:2810 and :2816.
"""

from hashlib import sha256
import os
from pathlib import Path

import pytest

from forward_oracle import _Recording
from program_oracle import _place, check_program
from record_oracle import entry_reader
from test_callee_preserved_low_binary import (
    APPEND, REPO, _core_run, _projector, core, image_ranges,
)
from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from tdo_v2.image_info import ReadOnlyImage, load_image_info
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.interprocedural import analyze_units, function_key
from tdo_v2.normalize import NormalizedFunction
from tdo_v2.operation_records import StitchContext, eligibility, evaluate, render, root_record
from tdo_v2.relative_memory import ImageBaseTracking
from tdo_v2.span_geometry import StorageObjectKind
from tdo_v2.summary_templates import export_summary, image_provenance, instantiate


LEAF, CALLER = "1b1:10b560", "1b1:10b5a0"
STORE, CALL = "1b1:10b597:1:STORE", "1b1:10b5bc:2:CALL"
IMAGE_SHA = "68e1f59b6e4980df254407d430f065072d9ac64805588993e508de3e0b5da4a4"
DIGESTS = {
    LEAF: "ac3a72232f08ea14a84263c7e63d85193c9e1a00196c7bc11b925d1f06aef055",
    CALLER: "94496883dd61a32001eebb9fa135e5c70da57075f1c131c84162f4d2d08fa0be",
}
INDICES = (0, 1, 2, 3, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF)


@pytest.fixture(scope="module")
def indexed_binary():
    location = os.environ.get("TDO_INDEXED_CALL_MEMORY_BUNDLE")
    if not location:
        pytest.skip("set TDO_INDEXED_CALL_MEMORY_BUNDLE to the original two-function Suite10 export")
    generation = Path(location)
    binding = NamingBindingExpectation(sha256((REPO / "ghidra" / "GhidraV2CallNaming.java").read_bytes()).digest(),
                                       CALL_NAMING_GHIDRA_VERSION)
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        scope = session.program_result
        units = {function_key(row.unit.scopes.function.entry): row.unit for row in session.iter_functions()}
    assert set(units) == {LEAF, CALLER}
    assert scope.evidence.executable_sha256.hex() == IMAGE_SHA
    for key, digest in DIGESTS.items():
        assert units[key].scopes.function.observation_digest.hex() == digest
    info = load_image_info(generation)
    assert info is not None, "use the current bounded exporter, including original image facts"
    image = ReadOnlyImage(generation, info)
    spaces = scope.evidence.address_spaces
    ids = tuple(next(row.space_id for row in spaces if getattr(row, flag))
                for flag in ("is_constant_space", "is_register_space", "is_unique_space"))
    memory = scope.evidence.image_base.space_id
    relocates = image_provenance(lambda address, size: image.value(memory, address, size),
                                [(offset, size) for sid, offset, size in info.relocations if sid == memory])
    provenance = {}
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("TDO_V2_FORWARD", "1")
        with ImageBaseTracking(image_ranges(info, memory), relocates):
            results = analyze_units(list(units.values()), image_info=info, record_provenance=provenance,
                                    assume_import_slots_hold_exports=False,
                                    assume_globals_disjoint_from_stack=False,
                                    assume_entry_values_not_frame=False,
                                    assume_opaque_callees_leave_no_stack_addresses=False,
                                    private_frame_above=0)
    assert all(isinstance(item.normalized, NormalizedFunction) for item in results.values())
    return dict(units=units, results=results, ids=ids, memory=memory, image=image, provenance=provenance,
                program={(unit.scopes.function.entry.space_id, unit.scopes.function.entry.byte_offset):
                         unit.observation for unit in units.values()},
                address_bits={row.space_id: row.address_size_bits for row in spaces if row.is_memory_space})


@pytest.mark.parametrize("key", (LEAF, CALLER))
def test_original_indexed_store_address_width_value_and_two_writer_bytes(indexed_binary, key):
    case = indexed_binary
    constant, register, _ = case["ids"]
    unit = case["units"][key]
    _, operations = _projector(case["results"][LEAF])
    assert operations[STORE].inputs[2].byte_size == 2
    for seed, index in enumerate(INDICES):
        base, value = 0x71000000, 0x12340000 | ((0xA15B + seed) & 0xFFFF)
        expected = (base + 2 * index) & ((1 << 64) - 1)
        vm = _Recording(unit.observation, constant_space=constant, seed=seed,
                        subjects={STORE: 1} if key == LEAF else {},
                        contexts={(CALL, STORE): 1} if key == CALLER else {},
                        program=case["program"], address_bits=case["address_bits"])
        for offset, number in ((0x20, 0x70000000), (0x28, 0x74000000),
                               (0x38, base), (0x30, (0xDEADBEEF << 32) | index), (0x10, value)):
            vm.preset(register, offset, 8, number)
        run = vm.run()
        assert run.completed and STORE in run.executed and not vm.opaque_opcodes
        assert vm.seen[STORE if key == LEAF else (CALL, STORE)] == [expected]
        for byte in range(2):
            actual, writer = vm._byte(case["memory"], expected + byte)
            assert actual == ((value >> (8 * byte)) & 0xFF)
            assert writer == (STORE if key == LEAF else CALL)
        if key == CALLER:
            effect = dict(case["results"][CALLER].normalized.proven_call_effects)[CALL]
            (indexed,) = [run.write for run in effect.memory_runs if run.write.index is not None]
            (call, snapshot), = vm.activation_snapshots.values()
            assert call == CALL
            assert _place(indexed, snapshot, vm.entry_values, register, moduli=vm._moduli) == (
                case["memory"], expected, 2)


def test_original_store_summary_carries_the_exact_entry_register_relation(indexed_binary):
    item = indexed_binary["results"][LEAF]
    object_id = dict(item.summary.writer_objects)[STORE]
    relation = dict(item.summary.address_relations)[object_id]
    assert relation.base.object_id.kind is StorageObjectKind.REGISTER_FILE
    assert (relation.base.start, relation.base.size) == (0x38, 8)
    assert relation.index.object_id == relation.base.object_id
    assert (relation.index.start, relation.index.size) == (0x30, 4)
    assert (relation.space_id, relation.extend, relation.preoffset, relation.scale) == (0x1B1, "zext", 0, 2)
    runs = [run for exit_ in item.summary.exits for run in exit_.runs if STORE in run.writers]
    assert runs and all(run.span.object_id == object_id and run.span.size == 2 for run in runs)


def test_original_indexed_summary_template_roundtrip(indexed_binary):
    item = indexed_binary["results"][LEAF]
    template = export_summary(item, indexed_binary["results"])
    indexed = [row["indexed"] for row in template["objects"] if "indexed" in row]
    assert indexed == [dict(base=dict(object="registers", start=0x38, size=8),
                            index=dict(object="registers", start=0x30, size=4),
                            extend="zext", preoffset=0, scale=2)]
    relation = dict(item.summary.address_relations)[dict(item.summary.writer_objects)[STORE]]
    restored, _ = instantiate(template, "actual-suite10-indexed-halfword", relation.base.object_id, 0x1B1)
    assert len(restored.address_relations) == len(item.summary.address_relations)
    (_, recovered), = restored.address_relations
    assert (recovered.base.start, recovered.base.size, recovered.index.start, recovered.index.size,
            recovered.space_id, recovered.extend, recovered.preoffset, recovered.scale) == (0x38, 8, 0x30, 4,
                                                                                         0x1B1, "zext", 0, 2)


def test_original_caller_receives_an_indexed_proven_memory_run_and_real_ssa_write(indexed_binary):
    item = indexed_binary["results"][CALLER]
    effect = dict(item.normalized.proven_call_effects)[CALL]
    runs = [(ordinal, run) for ordinal, run in enumerate(effect.memory_runs, start=len(effect.runs))
            if run.write.index is not None]
    assert len(runs) == 1
    ordinal, run = runs[0]
    assert run.write.anchor is not None and (run.write.anchor.start, run.write.anchor.size) == (0x38, 8)
    assert (run.write.displacement, run.write.size) == (0, 2)
    assert run.write.index.memory is None
    assert (run.write.index.register.start, run.write.index.register.size) == (0x30, 4)
    assert (run.write.index.extend, run.write.index.preoffset, run.write.index.scale) == ("zext", 0, 2)
    definitions = [definition for definition in item.normalized.memory_ssa.definitions
                   if definition.operation_key == f"{CALL}~{ordinal}"
                   and definition.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE]
    assert len(definitions) == 1 and definitions[0].span.size == 2
    assert definitions[0].span.object_id in item.normalized.wild_objects
    # The caller must retain the varying index, not collapse it to base+0.
    atoms, space = dict(item.normalized.address_objects)[definitions[0].span.object_id]
    assert space == 0x1B1 and sorted(coefficient for _, coefficient in atoms) == [1, 2]


def test_original_caller_graph_oracle_locates_every_indexed_written_byte(indexed_binary):
    case = indexed_binary
    item = case["results"][CALLER]
    stack = 0x70000000

    def registers(seed):
        index = INDICES[seed]
        # Every index writes the caller's saved RBP bytes, making its original
        # post-call LOAD demand the callee's real two-byte STORE. Distinct
        # high unsigned indices still land here only through the correct zext.
        base = (stack - 8 - 2 * index) & ((1 << 64) - 1)
        return {0x20: stack, 0x28: 0x74000000, 0x38: base,
                0x30: (0xDEADBEEF << 32) | index, 0x10: 0xA15B + seed}

    report = check_program(item.normalized, item.unit.observation, case["program"],
                           seeds=range(len(INDICES)), register_pools=registers,
                           spaces=case["ids"], address_bits=case["address_bits"], external_abi="sysv64")
    assert report.runs == len(INDICES) and report.unsupported == 0
    assert report.checked > 0 and report.through_calls > 0
    assert report.place_checked > 0 and report.place_covered > 0
    assert report.place_unlocated_only == report.place_failed == report.place_failed_debt == 0
    # This original callee does not claim whole-memory preservation; the
    # checked obligation is its two bytes demanded by the caller's real LOAD.
    assert report.footprint_unlocated == 0
    assert not report.silent and not report.covered_by_debt


def test_original_thunk_reexports_the_same_entry_relation_through_its_summary(indexed_binary):
    item = indexed_binary["results"][CALLER]
    relations = dict(item.summary.address_relations)
    assert len(relations) == 1
    (object_id, relation), = relations.items()
    assert relation.base.object_id.kind is StorageObjectKind.REGISTER_FILE
    assert relation.index.object_id == relation.base.object_id
    semantic = (relation.base.start, relation.base.size, relation.index.start, relation.index.size,
                relation.space_id, relation.extend, relation.preoffset, relation.scale)
    assert semantic == (0x38, 8, 0x30, 4, 0x1B1, "zext", 0, 2)
    runs = [run for exit_ in item.summary.exits for run in exit_.runs if run.span.object_id == object_id]
    assert runs and all(run.span.size == 2 for run in runs)
    template = export_summary(item, indexed_binary["results"])
    restored, _ = instantiate(template, "actual-suite10-indexed-thunk", relation.base.object_id, 0x1B1)
    (_, recovered), = restored.address_relations
    assert (recovered.base.start, recovered.base.size, recovered.index.start, recovered.index.size,
            recovered.space_id, recovered.extend, recovered.preoffset, recovered.scale) == semantic


def test_original_thunk_memory_output_stitches_to_the_original_child_store(indexed_binary):
    case = indexed_binary
    item = case["results"][CALLER]
    effect = dict(item.normalized.proven_call_effects)[CALL]
    (ordinal,) = [ordinal for ordinal, run in enumerate(effect.memory_runs, start=len(effect.runs))
                  if run.write.index is not None]
    (identifier,) = [identifier for identifier, definition in enumerate(item.normalized.memory_ssa.definitions)
                     if definition.operation_key == f"{CALL}~{ordinal}"
                     and definition.span.object_id.kind is StorageObjectKind.FUNCTION_RELATIVE]
    span = item.normalized.memory_ssa.definitions[identifier].span
    node = item.normalized.memory_graph.definition_nodes[identifier]
    record = root_record(item.normalized, item.unit, [(node, (span,))], declared=item.declared,
                         provenance=case["provenance"][id(item)][1], stitch=StitchContext(case["provenance"]))
    assert not record["truncated"]
    (called,) = [node for node in record["nodes"] if node["kind"] == "call" and node["call"] == CALL]
    assert called.get("stitched"), called.get("stitch_cut")
    assert any(node["kind"] == "op" and node.get("key") == STORE and node.get("import")
               for node in record["nodes"])
    assert eligibility(record, "stitched") is None
    assert "zext" in called["stitched"][0]["output"]["place"]
    assert "=>" in render(record)
    constant, register, _ = case["ids"]
    for seed, index in enumerate(INDICES):
        value = 0x12340000 | ((0xA15B + seed) & 0xFFFF)
        vm = _Recording(item.unit.observation, constant_space=constant, seed=seed, subjects={},
                        program=case["program"], address_bits=case["address_bits"])
        for offset, number in ((0x20, 0x70000000), (0x28, 0x74000000), (0x38, 0x71000000),
                               (0x30, (0xDEADBEEF << 32) | index), (0x10, value)):
            vm.preset(register, offset, 8, number)
        assert vm.run().completed
        read = entry_reader(vm)

        def entry(node):
            if isinstance(node, dict) and "register" in node:
                part = node["register"]
                return read(("entry", register, part["offset"], part["size"]))
            return read(node)

        trace = set()
        assert evaluate(record, entry, route="stitched", trace=trace) == {value & 0xFFFF}
        assert called["id"] in trace


def test_original_core_post_resize_store_is_not_relabelled_as_an_entry_base(core, monkeypatch):
    result = _core_run(core, monkeypatch, True, tracking=True)
    summary = result["results"][APPEND].summary
    assert {"1b1:1800f5078:3:STORE", "1b1:1800f50d6:3:STORE"} <= set(summary.unknown_writers)
    objects = dict(summary.writer_objects)
    relations = dict(summary.address_relations)
    assert not any(objects.get(writer) in relations for writer in
                   ("1b1:1800f5078:3:STORE", "1b1:1800f50d6:3:STORE"))
