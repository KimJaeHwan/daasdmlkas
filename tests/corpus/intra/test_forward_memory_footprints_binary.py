"""Original DFB044 stack accesses, with DFB043/122 as unchanged controls.

Set TDO_FORWARD_MEMORY_BUNDLE to the sealed seven-function Suite09 subset.
The original ELF SHA and function observations below pin the compiled code;
the shared source global is program input, and all source/sink bodies execute.
No source return or memory instruction is replaced in the raw runs.
"""

from hashlib import sha256
import json
import os
from pathlib import Path
import sys

import pytest

from forward_oracle import _Recording
from tdo_v2 import summary_engine
from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from tdo_v2.forward import concretizes, forward_facts
from tdo_v2.image_info import ReadOnlyImage, load_image_info
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.interprocedural import _direct_calls, function_key
from tdo_v2.normalize import NormalizedFunction


REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "tools" / "bundle_export"))
import run_dfbench


CONSTANT, VARIABLE, STRCPY = "1b1:104bb5", "1b1:104bf6", "1b1:105450"
INDEX_STORE, INDEX_LOAD = "1b1:104c22:2:STORE", "1b1:104c39:1:LOAD"
ARRAY_STORE, ARRAY_LOAD = "1b1:104c35:4:STORE", "1b1:104c3e:3:LOAD"
IMAGE_SHA = "759c776096d7454feadfbe92b4645b4a825450cce099b732363b1d9cc7238e29"
DIGESTS = {
    CONSTANT: "84aacdf2a24798f99f476558223a74dffc57ec4dc1cec2646a865957fa28a031",
    VARIABLE: "616eb37389b7b178e624ff29616ce3ec1a773d6ce8cf1d65bc8e20ac55baa542",
    STRCPY: "94bb3e9a6c876199ae6d8967b7ef28bd4ead49059b7d46b82addf8e82d21a28d",
}
SOURCE_INPUTS = (0, 1, 2, 3, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF)


@pytest.fixture(scope="module")
def actual():
    location = os.environ.get("TDO_FORWARD_MEMORY_BUNDLE")
    if not location:
        pytest.skip("set TDO_FORWARD_MEMORY_BUNDLE to the original sealed Suite09 subset")
    generation = Path(location)
    binding = NamingBindingExpectation(
        sha256((REPO / "ghidra" / "GhidraV2CallNaming.java").read_bytes()).digest(),
        CALL_NAMING_GHIDRA_VERSION,
    )
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        program_scope = session.program_result
        evidences = list(session.iter_functions())
    units = {function_key(row.unit.scopes.function.entry): row.unit for row in evidences}
    selected, pending = set(), list(DIGESTS)
    while pending:
        key = pending.pop()
        if key in selected:
            continue
        selected.add(key)
        pending.extend(_direct_calls(units[key], units).values())
    assert selected == set(DIGESTS) | {"1b1:10453b", "1b1:10454a", "1b1:104559", "1b1:104595"}
    evidences = [row for row in evidences if function_key(row.unit.scopes.function.entry) in selected]
    for key, digest in DIGESTS.items():
        assert units[key].scopes.function.observation_digest.hex() == digest
    evidence = units[VARIABLE].scopes.program.evidence
    assert evidence.executable_sha256.hex() == IMAGE_SHA
    register = next(row.space_id for row in evidence.address_spaces if row.is_register_space)
    constant = next(row.space_id for row in evidence.address_spaces if row.is_constant_space)
    manifest = json.loads((generation / "manifest.json").read_text())
    members = {row["id"]: row["path"] for row in manifest["members"]}
    blocks = [(row["space_id"], row["byte_start"], (generation / members[row["member_id"]]).read_bytes())
              for row in manifest["blocks"] if row["is_initialized"] and row["member_id"]]

    def image(space, address):
        for block_space, start, data in blocks:
            if space == block_space and start <= address < start + len(data):
                return data[address - start]
        return None

    image_info = load_image_info(generation)
    assert image_info is not None
    (source_global,) = [row for row in image_info.exports if row.name == "g_dfb_source_seed"]
    return dict(generation=generation, scope=program_scope, evidences=evidences, units=units,
                image_info=image_info, readonly=ReadOnlyImage(generation, image_info), image=image,
                register=register, constant=constant, source_global=source_global,
                program={(units[key].scopes.function.entry.space_id,
                          units[key].scopes.function.entry.byte_offset): units[key].observation
                         for key in selected},
                address_bits={row.space_id: row.address_size_bits for row in evidence.address_spaces
                              if row.is_memory_space})


def _analyze(actual, monkeypatch, enabled, engine, *, identities=False, provenance=None):
    captured = {}
    analyze = summary_engine.analyze_units

    def capture(*args, **options):
        result = analyze(*args, **options)
        captured.update(result)
        if provenance is not None:
            provenance.update(options.get("record_provenance") or {})
        return result

    with monkeypatch.context() as patch:
        patch.setenv("TDO_V2_FORWARD", "1" if enabled else "0")
        patch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
        patch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
        if not identities:
            from tdo_v2 import _load_identity

            patch.setattr(_load_identity, "prepare_load_identities", lambda *args, **options: None)
        patch.setattr(summary_engine, "analyze_units", capture)
        run = summary_engine.analyze_observed_with_summaries(
            actual["scope"], actual["evidences"], image_info=actual["image_info"],
            readonly_image=actual["readonly"],
            boundary_provider=run_dfbench.boundary_provider(False, "sysv64"),
            external_models=run_dfbench.external_models(actual["generation"]), operation_records=True,
        )
    assert not run.failed_functions
    assert all(isinstance(row.normalized, NormalizedFunction) for row in captured.values())
    roots = {f"{row.function_space_id:x}:{row.function_byte_offset:x}": row for row in run.roots}
    assert set(roots) == set(DIGESTS)
    return roots, captured


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_original_index_reload_drops_only_the_disjoint_array_writer(actual, monkeypatch, engine):
    before, old = _analyze(actual, monkeypatch, False, engine)
    after, new = _analyze(actual, monkeypatch, True, engine)
    assert before[VARIABLE].reached_origin_labels == after[VARIABLE].reached_origin_labels == (
        "dfb_source_A.ret", "dfb_source_C.ret")
    assert before[VARIABLE].effective_completeness.reachable_unresolved_reads == 2
    assert after[VARIABLE].effective_completeness.reachable_unresolved_reads == 1
    assert not after[VARIABLE].is_effectively_complete
    for key, origins in ((CONSTANT, ("dfb_source_B.ret",)), (STRCPY, ("dfb_source_A.ret",))):
        assert before[key] == after[key]
        assert after[key].reached_origin_labels == origins
        assert after[key].is_effectively_complete
        assert after[key].effective_completeness.reachable_unresolved_reads == 0
    assert any(row.operation_key == INDEX_LOAD and ARRAY_STORE in row.writers
               for row in old[VARIABLE].normalized.may_alias_reads)
    normalized = new[VARIABLE].normalized
    assert all(ARRAY_STORE not in row.writers for row in normalized.may_alias_reads
               if row.operation_key == INDEX_LOAD)
    ssa = normalized.memory_ssa
    reads = [row for row in ssa.reads if ssa.actions[row.action_id].operation_key == INDEX_LOAD
             and row.span.object_id.kind.value == "function_relative"]
    assert reads and sum(row.span.size for row in reads) == 4
    assert {ssa.definitions[definition].operation_key for row in reads for fragment in row.fragments
            for definition in fragment.definition_ids} == {INDEX_STORE}
    old_facts = {row.operation: row for row in forward_facts(
        old[VARIABLE].normalized, old[VARIABLE].unit, readonly_image=actual["readonly"])}
    facts = {row.operation: row for row in forward_facts(
        normalized, new[VARIABLE].unit, readonly_image=actual["readonly"])}
    assert not old[VARIABLE].normalized.forward_memory_proofs
    (proof,) = [row for row in normalized.forward_memory_proofs
                if (row.read, row.writer) == (INDEX_LOAD, ARRAY_STORE)]
    assert proof.span.size == 4 and proof.span.object_id.kind.value == "function_relative"
    for fact, key in ((proof.read_fact, INDEX_LOAD), (proof.write_fact, ARRAY_STORE)):
        assert (fact.operation, fact.function, fact.input, fact.context) == (key, VARIABLE, 1, ())
        assert fact.claim == old_facts[key].claim
        assert set(old_facts[key].requires) <= set(fact.requires)
    assert ARRAY_LOAD not in old_facts
    assert facts[ARRAY_LOAD].claim == facts[ARRAY_STORE].claim
    ((base, offsets),) = facts[ARRAY_LOAD].claim.items
    assert base == ("entry", 0x20, 8)
    assert (offsets.lo, offsets.hi, offsets.stride, offsets.bits, offsets.signed) == (-40, -28, 4, 64, True)


def test_actual_sparse_and_dense_results_agree(actual, monkeypatch):
    sparse_roots, sparse = _analyze(actual, monkeypatch, True, "sparse")
    dense_roots, dense = _analyze(actual, monkeypatch, True, "dense")
    assert sparse_roots == dense_roots
    assert sparse.keys() == dense.keys()
    for key in sparse:
        assert sparse[key].summary == dense[key].summary
        assert sparse[key].normalized.memory_ssa == dense[key].normalized.memory_ssa
        assert sparse[key].normalized.may_alias_reads == dense[key].normalized.may_alias_reads
        assert sparse[key].normalized.forward_memory_proofs == dense[key].normalized.forward_memory_proofs


@pytest.mark.parametrize("engine", ("sparse", "dense"))
def test_original_pcode_bytes_values_addresses_and_widths(actual, monkeypatch, engine, identities=False):
    _, analyzed = _analyze(actual, monkeypatch, True, engine, identities=identities)
    item = analyzed[VARIABLE]
    facts = {row.operation: row for row in forward_facts(
        item.normalized, item.unit, readonly_image=actual["readonly"])}
    observation = item.unit.observation
    operations = {f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}:{n}:{operation.opcode}":
                  operation for instruction in observation.instructions
                  for n, operation in enumerate(instruction.operations)}
    subjects = {key: 1 for key in (INDEX_STORE, INDEX_LOAD, ARRAY_STORE, ARRAY_LOAD)}
    value_subjects = {INDEX_STORE: 2, ARRAY_STORE: 2,
                      "1b1:104c39:2:COPY": 0, "1b1:104c3e:4:COPY": 0}
    for key in subjects:
        operation = operations[key]
        width = operation.output.byte_size if operation.opcode == "LOAD" else operation.inputs[2].byte_size
        assert width == 4
    indices = set()
    for number, seed in enumerate(SOURCE_INPUTS):
        stack = 0x70000000 + 0x100 * number
        index, value = (seed + 3) & 3, (seed + 1) & 0xFFFFFFFF
        indices.add(index)
        recordings = []
        for selected in (subjects, value_subjects):
            vm = _Recording(observation, subjects=selected, constant_space=actual["constant"], seed=number,
                            program=actual["program"], image=actual["image"], address_bits=actual["address_bits"])
            vm.preset(actual["register"], 0x20, 8, stack)
            global_ = actual["source_global"]
            vm.preset(global_.space_id, global_.byte_offset, 4, seed)
            run = vm.run()
            assert run.completed and run.executed and not vm.opaque_opcodes
            recordings.append((vm, run))
        vm, run = recordings[0]
        addresses = {INDEX_STORE: stack - 12, INDEX_LOAD: stack - 12,
                     ARRAY_STORE: stack - 40 + 4 * index, ARRAY_LOAD: stack - 40 + 4 * index}
        for key, address in addresses.items():
            assert vm.seen[key] == [address]
            if key in facts:
                assert concretizes(facts[key].claim, address, lambda offset, size: stack)
        assert recordings[1][0].seen == {
            INDEX_STORE: [index], ARRAY_STORE: [value],
            "1b1:104c39:2:COPY": [index], "1b1:104c3e:4:COPY": [value],
        }
        for reader, writer, expected in ((INDEX_LOAD, INDEX_STORE, index), (ARRAY_LOAD, ARRAY_STORE, value)):
            address = addresses[reader]
            dependencies = {row.offset: row.writer for row in run.dependencies
                            if row.reader == reader and row.space_id == 0x1B1}
            assert dependencies == {address + byte: writer for byte in range(4)}
            assert [vm._bytes[(0x1B1, address + byte)] for byte in range(4)] == [
                ((expected >> (8 * byte)) & 0xFF, writer) for byte in range(4)]
    assert indices == {0, 1, 2, 3}
    assert set(subjects) <= facts.keys()
