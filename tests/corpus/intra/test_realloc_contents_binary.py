"""Original ELF content observations relative to explicit allocator oracles.

The Android-built ELF is not a glibc runtime certification. The existing
interpreter's always-moved allocator and the small in-place/failure adapters
below select external outcomes; they are not native executions or proofs of
all paths. Static copied-content assertions are added separately from these
source/image/observation pins and original byte-writer observations.
"""

from hashlib import sha256
from dataclasses import replace
import os
from pathlib import Path

import pytest

from forward_oracle import _Recording
from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from tdo_v2.image_info import load_image_info
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.interprocedural import function_key
from tdo_v2.interprocedural import analyze_units
from tdo_v2.forward import probe
from tdo_v2.lifecycle_contracts import load_lifecycle_contracts
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.query import BackwardSliceQuery
from tdo_v2.summary_store import load_external_models


REPO = Path(__file__).resolve().parents[3]
SOURCE_SHA = "0cd135a43cd88c56c9fe6ffad01b7a1500dedbd686543b2e09d2144dc066e5fb"
IMAGE_SHA = "0d9b7940e00656ae71a5a69989c11cebdba519c50623c02ecbdee4cb79f42a42"
GROW, SHRINK, PARTIAL, OPAQUE = "1b1:1007e0", "1b1:100840", "1b1:1008a0", "1b1:100910"
DIGESTS = {
    GROW: "1de21db7be0ae53deb82cb7aeaf0c00122a747d35d6ae16432cc4e9c68854341",
    SHRINK: "8b12011b68de03a6b52ae78767762dd41a89da962690f7d23e008d492eea4a5d",
    PARTIAL: "4559072398f6bafb7757305d1b1821496118367c3f0f7867a0d8a093448002d3",
    OPAQUE: "ff5c5154c48dba8f68878e6e60b6f214a1718ce78da819e4a822779a4a679d01",
}
# Original STORE4 offsets 0/4/12, realloc CALL, success LOAD8, free CALL,
# original result-NULL CBRANCH, and requested size. Addresses pin this ELF,
# never production dispatch or a claimed universal allocator target set.
POINTS = {
    GROW: (("1007fc:1", "100803:2", "100807:2"), "100816:2", "100820:0", "100833:2", "10081e:0", 32),
    SHRINK: (("10085c:1", "100863:2", "100867:2"), "100876:2", "100880:0", "100893:2", "10087e:0", 8),
    PARTIAL: (("1008bc:1", "1008c3:2", "1008c7:2"), "1008d6:2", "1008e6:0", "1008f9:2", "1008de:0", 32),
    OPAQUE: (("10092c:1", "100933:2", "100937:2"), "100946:2", "10095b:0", "10096b:2", "10094e:0", 32),
}
PATCH, BARRIER = "1b1:1008e0:2:STORE", "1b1:100956:2:CALL"


def _key(point, opcode):
    return "1b1:" + point + ":" + opcode


@pytest.fixture(scope="module")
def binary():
    location = os.environ.get("TDO_REALLOC_CONTENTS_BUNDLE")
    if not location:
        pytest.skip("set TDO_REALLOC_CONTENTS_BUNDLE to the sealed four-function realloc ELF")
    generation = Path(location)
    assert sha256((REPO / "tests/corpus/fixtures/realloc_contents.c").read_bytes()).hexdigest() == SOURCE_SHA
    assert sha256((generation / "original.bin").read_bytes()).hexdigest() == IMAGE_SHA
    binding = NamingBindingExpectation(sha256((REPO / "ghidra/GhidraV2CallNaming.java").read_bytes()).digest(),
                                       CALL_NAMING_GHIDRA_VERSION)
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        scope = session.program_result
        units = {function_key(row.unit.scopes.function.entry): row.unit for row in session.iter_functions()}
    assert set(units) == set(DIGESTS) and scope.evidence.executable_sha256.hex() == IMAGE_SHA
    for key, digest in DIGESTS.items():
        assert units[key].scopes.function.observation_digest.hex() == digest
    spaces = scope.evidence.address_spaces
    memory = scope.evidence.image_base.space_id
    register = next(row.space_id for row in spaces if row.is_register_space)
    constant = next(row.space_id for row in spaces if row.is_constant_space)
    return dict(units=units, memory=memory, register=register, constant=constant,
                info=load_image_info(generation),
                models=load_external_models(sorted((REPO / "models/external").glob("*.json")),
                                            "x86:LE:64:default", "sysv64"),
                program={(memory, unit.scopes.function.entry.byte_offset): unit.observation
                         for unit in units.values()},
                address_bits={row.space_id: row.address_size_bits for row in spaces if row.is_memory_space})


def _operations(unit):
    return {f"{ins.address.space_id:x}:{ins.address.byte_offset:x}:{i}:{op.opcode}": op
            for ins in unit.observation.instructions for i, op in enumerate(ins.operations)}


@pytest.mark.parametrize("function", POINTS)
def test_original_three_stores_success_guard_and_memory_widths(binary, function):
    stores, call, read, release, branch, _ = POINTS[function]
    ops = _operations(binary["units"][function])
    assert [ops[_key(point, "STORE")].inputs[2].byte_size for point in stores] == [4, 4, 4]
    assert ops[_key(read, "LOAD")].output.byte_size == 8
    assert ops[_key(call, "CALL")].inputs[0].coordinate.byte_offset == 0x1009C0
    assert ops[_key(release, "CALL")].inputs[0].coordinate.byte_offset == 0x1009D0
    assert ops[_key(branch, "CBRANCH")].inputs[1].byte_size == 1
    if function == PARTIAL:
        assert ops[PATCH].inputs[2].byte_size == 2
    if function == OPAQUE:
        assert ops[BARRIER].inputs[0].coordinate.byte_offset == 0x1009E0


class _OutcomeRecording(_Recording):
    """One existing interpreter, choosing only the named external outcome.

    In-place and failure execute the base interpreter's existing no-memory
    external footer (same ABI-volatile havoc and SP restore). The opaque
    adapter chooses a one-byte mutation, not a static preservation contract.
    All original p-code operations and their data dependencies are unchanged.
    """

    def __init__(self, *args, resize_outcome, **kwargs):
        super().__init__(*args, **kwargs)
        self.resize_outcome = resize_outcome
        self.resize_observation = None
        self.values = {}

    def _execute(self, key, operation, run):
        if key in self.subjects and operation.opcode == "STORE":
            self.values.setdefault(key, []).append(self._subject_value(operation.inputs[2]))
        result = super()._execute(key, operation, run)
        if key in self.subjects and operation.opcode == "LOAD":
            self.values.setdefault(key, []).append(self._subject_value(operation.output))
        return result

    def _run_external_body(self, name, key):
        if name not in ("realloc", "realloc_opaque_mutate"):
            return super()._run_external_body(name, key)
        register, memory = self._havoc[0], self._order[0][0]
        (first, second, _), _ = self._EXTERNAL_ABIS[self._external_abi]
        old, _ = self._peek(register, first, 8)
        if name == "realloc_opaque_mutate":
            assert old in self._blocks and self._blocks[old] == 32
            self._put(key, memory, old, 1, 0xA5, {("call", key)})
            return super()._run_external_body("FDebug::CheckVerifyFailedImpl", key)
        size, _ = self._peek(register, second, 8)
        assert old in self._blocks and self._blocks[old] == 16 and size in (8, 32)
        before = tuple(self._byte(memory, old + index) for index in range(16))
        if self.resize_outcome == "moved":
            super()._run_external_body(name, key)
            result, _ = self._peek(register, 0, 8)
            assert result != old and old not in self._blocks and self._blocks[result] == size
        else:
            blocks = dict(self._blocks)
            if self.resize_outcome == "inplace":
                self._blocks[old] = size
                result = old
            else:
                assert self.resize_outcome == "failure"
                result = 0
            super()._run_external_body("FDebug::CheckVerifyFailedImpl", key)
            self._put(key, register, 0, 8, result, set())
            assert tuple(self._byte(memory, old + index) for index in range(16)) == before
            if not result:
                assert self._blocks == blocks
        if result:
            assert tuple(self._byte(memory, result + index) for index in range(min(16, size))) == before[:min(16, size)]
        self.resize_observation = (old, size, result)


def _run(binary, function, outcome, seed):
    stores, _, read, _, _, _ = POINTS[function]
    subjects = {_key(point, "STORE"): 1 for point in stores}
    subjects[_key(read, "LOAD")] = 1
    if function == PARTIAL:
        subjects[PATCH] = 1
    memory, register = binary["memory"], binary["register"]
    vm = _OutcomeRecording(binary["units"][function].observation, constant_space=binary["constant"],
                           seed=0, subjects=subjects, resize_outcome=outcome,
                           program=binary["program"], havoc_calls=(register, 32, 8),
                           externals={(memory, 0x1009B0): "malloc", (memory, 0x1009C0): "realloc",
                                      (memory, 0x1009D0): "free", (memory, 0x1009E0): "realloc_opaque_mutate"},
                           external_abi="sysv64", address_bits=binary["address_bits"])
    for offset, value in ((32, 0x70000000), (40, 0x74000000), (56, seed)):
        vm.preset(register, offset, 8, value)
    return vm, vm.run()


@pytest.mark.parametrize("function", POINTS)
@pytest.mark.parametrize("outcome", ("moved", "inplace", "failure"))
def test_original_content_byte_writers_under_selected_external_outcomes(binary, function, outcome):
    stores, call, read, release, branch, size = POINTS[function]
    writer_keys, reader = tuple(_key(point, "STORE") for point in stores), _key(read, "LOAD")
    for seed in (0, 0x0123456789ABCDEF, 0x80000000FFFFFFFF, 0xFFFFFFFFFFFFFFFF):
        vm, run = _run(binary, function, outcome, seed)
        assert run.completed and not vm.opaque_opcodes and not vm._blocks
        old, observed_size, result = vm.resize_observation
        assert old == 0x60000000 and observed_size == size
        assert run.executed.count(_key(call, "CALL")) == run.executed.count(_key(release, "CALL")) == 1
        assert _key(branch, "CBRANCH") in run.executed
        for writer, offset, value in zip(writer_keys, (0, 4, 12), (seed & 0xFFFFFFFF, seed >> 32, 0x76543210)):
            assert vm.seen[writer] == [old + offset] and vm.values[writer] == [value]
        if outcome == "failure":
            assert result == 0 and vm._free == [old]
            assert reader not in run.executed and PATCH not in run.executed and BARRIER not in run.executed
            assert vm._peek(binary["register"], 0, 8)[0] == 0
            continue
        assert result == (old if outcome == "inplace" else 0x60001000)
        assert vm._free == [result] and vm.seen[reader] == [result]
        expected = seed
        writers = [writer_keys[0]] * 4 + [writer_keys[1]] * 4
        if function == PARTIAL:
            expected = (seed & ~(0xFFFF << 16)) | (0xBEEF << 16)
            assert vm.seen[PATCH] == [result + 2] and vm.values[PATCH] == [0xBEEF]
            writers[2:4] = [PATCH, PATCH]
        if function == OPAQUE:
            expected = (seed & ~0xFF) | 0xA5
            assert run.executed.count(BARRIER) == 1
            writers[0] = BARRIER
        assert vm.values[reader] == [expected] and vm._peek(binary["register"], 0, 8)[0] == expected
        actual = {(row.offset - result, row.writer) for row in run.dependencies
                  if row.reader == reader and row.space_id == binary["memory"]}
        assert actual == set(enumerate(writers))
        assert not any(row.reader == reader and row.writer == writer_keys[2] for row in run.dependencies)


@pytest.fixture(params=("sparse", "dense"))
def static_engine(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    return request.param


def _static(binary, contents):
    # This explicit glibc documentation-relative profile exercises the static
    # model contract. It does NOT identify the Android ELF's runtime as glibc.
    contracts = load_lifecycle_contracts(REPO / "models/lifecycle/glibc_sysv64.json")
    if not contents:
        contracts = tuple(replace(row, contents="unknown") if row.kind == "resize" else row
                          for row in contracts)
    return analyze_units(list(binary["units"].values()), image_info=binary["info"],
                         external_models=binary["models"], lifecycle_contracts=contracts,
                         assume_entry_values_not_frame=False,
                         assume_opaque_callees_leave_no_stack_addresses=False,
                         assume_globals_disjoint_from_stack=False, private_frame_above=0)


def _copy_proofs(item, reader):
    plan = item.normalized.forward_inputs.read_separations
    return () if plan is None else tuple(row for row in plan.copy_proofs if row.reader == reader)


def _call_debts(item, reader):
    return {call for row in item.normalized.call_clobber_reads if row.operation_key == reader
            for call in row.intervening_calls}


def _payload_read(item, reader):
    ssa = item.normalized.memory_ssa
    rows = [row for row in ssa.reads if ssa.actions[row.action_id].operation_key == reader
            and row.span.object_id.kind.value == "function_relative"]
    assert len(rows) == 1
    return rows[0]


def _assert_transfer_graph(item, proofs):
    """Inspect existing graph edges, without building another graph/oracle."""
    normalized = item.normalized
    ssa, bindings, graph = normalized.memory_ssa, normalized.memory_graph, normalized.dependencies
    assert proofs and bindings.transfers and len(bindings.transfers) == len(bindings.transfer_nodes)
    for proof in proofs:
        rows = [(row, node) for row, node in zip(bindings.transfers, bindings.transfer_nodes)
                if ssa.actions[row.action_id].operation_key == proof.reader and row.span == proof.span]
        assert len(rows) == 1
        transfer, node = rows[0]
        definition = ssa.definitions[transfer.definition_id]
        assert definition.kind is MemoryDefinitionKind.DATA_WRITE and definition.operation_key == proof.source[1]
        assert transfer.call == proof.call and transfer.guard == proof.outcome.guard
        assert transfer.contract == proof.contract and transfer.requires == proof.requires
        assert graph.node(node).kind == "effect"
        source = bindings.definition_nodes[transfer.definition_id]
        call = graph.node_for_key("op:" + proof.call)
        guard = graph.node_for_key("op:" + proof.outcome.guard)
        reader = graph.node_for_key("op:" + proof.reader)
        incoming = {(origin, edge.kind, edge.span) for origin, _, edge in graph.in_edges(node)}
        assert (source, "memory_transfer", proof.span) in incoming
        assert (call, "memory_transfer", proof.span) in incoming
        assert (guard, "control_dependence", proof.span) in incoming
        assert any(target == reader and edge.kind == "memory_read" and edge.span == proof.span
                   for _, target, edge in graph.out_edges(node))
        assert not any(target == reader and edge.kind == "memory_read" and edge.span == proof.span
                       for _, target, edge in graph.out_edges(source))
        query = BackwardSliceQuery().run(normalized, reader, include_control=True)
        assert {source, node, call, guard, graph.node_for_key("op:" + definition.operation_key)} <= set(query.reachable_nodes)


@pytest.fixture
def static_results(binary, static_engine):
    # Four small functions only; share both batches across their assertions.
    cache = binary.setdefault("static_cache", {})
    if static_engine not in cache:
        cache[static_engine] = (_static(binary, False), _static(binary, True))
    return cache[static_engine]


@pytest.mark.parametrize("function", (GROW, SHRINK, PARTIAL))
def test_static_prefix_contract_transfers_exact_original_fragments(binary, static_results, function):
    before, after = static_results
    item, original = after[function], before[function]
    stores, call, read, _, branch, size = POINTS[function]
    reader, realloc = _key(read, "LOAD"), _key(call, "CALL")
    assert realloc in _call_debts(original, reader) and not _copy_proofs(original, reader)
    assert not item.proven[realloc].preserves_memory
    if function != PARTIAL:
        assert realloc not in _call_debts(item, reader)
    proofs = _copy_proofs(item, reader)
    assert len(proofs) == 2
    assert {row.source[1] for row in proofs} == {_key(point, "STORE") for point in stores[:2]}
    assert {(row.offset, row.span.size) for row in proofs} == ({(0, 2), (4, 4)} if function == PARTIAL else {(0, 4), (4, 4)})
    for row in proofs:
        assert row.call == realloc and row.old_size == 16 and row.new_size == size
        assert row.outcome.guard == _key(branch, "CBRANCH") and row.result_definitions
        assert row.outcome.success_edge != row.outcome.failure_edge and row.outcome.definitions
        assert row.input_lifetime.live and row.writer_lifetime is not None
        assert row.contract in row.requires and set(row.snapshot_requires) <= set(row.requires)
        assert set(row.requires) <= set(item.inherited_assumptions)
    normalized, read_row = item.normalized, _payload_read(item, reader)
    assert read_row.span.size == 8
    found, labels = probe(normalized, reader, tuple(fragment.span for fragment in read_row.fragments))
    for fragment in read_row.fragments:
        assert len(fragment.definition_ids) == 1
        source = normalized.memory_ssa.definitions[fragment.definition_ids[0]].operation_key
        if source == PATCH:
            assert found[fragment.span] is None
        else:
            assert found[fragment.span] == fragment.definition_ids[0]
    assert {row.contract for row in proofs} <= set(labels)
    _assert_transfer_graph(item, proofs)
    if function == PARTIAL:
        assert sorted(fragment.span.size for fragment in read_row.fragments) == [2, 2, 4]
        (patch,) = [fragment for fragment in read_row.fragments
                   if normalized.memory_ssa.definitions[fragment.definition_ids[0]].operation_key == PATCH]
        identifier = patch.definition_ids[0]
        graph = normalized.dependencies
        assert patch.span.size == 2 and all(row.span != patch.span for row in proofs)
        assert any(origin == normalized.memory_graph.definition_nodes[identifier] and edge.kind == "memory_read"
                   and edge.span == patch.span for origin, _, edge in graph.in_edges(graph.node_for_key("op:" + reader)))
        # Existing CALL clobber derivation does not byte-kill this STORE2
        # from the whole LOAD8 demand. Prefix-copy evidence must neither
        # waive the patch bytes nor mislabel them as copied old contents.
        debts = [row for row in normalized.call_clobber_reads if row.operation_key == reader]
        assert len(debts) == 1 and debts[0].spans == (patch.span,)
        assert debts[0].intervening_calls == (realloc,)


def test_static_unknown_post_resize_call_does_not_borrow_copy_contract(binary, static_results):
    before, after = static_results
    reader, call = _key(POINTS[OPAQUE][2], "LOAD"), _key(POINTS[OPAQUE][1], "CALL")
    for results in (before, after):
        item = results[OPAQUE]
        assert {call, BARRIER} <= _call_debts(item, reader)
        assert not _copy_proofs(item, reader)
        read = _payload_read(item, reader)
        found, _ = probe(item.normalized, reader, tuple(row.span for row in read.fragments))
        assert all(value is None for value in found.values())
        assert not item.proven[call].preserves_memory
