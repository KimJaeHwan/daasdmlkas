"""Original ELF calls/loops under explicit test-only POSIX lifecycle contracts.

The NDK-built Android ELF is not identified as glibc. The two optional
contracts below are documentation-relative test inputs on the existing CRT
model; neither symbol matching nor finite p-code runs certify its runtime
allocator, callbacks, success, or all paths. No freed branch dereferences an
old pointer. The unchanged oracle deliberately reuses a freed address.
"""

from dataclasses import replace
from hashlib import sha256
import os
from pathlib import Path

import pytest

from forward_oracle import _Recording
from tdo_v2._allocation_lifetime import AllocationAnalysis
from tdo_v2._allocation_outcomes import failed_resize
from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from tdo_v2.image_info import load_image_info
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.interprocedural import analyze_units, function_key
from tdo_v2.lifecycle_contracts import load_lifecycle_contracts
from tdo_v2.normalize import NormalizedFunction
from tdo_v2.summary_store import load_external_models


REPO = Path(__file__).resolve().parents[3]
SOURCE_SHA = "a534de72ea6e82a656aaaba97c415e4525cd89e5f19fcd05768d63466bc78e71"
IMAGE_SHA = "4f0d891fbb056a62408ccabcaab8dce7293888e13de8ef3a9941c6d6c35f2a14"
ALIAS, HELPER, LOOP, OUTER = "1b1:1008a0", "1b1:100900", "1b1:100960", "1b1:1009e0"
RESIZE, ZERO, KEEP, KEEP_HELPER = "1b1:100a30", "1b1:100a90", "1b1:100ad0", "1b1:100b20"
DIGESTS = {
    ALIAS: "76410cf8d3e233807ecfc8f528152159297d086a274453ebc31c72e27611d30c",
    HELPER: "58a4e8ff4afa65887cdf37357b9ccac7120d18a2ec3337b73b95886e7321aec5",
    LOOP: "5b3ee894eb297831ea90f91f70870baa2ec2869f5ee8a70b727724f0b10e88c2",
    OUTER: "3d3aed867c6b3a36b59757002b2355a64af57475a97b0c3be2ae7e345882bb2f",
    RESIZE: "810ca13d3954e34833d8cd406967a310a33a36c93dcb0a5607711f33abb2066e",
    ZERO: "b3f716d2133c05a12e088f63f5f457550794d939741fd27d55d1e221bffb3fea",
    KEEP: "0e12ec102409de0135767edadfc1a7097207c0c68a65ed8b85d12169b1e87faa",
    KEEP_HELPER: "302ce198035e2d61953d2fb3dc1ea932faa1130504c31841012fb51953d7b0ec",
}
ALLOCATION, CROSSING = "1b1:1008b5:2:CALL", "1b1:1008ce:2:CALL"
INITIAL, READ = "1b1:1008c2:1:STORE", "1b1:1008db:0:LOAD"
HELPER_WRITE = "1b1:100941:1:STORE"
LOOP_STORE, LOOP_READ = "1b1:100996:1:STORE", "1b1:100999:2:LOAD"
OUTER_STORE, OUTER_READ = "1b1:100a04:1:STORE", "1b1:100a07:2:LOAD"
POSIX = "https://pubs.opengroup.org/onlinepubs/9799919799/functions/"


@pytest.fixture(scope="module")
def binary():
    location = os.environ.get("TDO_ALLOCATION_LIFETIME_BUNDLE")
    if not location:
        pytest.skip("set TDO_ALLOCATION_LIFETIME_BUNDLE to the sealed eight-function lifetime ELF")
    generation = Path(location)
    assert sha256((REPO / "tests/corpus/fixtures/allocation_lifetime.c").read_bytes()).hexdigest() == SOURCE_SHA
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
    models = load_external_models(sorted((REPO / "models/external").glob("*.json")),
                                  "x86:LE:64:default", "sysv64")
    # Reuse physical ports/model identity only, NOT the shipped glibc audit.
    # The POSIX citations and distinct labels are part of each proof's digest.
    contracts = tuple(replace(row, contract_id="posix-fixture-" + ("malloc" if row.kind == "allocate" else "free"),
                              references=(POSIX + ("malloc.html" if row.kind == "allocate" else "free.html"),))
                      for row in load_lifecycle_contracts(REPO / "models/lifecycle/glibc_sysv64.json")
                      if row.kind in ("allocate", "release"))
    assert len(contracts) == 2 and all(row.nullable for row in contracts)
    return dict(units=units, memory=memory, register=register, constant=constant, models=models,
                info=load_image_info(generation), contracts=contracts, cache={},
                program={(memory, unit.scopes.function.entry.byte_offset): unit.observation
                         for unit in units.values()},
                address_bits={row.space_id: row.address_size_bits for row in spaces if row.is_memory_space})


@pytest.fixture(params=("sparse", "dense"))
def engine(request, monkeypatch):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    return request.param


def _analyze(binary, contracts, keys=(ALIAS, HELPER, LOOP, OUTER, KEEP, KEEP_HELPER)):
    return analyze_units([binary["units"][key] for key in keys], image_info=binary["info"],
                         external_models=binary["models"], lifecycle_contracts=contracts,
                         assume_entry_values_not_frame=False,
                         assume_opaque_callees_leave_no_stack_addresses=False,
                         assume_globals_disjoint_from_stack=False, private_frame_above=0)


@pytest.fixture
def results(binary, engine):
    if engine not in binary["cache"]:
        binary["cache"][engine] = _analyze(binary, binary["contracts"])
    return binary["cache"][engine]


def _pointer(analysis, key):
    return analysis.input(key, analysis.ops[key].inputs[1])


def test_original_two_ports_keep_one_ref_and_conditional_free_union(binary, results):
    item, peer = results[ALIAS], results[HELPER]
    assert isinstance(item.normalized, NormalizedFunction)
    peer_before = (peer.normalized, peer.summary, dict(peer.proven))
    analysis = AllocationAnalysis(item, results=results)
    first, second = analysis.argument(CROSSING, (56, 8)), analysis.argument(CROSSING, (48, 8))
    assert not first.unknown and first.targets == second.targets and len(first.targets) == 1
    ref = next(iter(first.targets)).allocation
    assert ref.event == ALLOCATION and ref.function == ALIAS and ref.occurrence == "single"
    assert analysis.lifetime(_pointer(analysis, INITIAL), INITIAL).live
    assert analysis.access(INITIAL) is not None
    after = _pointer(analysis, READ)
    assert after.targets == first.targets
    lifetime = analysis.lifetime(after, READ)
    assert not lifetime.live and len(lifetime.calls) == 1
    crossing = lifetime.calls[0]
    assert crossing.allocation == ref and crossing.context == (ALIAS, CROSSING)
    assert crossing.input_states == ("live",)
    assert set(crossing.output_states) == {"live", "ended"}
    ports = {span.start: fact for span, fact in crossing.ports}
    assert {56, 48} <= set(ports)
    assert ports[56].targets == ports[48].targets == first.targets
    assert any(label.startswith("lifecycle-contract:posix-fixture-free@") for label in lifetime.requires)
    assert not any(label.startswith("lifecycle-contract:glibc-") for label in lifetime.requires)
    assert (peer.normalized, peer.summary, peer.proven) == peer_before
    assert peer.normalized.activation_entry is None and not peer.activations


def test_original_known_null_release_helper_keeps_both_alias_ports_live(binary, results):
    item, peer = results[KEEP], results[KEEP_HELPER]
    peer_before = (peer.normalized, peer.summary, dict(peer.proven))
    analysis = AllocationAnalysis(item, results=results)
    call, reader = "1b1:100af5:2:CALL", "1b1:100afa:0:LOAD"
    first, second = analysis.argument(call, (56, 8)), analysis.argument(call, (48, 8))
    assert first.targets and first.targets == second.targets and not first.unknown and not second.unknown
    pointer = _pointer(analysis, reader)
    assert pointer.targets == first.targets
    lifetime = analysis.lifetime(pointer, reader)
    assert lifetime.live and len(lifetime.calls) == 1
    crossing = lifetime.calls[0]
    assert crossing.input_states == crossing.output_states == ("live",)
    assert crossing.context == (KEEP, call)
    assert {span.start for span, _ in crossing.ports} >= {56, 48}
    assert {target.allocation for _, fact in crossing.ports for target in fact.targets} == \
        {target.allocation for target in first.targets}
    assert "1b1:100b46:2:CALL" in crossing.evidence.events
    assert any(label.startswith("lifecycle-contract:posix-fixture-free@") for label in lifetime.requires)
    assert (peer.normalized, peer.summary, peer.proven) == peer_before
    assert peer.normalized.activation_entry is None and not peer.activations


@pytest.mark.parametrize("key,writer,event,occurrence", (
    (LOOP, LOOP_STORE, "1b1:100985:2:CALL", "family"),
    (OUTER, OUTER_STORE, "1b1:1009ef:2:CALL", "single"),
))
def test_original_loop_birth_use_free_certifies_only_the_current_occurrence(binary, results, key, writer, event, occurrence):
    analysis = AllocationAnalysis(results[key], results=results)
    pointer = _pointer(analysis, writer)
    assert not pointer.unknown and len(pointer.targets) == 1
    ref = next(iter(pointer.targets)).allocation
    assert ref.event == event and ref.occurrence == occurrence
    assert analysis.extent(ref)[0] == 8
    if occurrence == "family":
        assert analysis.local_occurrence(pointer, ref, writer)
    assert analysis.lifetime(pointer, writer).live
    assert analysis.access(writer) is not None


def test_owned_extent_withdrawal_cannot_turn_live_into_a_byte_access(binary, engine):
    weak = tuple(replace(row, owned_footprint=False) if row.kind == "allocate" else row
                 for row in binary["contracts"])
    result = _analyze(binary, weak, (LOOP,))
    analysis = AllocationAnalysis(result[LOOP], results=result)
    pointer = _pointer(analysis, LOOP_STORE)
    assert analysis.lifetime(pointer, LOOP_STORE).live
    assert analysis.access(LOOP_STORE) is None


def test_original_positive_size_null_result_keeps_only_the_failed_old_range(binary, engine):
    # A distinct test-only, failure-only audit. No successful/moved/in-place
    # epoch or zero-size outcome is asserted for this Android-built fixture.
    resize = next(row for row in load_lifecycle_contracts(REPO / "models/lifecycle/glibc_sysv64.json")
                  if row.kind == "resize")
    resize = replace(resize, contract_id="posix-fixture-realloc-failure", failure="retain",
                     inplace="unknown", moved="unknown", zero_size="unknown",
                     references=("https://pubs.opengroup.org/onlinepubs/009696899/functions/realloc.html",))
    result = _analyze(binary, (*binary["contracts"], resize), (RESIZE, ZERO))
    analysis = AllocationAnalysis(result[RESIZE], results=result)
    call, writer, reader = "1b1:100a54:2:CALL", "1b1:100a6b:1:STORE", "1b1:100a6e:0:LOAD"
    pointer = _pointer(analysis, writer)
    assert not pointer.unknown and len(pointer.targets) == 1
    ref = next(iter(pointer.targets)).allocation
    assert ref.event == "1b1:100a3f:2:CALL" and analysis.extent(ref)[0] == 8
    failure = failed_resize(analysis, call, writer)
    assert failure and analysis.lifetime(pointer, writer).live
    assert analysis.lifetime(_pointer(analysis, reader), reader).live
    evidence = analysis.access(writer)
    assert evidence is not None and evidence.outcomes
    assert failure in evidence.outcomes
    assert resize.label in evidence.requires
    # A separate original success-path point cannot borrow the failure edge.
    success = "1b1:100a5e:0:COPY"
    assert success in analysis.ops and not failed_resize(analysis, call, success)
    old = analysis.argument(call, resize.pointer)
    assert old.targets and not analysis.lifetime(old, success).live
    assert not result[RESIZE].proven[call].preserves_memory

    zero = AllocationAnalysis(result[ZERO], results=result)
    zero_call = "1b1:100ab0:2:CALL"
    size = zero.port(resize.size)
    numbers, _ = zero.numeric.bind(zero_call, (size,))
    assert numbers[size].single_number() == 0
    zero_point = "1b1:100ac2:0:COPY"
    assert zero_point in zero.ops and not failed_resize(zero, zero_call, zero_point)


@pytest.mark.parametrize("key,release,expected", ((ALIAS, 0, 0x12340C22), (ALIAS, 1, 0),
                                                 (KEEP, 0, 0x12340C22), (LOOP, 0, 1), (OUTER, 0, 1)))
def test_original_pcode_finite_runs_and_reuse_are_not_native_allocator_claims(binary, key, release, expected):
    unit = binary["units"][key]
    subjects = {f"{ins.address.space_id:x}:{ins.address.byte_offset:x}:{i}:{op.opcode}": 1
                for ins in unit.observation.instructions for i, op in enumerate(ins.operations)
                if op.opcode in ("STORE", "LOAD")}
    memory, register = binary["memory"], binary["register"]
    vm = _Recording(unit.observation, constant_space=binary["constant"], seed=0, subjects=subjects,
                    program=binary["program"], havoc_calls=(register, 32, 8),
                    externals={(memory, 0x100B90): "malloc", (memory, 0x100BA0): "free"},
                    external_abi="sysv64", address_bits=binary["address_bits"])
    for offset, value in ((32, 0x70000000), (40, 0x74000000), (56, 0x12345678), (48, release)):
        vm.preset(register, offset, 8, value)
    run = vm.run()
    assert run.completed and not vm.opaque_opcodes and vm._peek(register, 0, 8)[0] == expected
    assert not vm._blocks and vm._free == [0x60000000]
    if key == ALIAS:
        assert vm.seen[INITIAL] == [0x60000000]
        assert vm.seen.get(READ, []) == ([] if release else [0x60000000])
        assert run.executed.count("1b1:100922:2:CALL") == release
        assert run.executed.count("1b1:1008e1:2:CALL") == 1 - release
    elif key == KEEP:
        assert vm.seen["1b1:100aec:1:STORE"] == vm.seen["1b1:100afa:0:LOAD"] == [0x60000000]
        assert run.executed.count("1b1:100b46:2:CALL") == 1
    else:
        writer, reader = (LOOP_STORE, LOOP_READ) if key == LOOP else (OUTER_STORE, OUTER_READ)
        assert vm.seen[writer] == vm.seen[reader] == [0x60000000, 0x60000000]
        assert run.executed.count(writer) == run.executed.count(reader) == 2
        assert {dependency.offset for dependency in run.dependencies
                if dependency.reader == reader and dependency.space_id == memory
                and dependency.writer == writer} == set(range(0x60000000, 0x60000008))
        for operation in unit.observation.instructions:
            for ordinal, op in enumerate(operation.operations):
                operation_key = f"{operation.address.space_id:x}:{operation.address.byte_offset:x}:{ordinal}:{op.opcode}"
                if operation_key in (writer, reader):
                    assert (op.inputs[2].byte_size if op.opcode == "STORE" else op.output.byte_size) == 8


class _PositiveSizeResizeFailure(_Recording):
    """Select only realloc(p,16)'s documented NULL/old-retain outcome.

    This is a test-only external-contract adapter, not another interpreter or
    native allocator. All original program operations still run unchanged.
    """

    def _run_external_body(self, name, key):
        if name != "realloc":
            return super()._run_external_body(name, key)
        register, memory = self._havoc[0], self._order[0][0]
        (first, second, third), preserved = self._EXTERNAL_ABIS[self._external_abi]
        old, _ = self._peek(register, first, 8)
        size, _ = self._peek(register, second, 8)
        self._peek(register, third, 8)  # Same argument sampling as the base external body.
        assert old in self._blocks and self._blocks[old] == 8 and size == 16
        blocks, freed = dict(self._blocks), list(self._free)
        ram = {place: value for place, value in self._bytes.items() if place[0] == memory}
        # The existing Interpreter external footer, unchanged: havoc precisely
        # the same ABI-volatile bytes, set the result, restore the call's SP.
        for space, offset, width in self._registers:
            if space != register:
                continue
            for byte in range(offset, offset + width):
                base = byte - byte % 8 if byte < 0x100 else byte
                if base in preserved or 0x20 <= byte < 0x28:
                    continue
                self._put(key, register, byte, 1, self._rng.randrange(256), {("call", key)})
        self._put(key, register, 0, 8, 0, set())
        sp_space, sp_offset, _ = self._havoc
        for index, value in enumerate(self._stack_snapshot):
            self._bytes[(sp_space, sp_offset + index)] = value
            self._restore_provenance(sp_space, sp_offset + index, index)
        assert self._blocks == blocks and self._free == freed
        assert {place: value for place, value in self._bytes.items() if place[0] == memory} == ram
        self.failed_outcome = (old, size)


def test_original_resize_failure_and_success_execute_their_own_raw_paths(binary):
    # Finite runs relative to the external contract, not a native failure
    # injection and not a claim that realloc always fails or always moves.
    unit, memory, register = binary["units"][RESIZE], binary["memory"], binary["register"]
    writer, reader, release_pointer = "1b1:100a6b:1:STORE", "1b1:100a6e:0:LOAD", "1b1:100a71:0:COPY"
    call, release = "1b1:100a54:2:CALL", "1b1:100a74:2:CALL"
    for interpreter, fails in ((_Recording, False), (_PositiveSizeResizeFailure, True)):
        vm = interpreter(unit.observation, constant_space=binary["constant"], seed=0,
                         subjects={writer: 1, reader: 1, release_pointer: 0},
                         program=binary["program"], havoc_calls=(register, 32, 8),
                         externals={(memory, 0x100B90): "malloc", (memory, 0x100BA0): "free",
                                    (memory, 0x100BB0): "realloc"},
                         external_abi="sysv64", address_bits=binary["address_bits"])
        for offset, value in ((32, 0x70000000), (40, 0x74000000), (56, 0x12345678)):
            vm.preset(register, offset, 8, value)
        run = vm.run()
        assert run.completed and not vm.opaque_opcodes and not vm._blocks
        assert run.executed.count(call) == run.executed.count(release) == 1
        assert vm._peek(register, 0, 8)[0] == (0x12345678 if fails else 0)
        expected_address = 0x60000000 if fails else 0x60001000
        assert vm.seen[release_pointer] == vm._free == [expected_address]
        assert vm.seen.get(writer, []) == vm.seen.get(reader, []) == ([expected_address] if fails else [])
        if fails:
            assert vm.failed_outcome == (expected_address, 16)
            assert {dependency.offset for dependency in run.dependencies
                    if dependency.reader == reader and dependency.space_id == memory
                    and dependency.writer == writer} == set(range(expected_address, expected_address + 8))
