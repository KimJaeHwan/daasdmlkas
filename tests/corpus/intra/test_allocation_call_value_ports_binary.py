"""Compiled x64 ELF caller pointers cross original reg/off/memory ports.

Set TDO_ALLOCATION_CALL_VALUES_BUNDLE to its sealed generation. Reproduce:
  <NDK>/bin/x86_64-linux-android35-clang -O1 -g -shared -fPIC \
    -fno-stack-protector -fno-inline -fno-unroll-loops -fno-vectorize \
    -fno-slp-vectorize tests/corpus/sources/allocation_call_value_ports.c -o <ELF>
  .venv/bin/python tools/bundle_export/export_bundle.py <ELF> --output-root <dir> \
    --function-name case_allocation_echo_register --function-name case_allocation_echo_offset \
    --function-name case_allocation_echo_memory --function-name case_allocation_echo_barrier

This is a compiled testbed, not an external-library success or native libc
certification. The existing glibc documentation-relative profile is explicit
test input; it does not identify this Android ELF's runtime as glibc. Finite
original-p-code runs use the existing allocator oracle, not a native process.
"""

from hashlib import sha256
import json
import os
from pathlib import Path

import pytest

from forward_oracle import _Recording
from tdo_v2._allocation_lifetime import AllocationAnalysis
from tdo_v2._call_value_ports import scalar_call_rows
from tdo_v2.configured_naming_contracts import NamingBindingExpectation
from tdo_v2.image_info import load_image_info
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.interprocedural import analyze_units, function_key
from tdo_v2.lifecycle_contracts import load_lifecycle_contracts
from tdo_v2.memory_contracts import MemoryDefinitionKind
from tdo_v2.summary_store import load_external_models


REPO = Path(__file__).resolve().parents[3]
SOURCE_SHA = "3dcb4515180b05d271c3b49eb6a78abe269bb8c549ca4e2b2818e36cc3eee136"
IMAGE_SHA = "00cd5ff403587185504ec9e09b5d297becaee657abdb10bc66ef69bdf60d16b1"
NAMING_SHA = "69a175c7154ea56bc02f96ba00249e9701048e771dc4170745eb7411d9d54e5b"
DIGESTS = {
    "1b1:104810": "cd9bc9dbaef23e260f561a84de3401ba6b38cdebd32833e2f0642b2c9b6d20d8",
    "1b1:104860": "1c8a57212b44c1ec190dcf962f480a906eb20ff3a82b0a47315aa3c1ea15d247",
    "1b1:1048b0": "56a3d7c8f73302af8310514156c22c034dbca955311b28679019c3342f6ca3c1",
    "1b1:104910": "afa90b21ab1624c1a7047d8a9c27d1834ff54d751c2f6663fca1a22681082568",
    "1b1:104850": "7fbab673f4b9391576d5a4257813d3d170d6a4d215d9310cfef055926c89dab5",
    "1b1:1048a0": "8c3b6b465c9161bacd22b4cc577f8de4ee50120c2e3266dda126dd4a2843ea0f",
    "1b1:104900": "bd6563532e787232c80edaa569b0763beef84385aac354f61b5348bf266f106d",
}
# Original entry, birth CALL, helper CALL, payload STORE/LOAD, release CALL,
# selected pre-call source class, and expected allocation-relative offset.
CASES = {
    "register": (0x104810, 0x10481e, 0x10482e, 0x104833, 0x104835, 0x10483a, "reg", 0),
    "offset": (0x104860, 0x10486e, 0x10487e, 0x104883, 0x104885, 0x10488a, "off", 4),
    "memory": (0x1048b0, 0x1048c2, 0x1048d7, 0x1048dc, 0x1048de, 0x1048e3, "mem", 0),
    "barrier": (0x104910, 0x104921, 0x104931, 0x10493e, 0x104941, 0x104947, "reg", 0),
}


def _key(address, ordinal, opcode):
    return f"1b1:{address:x}:{ordinal}:{opcode}"


def _operations(unit):
    return {_key(instruction.address.byte_offset, ordinal, operation.opcode): operation
            for instruction in unit.observation.instructions for ordinal, operation in enumerate(instruction.operations)}


@pytest.fixture(scope="module")
def binary():
    location = os.environ.get("TDO_ALLOCATION_CALL_VALUES_BUNDLE")
    if not location:
        pytest.skip("set TDO_ALLOCATION_CALL_VALUES_BUNDLE to the sealed seven-function ELF fixture")
    generation = Path(location)
    assert sha256((REPO / "tests/corpus/sources/allocation_call_value_ports.c").read_bytes()).hexdigest() == SOURCE_SHA
    assert sha256((generation / "original.bin").read_bytes()).hexdigest() == IMAGE_SHA
    names = json.loads((generation / "call-names-000000.json").read_bytes())
    assert names["exporter_source_sha256"] == NAMING_SHA and names["ghidra_version"] == "12.0.4"
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=
            NamingBindingExpectation(bytes.fromhex(NAMING_SHA), "12.0.4")) as session:
        scope = session.program_result
        units = {function_key(row.unit.scopes.function.entry): row.unit for row in session.iter_functions()}
    assert set(units) == set(DIGESTS) and scope.evidence.executable_sha256.hex() == IMAGE_SHA
    for key, digest in DIGESTS.items():
        assert units[key].scopes.function.observation_digest.hex() == digest
    assert scope.evidence.translation_namespace.language_id == "x86:LE:64:default"
    spaces = scope.evidence.address_spaces
    return dict(units=units, info=load_image_info(generation), cache={},
                models=load_external_models(sorted((REPO / "models/external").glob("*.json")),
                                            "x86:LE:64:default", "sysv64"),
                contracts=load_lifecycle_contracts(REPO / "models/lifecycle/glibc_sysv64.json"),
                memory=scope.evidence.image_base.space_id,
                register=next(space.space_id for space in spaces if space.is_register_space),
                constant=next(space.space_id for space in spaces if space.is_constant_space),
                program={(unit.scopes.function.entry.space_id, unit.scopes.function.entry.byte_offset): unit.observation
                         for unit in units.values()},
                address_bits={space.space_id: space.address_size_bits for space in spaces if space.is_memory_space})


@pytest.fixture(params=("sparse", "dense"))
def results(binary, monkeypatch, request):
    monkeypatch.setenv("TDO_V2_FORWARD", "1")
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", request.param)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", request.param)
    if request.param not in binary["cache"]:
        binary["cache"][request.param] = analyze_units(list(binary["units"].values()),
            image_info=binary["info"], external_models=binary["models"], lifecycle_contracts=binary["contracts"],
            assume_entry_values_not_frame=False, assume_opaque_callees_leave_no_stack_addresses=False,
            assume_globals_disjoint_from_stack=False, private_frame_above=0)
    return binary["cache"][request.param]


@pytest.mark.parametrize("case", CASES)
def test_original_caller_allocation_crosses_only_verified_value_ports(binary, results, case):
    entry, birth, call, write, _, _, kind, offset = CASES[case]
    item = results[f"1b1:{entry:x}"]
    analysis = AllocationAnalysis(item, results=results)
    writer, origin = _key(write, 1, "STORE"), _key(call, 2, "CALL")
    port = scalar_call_rows(item.normalized)[origin + "~0"]
    assert port.width == 8 and port.row[0] == kind
    pointer = analysis.input(writer, analysis.ops[writer].inputs[1])
    if case == "barrier":
        assert pointer.unknown and analysis.access(writer) is None
        assert any(row.operation_key == writer for row in item.normalized.call_clobber_reads)
        return
    assert not pointer.unknown and len(pointer.targets) == 1
    target, = pointer.targets
    assert target.allocation.function == item.key and target.allocation.event == _key(birth, 2, "CALL")
    assert target.offset == offset and analysis.extent(target.allocation)[0] == 8
    assert analysis.lifetime(pointer, writer).live and analysis.access(writer) is not None
    output = next(row for row in analysis.ssa.definitions if row.operation_key == origin + "~0")
    assert output.kind is MemoryDefinitionKind.DATA_WRITE and output.span.size == 8
    assert any(identity[1] == output.operation_key for identity in pointer.definitions)
    assert any(label.startswith("lifecycle-contract:glibc-sysv64-malloc@") for label in pointer.requires)
    # Isolate the formerly missing consumer without changing a byte of the
    # accepted function, graph, SSA, or already-issued physical source port.
    disabled = AllocationAnalysis(item, results=results)
    disabled._call_values = {}
    before = disabled.input(writer, disabled.ops[writer].inputs[1])
    assert before.unknown and disabled.access(writer) is None


@pytest.mark.parametrize("case", ("register", "offset", "memory"))
@pytest.mark.parametrize("value", (0, 0x12345678, 0xffffffff))
def test_original_pcode_payload_and_byte_writer_after_real_helper_call(binary, case, value):
    entry, birth, call, write, read, release, _, offset = CASES[case]
    unit = binary["units"][f"1b1:{entry:x}"]
    operations = _operations(unit)
    writer, reader, crossing = _key(write, 1, "STORE"), _key(read, 0, "LOAD"), _key(call, 2, "CALL")
    memory, register = binary["memory"], binary["register"]
    externals = {(memory, operations[_key(birth, 2, "CALL")].inputs[0].coordinate.byte_offset): "malloc",
                 (memory, operations[_key(release, 2, "CALL")].inputs[0].coordinate.byte_offset): "free"}
    vm = _Recording(unit.observation, constant_space=binary["constant"], seed=value,
        subjects={writer: 1, reader: 1}, program=binary["program"], externals=externals,
        havoc_calls=(register, 32, 8), external_abi="sysv64", address_bits=binary["address_bits"])
    for start, number in ((32, 0x70000000), (40, 0x74000000), (56, value)):
        vm.preset(register, start, 8, number)
    run = vm.run()
    assert run.completed and not vm.opaque_opcodes and run.executed.count(crossing) == 1
    assert vm._peek(register, 0, 4)[0] == value
    assert vm.seen[writer] == vm.seen[reader] == [0x60000000 + offset]
    assert {(row.offset, row.writer) for row in run.dependencies if row.reader == reader and row.space_id == memory} == \
        {(0x60000000 + offset + byte, writer) for byte in range(4)}
    assert not vm._blocks and vm._free == [0x60000000]
