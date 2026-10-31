"""The same fixed-64-bit C program compiled for ARM64, x86 and x64.

Set TDO_LOOP_READ_FROM_DATA to output/loop-memory-read-from-testbed, containing
the three sealed <arch>/bundles/<generation> directories below. The original
ARM fixture remains independently pinned in test_loop_memory_read_from_binary.

Build tests/corpus/sources/loop_memory_read_from.c with Apple clang 21 arm64
(-O1 -dynamiclib -fno-stack-protector -fno-inline -fno-vectorize
 -fno-slp-vectorize -fno-unroll-loops -ffreestanding), or MinGW GCC 15.2
i686/x86_64 (-O1 -shared -fno-stack-protector -fno-inline -fno-unroll-loops
 -fno-tree-vectorize -fno-tree-slp-vectorize -ffreestanding
 -Wl,--no-insert-timestamp). Use the ordinary export_bundle.py on the four
loop_rf_* symbols (leading underscore on Mach-O), not edited observations.

PE checks execute the original extracted p-code, not native Windows code.
ABI placements below are test inputs only; the engine receives no ABI rules.
"""

from hashlib import sha256
import os
from pathlib import Path

import pytest

from graph_oracle import check
from pcode_interpreter import Entry, Interpreter
from test_loop_memory_read_from_binary import _graph_sources, _initial, _spaces
from tdo_v2.configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation
from tdo_v2.integration.configured_bundle import admit_frozen_bundle
from tdo_v2.integration.observed_function_session import open_observed_function_session
from tdo_v2.normalize import FunctionNormalizer, NormalizedFunction


REPO = Path(__file__).resolve().parents[3]
SOURCE_SHA = "17b6926028319a100405c9b97df1703f060c976ef0411a25cf4ec04f09876f24"
BASE, STACK, PATCH = 0x50000000, 0x70000000, 0xa6
COUNTS = (0, 1, 2, 5)
VALUES = (0x0123456789abcdef, 0x11223344ffffffff)  # unequal halves and low-DWORD carry


def _case(space, base, entry, reads, writes):
    def key(point, opcode):
        offset, ordinal = point
        return f"{space:x}:{base + offset:x}:{ordinal}:{opcode}"
    return dict(entry=base + entry,
        reads=tuple((key(point, "LOAD"), lane, size, guard[0] if guard else "all")
                    for point, lane, size, *guard in reads),
        writes=tuple((key(point, "STORE"), lane, size) for point, lane, size in writes))


PROFILES = {
    "arm64": dict(
        generation="64606cd6223a01c87bf123a13f73b91709492fdfbbe5e85475d0ed812b1ea33b",
        image="64e4f7f89b1a2016bb1501d6089555762e2e2e2545e01a9fbcef3a3b2b5b280a",
        language="AARCH64:LE:64:AppleSilicon", pointer=8,
        cases={
            "write_read": _case(0x1b1, 0, 0x2b8, [((0x2d0, 2), 0, 8)], [((0x2cc, 1), 0, 8)]),
            "partial": _case(0x1b1, 0, 0x2f0, [((0x300, 2), 0, 8)],
                             [((0x2f8, 1), 0, 8), ((0x2fc, 2), 3, 1)]),
            "conditional": _case(0x1b1, 0, 0x318, [((0x328, 2), 0, 8)], [((0x33c, 1), 0, 8)]),
            "read_first": _case(0x1b1, 0, 0x344, [((0x358, 1), 0, 8)], [((0x360, 3), 0, 8)]),
        }),
    "x64": dict(
        generation="3e3fa77b82ab4e90039ee633954e5bfada73a12da4a24317e305a7462e6d0e41",
        image="29b6e687727c207dfa5fb5f9deb84f3241661c0ef3cf0c13fd918ad326c8d521",
        language="x86:LE:64:default", pointer=8,
        cases={
            "write_read": _case(0x1b1, 0x2da0a0000, 0x1300,
                                [((0x1323, 0), 0, 8)], [((0x1320, 1), 0, 8)]),
            "partial": _case(0x1b1, 0x2da0a0000, 0x133a, [((0x1367, 0), 0, 8)],
                             [((0x1360, 1), 0, 8), ((0x1363, 2), 3, 1)]),
            "conditional": _case(0x1b1, 0x2da0a0000, 0x137d,
                                 [((0x13a0, 0), 0, 8, "skipped"), ((0x13b6, 0), 0, 8, "written")],
                                 [((0x13b3, 1), 0, 8)]),
            "read_first": _case(0x1b1, 0x2da0a0000, 0x13c8,
                                [((0x13e0, 0), 0, 8)], [((0x13e6, 1), 0, 8)]),
        }),
    "x86": dict(
        generation="d83881c00fa0ef36ae114822aebba6a135b438774bd1f58940cb03ae5b7d5831",
        image="c889ece6b8b05bdbb41aee9903adea287b8206a6c75ffe5e69ccf8ab8025f12a",
        language="x86:LE:32:default", pointer=4,
        cases={
            "write_read": _case(0x1a1, 0x65980000, 0x1380,
                                [((0x13c6, 0), 0, 4), ((0x13c9, 1), 4, 4)],
                                [((0x13c0, 1), 0, 4), ((0x13c3, 2), 4, 4)]),
            "partial": _case(0x1a1, 0x65980000, 0x13fa,
                             [((0x1456, 0), 0, 4), ((0x1459, 1), 4, 4)],
                             [((0x1448, 1), 0, 4), ((0x144b, 2), 4, 4), ((0x1453, 2), 3, 1)]),
            "conditional": _case(0x1a1, 0x65980000, 0x148a,
                                 [((0x1500, 0), 0, 4, "skipped"), ((0x1502, 1), 4, 4, "skipped"),
                                  ((0x153b, 0), 0, 4, "written"), ((0x153d, 1), 4, 4, "written")],
                                 [((0x1536, 1), 0, 4), ((0x1538, 2), 4, 4)]),
            "read_first": _case(0x1a1, 0x65980000, 0x1559,
                                [((0x15c0, 0), 0, 4), ((0x15c3, 1), 4, 4)],
                                [((0x15ca, 1), 0, 4), ((0x15cd, 2), 4, 4)]),
        }),
}


@pytest.fixture(scope="module", params=PROFILES)
def compiled_target(request):
    root = os.environ.get("TDO_LOOP_READ_FROM_DATA")
    if not root:
        pytest.skip("set TDO_LOOP_READ_FROM_DATA for sealed cross-architecture C testbed")
    arch, profile = request.param, PROFILES[request.param]
    assert sha256((REPO / "tests/corpus/sources/loop_memory_read_from.c").read_bytes()).hexdigest() == SOURCE_SHA
    source = (REPO / "ghidra/GhidraV2CallNaming.java").read_bytes().replace(b"\r\n", b"\n")
    binding = NamingBindingExpectation(sha256(source).digest(), CALL_NAMING_GHIDRA_VERSION)
    directory = Path(root) / arch / "bundles" / profile["generation"]
    with open_observed_function_session(admit_frozen_bundle(directory), naming_binding=binding) as session:
        units = {item.unit.scopes.function.entry.byte_offset: item.unit for item in session.iter_functions()}
    assert set(units) == {case["entry"] for case in profile["cases"].values()}
    for unit in units.values():
        evidence = unit.scopes.program.evidence
        assert evidence.executable_sha256.hex() == profile["image"]
        assert evidence.translation_namespace.language_id == profile["language"]
    return arch, profile, units


def _inputs(arch, count, value):
    if arch == "arm64":
        return {8: STACK, 0x4000: BASE, 0x4008: count, 0x4010: value, 0x4018: PATCH}, ()
    if arch == "x64":
        return {0x20: STACK, 8: BASE, 0x10: count, 0x80: value, 0x88: PATCH}, ((STACK, 0x12345678, 8),)
    return {0x10: STACK}, ((STACK, 0x12345678, 4), (STACK + 4, BASE, 4),
                           (STACK + 8, count, 8), (STACK + 16, value, 8), (STACK + 24, PATCH, 1))


def _image(memory, stack):
    def byte(space, address):
        if space != memory:
            return None
        if BASE <= address < BASE + 64:
            word, lane = divmod(address - BASE, 8)
            return _initial(word) >> (8 * lane) & 255
        for start, value, size in stack:
            if start <= address < start + size:
                return value >> (8 * (address - start)) & 255
        return None
    return byte


def _expected(arch, name, case, count, value, memory):
    latest, reads, writes, result = [None] * 8, {}, {}, 0
    for key, lo, width in case["writes"]:
        latest[lo:lo + width] = [key] * width
    assert all(latest)
    for visit in range(count):
        remaining, address = count - visit, BASE + 8 * visit
        stored = ((value & ~(255 << 24)) | (PATCH << 24)) if name == "partial" else \
                 value if name == "conditional" else (value + remaining) % (1 << 64)
        performed = name != "conditional" or remaining & 1
        before_store = name == "read_first" or not performed
        result ^= _initial(visit) if before_store else stored
        for key, lane, width, guard in case["reads"]:
            if guard == "written" and not performed or guard == "skipped" and performed:
                continue
            for byte in range(lane, lane + width):
                reads[key, address + byte] = Entry(memory, address + byte) if before_store else latest[byte]
        if performed:
            for byte in range(8):
                writes[memory, address + byte] = (stored >> (8 * byte) & 255, latest[byte])
    return reads, writes, result


def _concrete(normalized, unit, arch, profile, name, case):
    constant, register, unique, memory = _spaces(unit)
    for count in COUNTS:
        for value in VALUES:
            registers, stack = _inputs(arch, count, value)
            image = _image(memory, stack)
            vm = Interpreter(unit.observation, constant_space=constant, seed=count, image=image)
            for offset, number in registers.items():
                vm.preset(register, offset, profile["pointer"], number)
            run = vm.run()
            assert run.completed and not vm.opaque_opcodes
            for key, _, _, guard in case["reads"]:
                expected_count = sum(guard == "all" or (guard == "written") == bool(remaining & 1)
                                     for remaining in range(1, count + 1))
                assert run.executed.count(key) == expected_count
            reads, writes, result = _expected(arch, name, case, count, value, memory)
            actual = {(row.reader, row.offset): row.writer for row in run.dependencies
                      if row.space_id == memory and BASE <= row.offset < BASE + 64}
            assert actual == reads
            final = vm.final_bytes()
            assert {(space, offset): (number, writer) for (space, offset), (number, writer, _) in final.items()
                    if space == memory and BASE <= offset < BASE + 64} == writes
            low = 0x4000 if arch == "arm64" else 0
            returned = sum(final[register, low + byte][0] << (8 * byte) for byte in range(profile["pointer"]))
            if arch == "x86":
                returned |= sum(final[register, 8 + byte][0] << (32 + 8 * byte) for byte in range(4))
            assert returned == result
            report = check(normalized, unit.observation, seeds=(count,), register_pools=lambda _: registers,
                           spaces=(constant, register, unique), image=image)
            assert report.runs == 1 and report.checked and not report.unsupported
            assert not report.opaque_opcodes and not report.silent


@pytest.mark.parametrize("engine", ("sparse", "dense"))
@pytest.mark.parametrize("name", ("write_read", "partial", "conditional", "read_first"))
def test_fixed_word_real_cross_arch_byte_relations(compiled_target, monkeypatch, engine, name):
    arch, profile, units = compiled_target
    case = profile["cases"][name]
    unit = units[case["entry"]]
    monkeypatch.setenv("TDO_V2_MEMORY_SSA_ENGINE", engine)
    monkeypatch.setenv("TDO_V2_DATAFLOW_ENGINE", engine)
    normalized = FunctionNormalizer().normalize(unit)
    assert isinstance(normalized, NormalizedFunction)
    raw = {f"{ins.address.space_id:x}:{ins.address.byte_offset:x}:{i}:{op.opcode}": op
           for ins in unit.observation.instructions for i, op in enumerate(ins.operations)}
    for key, _, width, _ in case["reads"]:
        assert raw[key].output.byte_size == width
    for key, _, width in case["writes"]:
        assert raw[key].inputs[2].byte_size == width
    loop = normalized.memory_graph.loop_memory
    _graph_sources(normalized, unit)
    family, = loop.plan.families
    assert family.address_bits == 8 * profile["pointer"]
    split_updates = name == "conditional" and arch != "arm64"
    assert len(family.latches) == len(family.transition_definition_ids) == (2 if split_updates else 1)
    assert {edge.predecessor_key for edge in family.backedge_edges} == set(family.latches)
    latest = [None] * 8
    writer_lanes = {key: lo for key, lo, _ in case["writes"]}
    for key, lo, width in case["writes"]:
        latest[lo:lo + width] = [key] * width
    actual = {}
    for row in loop.plan.read_from:
        reader, writer = (loop.plan.accesses[index].operation_key
                          for index in (row.reader_access, row.writer_access))
        for byte in range(row.read_offset, row.read_offset + row.width):
            assert (reader, byte) not in actual
            actual[reader, byte] = writer, row.write_offset + byte - row.read_offset
    # GCC has a separate LOAD on each branch: only the written-path LOAD
    # gets a fact. Clang's shared LOAD remains unknown after the must-meet.
    expected = {(key, byte): (latest[lane + byte], lane + byte - writer_lanes[latest[lane + byte]])
                for key, lane, width, guard in case["reads"] for byte in range(width)
                if name in ("write_read", "partial") or name == "conditional" and guard == "written"}
    assert actual == expected
    _concrete(normalized, unit, arch, profile, name, case)
