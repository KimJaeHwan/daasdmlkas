"""The standalone producer must use the same byte SSA as existing Bundles."""

from copy import deepcopy
import json
from pathlib import Path
import struct
import sys

import pytest

from tdo_v2.graph_contracts import NodeKind
from tdo_v2.integration.standalone_arm64 import build_standalone_arm64_graphs

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "bundle_export"))
from arm64_local import _write_bundle, export, json_bytes

import _elf_fixture as ef
from arm64_local_facts import compare_memory, describe
import lifting

ENTRY = 0x401000


def arm64_export(tmp_path, code):
    code = bytes.fromhex(code)
    image = bytearray(ef.make_elf([ef.Segment(ENTRY, code)],
                                 e_type=2, link_base=0x400000, machine=183, dynamic=False).data)
    image.extend(bytes(-len(image) % 8))
    struct.pack_into("<Q", image, 40, len(image))
    struct.pack_into("<HHH", image, 58, 64, 1, 0)
    image.extend(bytes(64))
    path = tmp_path / "test.elf"
    path.write_bytes(image)
    return export(path, tmp_path / "bundles", entry=ENTRY, size=len(code))


def local_graph(generation):
    snapshot, _ = build_standalone_arm64_graphs(generation)
    graph, = snapshot.graphs.values()
    return snapshot.program.evidence, graph


@pytest.mark.parametrize(("first_two_words", "definitions", "debt"), [
    ("02040091 e20700f9", [(8, 0x401004)], 0),  # ADD, STR x2
    ("e00700f9 e20b00b9", [(4, 0x401004), (4, 0x401000)], 0),  # STR x0, then the low 4 bytes
    ("e00700f9 220000f9", [(8, 0x401000)], 1),  # STR x0, then STR x2 through unknown x1
])
def test_standalone_store_reload_query(tmp_path, first_two_words, definitions, debt):
    pytest.importorskip("pypcode")
    generation = arm64_export(tmp_path, f"{first_two_words} e30740f9 640400d1 c0035fd6")
    _program, graph = local_graph(generation)
    deps = graph.normalized.dependencies
    seed = deps.node_for_key("op:1:40100c:0:INT_SUB")
    result = graph.query(seed)
    ops = {deps.node(n).key for n in result.reachable_nodes if deps.node(n).kind is NodeKind.OPERATION}
    assert "op:1:401008:1:LOAD" in ops
    assert {f"op:1:{addr:x}:1:STORE" for _, addr in definitions} <= ops
    assert len(result.reachable_unresolved_read_nodes) == debt

    ssa = graph.normalized.memory_ssa
    read, = (r for r in ssa.reads if r.span.object_id.kind.value == "function_relative")
    assert [(fragment.span.end - fragment.span.start,
             int(ssa.definitions[fragment.definition_ids[0]].operation_key.split(":")[1], 16))
            for fragment in read.fragments] == definitions


def test_standalone_memory_facts_bind_graph_and_notice_wrong_width(tmp_path):
    pytest.importorskip("pypcode")
    generation = arm64_export(tmp_path, "ff0700f9 e30b40b9 c0035fd6")  # STR XZR, LDR W3, RET
    program, graph = local_graph(generation)
    report = describe(generation)
    store, load = report["memory"]
    assert [store["state"], load["state"]] == ["match", "match"]
    assert [store["graph_operation"], load["graph_operation"]] == [
        "op:1:401000:2:STORE", "op:1:401004:1:LOAD",
    ]
    assert store["fields"]["base"]["pcode"] == "sp"
    assert store["fields"]["displacement"]["pcode"] == 8
    assert store["fields"]["register"] == dict(encoded="xzr", pcode="constant_zero",
                                               state="match", basis="value_only")
    assert load["fields"]["register"]["pcode"] == "w3"
    assert load["fields"]["size"]["pcode"] == 4
    assert report["facts"]["schema"] == "tbr-arm64-local-facts-1"
    assert report["facts"]["rows"][0]["aarch64"]["observation"] == "pypcode_sleigh"

    row = deepcopy(lifting.row_facts(graph.unit.observation.instructions[1]))
    row["ops"][1]["output"]["size"] = 8
    registers = {(r.space_id, r.byte_offset, r.byte_size): r.name for r in program.register_evidence.registers}
    result = compare_memory(0xB9400BE3, row, registers)
    assert result["state"] == "mismatch"
    assert result["fields"]["size"] == dict(encoded=4, pcode=8, state="mismatch")


def test_standalone_refuses_call_and_resealed_wrong_namespace(tmp_path):
    pytest.importorskip("pypcode")
    with pytest.raises(ValueError, match="unsupported ARM64 instruction"):
        arm64_export(tmp_path, "00000094 c0035fd6")  # BL, RET
    assert not (tmp_path / "bundles").exists()

    generation = arm64_export(tmp_path, "c0035fd6")
    program = json.loads((generation / "program.json").read_bytes())
    program["translation_namespace"]["language_id"] = "AARCH64:LE:64:v8A"
    blocks = [(0x400000, (generation / "memory-000000.bin").read_bytes()),
              (ENTRY, (generation / "memory-000001.bin").read_bytes())]
    other = _write_bundle(tmp_path / "second", (generation / "original.bin").read_bytes(),
                          (generation / "call-interface-profile.json").read_bytes(), json_bytes(program),
                          blocks, (generation / "function-000000.json").read_bytes())
    with pytest.raises(ValueError, match="profile and sealed program disagree"):
        build_standalone_arm64_graphs(other)


def test_standalone_accepts_add_to_sp_alias_and_reports_space_widths(tmp_path):
    pytest.importorskip("pypcode")
    generation = arm64_export(tmp_path, "e0030091 c0035fd6")  # ADD X0, SP, #0 (MOV alias)
    program, graph = local_graph(generation)
    assert [space.address_size_bits for space in program.address_spaces] == [64, 64, 32, 32]
    assert len(graph.unit.observation.instructions) == 2


@pytest.mark.parametrize("change", ["encoded_call", "return_input", "replaced_load", "unaligned_entry"])
def test_standalone_refuses_resealed_bytes_or_local_operation_kind(tmp_path, change):
    pytest.importorskip("pypcode")
    generation = arm64_export(tmp_path, "e30740f9 c0035fd6")
    observation = json.loads((generation / "function-000000.json").read_bytes())
    blocks = [(0x400000, (generation / "memory-000000.bin").read_bytes()),
              (ENTRY, (generation / "memory-000001.bin").read_bytes())]
    message = "requires straight-line code and one terminal RET"
    if change == "encoded_call":
        blocks[1] = (ENTRY, bytes.fromhex("00000094 c0035fd6"))
    elif change == "return_input":
        observation["instructions"][-1]["operations"][0]["inputs"][0]["byte_offset"] -= 8
    elif change == "unaligned_entry":
        observation["entry"]["byte_offset"] += 1
        for row in observation["instructions"]:
            row["address"]["byte_offset"] += 1
            if row["fallthrough"] is not None:
                row["fallthrough"]["byte_offset"] += 1
        blocks[1] = (ENTRY + 1, blocks[1][1])
        message = "must contain only its function and image-base anchor"
    else:
        load = observation["instructions"][0]["operations"][1]
        load["opcode"], load["inputs"] = "COPY", load["inputs"][1:]
    other = _write_bundle(tmp_path / "second", (generation / "original.bin").read_bytes(),
                          (generation / "call-interface-profile.json").read_bytes(),
                          (generation / "program.json").read_bytes(), blocks, json_bytes(observation))
    with pytest.raises(ValueError, match=message):
        build_standalone_arm64_graphs(other)
