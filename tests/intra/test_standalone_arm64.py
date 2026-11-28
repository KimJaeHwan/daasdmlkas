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


def arm64_export(tmp_path, code, *, branches=False, pairs=False):
    code = bytes.fromhex(code)
    image = bytearray(ef.make_elf([ef.Segment(ENTRY, code)],
                                 e_type=2, link_base=0x400000, machine=183, dynamic=False).data)
    image.extend(bytes(-len(image) % 8))
    struct.pack_into("<Q", image, 40, len(image))
    struct.pack_into("<HHH", image, 58, 64, 1, 0)
    image.extend(bytes(64))
    path = tmp_path / "test.elf"
    path.write_bytes(image)
    return export(path, tmp_path / "bundles", entry=ENTRY, size=len(code), branches=branches, pairs=pairs)


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


BRANCH_BODY = "e10700f9 02000014 e20700f9 e80740f9 00050091 ff430091 c0035fd6"


@pytest.mark.parametrize("prefix,condition,branch_index", [
    ("ff4300d1 60000034", "w0", 1),
    ("ff4300d1 600000b4", "x0", 1),
    *(("ff4300d1 1f1c0071 " + (0x54000060 + code).to_bytes(4, "little").hex(), form, 2)
      for code, form in enumerate("eq ne cs cc mi pl vs vc hi ls ge lt gt le".split())),
    ("ff4300d1 1f0440f1 61000054", "ne", 2),  # CMP X0,#1,LSL #12
])
def test_standalone_keeps_both_arms_at_the_stack_join(tmp_path, prefix, condition, branch_index):
    pytest.importorskip("pypcode")
    generation = arm64_export(tmp_path, f"{prefix} {BRANCH_BODY}", branches=True)
    _program, graph = local_graph(generation)
    deps = graph.normalized.dependencies
    branch_pc = ENTRY + branch_index * 4
    store_pcs = (branch_pc + 4, branch_pc + 12)
    load_pc = branch_pc + 16

    load = deps.node_for_key(f"op:1:{load_pc:x}:1:LOAD")
    data = graph.query(load)
    store_keys = {f"op:1:{pc:x}:1:STORE" for pc in store_pcs}
    assert store_keys <= {deps.node(node).key for node in data.reachable_nodes}
    assert data.reachable_unresolved_read_nodes == ()
    ssa = graph.normalized.memory_ssa
    read, = (r for r in ssa.reads if r.span.object_id.kind.value == "function_relative")
    fragment, = read.fragments
    assert fragment.span.end - fragment.span.start == 8
    definition, = fragment.definition_ids
    join, = (item for item in ssa.joins if item.join_definition_id == definition)
    assert {"op:" + ssa.definitions[i].operation_key for i in join.source_definition_ids} == store_keys

    report = describe(generation)
    branch, jump = report["branches"]
    assert [edge["outcome"] for edge in branch["successors"]] == ["taken", "not_taken"]
    assert [int(edge["address"]["offset"], 16) for edge in branch["successors"]] == list(reversed(store_pcs))
    assert jump["successors"] == [{"outcome": "always", "address": {"space": 1, "offset": f"{load_pc:x}"}}]
    assert branch["graph_operation"] in {deps.node(node).key
                                         for node in graph.query(load, include_control=True).reachable_nodes}
    predicate = branch["condition"]["test"]
    if branch_index == 1:
        assert predicate["zero"]["pre_register"]["name"] == condition
    else:
        assert predicate["flags"] == condition
        decision = graph.query(deps.node_for_key(branch["graph_operation"]))
        displacement = int(graph.unit.observation.instructions[1].operations[0].opcode == "INT_LEFT")
        flag_operations = {"NG": (4, "INT_SLESS"), "ZR": (5, "INT_EQUAL"),
                           "CY": (1, "INT_LESSEQUAL"), "OV": (2, "INT_SBORROW")}
        for item in predicate["inputs"]:
            ordinal, opcode = flag_operations[item["pre_register"]["name"]]
            assert f"op:1:{branch_pc - 4:x}:{ordinal + displacement}:{opcode}" in {
                deps.node(node).key for node in decision.reachable_nodes
            }


@pytest.mark.parametrize("branch_word,message", [
    ("200000b4", "not a distinct forward local instruction"),  # taken == fallthrough
    ("e0ffffb4", "not a distinct forward local instruction"),  # backedge
    ("e00100b4", "not a distinct forward local instruction"),  # outside function
    ("7f0000b4", "unsupported ARM64 instruction"),  # CBZ XZR
    ("6e000054", "unsupported ARM64 instruction"),  # AL
    ("6f000054", "unsupported ARM64 instruction"),  # NV
    ("03000014", "unreachable instruction"),        # B leaves a hole
])
def test_standalone_refuses_out_of_scope_branches(tmp_path, branch_word, message):
    pytest.importorskip("pypcode")
    with pytest.raises(ValueError, match=message):
        arm64_export(tmp_path, f"ff4300d1 {branch_word} {BRANCH_BODY}", branches=True)
    assert not (tmp_path / "bundles").exists()


@pytest.mark.parametrize("changed", ["flow_target", "pcode_target", "flag", "cmp_imm", "flag_write", "flags_alias", "v1"])
def test_standalone_branch_rejects_resealed_inconsistent_observation(tmp_path, changed):
    from arm64_local import language_id
    from tdo_v2.integration.standalone_arm64 import PROFILE

    pytest.importorskip("pypcode")
    generation = arm64_export(tmp_path, f"ff4300d1 1f1c0071 61000054 {BRANCH_BODY}", branches=True)
    observation = json.loads((generation / "function-000000.json").read_bytes())
    rows = observation["instructions"]
    branch = rows[2]
    profile = (generation / "call-interface-profile.json").read_bytes()
    program = json.loads((generation / "program.json").read_bytes())
    if changed == "flow_target":
        branch["flow_targets"][0]["byte_offset"] += 4
    elif changed == "pcode_target":
        branch["operations"][1]["inputs"][0]["byte_offset"] += 4
    elif changed == "flag":
        branch["operations"][0]["inputs"][0]["byte_offset"] += 1   # CY in place of ZR
    elif changed == "cmp_imm":
        rows[1]["operations"][0]["inputs"][0]["byte_offset"] += 1
    elif changed == "flag_write":
        op = deepcopy(rows[1]["operations"][7])
        op["ordinal"] = len(rows[0]["operations"])
        op["inputs"] = [{"kind_code": 1, "space_id": 0, "byte_offset": 1, "byte_size": 1}]
        rows[0]["operations"].append(op)
    elif changed == "flags_alias":
        names = {r["name"]: r for r in program["register_evidence"]["registers"]}
        ng, zr = names["tmpNG"], names["tmpZR"]
        for op in rows[1]["operations"]:
            for value in [*op["inputs"], op["output"]]:
                if value and value["kind_code"] == 2 and value["byte_offset"] == zr["byte_offset"]:
                    value["byte_offset"] = ng["byte_offset"]
        zr["byte_offset"] = ng["byte_offset"]
        program["register_evidence"]["registers"].sort(
            key=lambda r: (r["space_id"], r["byte_offset"], r["byte_size"], r["name"]))
    else:
        profile = json_bytes(dict(json.loads(profile), schema=PROFILE))
        program["translation_namespace"]["language_id"] = language_id(profile)
    blocks = [(0x400000, (generation / "memory-000000.bin").read_bytes()),
              (ENTRY, (generation / "memory-000001.bin").read_bytes())]
    other = _write_bundle(tmp_path / "second", (generation / "original.bin").read_bytes(), profile,
                          json_bytes(program), blocks, json_bytes(observation))
    with pytest.raises(ValueError, match="local flow and one terminal RET|straight-line code and one terminal RET"):
        build_standalone_arm64_graphs(other)


def test_standalone_diagnostic_rejects_swapped_outcomes(tmp_path, monkeypatch):
    from arm64_local_facts import Arm64Facts

    pytest.importorskip("pypcode")
    generation = arm64_export(tmp_path, f"ff4300d1 600000b4 {BRANCH_BODY}", branches=True)
    original = Arm64Facts.row

    def swapped(self, *args, **kwargs):
        row = original(self, *args, **kwargs)
        if row["aarch64"]["form"] == "cbz":
            taken, next_row = row["transfer"]["edges"]
            taken["to"], next_row["to"] = next_row["to"], taken["to"]
        return row

    monkeypatch.setattr(Arm64Facts, "row", swapped)
    with pytest.raises(ValueError, match="branch outcome disagrees"):
        describe(generation)
