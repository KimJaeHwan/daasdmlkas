"""Pair lifts must agree with encoded memory lanes, register roles and writeback."""

from copy import deepcopy
import json

import pytest

from test_standalone_arm64 import ENTRY, arm64_export, local_graph
from arm64_local import _write_bundle, json_bytes
from arm64_local_facts import describe
from tdo_v2.integration.standalone_arm64 import build_standalone_arm64_graphs

RET = "c0035fd6"


def word(load, width, mode, *, base=31, first=2, second=3, displacement=0):
    prefix = {"post": 0x28800000, "offset": 0x29000000, "pre": 0x29800000}[mode]
    encoded = (prefix | (int(width == 8) << 31) | (int(load) << 22) | ((displacement // width & 127) << 15)
               | (second << 10) | (base << 5) | first)
    return encoded.to_bytes(4, "little").hex()


@pytest.mark.parametrize("load", [False, True])
@pytest.mark.parametrize("width", [4, 8])
@pytest.mark.parametrize("mode", ["offset", "pre", "post"])
@pytest.mark.parametrize("scale", [-64, 0, 63])
def test_pair_two_accesses_and_exact_signed_displacement(tmp_path, load, width, mode, scale):
    pytest.importorskip("pypcode")
    delta = scale * width
    generation = arm64_export(tmp_path, f"{word(load, width, mode, displacement=delta)} {RET}", pairs=True)
    pair, = describe(generation)["pairs"]
    assert pair["base"] == "sp"
    assert pair["mode"] == mode
    a, b = pair["accesses"]
    first = 0 if mode == "post" else delta
    assert [a["offset_from_incoming_base"], b["offset_from_incoming_base"]] == [first, first + width]
    assert [a["width"], b["width"]] == [width, width]
    assert a["op"]["ordinal"] < b["op"]["ordinal"]
    assert a["graph_operation"] != b["graph_operation"]
    assert a["op"]["opcode"] == b["op"]["opcode"] == ("LOAD" if load else "STORE")
    if mode == "offset":
        assert pair["writeback"] is None
    else:
        assert pair["writeback"]["delta"] == delta
        assert pair["writeback"]["op"]["opcode"] == "INT_ADD"


@pytest.mark.parametrize("load,width,mode,base,first,second", [
    (True, 4, "offset", 2, 2, 3),  # both addresses use incoming x2
    (True, 8, "offset", 2, 2, 3),
    (False, 4, "offset", 2, 2, 2),
    (False, 8, "offset", 31, 31, 31),
    (False, 4, "pre", 2, 31, 3),
    (True, 4, "pre", 2, 31, 3),
    (True, 8, "post", 2, 3, 31),
])
def test_defined_aliases_and_zero_register(tmp_path, load, width, mode, base, first, second):
    pytest.importorskip("pypcode")
    generation = arm64_export(tmp_path, f"{word(load, width, mode, base=base, first=first, second=second)} {RET}",
                              pairs=True)
    pair, = describe(generation)["pairs"]
    for register, access in zip((first, second), pair["accesses"]):
        if register == 31:
            assert access["register_effect"] == ("discard_load" if load else "store_zero")
        else:
            assert access["register"] == f"{'x' if width == 8 else 'w'}{register}"


@pytest.mark.parametrize("pair", [
    word(True, 8, "offset", first=2, second=2),
    word(True, 8, "offset", first=31, second=31),
    word(False, 8, "pre", base=2),
    word(True, 4, "post", base=3),
    "e20f00a8",  # STNP X2, X3, [SP]
    "e20f00ad",  # STP Q2, Q3, [SP]
])
def test_constrained_unpredictable_or_other_pair_class_refused(tmp_path, pair):
    pytest.importorskip("pypcode")
    with pytest.raises(ValueError, match="unsupported ARM64 instruction"):
        arm64_export(tmp_path, f"{pair} {RET}", pairs=True)


def test_saved_and_overwritten_stack_lanes_and_restored_sp(tmp_path):
    pytest.importorskip("pypcode")
    generation = arm64_export(tmp_path, "e10bbfa9 e30700f9 e417c1a8 e40700f9 e50b00f9 c0035fd6", pairs=True)
    report = describe(generation)
    _program, graph = local_graph(generation)
    stp, ldp = report["pairs"]
    ssa = graph.normalized.memory_ssa
    first, second = [item["graph_operation"][3:] for item in ldp["accesses"]]
    stack = [r for r in ssa.reads if r.span.object_id.kind.value == "function_relative"]
    reads = {ssa.actions[r.action_id].operation_key: r for r in stack}
    assert [(reads[key].span.start - (1 << 64), reads[key].span.end - reads[key].span.start)
            for key in (first, second)] == [(-16, 8), (-8, 8)]
    for key, expected in ((first, stp["accesses"][0]["graph_operation"][3:]), (second, "1:401004:1:STORE")):
        assert {ssa.definitions[ident].operation_key for f in reads[key].fragments for ident in f.definition_ids} == {expected}
    for key, expected in (("1:40100c:1:STORE", 8), ("1:401010:1:STORE", 16)):
        action, = (item for item in ssa.actions if item.operation_key == key)
        spans = [ssa.definitions[ident].span for ident in action.write_definition_ids]
        assert sum(s.end - s.start for s in spans) == 8
        assert min(s.start for s in spans) - (1 << 64) == expected


def test_restored_stack_slot_uses_the_original_ssa_definition(tmp_path):
    pytest.importorskip("pypcode")
    generation = arm64_export(
        tmp_path, "e60700f9 e10bbfa9 e417c1a8 e00740f9 c0035fd6", pairs=True)
    _program, graph = local_graph(generation)
    ssa = graph.normalized.memory_ssa
    read, = (r for r in ssa.reads if r.span.object_id.kind.value == "function_relative"
             and ssa.actions[r.action_id].operation_key == "1:40100c:1:LOAD")
    assert read.span.start - (1 << 64) == 8
    assert {ssa.definitions[ident].operation_key
            for f in read.fragments for ident in f.definition_ids} == {"1:401000:1:STORE"}
    seed = graph.normalized.dependencies.node_for_key("op:1:40100c:1:LOAD")
    assert graph.query(seed).reachable_unresolved_read_nodes == ()


@pytest.mark.parametrize("change", ["writeback", "new_base_in_post", "width", "swap_writes", "missing_zext",
                                    "extra_access", "gpr_alias_sp", "gpr_alias_flag", "w_alias_shift"])
def test_resealed_wrong_pair_effects_are_refused(tmp_path, change):
    pytest.importorskip("pypcode")
    generation = arm64_export(tmp_path, f"{word(True, 4, 'post', displacement=16)} {RET}", pairs=True)
    report = describe(generation)["pairs"][0]
    observation = json.loads((generation / "function-000000.json").read_bytes())
    program = json.loads((generation / "program.json").read_bytes())
    ops = observation["instructions"][0]["operations"]
    wb = ops[report["writeback"]["op"]["ordinal"]]
    first = ops[report["accesses"][0]["op"]["ordinal"]]
    reason = "pair effects disagree"
    if change == "writeback":
        wb["inputs"][1]["byte_offset"] ^= 8
    elif change == "new_base_in_post":
        first["inputs"][1] = deepcopy(wb["output"])
    elif change == "width":
        first["output"]["byte_size"] = 8
    elif change == "swap_writes":
        ops[-2]["output"], ops[-1]["output"] = ops[-1]["output"], ops[-2]["output"]
    elif change == "missing_zext":
        ops[-2]["inputs"][0] = deepcopy(first["output"])
    elif change == "extra_access":
        extra = deepcopy(first)
        extra["ordinal"] = len(ops)
        ops.append(extra)
    else:
        table = program["register_evidence"]["registers"]
        names = {item["name"]: item for item in table}
        if change in ("gpr_alias_sp", "gpr_alias_flag"):
            target = names["sp" if change == "gpr_alias_sp" else "ZR"]["byte_offset"]
            names["x2"]["byte_offset"] = names["w2"]["byte_offset"] = target
            ops[-2]["output"]["byte_offset"] = target
        else:
            names["w2"]["byte_offset"] += 4
        table.sort(key=lambda r: (r["space_id"], r["byte_offset"], r["byte_size"], r["name"]))
        reason = "pair register file has conflicting"
    blocks = [(0x400000, (generation / "memory-000000.bin").read_bytes()),
              (ENTRY, (generation / "memory-000001.bin").read_bytes())]
    forged = _write_bundle(tmp_path / "forged", (generation / "original.bin").read_bytes(),
                           (generation / "call-interface-profile.json").read_bytes(), json_bytes(program),
                           blocks, json_bytes(observation))
    with pytest.raises(ValueError, match=reason):
        build_standalone_arm64_graphs(forged)
