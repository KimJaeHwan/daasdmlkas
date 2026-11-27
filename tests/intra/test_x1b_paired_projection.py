"""X-1b paired comparison (design_x1b_method_r3 section 3 / C / F): the coordinate projection's own tests.

A small synthetic paired snapshot: one function with an SSA (definitions, actions, state nodes, atoms), a
dependency graph, a memory graph and a summary. A consistent renumbering with new identity digests and a
generation-only change pass; a same-kind edge rewiring, a moved debt, a verdict-only change and a premise-use-only
change fail; an ambiguous coordinate stops; the pair check refuses a snapshot that is not the recorded input.
"""
from __future__ import annotations

import copy
import gzip
import json
import sys
from pathlib import Path
from tempfile import TemporaryFile

import pytest

TOOLS = Path(__file__).resolve().parents[2] / "tools" / "graph_fidelity"
sys.path.insert(0, str(TOOLS))

import paired_projection  # noqa: E402
import semantic_snapshot  # noqa: E402
import snapshot_sections  # noqa: E402
from paired_projection import Ambiguous, project_document  # noqa: E402
from snapshot_sections import Sections, open_snapshot  # noqa: E402

KEY = "1b1:1000"


def scope(digest):
    return {"digest": {"bytes": digest}, "kind": {"enum": "StorageScopeKind.FUNCTION"}, "type": "StorageScopeId"}


def program_scope(digest):
    return {"digest": {"bytes": digest}, "kind": {"enum": "StorageScopeKind.PROGRAM"}, "type": "StorageScopeId"}


def relative(function_digest, space_key, start, size=8):
    return {"object_id": {"kind": {"enum": "StorageObjectKind.FUNCTION_RELATIVE"}, "scope": scope(function_digest),
                          "space_key": space_key, "type": "StorageObjectId"},
            "size": size, "start": start, "type": "ByteSpan"}


def register(program_digest, start):
    return {"object_id": {"kind": {"enum": "StorageObjectKind.REGISTER_FILE"}, "scope": program_scope(program_digest),
                          "space_key": 0, "type": "StorageObjectId"}, "size": 8, "start": start, "type": "ByteSpan"}


def document(*, f="a" * 64, u="b" * 64, p="c" * 64, space=(1 << 200) + 7, atom=(1 << 210) + 9, order=(0, 1, 2),
             generation="g1", verdict="StackRestoration.PROVEN", premise="globals-disjoint-from-stack",
             debt_site="1b1:1004:0:STORE", rewire=False):
    """``order``: the positions the three definitions take (a renumbering permutes them and every reference)."""
    defs = [
        {"block_key": KEY, "kind": {"enum": "MemoryDefinitionKind.ENTRY"}, "operation_key": None,
         "span": relative(f, space, 0), "type": "MemoryDefinition", "write_ordinal": None},
        {"block_key": KEY, "kind": {"enum": "MemoryDefinitionKind.WRITE"}, "operation_key": "1b1:1004:0:STORE",
         "span": relative(f, space, 0), "type": "MemoryDefinition", "write_ordinal": 0},
        {"block_key": KEY, "kind": {"enum": "MemoryDefinitionKind.WRITE"}, "operation_key": "1b1:1008:0:STORE",
         "span": relative(f, space, 8), "type": "MemoryDefinition", "write_ordinal": 0},
    ]
    position = {logical: order[logical] for logical in range(3)}
    definitions = [None] * 3
    for logical, row in enumerate(defs):
        definitions[position[logical]] = row
    atoms = [{"object_id": relative(f, space, 0)["object_id"], "size": 8, "start": 0, "type": "AtomicSpan"},
             {"object_id": relative(f, space, 0)["object_id"], "size": 8, "start": 8, "type": "AtomicSpan"}]
    ssa = {
        "type": "LocalMemorySsaResult", "function_scope": scope(f), "unit_digest": {"bytes": u},
        "definitions": definitions, "atomic_spans": atoms,
        "actions": [{"type": "MemoryAction", "operation_key": "1b1:1004:0:STORE",
                     "write_definition_ids": [position[1]]}],
        "state_nodes": [{"type": "MemoryStateNode", "definition_ids": [position[1]], "start_atom": 0, "stop_atom": 1,
                         "left_node_id": None, "right_node_id": 1},
                        {"type": "MemoryStateNode", "definition_ids": [position[2]], "start_atom": 1, "stop_atom": 2,
                         "left_node_id": None, "right_node_id": None}],
        "observed_terminal_states": [{"type": "ObservedTerminalMemoryState", "root_node_id": 0}],
        "reads": [{"type": "MemoryRead", "action_id": 0, "read_ordinal": 0,
                   "fragments": [{"definition_ids": [position[0]]}]}],
    }
    unit = {"type": "StorageScopeId"}
    del unit
    node_of = lambda logical: f"memory:memory-v3:{f}:{u}:definition:{position[logical]}"  # noqa: E731
    nodes = [{"key": "op:1b1:1004:0:STORE", "kind": {"enum": "NodeKind.OPERATION"}, "label": "STORE",
              "type": "NodeRecord"},
             {"key": node_of(1), "kind": {"enum": "NodeKind.MEMORY_DEFINITION"}, "label": "write", "type": "NodeRecord"},
             {"key": node_of(2), "kind": {"enum": "NodeKind.MEMORY_DEFINITION"}, "label": "write", "type": "NodeRecord"},
             {"key": node_of(0), "kind": {"enum": "NodeKind.OBSERVED_INPUT"}, "label": "entry", "type": "NodeRecord"}]
    edge_target = 2 if rewire else 1   # (a same-kind rewiring: the STORE defines the other write)
    normalized = {
        "type": "NormalizedFunction", "memory_ssa": ssa,
        "address_atoms": [[atom, f"entry register_file+0x20:8 #{atom & 0xffffffff:08x}"]],
        "address_objects": [[relative(f, space, 0)["object_id"], [[[atom, 1]], 433]]],
        "effects": [{"operation_key": "1b1:1004:0:STORE", "reads": [{"span": register(p, 32)}],
                     "writes": [{"span": relative(f, space, 0)}]}],
        "dependencies": {"nodes": nodes, "edges": [[0, edge_target, {"kind": "memory_defines", "type": "EdgeRecord"}],
                                                   [3, 0, {"kind": "memory_read", "type": "EdgeRecord"}]]},
        "memory_graph": {"definition_nodes": [None] * 3, "action_nodes": [0]},
        "premise_uses": [premise],
    }
    for logical, node in ((0, 3), (1, 1), (2, 2)):
        normalized["memory_graph"]["definition_nodes"][position[logical]] = node
    summary = {"type": "FunctionSummary", "exits": [{"runs": [
        {"definitions": [position[1]], "debts": [{"kind": "clobber", "site": debt_site}], "sources": [],
         "span": relative(f, space, 0)}]}],
        "proven": [{"stack_restoration": {"enum": verdict}}]}
    sections = {f"function:{KEY}:normalized": normalized, f"function:{KEY}:summary": summary,
                "run:supports": [premise]}
    meta = {"generation": generation, "config": "default", "bindings": [], "options": None, "models": None,
            "paired": True, "manifest_sha256": "m-" + generation, "seal_sha256": "s-" + generation}
    return {"meta": meta, "complete": True, "sections": sections,
            "digests": {name: semantic_snapshot._digest(data) for name, data in sections.items()}}


def projected_equal(left, right) -> bool:
    return project_document(left)["digests"] == project_document(right)["digests"]


def test_consistent_renumbering_with_new_digests_passes():
    base = document()
    renumbered = document(f="d" * 64, u="e" * 64, p="f" * 64, space=(1 << 201) + 3, atom=(1 << 211) + 5,
                          order=(2, 0, 1))
    assert base["digests"] != renumbered["digests"]
    assert projected_equal(base, renumbered)


def test_generation_only_change_passes_the_pair_check(tmp_path):
    left, right = document(generation="g1"), document(generation="g2")
    paths = []
    for name, value in (("left", left), ("right", right)):
        path = tmp_path / f"{name}.json.gz"
        with gzip.open(path, "wt", encoding="utf-8") as handle:
            json.dump(value, handle)
        paths.append(path)
    pair = {"left": {"manifest_sha256": "m-g1", "seal_sha256": "s-g1"},
            "right": {"manifest_sha256": "m-g2", "seal_sha256": "s-g2"}}
    assert semantic_snapshot.compare(*paths, pair=pair) == 0
    assert semantic_snapshot.compare(*paths, pair=pair, projected=True) == 0
    wrong = {**pair, "right": {"manifest_sha256": "m-other", "seal_sha256": "s-g2"}}
    assert semantic_snapshot.compare(*paths, pair=wrong) == 2
    assert semantic_snapshot.compare(*paths) == 2   # (no pair: the differing generation stops the plain compare)
    with semantic_snapshot.PairedComparison() as comparison:
        assert comparison.compare(*paths, pair, projected=True) == 0
        assert comparison.compare(*paths, wrong, projected=True) == 2


@pytest.mark.parametrize("change", [
    {"rewire": True},                                   # same-kind edge rewiring
    {"debt_site": "1b1:1008:0:STORE"},                  # a debt moved, count unchanged
    {"verdict": "StackRestoration.UNKNOWN"},            # verdict only
    {"premise": "image-code-unmodified-at-runtime"},    # premise use only
])
def test_a_changed_decision_fails(change):
    assert not projected_equal(document(), document(**change))
    assert not projected_equal(document(order=(1, 2, 0)), document(order=(2, 1, 0), **change))


def test_a_rewired_reference_fails_even_after_renumbering():
    base = document()
    rewired = copy.deepcopy(document(order=(2, 0, 1)))
    ssa = rewired["sections"][f"function:{KEY}:normalized"]["memory_ssa"]
    ssa["reads"][0]["fragments"][0]["definition_ids"] = [ssa["actions"][0]["write_definition_ids"][0]]
    assert not projected_equal(base, rewired)


def test_an_ambiguous_coordinate_stops():
    value = document()
    nodes = value["sections"][f"function:{KEY}:normalized"]["dependencies"]["nodes"]
    nodes.append(copy.deepcopy(nodes[0]))
    with pytest.raises(Ambiguous):
        project_document(value)


def test_an_unowned_function_scope_stops():
    value = document()
    value["sections"][f"function:{KEY}:summary"]["exits"][0]["runs"][0]["span"] = relative("9" * 64, 5, 0)
    with pytest.raises(Ambiguous):
        project_document(value)


def test_the_erased_fields_are_listed_with_reasons():
    for table in (paired_projection.IDENTITY_RENAMED, paired_projection.DIGEST_FIELDS_ERASED,
                  paired_projection.TREE_LINKS_ERASED):
        assert table and all(isinstance(reason, str) and reason for reason in table.values())


def test_multiset_sort_keeps_lexical_order_across_blocks(monkeypatch):
    monkeypatch.setattr(paired_projection, "_SORT_BLOCK", 2)
    rows = [{"a": [item]} for item in (2, 10, 3, 10, 0)]
    expected = sorted(rows, key=paired_projection.canonical)
    paired_projection._sort_by_canonical(rows)
    assert rows == expected


def write_snapshot(path, value):
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump(value, handle, indent=1, ensure_ascii=False)
    return path


@pytest.mark.parametrize("legacy", [False, True])
def test_indexed_projection_resolves_summary_from_unsorted_sections(tmp_path, monkeypatch, legacy):
    monkeypatch.setattr(snapshot_sections, "_SHARE_IDENTIFIERS_ABOVE", 0)
    source = document(order=(2, 0, 1))
    sections = source["sections"]
    owner = f"function:{KEY}:normalized" + ("[0]" if legacy else "")
    normalized = sections.pop(f"function:{KEY}:normalized")
    source["sections"] = {"run:comment": '문자열 ["\\"] }', **sections, owner: normalized}
    source["digests"] = {name: semantic_snapshot._digest(data) for name, data in source["sections"].items()}
    original = copy.deepcopy(source)
    expected = project_document(source)
    assert source == original
    path = write_snapshot(tmp_path / "shuffled.json.gz", source)
    with open_snapshot(path) as snapshot, TemporaryFile() as stream:
        projected = Sections(stream)
        assert paired_projection.project_snapshot(snapshot, projected) == expected["digests"]
        assert {key: projected[key] for key in projected} == expected["sections"]


@pytest.mark.parametrize("fault", [
    "no sections", "missing digest", "trailing data", "truncated gzip", "invalid deflate", "broken value",
])
def test_indexed_pair_fails_closed_even_against_itself(tmp_path, fault):
    source = document()
    if fault == "no sections":
        del source["sections"]
        source["digests"] = {}
    if fault == "missing digest":
        source["digests"].pop("run:supports")
    contents = json.dumps(source)
    if fault == "trailing data":
        contents += " true"
    if fault == "broken value":
        contents = contents.replace('"run:supports": [', '"run:supports": [,', 1)
    path = tmp_path / "broken.json.gz"
    compressed = gzip.compress(contents.encode())
    if fault == "truncated gzip":
        compressed = compressed[:-4]
    if fault == "invalid deflate":
        compressed = compressed[:10] + b"\x07" + compressed[11:]
    path.write_bytes(compressed)
    identity = {key: source["meta"][key] for key in ("manifest_sha256", "seal_sha256")}
    pair = {"left": identity, "right": identity}
    for projected in (False, True):
        assert semantic_snapshot.compare(path, path, pair=pair, projected=projected) == 2


def test_bounded_pair_shows_a_change_of_read_ordinal(tmp_path, capsys):
    a, b = document(), document(generation="g2")
    name = f"function:{KEY}:normalized"
    b["sections"][name]["memory_ssa"]["reads"][0]["read_ordinal"] = 1
    b["digests"][name] = semantic_snapshot._digest(b["sections"][name])
    paths = [write_snapshot(tmp_path / f"{side}.json.gz", source) for side, source in [("a", a), ("b", b)]]
    pair = {"left": {"manifest_sha256": "m-g1", "seal_sha256": "s-g1"},
            "right": {"manifest_sha256": "m-g2", "seal_sha256": "s-g2"}}
    for projected in (False, True):
        assert semantic_snapshot.compare(*paths, pair=pair, projected=projected) == 1
        assert "at $.memory_ssa.reads[0].read_ordinal: 0 | 1" in capsys.readouterr().out


def test_indexed_projection_checks_a_scope_in_a_run_section(tmp_path):
    source = document()
    source["sections"]["run:supports"] = [relative("9" * 64, 5, 0)]
    path = write_snapshot(tmp_path / "scope.json.gz", source)
    with open_snapshot(path) as snapshot, pytest.raises(Ambiguous, match="owned by no function"):
        paired_projection.project_snapshot(snapshot)


def add_unlabelled_objects(source, *, offset=0):
    part = source["sections"][f"function:{KEY}:normalized"]
    digest = part["memory_ssa"]["function_scope"]["digest"]["bytes"]
    atoms = ((1 << 221) + offset, (1 << 221) + offset + 1)
    space_keys = ((1 << 220) + offset, (1 << 220) + offset + 1)
    for atom, key in zip(atoms, space_keys, strict=True):
        part["address_objects"].append([relative(digest, key, 0)["object_id"], [[[atom, 1]], 433]])
    return part, atoms, space_keys


def record_origins(part, atoms, *, same_site=False, first_operand=0, first_input=None):
    origins = []
    for index, atom in enumerate(atoms):
        site = f"1b1:{0x1010 + (0 if same_site else index):x}:0:INT_SEXT"
        terms = [] if first_input is None or index else [[first_input, 1]]
        expr = [{"set": terms}, 0, 4, 0]
        recipe = ["operation", site, [["boundary", "sext"], 8], [[first_operand if index == 0 else 0, expr]]]
        origins.append([atom, {"set": [recipe]}, {"set": []}])
    part["address_atom_origins"] = origins


def test_origin_recipes_resolve_distinct_unaccessed_objects_across_renumbering(tmp_path):
    a = document()
    b = document(f="d" * 64, u="e" * 64, p="f" * 64, order=(2, 0, 1))
    for shift, doc in enumerate((a, b)):
        part, atoms, keys = add_unlabelled_objects(doc, offset=4 * shift)
        with pytest.raises(Ambiguous, match="two space keys share one base expression"):
            project_document(doc)
        record_origins(part, atoms)
        names = paired_projection.build_tokens(doc)["spaces"]
        assert names[keys[0]] != names[keys[1]]
    assert projected_equal(a, b)
    path = write_snapshot(tmp_path / "origins.json.gz", b)
    with open_snapshot(path) as indexed:
        assert paired_projection.project_snapshot(indexed) == project_document(a)["digests"]


def test_origin_coordinates_refuse_collisions_even_without_any_effect_user():
    doc = document()
    part, atoms, _ = add_unlabelled_objects(doc)
    record_origins(part, atoms, same_site=True)
    with pytest.raises(Ambiguous, match="two address atoms share one origin coordinate"):
        project_document(doc)


def test_rewiring_the_origin_operand_changes_the_object_coordinate():
    a, b = document(), document()
    for index, doc in enumerate((a, b)):
        part, atoms, keys = add_unlabelled_objects(doc)
        record_origins(part, atoms, first_operand=index)
    assert paired_projection.build_tokens(a)["spaces"][keys[0]] != paired_projection.build_tokens(b)["spaces"][keys[0]]
    assert not projected_equal(a, b)


def test_unlabelled_origin_inputs_keep_raw_identity_even_with_a_unique_use():
    names = []
    for index in range(2):
        doc = document()
        part, atoms, keys = add_unlabelled_objects(doc)
        unknown = (1 << 238) + index
        obj = copy.deepcopy(part["address_objects"][0][0])
        obj["space_key"] = (1 << 239) + index
        part["address_objects"].append([obj, [[[unknown, 2]], 433]])
        record_origins(part, atoms, first_input=unknown)
        names.append(paired_projection.build_tokens(doc)["spaces"][keys[0]])
    assert names[0] != names[1]


def test_an_ssa_join_keeps_each_source_paired_with_its_expression():
    names = []
    for index in range(2):
        doc = document()
        part, atoms, keys = add_unlabelled_objects(doc)
        record_origins(part, atoms)
        target = ["JOIN", None, None, KEY, "register_file", 0, 32, 8]
        operands = []
        for position, literal in enumerate((1, 2) if index == 0 else (2, 1)):
            source = ["DATA_WRITE", "1b1:1004:0:COPY", position, None, "register_file", 0, 32, 8]
            operands.append([[source, 1], [{"set": []}, literal, 8, 0]])
        part["address_atom_origins"][0][1]["set"] = [["join", KEY, target, {"set": operands}]]
        names.append(paired_projection.build_tokens(doc)["spaces"][keys[0]])
    assert names[0] != names[1]


def test_a_relative_entry_base_overrides_an_identical_display_label():
    names = []
    for location in (32, 40):
        doc = document()
        part, atoms, keys = add_unlabelled_objects(doc)
        record_origins(part, atoms)
        original = part["address_atoms"][0][0]
        part["address_atoms"][0][1] = f"entry register_file+{location:#x}:8"
        part["address_atoms"].append([atoms[0], "entry function_relative+0x10000000000000000:4"])
        payload = ["entry", None, ["function_relative", "function", 433, 1 << 64, 4],
                   [["object-base", [{"set": [[original, 1]]}, 0, None, 0]]]]
        part["address_atom_origins"][0][1]["set"] = [payload]
        names.append(paired_projection.build_tokens(doc)["spaces"][keys[0]])
    assert names[0] != names[1]
