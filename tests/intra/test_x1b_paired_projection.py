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


def test_snapshot_writer_preserves_canonical_bytes_and_exact_section_bounds(tmp_path, monkeypatch):
    monkeypatch.setattr(snapshot_sections, "_CHUNK_SIZE", 16)
    reference = document()
    reference["meta"]["seconds"] = 0.0
    reference["sections"]["a:unicode"] = ["한글", "quote\"backslash\\", None]
    reference["digests"]["a:unicode"] = semantic_snapshot._digest(reference["sections"]["a:unicode"])
    path = tmp_path / "sample.json.gz"

    assert semantic_snapshot._write(path, reference["meta"], iter(reference["sections"].items()), "test") == 0
    with gzip.open(path, "rb") as handle:
        assert handle.read() == json.dumps(reference, sort_keys=True, separators=(",", ":")).encode()
    with open_snapshot(path) as reopened:
        assert reopened["digests"] == reference["digests"]
        for name, data in reference["sections"].items():
            assert reopened["sections"][name] == data


def test_snapshot_writer_preserves_existing_output_when_section_copy_fails(tmp_path, monkeypatch):
    reference = document()
    reference["meta"]["seconds"] = 0.0
    path = tmp_path / "sample.json.gz"
    assert semantic_snapshot._write(path, reference["meta"], iter(reference["sections"].items()), "test") == 0
    before = path.read_bytes()

    def interrupt_copy(self, name):
        yield b"["
        raise OSError("section copy failed")

    monkeypatch.setattr(Sections, "chunks", interrupt_copy)
    with pytest.raises(OSError, match="section copy failed"):
        semantic_snapshot._write(path, reference["meta"], iter(reference["sections"].items()), "test")
    assert path.read_bytes() == before
    assert sorted(tmp_path.iterdir()) == [path]


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


def projected_load(alternatives=(0, 1), *, address_register=32):
    value = document()
    section = value["sections"][f"function:{KEY}:normalized"]
    ssa = section["memory_ssa"]
    action = "1b1:100c:0:LOAD"
    spans = [register("c" * 64, address_register)] + [
        relative("a" * 64, (1 << 200) + 7, offset * 8) for offset in alternatives
    ]
    section["effects"].append({"type": "ObservedEffect", "operation_key": action, "kind": {"enum": "EffectKind.READ"},
                               "memory_read": None, "unresolved_reads": [],
                               "reads": [{"type": "ResolvedStorage", "span": span} for span in spans]})
    section["may_alias_reads"] = [{"type": "MayAliasRead", "operation_key": action, "unknown_address": False,
                                   "spans": spans[1:], "writers": ["1b1:1004:0:STORE"]}]
    section["call_clobber_reads"] = [{"type": "CallClobberRead", "operation_key": action,
                                      "spans": spans, "intervening_calls": ["1b1:100a:0:CALL"]}]
    unit = {"type": "LocalMemoryUnit", "blocks": [{"type": "LocalMemoryBlock", "actions": [
        {"type": "LocalStorageAction", "operation_key": action, "reads": spans, "unresolved_reads": []}]}]}
    section["memory_unit"] = unit
    ssa["reads"][0]["type"] = "MemoryReadResolution"
    ssa["actions"].append({"type": "MemoryActionResult", "operation_key": action, "write_definition_ids": []})
    nodes = section["dependencies"]["nodes"]
    section["memory_graph"]["action_nodes"].append(len(nodes))
    nodes.append({"key": f"op:{action}", "type": "NodeRecord", "label": "LOAD",
                  "kind": {"enum": "NodeKind.OPERATION"}})
    ssa["reads"].extend(
        {"type": "MemoryReadResolution", "action_id": 1, "read_ordinal": index, "span": span,
         "fragments": [{"definition_ids": [definition]}]}
        for index, (span, definition) in enumerate(zip(spans, [0, *(offset + 1 for offset in alternatives)]))
    )
    section["call_observations"] = {"memory_binding": {"unit": copy.deepcopy(unit), "result": copy.deepcopy(ssa)}}
    return value, section


def test_projected_load_reorders_the_candidates_with_their_own_ssa_reads():
    left, _ = projected_load()
    right, section = projected_load((1, 0))
    assert projected_equal(left, right)

    # Same candidates in both snapshots, but the mirrored SSA copy now binds
    # one read to the other candidate's definition.
    section["call_observations"]["memory_binding"]["result"]["reads"][-1]["fragments"][0]["definition_ids"] = [2]
    assert not projected_equal(left, right)


def test_projected_load_preserves_the_address_operand_and_candidate_count():
    left, _ = projected_load()
    assert not projected_equal(left, projected_load((1, 0), address_register=40)[0])
    assert not projected_equal(left, projected_load((0,))[0])


@pytest.mark.parametrize("inconsistent", ["duplicate ordinals", "additional consumer", "partial clobber"])
def test_projected_load_keeps_ordinals_when_the_positional_uses_are_not_all_matched(inconsistent):
    left, left_section = projected_load()
    right, right_section = projected_load((1, 0))
    for section in (left_section, right_section):
        if inconsistent == "duplicate ordinals":
            section["memory_ssa"]["reads"][-1]["read_ordinal"] = 1
        elif inconsistent == "additional consumer":
            section["call_observations"]["port_read"] = {"read_ordinal": 1}
        else:
            clobber = section["call_clobber_reads"][0]
            clobber["spans"] = clobber["spans"][1:]
    assert not projected_equal(left, right)


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


@pytest.mark.parametrize("kind", ["join", "nonstack-join"])
def test_an_ssa_join_keeps_each_source_paired_with_its_expression(kind):
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
        part["address_atom_origins"][0][1]["set"] = [[kind, KEY, target, {"set": operands}]]
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


@pytest.mark.parametrize("scale", [1, 4])
def test_address_relation_rows_ignore_order_and_keep_operand_roles(scale):
    def rows(doc):
        value = doc["sections"][f"function:{KEY}:summary"]
        return value.setdefault("address_relations", [
            [relative("a" * 64, n, 0)["object_id"],
             {"type": "IndexedAnchor", "base": register("c" * 64, i),
              "index": register("c" * 64, i + 8), "scale": scale,
              "space_id": 433, "extend": "identity", "preoffset": 0}]
            for n, i in ((1, 16), (2, 32))
        ])

    before, after = document(), document()
    rows(before)
    rows(after).reverse()
    assert projected_equal(before, after)
    relation = rows(after)[0][1]
    relation["base"], relation["index"] = relation["index"], relation["base"]
    assert not projected_equal(before, after)
    rows(after)[:] = [*rows(before), rows(before)[0]]
    assert not projected_equal(before, after)


def test_writer_condition_rows_ignore_order_and_keep_read_write_pairs():
    def rows(doc):
        value = doc["sections"][f"function:{KEY}:summary"]
        return value.setdefault("writer_conditions", [
            [register("c" * 64, position), relative("a" * 64, 433, position + 8)]
            for position in (16, 32)
        ])

    before, after = document(), document()
    rows(before)
    rows(after).reverse()
    assert projected_equal(before, after)
    rows(after)[0].reverse()
    assert not projected_equal(before, after)
    rows(after)[:] = [*rows(before), rows(before)[0]]
    assert not projected_equal(before, after)


def add_register_proofs(source, *, f, p, observation, delta=8):
    from tdo_v2.register_delta_proofs import RegisterDeltaBlock, RegisterDeltaCallFact, RegisterDeltaProof

    operation = "1b1:1004:0:CALL"
    fact = RegisterDeltaCallFact(operation, "1b1:2000", "call", 8, -8, "1" * 64)
    proofs = [RegisterDeltaProof((reg, 8), delta, p, f, observation, "0" * 64, (operation,),
                                (RegisterDeltaBlock(KEY, (), True, 0, delta),), (KEY,), (fact,), ())
              for reg in (32, 40)]
    summary = source["sections"][f"function:{KEY}:summary"]
    summary["independent_delta_proofs"] = [semantic_snapshot.encode(proof) for proof in proofs]
    hashes = [proof.record()["content_sha256"] for proof in proofs]
    nodes = source["sections"][f"function:{KEY}:normalized"]["dependencies"]["nodes"]
    nodes[0]["semantic_identity"] = "register-delta-proof:" + ",".join(hashes)
    return nodes[0], hashes


def test_register_proof_reference_uses_exact_receipts_and_preserves_order(tmp_path):
    a, b = document(), document(f="d" * 64, u="e" * 64, p="f" * 64)
    _, before = add_register_proofs(a, f="a" * 64, p="c" * 64, observation="2" * 64)
    node, after = add_register_proofs(b, f="d" * 64, p="f" * 64, observation="3" * 64)
    assert before != after and projected_equal(a, b)
    path = write_snapshot(tmp_path / "proofs.json.gz", b)
    with open_snapshot(path) as indexed:
        assert paired_projection.project_snapshot(indexed) == project_document(a)["digests"]
    node["semantic_identity"] = "register-delta-proof:" + ",".join(reversed(after))
    assert not projected_equal(a, b)
    add_register_proofs(b, f="d" * 64, p="f" * 64, observation="3" * 64, delta=16)
    assert not projected_equal(a, b)


def test_register_proof_reference_does_not_infer_an_unbound_receipt():
    doc = document()
    node, hashes = add_register_proofs(doc, f="a" * 64, p="c" * 64, observation="2" * 64)
    doc["sections"]["run:unrelated"] = node["semantic_identity"]
    summary = doc["sections"][f"function:{KEY}:summary"]
    summary["independent_delta_proofs"][1]["blocks"][0]["type"] = "OtherBlock"
    output = project_document(doc)["sections"]
    assert output["run:unrelated"] == node["semantic_identity"]
    mapped = output[f"function:{KEY}:normalized"]["dependencies"]["nodes"]
    mapped_identity = next(item["semantic_identity"] for item in mapped if "semantic_identity" in item)
    assert mapped_identity.startswith("register-delta-proof:proof@") and mapped_identity.endswith("," + hashes[1])


def test_register_proof_supports_and_exit_dependencies_follow_the_receipt():
    a, b = document(), document(f="d" * 64, u="e" * 64, p="f" * 64)
    for doc, f, p, obs in ((a, "a", "c", "2"), (b, "d", "f", "3")):
        _, hashes = add_register_proofs(doc, f=f * 64, p=p * 64, observation=obs * 64)
        deps = sorted(f"register-delta-proof:{digest}" for digest in hashes)
        doc["sections"]["run:supports"] = {"type": "ContinuationCertificate", "dependencies": deps,
                                           "exits": [{"type": "ExitRecord", "dependencies": deps}],
                                           "evidence": {"set": [{"type": "EvidenceRef", "kind": "proof", "id": hashes[0]}]}}
    assert projected_equal(a, b)


def test_interim_index_objects_use_their_own_recorded_bases(tmp_path):
    a, b = document(), document(f="d" * 64, u="e" * 64, p="f" * 64)
    for offset, doc in enumerate((a, b)):
        part, atoms, keys = add_unlabelled_objects(doc, offset=4 * offset)
        record_origins(part, atoms)
        objects, origins = part["address_objects"][-2:], part.pop("address_atom_origins")
        del part["address_objects"][-2:]
        doc["sections"]["run:index_diagnostics"] = {
            "dict": {"index_objects": {"set": [obj for obj, _ in objects]}, "seam_refusals": 0}}
        doc["sections"]["run:index_object_origins"] = {"items": [
            [part["memory_ssa"]["function_scope"],
             {"dict": {"address_objects": objects, "address_atoms": [], "address_atom_origins": origins}}]]}
        doc["digests"] = {name: semantic_snapshot._digest(data) for name, data in doc["sections"].items()}
        tokens = paired_projection.build_tokens(doc)["spaces"]
        assert tokens[keys[0]] != tokens[keys[1]]
    assert projected_equal(a, b)
    path = write_snapshot(tmp_path / "index.json.gz", b)
    with open_snapshot(path) as indexed:
        assert paired_projection.project_snapshot(indexed) == project_document(a)["digests"]
    evidence = b["sections"]["run:index_object_origins"]["items"][0][1]["dict"]["address_objects"]
    evidence[0][1][0][0][1] = -1
    assert not projected_equal(a, b)


def test_an_interim_relative_entry_label_alone_does_not_prove_its_base():
    a, b = document(), document()
    for offset, doc in enumerate((a, b)):
        part, atoms, keys = add_unlabelled_objects(doc, offset=4 * offset)
        obj, (_, space) = part["address_objects"].pop()
        part["address_objects"].pop()
        obj = [obj, [[[atoms[1], 2]], space]]
        doc["sections"]["run:index_diagnostics"] = {"dict": {"index_objects": {"set": [obj[0]]}}}
        doc["sections"]["run:index_object_origins"] = {"items": [
            [part["memory_ssa"]["function_scope"], {"dict": {
                "address_objects": [obj], "address_atom_origins": [],
                "address_atoms": [[atoms[1], "entry function_relative+0x0:8"]]
            }}]]}
    assert not projected_equal(a, b)


def test_a_join_span_with_an_unproven_relative_base_stays_distinct():
    names = []
    for offset in (0, 1):
        doc = document()
        part, atoms, keys = add_unlabelled_objects(doc)
        record_origins(part, atoms)
        raw = (1 << 215) + offset
        part["address_atoms"].append([raw, "entry function_relative+0x10:8"])
        target = ["JOIN", None, None, KEY, "function_relative", [433, {"set": [[raw, 1]]}], 16, 8]
        source = ["DATA_WRITE", "1b1:1004:0:STORE", 0, None, *target[4:]]
        operands = [[[source, 1], [{"set": []}, 0, 8, 0]]]
        part["address_atom_origins"][0][1]["set"] = [["nonstack-join", KEY, target, {"set": operands}]]
        names.append(paired_projection.build_tokens(doc)["spaces"][keys[0]])
    assert names[0] != names[1]
