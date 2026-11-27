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

import pytest

TOOLS = Path(__file__).resolve().parents[2] / "tools" / "graph_fidelity"
sys.path.insert(0, str(TOOLS))

import paired_projection  # noqa: E402
import semantic_snapshot  # noqa: E402
from paired_projection import Ambiguous, project_document  # noqa: E402

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
