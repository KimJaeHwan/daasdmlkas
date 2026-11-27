"""X-1b coordinate projection of a paired semantic snapshot (design_x1b_method_r3, sections 3 / C / F).

A paired comparison of two Bundles whose identity digests differ (row lengths, the register table) cannot compare
snapshots position by position: identities are content hashes, and the engine orders some collections by them and
refers to their members by index. The projection makes a snapshot identity-free without losing decisions:

1. identity tokens -- every scope digest, unit digest, relative space key and address-atom hash -- are renamed to
   the coordinate of their owner (``IDENTITY_RENAMED``, each with its reason); an unowned or ambiguous identity
   stops the projection (never merged);
2. index references are replaced by the content of what they refer to (``REFERENCES``: field -> table), so a
   rewired dependency stays visible and a consistent renumbering does not;
3. collections the engine orders by identity are compared as multisets (``COLLECTIONS``); every other list keeps
   its order (operand order stays significant).
"""
from __future__ import annotations

import hashlib
import json
import re

HEX64 = re.compile(r"(?<![0-9a-f])[0-9a-f]{40,64}(?![0-9a-f])")   # (digests; space keys may drop leading zeros)
ATOM_SUFFIX = re.compile(r" #[0-9a-f]{8}$")
SMALL = 1 << 32   # (a space key below this is a plain space id, not a hash)

# identity values renamed to their owner's coordinate (the only values the projection changes)
IDENTITY_RENAMED = {
    "StorageScopeId.digest": "scope identity: a content hash of the function unit / program -> F:<entry> / P",
    "LocalMemorySsaResult.unit_digest / MemoryGraph.unit_digest": "unit identity (content hash) -> U:<entry>",
    "StorageObjectId.space_key": "relative space identity (hash of its base) -> K:<base expression in atom labels>",
    "address atom hash": "an address atom's hash -> its label without the '#xxxxxxxx' hash suffix",
    "64-hex substrings naming a renamed digest / space key": "the same tokens inside keys / labels",
}
# content digests of input members (the observation, its effect evidence, the cut set): they change whenever an
# input field is added, by design; the content they hash is compared by stage 0 / the decisions themselves
DIGEST_FIELDS_ERASED = {
    "observation_digest": "hash of the function observation member (input)",
    "effect_evidence_digest": "hash of the call-effect evidence member (input)",
    "canonical_digest": "hash of the terminal-cut input set",
    "authority_digest": "hash of a debt's authority record (its kind / site / storage stay compared)",
    "evidence_digest": "hash of a debt's evidence record (its kind / site / storage stay compared)",
    "occurrence_digest": "hash of a call-site transition's occurrence (its site key stays compared)",
}
# state-node trees: a balanced tree over atoms ordered by identity -- its shape (left / right links) is layout; a
# node is compared by its own content (definitions, atom range) and a state by the set of nodes it reaches
TREE_LINKS_ERASED = {"left_node_id": "state-tree layout", "right_node_id": "state-tree layout",
                     "state_nodes / call_state_nodes rows": "a persistent tree arena (path copying): its intermediate "
                     "nodes depend on the tree shape; every state is compared by the node set its root reaches"}
NODE_KEY_INDEX = re.compile(r":definition:(\d+)$")


class Ambiguous(ValueError):
    """Two referents share one coordinate, or an identity has no owner (design F: stop, decide a finer coordinate)."""


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def short(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()[:16]


# -- 1. identity tokens -------------------------------------------------------------------------------------------

def _function_sections(document):
    """{function key: normalized dict} (default: ``:normalized``; legacy: ``:normalized[0]``)."""
    result = {}
    for name, data in document["sections"].items():
        match = re.fullmatch(r"function:(.+):normalized(\[0\])?", name)
        if match and isinstance(data, dict) and "memory_ssa" in data:
            result[match.group(1)] = data
    return result


def _walk(value, visit, path=()):
    visit(value, path)
    if isinstance(value, dict):
        for key, item in value.items():
            _walk(item, visit, path + (key,))
    elif isinstance(value, list):
        for item in value:
            _walk(item, visit, path + ("[]",))


def build_tokens(document) -> dict:
    tokens: dict = {}

    def bind(raw, token):
        if tokens.setdefault(raw, token) != token:
            raise Ambiguous(f"identity {str(raw)[:24]} has two owners: {tokens[raw]} / {token}")

    for key, normalized in _function_sections(document).items():
        ssa = normalized["memory_ssa"]
        if ssa.get("function_scope"):
            bind(ssa["function_scope"]["digest"]["bytes"], f"F:{key}")
        if ssa.get("unit_digest"):
            bind(ssa["unit_digest"]["bytes"], f"U:{key}")
    programs = set()

    def scopes(value, path):
        if isinstance(value, dict) and value.get("type") == "StorageScopeId":
            kind, digest = value["kind"]["enum"], value["digest"]["bytes"]
            if kind == "StorageScopeKind.PROGRAM":
                programs.add(digest)
            elif digest not in tokens:
                raise Ambiguous(f"function scope {digest[:16]} is owned by no function of this snapshot")

    for data in document["sections"].values():
        _walk(data, scopes)
    if len(programs) > 1:
        raise Ambiguous(f"{len(programs)} program scopes")
    for digest in programs:
        bind(digest, "P")
    labels: dict = {}   # raw atom -> {(function, label)}
    for key, normalized in _function_sections(document).items():
        for raw, label in normalized.get("address_atoms") or ():
            labels.setdefault(raw, set()).add((key, ATOM_SUFFIX.sub("", rename_text(label, tokens))))
    by_label: dict = {}
    for raw, owners in labels.items():
        if len({label for _, label in owners}) != 1:
            raise Ambiguous(f"address atom {str(raw)[:16]} has two labels")
        by_label.setdefault(next(iter(owners))[1], set()).add(raw)
    atoms: dict = {}
    for raw, owners in labels.items():
        label = next(iter(owners))[1]
        # (x86: one label, different hashes in different functions -> named per function)
        atoms[raw] = f"A:{label}" if len(by_label[label]) == 1 else \
            f"A:{','.join(sorted(key for key, _ in owners))}:{label}"
    if len(set(atoms.values())) != len(atoms):
        raise Ambiguous("two address atoms share one label")
    # atoms the engine does not label (boundary / join / shared-load atoms, relative_memory.py): named by their
    # function and the shapes of the base expressions they occur in; a collision stops the comparison (design F)
    shapes: dict = {}
    for key, normalized in _function_sections(document).items():
        users: dict = {}   # relative space key -> the operations whose effects read / write that object
        for effect in normalized.get("effects") or ():
            for side in ("reads", "writes"):
                for storage in effect.get(side) or ():
                    object_id = ((storage or {}).get("span") or {}).get("object_id") or {}
                    if isinstance(object_id.get("space_key"), int) and object_id["space_key"] >= SMALL:
                        users.setdefault(object_id["space_key"], set()).add(f"{side}:{effect.get('operation_key')}")
        for entry in normalized.get("address_objects") or ():
            terms, space = entry[1][0], entry[1][1]
            space_key = entry[0].get("space_key") if isinstance(entry[0], dict) else None
            for atom, coefficient in terms:
                if atom in atoms:
                    continue
                others = sorted([atoms.get(other, "?"), weight] for other, weight in terms if other != atom)
                shapes.setdefault(atom, set()).add(canonical([key, coefficient, others, space,
                                                              sorted(users.get(space_key, ()))]))
    for atom, occurrences in shapes.items():
        atoms[atom] = "A?:" + canonical(sorted(occurrences))
    if len(set(atoms.values())) != len(atoms):
        raise Ambiguous("two unlabeled address atoms occur in the same expression shapes")
    # a relative space key is the hash of its base expression (address_objects: object -> atoms x coefficients,
    # space id): its coordinate is that expression written with atom labels
    spaces: dict = {}
    for normalized in _function_sections(document).values():
        for entry in normalized.get("address_objects") or ():
            object_id, expression = entry[0], entry[1]
            raw = object_id.get("space_key") if isinstance(object_id, dict) else None
            if not isinstance(raw, int) or raw < SMALL:
                continue
            terms, space = expression[0], expression[1]
            label = "K:" + canonical([sorted([atoms.get(atom, f"?{atom}"), coefficient] for atom, coefficient in terms),
                                      space])
            if spaces.setdefault(raw, label) != label:
                raise Ambiguous(f"space key {str(raw)[:16]} has two base expressions")

    def unowned(value, path):
        if isinstance(value, dict) and value.get("type") == "StorageObjectId":
            raw = value.get("space_key")
            if isinstance(raw, int) and raw >= SMALL and raw not in spaces:
                raise Ambiguous(f"space key {str(raw)[:16]} has no base expression in this snapshot")

    for data in document["sections"].values():
        _walk(data, unowned)
    if len(set(spaces.values())) != len(spaces):
        raise Ambiguous("two space keys share one base expression")
    for raw, label in spaces.items():   # (labels spell a space key in hex, padded or not)
        bind(format(raw, "064x"), label)
        if format(raw, "x") != format(raw, "064x"):
            bind(format(raw, "x"), label)
    return {"digests": tokens, "spaces": spaces, "atoms": atoms}


def rename_text(text: str, digests: dict) -> str:
    return HEX64.sub(lambda match: digests.get(match.group(0), match.group(0)), text)


def rename(value, tokens):
    """Every identity token replaced by its coordinate (structure unchanged)."""
    digests, spaces, atoms = tokens["digests"], tokens["spaces"], tokens["atoms"]
    if isinstance(value, dict):
        if set(value) == {"bytes"} and value["bytes"] in digests:
            return {"token": digests[value["bytes"]]}
        result = {}
        for key, item in value.items():
            if key in DIGEST_FIELDS_ERASED and (isinstance(item, dict) and set(item) == {"bytes"}
                                                or isinstance(item, str) and HEX64.fullmatch(item)):
                result[key] = {"erased": key}
                continue
            if key == "space_key" and isinstance(item, int) and item in spaces:   # (small keys stay)
                result[key] = spaces[item]
            else:
                result[key] = rename(item, tokens)
        return result
    if isinstance(value, list):
        return [rename(item, tokens) for item in value]
    if isinstance(value, str):
        return ATOM_SUFFIX.sub("", rename_text(value, digests)) if ATOM_SUFFIX.search(value) else             rename_text(value, digests)
    if isinstance(value, int) and not isinstance(value, bool) and value in atoms:
        return atoms[value]
    return value


# -- 2. references --------------------------------------------------------------------------------------------------

# field name -> table it indexes, inside one LocalMemorySsaResult-shaped object (definitions / actions / state nodes
# / atomic spans); resolved to the referent's content
SSA_REFERENCES = {
    "definition_ids": "definitions", "write_definition_ids": "definitions", "source_definition_ids": "definitions",
    "join_definition_id": "definitions",
    "start_atom": "atomic_spans", "stop_atom": "atomic_spans",
    "left_node_id": "state_nodes", "right_node_id": "state_nodes", "root_node_id": "state_nodes",
    "action_id": "actions",
    # (LocalReadFrom in memory_graph.local_reads.plan: definition ids of the function's memory_ssa,
    # _memory_read_sources.py:38 / :108)
    "source_definition_id": "definitions", "address_witnesses": "definitions",
    # (GuardedImagePlan reads in memory_graph.image_reads.plan)
    "address_definition_id": "definitions",
}
# dependency-graph node references of a normalized function (field -> how its ints sit)
NODE_REFERENCE_LISTS = ("definition_nodes", "action_nodes", "unresolved_read_nodes", "unresolved_write_nodes",
                        "effect_nodes", "source_nodes", "may_alias_nodes", "candidate_nodes", "constant_nodes")
REFERENCES = {"ssa": SSA_REFERENCES, "graph nodes": NODE_REFERENCE_LISTS,
              "graph edges": "dependencies.edges[i][0..1], cfg.edges[i][0..1]",
              "summary": "FunctionSummary exits[].runs[].definitions -> the function's memory_ssa.definitions",
              "memory graph": "entry_bindings[i][0] -> dependency node"}
# collections the engine orders by identity: compared as multisets after resolution
COLLECTIONS = {"definitions", "state_nodes", "atomic_spans", "actions", "reads", "flow_edges", "joins", "nodes",
               "edges", "address_atoms", "address_objects", "runs", "entry_bindings", "observed_inputs",
               "call_state_nodes", "observed_terminal_states", "call_memory_states", "sources", "address_witnesses",
               "definition_nodes", "action_nodes",
               # FunctionSummary run conditions: (span, span) pairs sorted by canonical key (function_summary.py:422)
               # -- the pairs keep their order
               "conditions"}


def _is_ssa(value) -> bool:
    return isinstance(value, dict) and {"definitions", "state_nodes", "atomic_spans"} <= set(value)


class _Ssa:
    """Resolution of one SSA object's internal references (memoized, cycle-checked). State-node references
    stay in their arena: ``call_state_nodes`` / ``call_memory_states`` roots refer to ``call_state_nodes``
    (memory_contracts.py:434), every other one to ``state_nodes``; ``stop_atom`` is exclusive."""

    CALL_ARENA = ("call_state_nodes", "call_memory_states")

    def __init__(self, ssa):
        self.ssa, self.memo, self.active = ssa, {}, set()

    def resolve(self, table: str, index, arena: str = "state_nodes"):
        if index is None:
            return None
        rows = self.ssa.get(table)
        if rows is None or not isinstance(index, int) or not 0 <= index < len(rows):
            raise Ambiguous(f"{table}[{index}] out of range")
        key = (table, index)
        if key in self.memo:
            return self.memo[key]
        if key in self.active:
            raise Ambiguous(f"reference cycle at {table}[{index}]")
        self.active.add(key)
        value = self.row(rows[index], table if table in ("state_nodes", "call_state_nodes") else arena)
        self.active.discard(key)
        self.memo[key] = value
        return value

    def reach(self, arena: str, index):
        """The contents of every node of ``arena`` reachable from ``index`` (the state it roots), sorted."""
        rows, seen, pending = self.ssa.get(arena) or (), set(), [index]
        while pending:
            current = pending.pop()
            if current is None or current in seen:
                continue
            if not isinstance(current, int) or not 0 <= current < len(rows):
                raise Ambiguous(f"{arena}[{current}] out of range")
            seen.add(current)
            pending += [rows[current].get("left_node_id"), rows[current].get("right_node_id")]
        return sorted(short(self.resolve(arena, item, arena)) for item in seen)

    def row(self, value, arena: str = "state_nodes"):
        if isinstance(value, dict):
            result = {}
            for name, item in value.items():
                table = SSA_REFERENCES.get(name)
                if table == "state_nodes":
                    table = arena
                if name in TREE_LINKS_ERASED and value.get("type") == "MemoryStateNode":
                    continue
                if name == "root_node_id":
                    result[name] = None if item is None else {"state": arena, "nodes": self.reach(arena, item)}
                    continue
                if name == "stop_atom" and isinstance(item, int):
                    result[name] = self.ref("atomic_spans", item - 1, arena, last=True)
                elif table is not None and isinstance(item, list):
                    result[name] = [self.ref(table, entry, arena) for entry in item]
                elif table is not None and (isinstance(item, int) or item is None):
                    result[name] = self.ref(table, item, arena)
                else:
                    result[name] = self.row(item, arena)
            return result
        if isinstance(value, list):
            return [self.row(item, arena) for item in value]
        return value

    def ref(self, table, index, arena="state_nodes", last=False):
        if isinstance(index, dict) and "ref" in index:
            return index   # (already resolved by its own SSA object)
        resolved = self.resolve(table, index, arena)
        if resolved is None:
            return None
        return {"ref": table, "to": short(resolved), **({"end": True} if last else {})}

    def top(self):
        """The SSA object with every reference resolved (call arenas use their own state nodes); the arenas
        themselves are not compared row by row -- only through the states that reach them (TREE_LINKS_ERASED)."""
        return {name: ({"arena": "compared through the states whose roots reach it"}
                       if name in ("state_nodes", "call_state_nodes") else
                       self.row(item, "call_state_nodes" if name in self.CALL_ARENA else "state_nodes"))
                for name, item in self.ssa.items()}


def _resolve_ssa_objects(value):
    if _is_ssa(value):
        return _Ssa(value).top()
    if isinstance(value, dict):
        return {name: _resolve_ssa_objects(item) for name, item in value.items()}
    if isinstance(value, list):
        return [_resolve_ssa_objects(item) for item in value]
    return value


def _node_coordinate(nodes, index):
    if not isinstance(index, int) or not 0 <= index < len(nodes):
        raise Ambiguous(f"dependency node {index} out of range")
    return {"node": short(nodes[index])}


STRUCTURAL = "dependency nodes still carrying an identity hash: their own form refined twice by their edges"


def _resolve_graph(normalized):
    graph = normalized.get("dependencies")
    if not isinstance(graph, dict) or "nodes" not in graph:
        return normalized
    ssa = _Ssa(normalized["memory_ssa"]) if _is_ssa(normalized.get("memory_ssa")) else None
    # a local-read effect node's coordinate is the read it stands for (effect_nodes[i] <-> plan.reads[i])
    local_reads = (normalized.get("memory_graph") or {}).get("local_reads") or None
    read_nodes, resolved_reads = {}, None
    if local_reads and ssa is not None:
        resolved_reads = [ssa.row(read) for read in local_reads["plan"]["reads"]]
        if len(local_reads["effect_nodes"]) != len(resolved_reads):
            raise Ambiguous("local-read effect nodes and plan reads do not pair")
        for index, node in enumerate(local_reads["effect_nodes"]):
            read_nodes[node] = short(resolved_reads[index])

    # guarded image reads: candidate_nodes[k] <-> the k-th candidate of plan.reads (flattened); every node sharing
    # that candidate node's semantic_identity (its alternative / source nodes) takes the candidate as coordinate
    image = (normalized.get("memory_graph") or {}).get("image_reads") or None
    identities, resolved_image = {}, None
    if image and ssa is not None:
        resolved_image = [ssa.row(read) for read in image["plan"]["reads"]]
        flat = [({**read, "candidates": None}, candidate) for read in resolved_image
                for candidate in read.get("candidates") or ()]
        if len(flat) != len(image.get("candidate_nodes") or ()):
            raise Ambiguous("guarded image candidate nodes and plan candidates do not pair")
        for position, node_index in enumerate(image["candidate_nodes"]):
            identity = graph["nodes"][node_index].get("semantic_identity")
            coordinate = short(flat[position])
            if identity is not None and identities.setdefault(identity, coordinate) != coordinate:
                raise Ambiguous("one guarded image identity names two candidates")

    def node_form(node, index=None):
        """A node record with its key's definition index resolved and any remaining 64-hex content hash elided
        (a collision is caught below)."""
        key = node.get("key", "")
        identity = node.get("semantic_identity")
        if identity in identities:
            key = re.sub(r":(image-[a-z]+):[0-9a-f]+$", r":\1:" + identities[identity], key)
            node = {**node, "semantic_identity": identities[identity]}
        if index in read_nodes:
            key = re.sub(r":local-read:[0-9a-f]+$", ":local-read:" + read_nodes[index], key)
        match = NODE_KEY_INDEX.search(key)
        if match and ssa is not None:
            key = key[:match.start()] + ":definition:" + ssa.ref("definitions", int(match.group(1)))["to"]
        key = re.sub(r"(?<![A-Za-z]:)[0-9a-f]{40,64}", "<h>", key)
        return {**node, "key": key}

    nodes = [node_form(node, index) for index, node in enumerate(graph["nodes"])]
    # a node still carrying an identity hash (its key elided to <h>, or a raw semantic_identity): a structural
    # coordinate -- its form refined twice by the multiset of its edges (direction, payload, neighbour)
    pending = [index for index, node in enumerate(nodes)
               if "<h>" in node.get("key", "") or HEX64.fullmatch(str(node.get("semantic_identity") or ""))]
    if pending:
        current = [short({**node, "semantic_identity": None}) for node in nodes]
        incident: dict = {index: [] for index in pending}
        for source, target, payload in graph["edges"]:
            if source in incident:
                incident[source].append(("out", canonical(payload), target))
            if target in incident:
                incident[target].append(("in", canonical(payload), source))
        for _ in range(2):
            current = [current[index] if index not in incident else
                       short([current[index], sorted([direction, payload, current[other]]
                                                     for direction, payload, other in incident[index])])
                       for index in range(len(nodes))]
        nodes = [{**node, "key": re.sub(r"<h>", "", node.get("key", "")) + ":" + current[index],
                  "semantic_identity": current[index]} if index in incident else node
                 for index, node in enumerate(nodes)]
    coordinates = [canonical(node) for node in nodes]
    if len(set(coordinates)) != len(coordinates):
        raise Ambiguous("two dependency nodes share one coordinate")
    result = dict(normalized)
    result["dependencies"] = {
        "nodes": nodes,
        "edges": [[_node_coordinate(nodes, source), _node_coordinate(nodes, target), payload]
                  for source, target, payload in graph["edges"]],
    }
    cfg = normalized.get("cfg")
    if isinstance(cfg, dict) and "nodes" in cfg:
        result["cfg"] = {"nodes": cfg["nodes"], "edges": [
            [{"cfg": short(cfg["nodes"][source])}, {"cfg": short(cfg["nodes"][target])}, payload]
            for source, target, payload in cfg["edges"]]}

    aligned = {"definition_nodes": "definitions", "action_nodes": "actions"}   # (positional: entry i <-> row i)

    def nodes_in(value):
        if isinstance(value, dict):
            out = {}
            for name, item in value.items():
                if name in aligned and isinstance(item, list) and ssa is not None:
                    rows = ssa.ssa.get(aligned[name]) or ()
                    if len(rows) != len(item):
                        raise Ambiguous(f"{name} does not pair with {aligned[name]}")
                    out[name] = [{"row": short(ssa.resolve(aligned[name], index)), **_node_coordinate(nodes, entry)}
                                 for index, entry in enumerate(item)]
                elif name in NODE_REFERENCE_LISTS and isinstance(item, list):
                    out[name] = [_node_coordinate(nodes, entry) for entry in item]
                elif name == "entry_bindings" and isinstance(item, list):
                    out[name] = [[_node_coordinate(nodes, entry[0]), *entry[1:]] for entry in item]
                else:
                    out[name] = nodes_in(item)
            return out
        if isinstance(value, list):
            return [nodes_in(item) for item in value]
        return value

    if resolved_image is not None:
        memory_graph = dict(result["memory_graph"])
        memory_graph["image_reads"] = {**image, "plan": {**image["plan"], "reads": resolved_image}}
        result["memory_graph"] = memory_graph
    if resolved_reads is not None:
        memory_graph = dict(result["memory_graph"])
        memory_graph["local_reads"] = {**local_reads, "plan": {**local_reads["plan"], "reads": resolved_reads}}
        result["memory_graph"] = memory_graph
    return {name: (item if name in ("dependencies", "cfg") else nodes_in(item)) for name, item in result.items()}


def _resolve_summary(summary, normalized):
    if not isinstance(summary, dict) or normalized is None:
        return summary
    ssa = _Ssa(normalized["memory_ssa"])

    def runs_in(value):
        if isinstance(value, dict):
            out = {}
            for name, item in value.items():
                if name == "runs" and isinstance(item, list):
                    out[name] = [{**run, "definitions": [ssa.ref("definitions", index)
                                                        for index in run.get("definitions") or ()]}
                                 if isinstance(run, dict) and "definitions" in run else runs_in(run)
                                 for run in item]
                else:
                    out[name] = runs_in(item)
            return out
        if isinstance(value, list):
            return [runs_in(item) for item in value]
        return value

    return runs_in(summary)


# -- 3. collections ---------------------------------------------------------------------------------------------------

def _multisets(value):
    if isinstance(value, dict):
        out = {}
        for name, item in value.items():
            if name == "address_objects" and isinstance(item, list):
                # an expression's terms are ordered by atom hash: a sum, compared as a multiset of (atom, coefficient)
                item = [[entry[0], [sorted(entry[1][0], key=canonical), *entry[1][1:]]]
                        if isinstance(entry, list) and len(entry) == 2 and isinstance(entry[1], list) else entry
                        for entry in item]
            item = _multisets(item)
            if name in COLLECTIONS and isinstance(item, list):
                item = sorted(item, key=canonical)
            elif name in ("set", "items") and isinstance(item, list):
                item = sorted(item, key=canonical)
            out[name] = item
        return out
    if isinstance(value, list):
        return [_multisets(item) for item in value]
    return value


def project_document(document) -> dict:
    """The projected document: sections identity-free, digests recomputed."""
    tokens = build_tokens(document)
    normalized = {key: rename(value, tokens) for key, value in _function_sections(document).items()}
    sections = {}
    for name, data in document["sections"].items():
        match = re.fullmatch(r"function:(.+):(normalized(?:\[\d+\])?|summary|analyzed)", name)
        value = rename(data, tokens)   # (identities first: referents are hashed identity-free)
        if match and match.group(2).startswith("normalized"):
            value = _resolve_graph(_resolve_ssa_objects(value))
        elif match and match.group(2) == "summary":
            value = _resolve_summary(value, normalized.get(match.group(1)))
        else:
            value = _resolve_ssa_objects(value)
        sections[name] = _multisets(value)
    digests = {name: hashlib.sha256(canonical(data).encode()).hexdigest() for name, data in sections.items()}
    return {"meta": document["meta"], "complete": True, "sections": sections, "digests": digests}
