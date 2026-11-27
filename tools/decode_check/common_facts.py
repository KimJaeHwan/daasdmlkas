"""TBR G2a: x86 common facts derived from a Ghidra Bundle, their G1 verdicts (-4) and the parity with the engine's
call relations (design .census6/design_tbr_g2_common_facts_r5.md, closed 2026-11-27).

- ``derive_row``: a claim (``source: "derived"``) per row, read from Ghidra's p-code through the lift table: the
  form (s3.1), edges (s3.2 / s3.3), condition (s3.4), target_value (s3.5), link_write (s3.6), op references (s3.8),
  lands_on (s4) and the byte premise (s2). TBR never states a return, an OS resumption or a premise default.
- ``row_verdicts``: G1 evidence -4 per row, from the voters (s8). Only what an independent comparison supports is
  confirmed; the rest stays unobserved.
- ``parity``: the facts' link claims against the engine's ``call_relations`` (s3.8 / G2a): missing / extra / field
  differences, each missing relation with the recognizer check that failed.

Pure functions of plain facts (Rust-reproducible); the engine objects enter only through ``decode_check.collect``.
"""

from __future__ import annotations

import hashlib
import json

import lifting

SCHEMA = "tbr-common-facts-1"
VERDICT_SCHEMA = "tbr-common-facts-verdicts-1"
RULE_VERSION = "g2a-1"
VIEW = "0"                      # Ghidra exports one decode view per row
PREMISE = "image-code-unmodified-at-runtime"
WHEN_ORDER = ("always", "taken", "not_taken", "normal_entry", "abort", "trap", "trap_return")
SOURCE_ORDER = ("sequential", "encoded_target", "computed", "os", "os_return")
REQUIRES_ORDER = (None, "os-contract", "normal-transaction-start", "outermost-transaction", "nested-transaction")
# the -4 field order of the per-row code string (one character per field: c confirmed, x contradicted,
# u unobserved, n not applicable)
FIELDS = ("kind", "edges", "to.sequential", "to.encoded_target", "to.computed_os", "to.os_return", "condition",
          "link.value", "link.continuation", "link.slot", "link.location_kind", "link.register", "link.space",
          "link.relocation", "target_value", "op_keys", "lands_on")
U = lambda reason: {"unobserved": reason}   # noqa: E731


def _addr(space, offset):
    return {"space": space, "offset": f"{offset:x}"}


def _reg(varnode):
    return {"space": varnode["space"], "offset": varnode["offset"], "size": varnode["size"]}


def row_id(facts: dict) -> str:
    return f"{facts['space']:x}:{facts['address']:x}:{facts['length'] if facts['length'] is not None else 'u'}:{VIEW}"


def _edge(when, source, to, requires=None):
    return {"when": when, "source": source, "requires": requires, "to": to}


def _edge_key(edge):
    return (WHEN_ORDER.index(edge["when"]), SOURCE_ORDER.index(edge["source"]), REQUIRES_ORDER.index(edge["requires"]))


# -- value_ref from the row's own p-code (s3.5) ------------------------------------------------------------------

def _value_ref(ops, varnode, upto, row_ref, depth=0):
    """The pre-state expression of ``varnode`` as used before op ``upto``: a register not redefined earlier in the
    row is a pre-state leaf; a definition is followed through COPY / INT_ADD / INT_SUB / INT_MULT / INT_ZEXT /
    INT_SEXT / LOAD; a LOAD preceded by any STORE in the row may alias (unobserved)."""
    if varnode is None or depth > 16:
        return U("expression too deep or missing")
    if varnode["kind"] == "CONSTANT":
        return {"constant": f"{varnode['offset']:x}", "width": varnode["size"] * 8}
    if varnode["kind"] == "ADDRESS":
        return {"constant": f"{varnode['offset']:x}", "width": varnode["size"] * 8}
    for index in range(upto - 1, -1, -1):
        op = ops[index]
        if op["output"] != varnode:
            if op["output"] is not None and varnode["kind"] in ("REGISTER", "UNIQUE") \
                    and op["output"]["space"] == varnode["space"] \
                    and op["output"]["offset"] < varnode["offset"] + varnode["size"] \
                    and varnode["offset"] < op["output"]["offset"] + op["output"]["size"]:
                return U("partial overlapping redefinition in the row")
            continue
        width = varnode["size"] * 8
        name, inputs = op["opcode"], op["inputs"]
        if name == "COPY" and len(inputs) == 1:
            return _value_ref(ops, inputs[0], index, row_ref, depth + 1)
        if name in ("INT_ADD", "INT_SUB", "INT_MULT") and len(inputs) == 2:
            key = {"INT_ADD": "add", "INT_SUB": "sub", "INT_MULT": "mul"}[name]
            return {key: [_value_ref(ops, inputs[0], index, row_ref, depth + 1),
                          _value_ref(ops, inputs[1], index, row_ref, depth + 1)], "width": width}
        if name in ("INT_ZEXT", "INT_SEXT") and len(inputs) == 1:
            return {"zext" if name == "INT_ZEXT" else "sext": _value_ref(ops, inputs[0], index, row_ref, depth + 1),
                    "width": width}
        if name == "LOAD" and len(inputs) == 2 and inputs[0]["kind"] == "CONSTANT":
            if any(prior["opcode"] == "STORE" for prior in ops[:index]):
                return U("intra-row store may alias")
            return {"memory": {"space": inputs[0]["offset"], "address": _value_ref(ops, inputs[1], index, row_ref,
                                                                                 depth + 1),
                               "size": varnode["size"], "segment_base": None}}
        return {"op_output": {"row": row_ref, "ordinal": index, "opcode": name}}
    if varnode["kind"] == "REGISTER":
        return {"pre_register": _reg(varnode), "width": varnode["size"] * 8}
    return U(f"{varnode['kind']} used before any definition in the row")


def _chain(ops, varnode, upto):
    """Ordinals of the ops a value depends on (for op_keys.target)."""
    out, todo = set(), [(varnode, upto)]
    while todo:
        item, limit = todo.pop()
        if item is None or item["kind"] in ("CONSTANT", "ADDRESS"):
            continue
        for index in range(limit - 1, -1, -1):
            if ops[index]["output"] == item:
                if index not in out:
                    out.add(index)
                    todo.extend((inp, index) for inp in ops[index]["inputs"])
                break
    return sorted(out)


# -- the derived row (claims) ------------------------------------------------------------------------------------

FORM = {   # lift pattern -> kind (s3.1 applied to the producer's own decode, here Ghidra's p-code)
    "plain": "none", "internal": "none", "cmov": "none", "rep": "none",
    "jcc": "conditional", "jmp": "direct", "call": "direct", "call $+5": "direct",
    "call indirect": "indirect", "jmp indirect": "indirect", "ret": "indirect",
    "interrupt": "trap", "interrupt-return": "trap", "syscall": "trap", "fault": "trap",
}


def derive_row(facts: dict, lift, observation: str, rows_index: dict) -> dict:
    """The derived claim of one row. ``rows_index`` = {(space, address): length} of the observation's rows."""
    ops = facts["ops"]
    space, start, length = facts["space"], facts["address"], facts["length"]
    rid = row_id(facts)
    row_ref = {"id": rid, "observation": observation}
    nxt = None if length is None else start + length
    pattern = None if lift is None else lift.pattern
    kind = FORM.get(pattern, "unknown")
    edges, transfer_ordinal, target_value, condition, link = [], None, None, None, None
    target_ops, transient, sp_adjust, link_ops = [], [], [], []
    seq = U("no exported length") if nxt is None else _addr(space, nxt)
    flows = [i for i, op in enumerate(ops) if op["opcode"] in lifting.FLOW_OPS and i not in (lift.skipped if lift else ())]
    last = flows[-1] if flows else None
    if kind == "none":
        edges = [_edge("always", "sequential", seq)]
    elif kind == "conditional":
        target = ops[last]["inputs"][0]
        edges = [_edge("taken", "encoded_target", _addr(space, target["offset"])),
                 _edge("not_taken", "sequential", seq)]
        transfer_ordinal = last
        cond = ops[last]["inputs"][1] if len(ops[last]["inputs"]) > 1 else None
        value = _value_ref(ops, cond, last, row_ref)
        condition = {"test": value if "unobserved" in value else
                     ({"op_output": value["op_output"]} if "op_output" in value else {"nonzero": value}),
                     "taken_when": "true"}
    elif kind == "direct":
        target = ops[last]["inputs"][0]
        edges = [_edge("always", "encoded_target", _addr(space, target["offset"]))]
        transfer_ordinal = last
    elif kind == "indirect":
        edges = [_edge("always", "computed", None)]
        transfer_ordinal = last
        if pattern == "ret":
            target_value = _value_ref(ops, ops[last]["inputs"][0], last, row_ref)
        else:
            # (the target is read in the pre-state, before the push: follow it from the transfer's input)
            target_value = _value_ref(ops, ops[last]["inputs"][0], last, row_ref)
        target_ops = _chain(ops, ops[last]["inputs"][0], last)
    elif kind == "trap":
        edges = [_edge("trap", "os", None)]
        transfer_ordinal = last
        if pattern in ("interrupt", "interrupt-return", "syscall"):
            edges.append(_edge("trap_return", "os_return", seq, "os-contract"))
    if pattern in ("call", "call $+5", "call indirect") and last is not None and last >= 2:
        sub_op, store_op = ops[last - 2], ops[last - 1]
        width = store_op["inputs"][2]["size"] * 8
        value = store_op["inputs"][2]
        fallthrough = None if facts["fallthrough"] is None else _addr(facts.get("fallthrough_space", space),
                                                                       facts["fallthrough"])
        link = {"location": {"memory": {"space": store_op["inputs"][0]["offset"], "base": _reg(sub_op["inputs"][0]),
                                        "relative_to": "pre_sp", "slot_offset": -(width // 8)}},
                "sp_delta": -sub_op["inputs"][1]["offset"],
                "value": {"bits": f"{value['offset']:x}", "width": width} if value["kind"] == "CONSTANT"
                else U("stored value not a constant"),
                "continuation": fallthrough if fallthrough is not None else U("no Ghidra fallthrough"),
                "relocation": "instruction_relative", "derivation": "isa_next_ip"}
        transient, sp_adjust, link_ops = [last - 2, last - 1], [last - 2], [last - 1]
        if pattern == "call $+5":
            edges = [_edge("always", "encoded_target", _addr(space, ops[last]["inputs"][0]["offset"]))]

    def ref(ordinal):
        return {"row": row_ref, "ordinal": ordinal, "opcode": ops[ordinal]["opcode"]}

    for edge in edges:
        to = edge["to"]
        if to is None:
            edge["lands_on"] = {"class": "unresolved"}
        elif "unobserved" in to:
            edge["lands_on"] = U("address unknown")
        else:
            edge["lands_on"] = _lands_on(int(to["offset"], 16), to["space"], rows_index, observation)
    edges.sort(key=_edge_key)
    return {"id": rid, "space": space, "offset": f"{start:x}", "length": length, "view": VIEW,
            "observation": observation,
            "transfer": {"kind": kind, "edges": edges, "condition": condition,
                         "target_value": target_value, "target_auth": None, "link_write": link,
                         "hint": {"CALL": "call", "CALLIND": "call", "RETURN": "return", "BRANCH": "jump",
                                  "BRANCHIND": "jump", "CBRANCH": "jump"}.get(ops[last]["opcode"]) if last is not None
                         else None,
                         "op_keys": {"transfer": None if transfer_ordinal is None else ref(transfer_ordinal),
                                     "target": [ref(i) for i in target_ops],
                                     "condition": [], "auth": [], "link": [ref(i) for i in link_ops],
                                     "sp_adjust": [ref(i) for i in sp_adjust],
                                     "setup": [ref(i) for i in range(transfer_ordinal)] if transfer_ordinal else [],
                                     "transient": [ref(i) for i in transient], "persistent": [],
                                     "entry_ordinal": transfer_ordinal, "encoding_only": []}},
            "bytes": {"range": [f"{start:x}", f"{nxt:x}"] if nxt is not None else U("no exported length"),
                      "holds_if": PREMISE},
            "isa": [], "vendor_views": None}


def _lands_on(address, space, rows_index, observation):
    starts, inside = [], []
    for (row_space, row_start), length in rows_index.items():
        if row_space != space or length is None:
            continue
        if row_start == address:
            starts.append({"id": f"{row_space:x}:{row_start:x}:{length}:{VIEW}", "observation": observation})
        elif row_start < address < row_start + length:
            inside.append({"id": f"{row_space:x}:{row_start:x}:{length}:{VIEW}", "observation": observation})
    # (the search covers this observation's rows only: an empty list is not a whole-program zero, so the
    #  class is decided only by a positive match; mapping / import are not wired in G2a)
    cls = "row_start" if starts else ("mid_row" if inside else "unclassified")
    return {"starts": starts if starts or inside else U("searched this observation's rows only"),
            "inside": inside if starts or inside else U("searched this observation's rows only"),
            "mapping": U("mapping not wired in G2a"), "import": U("import roles not wired in G2a"), "class": cls}


def document(bundle: dict, producer: dict, program: dict, rows: list) -> dict:
    rows = sorted(rows, key=lambda row: (row["id"], row["observation"]))
    return {"schema": SCHEMA, "source": "derived", "bundle": bundle, "producer": producer, "program": program,
            "rows": rows}


def canonical(document_: dict) -> bytes:
    return json.dumps(document_, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(document_: dict) -> str:
    return hashlib.sha256(canonical(document_)).hexdigest()


# -- -4 verdicts (s8) --------------------------------------------------------------------------------------------

VOTER_FORM = {"none": "none", "jcc": "conditional", "jmp_near": None, "call_near": None, "ret_near": "indirect",
              "syscall": "trap", "sysenter": "trap", "int_n": "trap", "int3": "trap", "int1": "trap", "hlt": "trap",
              "ud": "trap"}


def _consensus(ballot):
    voters = list(ballot["intel"]) + list(ballot["amd"])
    if any(v.status != "ok" for v in voters):
        statuses = {v.status for v in voters}
        return ("invalid", None) if statuses == {"invalid"} else (None, None)
    flows = {(v.flow, bool(v.indirect)) for v in voters}
    lengths = {v.length for v in voters}
    if len(flows) != 1 or len(lengths) != 1:
        return None, None
    return flows.pop(), lengths.pop()


def _expected(form):
    flow, indirect = form
    if flow in ("jmp_near", "call_near"):
        kind = "indirect" if indirect else "direct"
    else:
        kind = VOTER_FORM.get(flow)
    if kind is None:
        return None, None
    triples = {
        "none": [("always", "sequential", None)],
        "conditional": [("taken", "encoded_target", None), ("not_taken", "sequential", None)],
        "direct": [("always", "encoded_target", None)],
        "indirect": [("always", "computed", None)],
        "trap": [("trap", "os", None)] + ([] if flow == "ud" else [("trap_return", "os_return", "os-contract")]),
    }[kind]
    return kind, triples


def _unknown(value) -> bool:
    """A claim the producer marked unobserved: its verdict is unobserved, never contradicted."""
    return isinstance(value, dict) and "unobserved" in value


def row_verdicts(row: dict, ballot: dict | None, result: dict | None) -> str:
    """The -4 code string over FIELDS for one derived row (s8): c / x / u / n."""
    codes = dict.fromkeys(FIELDS, "u")
    transfer = row["transfer"]
    if ballot is None or result is None or not result.get("attributes"):
        return "".join(codes[f] for f in FIELDS)            # never compared: unobserved throughout
    form, length = _consensus(ballot)
    if form is None:
        return "".join(codes[f] for f in FIELDS)
    if form == "invalid":
        codes["kind"] = "c" if transfer["kind"] == "trap" else "x"
        return "".join(codes[f] for f in FIELDS)
    kind, triples = _expected(form)
    if kind is None:
        return "".join(codes[f] for f in FIELDS)
    codes["kind"] = "c" if transfer["kind"] == kind else "x"
    claimed = sorted((e["when"], e["source"], e["requires"]) for e in transfer["edges"])
    codes["edges"] = "c" if claimed == sorted(triples) else "x"
    start = int(row["offset"], 16)
    by_source = {e["source"]: e for e in transfer["edges"]}
    sources = {t[1] for t in triples}
    codes["to.sequential"] = "n"
    if "sequential" in sources:
        edge = by_source.get("sequential")
        expected = _addr(row["space"], start + length)
        codes["to.sequential"] = "u" if edge is None or _unknown(edge["to"]) else ("c" if edge["to"] == expected
                                                                                 else "x")
    codes["to.encoded_target"] = "u" if "encoded_target" in sources else "n"   # (XED computed: unobserved today)
    if sources & {"computed", "os"}:
        nulls = [by_source[s]["to"] is None for s in ("computed", "os") if s in by_source]
        codes["to.computed_os"] = "c" if nulls and all(nulls) else "x"
    else:
        codes["to.computed_os"] = "n"
    if "os_return" in sources:
        edge = by_source.get("os_return")
        if form[0] in ("syscall", "int_n", "int3", "int1"):
            codes["to.os_return"] = "u" if edge is None or _unknown(edge["to"]) else (
                "c" if edge["to"] == _addr(row["space"], start + length) else "x")
        elif form[0] == "sysenter" or form[0] == "hlt":
            codes["to.os_return"] = "u" if edge is None else ("c" if edge["to"] is None else "x")
    else:
        codes["to.os_return"] = "n"
    codes["condition"] = "u" if kind == "conditional" else "n"      # (opaque test: no independent comparison)
    link = transfer["link_write"]
    is_call = form[0] == "call_near"
    if not is_call:
        for name in ("link.value", "link.continuation", "link.slot", "link.location_kind", "link.register",
                     "link.space", "link.relocation"):
            codes[name] = "x" if link is not None else "n"
    elif link is None:
        for name in ("link.value", "link.continuation", "link.slot", "link.location_kind"):
            codes[name] = "x"
    else:
        a7 = result["attributes"].get("a7", {})
        a11b = result["attributes"].get("a11b", {})
        value = link["value"]
        if a7.get("state") == "applied" and "unobserved" not in value:
            width, stored = a7["value"]
            codes["link.value"] = "c" if (value["width"], int(value["bits"], 16)) == (width, stored) else "x"
        elif a7.get("state") == "unrecognized":
            codes["link.value"] = "x"
        cont = link["continuation"]
        if "unobserved" not in cont:
            codes["link.continuation"] = "c" if cont == _addr(row["space"], start + length) else "x"
        if a11b.get("state") == "applied":
            size = a11b["value"]
            memory = link["location"].get("memory", {})
            codes["link.slot"] = "c" if memory.get("slot_offset") == -size and link["sp_delta"] == -size else "x"
        codes["link.location_kind"] = "c" if "memory" in link["location"] else "x"
    codes["target_value"] = "u" if kind == "indirect" else ("x" if transfer["target_value"] is not None else "n")
    codes["lands_on"] = "u"
    return "".join(codes[f] for f in FIELDS)


def row_set_digest(rows: list) -> str:
    lines = "".join(f"{row['space']:x}:{row['offset']}:{row['length']}:{row['view']}:{row['observation']}\n"
                    for row in sorted(rows, key=lambda r: (r["id"], r["observation"])))
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def verdict_block(facts_digest: str, rows: list, codes: dict) -> dict:
    """The -4 section: binding (facts digest, rule version, row-set digest) and one code string per row."""
    return {"schema": VERDICT_SCHEMA, "rule_version": RULE_VERSION, "facts_sha256": facts_digest,
            "row_set_sha256": row_set_digest(rows), "fields": list(FIELDS),
            "rows": [{"id": row["id"], "observation": row["observation"], "codes": codes[(row["id"], row["observation"])]}
                     for row in sorted(rows, key=lambda r: (r["id"], r["observation"]))]}


# -- parity with the engine's call relations (G2a) -----------------------------------------------------------

def projection(row: dict, facts: dict, stack_register) -> tuple:
    """(relation fields or None, failed check) of a derived row's link claim, with the s3.8 push checks the
    engine applies (call_relations.py:61-108, observed_call_state.py:169-260) mirrored on the plain facts."""
    link = row["transfer"]["link_write"]
    if link is None or "memory" not in link["location"]:
        return None, None
    ops = facts["ops"]
    if facts["fallthrough"] is None:
        return None, "no-fallthrough"
    if stack_register is None:
        return None, "no-stack-register"
    calls = [i for i, op in enumerate(ops) if op["opcode"] in ("CALL", "CALLIND")]
    if len(calls) != 1:
        return None, "not-exactly-one-call"
    call = calls[0]
    if any(op["opcode"] in ("BRANCH", "CBRANCH", "BRANCHIND", "RETURN") for op in ops[:call]):
        return None, "transfer-before-call"
    subs = [i for i in range(call) if ops[i]["opcode"] == "INT_SUB" and ops[i]["output"] is not None
            and ops[i]["output"]["kind"] == "REGISTER" and ops[i]["inputs"][0] == ops[i]["output"]
            and ops[i]["inputs"][1]["kind"] == "CONSTANT"
            and ops[i]["inputs"][1]["offset"] == ops[i]["output"]["size"]]
    if len(subs) != 1:
        return None, "not-exactly-one-adjustment"
    sub = subs[0]
    between = ops[sub + 1:call]
    if len(between) != 1 or between[0]["opcode"] != "STORE":
        return None, "ops-between-adjust-and-call"
    sp = ops[sub]["output"]
    if (sp["space"], sp["offset"], sp["size"]) != (stack_register.space_id, stack_register.byte_offset,
                                                  stack_register.byte_size):
        return None, "adjustment-not-the-stack-register"
    for index, op in enumerate(ops):
        if index != sub and op["output"] is not None and op["output"]["space"] == sp["space"] \
                and op["output"]["offset"] < sp["offset"] + sp["size"] and sp["offset"] < op["output"]["offset"] + op["output"]["size"]:
            return None, "another-stack-register-write"
    store = between[0]
    value = store["inputs"][2]
    if value["kind"] != "CONSTANT" or value["offset"] != facts["fallthrough"] % (1 << (value["size"] * 8)) \
            or store["inputs"][1] != sp:
        return None, "store-shape"
    address = facts["address"]
    key = lambda i: f"{facts['space']:x}:{address:x}:{i}:{ops[i]['opcode']}"   # noqa: E731
    return {"call_key": key(call), "kind": "push", "delta": link["sp_delta"],
            "continuation": (facts.get("fallthrough_space", facts["space"]), facts["fallthrough"]),
            "relocation": "instruction-relative", "length": facts["fallthrough"] - address,
            "entry_ordinal": call, "setup_ops": tuple(key(i) for i in range(call)),
            "transient_ops": (key(sub), key(call - 1)),
            "link": (facts.get("fallthrough_space", facts["space"]), value["size"])}, None   # LinkSlot(fallthrough space)


def engine_fields(relation) -> dict:
    link = relation.link
    link_tuple = (link.space_id, link.size) if hasattr(link, "size") else (link.space_id, link.byte_offset,
                                                                            link.byte_size)
    return {"call_key": relation.call_key, "kind": relation.kind, "delta": relation.delta,
            "continuation": (relation.continuation.space_id, relation.continuation.byte_offset),
            "relocation": relation.relocation, "length": relation.length, "entry_ordinal": relation.entry_ordinal,
            "setup_ops": tuple(relation.setup_ops), "transient_ops": tuple(relation.transient_ops),
            "link": link_tuple}


def parity(function: dict, derived: dict, stack_register) -> dict:
    """{missing: [(row, reason)], extra: [call_key], differs: [(call_key, field)]} for one function.
    ``derived`` = {(space, address): derived row}; ``function["engine_relations"]`` = {call_key: fields}."""
    engine = function.get("engine_relations") or {}
    projected = {}
    missing, extra, differs = [], [], []
    for facts in function["rows"]:
        row = derived[(facts["space"], facts["address"])]
        fields, reason = projection(row, facts, stack_register)
        if fields is not None:
            projected[fields["call_key"]] = fields
        elif reason is not None:
            missing.append((row["id"], reason))
    for key, fields in projected.items():
        other = engine.get(key)
        if other is None:
            missing.append((key, "engine-has-no-relation"))
            continue
        for name, value in fields.items():
            if other.get(name) != value:
                differs.append((key, name))
    for key in engine:
        if key not in projected and engine[key]["kind"] == "push":
            extra.append(key)
    return {"missing": missing, "extra": extra, "differs": differs}
