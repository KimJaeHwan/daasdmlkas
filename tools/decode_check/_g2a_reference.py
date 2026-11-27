"""Frozen 798b903 verdict functions (vote_form, _compare_present_fields, row_verdicts), copied verbatim.

The reference for TDO_V2_G2A_COST_CROSSCHECK=1 (design_tbr_g2a_cost r1 E1): with the switch, the collector keeps the
ballots and asserts per row that these functions, fed the original votes, give the same units (or the same
exception) as common_facts fed the vote summaries. Remove once the -5 compaction is accepted.
"""

from common_facts import *  # noqa: F401,F403  (the unchanged helpers: unit, member, schema, code, ...)
from common_facts import MISS, compare, common, independent_length, mnemonic  # noqa: F401


def vote_form(vs, isa):
    if vs and all(v.status == "invalid" for v in vs):
        if (isa.get("facts", {}).get("F1", {}).get("class") == "invalid_encoding"
                and "F1" not in isa.get("unobserved", {})):
            return "invalid", False
        return MISS
    if any(v.status != "ok" for v in vs):
        return MISS

    def form(v):
        if v.flow == "ud":
            return ("ud2", False) if v.mnemonic.lower() == "ud2" else MISS
        if v.flow not in ("none", "call_near", "jmp_near", "ret_near", "jcc", "xbegin", "int_n",
                          "int3", "int1", "syscall", "sysenter", "hlt", "iret", "ret_far", "call_far", "jmp_far"):
            return MISS
        return v.flow, bool(v.indirect) if v.flow in ("jmp_near", "call_near") else False

    return common(map(form, vs))

def _compare_present_fields(r, vs, index, isa, vendor=None):
    t, m = r["transfer"], member(r, vendor)
    f = dict(space=r["space"], address=int(r["offset"], 16))
    prefix = f"vendor_views.{vendor}." if vendor else ""
    stem = "" if vendor else "transfer."
    units = []

    def add(path, state, edge=None, op=None):
        units.append(unit(prefix + path, state, edge, op))

    def cmp(path, actual, want, edge=None):
        state = code(actual, want)
        add(path, state, edge)
        return state

    def excluded(path, x):
        add(path, "n" if x is None or x is MISS or unknown(x) else "x")

    form = vote_form(vs, isa)
    path = "bytes" if vendor else "bytes.range"
    if form is MISS:
        for p in ("length", path, stem + "edges", stem + "link_write", stem + "target_value"):
            add(p, "?")
        if not vendor:
            for p in ("kind", "exception_basis", "condition", "target_auth", "op_keys"):
                add(stem + p, "?")
        return units
    length = independent_length(vs)
    cmp("length", m.get("length") if m.get("length") is not None else MISS, length)
    cmp(path, m.get("bytes", MISS), interval(f, length) if length is not MISS else MISS)
    flow = form[0]
    kind, keys = schema(form)
    if not vendor:
        cmp("transfer.kind", t.get("kind", MISS), kind)
        basis = {"ud2": "defined_ud", "invalid": "invalid_encoding"}.get(flow)
        if basis:
            cmp("transfer.exception_basis", t.get("exception_basis", MISS), basis)
        else:
            excluded("transfer.exception_basis", t.get("exception_basis"))

    edges = m.get("edges", MISS)
    path = stem + "edges"
    groups = defaultdict(list)
    if isinstance(edges, list):
        for e in edges:
            groups[triple(e)].append(e)
    if not keys and not groups:
        cmp(path, edges, [])
    for k in dict.fromkeys([*keys, *groups]):
        group = groups[k]
        if k not in keys or len(group) != 1:
            add(path, "u" if unknown(edges) else "x", k)
            continue
        e = group[0]
        if unknown(e):
            add(path, "u" if set(e) == set(EC) | {"unobserved"} else "x", k)
            continue
        add(path, "c", k)
        expected = MISS
        source = k[1]
        if source in ("computed", "os") or source == "os_return" and flow == "sysenter":
            expected = None
        elif source == "sequential" and length is not MISS:
            expected = next_addr(f, length)
        elif source == "encoded_target":
            dest = common(compare.voter_values(v, f["address"]).get("a5") if v.target_derivation == "decoder"
                          else MISS for v in vs)
            if type(dest) is int:
                expected = addr(f["space"], dest)
        elif source == "os_return" and length is not MISS and flow in ("int_n", "int3", "int1", "syscall"):
            f3 = isa.get("facts", {}).get("F3", {})
            if "F3" not in isa.get("unobserved", {}) and f3.get("flow") == flow:
                expected = next_addr(f, length)
        to = e.get("to", MISS)
        if flow == "hlt" and k == SAVED:
            state = "u" if to is None or to is MISS or unknown(to) else "x"
            add(path + ".to", state, k)
        else:
            state = cmp(path + ".to", to, expected, k)
        land = e.get("lands_on", {})
        observed = index.landing(expected) if state == "c" else {}
        cls = observed.get("class", MISS)
        cmp(path + ".lands_on.class", sub(land, "class"), MISS if cls == "unclassified" else cls, k)
        if expected is not None:
            for field in ("starts", "inside", "mapping", "import"):
                want = observed.get(field, MISS)
                cmp(path + ".lands_on." + field, sub(land, field), MISS if unknown(want) else want, k)

    if not vendor:
        condition = t.get("condition", MISS)
        cp = "transfer.condition"
        if flow != "jcc":
            excluded(cp, condition)
        elif not isinstance(condition, dict) or unknown(condition):
            add(cp, "u" if condition is MISS or unknown(condition) else "x")
        else:
            add(cp, "c")
            cmp(cp + ".taken_when", sub(condition, "taken_when"), "true")
            test = sub(condition, "test")
            name = common(mnemonic(v) for v in vs)
            if name in CC:
                actual = test if not isinstance(test, dict) or unknown(test) else test.get("flags", False)
                cmp(cp + ".test", actual, name)
                add(cp + ".test.inputs", "u")
            elif name in ("jrcxz", "jecxz", "loop"):
                width = common(v.address_bits for v in vs)
                key = "nonzero" if name == "loop" else "zero"
                val = sub(test, key)
                if val is MISS and isinstance(test, dict) and not unknown(test):
                    add(cp + ".test", "x")
                elif width not in (32, 64) or val is MISS or unknown(val):
                    add(cp + ".test", "u")
                else:
                    original = val
                    if key == "nonzero":
                        pair = val.get("sub", []) if isinstance(val, dict) else []
                        original = pair[0] if len(pair) == 2 and pair[1] == {"constant": "1", "width": width} else {}
                    ok = (sub(original, "pre_register", "offset") == lifting.RCX
                          and sub(original, "width") == width and sub(val, "width") == width)
                    # Decoder evidence supplies predicate shape and width. Coordinate identity is separate.
                    add(cp + ".test", "c" if ok else "x")
                    add(cp + ".test.inputs", "u")
            elif name in ("loope", "loopne") and isinstance(test, dict) and not unknown(test):
                add(cp + ".test", "u" if "op_output" in test else "x")
            else:
                add(cp + ".test", "u")
        excluded("transfer.target_auth", t.get("target_auth"))
        for name, refs in t["op_keys"].items():
            p = "transfer.op_keys." + name
            if name in ("encoding_only", "entry_ordinal"):
                add(p, "u")
            else:
                for op in refs if isinstance(refs, list) else [refs] if refs else []:
                    add(p, "u", op=op)

    target = m.get("target_value", MISS)
    if kind == "indirect":
        add(stem + "target_value", "u")
    else:
        excluded(stem + "target_value", target)
    link = m.get("link_write", MISS)
    lp = stem + "link_write"
    if flow != "call_near":
        excluded(lp, link)
    elif not isinstance(link, dict) or unknown(link):
        add(lp, "x" if link is None else "u")
    else:
        a7 = [compare.voter_values(v, f["address"])["a7"] for v in vs]
        width, bits = (common(tup[j] for tup in a7) for j in (0, 1))
        size = common(compare.voter_values(v, f["address"])["a11b"] for v in vs)
        cmp(lp + ".value.width", sub(link, "value", "width"),
            width if size is not MISS and width == 8 * size else MISS)
        cmp(lp + ".value.bits", sub(link, "value", "bits"),
            format(bits, "x") if bits is not MISS and width is not MISS else MISS)
        cmp(lp + ".continuation", sub(link, "continuation"), next_addr(f, length) if length is not MISS else MISS)
        loc = sub(link, "location")
        cmp(lp + ".location", set(loc) if isinstance(loc, dict) and not unknown(loc) else MISS, {"memory"})
        cmp(lp + ".location.memory.relative_to", sub(loc, "memory", "relative_to"), "pre_sp")
        delta = -size if type(size) is int else MISS
        cmp(lp + ".location.memory.slot_offset", sub(loc, "memory", "slot_offset"), delta)
        cmp(lp + ".sp_delta", sub(link, "sp_delta"), delta)
        for field in ("location.memory.base", "location.memory.space", "relocation", "derivation"):
            add(lp + "." + field, "u")
    return units

def row_verdicts(r, vs, index, isa, vendor=None):
    form = vote_form(vs, isa)
    # The current F3 records decoded flow. It has no execution-path observation.
    structural_isa = dict(
        isa, unobserved=dict(isa.get("unobserved", {}), F3="execution path unknown")
    )
    units = _compare_present_fields(r, vs, index, structural_isa, vendor)
    m = member(r, vendor)
    prefix = f"vendor_views.{vendor}." if vendor else "transfer."
    existing = {u["path"] for u in units}

    def fill(root, fields, state):
        for field in fields:
            path = prefix + root + "." + field
            if path not in existing:
                units.append(unit(path, state))
                existing.add(path)

    link = m.get("link_write", MISS)
    pred = r["transfer"].get("condition", MISS)
    if form is MISS:
        fill("link_write", LINK_FIELDS, "?")
        if not vendor:
            fill("condition", PRED_FIELDS, "?")
        return units

    t = r["transfer"]
    flow = form[0]
    if (not vendor and t.get("kind") == "unknown" and t.get("edges") == []
            and schema(form)[0] != "unknown"):
        absent = {"transfer.kind"}
        if flow == "call_near" and link is None:
            absent.add("transfer.link_write")
        if flow == "jcc" and pred is None:
            absent.add("transfer.condition")
        for u in units:
            missing_role = u["path"] == "transfer.edges" and "edge" in u
            if u["code"] == "x" and (u["path"] in absent or missing_role):
                u["code"] = "u"

    if flow == "call_near":
        fill("link_write", LINK_FIELDS, "u")
    elif link is MISS or link is None or unknown(link):
        fill("link_write", LINK_FIELDS, "n")

    if not vendor:
        if flow == "jcc":
            if sub(pred, "test", "op_output") is not MISS:
                for u in units:
                    if u["path"] == prefix + "condition.test":
                        u["code"] = "u"
            fill("condition", PRED_FIELDS, "u")
        elif pred is MISS or pred is None or unknown(pred):
            fill("condition", PRED_FIELDS, "n")

    es = m.get("edges")
    if isinstance(es, list):
        for e in es:
            if unknown(e) or e.get("to", MISS) is not None:
                continue
            land = e.get("lands_on", MISS)
            if isinstance(land, dict) and not unknown(land) and set(land) - {"class"}:
                key = triple(e)
                # Subfield comparisons exist only for a unique matched ordinary role.
                if any(u["path"] == prefix + "edges.lands_on.class"
                       and u.get("edge") == dict(zip(EC, key)) for u in units):
                    units.append(unit(prefix + "edges.lands_on", "x", key))
    return units
