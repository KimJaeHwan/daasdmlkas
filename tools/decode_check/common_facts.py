"""G2a common claims, field comparisons, and observation-local parity."""

from __future__ import annotations

from bisect import bisect_left
from collections import Counter, defaultdict
import hashlib
import json
from typing import NamedTuple

import compare
import decoders
import lifting


SCHEMA = "tbr-common-facts-1"
VERDICT_SCHEMA = "tbr-common-facts-verdicts-1"    # (-4 block, read only, with rule "g2a-3")
VERDICT_SCHEMA2 = "tbr-common-facts-verdicts-2"   # (-5 block: interned unit sets, design_tbr_g2a_cost r1 C3)
FACTS_RULE = "g2b-1"     # the facts file's producer.rule (g2b-1: program.code added, design_tbr_g2b r1 s1)
VERDICT_RULE = "g2a-4"   # the -5 block and the report header (design_tbr_g2a_cost r2 D3)
PREMISE = "image-code-unmodified-at-runtime"
VENDORS = ("intel", "amd")
CALLS = {"CALL", "CALLIND"}
BRANCHES = {"BRANCH", "CBRANCH", "BRANCHIND", "RETURN"}
EC = ("when", "source", "requires")
ORDERS = (
    ("always", "taken", "not_taken", "normal_entry", "abort", "trap", "trap_return"),
    ("sequential", "encoded_target", "computed", "os", "os_return"),
    (None, "os-contract", "normal-transaction-start", "outermost-transaction", "nested-transaction"),
)
SEQ = ("always", "sequential", None)
DIRECT = ("always", "encoded_target", None)
IND = ("always", "computed", None)
TAKEN = ("taken", "encoded_target", None)
NEXT = ("not_taken", "sequential", None)
OS = ("trap", "os", None)
SAVED = ("trap_return", "os_return", "os-contract")
NORMAL = ("normal_entry", "sequential", "normal-transaction-start")
OUTER = ("abort", "encoded_target", "outermost-transaction")
NESTED = ("abort", "computed", "nested-transaction")
MISS = object()


def U(reason):
    return {"unobserved": reason}


def unknown(x):
    return isinstance(x, dict) and "unobserved" in x


def canonical(x):
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(x):
    return hashlib.sha256(canonical(x)).hexdigest()


def addr(space, offset):
    return {"space": space, "offset": format(offset, "x")}


def reg(v):
    return {k: v[k] for k in ("space", "offset", "size", "name") if k in v}


def coord(r):
    return r["space"], r["offset"], r["size"]


def register(r):
    if r is None:
        return None
    return dict(name=r.name, space=r.space_id, offset=r.byte_offset, size=r.byte_size)


def rid(space, start, length, view):
    return f"{space:x}:{start:x}:{length if length is not None else 'u'}:{view}"


def identity(f, fid):
    return rid(f["space"], f["address"], f["length"], f.get("view", "0")), fid


def rr(r):
    return r["id"], r["observation"]


def ref(r):
    return {"id": r["id"], "observation": r["observation"]}


def opref(ops, i):
    return {"ordinal": i, "opcode": ops[i]["opcode"]}


def opkey(f, i):
    return f"{f['space']:x}:{f['address']:x}:{i}:{f['ops'][i]['opcode']}"


def triple(e):
    return tuple(e[k] for k in EC)


def row_set_digest(rows):
    return digest([[r[k] for k in ("space", "offset", "length", "view", "observation")]
                   for r in sorted(rows, key=rr)])


def document(bundle, producer, program, rows):
    ordered = sorted(rows, key=rr)
    if len({rr(r) for r in ordered}) != len(ordered):
        raise ValueError("duplicate row reference")
    for r in ordered:
        for v in [r["transfer"], *(r.get("vendor_views") or {}).values()]:
            if isinstance(v.get("edges"), list):
                v["edges"].sort(key=lambda e: tuple(order.index(x) for order, x in zip(ORDERS, triple(e))))
    return dict(schema=SCHEMA, source="derived", bundle=bundle, producer=producer,
                program=program, rows=ordered)


def schema(form):
    flow, indirect = form
    if flow == "none":
        return "none", [SEQ]
    if flow == "jcc":
        return "conditional", [TAKEN, NEXT]
    if flow == "xbegin":
        return "conditional", [NORMAL, OUTER, NESTED]
    if flow in ("call_near", "jmp_near"):
        return ("indirect", [IND]) if indirect else ("direct", [DIRECT])
    if flow in ("ret_near", "iret", "ret_far"):
        return "indirect", [IND]
    if flow in ("ud2", "invalid"):
        return "trap", [OS]
    if flow in ("int_n", "int3", "int1", "syscall", "sysenter", "hlt"):
        return "trap", [OS, SAVED]
    return "unknown", []


def overlap(v, w):
    return v["offset"] < w["offset"] + w["size"] and w["offset"] < v["offset"] + v["size"]


def same_reg(v, r):
    return r is not None and v is not None and v["kind"] == "REGISTER" and coord(v) == coord(r)


def const(v):
    return v is not None and v["kind"] == "CONSTANT"


def push_gate(f, sp):
    """Mirror observed_call_state first, then apply call_relations' validated-SP check."""
    ops = f["ops"]
    calls = [i for i, o in enumerate(ops) if o["opcode"] in CALLS]
    if len(calls) != 1:
        return None, "call-count"
    call = calls[0]
    swi = any(o["opcode"] == "CALLOTHER" and o["inputs"] and const(o["inputs"][0])
              and o["inputs"][0]["offset"] == 16 for o in ops[:call])
    prefix = "swi+CALLIND: " if swi and ops[call]["opcode"] == "CALLIND" else ""
    if not f["flow"]["is_call"]:
        return None, prefix + "not-call-flow"
    if f["fallthrough"] is None:
        return None, prefix + "no-fallthrough"
    if any(o["opcode"] in BRANCHES for o in ops[:call]):
        return None, "branch-before-call"

    accepted = []
    reason = prefix + "no-stack-adjustment"
    for i, o in enumerate(ops[:call]):
        r, a = o["output"], o["inputs"]
        if o["opcode"] != "INT_SUB" or not r or r["kind"] != "REGISTER" or len(a) != 2 or a[0] != r:
            continue
        if not const(a[1]) or a[1]["offset"] != r["size"]:
            reason = "adjustment-width"
            continue
        stores = []
        reason = "no-matching-store"
        for j in range(i + 1, call):
            s = ops[j]["inputs"]
            if ops[j]["opcode"] != "STORE" or len(s) != 3:
                continue
            if not const(s[0]) or s[0]["offset"] != f["space"] or s[1] != r:
                reason = "store-space-or-base"
                continue
            if const(s[2]) and s[2]["size"] == r["size"] and s[2]["offset"] == f["fallthrough"]:
                stores.append(j)
            else:
                reason = "stored-width-or-fallthrough"
        if len(stores) != 1:
            if len(stores) > 1:
                reason = "multiple-matching-stores"
            continue
        if call != i + 2:
            return None, "intervening-operation"
        # _writes_register in the pinned engine compares REGISTER byte slices.
        if any(k != i and w and w["kind"] == "REGISTER" and overlap(w, r)
               for k, w in enumerate(op["output"] for op in ops)):
            return None, "overlapping-adjustment-write"
        accepted.append(i)

    if len(accepted) != 1:
        return None, reason if not accepted else "multiple-accepted-adjustments"
    i = accepted[0]
    if sp is None:
        return None, "no-stack-register"
    if not same_reg(ops[i]["output"], sp):
        return None, "adjustment-not-stack-register"
    return (i, i + 1, call), None


def arm_shape(f, regs):
    ops = f["ops"]
    sp, lr, pc = (regs.get(k) for k in ("sp", "lr", "pc"))
    if not all((sp, lr, pc)) or len(ops) not in (2, 3) or not f["flow"]["is_call"]:
        return None
    write, call = ops[-2:]
    if not same_reg(write["output"], lr) or call["opcode"] not in CALLS:
        return None
    a = write["inputs"]
    if not all(map(const, a)):
        return None
    if write["opcode"] == "INT_ADD" and len(a) == 2:
        bits = a[0]["offset"] + a[1]["offset"]
        relative = a[0]["offset"] == f["address"]
        if relative and a[1]["offset"] != 4:
            return None
    elif write["opcode"] == "COPY" and len(a) == 1:
        bits, relative = a[0]["offset"], False
    else:
        return None
    if call["opcode"] == "CALLIND":
        c = ops[0]
        if len(ops) != 3 or c["opcode"] != "COPY" or not same_reg(c["output"], pc) or len(c["inputs"]) != 1:
            return None
        t = c["inputs"][0]
        if call["inputs"] != [c["output"]] or t["kind"] != "REGISTER" or t["size"] != pc["size"]:
            return None
        if any(t["space"] == r["space"] and overlap(t, r) for r in (sp, pc)):
            return None
    elif len(ops) != 2:
        return None
    return bits % (1 << (8 * lr["size"])), relative


def nodes(x):
    if isinstance(x, dict):
        yield x
        for v in x.values():
            yield from nodes(v)
    elif isinstance(x, list):
        for v in x:
            yield from nodes(v)


def value(f, operand, use, *, segment=None, call_cut=None):
    """Return a pre-state expression and its checked reaching definitions."""
    ops, seen = f["ops"], set()

    def fail(reason):
        raise ValueError(reason)

    def memory(space, address, size, i):
        for prior in ops[:i]:
            a, out = prior["inputs"], prior["output"]
            if prior["opcode"] == "STORE" and (not a or not const(a[0]) or a[0]["offset"] == space):
                fail("earlier STORE may alias")
            if out and out["kind"] == "ADDRESS" and out["space"] == space:
                fail("earlier memory output may alias")
        base = None
        if f.get("isa", "x86-64") == "x86-64":
            leaves = [x for x in nodes(address)
                      if x.get("pre_register", {}).get("offset") in (0x110, 0x118)
                      and x["pre_register"]["size"] == 8]
            if leaves:
                if len(leaves) != 1 or leaves[0] not in address.get("add", ()):
                    fail("segment base cannot be separated")
                base = leaves[0]
                if segment is not None and base["pre_register"]["offset"] != segment:
                    fail("segment override differs from lift")
                address = next(x for x in address["add"] if x != base)
            elif segment is not None:
                fail("segment base not identified")
        if address.get("width") == 32:
            address = {"zext": address, "width": 64}
        if address.get("width") != 64:
            fail("unresolved effective address width")
        return {"memory": dict(space=space, address=address, size=size, segment_base=base)}

    def read(v, limit, depth):
        if not v or depth > 40 or v["size"] <= 0:
            fail("missing or excessively deep operand")
        w = v["size"] * 8
        if const(v):
            return {"constant": format(v["offset"] % (1 << w), "x"), "width": w}
        if v["kind"] == "ADDRESS":
            return memory(v["space"], {"constant": format(v["offset"], "x"), "width": 64}, v["size"], limit)
        if v["kind"] not in ("REGISTER", "UNIQUE"):
            fail("unsupported value space")
        for i in range(limit - 1, -1, -1):
            o = ops[i]
            out = o["output"]
            if not out or out["space"] != v["space"] or not overlap(v, out):
                continue
            if out != v:
                fail("partial or ambiguous reaching definition")
            if call_cut is not None and i >= call_cut:
                fail("operand depends on the call setup")
            seen.add(i)
            name, a = o["opcode"], o["inputs"]
            if name == "LOAD" and len(a) == 2 and const(a[0]) and a[0]["offset"] == f["space"]:
                return memory(a[0]["offset"], read(a[1], i, depth + 1), v["size"], i)
            arithmetic = {"INT_ADD": "add", "INT_SUB": "sub", "INT_MULT": "mul"}
            comparisons = {"INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS"}
            boolean = {"BOOL_AND", "BOOL_OR", "BOOL_XOR"}
            bitwise = {"INT_AND", "INT_OR", "INT_XOR"}
            if name not in (set(arithmetic) | comparisons | boolean | bitwise |
                            {"COPY", "INT_ZEXT", "INT_SEXT", "SUBPIECE", "BOOL_NEGATE"}):
                fail("unsupported defining opcode " + name)
            args = [read(t, i, depth + 1) for t in a]
            sizes = [t["size"] * 8 for t in a]
            if name == "COPY" and sizes == [w]:
                return args[0]
            if name in arithmetic and sizes == [w, w]:
                return {arithmetic[name]: args, "width": w}
            if name in ("INT_ZEXT", "INT_SEXT") and len(a) == 1 and sizes[0] < w:
                return {"zext" if name == "INT_ZEXT" else "sext": args[0], "width": w}
            if name == "SUBPIECE" and len(a) == 2 and const(a[1]) and a[1]["offset"] == 0 and sizes[0] > w:
                return {"trunc": args[0], "width": w}
            if ((name in comparisons and w == 8 and len(a) == 2 and sizes[0] == sizes[1])
                    or (name in boolean and sizes == [8, 8] and w == 8)
                    or (name == "BOOL_NEGATE" and sizes == [8] and w == 8)
                    or (name in bitwise and sizes == [w, w])):
                return {"op_output": opref(ops, i)}
            fail("ill-typed defining opcode " + name)
        if v["kind"] == "REGISTER":
            return {"pre_register": reg(v), "width": w}
        fail("undefined unique")

    try:
        if any(o["opcode"] in lifting.FLOW_OPS for o in ops[:use]):
            fail("non-linear path or opaque userop")
        return read(operand, use, 0), sorted(seen)
    except ValueError as error:
        return U(str(error)), []


CC = "o no b ae e ne be a s ns p np l ge le g".split()
ALIASES = {"z": "e", "nz": "ne", "c": "b", "nae": "b", "nb": "ae", "nc": "ae",
           "na": "be", "nbe": "a", "pe": "p", "po": "np", "nge": "l", "nl": "ge",
           "ng": "le", "nle": "g"}
PATTERN = {"plain": "none", "rep": "none", "internal": "none", "cmov": "none", "jcc": "jcc",
           "jmp": "jmp_near", "jmp indirect": "jmp_near", "call": "call_near",
           "call indirect": "call_near", "call $+5": "call_near", "ret": "ret_near",
           "interrupt": "int_n", "interrupt-return": "int_n", "syscall": "syscall"}


def producer_form(f, lift, data):
    if lift is None:
        return "unknown", False
    p, ops = lift.pattern, f["ops"]
    b = data[len(compare._prefix_run(data)):]
    if p == "transactional" and ops[0]["inputs"][0]["offset"] == 85:
        return "xbegin", False
    if p == "userop" and len(ops) == 1 and ops[0]["inputs"] and const(ops[0]["inputs"][0]):
        if ops[0]["inputs"][0]["offset"] == 3:
            return "sysenter", False
    if p == "fault":
        if b.startswith(b"\x0f\x0b"):
            return "ud2", False
        return ("invalid" if b[:1] == b"\xce" else "unknown"), False
    if b[:1] in (b"\xcb", b"\xca", b"\xcf") and ops and ops[-1]["opcode"] == "RETURN":
        return ("iret" if b[0] == 0xcf else "ret_far"), True
    if b[:1] == b"\xff" and len(b) >= 2 and ((b[1] >> 3) & 7) in (3, 5):
        return "far", False
    return PATTERN.get(p, "unknown"), p in ("jmp indirect", "call indirect", "ret")


def cc_bytes(b):
    if b and 0x70 <= b[0] <= 0x7f:
        return CC[b[0] & 15]
    if len(b) > 1 and b[0] == 15 and 0x80 <= b[1] <= 0x8f:
        return CC[b[1] & 15]
    return None


def predicate(f, i, b, prefix):
    a = f["ops"][i]["inputs"]
    v, used = value(f, a[1] if len(a) == 2 else None, i)
    cc = cc_bytes(b)
    if cc is not None:
        positive = {"e": 0x206, "b": 0x200, "s": 0x207, "p": 0x202, "o": 0x20b}
        leaf = v.get("pre_register", {})
        proven = cc in positive and leaf.get("offset") == positive[cc] and v.get("width") == 8
        return {"flags": cc, "inputs": [v] if proven else U("incoming flag identities")}, used
    if b[:1] in (b"\xe2", b"\xe3") and "op_output" in v:
        j = v["op_output"]["ordinal"]
        o = f["ops"][j]
        w = 32 if 0x67 in prefix else 64
        if o["opcode"] == ("INT_EQUAL" if b[0] == 0xe3 else "INT_NOTEQUAL") and len(o["inputs"]) == 2:
            t, zero = o["inputs"]
            expr, _ = value(f, t, j)
            original = expr if b[0] == 0xe3 else (expr.get("sub") or [{}])[0]
            if (const(zero) and zero["offset"] == 0 and expr.get("width") == w
                    and original.get("pre_register", {}).get("offset") == lifting.RCX
                    and (b[0] == 0xe3 or expr["sub"][1] == {"constant": "1", "width": w})):
                return {"zero" if b[0] == 0xe3 else "nonzero": expr}, used
    # In particular, a counter-only LOOPZ/LOOPNZ lift cannot establish the conjunction.
    return U("whole encoded predicate not established"), used


def next_addr(f, length):
    if type(length) is int:
        return addr(f["space"], (f["address"] + length) % (1 << 64))
    return U("length unavailable")


def interval(f, length):
    if type(length) is int:
        return [format(f["address"], "x"), format(f["address"] + length, "x")]
    return U("length unavailable")


def make_push(f, base, space, width, bits, delta, length):
    return {"location": {"memory": {"space": space, "base": base, "relative_to": "pre_sp", "slot_offset": delta}},
            "value": {"width": width, "bits": bits}, "sp_delta": delta, "continuation": next_addr(f, length),
            "relocation": "instruction_relative", "derivation": "isa_next_ip"}


def make_edges(form, f, length, target):
    seq = next_addr(f, length)
    dest = {"encoded_target": target, "sequential": seq, "os": None, "computed": None,
            "os_return": None if form[0] in ("sysenter", "hlt") else seq}
    return [dict(zip(EC, k), to=dest[k[1]]) for k in schema(form)[1]]


def _derive_lift_row(f, lift, fid, regs, data=b"", split=False):
    ops, n = f["ops"], f["length"]
    arm = f.get("isa") == "aarch64"
    shape = arm_shape(f, regs) if arm else None
    form = producer_form(f, lift, data) if not arm else ("unknown", False)
    if shape is not None:
        form = "call_near", ops[-1]["opcode"] == "CALLIND"
    flow, _ = form
    kind, _ = schema(form)
    skipped = lift.skipped if lift else ()
    flows = [i for i, o in enumerate(ops) if o["opcode"] in lifting.FLOW_OPS and i not in skipped]
    i = flows[-1] if flows and kind not in ("unknown", "none") else None
    if kind == "trap" or flow == "xbegin":
        i = next((j for j, o in enumerate(ops) if o["opcode"] == "CALLOTHER"), i)
    keys = {k: [] for k in ("condition", "target", "auth", "link", "sp_adjust", "setup",
                            "transient", "persistent", "encoding_only")}
    keys.update(transfer=opref(ops, i) if i is not None else None, entry_ordinal=i)
    keys["setup"] = [opref(ops, j) for j in range(i or 0)]
    dest = U("encoded destination unavailable")
    operand = ops[i]["inputs"][0] if i is not None and ops[i]["inputs"] else None
    if operand and operand["kind"] == "ADDRESS":
        dest = addr(operand["space"], operand["offset"])
    prefix = compare._prefix_run(data)
    b = data[len(prefix):]
    if flow == "xbegin" and b.startswith(b"\xc7\xf8"):
        size = 2 if 0x66 in prefix else 4
        if n == len(prefix) + 2 + size and len(b) >= 2 + size:
            disp = int.from_bytes(b[2:2 + size], "little", signed=True)
            dest = addr(f["space"], (f["address"] + n + disp) % (1 << 64))
    target = condition = link = None
    if kind == "indirect":
        seg = next(({0x64: 0x110, 0x65: 0x118}.get(x) for x in reversed(prefix)
                    if x in (0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65)), None)
        target, used = value(f, operand, i, segment=seg,
                             call_cut=i - 2 if flow == "call_near" and not arm else None)
        keys["target"] = [opref(ops, j) for j in used]
    if flow == "jcc":
        test, used = predicate(f, i, b, prefix)
        condition = {"taken_when": "true", "test": test}
        keys["condition"] = [opref(ops, j) for j in used]
    if shape is not None:
        bits, relative = shape
        lr = regs["lr"]
        link = {"location": {"register": lr}, "sp_delta": 0,
                "value": {"width": 8 * lr["size"], "bits": format(bits, "x")},
                "continuation": next_addr(f, 4), "relocation": "instruction_relative" if relative else "unknown",
                "derivation": "pc_plus_4" if relative else "constant"}
        keys["link"] = [opref(ops, i - 1)]
        keys["persistent"] = keys["link"][:]
    elif flow == "call_near":
        sub_op, store = ops[i - 2:i]
        sel, _, v = store["inputs"]
        base = regs.get("sp") if same_reg(sub_op["output"], regs.get("sp")) else reg(sub_op["output"])
        link = make_push(f, base, sel["offset"], 8 * v["size"], format(v["offset"], "x") if const(v)
                         else U("stored operand"), -sub_op["inputs"][1]["offset"], n)
        keys["link"], keys["sp_adjust"] = [opref(ops, i - 1)], [opref(ops, i - 2)]
        gate, _ = push_gate(f, regs.get("sp"))
        if gate is not None:
            keys["transient"] = [opref(ops, j) for j in gate[:2]]
        else:
            keys["persistent"] = keys["sp_adjust"] + keys["link"]
    t = dict(kind=kind, edges=make_edges(form, f, n, dest), condition=condition, target_value=target,
             target_auth=None, link_write=link, op_keys=keys, hint=None)
    if i is not None:
        t["hint"] = {"CALL": "call", "CALLIND": "call", "BRANCH": "jump", "CBRANCH": "jump",
                     "BRANCHIND": "jump", "RETURN": "return"}.get(ops[i]["opcode"])
    isa = []
    if flow in ("invalid", "ud2"):
        t["exception_basis"] = "invalid_encoding" if flow == "invalid" else "defined_ud"
        if flow == "invalid":
            isa.append(dict(kind="F1", value="invalid_encoding", conditions=[]))
    if flow in ("int_n", "syscall"):
        isa.append(dict(kind="F3", value="saved_next_pc",
                        conditions=[dict(what="taken as encoded trap", source="os_model", state="unknown")]))
    vendors = None
    family = (0x66 in prefix and flow in ("call_near", "jmp_near", "ret_near", "jcc"))
    if not arm and (split or family):
        vendors = {}
        for vendor in VENDORS:
            if data.startswith(b"\x66\xe8") and form == ("call_near", False):
                size = 4 if vendor == "intel" else 2
                length, width = 2 + size, 64 if vendor == "intel" else 16
                stored = (f["address"] + length) % (1 << width)
                dst = U("displacement not covered")
                if len(data) >= length:
                    disp = int.from_bytes(data[2:length], "little", signed=True)
                    dst = addr(f["space"], (f["address"] + length + disp) % (1 << width))
                vl = make_push(f, base, f["space"], width, format(stored, "x"), -(width // 8), length)
                vendors[vendor] = dict(length=length, bytes=interval(f, length),
                                       edges=make_edges(form, f, length, dst), link_write=vl, target_value=None)
            else:
                u = U("vendor-specific constructor unavailable")
                es = [dict(zip(EC, k), **u) for k in schema(form)[1]] if kind != "unknown" else u
                vendors[vendor] = dict(length=u, bytes=u, edges=es, link_write=u, target_value=u)
    return dict(id=identity(f, fid)[0], observation=fid, space=f["space"], offset=format(f["address"], "x"),
                length=n, view=f.get("view", "0"), transfer=t, bytes=dict(range=interval(f, n), holds_if=PREMISE),
                vendor_views=vendors, isa=isa)


class Index:
    """The raw Bundle supplies starts. Length evidence may differ per vendor."""
    def __init__(self, entries, complete):
        self.complete = complete
        self.starts = defaultdict(list)
        self.width = defaultdict(int)
        self.unknown_start = {}
        for space, start, length, key in entries:
            self.starts[space].append((start, key, length))
            if type(length) is int:
                self.width[space] = max(self.width[space], length)
            else:
                self.unknown_start[space] = min(start, self.unknown_start.get(space, start))
        for items in self.starts.values():
            items.sort(key=lambda x: (x[0], x[1]))

    def landing(self, to):
        if unknown(to):
            return U("unknown destination")
        if to is None:
            return {"class": "unresolved"}
        s, x = to["space"], int(to["offset"], 16)
        items = self.starts.get(s, [])
        lo = bisect_left(items, (x - self.width[s],))
        hi = bisect_left(items, (x + 1,))
        starts, inside = [], []
        for y, key, n in items[lo:hi]:
            if y == x:
                starts.append(key)
            elif type(n) is int and y < x < y + n:
                inside.append(key)

        def refs(keys):
            return [dict(id=i, observation=o) for i, o in sorted(keys)]

        ins_complete = self.complete and self.unknown_start.get(s, x) >= x
        return {"starts": refs(starts) if self.complete else U("incomplete row set"),
                "inside": refs(inside) if ins_complete else U("incomplete intervals"),
                "mapping": U("mapping not compared"), "import": U("import role not compared"),
                "class": "row_start" if starts else "mid_row" if self.complete and inside else "unclassified"}


def member(r, vendor):
    if vendor and r["vendor_views"]:
        return r["vendor_views"][vendor]
    return dict(r["transfer"], length=r["length"], bytes=r["bytes"]["range"])


def finish_landings(rows, complete):
    for vendor in (None, *VENDORS):
        idx = Index(((r["space"], int(r["offset"], 16), member(r, vendor)["length"], rr(r))
                     for r in rows), complete)
        for r in rows:
            if vendor and not r["vendor_views"]:
                continue
            edges = member(r, vendor)["edges"]
            if isinstance(edges, list):
                for e in edges:
                    if not unknown(e):
                        e["lands_on"] = idx.landing(e["to"])


def common(values):
    a = list(values)
    return a[0] if a and all(x == a[0] for x in a) else MISS


def votes(ballot, result, vendor=None):
    if not ballot or not result or not result.get("attributes"):
        return []
    out = []
    for v in (VENDORS if vendor is None else (vendor,)):
        vs = ballot.get(v, ())
        names = decoders.INTEL_VOTERS if v == "intel" else decoders.AMD_VOTERS
        if Counter(d.voter for d in vs) != Counter(names) or any(d.amd != (v == "amd") for d in vs):
            return []
        out.extend(vs)
    w = result["window"]
    for d in out:
        if d.status not in ("ok", "invalid") or (d.status == "ok" and not 0 < d.length <= w["verified"]):
            return []
        for start, size, kind in w["relocations"]:
            if d.status == "invalid" or (start < d.length and start + size > 0 and
                    (kind != "DIR64" or not any(a <= start and start + size <= a + n for a, n in d.value_fields))):
                return []
    return out


class VoteSummary(NamedTuple):
    """The voter values G2a reads after collection (design_tbr_g2a_cost r1 C1, r2 D2). ``None`` is ABSENT: no
    common value (port: Option); none of these values can be JSON null where it is read."""
    empty: bool
    all_invalid: bool
    any_not_ok: bool
    ok_form: tuple | None
    length: int | None
    a7_width: int | None
    a7_bits: int | None
    a11b: int | None
    a5: int | None
    mnemonic: str | None
    address_bits: int | None


ABSENT = None
EMPTY = VoteSummary(True, False, False, None, None, None, None, None, None, None, None)


def _form(v):
    if v.flow == "ud":
        return ("ud2", False) if v.mnemonic.lower() == "ud2" else MISS
    if v.flow not in ("none", "call_near", "jmp_near", "ret_near", "jcc", "xbegin", "int_n",
                      "int3", "int1", "syscall", "sysenter", "hlt", "iret", "ret_far", "call_far", "jmp_far"):
        return MISS
    return v.flow, bool(v.indirect) if v.flow in ("jmp_near", "call_near") else False


def _agreed(values):
    x = common(values)
    return ABSENT if x is MISS else x


def _val(x):
    return MISS if x is ABSENT else x


def summarize_votes(vs, address):
    """A pure function of the accepted votes and the row address. Voter values are read only when every vote is
    ok (the only case where G2a consumes them), so no new exception site exists (r2 D2)."""
    vs = list(vs)
    if not vs:
        return EMPTY
    all_invalid = all(v.status == "invalid" for v in vs)
    any_not_ok = any(v.status != "ok" for v in vs)
    n = independent_length(vs)
    if any_not_ok:
        return VoteSummary(False, all_invalid, True, ABSENT, ABSENT if n is MISS else n,
                           ABSENT, ABSENT, ABSENT, ABSENT, ABSENT, ABSENT)
    vals = [compare.voter_values(v, address) for v in vs]
    a7 = [x.get("a7") for x in vals]
    a7w = a7b = ABSENT
    if all(t is not None for t in a7):
        a7w, a7b = _agreed(t[0] for t in a7), _agreed(t[1] for t in a7)
    a11 = [x.get("a11b") for x in vals]
    a11b = _agreed(a11) if all(t is not None for t in a11) else ABSENT
    a5 = ABSENT
    if all(v.target_derivation == "decoder" for v in vs):
        d = _agreed(x.get("a5") for x in vals)
        a5 = d if type(d) is int else ABSENT
    return VoteSummary(False, False, False, _agreed(map(_form, vs)), ABSENT if n is MISS else n, a7w, a7b, a11b,
                       a5, _agreed(map(mnemonic, vs)), _agreed(v.address_bits for v in vs))


def as_summary(vs, address):
    return vs if isinstance(vs, VoteSummary) else summarize_votes(vs, address)


def vote_form(vs, isa):
    s = vs if isinstance(vs, VoteSummary) else summarize_votes(vs, 0)
    if s.all_invalid:
        if (isa.get("facts", {}).get("F1", {}).get("class") == "invalid_encoding"
                and "F1" not in isa.get("unobserved", {})):
            return "invalid", False
        return MISS
    if s.any_not_ok:
        return MISS
    return _val(s.ok_form)


def mnemonic(d):
    m = d.mnemonic.lower()
    if m.startswith("j") and not m.endswith("cxz"):
        return ALIASES.get(m[1:], m[1:])
    return {"loopz": "loope", "loopnz": "loopne"}.get(m, m)


LINK_FIELDS = (
    "value.width", "value.bits", "continuation", "location",
    "location.memory.relative_to", "location.memory.slot_offset",
    "location.memory.base", "location.memory.space",
    "sp_delta", "relocation", "derivation",
)
PRED_FIELDS = ("taken_when", "test", "test.inputs")


def code(actual, want):
    if actual is MISS or unknown(actual) or want is MISS:
        return "u"
    if type(actual) is not type(want):
        return "x"
    if isinstance(want, (dict, list)):
        return "c" if canonical(actual) == canonical(want) else "x"
    return "c" if actual == want else "x"


def sub(d, *path):
    for k in path:
        d = d.get(k, MISS) if isinstance(d, dict) else MISS
    return d


def split_needed(ballot, result):
    if any(x.get("kind") == "vendor" for x in (result or {}).get("attributes", {}).values()):
        return True

    def signature(d):
        return d.status, d.length, d.flow, d.indirect, d.operand_bits, d.target_ip_bits, d.encoded_disp_bits

    a, b = (common(signature(d) for d in votes(ballot, result, v)) for v in VENDORS)
    return a is not MISS and b is not MISS and a != b


def independent_length(vs):
    n = common(d.length if d.status == "ok" else MISS for d in vs)
    return n if type(n) is int else MISS


def unit(path, state, edge=None, op=None):
    item = {"path": path, "code": state}
    if edge is not None:
        item["edge"] = dict(zip(EC, edge))
    if op is not None:
        item["op"] = op
    return item


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

    vs = as_summary(vs, f["address"])
    form = vote_form(vs, isa)
    path = "bytes" if vendor else "bytes.range"
    if form is MISS:
        for p in ("length", path, stem + "edges", stem + "link_write", stem + "target_value"):
            add(p, "?")
        if not vendor:
            for p in ("kind", "exception_basis", "condition", "target_auth", "op_keys"):
                add(stem + p, "?")
        return units
    length = _val(vs.length)
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
            dest = _val(vs.a5)
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
            name = _val(vs.mnemonic)
            if name in CC:
                actual = test if not isinstance(test, dict) or unknown(test) else test.get("flags", False)
                cmp(cp + ".test", actual, name)
                add(cp + ".test.inputs", "u")
            elif name in ("jrcxz", "jecxz", "loop"):
                width = _val(vs.address_bits)
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
        width, bits = _val(vs.a7_width), _val(vs.a7_bits)
        size = _val(vs.a11b)
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


def row_state(units):
    states = {u["code"] if isinstance(u, dict) else u[1] for u in units}
    return "x" if "x" in states else "u" if states & {"?", "u"} or "c" not in states else "c"


def verdict_block(doc, units):
    """The -4 block (tbr-common-facts-verdicts-1, rule g2a-3): kept for the retained -4 reader and its tests."""
    return dict(schema=VERDICT_SCHEMA, rule_version="g2a-3", facts_sha256=digest(doc),
                row_set_sha256=row_set_digest(doc["rows"]),
                rows=[dict(ref(r), units=units[rr(r)], state=row_state(units[rr(r)])) for r in doc["rows"]])


def denominators(units):
    counts = defaultdict(Counter)
    for row in units.values():
        for u in row:
            counts[u["path"]][u["code"]] += 1
    return _rates(counts)


def denominators_of_sets(sets, row_set):
    """Same result as denominators() over the expanded rows: a set used by N rows counts N times (r1 C2)."""
    uses = Counter(row_set.values())
    counts = defaultdict(Counter)
    for sid, units in enumerate(sets):
        if not uses[sid]:
            continue
        for u in units:
            counts[FIELD_PATHS[u[0]]][u[1]] += uses[sid]
    return _rates(counts)


def _rates(counts):
    out = {}
    for path, c in sorted(counts.items()):
        n = c["c"] + c["u"] + c["x"]
        out[path] = dict(confirmed=c["c"], contradicted=c["x"], unobserved_applicable=c["u"],
                         unobserved=c["u"] + c["?"], N_applicable=n, N_not_applicable=c["n"],
                         N_applicability_unknown=c["?"], N_considered=sum(c.values()))
        if n:
            out[path]["confirmed_rate"] = c["c"] / n
    return out


def resolve(op, r, f):
    if not isinstance(op, dict) or op.get("row", ref(r)) != ref(r):
        raise ValueError("wrong op row")
    i = op.get("ordinal")
    if type(i) is not int or not 0 <= i < len(f["ops"]) or op.get("opcode") != f["ops"][i]["opcode"]:
        raise ValueError("wrong op ordinal or opcode")
    return opkey(f, i)


def engine_fields(rel):
    return dict(call_key=rel.call_key, kind=rel.kind, sp=coord(register(rel.sp)),
                link=(rel.link.space_id, rel.link.size) if rel.kind == "push" else coord(register(rel.link)),
                delta=rel.delta, continuation=(rel.continuation.space_id, rel.continuation.byte_offset),
                relocation=rel.relocation, length=rel.length, entry_ordinal=rel.entry_ordinal,
                setup_ops=tuple(rel.setup_ops), transient_ops=tuple(rel.transient_ops))


def _project_claim(r, f, regs, vendor=None):
    arm = f.get("isa") == "aarch64"
    if arm:
        shape = arm_shape(f, regs)
        if shape is None or not f["flow"]["has_fallthrough"] or f["fallthrough"] is None:
            return None, "register-link shape, registers or fallthrough"
        if shape[0] != f["fallthrough"]:
            return None, "link write differs from fallthrough"
        gate = (len(f["ops"]) - 2, len(f["ops"]) - 1)
    else:
        gate, why = push_gate(f, regs.get("sp"))
        if gate is None:
            return None, why

    m, keys = member(r, vendor), r["transfer"]["op_keys"]
    try:
        link = m["link_write"]
        val, loc = link["value"], link["location"]
        width, bits = val["width"], int(val["bits"], 16)
        if type(width) is not int or width not in (16, 32, 64):
            raise ValueError("stored width")
        cont = link["continuation"]
        at = cont["space"], int(cont["offset"], 16)
        if bits != at[1] % (1 << width):
            raise ValueError("stored bits differ from continuation")
        if arm:
            lr = loc["register"]
            where, sp = coord(lr), coord(regs["sp"])
            if bits != shape[0] or width != lr["size"] * 8 or where != coord(regs["lr"]):
                raise ValueError("link register or value")
            expected_derivation = "pc_plus_4" if shape[1] else "constant"
            expected_link, expected_adjust = [gate[0]], []
        else:
            mem = loc["memory"]
            sp = coord(mem["base"])
            where = mem["space"], width // 8
            if (mem["relative_to"] != "pre_sp" or mem["slot_offset"] != link["sp_delta"]
                    or mem["slot_offset"] != -(width // 8)):
                raise ValueError("inconsistent pre-SP slot")
            store = f["ops"][gate[1]]["inputs"]
            if width != 8 * store[2]["size"] or bits != store[2]["offset"] or mem["space"] != store[0]["offset"]:
                raise ValueError("claim differs from observed STORE")
            expected_derivation = "isa_next_ip"
            expected_link, expected_adjust = [gate[1]], [gate[0]]
        if link["derivation"] != expected_derivation:
            raise ValueError("derivation")
        for name, indices in (("link", expected_link), ("sp_adjust", expected_adjust)):
            if [resolve(x, r, f) for x in keys[name]] != [opkey(f, j) for j in indices]:
                raise ValueError("op_keys." + name)
        reloc = {"unknown": "unknown", "instruction_relative": "instruction-relative"}[link["relocation"]]
        return dict(call_key=resolve(keys["transfer"], r, f), kind="link" if arm else "push", sp=sp,
                    link=where, delta=link["sp_delta"], continuation=at, relocation=reloc,
                    length=at[1] - f["address"], entry_ordinal=keys["entry_ordinal"],
                    setup_ops=tuple(resolve(x, r, f) for x in keys["setup"]),
                    transient_ops=tuple(resolve(x, r, f) for x in keys["transient"])), None
    except (KeyError, TypeError, ValueError, IndexError) as error:
        return None, "claim: " + str(error)


def parity(fn, rows, regs, vendor_lengths):
    records, joined = [], set()
    engine, fid = fn["engine_relations"], fn["function_id"]
    for f in fn["rows"]:
        r = rows[identity(f, fid)]
        for i, o in enumerate(f["ops"]):
            if o["opcode"] not in CALLS:
                continue
            key = opkey(f, i)
            joined.add(key)
            for v in (None, *(r.get("vendor_views") or {})):
                ctx = dict(row=ref(r), view=r["view"], vendor=v, op=opref(f["ops"], i), call_key=key)
                if engine is None:
                    records.append(dict(ctx, status="engine-error", reason=fn["engine_error"]))
                    continue
                other = engine.get(key)
                n = vendor_lengths.get((rr(r), v))
                if v and (type(n) is not int or f["length"] != n):
                    records.append(dict(ctx, status="outside-observed-view",
                                        reason="vendor interval not established for this lift"))
                    continue
                p, why = projection(r, f, regs, v)
                if p is None:
                    status = ("missing" if other is not None
                              else "claim-error" if why.startswith("claim") else "neither")
                elif other is None:
                    status = "extra"
                else:
                    differences = {k: {"claim": p[k], "engine": other[k]} for k in other if p[k] != other[k]}
                    status = "differs" if differences else "matched"
                    if differences:
                        ctx["differences"] = differences
                records.append(dict(ctx, status=status, reason=why))
    for key in sorted(set(engine or {}) - joined):
        records.append(dict(observation=fid, call_key=key, status="missing", reason="engine key outside source calls"))
    return records


def input_checks(fn, rows):
    result = []
    for f in fn["rows"]:
        r = rows[identity(f, fn["function_id"])]
        t = r["transfer"]
        for i, op in enumerate(f["ops"]):
            ref_op = opref(f["ops"], i)
            tail = (fn.get("tails") or {}).get(opkey(f, i))
            if op["opcode"] == "RETURN":
                a = op["inputs"]
                want, _ = value(f, a[0] if len(a) == 1 else None, i)
                actual = t.get("target_value", MISS)
                if f.get("isa") == "aarch64" and isinstance(actual, dict) and "pre_register" in actual:
                    # The sealed encoding uses the named register table. The
                    # lift operand supplies the same coordinate without a name.
                    actual = dict(actual, pre_register={k: v for k, v in actual["pre_register"].items() if k != "name"})
                fields = {
                    "transfer": code(sub(t, "op_keys", "transfer"), ref_op),
                    "target_value": "u" if unknown(want) else code(actual, want),
                }
                if t.get("kind") == "trap":
                    # A trap row's transfer op is its userop; a RETURN after it is not the row's transfer and
                    # carries no target claim, so neither input comparison applies.
                    fields = {"transfer": "n", "target_value": "n"}
            elif tail and tail["kind"] in ("branch", "cbranch"):
                destinations = {DIRECT: tail["target"]}
                if tail["kind"] == "cbranch":
                    ft = lifting.continuation(f)
                    destinations = {
                        TAKEN: tail["target"], NEXT: addr(*ft) if ft is not None else MISS,
                    }
                es = t.get("edges")
                fields = {"transfer": code(sub(t, "op_keys", "transfer"), ref_op)}
                if isinstance(es, list):
                    fields["edges"] = "c" if Counter(map(triple, es)) == Counter(destinations.keys()) else "x"
                else:
                    fields["edges"] = "u"
                for key, want in destinations.items():
                    matches = [e for e in es if triple(e) == key] if isinstance(es, list) else []
                    actual = matches[0].get("to", MISS) if len(matches) == 1 else MISS
                    fields[key[1]] = code(actual, want)
            else:
                continue
            result.append(dict(row=ref(r), op=ref_op, fields=fields))
    return result


def different_lifts(groups, rows, raw, regs):
    by_instruction = defaultdict(list)
    for (isa, space, start, view, data), keys in groups.items():
        by_instruction[isa, space, start, data].extend(keys)

    results = []
    for keys in by_instruction.values():
        for vendor in (None, *VENDORS):
            selected = [k for k in keys if vendor is None or rows[k]["vendor_views"]]
            if len({digest(raw[k]["ops"]) for k in selected}) < 2:
                continue
            arch, lifts = [], []
            for k in selected:
                r, f = rows[k], raw[k]
                t, m = r["transfer"], member(r, vendor)
                edges = m["edges"]
                if isinstance(edges, list):
                    edges = [
                        {field: e[field] for field in (*EC, "to", "unobserved") if field in e}
                        for e in edges
                    ]
                link = m["link_write"]
                arch_link = (
                    {key: val for key, val in link.items() if key not in ("relocation", "derivation")}
                    if isinstance(link, dict) else link
                )
                arch.append(dict(
                    length=m["length"], kind=t["kind"], condition=t["condition"],
                    target_value=m["target_value"], target_auth=t["target_auth"],
                    edges=edges, link_write=arch_link,
                ))
                detail = dict(
                    row=ref(r), view=r["view"], op_refs="resolved",
                    relocation_check="u", derivation_check="u",
                )
                try:
                    for node in nodes(r):
                        if {"ordinal", "opcode"} <= node.keys():
                            resolve(node, r, f)
                except (TypeError, ValueError, KeyError) as error:
                    detail.update(op_refs="invalid", reason=str(error))

                observed = vendor is None or type(m["length"]) is int and m["length"] == f["length"]
                observed = observed and f.get("fallthrough_space", f["space"]) == f["space"]
                want = None
                if observed and f.get("isa") == "aarch64":
                    shape = arm_shape(f, regs)
                    if shape and f["flow"]["has_fallthrough"] and shape[0] == f["fallthrough"]:
                        want = ("instruction_relative", "pc_plus_4") if shape[1] else ("unknown", "constant")
                elif observed and push_gate(f, regs.get("sp"))[0] is not None:
                    want = "instruction_relative", "isa_next_ip"
                if want is not None:
                    detail["relocation_check"] = code(sub(link, "relocation"), want[0])
                    detail["derivation_check"] = code(sub(link, "derivation"), want[1])
                lifts.append(detail)

            fields = {}
            for field in arch[0]:
                vals = [a[field] for a in arch]
                known = [v for v in vals if not any(unknown(n) or "op_output" in n for n in nodes(v))]
                if len({digest(v) for v in known}) > 1:
                    fields[field] = "x"
                else:
                    fields[field] = "c" if len(known) == len(vals) else "u"
            results.append(dict(vendor=vendor, fields=fields, lifts=lifts))
    return results


def derive_row(f, lift, fid, regs, data=b"", split=False):
    r = _derive_lift_row(f, lift, fid, regs, data, split)
    t = r["transfer"]
    keys = t["op_keys"]
    link = t["link_write"]

    if isinstance(link, dict) and "memory" in link.get("location", {}):
        mem = link["location"]["memory"]
        val = link["value"]
        width = val["width"]
        cont = link["continuation"]
        width_ok = type(width) is int and width in (16, 32, 64)
        slot_ok = width_ok and mem["slot_offset"] == link["sp_delta"] == -(width // 8)
        bits_ok = (
            width_ok and not unknown(cont) and isinstance(val["bits"], str)
            and int(val["bits"], 16) == int(cont["offset"], 16) % (1 << width)
        )

        if not width_ok:
            val["width"] = U("unsupported near-call store width")
        else:
            if not slot_ok:
                reason = "adjustment and stored width disagree"
                mem["slot_offset"] = U(reason)
                link["sp_delta"] = U(reason)
            if not unknown(cont) and isinstance(val["bits"], str) and not bits_ok:
                val["bits"] = U("stored bits disagree with architectural continuation")

        observed = (f.get("fallthrough_space", f["space"]), f["fallthrough"])
        claimed = None if unknown(cont) else (cont["space"], int(cont["offset"], 16))
        removable = slot_ok and bits_ok and claimed == observed and mem["space"] == observed[0]
        if keys["transient"] and not removable:
            keys["persistent"] = keys["transient"]
            keys["transient"] = []

    prefix = compare._prefix_run(data)
    if lift and lift.pattern in ("jmp indirect", "call indirect") and 0x67 in prefix:
        for node in nodes(t.get("target_value")):
            if "memory" not in node:
                continue
            a = node["memory"]["address"]
            extended = a.get("width") == 64 and sub(a, "zext", "width") == 32
            small_constant = (
                "constant" in a and a.get("width") == 64
                and int(a["constant"], 16) < (1 << 32)
            )
            if not extended and not small_constant:
                t["target_value"] = U("32-bit effective offset not established")
                keys["target"] = []
                break
    return r


def projection(r, f, regs, vendor=None):
    projected, reason = _project_claim(r, f, regs, vendor)
    if projected is None:
        return None, reason

    ft = (f.get("fallthrough_space", f["space"]), f["fallthrough"])
    if projected["continuation"] != ft:
        return None, "claim: continuation differs from full observed fallthrough"
    if projected["kind"] == "push" and projected["link"][0] != ft[0]:
        return None, "claim: link slot space differs from observed fallthrough"
    return projected, None


def row_verdicts(r, vs, index, isa, vendor=None):
    vs = as_summary(vs, int(r["offset"], 16))
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


# -- cost compaction (design_tbr_g2a_cost r1 C2-C4, r2 D1-D4) ----------------------------------------------------

_EDGE_FIELDS = ("edges", "edges.to", "edges.lands_on", "edges.lands_on.class", "edges.lands_on.starts",
                "edges.lands_on.inside", "edges.lands_on.mapping", "edges.lands_on.import")
_OP_NAMES = ("transfer", "target", "condition", "auth", "link", "sp_adjust", "setup", "transient", "persistent")
FIELD_PATHS = tuple(
    ["length", "bytes.range"]
    + ["transfer." + p for p in (("kind", "exception_basis") + _EDGE_FIELDS + ("condition",)
                                 + tuple("condition." + f for f in PRED_FIELDS) + ("target_auth", "op_keys")
                                 + tuple("op_keys." + n for n in _OP_NAMES)
                                 + ("op_keys.encoding_only", "op_keys.entry_ordinal", "target_value", "link_write")
                                 + tuple("link_write." + f for f in LINK_FIELDS))]
    + [f"vendor_views.{v}.{p}" for v in VENDORS
       for p in (("length", "bytes") + _EDGE_FIELDS + ("target_value", "link_write")
                 + tuple("link_write." + f for f in LINK_FIELDS))])
PATH_ID = {p: i for i, p in enumerate(FIELD_PATHS)}
CODES = ("c", "x", "u", "n", "?")


def to_unit(u):
    """A unit dict (row_verdicts' output) as an immutable value: (path_id, code, edge | None, op | None) with
    edge = (when, source, requires) and op = (ordinal, opcode, (id, observation) | None)."""
    if not set(u) <= {"path", "code", "edge", "op"} or ("edge" in u and "op" in u):
        raise ValueError(f"unit shape {sorted(u)}")
    edge = triple(u["edge"]) if "edge" in u else None
    op = None
    if "op" in u:
        o = u["op"]
        if set(o) not in ({"ordinal", "opcode"}, {"row", "ordinal", "opcode"}):
            raise ValueError(f"unit op shape {sorted(o)}")
        op = (o["ordinal"], o["opcode"], rr(o["row"]) if "row" in o else None)
    return PATH_ID[u["path"]], u["code"], edge, op


def from_unit(x):
    pid, state, edge, op = x
    out = {"path": FIELD_PATHS[pid], "code": state}
    if edge is not None:
        out["edge"] = dict(zip(EC, edge))
    if op is not None:
        out["op"] = {"ordinal": op[0], "opcode": op[1]}
        if op[2] is not None:
            out["op"]["row"] = {"id": op[2][0], "observation": op[2][1]}
    return out


def unit_json(x):
    pid, state, edge, op = x
    if edge is not None and op is not None:
        raise ValueError("a unit has an edge or an op, never both")
    if op is not None:
        o = {"ordinal": op[0], "opcode": op[1]}
        if op[2] is not None:
            o["row"] = {"id": op[2][0], "observation": op[2][1]}
        return [pid, state, None, o]
    return [pid, state, list(edge)] if edge is not None else [pid, state]


def unit_from_json(x):
    """Structural check of one -5 unit (r1 C3 reader, structural); raises ValueError."""
    if not isinstance(x, list) or len(x) not in (2, 3, 4):
        raise ValueError("unit arity")
    pid, state = x[0], x[1]
    if type(pid) is not int or not 0 <= pid < len(FIELD_PATHS) or not isinstance(state, str) or state not in CODES:
        raise ValueError("unit path id or code")
    edge = op = None
    if len(x) == 3:
        e = x[2]
        if (not isinstance(e, list) or len(e) != 3
                or not all((v is None or isinstance(v, str)) and v in order for v, order in zip(e, ORDERS))):
            raise ValueError("unit edge")
        edge = tuple(e)
    elif len(x) == 4:
        o = x[3]
        if x[2] is not None or not isinstance(o, dict) or set(o) not in ({"ordinal", "opcode"},
                                                                         {"row", "ordinal", "opcode"}):
            raise ValueError("unit op slot")
        if type(o["ordinal"]) is not int or o["ordinal"] < 0 or not isinstance(o["opcode"], str) or not o["opcode"]:
            raise ValueError("unit op ordinal or opcode")
        row = None
        if "row" in o:
            w = o["row"]
            if (not isinstance(w, dict) or set(w) != {"id", "observation"}
                    or not all(isinstance(v, str) and v for v in w.values())):
                raise ValueError("unit op row")
            row = rr(w)
        op = (o["ordinal"], o["opcode"], row)
    return pid, state, edge, op


def block_units(block):
    """Per verdict row, its units in dict form, for a -4 or a -5 block (-5 sets are expanded once)."""
    if block.get("schema") == VERDICT_SCHEMA2:
        sets = [[from_unit(unit_from_json(x)) for x in s] for s in block["unit_sets"]]
        return lambda vr: sets[vr["set"]]
    return lambda vr: vr["units"]


def verdict_block5(doc, facts_sha256, sets, row_set):
    """-5 block (tbr-common-facts-verdicts-2, rule g2a-4): the sets the rows use, numbered by first use in the
    document's row order (r1 C3); a set no row uses is not written."""
    number, used = {}, []
    for r in doc["rows"]:
        sid = row_set[rr(r)]
        if sid not in number:
            number[sid] = len(used)
            used.append(sets[sid])
    states = [row_state(s) for s in used]
    return dict(schema=VERDICT_SCHEMA2, rule_version=VERDICT_RULE, facts_sha256=facts_sha256,
                row_set_sha256=row_set_digest(doc["rows"]), field_paths=list(FIELD_PATHS),
                unit_sets=[[unit_json(x) for x in s] for s in used],
                rows=[dict(ref(r), set=number[row_set[rr(r)]], state=states[number[row_set[rr(r)]]])
                      for r in doc["rows"]])


def expand_block5(block):
    """The -4 rows a -5 block stands for (equivalence checks, design r1 E1)."""
    units = block_units(block)
    return [dict(id=vr["id"], observation=vr["observation"], units=units(vr), state=vr["state"])
            for vr in block["rows"]]


def _chunks(doc, stream_key):
    yield b"{"
    for i, key in enumerate(sorted(doc)):
        yield (b"," if i else b"") + canonical(key) + b":"
        if key == stream_key and isinstance(doc[key], list):
            yield b"["
            for j, item in enumerate(doc[key]):
                yield (b"," if j else b"") + canonical(item)
            yield b"]"
        else:
            yield canonical(doc[key])
    yield b"}"


def streamed_digest(doc, stream_key="rows"):
    """== digest(doc), without building canonical(doc) as one object (r1 C4)."""
    h = hashlib.sha256()
    for chunk in _chunks(doc, stream_key):
        h.update(chunk)
    return h.hexdigest()


def write_canonical(path, doc, stream_key="rows"):
    """Writes canonical(doc) + LF and returns SHA256(canonical(doc)) (the LF excluded, r2 D4). The bytes go to a
    per-call temporary file created exclusively beside the target and renamed over it only when complete (Fable impl
    r1 P3-8, Astra impl r2 item 2)."""
    import os
    from uuid import uuid4

    target = os.path.abspath(os.fsdecode(path))
    temporary = os.path.join(os.path.dirname(target), f".g2a-{uuid4().hex}.partial")
    digest = hashlib.sha256()
    out = open(temporary, "xb")
    try:
        with out:
            for chunk in _chunks(doc, stream_key):
                out.write(chunk)
                digest.update(chunk)
            out.write(b"\n")
        os.replace(temporary, target)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return digest.hexdigest()
