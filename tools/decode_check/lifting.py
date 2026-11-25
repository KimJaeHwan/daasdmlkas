"""Ghidra-side facts of G1 decode_check: lift identification (design r2 s1, r3 s1,
r4 s1 / s2) on plain row facts, no engine objects (the same input a Rust
implementation would take).

``row_facts(instruction, exit_row)`` turns a validated instruction into a dict;
``identify(facts, table)`` matches it against the pinned lifting table and
returns the Ghidra-side attribute values. The table applies only under a named
premise (``stock-ghidra-translator``): the Bundle carries no compiled-SLEIGH
identity, so without the premise every table-dependent attribute is
``unobserved`` ("translation-unverified"); A1 and an explicit A2 stay compared.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Ghidra 12.0.4, x86:LE:64:default 4.6 (x86-64.sla d5adc314, the engine's own evidence: fault_premise.py,
# pcodeop_models x86.json): userop indices this table reads
TABLE = {
    "id": "x86-64-lift-table-4",
    "language": ("x86:LE:64:default", 4, 6),
    "ghidra": "12.0.4",
    "sla_sha256_prefix": "d5adc314",
    "userops": {16: "swi", 77: "invalidInstructionException", 84: "xabort", 85: "xbegin", 86: "xend", 99: "xtest"},
    "allowed_prefix": frozenset({"COPY", "INT_ADD", "INT_SUB", "INT_MULT", "INT_ZEXT", "INT_SEXT", "SUBPIECE",
                                 "PIECE", "LOAD", "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS",
                                 "INT_LESSEQUAL", "INT_SLESSEQUAL", "BOOL_NEGATE", "BOOL_AND", "BOOL_OR",
                                 "BOOL_XOR", "INT_CARRY", "INT_SCARRY", "INT_SBORROW", "INT_2COMP", "INT_NEGATE"}),
}
FLOW_OPS = frozenset({"BRANCH", "CBRANCH", "BRANCHIND", "CALL", "CALLIND", "RETURN", "CALLOTHER"})
RSP, RCX = 0x20, 0x08
TRANSLATION_PREMISE = "stock-ghidra-translator"
NA = ("n/a",)   # (the same "does not apply" value as compare.NA)


def row_facts(instruction, exit_row=None, register_space=None) -> dict:
    """Plain facts of one validated instruction (engine object -> dict)."""
    def varnode(item):
        if item is None:
            return None
        return {"kind": item.kind.name, "space": item.coordinate.space_id, "offset": item.coordinate.byte_offset,
                "size": item.byte_size}

    flow = instruction.flow
    return {
        "address": instruction.address.byte_offset,
        "space": instruction.address.space_id,
        "length": instruction.length,
        "fallthrough": None if instruction.fallthrough is None else instruction.fallthrough.byte_offset,
        "fallthrough_space": None if instruction.fallthrough is None else instruction.fallthrough.space_id,
        "flow_targets": sorted(target.byte_offset for target in instruction.flow_targets),
        "flow": {name: getattr(flow, name) for name in ("is_flow", "has_fallthrough", "is_call", "is_jump",
                                                         "is_terminal", "is_computed", "is_conditional",
                                                         "is_unconditional", "is_override")},
        "ops": [{"opcode": op.opcode, "inputs": [varnode(item) for item in op.inputs], "output": varnode(op.output)}
                for op in instruction.operations],
        "exit": None if exit_row is None else {"target": exit_row.target.byte_offset,
                                               "target_space": exit_row.target.space_id, "kind": exit_row.kind,
                                               "function": None if exit_row.function is None
                                               else exit_row.function.byte_offset},
    }


def continuation(facts: dict):
    """(space, offset) of the row's continuation: the listing fallthrough, else the S1 exit target (the
    kind-4 restoration, for comparison only); a missing space means the row's own (test facts)."""
    if facts.get("fallthrough") is not None:
        return facts.get("fallthrough_space", facts.get("space")), facts["fallthrough"]
    if facts.get("exit"):
        return facts["exit"].get("target_space", facts.get("space")), facts["exit"]["target"]
    return None


@dataclass
class Lift:
    pattern: str
    values: dict = field(default_factory=dict)     # attribute -> Ghidra value
    unobserved: dict = field(default_factory=dict)  # attribute -> reason
    skipped: tuple = ()                             # ordinals excluded as intra-instruction skips


def _is_reg(item, offset=None, size=None):
    return item is not None and item["kind"] == "REGISTER" and (offset is None or item["offset"] == offset) \
        and (size is None or item["size"] == size)


def _is_const(item):
    return item is not None and item["kind"] == "CONSTANT"


def _is_address(item):
    return item is not None and item["kind"] == "ADDRESS"


def _width_before_extension(ops, varnode, upto):
    """Bits of ``varnode`` before a zero / sign extension inside the row (target_operand_bits)."""
    for op in reversed(ops[:upto]):
        if op["output"] == varnode:
            if op["opcode"] in ("INT_ZEXT", "INT_SEXT") and op["inputs"]:
                return op["inputs"][0]["size"] * 8
            return varnode["size"] * 8
    return varnode["size"] * 8


def _space_ok(item, space):
    """A LOAD / STORE space-selector constant naming the row's own address space (``space`` None: unchecked)."""
    return _is_const(item) and (space is None or item["offset"] == space)


def _push(ops, upto, table=None, space=None):
    """(push bytes, STORE width bits, STORE value or None, RSP width bits) when ``ops[:upto]`` is exactly
    allowed prefix ops (none writing RSP) ; INT_SUB RSP = RSP - const ; STORE [RSP] -- the near-call push
    (r2 s1), RSP the full 64-bit register and the STORE into the row's own address space. Anything else
    (a second RSP write: far call; another base register; ESP; another space; ops between) -> None."""
    table = table or TABLE
    if upto < 2:
        return None
    sub_op, store_op = ops[upto - 2], ops[upto - 1]
    if sub_op["opcode"] != "INT_SUB" or not _is_reg(sub_op["output"], RSP, 8) or len(sub_op["inputs"]) != 2 \
            or not _is_reg(sub_op["inputs"][0], RSP, 8) or not _is_const(sub_op["inputs"][1]):
        return None
    if store_op["opcode"] != "STORE" or len(store_op["inputs"]) != 3 or not _is_reg(store_op["inputs"][1], RSP, 8) \
            or not _space_ok(store_op["inputs"][0], space):
        return None
    for op in ops[:upto - 2]:
        if op["opcode"] not in table["allowed_prefix"] or _is_reg(op["output"], RSP):
            return None
    value = store_op["inputs"][2]
    return (sub_op["inputs"][1]["offset"], value["size"] * 8, value["offset"] if _is_const(value) else None,
            sub_op["output"]["size"] * 8)


def _ret_shape(ops, space):
    """(W, K or None) when ``ops`` is exactly (Astra impl r4 s2; Ghidra 12.0.4 ia.sinc pop88 / RET imm16):
        T:W = LOAD(const(row space), RSP:8)
        RSP:8 = INT_ADD(RSP:8, const:8(W))
        [RSP:8 = INT_ADD(RSP:8, const:8(K))]     (once, 0 <= K <= 0xffff)
        RETURN(T:W)
    T a REGISTER / UNIQUE of size W (8, or 2 for 66 C3), never RSP; nothing else."""
    if len(ops) not in (3, 4):
        return None
    load, first, rest = ops[0], ops[1], ops[2:]
    ret = rest[-1]
    second = rest[0] if len(rest) == 2 else None
    if load["opcode"] != "LOAD" or len(load["inputs"]) != 2 or not _space_ok(load["inputs"][0], space) \
            or not _is_reg(load["inputs"][1], RSP, 8):
        return None
    target = load["output"]
    if target is None or target["kind"] not in ("REGISTER", "UNIQUE") or target["size"] not in (2, 8) \
            or _is_reg(target, RSP):
        return None
    width = target["size"]

    def adjust(op, value=None):
        return op["opcode"] == "INT_ADD" and _is_reg(op["output"], RSP, 8) and len(op["inputs"]) == 2 \
            and _is_reg(op["inputs"][0], RSP, 8) and _is_const(op["inputs"][1]) and op["inputs"][1]["size"] == 8 \
            and (value is None or op["inputs"][1]["offset"] == value)

    if not adjust(first, width):
        return None
    immediate = None
    if second is not None:
        if not adjust(second) or not 0 <= second["inputs"][1]["offset"] <= 0xFFFF:
            return None
        immediate = second["inputs"][1]["offset"]
    if ret["opcode"] != "RETURN" or len(ret["inputs"]) != 1 or ret["inputs"][0] != target:
        return None
    return width, immediate


def _prefix_ok(ops, upto, table):
    return all(op["opcode"] in table["allowed_prefix"] for op in ops[:upto])


def _memory_address_bits(ops, target, upto):
    """A11c of an indirect transfer (Astra impl r4 s3): the LOAD address width before extension when a LOAD
    of this row produces the target -- directly or through same-size COPYs (Ghidra: LOAD -> COPY -> CALLIND);
    64 when the target is itself a memory (ADDRESS) varnode (Ghidra: BRANCHIND [ram slot] for jmp [rip+x]:
    the slot address is fixed, no computation in the row); NA for a register target the row does not write;
    None when the origin is not recoverable (unobserved)."""
    if target is not None and target["kind"] == "ADDRESS":
        return 64
    for index in range(upto - 1, -1, -1):
        op = ops[index]
        if op["output"] == target:
            if op["opcode"] == "LOAD" and len(op["inputs"]) == 2:
                return _width_before_extension(ops, op["inputs"][1], index)
            if op["opcode"] == "COPY" and len(op["inputs"]) == 1 and op["inputs"][0] is not None \
                    and op["inputs"][0]["size"] == target["size"]:
                return _memory_address_bits(ops, op["inputs"][0], index)
            return None
    return NA if target is not None and target["kind"] == "REGISTER" else None


def identify(facts: dict, table: dict = TABLE) -> Lift:
    ops = facts["ops"]
    space = facts.get("space")
    start = facts["address"]
    length = facts["length"]
    nxt = None if length is None else start + length
    opcodes = [op["opcode"] for op in ops]
    flows = [i for i, name in enumerate(opcodes) if name in FLOW_OPS]
    continuation = facts["fallthrough"] is not None or facts["exit"] is not None

    def lift(pattern, **values):
        return Lift(pattern, values)

    # -- trap shapes: CALLOTHER(constants) ; CALLIND [; RETURN const]  /  CALLOTHER 77 ; BRANCHIND
    if opcodes[:1] == ["CALLOTHER"] and ops[0]["inputs"] and all(_is_const(i) for i in ops[0]["inputs"]):
        index = ops[0]["inputs"][0]["offset"]
        name = table["userops"].get(index)
        rest = opcodes[1:]
        if name == "swi" and rest in (["CALLIND"], ["CALLIND", "RETURN"]) and len(ops[0]["inputs"]) == 2:
            vector = ops[0]["inputs"][1]["offset"]
            # (whether the OS returns after an interrupt is not observable: A3 unobserved, r3 s3)
            return Lift("interrupt", {"a10": ("int", vector), "a6": "none", "a8": "none", "a9": "none", "a5": None},
                        {"a3": "OS return after an interrupt is not observable"})
        if name == "invalidInstructionException" and rest == ["BRANCHIND"]:
            return lift("fault", a10=("invalid-opcode",), a6="none", a8="none", a9="none", a5=None,
                        a3="sequential" if continuation else "none")
        if name in ("xbegin", "xabort", "xend", "xtest") and not rest:
            return Lift("transactional", {"a10": ("none",), "a6": "none", "a9": "none"},
                        {"a3": "transactional semantics not compared", "a8": "transactional", "a5": "transactional"})
        return Lift("userop", {}, {name_: f"userop {index} ({name or 'unmapped'}) not in the table"
                                   for name_ in ("a3", "a5", "a6", "a8", "a9", "a10")})
    # -- rep string: CBRANCH ADDRESS(next) earlier, BRANCH ADDRESS(start) last (intra-instruction skip + repeat)
    if len(flows) >= 2 and opcodes[-1] == "BRANCH" and _is_address(ops[-1]["inputs"][0]) \
            and ops[-1]["inputs"][0]["offset"] == start and nxt is not None \
            and all(opcodes[i] == "CBRANCH" and _is_address(ops[i]["inputs"][0]) and ops[i]["inputs"][0]["offset"] == nxt
                    for i in flows[:-1]):
        return Lift("rep", {"a3": "sequential" if continuation else "none", "a5": None, "a6": "none", "a8": "none",
                            "a9": "none", "a10": ("none",)}, {}, tuple(flows))
    # -- CMOVcc: one CBRANCH ADDRESS(next) followed by non-flow operations (the conditional move)
    if len(flows) == 1 and opcodes[flows[0]] == "CBRANCH" and flows[0] < len(ops) - 1 and nxt is not None \
            and _is_address(ops[flows[0]]["inputs"][0]) and ops[flows[0]]["inputs"][0]["offset"] == nxt \
            and all(name not in FLOW_OPS for name in opcodes[flows[0] + 1:]):
        return Lift("cmov", {"a3": "sequential" if continuation else "none", "a5": None, "a6": "none", "a8": "none",
                             "a9": "none", "a10": ("none",)}, {}, (flows[0],))
    if not flows:
        return lift("plain", a3="sequential" if continuation else "none", a5=None, a6="none", a8="none", a9="none",
                    a10=("none",))
    last = flows[-1]
    if len(flows) != 1 or last != len(ops) - 1:
        return Lift("unidentified", {}, {name: "unidentified lift" for name in ("a3", "a5", "a6", "a8", "a9", "a10")})
    op = ops[last]
    name = op["opcode"]
    target = op["inputs"][0] if op["inputs"] else None
    if name == "BRANCH" and nxt is None and _push(ops, last, table, space) is not None:
        return Lift("unidentified", {}, {name_: "push + BRANCH without a known next address (no length)"
                                         for name_ in ("a3", "a5", "a6", "a8", "a9", "a10")})
    if name in ("CALL", "CALLIND", "BRANCH") and _push(ops, last, table, space) is not None \
            and (name != "BRANCH" or (_is_address(target) and target["offset"] == nxt)):
        push = _push(ops, last, table, space)
        values = {"a6": "near", "a9": "none", "a10": ("none",), "a11b": push[0], "a11a": push[3],
                  "a7": (push[1], push[2]), "a3": "call-continuation" if continuation else "none"}
        if name == "CALLIND":
            values.update(a8="indirect", a5=None, target_operand_bits=_width_before_extension(ops, target, last))
            memory = _memory_address_bits(ops, target, last - 2)
            if memory is not None:
                values["a11c"] = memory
            unobserved = {} if memory is not None else {"a11c": "indirect target origin not recoverable"}
            return Lift("call indirect", values, unobserved)
        else:   # CALL ADDRESS, or call $+5 lifted as push + BRANCH ADDRESS(next)
            values.update(a8="direct", a5=target["offset"], a11c=NA)
        return Lift("call $+5" if name == "BRANCH" else ("call indirect" if name == "CALLIND" else "call"), values)
    if name in ("CALL", "CALLIND"):
        return Lift("unidentified", {}, {name_: "CALL / CALLIND without the exact near-call push (far call?)"
                                         for name_ in ("a3", "a5", "a6", "a8", "a9", "a10")})
    if not _prefix_ok(ops, last, table):
        return Lift("unidentified", {}, {name_: "operation outside the allowed prefix list"
                                         for name_ in ("a3", "a5", "a6", "a8", "a9", "a10")})
    if name == "BRANCH" and _is_address(target):
        if target["offset"] == start and len(ops) == 1:
            # BRANCH(self) alone: F4 (hlt) and EB FE lift alike -- the origin is not decidable (r4 s1)
            return Lift("branch-self", {"a6": "none", "a9": "none"},
                        {"a5": "origin not decidable from the Ghidra evidence", "a8": "origin not decidable",
                         "a3": "origin not decidable", "a10": "origin not decidable"})
        return lift("jmp", a11c=NA, a3="none" if not continuation else "sequential", a5=target["offset"], a6="none",
                    a8="direct", a9="none", a10=("none",))
    if name == "CBRANCH" and _is_address(target):
        values = {"a3": "sequential" if continuation else "none", "a5": target["offset"], "a6": "none",
                  "a8": "direct", "a9": "none", "a10": ("none",)}
        condition = op["inputs"][1] if len(op["inputs"]) > 1 else None
        for prior in reversed(ops[:last]):
            if prior["output"] == condition and prior["opcode"] in ("INT_EQUAL", "INT_NOTEQUAL"):
                counter = next((item for item in prior["inputs"] if _is_reg(item, RCX)), None)
                if counter is not None:
                    values["a12"] = counter["size"] * 8
                break
        return Lift("jcc", values)
    if name == "BRANCHIND":
        values = {"a3": "none" if not continuation else "sequential", "a5": None, "a6": "none", "a8": "indirect",
                  "a9": "none", "a10": ("none",), "target_operand_bits": _width_before_extension(ops, target, last)}
        memory = _memory_address_bits(ops, target, last)
        if memory is not None:
            values["a11c"] = memory
        return Lift("jmp indirect", values, {} if memory is not None else
                    {"a11c": "indirect target origin not recoverable"})
    if name == "RETURN":
        shape = _ret_shape(ops, space)
        if shape is not None:
            width, immediate = shape
            return lift("ret", a3="none" if not continuation else "sequential", a5=None, a6="none", a8="none",
                        a9="near_imm" if immediate is not None else "near", a10=("none",), a11b=width, a11a=64,
                        ret_imm=immediate)
        return Lift("unidentified", {}, {name_: "RETURN without the exact ret shape"
                                         for name_ in ("a3", "a5", "a6", "a8", "a9", "a10")})
    return Lift("unidentified", {}, {name_: "unidentified lift" for name_ in ("a3", "a5", "a6", "a8", "a9", "a10")})


# Ghidra 12.0.4 listing flow bits expected per voter flow form (r3 s3); isFlow() is always true and
# isUnConditional() is !isConditional(); forms without an independent mapping are not in the table
LISTING_BITS = {
    "none": {"has_fallthrough": True, "is_call": False, "is_jump": False, "is_terminal": False,
             "is_computed": False, "is_conditional": False, "is_flow": True, "is_unconditional": True},
    "call_direct": {"has_fallthrough": True, "is_call": True, "is_jump": False, "is_terminal": False,
                    "is_computed": False, "is_conditional": False, "is_flow": True, "is_unconditional": True},
    "call_indirect": {"has_fallthrough": True, "is_call": True, "is_jump": False, "is_terminal": False,
                      "is_computed": True, "is_conditional": False, "is_flow": True, "is_unconditional": True},
    "jmp_direct": {"has_fallthrough": False, "is_call": False, "is_jump": True, "is_terminal": False,
                   "is_computed": False, "is_conditional": False, "is_flow": True, "is_unconditional": True},
    "jmp_indirect": {"has_fallthrough": False, "is_call": False, "is_jump": True, "is_terminal": False,
                     "is_computed": True, "is_conditional": False, "is_flow": True, "is_unconditional": True},
    "jcc": {"has_fallthrough": True, "is_call": False, "is_jump": True, "is_terminal": False,
            "is_computed": False, "is_conditional": True, "is_flow": True, "is_unconditional": False},
    "ret": {"has_fallthrough": False, "is_call": False, "is_jump": False, "is_terminal": True,
            "is_computed": False, "is_conditional": False, "is_flow": True, "is_unconditional": True},
}


def table_identity(language_id: str, major: int, minor: int, table: dict = TABLE) -> dict:
    """The r4 s2 identity checks a Bundle allows: language id + version from its own program evidence
    (checked), the Ghidra version (the admitted naming sidecar is pinned to it by the engine contract),
    and the compiled-SLEIGH digest -- which no Bundle carries today (missing: only the named premise
    stock-ghidra-translator covers it). ``state``: matched / mismatch / missing-digest."""
    language = (language_id, major, minor)
    checks = {"language": "matched" if language == table["language"] else f"mismatch {language}",
              "ghidra": "matched (admitted naming sidecar, CALL_NAMING_GHIDRA_VERSION)",
              "sla_digest": "missing (not in the Bundle)"}
    state = "mismatch" if language != table["language"] else "missing-digest"
    return {"state": state, "checks": checks, "table": table["id"]}
