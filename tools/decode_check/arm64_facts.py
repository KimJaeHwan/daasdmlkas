"""G2c producer claims from admitted, little-endian A64 Bundle bytes."""

from collections import Counter, defaultdict

import common_facts as cf
import lifting
import producer_override


LEGACY_RULE = "g2c-1"
RULE = "g2c-2"
FILE_RUNTIME_UNOBSERVED = "AArch64 file mapping is outside the G2b survey"
NEXT_PC_MASK = (1 << 64) - 1
CC = "eq ne cs cc mi pl vs vc hi ls ge lt gt le al nv".split()
FLAGS = ("ZR", "ZR", "CY", "CY", "NG", "NG", "OV", "OV", "CY ZR", "CY ZR",
         "NG OV", "NG OV", "ZR NG OV", "ZR NG OV", "", "")

# Arm A-profile A64 instruction encodings (DDI0602). The mask leaves only
# the documented operand bits free. Unsupported encodings stay unobserved.
ENCODINGS = (
    (0xFC000000, 0x14000000, "b"), (0xFC000000, 0x94000000, "bl"),
    (0xFF000010, 0x54000000, "b.cond"),
    (0x7F000000, 0x34000000, "cbz"), (0x7F000000, 0x35000000, "cbnz"),
    (0x7F000000, 0x36000000, "tbz"), (0x7F000000, 0x37000000, "tbnz"),
    (0x7FE00C00, 0x1A800000, "csel"), (0x7FE00C00, 0x1A800400, "csinc"),
    (0x7FE00C00, 0x5A800000, "csinv"), (0x7FE00C00, 0x5A800400, "csneg"),
    (0xFFFFFC1F, 0xD61F0000, "br"), (0xFFFFFC1F, 0xD63F0000, "blr"),
    (0xFFFFFC1F, 0xD65F0000, "ret"),
    (0xFFFFFC00, 0xD71F0800, "braa"), (0xFFFFFC00, 0xD71F0C00, "brab"),
    (0xFFFFFC1F, 0xD61F081F, "braaz"), (0xFFFFFC1F, 0xD61F0C1F, "brabz"),
    (0xFFFFFC00, 0xD73F0800, "blraa"), (0xFFFFFC00, 0xD73F0C00, "blrab"),
    (0xFFFFFC1F, 0xD63F081F, "blraaz"), (0xFFFFFC1F, 0xD63F0C1F, "blrabz"),
    (0xFFFFFFFF, 0xD65F0BFF, "retaa"), (0xFFFFFFFF, 0xD65F0FFF, "retab"),
    (0xFFFFFFFF, 0xD69F03E0, "eret"),
    (0xFFE0001F, 0xD4000001, "svc"), (0xFFE0001F, 0xD4000002, "hvc"),
    (0xFFE0001F, 0xD4000003, "smc"), (0xFFE0001F, 0xD4200000, "brk"),
    (0xFFE0001F, 0xD4400000, "hlt"), (0xFFFF0000, 0x00000000, "udf"),
    (0xFFFFFFFF, 0xD503201F, "nop"),
    (0xFFFFFFFF, 0xD503241F, "bti"), (0xFFFFFFFF, 0xD503245F, "bti_c"),
    (0xFFFFFFFF, 0xD503249F, "bti_j"), (0xFFFFFFFF, 0xD50324DF, "bti_jc"),
    (0xFFFFFFFF, 0xD503211F, "pacia1716"), (0xFFFFFFFF, 0xD503215F, "pacib1716"),
    (0xFFFFFFFF, 0xD503219F, "autia1716"), (0xFFFFFFFF, 0xD50321DF, "autib1716"),
    (0xFFFFFFFF, 0xD503231F, "paciaz"), (0xFFFFFFFF, 0xD503235F, "pacibz"),
    (0xFFFFFFFF, 0xD503233F, "paciasp"), (0xFFFFFFFF, 0xD503237F, "pacibsp"),
    (0xFFFFFFFF, 0xD503239F, "autiaz"), (0xFFFFFFFF, 0xD50323DF, "autibz"),
    (0xFFFFFFFF, 0xD50323BF, "autiasp"), (0xFFFFFFFF, 0xD50323FF, "autibsp"),
    (0xFFFFFFFF, 0xD50320FF, "xpaclri"),
    (0x3FFF7C00, 0x085F7C00, "load_exclusive"),
    (0x3FE07C00, 0x08007C00, "store_exclusive"),
    (0xFFFFF0FF, 0xD503305F, "clrex"),
    (0xFFFFFFE0, 0xD50B7420, "dc_zva"), (0xFFFFFFE0, 0xD50B7B20, "dc_cvau"),
    (0xFFFFFFE0, 0xD50B7520, "ic_ivau"),
    (0xFFFFFFE0, 0xD53B0020, "mrs_ctr_el0"), (0xFFFFFFE0, 0xD53BE040, "mrs_cntvct_el0"),
    (0xFFFFFFE0, 0xD53BD040, "mrs_tpidr_el0"), (0xFFFFFFE0, 0xD51BD040, "msr_tpidr_el0"),
    (0xFFFFFFE0, 0xD53BD060, "mrs_tpidrro_el0"),
    (0xFFFFFFE0, 0xD5381000, "mrs_sctlr_el1"), (0xFFFFFFE0, 0xD5181000, "msr_sctlr_el1"),
)
COND_BITS = {"b.cond": 19, "cbz": 19, "cbnz": 19, "tbz": 14, "tbnz": 14}
SELECT_FALSE_OP = {"csel": "identity", "csinc": "increment", "csinv": "invert", "csneg": "negate"}
CALLS = {"bl", "blr", "blraa", "blrab", "blraaz", "blrabz"}
RETURNS = {"ret", "retaa", "retab"}
TRAPS = {"svc", "hvc", "smc", "brk", "hlt", "udf"}
CACHE = {"dc_cvau", "ic_ivau"}
AUTH_KEYS = {
    "braa": "ia", "braaz": "ia", "blraa": "ia", "blraaz": "ia", "retaa": "ia",
    "brab": "ib", "brabz": "ib", "blrab": "ib", "blrabz": "ib", "retab": "ib",
}
BTI_BRANCHES = ({"br"} | CALLS | AUTH_KEYS.keys()) - ({"bl"} | RETURNS)
BTI_CLASSES = {"bti": [], "bti_c": ["01", "10"], "bti_j": ["01", "11"], "bti_jc": ["01", "10", "11"]}
SYSTEM_CONTROLS = {
    "mrs_ctr_el0": "SCTLR_EL1.UCT", "mrs_cntvct_el0": "CNTKCTL_EL1.EL0VCTEN",
    "dc_zva": "SCTLR_EL1.DZE", "dc_cvau": "SCTLR_EL1.UCI", "ic_ivau": "SCTLR_EL1.UCI",
}


def decode(word, *, rule=RULE):
    for mask, expected, form in ENCODINGS:
        if word & mask == expected:
            if rule == LEGACY_RULE and form in SELECT_FALSE_OP:
                return None
            if form in ("load_exclusive", "store_exclusive"):
                size = ("b", "h", "", "")[word >> 30]
                variants = ("ldxr", "ldaxr") if form == "load_exclusive" else ("stxr", "stlxr")
                return variants[(word >> 15) & 1] + size
            return form
    return None


def signed(value, width):
    sign = 1 << (width - 1)
    return (value & (sign - 1)) - (value & sign)


def pre(reg, width):
    if not reg or reg["size"] * 8 != width:
        return cf.U("no validated register identity")
    return {"pre_register": reg, "width": width}


def gp(regs, number, width=64, *, sp=False):
    if number == 31 and not sp:
        return {"constant": "0", "width": width}
    name = ("sp" if width == 64 else "wsp") if number == 31 else ("x" if width == 64 else "w") + str(number)
    return pre(regs.get(name), width)


def flag_test(cc, regs):
    inputs = [pre(regs.get(name), 8) for name in FLAGS[cc].split()]
    if any(cf.unknown(part) for part in inputs):
        inputs = cf.U("no validated flag identity")
    return {"flags": CC[cc], "inputs": inputs}


def cond(form, word, regs):
    if form == "b.cond":
        test = flag_test(word & 15, regs)
    else:
        width = 64 if word >> 31 else 32
        operand = gp(regs, word & 31, width)
        if form in ("tbz", "tbnz"):
            bit = ((word >> 19) & 31) + (width - 32)
            test = {"bit_clear" if form == "tbz" else "bit_set": [operand, bit]}
        else:
            test = {"zero" if form == "cbz" else "nonzero": operand}
    return {"taken_when": "true", "test": test}


def value_select(form, word, regs):
    """An encoding-derived value claim. Arithmetic in either arm uses the operand width."""
    width = 64 if word >> 31 else 32
    rd, rn, rm = word & 31, (word >> 5) & 31, (word >> 16) & 31
    cc = (word >> 12) & 15
    # A64 ConditionHolds treats both AL and NV as true. Alias spellings such
    # as CINC invert the displayed condition; use the encoded bits here.
    predicate = {"constant": True, "encoded_condition": CC[cc]} if cc >= 14 else flag_test(cc, regs)
    destination = None  # Rd == 31 discards the selected value.
    if rd != 31:
        register = gp(regs, rd)
        destination = dict(register=register.get("pre_register", register),
                           extension="zero_extend" if width == 32 else "identity")
    return dict(width=width, destination=destination, condition=predicate, when_true=gp(regs, rn, width),
                when_false=dict(operation=SELECT_FALSE_OP[form], operand=gp(regs, rm, width)))


def condition(what, source):
    return dict(what=what, source=source, state="unknown")


def isa_fact(kind, value, *conditions):
    return dict(kind=kind, value=value, conditions=list(conditions))


def auth(form, word, regs):
    key = AUTH_KEYS[form]
    modifier = (gp(regs, 31, sp=True) if form in RETURNS else {"constant": "0", "width": 64}
                if form.endswith("z") else gp(regs, word & 31, sp=True))
    return dict(key=key, modifier=modifier, conditions=[
        condition("FEAT_PAuth", "profile"), condition("SCTLR_ELx.En" + key.upper(), "os_model"),
    ], on_failure="F3")


def pac_failure(combined):
    feature = "FEAT_FPACCOMBINE" if combined else "FEAT_FPAC"
    return isa_fact("F3", {"on_authentication_failure": "profile-dependent fault or failed pointer"},
                    condition(feature, "profile"), condition("authentication is enabled", "os_model"))


def overridden(f):
    profile = f.get("override")
    return f["flow"].get("is_override") or profile is not None and producer_override.present(profile)


def observed_ordinary(f, word):
    major = (word >> 25) & 15
    flow, ops = f["flow"], f["ops"]
    return (major in (4, 5, 6, 7, 8, 9, 12, 13, 14, 15) and flow["has_fallthrough"]
            and not any(flow.get(k) for k in ("is_call", "is_jump", "is_terminal", "is_computed", "is_conditional"))
            and not (f.get("flow_target_coords") or f.get("external_flow_targets"))
            and (f["fallthrough_space"], f["fallthrough"]) == (f["space"], (f["address"] + 4) & NEXT_PC_MASK)
            and not overridden(f) and bool(ops)
            and all(o["opcode"] not in lifting.FLOW_OPS and o["opcode"] != "UNIMPLEMENTED" for o in ops))


def edge(role, to):
    return dict(zip(cf.EC, role), to=to)


def pc(f, delta):
    return cf.addr(f["space"], (f["address"] + delta) & NEXT_PC_MASK)


def empty_transfer():
    return dict(kind="unknown", edges=[], condition=None, target_value=None, target_auth=None, link_write=None,
                op_keys=dict(transfer=None, entry_ordinal=None, **{key: [] for key in
                    ("target", "condition", "auth", "link", "sp_adjust", "setup",
                     "transient", "persistent", "encoding_only")}), hint=None)


def matches_address(operand, address):
    return (operand is not None and operand["kind"] == "ADDRESS"
            and operand["size"] == 8 and operand["space"] == address["space"]
            and operand["offset"] == int(address["offset"], 16))


def attach_ops(transfer, form, f, regs, target=None):
    ops, keys = f["ops"], transfer["op_keys"]
    if not ops or overridden(f):
        return
    op = ops[-1]
    name, args = op["opcode"], op["inputs"]
    position = len(ops) - 1
    if form == "b" or form in COND_BITS:
        wanted = "BRANCH" if form == "b" else "CBRANCH"
        if (name != wanted or len(args) != (1 if form == "b" else 2)
                or not matches_address(args[0], target)
                or any(p["opcode"] in lifting.FLOW_OPS for p in ops[:-1])):
            return
    elif form in CALLS:
        shape = cf.arm_shape(f, regs)
        if shape is None or shape[0] != int(pc(f, 4)["offset"], 16):
            return
        if form == "bl":
            if name != "CALL" or len(args) != 1 or not matches_address(args[0], target):
                return
        elif name != "CALLIND" or not cf.same_reg(ops[0]["inputs"][0], target.get("pre_register")):
            return
        if not shape[1]:
            transfer["link_write"].update(relocation="unknown", derivation="constant")
        keys["link"] = keys["persistent"] = [cf.opref(ops, position - 1)]
        if name == "CALLIND":
            keys["target"] = [cf.opref(ops, 0)]
    elif form in BTI_BRANCHES or form in RETURNS:
        if name not in ("BRANCHIND", "RETURN") or len(args) != 1 or len(ops) != 2:
            return
        capture = ops[0]
        if (capture["opcode"] != "COPY" or not cf.same_reg(capture["output"], regs.get("pc"))
                or args != [capture["output"]] or len(capture["inputs"]) != 1
                or not cf.same_reg(capture["inputs"][0], target.get("pre_register"))):
            return
        keys["target"] = [cf.opref(ops, 0)]
    else:
        return
    keys.update(transfer=cf.opref(ops, position), entry_ordinal=position,
                setup=[cf.opref(ops, i) for i in range(position)])
    transfer["hint"] = {"CALL": "call", "CALLIND": "call", "RETURN": "return"}.get(name, "jump")


def link(f, regs):
    location = regs.get("lr")
    return dict(location={"register": location} if location else cf.U("no validated x30"),
                value={"width": 64, "bits": pc(f, 4)["offset"]}, sp_delta=0, continuation=pc(f, 4),
                relocation="instruction_relative", derivation="pc_plus_4")


def transfer_for(form, word, f, regs):
    transfer = empty_transfer()
    kind, edges, target = "none", [edge(cf.SEQ, pc(f, 4))], None
    if form in ("b", "bl") or form in COND_BITS:
        conditional = form in COND_BITS
        width = COND_BITS.get(form, 26)
        target = pc(f, signed(word >> (5 if conditional else 0), width) * 4)
        kind, edges = "direct", [edge(cf.DIRECT, target)]
        if conditional:
            kind, edges = "conditional", [edge(cf.TAKEN, target), edge(cf.NEXT, pc(f, 4))]
            transfer["condition"] = cond(form, word, regs)
    elif form in BTI_BRANCHES or form in RETURNS or form == "eret":
        kind, edges = "indirect", [edge(cf.IND, None)]
        target = gp(regs, 30 if form in ("retaa", "retab") else (word >> 5) & 31)
        if form == "eret":
            target = cf.U("current EL and ELR_ELx are unobserved")
        transfer["target_value"] = target
    elif form in TRAPS:
        kind, edges = "trap", [edge(cf.OS, None)]
        if form == "udf":
            transfer["exception_basis"] = "defined_ud"
        else:
            saved = pc(f, 4) if form == "svc" else pc(f, 0) if form == "brk" else None
            edges.append(edge(cf.SAVED, saved))

    if form in CALLS:
        transfer["link_write"] = link(f, regs)
    if form in AUTH_KEYS:
        transfer["target_auth"] = auth(form, word, regs)
    transfer.update(kind=kind, edges=edges)
    attach_ops(transfer, form, f, regs, target)
    keys = transfer["op_keys"]
    keys["encoding_only"] = [key for key, role in (
        ("condition", "condition"), ("target_value", "target"), ("target_auth", "auth"), ("link_write", "link"),
    ) if transfer[key] is not None and not keys[role]]
    return transfer


def exclusive(form, word, regs):
    if form == "clrex" or form.startswith("ld"):
        return dict(monitor="clear" if form == "clrex" else "set",
                    conditional_store=[], status_output=None, unsupported=[])
    status, base, source = (word >> 16) & 31, (word >> 5) & 31, word & 31
    # A Bundle does not bind ARM CALLOTHER indices to the exclusive monitor
    # userops. A STORE after an internal CBRANCH alone is insufficient.
    result = dict(monitor="clear", conditional_store=cf.U("exclusive monitor userop identity unobserved"),
                  status_output=None if status == 31 else cf.U("exclusive status userop identity unobserved"),
                  encoded_status_register=None if status == 31 else gp(regs, status, 32),
                  unsupported=[])
    if status == source or (status == base and base != 31):
        result.update(monitor=cf.U("constrained unpredictable register overlap"),
                      unsupported=["constrained unpredictable register overlap"])
    return result


def isa_for(form, word, regs):
    if form in AUTH_KEYS:
        facts = [isa_fact("F1", "undefined without FEAT_PAuth", condition("FEAT_PAuth", "profile")),
                 pac_failure(combined=True)]
        if form in ("retaa", "retab"):
            facts.append(isa_fact("F4", {"secondary_modifier": cf.U("FEAT_PAuth_LR/PACM state unobserved")},
                                  condition("FEAT_PAuth_LR", "profile"), condition("PSTATE.PACM", "os_model")))
        return facts
    if form.startswith(("bti", "pac", "aut", "xpaclri")):
        feature = "FEAT_BTI" if form.startswith("bti") else "FEAT_PAuth"
        facts = [isa_fact("F4", "hint acts as NOP without " + feature, condition(feature, "profile"))]
        if form.startswith("aut"):
            facts.append(pac_failure(combined=False))
        return facts
    if form in ("svc", "brk"):
        return [isa_fact("F3", "saved_next_pc" if form == "svc" else "saved_current_pc",
                         condition("taken as encoded trap", "os_model"))]
    if form == "hlt":
        return [isa_fact("F2", "debug halt or undefined", condition("external debug enabled", "os_model")),
                isa_fact("F3", "saved PC unobserved", condition("execution path", "os_model"))]
    if form in ("eret", "hvc", "smc"):
        return [isa_fact("F2", "requires EL1 or higher", condition("current EL", "el"),
                         *([condition(form.upper() + " enabled", "os_model")] if form != "eret" else []))]
    if form.startswith(("ldxr", "ldaxr", "stxr", "stlxr")) or form == "clrex":
        details = exclusive(form, word, regs)
        facts = [isa_fact("exclusive", details, condition("completed instruction", "profile"))]
        if details["unsupported"]:
            status = (word >> 16) & 31
            alternatives = ["undefined", "nop"]
            if status == word & 31:
                alternatives.append("unknown stored data")
            if status == (word >> 5) & 31 and status != 31:
                alternatives.append("unknown address")
            facts.append(isa_fact("F1", dict(classification="constrained_unpredictable", alternatives=alternatives)))
        return facts
    if form in SYSTEM_CONTROLS:
        return [isa_fact("F2", form, condition(SYSTEM_CONTROLS[form], "os_model"), condition("current EL", "el")),
                *([isa_fact("F6", "system-register read")] if form.startswith("mrs") else [])]
    if form in ("mrs_sctlr_el1", "msr_sctlr_el1"):
        return [isa_fact("F2", "SCTLR_EL1 access requires EL1 or higher", condition("current EL", "el")),
                *([isa_fact("F6", "system-register read")] if form.startswith("mrs") else [])]
    if form in ("mrs_tpidr_el0", "msr_tpidr_el0", "mrs_tpidrro_el0"):
        facts = [isa_fact("F7", form, condition("hardware access controls permitting", "os_model"))]
        if form.startswith("mrs"):
            facts.append(isa_fact("F6", "system-register read"))
        return facts
    return []


class Arm64Facts:
    def __init__(self, blocks, registers, roles):
        self.blocks = defaultdict(list)
        for block, data in blocks:
            self.blocks[block["space_id"]].append((block, data))
        self.registers = registers | roles

    def basis(self, f):
        start = f["address"]
        # Older exporters omit the instruction length. The A64 word still has
        # four bytes; a conflicting concrete length is a different observation.
        if f["length"] not in (None, 4) or start % 4 or not 0 <= start <= NEXT_PC_MASK - 3:
            return cf.U("expected aligned four-byte row")
        end = start + 4
        overlaps = [(b, data) for b, data in self.blocks[f["space"]]
                    if b["byte_start"] < end and b["byte_start"] + b["byte_size"] > start]
        if len(overlaps) != 1:
            return cf.U("ambiguous overlapping sealed blocks" if overlaps else "no sealed instruction bytes")
        (b, data), = overlaps
        offset = start - b["byte_start"]
        if (offset < 0 or data is None or offset + 4 > len(data) or offset + 4 > b["byte_size"]
                or not b["is_initialized"] or not b["is_loaded"]
                or any(b[key] for key in ("is_overlay", "is_mapped", "is_external"))):
            return cf.U("no single eligible sealed block covers the instruction")
        word = int.from_bytes(data[offset:offset + 4], "little")
        return dict(source="sealed_bundle_bytes", member_id=b["member_id"], offset=offset, size=4, word=f"{word:08x}")

    def row(self, f, fid, *, rule=RULE):
        basis = self.basis(f)
        row = cf.derive_row(f, None, fid, self.registers)
        capsule = dict(form=cf.U("instruction bytes unavailable"), basis=basis)
        if cf.unknown(basis):
            if basis["unobserved"] == "expected aligned four-byte row":
                row["transfer"] = empty_transfer()
            elif row["transfer"]["link_write"] is not None:
                capsule["observation"] = "ghidra_pcode"
        else:
            word = int(basis["word"], 16)
            form = decode(word, rule=rule)
            row["bytes"]["range"] = cf.interval(f, 4)
            if form:
                capsule["form"] = form
                row["transfer"] = transfer_for(form, word, f, self.registers)
                row["isa"] = isa_for(form, word, self.registers)
                if form in SELECT_FALSE_OP:
                    capsule["value_select"] = value_select(form, word, self.registers)
            else:
                capsule["form"] = cf.U("encoding outside supported A64 forms")
                row["transfer"] = empty_transfer()
                if observed_ordinary(f, word):
                    capsule["observation"] = "ghidra_pcode"
                    row["transfer"].update(kind="none", edges=[edge(cf.SEQ, pc(f, 4))])
        row["aarch64"] = capsule
        return row

    def check_document(self, document, observations, complete):
        """Replay claim construction from admitted bytes and register identities."""
        if type(complete) is not bool:
            raise ValueError("missing AArch64 observation completeness")
        rule = document["producer"]["rule"]
        rows = [self.row(observations[key], key[1], rule=rule) for key in sorted(observations)]
        cf.finish_landings(rows, complete)
        fragments, _ = program_fragments(rows, observations)
        program = dict(document["program"], aarch64=fragments, tbi=tbi(), code=cf.U(FILE_RUNTIME_UNOBSERVED),
                       stack_register=self.registers.get("sp") or cf.U("no validated stack register"))
        rebuilt = dict(document, program=program, rows=rows)
        if cf.streamed_digest(document) != cf.streamed_digest(rebuilt):
            raise ValueError("G2c claims differ from admitted inputs")


def tbi():
    return {half: dict(tbi_data="unknown", tbi_instruction="unknown") for half in ("ttbr0", "ttbr1")}


def bti_context(source, target):
    form = source["aarch64"]["form"]
    rn = (int(source["aarch64"]["basis"]["word"], 16) >> 5) & 31
    landing = target["aarch64"]["form"]
    if not isinstance(landing, str):
        landing = cf.U("target form not identified")
    unknown_guard = dict(page=cf.U("page size unobserved"), elf_property=cf.U("ELF property unobserved"),
                         effective=cf.U("OS guarded-page state unobserved"))
    conditions = [condition("FEAT_BTI", "profile")]
    accepts = cf.U("target compatibility outside the supported landing forms")
    if landing in ("paciasp", "pacibsp"):
        conditions.append(condition("SCTLR_ELx.BTx", "os_model"))
        accepts = {"SCTLR_ELx.BTx=0": BTI_CLASSES["bti_jc"], "SCTLR_ELx.BTx=1": BTI_CLASSES["bti_c"]}
    elif isinstance(landing, str) and landing in BTI_CLASSES:
        accepts = BTI_CLASSES[landing]
    elif landing == "nop":
        accepts = []
    btype = {"guarded": "10", "unguarded": "10"} if form in CALLS else {
        "guarded": "01" if rn in (16, 17) else "11", "unguarded": "01"}
    return dict(source_row=cf.ref(source), target_row=cf.ref(target), target_basis="producer_flow_target",
                branch_kind=form, branch_register=rn,
                source_guard=unknown_guard, target_guard=unknown_guard, btype=btype,
                landing_instruction=landing, guarded_landing_accepts=accepts, conditions=conditions,
                verdict=cf.U("effective BTI state unobserved"))


def program_fragments(rows, raw):
    locations = defaultdict(list)
    for row in rows:
        locations[row["space"], int(row["offset"], 16)].append(row)
    counts, unknown, observed = Counter(), Counter(), Counter()
    surveys = {kind: [] for kind in ("trap_instruction", "cache_maintenance")}
    unexamined = defaultdict(list)
    pairs, gaps = [], []
    for row in rows:
        a64 = row["aarch64"]
        form, basis = a64["form"], a64["basis"]
        at = cf.ref(row)
        if not isinstance(form, str):
            reason = basis["unobserved"] if cf.unknown(basis) else form["unobserved"]
            unknown[reason] += 1
            if "observation" in a64:
                observed[row["transfer"]["kind"]] += 1
            unexamined[reason].append(at)
            continue
        counts[form] += 1
        if form in TRAPS or form in CACHE:
            kind = "trap_instruction" if form in TRAPS else "cache_maintenance"
            site = dict(row=at, form=form, basis=basis, holds_if=[cf.PREMISE])
            if form in TRAPS:
                word = int(basis["word"], 16)
                site.update(vector=None, immediate=(word if form == "udf" else word >> 5) & 0xFFFF,
                            syscall_abi=cf.U("no syscall ABI evidence") if form == "svc" else None)
            surveys[kind].append(site)
        if form in BTI_BRANCHES:
            f = raw[cf.rr(row)]
            targets = () if overridden(f) else f["flow_target_coords"]
            if not targets:
                gaps.append(dict(source_row=at, reason="no eligible observed indirect target"))
            pads = f.get("recorded_landing_pads")
            for coordinate in targets:
                if (pads is None and form in CALLS) or (pads is not None and tuple(coordinate) in pads):
                    gaps.append(dict(source_row=at, target=cf.addr(*coordinate),
                                     reason="target may be an exception landing pad"))
                    continue
                candidates = [r for r in locations[tuple(coordinate)] if r["view"] == row["view"]]
                if not candidates:
                    gaps.append(dict(source_row=at, target=cf.addr(*coordinate), reason="no target row in this view"))
                pairs.extend(bti_context(row, candidate) for candidate in candidates)
    report = dict(rows=len(rows), forms=dict(counts), unsupported=dict(unknown), pcode_only=dict(observed),
                  bti_pairs=len(pairs), bti_unresolved=dict(Counter(g["reason"] for g in gaps)),
                  sites={k: len(sites) for k, sites in surveys.items()})
    survey = dict(basis="sealed_bundle_bytes", examined=sum(counts.values()), sites=surveys,
                  unexamined=[dict(reason=reason, rows=refs) for reason, refs in sorted(unexamined.items())])
    return dict(branch_target_check=dict(pairs=pairs, unresolved=gaps), survey=survey), report
