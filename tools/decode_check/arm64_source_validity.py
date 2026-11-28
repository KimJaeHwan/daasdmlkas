"""Instruction-specific decode rejections from the pinned Arm A64 diagrams."""

RULE = "arm-a64-undefined-operands-1"

_LSE128 = "FEAT_LSE128"
_D128_THE = "FEAT_D128 && FEAT_THE"
_SVE_OR_SME = "FEAT_SVE || FEAT_SME"

# The A and R bits select the four acquire/release variants in each XML file.
_ATOMIC_ENCODINGS = {
    (f"{name}{suffix}_128_memop_128", f"{name.lower()}.xml", feature): opcode | order
    for name, opcode, feature in (
        ("LDCLRP", 0x19201000, _LSE128),
        ("LDSETP", 0x19203000, _LSE128),
        ("SWPP", 0x19208000, _LSE128),
        ("RCWCLRP", 0x19209000, _D128_THE),
        ("RCWSWPP", 0x1920a000, _D128_THE),
        ("RCWSETP", 0x1920b000, _D128_THE),
        ("RCWSCLRP", 0x59209000, _D128_THE),
        ("RCWSSWPP", 0x5920a000, _D128_THE),
        ("RCWSSETP", 0x5920b000, _D128_THE),
    )
    for suffix, order in (("", 0), ("A", 1 << 23), ("L", 1 << 22), ("AL", 3 << 22))
}

_SVE_IMMEDIATE_ENCODINGS = {
    ("sve_int_dup_imm_pred", "cpy_z_o_i_", "cpy_z_o_i.xml"): (0xff30c000, 0x05100000),
    ("sve_int_dup_imm_pred", "cpy_z_p_i_", "cpy_z_p_i.xml"): (0xff30c000, 0x05104000),
    ("sve_int_dup_imm", "dup_z_i_", "dup_z_i.xml"): (0xff3fc000, 0x2538c000),
}


def undefined_encoding(word, index):
    """Return a static UNDEFINED verdict for a matched, audited operand rule."""
    if len(index["candidates"]) != 1 or index.get("exclusions"):
        return None
    encoding, = index["candidates"]
    section, name, file = (encoding.get(key) for key in ("section", "id", "file"))
    feature = encoding.get("feature_condition")

    if section == "memop_128":
        opcode = _ATOMIC_ENCODINGS.get((name, file, feature))
        if opcode is None or word & 0xffe0fc00 != opcode:
            return None
        fields = {"Rt": word & 31, "Rt2": word >> 16 & 31}
        if 31 not in fields.values():
            return None
        reason = "atomic-data-register-31"
    else:
        form = _SVE_IMMEDIATE_ENCODINGS.get((section, name, file))
        if form is None or feature != _SVE_OR_SME:
            return None
        mask, opcode = form
        if word & mask != opcode:
            return None
        fields = {"size": word >> 22 & 3, "sh": word >> 13 & 1}
        if fields["size"] != 0 or fields["sh"] != 1:
            return None
        reason = "sve-byte-immediate-shift"

    return dict(kind="undefined-operand-encoding", verdict="UNDEFINED", rule=RULE,
                encoding=encoding, reason=reason, fields=fields)
