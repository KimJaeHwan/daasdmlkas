"""Arm-encoding facts for a bounded set of original-word verification rules."""

import re

from arm64_facts import condition, signed


RULE = "arm-a64-source-facts-1"
EXTENDED_RULE = "arm-a64-source-facts-2"
_ADDRESS = re.compile(r"\[(\w+),([wx]\w+)(?:,(lsl|uxtw|sxtw|sxtx)(?:#(\d+))?)?\]")
_IMMEDIATE_ADDRESS = re.compile(r"\[(\w+)(?:,#(-?\d+))?\]")
_MOVE_DESTINATION = r"([wx](?:[0-9]|[12][0-9]|30|zr))"
_MOVE_ALIAS = re.compile(_MOVE_DESTINATION + r",#(-?\d+)")
_MOVE_WIDE = re.compile(_MOVE_DESTINATION + r",#(\d+)(?:,lsl#(\d+))?")
_VECTOR_BASE = re.compile(r"\[(\w+)(?:,#(-?\d+),mulvl)?\]")
_ELEMENTS = {16: "h", 32: "s", 64: "d"}
_INDEX_EXTENSIONS = {2: "uxtw", 3: "lsl", 6: "sxtw", 7: "sxtx"}
_FMOPA = {
    "fmopa_za_pp_zz_32": (0xffe0001c, 0x80800000, 32, 3, "FEAT_SME"),
    "fmopa_za_pp_zz_64": (0xffe00018, 0x80c00000, 64, 7, "FEAT_SME_F64F64"),
}
_LD1W = {
    "ld1w_z_p_bi_u32": (0xa540a000, 32),
    "ld1w_z_p_bi_u64": (0xa560a000, 64),
}


def _gpr(name):
    return dict(register=name, width_bits=32 if name.startswith("w") else 64)


def _operand(name, role, **shape):
    return dict(register=name, role=role, **shape)


def _facts(encoding, mnemonic, runtime_check=None):
    requirements = []
    if encoding["feature_condition"] is not None:
        requirements.append(condition(encoding["feature_condition"], "profile"))
    if runtime_check is not None:
        requirements.append(condition(runtime_check, "os_model"))
    return dict(encoding=encoding["id"], mnemonic=mnemonic, conditions=requirements)


def _indexed_address(word, extension, scale):
    rn, rm = word >> 5 & 31, word >> 16 & 31
    prefix = "w" if extension in ("uxtw", "sxtw") else "x"
    index = prefix + ("zr" if rm == 31 else str(rm))
    return dict(kind="base-plus-extended-index", width_bits=64, base=_gpr("sp" if rn == 31 else f"x{rn}"),
                index=_gpr(index), extension=extension, shift=scale if word & 0x1000 else 0)


def _scalar_operand(size, opc, register_id):
    if (opc == 3 and size >= 2) or (opc == 2 and size == 3):
        return None
    width = 64 if opc == 2 or size == 3 else 32
    suffix = ("sb", "sh", "sw")[size] if opc >= 2 else ("b", "h", "", "")[size]
    mnemonic = ("ldr" if opc else "str") + suffix
    register = ("x" if width == 64 else "w") + ("zr" if register_id == 31 else str(register_id))
    return mnemonic, suffix, _operand(register, "destination" if opc else "source", width_bits=width)


def _offset_fields(word, encoding):
    if encoding["section"] != "ldst_regoff":
        return None
    option = _INDEX_EXTENSIONS.get(word >> 13 & 7)
    if option is None:
        return None
    is_prefetch = word & 0xffe00c00 == 0xf8a00800
    if is_prefetch:
        if (encoding["id"], encoding["file"], encoding["feature_condition"]) != (
                "PRFM_P_ldst_regoff", "prfm_reg.xml", None) or word & 0x18 == 0x18:
            return None
        address = _indexed_address(word, option, 3)
        return dict(_facts(encoding, "prfm"), address=address), {"address": address}

    layout = word & 0x3f200c00
    size, opc, register_id = word >> 30, word >> 22 & 3, word & 31
    if layout == 0x3c200800:
        if opc >= 2 and size:
            return None
        scale = 4 if opc >= 2 else size
        mnemonic = "ldr" if opc & 1 else "str"
        tag = "BHSDQ"[scale]
        register, width = f"{tag.lower()}{register_id}", 8 << scale
        filename, feature, check = f"{mnemonic}_reg_fpsimd.xml", "FEAT_FP", "AArch64_CheckFPEnabled"
    elif layout == 0x38200800:
        scalar = _scalar_operand(size, opc, register_id)
        if scalar is None:
            return None
        mnemonic, suffix, operand = scalar
        scale = size
        register, width = operand["register"], operand["width_bits"]
        tag = str(width) + ("B" if scale == 0 else "")
        register = ("x" if width == 64 else "w") + ("zr" if register_id == 31 else str(register_id))
        filename, feature, check = f"{mnemonic}_reg{'_gen' if not suffix else ''}.xml", None, None
    else:
        return None
    if scale == 0 and option == "lsl":
        tag += "L"
    expected = f"{mnemonic.upper()}_{tag}_ldst_regoff", filename, feature
    if (encoding["id"], encoding["file"], encoding["feature_condition"]) != expected:
        return None
    operand = _operand(register, "destination" if mnemonic.startswith("ldr") else "source", width_bits=width)
    address = _indexed_address(word, option, scale)
    facts = dict(_facts(encoding, mnemonic, check), operands=[operand], address=address, transfer_width_bits=8 << scale)
    return facts, {"operands": register, "address": address}


def _unsigned_offset(word, encoding):
    if encoding["section"] != "ldst_pos" or word & 0x3f000000 != 0x39000000:
        return None
    size, opc, rn = word >> 30, word >> 22 & 3, word >> 5 & 31
    scalar = _scalar_operand(size, opc, word & 31)
    if scalar is None:
        return None
    mnemonic, suffix, operand = scalar
    expected = (f"{mnemonic.upper()}_{operand['width_bits']}_ldst_pos",
                f"{mnemonic}_imm{'_gen' if not suffix else ''}.xml", None)
    if (encoding["id"], encoding["file"], encoding["feature_condition"]) != expected:
        return None
    base = "sp" if rn == 31 else f"x{rn}"
    address = dict(kind="base-plus-immediate", width_bits=64, base=_gpr(base),
                   displacement_bytes=(word >> 10 & 0xfff) << size)
    facts = dict(_facts(encoding, mnemonic), operands=[operand], address=address, transfer_width_bits=8 << size)
    return facts, {"operands": operand["register"], "address": address}


def _move_wide(word, encoding):
    if encoding["section"] != "movewide":
        return None
    name = {0x12800000: "movn", 0x52800000: "movz"}.get(word & 0x7f800000)
    width, hw = 64 if word >> 31 else 32, word >> 21 & 3
    if name is None or width == 32 and hw >= 2:
        return None
    expected = (f"{name.upper()}_{width}_movewide", f"{name}.xml", None)
    if (encoding["id"], encoding["file"], encoding["feature_condition"]) != expected:
        return None
    rd, immediate, shift = word & 31, word >> 5 & 0xffff, hw * 16
    register = ("x" if width == 64 else "w") + ("zr" if rd == 31 else str(rd))
    value = _move_value(name, width, immediate, shift)
    facts = dict(_facts(encoding, name), operands=[_operand(register, "destination", width_bits=width)],
                 immediate=dict(width_bits=width, value_hex=hex(value), encoded_value=immediate, shift=shift))
    return facts, {"operands": register, "immediate_value": (width, value), "immediate_encoding": (immediate, shift)}


def _move_value(name, width, immediate, shift):
    value = immediate << shift
    return ((1 << width) - 1) ^ value if name == "movn" else value


def _vectors(encoding, name, operands, display, check):
    return dict(_facts(encoding, name, check), operands=operands), {"operands": display}


def _vector_fields(word, encoding):
    identifier = encoding["id"]
    file_feature = encoding["file"], encoding["feature_condition"]
    zd, zn, zm = word & 31, word >> 5 & 31, word >> 16 & 31
    if identifier in _FMOPA:
        mask, value, bits, tile_mask, feature = _FMOPA[identifier]
        if word & mask != value or file_feature != ("fmopa_za_pp_zz.xml", feature):
            return None
        tile, pn, pm = f"za{word & tile_mask}", f"p{word >> 10 & 7}", f"p{word >> 13 & 7}"
        zn, zm = f"z{zn}", f"z{zm}"
        suffix = _ELEMENTS[bits]
        operands = [_operand(tile, "accumulator", element_bits=bits, vector_length="SVL"),
                    _operand(pn, "row-predicate", predicate_mode="merge", granularity_bits=bits),
                    _operand(pm, "column-predicate", predicate_mode="merge", granularity_bits=bits),
                    _operand(zn, "row-source", element_bits=bits, vector_length="SVL"),
                    _operand(zm, "column-source", element_bits=bits, vector_length="SVL")]
        return _vectors(encoding, "fmopa", operands, f"{tile}.{suffix},{pn}/m,{pm}/m,{zn}.{suffix},{zm}.{suffix}",
                        "CheckStreamingSVEAndZAEnabled")
    if (identifier == "zero_za_i_" and word & 0xffffff00 == 0xc0080000
            and file_feature == ("zero_za_i.xml", "FEAT_SME")):
        mask = word & 255
        tiles = [f"za{i}" for i in range(8) if mask >> i & 1]
        return dict(_facts(encoding, "zero", "CheckSMEAndZAEnabled"), tile_mask=mask, operands=[
            _operand(tile, "destination", element_bits=64, vector_length="SVL") for tile in tiles
        ]), {"tile_mask": mask}
    if (identifier == "bfmmla_z_zzz_" and word & 0xffe0fc00 == 0x6460e400
            and file_feature == ("bfmmla_z_zzz.xml", "FEAT_SVE && FEAT_BF16")):
        operands = [_operand(f"z{n}", role, element_bits=bits, vector_length="VL")
                    for n, role, bits in ((zd, "accumulator", 32), (zn, "source", 16), (zm, "source", 16))]
        return _vectors(encoding, "bfmmla", operands, f"z{zd}.s,z{zn}.h,z{zm}.h", "CheckNonStreamingSVEEnabled")
    if (identifier == "bfcvt_z_p_z_s2bf" and word & 0xffffe000 == 0x658aa000
            and file_feature == ("bfcvt_z_p_z.xml", "(FEAT_SVE && FEAT_BF16) || (FEAT_SME && FEAT_BF16)")):
        pg = f"p{word >> 10 & 7}"
        operands = [_operand(f"z{zd}", "destination", element_bits=16, vector_length="VL"),
                    _operand(pg, "predicate", predicate_mode="merge", granularity_bits=32),
                    _operand(f"z{zn}", "source", element_bits=32, vector_length="VL")]
        return _vectors(encoding, "bfcvt", operands, f"z{zd}.h,{pg}/m,z{zn}.s", "CheckSVEEnabled")
    if (identifier == "BFCVTN_asimdmisc_4S" and word & 0xbffffc00 == 0x0ea16800
            and file_feature == ("bfcvtn_advsimd.xml", "FEAT_BF16")):
        upper = bool(word & 0x40000000)
        name, lanes = ("bfcvtn2", 8) if upper else ("bfcvtn", 4)
        operands = [_operand(f"v{zd}", "destination", element_bits=16, lanes=lanes,
                             result_part="upper64" if upper else "lower64"),
                    _operand(f"v{zn}", "source", element_bits=32, lanes=4)]
        return _vectors(encoding, name, operands, f"v{zd}.{lanes}h,v{zn}.4s", "AArch64_CheckFPAdvSIMDEnabled")
    return None


def _vector_load(word, encoding):
    identifier = encoding["id"]
    if identifier not in _LD1W or (encoding["file"], encoding["feature_condition"]) != (
            "ld1w_z_p_bi.xml", "FEAT_SVE || FEAT_SME"):
        return None
    value, bits = _LD1W[identifier]
    if word & 0xfff0e000 != value:
        return None
    target, pg, rn = f"z{word & 31}", f"p{word >> 10 & 7}", word >> 5 & 31
    base, imm = ("sp" if rn == 31 else f"x{rn}"), signed(word >> 16 & 15, 4)
    # AddressAdd(base, imm * (CurrentVL()/esize) * mbytes), before per-lane predication.
    address = dict(kind="base-plus-scaled-vector-length", base=_gpr(base), width_bits=64, multiplier=imm,
                   vector_length="CurrentVL", lane_width_bits=bits, bytes_per_lane=4, scope="contiguous-start")
    operands = [_operand(target, "destination", element_bits=bits, vector_length="VL"),
                _operand(pg, "predicate", predicate_mode="zero", granularity_bits=bits)]
    facts = dict(_facts(encoding, "ld1w", "CheckSVEEnabled"), operands=operands, address=address,
                 transfer_width_bits=32)
    return facts, {"operands": f"{{{target}.{_ELEMENTS[bits]}}},{pg}/z", "address": (base, imm)}


def common_fields(word, index, *, rule=RULE):
    """Read modeled fields from sealed Arm candidates and exact instruction bits."""
    if len(index["candidates"]) != 1 or index.get("exclusions"):
        return None
    encoding, = index["candidates"]
    original = _offset_fields(word, encoding) or _vector_fields(word, encoding) or _vector_load(word, encoding)
    if original is not None or rule == RULE:
        return original
    return _move_wide(word, encoding) or _unsigned_offset(word, encoding)


def _observed(fields, mnemonic, rendered):
    if rendered is None:
        return {}
    if "immediate_value" in fields:
        return _observed_move(mnemonic, rendered)
    if (rendered["form"] != mnemonic
                            and not (mnemonic.startswith("bfcvtn") and rendered["form"].startswith("bfcvtn"))):
        return {}
    text = re.sub(r"\s+", "", ",".join(rendered["operands"]))
    if "tile_mask" in fields:
        if text == "{za}":
            return {"tile_mask": 255}
        if re.fullmatch(r"\{(?:za[0-7]\.d(?:,za[0-7]\.d)*)?\}", text):
            tiles = set(re.findall(r"za([0-7])\.d", text))
            if len(tiles) == text.count("za"):
                return {"tile_mask": sum(1 << int(tile) for tile in tiles)}
        return {}
    if "address" in fields:
        head, _, address = text.partition(",[")
        observed = {"operands": head} if head else {}
        if isinstance(fields["address"], tuple):
            if match := _VECTOR_BASE.fullmatch("[" + address):
                observed["address"] = match[1], int(match[2] or 0)
        elif fields["address"]["kind"] == "base-plus-immediate":
            if match := _IMMEDIATE_ADDRESS.fullmatch("[" + address):
                observed["address"] = dict(kind="base-plus-immediate", width_bits=64, base=_gpr(match[1]),
                                           displacement_bytes=int(match[2] or 0))
        elif match := _ADDRESS.fullmatch("[" + address):
            base, index, extension, shift = match.groups()
            observed["address"] = dict(kind="base-plus-extended-index", width_bits=64, base=_gpr(base),
                                       index=_gpr(index), extension=extension or "lsl", shift=int(shift or 0))
        return observed
    if rendered["form"] != mnemonic:
        return {"operands": rendered["form"] + " " + text}
    return {"operands": text}


def _observed_move(mnemonic, rendered):
    form = rendered["form"]
    text = re.sub(r"\s+", "", ",".join(rendered["operands"]))
    if form == "mov" and (match := _MOVE_ALIAS.fullmatch(text)):
        width = _gpr(match[1])["width_bits"]
        value = int(match[2])
        if -(1 << (width - 1)) <= value < 1 << width:
            return dict(operands=match[1], immediate_value=(width, value % (1 << width)))
    if form in ("movz", "movn") and (match := _MOVE_WIDE.fullmatch(text)):
        width = _gpr(match[1])["width_bits"]
        immediate, shift = int(match[2]), int(match[3] or 0)
        if immediate < 1 << 16 and shift in range(0, width, 16):
            return dict(operands=match[1], immediate_value=(width, _move_value(form, width, immediate, shift)),
                        immediate_encoding=(immediate, shift) if form == mnemonic else (form, immediate, shift))
    return {}


def compare_fields(facts, expected, llvm, gnu):
    observed = {name: _observed(expected, facts["mnemonic"], value) for name, value in (("llvm", llvm), ("gnu", gnu))}
    return {field: {tool: dict(state=("unobserved" if field not in fields else
                                      "confirmed" if fields[field] == value else "contradicted"))
                    for tool, fields in observed.items()} for field, value in expected.items()}
