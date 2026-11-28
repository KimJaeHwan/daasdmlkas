import json
from xml.etree import ElementTree

import pytest
import z3

from test_arm64_elf_functions import ENTRY, _elf
import arm64_local
import arm64_source_decode
import arm64_source_evidence
from arm64_encoding_index import EncodingIndex
from arm64_encoding_coverage import _mops_sample, _size_witnesses, _witnesses, sample_index
from arm64_source_facts import EXTENDED_RULE
from arm64_source_validity import undefined_encoding
from arm64_local import digest, json_bytes


def test_original_byte_cross_check_keeps_feature_overlap_and_binds_every_operand(monkeypatch):
    branch, pac, reserved = 0x54000022, 0xd503233f, 0xffffffff
    original = _elf(code=b"".join(word.to_bytes(4, "little") for word in (branch, pac, reserved)))

    class Index:
        def candidates(self, word):
            names = {branch: ("B_only_condbranch",), pac: ("HINT_HM_hints", "PACIASP_HI_hints")}.get(word, ())
            return {"candidates": [{"id": name, "feature_condition": "FEAT_PAuth" if name.startswith("PACIASP")
                                    else None} for name in names]}

    class Decoder:
        def __init__(self, path):
            self.identity = {"path": path}

        def decode(self, words):
            assert words == {ENTRY: branch, ENTRY + 4: pac, ENTRY + 8: reserved}
            if self.identity["path"] == "llvm":
                return {ENTRY: ("b.hs", f"{ENTRY+4:#x} <.text0+0x4>"), ENTRY + 4: ("hint", "#25"),
                        ENTRY + 8: ("<unknown>", "")}
            return {ENTRY: ("b.cs", f"{ENTRY+4:x} // b.hs"), ENTRY + 4: ("paciasp", ""),
                    ENTRY + 8: (".inst", "0xffffffff")}

        def check_identity(self):
            pass

    def forbid(*_args, **_kwargs):
        pytest.fail("original-byte cross-check called SLEIGH or TDO")

    monkeypatch.setattr(arm64_local, "_context", forbid)
    monkeypatch.setattr(arm64_source_evidence, "load_index", lambda _: (Index(), {"archive": "fixture"}))
    monkeypatch.setattr(arm64_source_decode, "LlvmObjdump", Decoder)
    monkeypatch.setattr(arm64_source_decode, "GnuObjdump", Decoder)
    options = dict(llvm_objdump="llvm", gnu_objdump="gnu", encoding_archive="fixture")
    encoded = arm64_source_evidence.collect_decode(original, entry=ENTRY, size=12, **options)
    record = arm64_source_evidence.verify_decode(original, encoded, **options)
    rows = record["slots"]
    assert [row["file_offset"] for row in rows] == list(range(record["source"]["file_offset"],
                                                             record["source"]["file_offset"]+12, 4))
    assert [row["comparison"] for row in rows] == ["same-rendering", "different-rendering", "unobserved"]
    assert rows[0]["llvm"]["mnemonic"] == "b.hs" and rows[0]["gnu"]["mnemonic"] == "b.cs"
    assert rows[0]["arm_check"]["llvm"] is rows[0]["arm_check"]["gnu"] is True
    assert rows[1]["arm_check"]["runtime_feature_state"] == "unobserved"
    assert rows[1]["arm_check"]["llvm"] is rows[1]["arm_check"]["gnu"] is True
    assert "arm_check" not in rows[2]

    rows[0]["gnu"]["operands"] = f"{ENTRY+8:x}"
    resealed = json_bytes(dict(digest=digest(json_bytes(record)), evidence=record)) + b"\n"
    with pytest.raises(ValueError, match="differs from replay"):
        arm64_source_evidence.verify_decode(original, resealed, **options)


def test_arm_branch_check_rejects_wrong_target_even_if_decoders_agree():
    candidate = {"candidates": [{"id": "B_only_condbranch"}]}
    word = 0x54ffffe2  # B.HS/B.CS to PC - 4.
    wrong = arm64_source_decode._rendered(("b.hs", "1004"), gnu=True)
    check = arm64_source_decode._arm_check(0x1000, word, candidate, wrong, wrong)
    assert check["expected"] == {"form": "b.cond", "operands": ["0xffc"], "condition": "cs"}
    assert check["llvm"] is check["gnu"] is False


def _source_index(word_id, file, feature=None, section="test"):
    return {"candidates": [dict(id=word_id, file=file, feature_condition=feature, section=section)], "exclusions": []}


def test_profiled_source_fields_keep_disagreeing_llvm_shift():
    row = arm64_source_decode._source_row(
        ENTRY, 0x3ce16840, _source_index("LDR_Q_ldst_regoff", "ldr_reg_fpsimd.xml", "FEAT_FP", "ldst_regoff"),
        ("ldr", "q0, [x2, x1, lsl #4]"), ("ldr", "q0, [x2, x1]"), profiled=True)
    assert row["llvm"]["operands"].endswith("lsl #4]")
    assert row["common_facts"]["transfer_width_bits"] == 128
    assert row["common_facts"]["address"] == {
        "kind": "base-plus-extended-index", "width_bits": 64,
        "base": {"register": "x2", "width_bits": 64}, "index": {"register": "x1", "width_bits": 64},
        "extension": "lsl", "shift": 0,
    }
    assert row["field_evidence"]["operands"]["llvm"]["state"] == "confirmed"
    assert row["field_evidence"]["address"] == {"llvm": {"state": "contradicted"}, "gnu": {"state": "confirmed"}}

    indexed = _source_index("LDR_64_ldst_regoff", "ldr_reg_gen.xml", None, "ldst_regoff")
    raw = ("ldr", "x1, [x0, x4, sxtx #3]")
    row = arm64_source_decode._source_row(ENTRY, 0xf864f801, indexed, raw, raw, profiled=True)
    assert row["common_facts"]["address"]["extension"] == "sxtx" and row["common_facts"]["address"]["shift"] == 3
    assert row["field_evidence"]["address"]["llvm"]["state"] == "confirmed"

    wrong_width = _source_index("LDR_32_ldst_regoff", "ldr_reg_gen.xml", None, "ldst_regoff")
    assert "common_facts" not in arm64_source_decode._source_row(ENTRY, 0xf864f801, wrong_width, raw, raw,
                                                               profiled=True)
    bad = ("ldrb", "w0, [x0, x0]")
    invalid = _source_index("LDRB_32B_ldst_regoff", "ldrb_reg.xml", None, "ldst_regoff")
    assert "common_facts" not in arm64_source_decode._source_row(ENTRY, 0x38600800, invalid, bad, bad, profiled=True)
    assert "common_facts" not in arm64_source_decode._source_row(ENTRY, 0x38606800, invalid, bad, bad, profiled=True)
    byte = _source_index("LDRB_32BL_ldst_regoff", "ldrb_reg.xml", None, "ldst_regoff")
    for word in (0x38606800, 0x38607800):
        byte_row = arm64_source_decode._source_row(ENTRY, word, byte, bad, bad, profiled=True)
        assert byte_row["common_facts"]["address"]["shift"] == 0
    wrong_prefetch = _source_index("PRFM_P_ldst_regoff", "prfm_reg.xml", None, "ldst_regoff")
    prefetch = ("prfm", "#24, [x0, x0]")
    assert "common_facts" not in arm64_source_decode._source_row(ENTRY, 0xf8a06818, wrong_prefetch, prefetch, prefetch,
                                                               profiled=True)
    indexed["exclusions"].append({"id": "other"})
    assert "common_facts" not in arm64_source_decode._source_row(ENTRY, 0xf864f801, indexed, raw, raw, profiled=True)


def test_profiled_vector_memory_keeps_symbolic_address_and_decodes_signed_multiplier():
    index = _source_index("ld1w_z_p_bi_u64", "ld1w_z_p_bi.xml", "FEAT_SVE || FEAT_SME")
    raw = ("ld1w", "{ z0.d }, p0/z, [sp, #-0x1, mul vl]")
    row = arm64_source_decode._source_row(ENTRY, 0xa56fa3e0, index, raw, raw, profiled=True)
    claim = row["common_facts"]
    assert claim["transfer_width_bits"] == 32 and claim["operands"][0]["element_bits"] == 64
    assert claim["address"]["vector_length"] == "CurrentVL" and claim["address"]["multiplier"] == -1
    assert claim["address"]["lane_width_bits"] == 64 and claim["address"]["bytes_per_lane"] == 4
    assert all(condition["state"] == "unknown" for condition in claim["conditions"])
    assert row["field_evidence"]["address"]["gnu"]["state"] == "confirmed"


def test_sme_zero_alias_requires_complete_mask_and_unique_tiles():
    index = _source_index("zero_za_i_", "zero_za_i.xml", "FEAT_SME")
    left, right = ("zero", "{za0.d,za0.d}"), ("zero", "{za}")
    row = arm64_source_decode._source_row(ENTRY, 0xc0080001, index, left, right, profiled=True)
    assert row["common_facts"]["tile_mask"] == 1
    assert row["field_evidence"]["tile_mask"] == {"llvm": {"state": "unobserved"}, "gnu": {"state": "contradicted"}}


def test_extended_profile_checks_move_alias_value_and_canonical_immediate_separately():
    index = _source_index("MOVN_32_movewide", "movn.xml", section="movewide")
    alias = "mov", "w3, #-0x28"
    canonical = "movn", "w3, #0x27"
    old = arm64_source_decode._source_row(ENTRY, 0x128004e3, index, alias, canonical, profiled=True)
    assert "common_facts" not in old
    row = arm64_source_decode._source_row(ENTRY, 0x128004e3, index, alias, canonical, profiled=True,
                                        rule=EXTENDED_RULE)
    assert row["comparison"] == "different-rendering"
    assert row["common_facts"]["immediate"] == {
        "width_bits": 32, "value_hex": "0xffffffd8", "encoded_value": 0x27, "shift": 0,
    }
    assert row["field_evidence"]["immediate_value"] == {"llvm": {"state": "confirmed"}, "gnu": {"state": "confirmed"}}
    assert row["field_evidence"]["immediate_encoding"]["llvm"]["state"] == "unobserved"

    wrong = "movn", "w3, #0x27, lsl #16"
    row = arm64_source_decode._source_row(ENTRY, 0x128004e3, index, alias, wrong, profiled=True,
                                        rule=EXTENDED_RULE)
    assert row["field_evidence"]["immediate_value"]["gnu"]["state"] == "contradicted"
    assert row["field_evidence"]["immediate_encoding"]["gnu"]["state"] == "contradicted"
    wrong_width = "mov", "x3, #-0x28"
    row = arm64_source_decode._source_row(ENTRY, 0x128004e3, index, wrong_width, canonical, profiled=True,
                                        rule=EXTENDED_RULE)
    assert row["field_evidence"]["operands"]["llvm"]["state"] == "contradicted"
    assert row["field_evidence"]["immediate_value"]["llvm"]["state"] == "contradicted"
    invalid = arm64_source_decode._source_row(ENTRY, 0x12c004e3, index, alias, canonical, profiled=True,
                                            rule=EXTENDED_RULE)
    assert "common_facts" not in invalid


def test_extended_profile_checks_opt_out_of_omitted_nonzero_address():
    index = _source_index("LDR_64_ldst_pos", "ldr_imm_gen.xml", section="ldst_pos")
    explicit = "ldr", "x17, [x16, #0x0]"
    omitted = "ldr", "x17, [x16]"
    row = arm64_source_decode._source_row(ENTRY, 0xf9400211, index, explicit, omitted, profiled=True,
                                        rule=EXTENDED_RULE)
    assert row["common_facts"]["address"]["displacement_bytes"] == 0
    assert row["field_evidence"]["address"] == {"llvm": {"state": "confirmed"}, "gnu": {"state": "confirmed"}}
    for wrong in (omitted, ("ldr", "x17, [x16, #-8]")):
        row = arm64_source_decode._source_row(ENTRY, 0xf9400611, index, ("ldr", "x17, [x16, #8]"), wrong,
                                             profiled=True, rule=EXTENDED_RULE)
        assert row["common_facts"]["address"]["displacement_bytes"] == 8
        assert row["field_evidence"]["address"]["gnu"]["state"] == "contradicted"


@pytest.mark.parametrize("profile", [
    arm64_source_decode.SVE_SME_PROFILE, arm64_source_decode.ALL_INSTRUCTIONS_PROFILE_V2,
])
def test_named_profile_selects_every_word_and_rejects_resealed_evidence(monkeypatch, profile):
    options = arm64_source_decode.SOURCE_DECODE_PROFILES[profile]
    word, undef, unmodeled = 0x0ea16bff, 0x2538ffff, 0xd503201f
    original = _elf(code=b"".join(value.to_bytes(4, "little") for value in (word, undef, unmodeled)))
    calls = []

    class Index:
        def candidates(self, queried):
            if queried == word:
                return _source_index("BFCVTN_asimdmisc_4S", "bfcvtn_advsimd.xml", "FEAT_BF16")
            if queried == undef:
                return _source_index("dup_z_i_", "dup_z_i.xml", "FEAT_SVE || FEAT_SME", "sve_int_dup_imm")
            return {"candidates": [], "exclusions": []}

    class LLVM:
        def __init__(self, path, *, options):
            calls.append((path, options))
            self.identity = {"options": list(options), "path": path}

        def decode(self, words):
            assert words == {ENTRY: word, ENTRY + 4: undef, ENTRY + 8: unmodeled}
            middle = ("dup", "z31.b, #-256") if self.identity["path"] == "gnu" else ("<unknown>", "")
            return {ENTRY: ("bfcvtn", "v31.4h, v31.4s"), ENTRY + 4: middle, ENTRY + 8: ("hint", "#0")}

        def check_identity(self):
            pass

    monkeypatch.setattr(arm64_source_decode, "LlvmObjdump", LLVM)
    monkeypatch.setattr(arm64_source_decode, "GnuObjdump", lambda path: LLVM(path, options=()))
    monkeypatch.setattr(arm64_source_decode, "_profile_probe", lambda llvm, gnu, index: [])
    monkeypatch.setattr(arm64_source_evidence, "load_index", lambda _: (Index(), {"archive": "fixture"}))
    paths = dict(llvm_objdump="llvm", gnu_objdump="gnu", encoding_archive="fixture")
    encoded = arm64_source_evidence.collect_decode(original, entry=ENTRY, size=12, decode_profile=profile, **paths)
    result = arm64_source_evidence.verify_decode(original, encoded, **paths)
    assert calls == [("llvm", options), ("gnu", ())] * 2
    assert result["schema"] == arm64_source_evidence.PROFILED_DECODE_SCHEMA
    assert all(status == "unobserved" for status in result["runtime"].values())
    assert result["slots"][0]["common_facts"]["operands"][1]["element_bits"] == 32
    invalid = result["slots"][1]
    assert "common_facts" not in invalid and "field_evidence" not in invalid
    assert invalid["comparison"] == "unobserved" and invalid["gnu"]["operands"] == "z31.b, #-256"
    edits = ["options", "profile", "operand"]
    if profile == arm64_source_decode.ALL_INSTRUCTIONS_PROFILE_V2:
        verdict = invalid["arm_check"]
        assert verdict["verdict"] == "UNDEFINED" and verdict["fields"] == {"size": 0, "sh": 1}
        assert verdict["observers"] == {"llvm": "unobserved", "gnu": "contradicted"}
        edits.extend(("verdict", "bits"))
    else:
        assert "arm_check" not in invalid
    for key in edits:
        edited = json.loads(encoded)["evidence"]
        if key == "options":
            edited["decoders"]["llvm"]["options"].pop()
        elif key == "profile":
            edited["decode_profile"] = "unknown"
        elif key == "verdict":
            edited["slots"][1].pop("arm_check")
        elif key == "bits":
            edited["slots"][1]["arm_check"]["fields"]["sh"] = 0
        else:
            edited["slots"][0]["common_facts"]["operands"][0]["element_bits"] = 32
        resealed = json_bytes(dict(digest=digest(json_bytes(edited)), evidence=edited)) + b"\n"
        with pytest.raises(ValueError, match="differs from replay|unknown AArch64 source decode profile"):
            arm64_source_evidence.verify_decode(original, resealed, **paths)


def test_undefined_atomic_rule_binds_both_registers_and_the_exact_encoding():
    index = _source_index("LDCLRP_128_memop_128", "ldclrp.xml", "FEAT_LSE128", "memop_128")
    for rt, rt2, rn in ((31, 0, 0), (0, 31, 0), (31, 31, 31), (1, 0, 31), (1, 1, 0)):
        word = 0x19201000 | (rt2 << 16) | (rn << 5) | rt
        verdict = undefined_encoding(word, index)
        if 31 in (rt, rt2):
            assert verdict["reason"] == "atomic-data-register-31"
            assert verdict["fields"] == {"Rt": rt, "Rt2": rt2}
        else:
            assert verdict is None
    assert undefined_encoding(0x19200c1f, index) is None
    assert undefined_encoding(0x19a0101f, index) is None
    matched, = index["candidates"]
    assert undefined_encoding(0x1920101f, dict(index, candidates=[matched, {"id": "another"}])) is None
    assert undefined_encoding(0x1920101f, dict(index, exclusions=[{"section": "reserved"}])) is None
    assert undefined_encoding(0x1920101f, dict(index, candidates=[dict(matched, file="other.xml")])) is None


@pytest.mark.parametrize("section,name,base", [
    ("sve_int_dup_imm_pred", "cpy_z_o_i_", 0x05100000),
    ("sve_int_dup_imm_pred", "cpy_z_p_i_", 0x05104000),
    ("sve_int_dup_imm", "dup_z_i_", 0x2538c000),
])
def test_undefined_sve_immediate_checks_the_size_shift_pair(section, name, base):
    index = _source_index(name, name[:-1] + ".xml", "FEAT_SVE || FEAT_SME", section)
    for size in range(4):
        for sh in (0, 1):
            word = base | (size << 22) | (sh << 13)
            verdict = undefined_encoding(word, index)
            if size == 0 and sh == 1:
                assert verdict["reason"] == "sve-byte-immediate-shift"
            else:
                assert verdict is None
    assert undefined_encoding(base ^ 0x4000 | 0x2000, index) is None


def test_undefined_verdict_is_independent_of_observer_agreement():
    index = _source_index("dup_z_i_", "dup_z_i.xml", "FEAT_SVE || FEAT_SME", "sve_int_dup_imm")
    display = ("dup", "z31.b, #-256")
    row = arm64_source_decode._source_row(ENTRY, 0x2538ffff, index, display, display,
                                         profiled=True, check_undefined=True)
    assert row["comparison"] == "same-rendering"
    assert row["arm_check"]["observers"] == {"llvm": "contradicted", "gnu": "contradicted"}
    row = arm64_source_decode._source_row(ENTRY, 0x2538ffff, index, ("udf", "#0"), (".inst", "0x2538ffff"),
                                         profiled=True, check_undefined=True)
    assert row["arm_check"]["verdict"] == "UNDEFINED"
    assert row["arm_check"]["observers"] == {"llvm": "unobserved", "gnu": "unobserved"}


def test_index_keeps_overlapping_rows_and_negative_masks():
    index = EncodingIndex(ElementTree.fromstring("""
      <encodingindex instructionset="A64">
        <hierarchy>
          <node iclass="fixture">
            <decode><box hibit="31"><c>0</c></box></decode>
          </node>
          <node iclass="reserved" unallocated="1">
            <decode><box hibit="31"><c>1</c></box></decode>
          </node>
        </hierarchy>
        <iclass_sect id="fixture">
          <regdiagram><box hibit="1" width="2" name="code"><c colspan="2"/></box></regdiagram>
          <instructiontable>
            <thead><tr id="heading2"><th class="bitfields">code</th></tr></thead>
            <tbody>
              <tr encname="GENERIC" iformfile="generic.xml"><td class="bitfield"/></tr>
              <tr encname="SPECIAL" iformfile="special.xml" arch_version="FEAT_X">
                <td class="bitfield">!= 10</td>
              </tr>
            </tbody>
          </instructiontable>
        </iclass_sect>
      </encodingindex>
    """))
    for word in (0, 1, 3):
        candidates = index.candidates(word)["candidates"]
        assert [row["id"] for row in candidates] == ["GENERIC", "SPECIAL"]
        assert candidates[1]["feature_condition"] == "FEAT_X"
    assert [row["id"] for row in index.candidates(2)["candidates"]] == ["GENERIC"]
    assert index.candidates(0x80000000)["exclusions"] == [
        {"section": "reserved", "reason": "unallocated-hierarchy"},
    ]


def test_sample_index_keeps_shared_paths_and_overlapping_table_rows():
    index = EncodingIndex(ElementTree.fromstring("""
      <encodingindex instructionset="A64">
        <hierarchy>
          <node iclass="shared"><decode><box hibit="0"><c>0</c></box></decode></node>
          <node iclass="shared"><decode><box hibit="0"><c>1</c></box></decode></node>
        </hierarchy>
        <iclass_sect id="shared">
          <regdiagram><box hibit="0" name="mode"><c/></box></regdiagram>
          <instructiontable>
            <thead><tr id="heading2"><th class="bitfields">mode</th></tr></thead>
            <tbody>
              <tr encname="OVERLAP" iformfile="first.xml"><td class="bitfield"/></tr>
              <tr encname="OVERLAP" iformfile="second.xml"><td class="bitfield">1</td></tr>
            </tbody>
          </instructiontable>
        </iclass_sect>
      </encodingindex>
    """))
    first, second = sample_index(index)
    assert first["row"] == 0 and first["variable_bit_mask"] == "ffffffff"
    assert second["row"] == 1 and second["variable_bit_mask"] == "fffffffe"
    assert all(word & 1 for word in second["samples"])
    assert first == list(sample_index(index))[0]


def test_sample_bits_can_vary_together_to_satisfy_table_exclusions():
    word = z3.BitVec("encoding_fixture", 32)
    constraints = z3.And(word <= 3, word >= 0, word != 1, word != 2)
    samples, mask = _witnesses(word, constraints)
    assert samples == (0, 3) and mask == 3
    assert _size_witnesses(word, constraints, samples, mask) == ()


def test_sample_size_field_covers_combinations_per_bit_sampling_can_miss():
    word = z3.BitVec("encoding_fixture", 32)
    base, size_mask = 0x0f00e000, (3 << 22) | (1 << 30)
    constraint = z3.And(word & ~size_mask == base, z3.Extract(23, 22, word) != 1)
    samples, mask = _witnesses(word, constraint)
    extra = _size_witnesses(word, constraint, samples, size_mask)
    assert extra and set(extra).isdisjoint(samples)
    assert mask == size_mask
    assert {sample & size_mask for sample in (*samples, *extra)} == {
        size | q for size in (0, 2 << 22, 3 << 22) for q in (0, 1 << 30)
    }


def test_sample_size_field_can_vary_without_changing_a_lane_index():
    word = z3.BitVec("encoding_fixture", 32)
    base, size_mask, lane_bit = 0x2f001000, 3 << 22, 1 << 21
    samples = (base, *(base | size << 22 | lane_bit for size in (1, 2, 3)))
    constraints = word & ~(size_mask | lane_bit) == base
    assert _size_witnesses(word, constraints, samples, size_mask) == (
        0x2f401000, 0x2f801000, 0x2fc01000,
    )


def test_mops_sample_combines_register_choices_and_keeps_opcode_fields():
    assert _mops_sample("memcms", "CPYFP_CPY_memcms", (0x19000400,)) == 0x19010440
    assert _mops_sample("memcms", "SETGP_SET_memcms", (0x1dc00400,)) == 0x1dc10440
    assert _mops_sample("other", "CPYFP_CPY_memcms", (0x19000400,)) is None
