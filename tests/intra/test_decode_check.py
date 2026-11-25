"""G1 ``tools/decode_check``: mapping and decoder cross-check on synthetic sealed
Bundles whose `original` is a synthetic PE32+ (tools/decode_check/_pe_fixture.py)
or ELF64 (_elf_fixture.py). The ELF mapping unit tests at the end need neither.

POSIX (admission) and the built decoders ($G1_DECODERS, build_decoders.sh) are
required; the tests skip otherwise.
"""

import os
from pathlib import Path
import sys

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "decode_check"))
sys.path.insert(0, str(REPO / "tools" / "bundle_lint"))

DECODERS = Path(os.environ.get("G1_DECODERS", "/root/g1_decoders"))
needs = pytest.mark.skipif(os.name != "posix" or not (DECODERS / "lib" / "libdc_xed.so").exists(),
                           reason="POSIX admission and the built decoders are required")

BASE = 0x140000000
CODE = BASE + 0x1000


def _bundle(tmp_path, functions, code: bytes, *, code_raw=None, image_base=BASE, program_base=None, pe_base=None):
    import _pe_fixture as pf
    import _sealed as s

    section = pf.Section(".text", 0x1000, code, raw=code_raw)
    original = pf.make_pe([section], image_base=pe_base or image_base)
    blocks = [s.Block(start=start, data=data, name=".text" if start != image_base else "Headers")
              for start, data in pf.blocks_for([section], original, image_base=image_base)]
    bundle = s.Bundle(functions, blocks=blocks, program=s.program(image_base=program_base or image_base),
                      overrides={"original": original})
    os.chmod(tmp_path, 0o755)
    return s.write(tmp_path, bundle)


def _pair(s, call_bytes=b"\xE8\x0B\x00\x00\x00", call_length=None, code=CODE):
    """A at CODE: call B (CODE + 0x10), ret; B: mov rax, rcx; ret."""
    CODE = code  # noqa: N806
    length = call_length or len(call_bytes)
    after = CODE + len(call_bytes)
    a = s.Function("A", s.observation(CODE, [s.call(CODE, CODE + 0x10, length=length), s.ret(after)]))
    if call_length is not None:   # (a Ghidra row whose length disagrees with the bytes)
        a.observation["instructions"][0]["fallthrough"] = s.coord(after)
        a.observation["instructions"][0]["operations"][1]["inputs"][2] = s.const(after)
    b = s.Function("B", s.observation(CODE + 0x10, [s.plain(CODE + 0x10, 3, ("COPY", [s.reg(s.RCX)], s.reg(s.RAX))),
                                                     s.ret(CODE + 0x13)]))
    code = bytearray(b"\xCC" * 0x20)
    code[0:len(call_bytes)] = call_bytes
    code[len(call_bytes)] = 0xC3
    code[0x10:0x14] = b"\x48\x89\xC8\xC3"
    return [a, b], bytes(code)


def _run(gen, premise=True):
    import _sealed as s
    import decode_check

    header, rows = decode_check.run(gen, s.NAMING_SOURCE, premise, full=True)
    found = {row.ident(): row for row in rows}
    assert len(found) == len(rows)
    return header, found


@needs
def test_reference_pair_rows_are_applied_with_the_translation_premise(tmp_path):
    import _sealed as s

    functions, code = _pair(s)
    header, rows = _run(_bundle(tmp_path, functions, code))
    assert header["global_reason"] is None
    assert rows[("mapping", "original", "bundle")].verdict == "applied"
    for key in ("function-000000/1:140001000", "function-000000/1:140001005", "function-000001/1:140001010",
                "function-000001/1:140001013"):
        row = rows[("decode", "row", key)]
        assert (row.run_state, row.verdict) == ("evaluated", "applied"), (key, row.detail)
    call = rows[("decode", "row", "function-000000/1:140001000")].detail["attributes"]
    assert call["a5"]["value"] == CODE + 0x10 and call["a7"]["value"] == [64, CODE + 5]


@needs
def test_without_the_premise_only_a1_a2_a4_are_compared(tmp_path):
    import _sealed as s

    functions, code = _pair(s)
    _, rows = _run(_bundle(tmp_path, functions, code), premise=False)
    row = rows[("decode", "row", "function-000000/1:140001000")]
    attributes = row.detail["attributes"]
    assert {name for name, item in attributes.items() if item["state"] == "applied"} == {"a1", "a2", "a4"}
    assert attributes["a5"]["reason"].startswith("translation-unverified")
    assert row.run_state == "unobserved"


@needs
def test_a_wrong_ghidra_length_is_a_decode_suspect(tmp_path):
    """B's mov rax, rcx is 3 bytes; Ghidra says 2 (its listing continuation stays the next row)."""
    import _sealed as s

    functions, code = _pair(s)
    functions[1].observation["instructions"][0]["length"] = 2
    _, rows = _run(_bundle(tmp_path, functions, code))
    row = rows[("decode", "row", "function-000001/1:140001010")]
    attributes = row.detail["attributes"]
    assert attributes["a2"]["kind"] == "ghidra-decode-suspect" and attributes["a4"]["state"] == "applied"
    assert row.verdict == "unrecognized" and row.detail["kind"] == "ghidra-decode-suspect"
    assert any(ident[1] == "suspect" for ident in rows)


@needs
def test_a_native_call_whose_length_and_continuation_disagree_is_an_internal_inconsistency(tmp_path):
    import _sealed as s

    functions, code = _pair(s, call_length=4)
    _, rows = _run(_bundle(tmp_path, functions, code))
    row = rows[("decode", "row", "function-000000/1:140001000")]
    assert row.detail["attributes"]["a2"]["kind"] == "ghidra-internal-inconsistency"


@needs
def test_66_e8_is_withheld_as_a_vendor_or_amd_split(tmp_path):
    import _sealed as s

    functions, code = _pair(s, call_bytes=b"\x66\xE8\x0A\x00\x00\x00")
    _, rows = _run(_bundle(tmp_path, functions, code))
    row = rows[("decode", "row", "function-000000/1:140001000")]
    assert row.verdict == "withheld", row.detail
    assert row.detail["attributes"]["a2"]["state"] == "withheld"


@needs
def test_a_sealed_byte_that_differs_from_the_file_stops_the_window(tmp_path):
    import _sealed as s

    functions, code = _pair(s)
    raw = bytearray(code)
    raw[2] ^= 0xFF   # (the file's call displacement differs from Ghidra's sealed bytes)
    _, rows = _run(_bundle(tmp_path, functions, code, code_raw=bytes(raw)))
    assert rows[("mapping", "block", "#1/1:140001000")].verdict == "unrecognized"
    row = rows[("decode", "row", "function-000000/1:140001000")]
    assert row.run_state == "unobserved"


@needs
def test_a_bundle_not_at_the_preferred_base_is_not_compared(tmp_path):
    import _sealed as s

    functions, code = _pair(s)
    header, rows = _run(_bundle(tmp_path, functions, code, pe_base=BASE + 0x10000000))
    assert "preferred base" in header["global_reason"]
    decode = [row for ident, row in rows.items() if ident[:2] == ("decode", "row")]
    assert decode and all(row.run_state == "unobserved" for row in decode)


# -- PE32+ relocations, loader-written ranges and loader-rule vectors (r2-r4)

IMM64 = 0x1122334455667788


def _pe_bundle(tmp_path, functions, sections, directories=()):
    import _pe_fixture as pf
    import _sealed as s

    original = pf.make_pe(sections, directories=directories)
    blocks = [s.Block(start=start, data=data, name="Headers" if start == BASE else f"s@{start:x}")
              for start, data in pf.blocks_for(sections, original)]
    bundle = s.Bundle(functions, blocks=blocks, program=s.program(image_base=BASE), overrides={"original": original})
    os.chmod(tmp_path, 0o755)
    return s.write(tmp_path, bundle)


def _mov_imm64(s):
    """M at CODE: mov rax, imm64 (48 B8 <8>); ret."""
    m = s.Function("M", s.observation(CODE, [s.plain(CODE, 10, ("COPY", [s.const(IMM64)], s.reg(s.RAX))),
                                             s.ret(CODE + 10)]))
    code = b"\x48\xB8" + IMM64.to_bytes(8, "little") + b"\xC3"
    return [m], code


def _reloc_section(entries):
    """A .reloc section at RVA 0x2000: one block for page 0x1000 with the given (type, offset)."""
    import _pe_fixture as pf
    import struct

    words = [kind << 12 | offset for kind, offset in entries]
    if len(words) % 2:
        words.append(0)                                   # (IMAGE_REL_BASED_ABSOLUTE padding)
    block = struct.pack("<II", 0x1000, 8 + 2 * len(words)) + b"".join(struct.pack("<H", w) for w in words)
    return pf.Section(".reloc", 0x2000, block, characteristics=0x42000040), pf.Directory(5, 0x2000, len(block))


@needs
@pytest.mark.parametrize("entries, state, reason", [
    ([(10, 2)], ("evaluated", "applied"), None),                                        # DIR64 inside the imm64
    ([(10, 0)], ("unobserved", None), "relocation over instruction encoding"),          # DIR64 over the opcode
    ([(3, 2)], ("unobserved", None), "relocation type type3 over the instruction"),     # HIGHLOW in PE32+
])
def test_pe_relocations_over_an_instruction(tmp_path, entries, state, reason):
    import _pe_fixture as pf
    import _sealed as s

    functions, code = _mov_imm64(s)
    reloc, directory = _reloc_section(entries)
    _, rows = _run(_pe_bundle(tmp_path, functions, [pf.Section(".text", 0x1000, code), reloc], [directory]))
    row = rows[("decode", "row", "function-000000/1:140001000")]
    assert (row.run_state, row.verdict) == state, row.detail
    assert row.detail["window"]["relocations"], row.detail["window"]     # (the relocation is listed)
    if reason:
        assert row.detail["reason"] == reason


def _data_section_with_directories():
    """.data at RVA 0x2000 holding an import, a delay-load, a TLS and a load-config directory."""
    import _pe_fixture as pf
    import struct

    data = bytearray(0x900)
    struct.pack_into("<IIIII", data, 0x000, 0x2100, 0, 0, 0x2180, 0x2200)      # import descriptor
    struct.pack_into("<QQQ", data, 0x100, 0x2190, 0x21A0, 0)                    # OriginalFirstThunk: 2 thunks
    struct.pack_into("<QQQ", data, 0x200, 0x2190, 0x21A0, 0)                    # IAT
    struct.pack_into("<IIIIIIII", data, 0x300, 1, 0x2180, 0x2400, 0x2410, 0x2430, 0, 0, 0)   # delay-load
    struct.pack_into("<QQ", data, 0x430, 0x21A0, 0)                             # delay name table: 1 entry
    struct.pack_into("<QQQQ", data, 0x500, 0, 0, BASE + 0x2600, 0)              # TLS: AddressOfIndex
    struct.pack_into("<I", data, 0x700, 0x100)                                  # load config size
    struct.pack_into("<Q", data, 0x700 + 0x58, BASE + 0x2800)                   # security cookie
    struct.pack_into("<QQ", data, 0x700 + 0x70, BASE + 0x2808, BASE + 0x2810)   # CFG check / dispatch
    directories = [pf.Directory(1, 0x2000, 40), pf.Directory(13, 0x2300, 64), pf.Directory(9, 0x2500, 40),
                   pf.Directory(10, 0x2700, 0x100)]
    return pf.Section(".data", 0x2000, bytes(data), characteristics=0xC0000040), directories


def test_pe_map_loader_written_ranges():
    import _pe_fixture as pf
    import pe_map

    data, directories = _data_section_with_directories()
    image = pe_map.parse(pf.make_pe([pf.Section(".text", 0x1000, b"\xC3"), data], directories=directories))
    assert image.ok and image.written.state == "complete", image.written.why
    assert set(image.written.ranges) == {(0x2200, 0x2210, "iat"), (0x2400, 0x2408, "delay-module-handle"),
                                         (0x2410, 0x2418, "delay-iat"), (0x2600, 0x2604, "tls-index"),
                                         (0x2800, 0x2808, "security-cookie"), (0x2808, 0x2810, "cfg-check-pointer"),
                                         (0x2810, 0x2818, "cfg-dispatch-pointer")}
    assert image.relocations.state == "absent"


def test_pe_map_unreadable_or_malformed_directories_are_indeterminate():
    import _pe_fixture as pf
    import check
    import pe_map
    import struct

    text = pf.Section(".text", 0x1000, b"\xC3")
    # an import descriptor whose thunk array points outside the image
    data = bytearray(0x40)
    struct.pack_into("<IIIII", data, 0, 0x9000, 0, 0, 0, 0x9000)
    image = pe_map.parse(pf.make_pe([text, pf.Section(".data", 0x2000, bytes(data))],
                                    directories=[pf.Directory(1, 0x2000, 40)]))
    assert image.written.state == "indeterminate" and "import directory" in image.written.why
    # a relocation block whose size is below its header
    bad = pf.Section(".reloc", 0x2000, struct.pack("<II", 0x1000, 4))
    image = pe_map.parse(pf.make_pe([text, bad], directories=[pf.Directory(5, 0x2000, 8)]))
    assert image.relocations.state == "indeterminate"
    assert "relocation ranges indeterminate" in check.global_reason(image, BASE, check.LANGUAGE)


def test_pe_map_loader_rule_vectors():
    import _pe_fixture as pf
    import pe_map
    import struct

    text = pf.Section(".text", 0x1000, b"\xC3" * 0x10)
    table = 0x58 + 240
    # VirtualSize 0 is not an adopted loader behaviour (patched: the fixture reads vsize 0 as "len(data)")
    original = bytearray(pf.make_pe([text, pf.Section(".zero", 0x2000, b"\x90" * 0x200)]))
    struct.pack_into("<I", original, table + 40 + 8, 0)
    image = pe_map.parse(bytes(original))
    zero = next(item for item in image.sections if item["name"] == ".zero")
    assert image.ok and zero["state"] == "ambiguous" and "VirtualSize == 0" in zero["why"]
    # not AMD64 / a section table past SizeOfHeaders: the whole mapping is unusable
    assert not pe_map.parse(pf.make_pe([text], machine=0x14C)).ok
    many = bytearray(pf.make_pe([text]))
    struct.pack_into("<H", many, 0x46, 12)                  # NumberOfSections 12: the table passes SizeOfHeaders
    assert not pe_map.parse(bytes(many)).ok
    # r4 s7: SectionAlignment = FileAlignment = 0x200, VirtualAddress 0x601, VirtualSize 0x200, no raw data
    original = bytearray(pf.make_pe([pf.Section(".text", 0x400, b"\xC3" * 0x200),
                                     pf.Section(".bss", 0x600, b"", vsize=0x200)],
                                    section_alignment=0x200, file_alignment=0x200, size_of_headers=0x400))
    struct.pack_into("<I", original, table + 40 + 12, 0x601)
    image = pe_map.parse(bytes(original))
    assert image.ok and image.at(0x601).kind == "ambiguous" and "not aligned" in image.at(0x601).why


def test_an_ambiguous_range_is_unobserved_even_with_zero_sealed_bytes():
    import check
    import pe_map

    image = check.Image.__new__(check.Image)
    image.blocks = [({"byte_start": BASE + 0x600, "byte_size": 0x200}, bytes(0x200))]
    image.mapping = pe_map.PeImage(True, ranges=[pe_map.Range(0x600, 0x800, "ambiguous", why="VirtualAddress not aligned")])
    image.base, image.original, image.relocations = BASE, b"", []
    image.written = check.Intervals([])
    assert image.verified_byte(BASE + 0x601) == (None, "ambiguous range (VirtualAddress not aligned)")
    assert image.window(BASE + 0x601)["verified"] == 0


# -- ELF64 x86-64 (elf_map, elf-loader-rules-1)

GHIDRA_PIE_BASE = 0x100000           # (Ghidra's base for an ET_DYN whose lowest PT_LOAD is at 0)
ELF_CODE = GHIDRA_PIE_BASE + 0x1000


def _elf_bundle(tmp_path, functions, elf, *, bias=GHIDRA_PIE_BASE, program_base=None):
    import _sealed as s

    blocks = [s.Block(start=bias + va, data=data, name=f"segment@{va:x}") for va, data in elf.loads]
    bundle = s.Bundle(functions, blocks=blocks, program=s.program(image_base=program_base or bias),
                      overrides={"original": elf.data})
    os.chmod(tmp_path, 0o755)
    return s.write(tmp_path, bundle)


@needs
def test_elf_pie_rows_are_applied_at_the_ghidra_load_bias(tmp_path):
    import _elf_fixture as ef
    import _sealed as s

    functions, code = _pair(s, code=ELF_CODE)
    header, rows = _run(_elf_bundle(tmp_path, functions, ef.make_elf([ef.Segment(0x1000, code)])))
    assert header["global_reason"] is None
    assert header["mapping"]["format"] == "elf" and header["mapping"]["load_bias"] == GHIDRA_PIE_BASE
    assert rows[("mapping", "original", "bundle")].verdict == "applied"
    for key in ("function-000000/1:101000", "function-000000/1:101005", "function-000001/1:101010",
                "function-000001/1:101013"):
        row = rows[("decode", "row", key)]
        assert (row.run_state, row.verdict) == ("evaluated", "applied"), (key, row.detail)


@needs
def test_elf_relocation_over_code_is_a_loader_written_range(tmp_path):
    """A text relocation (R_X86_64_RELATIVE) over B's first bytes: the loader rewrites them."""
    import _elf_fixture as ef
    import _sealed as s

    functions, code = _pair(s, code=ELF_CODE)
    elf = ef.make_elf([ef.Segment(0x1000, code)], relocations=[ef.Reloc(0x1010, 8, addend=0)])
    _, rows = _run(_elf_bundle(tmp_path, functions, elf))
    row = rows[("decode", "row", "function-000001/1:101010")]
    assert row.run_state == "unobserved" and "R_X86_64_RELATIVE" in row.detail["reason"], row.detail
    assert rows[("decode", "row", "function-000000/1:101000")].verdict == "applied"
    block = next(r for ident, r in rows.items() if ident[1] == "block" and ident[2].endswith(":101000"))
    assert block.detail["written"] == 8 and block.verdict == "applied"


@needs
def test_elf_exec_not_at_its_linked_base_is_not_compared(tmp_path):
    import _elf_fixture as ef
    import _sealed as s

    functions, code = _pair(s, code=0x501000)
    elf = ef.make_elf([ef.Segment(0x401000, code)], e_type=2, link_base=0x400000)
    header, _ = _run(_elf_bundle(tmp_path, functions, elf, bias=0x100000, program_base=0x500000))
    assert "linked (ET_EXEC)" in header["global_reason"]


def _elf(*args, **kwargs):
    import _elf_fixture as ef
    import elf_map

    return elf_map.parse(ef.make_elf(*args, **kwargs).data)


def test_elf_map_basic_ranges_and_zero_fill():
    import _elf_fixture as ef

    image = _elf([ef.Segment(0x1000, b"\x90" * 0x10, memsz=0x40, flags=6)])
    assert image.ok and image.image_base == 0 and not image.fixed_base
    assert image.at(0x1000).kind == "file" and image.at(0x1010).kind == "zero" and image.at(0x1040) is None
    assert image.written.state == "complete"


def test_elf_map_incongruent_or_oversized_segments_are_ambiguous():
    import _elf_fixture as ef

    assert _elf([ef.Segment(0x1000, b"\x90" * 8, offset=0x1100)]).at(0x1000).kind == "ambiguous"
    assert _elf([ef.Segment(0x1000, b"\x90" * 8, memsz=4)]).at(0x1000).kind == "ambiguous"


def test_elf_map_pages_two_segments_share_are_ambiguous():
    import _elf_fixture as ef

    image = _elf([ef.Segment(0x1000, b"\x90" * 0x100), ef.Segment(0x1800, b"\xCC" * 0x100, offset=0x2800)])
    assert image.at(0x1000).kind == "ambiguous" and image.at(0x1800).kind == "ambiguous"


def test_elf_map_relocation_widths_relr_and_copy():
    import _elf_fixture as ef

    image = _elf([ef.Segment(0x1000, b"\x90" * 0x100)],
                 relocations=[ef.Reloc(0x1000, 2), ef.Reloc(0x1020, 5, symbol=1), ef.Reloc(0x1040, 99),
                              ef.Reloc(0x1060, 0)],
                 relr=[0x2000, (0b101 << 1) | 1], symbol_sizes=[0, 12], pltgot=0x3000)
    targets = {(start, end, label) for start, end, label in image.written.ranges}
    assert image.written.state == "complete"
    assert (0x1000, 0x1004, "R_X86_64_PC32") in targets
    assert (0x1020, 0x102C, "R_X86_64_COPY") in targets
    assert (0x1040, 0x1050, "R_X86_64_99-unknown-width") in targets
    assert not any(start == 0x1060 for start, _, _ in targets)           # R_X86_64_NONE writes nothing
    assert {(0x2000, 0x2008), (0x2008, 0x2010), (0x2018, 0x2020)} <= {(a, b) for a, b, l in targets if l == "RELR"}
    assert (0x3008, 0x3018, "got-plt-reserved") in targets
    assert any(label == "dynamic" for _, _, label in targets)


def test_elf_map_android_packed_or_static_without_sections_is_indeterminate():
    import _elf_fixture as ef

    android = _elf([ef.Segment(0x1000, b"\x90")], extra_dynamic=[(0x6000000F, 0x2000), (0x60000010, 8)])
    assert android.written.state == "indeterminate" and "Android packed" in android.written.why
    static = _elf([ef.Segment(0x1000, b"\x90")], dynamic=False)
    assert static.written.state == "indeterminate" and "static image" in static.written.why


def _dependents(header, rows):
    found = {}
    for ident, row in rows.items():
        if ident[0] == "dependents":
            found[(ident[1], ident[2])] = row
    return header["dependents"]["summary"], found


@needs
def test_dependents_of_the_reference_pair_are_all_confirmed(tmp_path):
    import _sealed as s

    functions, code = _pair(s)
    header, rows = _run(_bundle(tmp_path, functions, code))
    summary, found = _dependents(header, rows)
    assert summary["s1"] == {"units": 2, "baseline_present": 2, "confirmed": 2, "would_block_disagreement": 0,
                             "would_block_unobserved": 0, "loss": 0, "loss_unknown": 0}
    for consumer in ("push_projection", "push_relation", "plain_push", "call_seed", "return_shape"):
        assert summary[consumer]["confirmed"] == summary[consumer]["units"] >= 1, (consumer, summary[consumer])
    assert all(not row.detail["would_block"] for row in found.values())   # (--full: every unit has a row)
    assert set(header["dependents"]["undetermined"]) == {"rp", "pass_through"}


@needs
def test_dependents_flip_only_is_call_r4_s6(tmp_path):
    """r4 s6 vector: a direct CALL with all three push facts, only `is_call` flipped:
    S1 population kept (and blocked by the F.is_call disagreement), push projection
    lost, push relation lost (relations iterate surviving projections), plain push kept."""
    import _sealed as s

    functions, code = _pair(s)
    functions[0].observation["instructions"][0]["flow_type"] = s.flow(is_flow=True, has_fallthrough=True,
                                                                       is_unconditional=True)
    header, rows = _run(_bundle(tmp_path, functions, code))
    _, found = _dependents(header, rows)
    call = next(key for consumer, key in found if consumer == "call_seed" and key.startswith("function-000000/"))
    s1 = found[("s1", "function-000000")]
    assert s1.detail["would_block"] and s1.detail["loss"] == 1 and s1.detail["baseline"] is True, s1.detail
    assert ["140001000", "F.is_call", "unrecognized"] in s1.detail["blocking"]
    projection = found[("push_projection", call)]
    relation = found[("push_relation", call)]
    assert projection.detail["baseline"] is False and projection.detail["loss"] == 0, projection.detail
    assert relation.detail["baseline"] is False and relation.detail["loss"] == 0, relation.detail
    plain = found[("plain_push", call)]
    assert plain.detail["baseline"] is True and not plain.detail["would_block"], plain.detail


@needs
def test_dependents_of_a_withheld_call_block_s1_and_the_seed(tmp_path):
    import _sealed as s

    functions, code = _pair(s, call_bytes=b"\x66\xE8\x0A\x00\x00\x00")
    header, rows = _run(_bundle(tmp_path, functions, code))
    summary, found = _dependents(header, rows)
    s1 = found[("s1", "function-000000")]
    assert (s1.run_state, s1.verdict) == ("evaluated", "withheld") and s1.detail["cause"] == "disagreement"
    assert summary["s1"]["loss"] == 1 and summary["call_seed"]["would_block_disagreement"] == 1


def test_dependents_core_counts_estimates_and_unobserved():
    import dependents

    function = {"function_id": "f", "s1": False,
                "rows": [{"address": 0x10, "native_call": True}, {"address": 0x15, "native_call": False}],
                "baseline": {"calls": [{"op": "1:10:1:CALL", "address": 0x10, "opcode": "CALL",
                                        "facts": {"naming": "applied", "push_projection": "applied",
                                                  "push_relation": "applied", "plain_push": "not_applicable"}}],
                             "exits": [], "branchind": [{"site": "control:x:1:15", "address": 0x15,
                                                         "unknown_transfer": True}], "returns": []}}
    states = {0x10: {"a7": "withheld"}, 0x15: {"*": "unobserved"}}
    judged = {(consumer, key): (run_state, verdict, detail)
              for consumer, key, run_state, verdict, detail in dependents.function_rows(function, states)}
    assert judged[("s1", "f")][2]["would_block"] is False                 # (a7 is not an S1 read)
    assert judged[("push_projection", "f/1:10:1:CALL")][1] == "withheld"
    assert judged[("push_projection", "f/1:10:1:CALL")][2]["loss"] == 1
    assert ("plain_push", "f/1:10:1:CALL") not in judged                  # (not a plain-push candidate)
    g3b7b = judged[("g3b7b_none_estimate", "f")]
    assert g3b7b[0] == "unobserved" and g3b7b[2]["loss"] == "unknown" and g3b7b[2]["branchind_rows"] == 1
    site = judged[("unknown_transfer_site", "f/control:x:1:15")]
    assert site[2]["cause"] == "unobserved" and site[2]["unknown_transfer"] is True
    summary = dependents.summary([(c, k, *v) for (c, k), v in judged.items()])
    assert summary["g3b7b_none_estimate"]["loss_unknown"] == 1 and summary["push_projection"]["loss"] == 1


INTERNAL = {"kind": "CONSTANT"}   # (an intra-instruction p-code branch destination)
RAM = {"kind": "MEMORY"}


@pytest.mark.parametrize("data, ops, expected", [
    (bytes.fromhex("660f44c1"), [("CBRANCH", INTERNAL), ("COPY", None)], False),   # 66 CMOVcc: internal branch only
    (bytes.fromhex("660f7f01"), [("STORE", None)], False),                       # 66 movdqa: no transfer op
    (bytes.fromhex("66e80a000000"), [("STORE", None), ("CALL", RAM)], True),     # 66 near CALL
    (bytes.fromhex("6767ff10"), [("LOAD", None), ("CALLIND", None)], True),      # 67 67 indirect CALL
    (bytes.fromhex("f366e800000000"), [("STORE", None), ("CALL", RAM)], True),   # r4 s8: 66 not the first byte
    (bytes.fromhex("66c3"), [("LOAD", None), ("RETURN", None)], True),           # 66 ret (terminal)
    (bytes.fromhex("66e90000"), [("BRANCH", RAM)], True),                        # 66 near jmp
    (bytes.fromhex("e800000000"), [("STORE", None), ("CALL", RAM)], False),      # plain near CALL
    (bytes.fromhex("4040e9"), [("BRANCH", RAM)], True),                          # repeated REX on a transfer
    (bytes.fromhex("f3"), [("CALL", RAM)], "unobserved"),                        # (verified bytes end first)
])
def test_guard_row_condition_vectors(data, ops, expected):
    import guards

    facts = {"length": 6 if data == b"\xf3" else len(data),
             "ops": [{"opcode": name, "inputs": [target]} for name, target in ops]}
    assert guards.row_condition(facts, data) == expected


def test_guard_intra_instruction_skips_need_the_lift_table():
    """66 0F 47 (16-bit CMOVA) lifts CBRANCH to the next address; EB 00 (jmp $+2) lifts a
    BRANCH to the same address and is a real jump. Only the lift table tells them apart."""
    import guards
    import lifting

    start = 0x1000
    nxt = {"kind": "MEMORY", "offset": start + 4, "space": 1, "size": 8}
    cmov = {"address": start, "length": 4, "fallthrough": start + 4, "exit": None,
            "ops": [{"opcode": "CBRANCH", "inputs": [nxt, {"kind": "UNIQUE", "offset": 0, "size": 1}]},
                    {"opcode": "COPY", "inputs": [{"kind": "REGISTER", "offset": 0, "size": 2}],
                     "output": {"kind": "REGISTER", "offset": 0, "size": 2}}]}
    data = bytes.fromhex("660f47c1")
    assert guards.row_condition(cmov, data, None) == "unobserved"                      # (no premise)
    assert guards.row_condition(cmov, data, lifting.Lift("cmov", {}, {}, (0,))) is False
    jump = {"address": start, "length": 3, "ops": [{"opcode": "BRANCH", "inputs": [
        {"kind": "MEMORY", "offset": start + 3, "space": 1, "size": 8}]}]}
    assert guards.row_condition(jump, bytes.fromhex("66eb00"), lifting.Lift("jmp", {})) is True


def test_guard_function_condition_is_x86_64_only():
    import guards

    assert guards.function_condition("x86:LE:64:default", [False, True]) is True
    assert guards.function_condition("x86:LE:64:default", [False, "unobserved"]) == "unobserved"
    assert guards.function_condition("x86:LE:64:default", [False]) is False
    assert guards.function_condition("x86:LE:32:default", [True]) is False


@needs
def test_s1_guard_rows_keep_recomputed_apart_from_firing(tmp_path):
    import _sealed as s

    functions, code = _pair(s, call_bytes=b"\x66\xE8\x0A\x00\x00\x00")
    del functions[1].observation["call_fallthrough"]       # (B: a function without S1)
    functions[1].observation.pop("fallthrough_exits", None)
    header, rows = _run(_bundle(tmp_path, functions, code))
    a = rows[("decode", "s1_guard", "function-000000")]
    assert (a.run_state, a.verdict) == ("evaluated", "withheld")
    assert a.detail["recomputed"] is True and a.detail["fired_at_production"] == "unobserved"
    assert a.detail["s1_observed"] is True and a.detail["rows"] == ["140001000"]
    b = rows[("decode", "s1_guard", "function-000001")]
    assert (b.verdict, b.detail["recomputed"], b.detail["s1_observed"]) == ("applied", False, False)
    assert header["guard"]["language_agrees"] and header["guard"]["machine"] == 0x8664
    assert rows[("decode", "row", "function-000000/1:140001000")].detail["guard"]["recomputed"] is True


def test_semantics_layer_is_reserved_and_never_counted():
    import decode_check
    from report import LAYERS, Row

    assert "semantics" in LAYERS and "semantics" in decode_check.RESERVED_LAYERS
    rows = [Row("decode", "row", "f/1:10", "evaluated", "applied", "lint"),
            Row("semantics", "rw_sets", "f/1:10", "evaluated", "applied", "lint"),
            Row("dependents", "s1", "f", "evaluated", "applied", "lint")]
    assert decode_check.g1_counts(rows) == {"decode/row": {"applied": 1}}


def test_elf_map_rejects_other_machines_and_types():
    import _elf_fixture as ef

    assert not _elf([ef.Segment(0x1000, b"\x90")], machine=183).ok          # EM_AARCH64: later
    assert not _elf([ef.Segment(0x1000, b"\x90")], e_type=1).ok             # ET_REL
