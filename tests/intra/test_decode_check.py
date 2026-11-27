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


# -- golden vectors (r3 s9): synthetic Bundles only; the Python / Rust parity reference

GOLDEN = REPO / "tests" / "intra" / "golden"


def _golden(name, generation):
    """The full report (every attribute and vote) minus the host's decoder build
    manifest. G1_REGEN_GOLDEN=1 rewrites the file after a reviewed change."""
    import json

    import _sealed as s
    import decode_check
    from report import dumps

    header, rows = decode_check.run(generation, s.NAMING_SOURCE, True, full=True)
    data = json.loads(dumps(header, rows))
    data["header"].pop("decoders")
    path = GOLDEN / f"decode_check_{name}.json"
    if os.environ.get("G1_REGEN_GOLDEN"):
        GOLDEN.mkdir(exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(data, indent=1, sort_keys=True) + "\n")
    assert json.loads(path.read_text(encoding="utf-8")) == data, f"golden {path.name} differs"


@needs
def test_golden_reference_pair(tmp_path):
    import _sealed as s

    functions, code = _pair(s)
    _golden("pair", _bundle(tmp_path, functions, code))


@needs
def test_golden_66_e8_pair(tmp_path):
    """Withheld call row, s1_guard true, S1 and the call seed blocked in dependents."""
    import _sealed as s

    functions, code = _pair(s, call_bytes=b"\x66\xE8\x0A\x00\x00\x00")
    _golden("pair_66e8", _bundle(tmp_path, functions, code))


@needs
def test_golden_elf_pie_with_a_text_relocation(tmp_path):
    import _elf_fixture as ef
    import _sealed as s

    functions, code = _pair(s, code=ELF_CODE)
    elf = ef.make_elf([ef.Segment(0x1000, code)], relocations=[ef.Reloc(0x1010, 8)])
    _golden("elf_pie_reloc", _elf_bundle(tmp_path, functions, elf))


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
                             "would_block_unobserved": 0, "would_block_refused": 0, "would_block_override": 0,
                             "loss_disagreement": 0, "loss_unobserved": 0, "loss_refused": 0, "loss_override": 0,
                             "loss_unknown": 0}
    for consumer in ("push_projection", "push_relation", "plain_push", "call_seed", "return_shape", "s1_l2_estimate"):
        assert summary[consumer]["confirmed"] == summary[consumer]["units"] >= 1, (consumer, summary[consumer])
    # (r3 s6: the G3b-7b estimate needs getParsedLength / prototype flow, which no Bundle exports)
    g3b7b = [row for (consumer, _), row in found.items() if consumer == "g3b7b_none_estimate"]
    assert g3b7b and all(row.run_state == "unobserved" and row.detail["loss"] == "unknown" for row in g3b7b)
    assert all(not row.detail["would_block"] for (consumer, _), row in found.items()
               if consumer != "g3b7b_none_estimate")   # (--full: every unit has a row)
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
    assert ["1:140001000", "F.is_call", "unrecognized"] in s1.detail["blocking"]
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
    assert summary["s1"]["loss_disagreement"] == 1 and summary["call_seed"]["would_block_disagreement"] == 1
    assert summary["s1"]["loss_unobserved"] == 0


def test_dependents_core_counts_estimates_and_unobserved():
    import dependents

    function = {"function_id": "f", "s1": False,
                "rows": [{"address": 0x10, "native_call": True}, {"address": 0x15, "native_call": False}],
                "baseline": {"calls": [{"op": "1:10:1:CALL", "address": 0x10, "opcode": "CALL",
                                        "facts": {"naming": "applied", "push_projection": "applied",
                                                  "push_relation": "applied", "plain_push": "not_applicable"}}],
                             "exits": [], "branchind": [{"site": "control:x:1:15", "address": 0x15,
                                                         "unknown_transfer": True}], "returns": []}}
    import compare

    compared = frozenset(compare.COMPARED)
    states = {0x10: {"a7": "withheld", "+": compared - {"a7"}}, 0x15: {"*": "unobserved"}}
    judged = {(consumer, key): (run_state, verdict, detail)
              for consumer, key, run_state, verdict, detail in dependents.function_rows(function, states)}
    assert judged[("s1", "f")][2]["would_block"] is False                 # (a7 is not an S1 read)
    assert judged[("push_projection", "f/1:10:1:CALL")][1] == "withheld"
    assert judged[("push_projection", "f/1:10:1:CALL")][2]["loss"] == 1
    assert ("plain_push", "f/1:10:1:CALL") not in judged                  # (not a plain-push candidate)
    g3b7b = judged[("g3b7b_none_estimate", "f")]
    assert (g3b7b[0], g3b7b[1]) == ("evaluated", "withheld") and g3b7b[2]["cause"] == "refused"   # (a BRANCHIND row)
    from report import Row
    Row("dependents", "g3b7b_none_estimate", "f", *g3b7b[:2], "lint", g3b7b[2])   # (a valid report row)
    assert g3b7b[2]["loss"] == "unknown" and g3b7b[2]["branchind_rows"] == 1
    site = judged[("unknown_transfer_site", "f/control:x:1:15")]
    assert site[2]["cause"] == "unobserved" and site[2]["unknown_transfer"] is True
    summary = dependents.summary([(c, k, *v) for (c, k), v in judged.items()])
    assert summary["g3b7b_none_estimate"]["loss_unknown"] == 1 and summary["push_projection"]["loss_disagreement"] == 1
    # an attribute a row did not compare is never confirmed (Astra impl r1 P1-1)
    assert dependents._status({"+": frozenset({"a2"})}, "a4") == "unobserved"
    assert dependents._status({"*": "unobserved"}, "a2") == "unobserved"


def test_dependents_reads_are_compared_attributes():
    """Fable impl r1 P3: every read names an attribute compare_row produces."""
    import compare
    import dependents

    reads = set(dependents.CALL_READS) | set(dependents.G3B7B_READS) | set(dependents.L2_EXTRA) | {"a7"}
    for names in dependents.READS.values():
        reads |= set(names)
    assert reads <= set(compare.COMPARED), reads - set(compare.COMPARED)


@needs
def test_dependents_of_a_never_compared_call_are_unobserved_not_confirmed(tmp_path):
    """Astra impl r1 P1-1: a native CALL whose bytes are not verified must not confirm S1."""
    import _sealed as s

    functions, code = _pair(s)
    raw = bytearray(code)
    raw[1] ^= 0xFF   # (the file's call displacement differs: the window stops after one byte)
    header, rows = _run(_bundle(tmp_path, functions, code, code_raw=bytes(raw)))
    _, found = _dependents(header, rows)
    s1 = found[("s1", "function-000000")]
    assert s1.detail["would_block"] and s1.detail["cause"] == "unobserved" and s1.detail["loss"] == 1, s1.detail


# -- realistic p-code rows (engine varnode kinds ADDRESS / CONSTANT / REGISTER / UNIQUE) for pure vectors
START = 0x140001000
RSP_, RAX_, RCX_, RIP_ = 0x20, 0x00, 0x08, 0x288


def _a(offset):
    return {"kind": "ADDRESS", "space": 1, "offset": offset, "size": 8}


def _c(value, size=8):
    return {"kind": "CONSTANT", "space": 0, "offset": value, "size": size}


def _r(offset, size=8):
    return {"kind": "REGISTER", "space": 2, "offset": offset, "size": size}


def _u(offset, size=8):
    return {"kind": "UNIQUE", "space": 3, "offset": offset, "size": size}


def _op(opcode, inputs, output=None):
    return {"opcode": opcode, "inputs": inputs, "output": output}


def _push(value, width=8):
    return [_op("INT_SUB", [_r(RSP_), _c(width)], _r(RSP_)), _op("STORE", [_c(1), _r(RSP_), _c(value, width)])]


def _row(length, ops, *, fallthrough=True, flow=None):
    nxt = None if length is None else START + length
    return {"address": START, "space": 1, "length": length, "ops": ops, "exit": None,
            "fallthrough": nxt if fallthrough and nxt is not None else None, "flow_targets": [],
            "flow": flow or {"is_flow": True, "has_fallthrough": fallthrough, "is_call": False, "is_jump": False,
                             "is_terminal": False, "is_computed": False, "is_conditional": False,
                             "is_unconditional": True, "is_override": False}}


def _cmov(length):
    nxt = None if length is None else START + length
    return [_op("BOOL_NEGATE", [_r(0x206, 1)], _u(0x100, 1)),
            _op("CBRANCH", [_a(nxt if nxt is not None else START + 4), _u(0x100, 1)]),
            _op("COPY", [_r(RCX_, 2)], _r(RAX_, 2))]


def _rep(length, last_ok=True):
    nxt = START + length
    ops = [_op("INT_EQUAL", [_r(RCX_), _c(0)], _u(0x10, 1)), _op("CBRANCH", [_a(nxt), _u(0x10, 1)]),
           _op("LOAD", [_c(1), _r(0x30)], _u(0x20, 2)), _op("STORE", [_c(1), _r(0x38), _u(0x20, 2)]),
           _op("INT_SUB", [_r(RCX_), _c(1)], _r(RCX_))]
    ops.append(_op("BRANCH", [_a(START)]) if last_ok else _op("CBRANCH", [_a(START), _u(0x10, 1)]))
    return ops


GUARD_VECTORS = [
    # (name, bytes, row, pattern, expected recomputed condition)
    ("66 CMOVcc", "660f44c1", _row(4, _cmov(4)), "cmov", False),
    ("66 CMOVcc without length", "660f44c1", _row(None, _cmov(None), fallthrough=False), "unidentified",
     "unobserved"),
    ("66 movdqa", "660f7f01", _row(4, [_op("STORE", [_c(1), _r(0x10), _r(0x1200, 16)])]), "plain", False),
    ("66 near CALL", "66e80a000000", _row(6, _push(START + 6) + [_op("CALL", [_a(START + 0x10)])]), "call", True),
    ("67 67 indirect CALL", "6767ff10",
     _row(4, [_op("LOAD", [_c(1), _r(RAX_)], _u(0x30))] + _push(START + 4) + [_op("CALLIND", [_u(0x30)])]),
     "call indirect", True),
    ("F3 66 E8 (66 not first)", "f366e800000000", _row(7, _push(START + 7) + [_op("CALL", [_a(START + 7)])]),
     "call", True),
    ("66 ret", "66c3", _row(2, [_op("LOAD", [_c(1), _r(RSP_)], _r(RIP_, 2)), _op("INT_ADD", [_r(RSP_), _c(2)], _r(RSP_)),
                                _op("RETURN", [_r(RIP_, 2)])], fallthrough=False), "ret", True),
    ("66 near jmp", "66e91000", _row(4, [_op("BRANCH", [_a(START + 0x14)])], fallthrough=False), "jmp", True),
    ("66 jmp $+3 (a real jump to next)", "66eb00", _row(3, [_op("BRANCH", [_a(START + 3)])], fallthrough=False),
     "jmp", True),
    ("plain near CALL", "e800000000", _row(5, _push(START + 5) + [_op("CALL", [_a(START + 0x20)])]), "call", False),
    ("repeated REX on a jmp", "4040e900000000", _row(7, [_op("BRANCH", [_a(START + 0x30)])], fallthrough=False),
     "jmp", True),
    ("66 rep movsw", "66f3a5", _row(3, _rep(3)), "rep", False),
    ("66 rep movsw, unidentified form", "66f3a5", _row(3, _rep(3, last_ok=False)), "unidentified", "unobserved"),
]


@pytest.mark.parametrize("name, data, facts, pattern, expected", GUARD_VECTORS, ids=[v[0] for v in GUARD_VECTORS])
def test_guard_row_condition_vectors(name, data, facts, pattern, expected):
    """r3 s8 / r4 s8 guard vectors on realistic p-code through the real lift table."""
    import guards
    import lifting

    lift = lifting.identify(facts)
    assert lift.pattern == pattern, (name, lift)
    assert guards.row_condition(facts, bytes.fromhex(data), lift) == expected, name


def test_guard_without_the_lift_table_keeps_self_or_next_branches_unobserved():
    import guards

    facts = _row(4, _cmov(4))
    assert guards.row_condition(facts, bytes.fromhex("660f44c1"), None) == "unobserved"
    jump = _row(4, [_op("BRANCH", [_a(START + 0x14)])], fallthrough=False)      # (target elsewhere: decidable)
    assert guards.row_condition(jump, bytes.fromhex("66e91000"), None) is True
    assert guards.row_condition(_row(1, [], flow={"is_call": True}), bytes.fromhex("66"), None) == "unobserved"
    assert guards.row_condition(_row(2, [_op("CALL", [_a(START)])]), bytes.fromhex("f3"), None) == "unobserved"


def _flow(form, **changes):
    import lifting

    bits = dict(lifting.LISTING_BITS[form]) if form else {
        "has_fallthrough": True, "is_call": False, "is_jump": False, "is_terminal": False, "is_computed": False,
        "is_conditional": False, "is_flow": True, "is_unconditional": True}
    bits["is_override"] = False
    bits.update(changes)
    return bits


def _compare(facts, data, *, s1=False, native_call=False):
    import compare
    import decoders
    import lifting

    window = {"bytes": data, "verified": len(data) if len(data) >= 15 else len(data), "stop": "test",
              "relocations": []}
    lift = lifting.identify(facts)
    result = compare.compare_row(facts, lift, window, decoders.ballot(data, facts["address"]), s1=s1,
                                 native_call=native_call, premise=True)
    return lift, result


def _jcc(length, target, condition_ops=None):
    ops = condition_ops if condition_ops is not None else [_op("BOOL_NEGATE", [_r(0x206, 1)], _u(0x100, 1))]
    return _row(length, ops + [_op("CBRANCH", [_a(target), _u(0x100, 1)])], flow=_flow("jcc"))


LOOP = [_op("INT_SUB", [_r(RCX_), _c(1)], _r(RCX_)), _op("INT_NOTEQUAL", [_r(RCX_), _c(0)], _u(0x100, 1))]
JRCXZ = [_op("INT_EQUAL", [_r(RCX_), _c(0)], _u(0x100, 1))]
PAD = "cc" * 13   # (the rest of a 15-byte window: int3 bytes after the instruction)

R4_S1_VECTORS = [
    # (name, bytes, facts, pattern, {attribute: expected state / value}, row state)
    ("75 00", "7500", _jcc(2, START + 2), "jcc", {"a5": START + 2, "a8": "applied"}, "applied"),
    ("75 FE", "75fe", _jcc(2, START), "jcc", {"a5": START, "a8": "applied"}, "applied"),
    ("74 00", "7400", _jcc(2, START + 2, []), "jcc", {"a5": START + 2}, "applied"),
    ("EB 00", "eb00", _row(2, [_op("BRANCH", [_a(START + 2)])], fallthrough=False, flow=_flow("jmp_direct")),
     "jmp", {"a5": START + 2, "a8": "applied"}, "applied"),
    ("74 FE", "74fe", _jcc(2, START, []), "jcc", {"a5": START}, "applied"),
    ("E2 FE", "e2fe", _jcc(2, START, LOOP), "jcc", {"a5": START, "a12": 64}, "applied"),
    ("E3 FE", "e3fe", _jcc(2, START, JRCXZ), "jcc", {"a5": START, "a12": 64}, "applied"),
    ("E3 00", "e300", _jcc(2, START + 2, JRCXZ), "jcc", {"a5": START + 2, "a12": 64}, "applied"),
    ("F4", "f4", _row(1, [_op("BRANCH", [_a(START)])], fallthrough=False, flow=_flow("jmp_direct")), "branch-self",
     {"a5": "unobserved", "a8": "unobserved"}, "unobserved"),
    ("EB FE", "ebfe", _row(2, [_op("BRANCH", [_a(START)])], fallthrough=False, flow=_flow("jmp_direct")),
     "branch-self", {"a5": "unobserved", "a8": "unobserved"}, "unobserved"),
    ("48 0F 44 C1", "480f44c1", _row(4, _cmov(4)), "cmov", {"a8": "applied", "F.is_jump": "applied"}, "applied"),
    ("66 0F 44 C1", "660f44c1", _row(4, _cmov(4)), "cmov", {"a8": "applied", "F.is_jump": "applied"}, "applied"),
    ("F3 A4", "f3a4", _row(2, _rep(2)), "rep", {"a8": "applied", "F.is_jump": "applied"}, "applied"),
]


@needs
@pytest.mark.parametrize("name, data, facts, pattern, expect, row_state", R4_S1_VECTORS,
                         ids=[v[0] for v in R4_S1_VECTORS])
def test_r4_s1_lift_vectors(name, data, facts, pattern, expect, row_state):
    """r4 s1: intra-instruction skips by pattern ordinal, never by target identity (Fable impl r1 P1-2).
    cmov / rep listing bits are pinned to the no-transfer form (lift table -5, real-Bundle data check)."""
    lift, result = _compare(facts, bytes.fromhex(data + PAD))
    assert lift.pattern == pattern, (name, lift)
    for attribute, wanted in expect.items():
        item = result["attributes"][attribute]
        if wanted in ("applied", "unobserved"):
            assert item["state"] == wanted, (name, attribute, item)
        else:
            assert item["state"] == "applied" and item["value"] == wanted, (name, attribute, item)
    assert result["state"] == row_state, (name, result["state"], result["attributes"])


@needs
def test_r4_s3_66_e9_high_address_is_withheld():
    """VA 0x140001000, 66 E9 00 00 00 00: Intel 6 bytes / 0x140001006, AMD 4 bytes / 0x1004 -> withheld."""
    facts = _row(4, [_op("BRANCH", [_a(0x1004)])], fallthrough=False, flow=_flow("jmp_direct"))
    _, result = _compare(facts, bytes.fromhex("66e900000000" + "cc" * 9))
    assert result["state"].startswith("withheld"), result["attributes"]


@needs
def test_r4_s5_length_and_listing_continuation_are_compared_apart():
    """90, length 1, listing continuation start + 2: A2 applied, A4 unrecognized."""
    facts = _row(1, [])
    facts["fallthrough"] = START + 2
    _, result = _compare(facts, bytes.fromhex("90" + PAD + "cc"))
    assert result["attributes"]["a2"]["state"] == "applied"
    assert result["attributes"]["a4"]["state"] == "unrecognized"


@needs
@pytest.mark.parametrize("data, ops, form, pattern", [
    ("ff1500010000", [_op("LOAD", [_c(1), _c(START + 6 + 0x100)], _u(0x40))] + _push(START + 6)
     + [_op("CALLIND", [_u(0x40)])], "call_indirect", "call indirect"),
    ("ff2500010000", [_op("LOAD", [_c(1), _c(START + 6 + 0x100)], _u(0x40)), _op("BRANCHIND", [_u(0x40)])],
     "jmp_indirect", "jmp indirect"),
])
def test_r4_s8_ff15_ff25_full_bytes(data, ops, form, pattern):
    facts = _row(6, ops, fallthrough=form.startswith("call"), flow=_flow(form))
    lift, result = _compare(facts, bytes.fromhex(data + "cc" * 9), native_call=form.startswith("call"))
    assert lift.pattern == pattern
    assert result["state"] == "applied", result["attributes"]


@needs
def test_r3_s2_no_length_outside_a_native_call_leaves_a2_unobserved():
    facts = _row(None, [])
    facts["fallthrough"] = START + 1
    _, result = _compare(facts, bytes.fromhex("90" + PAD + "cc"), s1=True)
    assert result["attributes"]["a2"]["state"] == "unobserved"


@pytest.mark.parametrize("name, facts, pattern", [
    ("E8 00000000 with length", _row(5, _push(START + 5) + [_op("CALL", [_a(START + 5)])], flow=_flow("call_direct")),
     "call"),
    ("push + BRANCH(next), length missing", _row(None, _push(START + 5) + [_op("BRANCH", [_a(START + 5)])],
                                                 fallthrough=False), "unidentified"),
    ("call $+5 lifted as push + BRANCH(next)", _row(5, _push(START + 5) + [_op("BRANCH", [_a(START + 5)])]),
     "call $+5"),
    ("far call FF 1C 25 (two pushes)", _row(7, [_op("LOAD", [_c(1), _c(0x2000)], _u(0x40))] + _push(0x33, 8)
                                            + _push(START + 7) + [_op("CALLIND", [_u(0x40)])]), "unidentified"),
    ("push with another base register", _row(5, [_op("INT_SUB", [_r(RCX_), _c(8)], _r(RSP_)),
                                                 _op("STORE", [_c(1), _r(RSP_), _c(START + 5)]),
                                                 _op("CALL", [_a(START + 0x40)])]), "unidentified"),
], ids=lambda v: v if isinstance(v, str) else None)
def test_near_call_shape_is_exact(name, facts, pattern):
    """Astra impl r1 P1-5 / Fable P2-1: exactly allowed prefix ops ; INT_SUB RSP = RSP - c ; STORE [RSP] ; flow."""
    import lifting

    assert lifting.identify(facts).pattern == pattern, name


@needs
def test_translation_identity_mismatch_refuses_the_table_even_with_the_premise(tmp_path):
    """r4 s2 (Astra impl r1 P1-4): stock / mismatched / digest-missing differ."""
    import _pe_fixture as pf
    import _sealed as s
    import decode_check

    functions, code = _pair(s)
    section = pf.Section(".text", 0x1000, code)
    original = pf.make_pe([section])
    blocks = [s.Block(start=start, data=data, name=".text" if start != BASE else "Headers")
              for start, data in pf.blocks_for([section], original)]
    bundle = s.Bundle(functions, blocks=blocks, program=s.program(image_base=BASE, language=("x86:LE:64:default", 4, 5)),
                      overrides={"original": original})
    os.chmod(tmp_path, 0o755)
    header, rows = decode_check.run(s.write(tmp_path, bundle), s.NAMING_SOURCE, True, full=True)
    identity = header["translation_identity"]
    assert identity["state"] == "mismatch" and identity["table_applied"] is False
    call = next(row for row in rows if row.layer == "decode" and row.key == "function-000000/1:140001000")
    assert call.detail["attributes"]["a5"]["reason"].startswith("translation identity mismatch")
    # the stock language: the digest is missing; the premise covers it (table applied), recorded as such
    header2, _ = _run(_bundle(tmp_path / "stock", *_pair(s)) if (tmp_path / "stock").mkdir() is None else None)
    assert header2["translation_identity"]["state"] == "missing-digest"
    assert header2["translation_identity"]["table_applied"] is True
    assert header2["translation_identity"]["checks"]["sla_digest"].startswith("missing")


# -- implementation review r2 (Astra REJECT, Fable APPROVE with P2): each test fails on the r1 behaviour

def _judged(function, states):
    import dependents

    return {(consumer, key): (run_state, verdict, detail)
            for consumer, key, run_state, verdict, detail in dependents.function_rows(function, states)}


def _fn(rows, *, s1=True, calls=(), branchind=(), returns=(), exits=()):
    return {"function_id": "f", "s1": s1, "rows": rows,
            "baseline": {"calls": list(calls), "exits": list(exits), "branchind": list(branchind),
                         "returns": list(returns)}}


def _ok(*bad):
    import compare

    return frozenset(compare.COMPARED) - set(bad)


def test_r2_l2_counts_a7_and_a1_disagreements_of_non_native_rows():
    """Astra impl r2 P1-1: a call $+5 (push + BRANCH, native_call False) with only A7 wrong, and an all-invalid
    row (A1), must block the L2 estimate; a non-call row with only A2 wrong too (P2-4)."""
    rows = [{"space": 1, "address": 0x10, "native_call": False}]
    for bad, state in (("a7", "unrecognized"), ("a1", "unrecognized"), ("a2", "unrecognized")):
        judged = _judged(_fn(rows), {(1, 0x10): {bad: state, "+": _ok(bad)}})
        assert judged[("s1_l2_estimate", "f")][2]["would_block"], bad
        assert not judged[("s1", "f")][2]["would_block"], bad      # (not an S1 read for a non-native row)


def test_r2_rows_of_different_spaces_never_share_a_state():
    """Astra impl r2 P1-2: an unverified native CALL and a verified one at the same offset of another space."""
    rows = [{"space": 1, "address": 0x10, "native_call": True}, {"space": 2, "address": 0x10, "native_call": True}]
    judged = _judged(_fn(rows), {(1, 0x10): {"*": "unobserved"}, (2, 0x10): {"+": _ok()}})
    s1 = judged[("s1", "f")][2]
    assert s1["would_block"] and s1["blocking"][0][0] == "1:10"


def test_r2_u2a_and_resolved_site_losses_point_the_right_way():
    """Fable impl r2 P2-1 / Astra r2 P2-4: an UNKNOWN site has no U2a loss to measure as 'resolved'; a resolved
    site whose A8 disagrees loses its complete successor set (loss 1); unknown_transfer False -> U2a loss 0."""
    rows = [{"space": 1, "address": 0x15, "native_call": False}]
    resolved = [{"site": "control:x:1:15", "address": (1, 0x15), "unknown_transfer": False}]
    unknown = [{"site": "control:x:1:15", "address": (1, 0x15), "unknown_transfer": True}]
    bad = {(1, 0x15): {"a8": "withheld", "+": _ok("a8")}}
    judged = _judged(_fn(rows, branchind=resolved), bad)
    assert judged[("resolved_transfer_site", "f/control:x:1:15")][2]["loss"] == 1
    assert judged[("unknown_transfer_site", "f/control:x:1:15")][2]["loss"] == 0
    judged = _judged(_fn(rows, branchind=unknown), bad)
    assert judged[("resolved_transfer_site", "f/control:x:1:15")][2]["loss"] == 0
    assert judged[("unknown_transfer_site", "f/control:x:1:15")][2]["loss"] == 1


def test_r2_plain_push_and_call_seed_read_the_listing_continuation():
    """Astra impl r1 P2-4 pinned (r2 P2-4): an A4-only disagreement blocks plain push and the call seed."""
    rows = [{"space": 1, "address": 0x10, "native_call": True}]
    call = {"op": "1:10:2:CALL", "address": (1, 0x10), "opcode": "CALL",
            "facts": {"naming": "applied", "push_projection": "applied", "push_relation": "applied",
                      "plain_push": "applied"}}
    judged = _judged(_fn(rows, calls=[call]), {(1, 0x10): {"a4": "unrecognized", "+": _ok("a4")}})
    assert judged[("plain_push", "f/1:10:2:CALL")][2]["would_block"]
    assert judged[("call_seed", "f/1:10:2:CALL")][2]["would_block"]


def test_r2_mode_constant_attributes_are_marked():
    import compare

    assert set(compare.MODE_CONSTANT) <= set(compare.COMPARED)


def test_r2_lift_rejects_wrong_spaces_and_widths():
    """Astra impl r2 P1-3: a push STORE into another space, and a ret that updates ESP, are not the shapes."""
    import lifting

    other_space = _row(5, [_op("INT_SUB", [_r(RSP_), _c(8)], _r(RSP_)), _op("STORE", [_c(7), _r(RSP_), _c(START + 5)]),
                           _op("CALL", [_a(START + 0x40)])])
    assert lifting.identify(other_space).pattern == "unidentified"
    esp = _row(1, [_op("LOAD", [_c(1), _r(RSP_)], _r(RIP_)), _op("INT_ADD", [_r(RSP_, 4), _c(8)], _r(RSP_, 4)),
                   _op("RETURN", [_r(RIP_)])], fallthrough=False)
    assert lifting.identify(esp).pattern == "unidentified"
    good = _row(1, [_op("LOAD", [_c(1), _r(RSP_)], _r(RIP_)), _op("INT_ADD", [_r(RSP_), _c(8)], _r(RSP_)),
                    _op("RETURN", [_r(RIP_)])], fallthrough=False)
    lift = lifting.identify(good)
    assert lift.pattern == "ret" and lift.values["a11a"] == 64


def test_r2_a11c_from_a_memory_indirect_target_only():
    import lifting

    memory = _row(6, [_op("LOAD", [_c(1), _c(START + 0x106)], _u(0x40))] + _push(START + 6)
                  + [_op("CALLIND", [_u(0x40)])])
    assert lifting.identify(memory).values["a11c"] == 64
    register = _row(2, _push(START + 2) + [_op("CALLIND", [_r(RAX_)])])
    assert lifting.identify(register).values["a11c"] == lifting.NA   # (register target: not applicable)


@needs
def test_r2_a11c_compared_with_the_voters_and_67_register_calls_not_unobserved():
    lift, result = _compare(_row(6, [_op("LOAD", [_c(1), _c(START + 0x106)], _u(0x40))] + _push(START + 6)
                                 + [_op("CALLIND", [_u(0x40)])], flow=_flow("call_indirect")),
                            bytes.fromhex("ff1500010000" + "cc" * 9), native_call=True)
    assert result["attributes"]["a11c"]["state"] == "applied"
    _, result = _compare(_row(3, _push(START + 3) + [_op("CALLIND", [_r(RAX_)])], flow=_flow("call_indirect")),
                         bytes.fromhex("67ffd0" + "cc" * 12), native_call=True)
    assert result["attributes"]["a11c"]["state"] == "not_applicable"


@needs
def test_r2_kind4_restored_continuation_joins_the_length_contract():
    """Astra impl r2 P2-2: S1 native CALL, length 5, no fallthrough, exit target start + 6."""
    facts = _row(5, _push(START + 5) + [_op("CALL", [_a(START + 0x40)])], flow=_flow("call_direct"))
    facts["fallthrough"], facts["exit"] = None, {"target": START + 6, "kind": 4, "function": None}
    _, result = _compare(facts, bytes.fromhex("e83b000000" + "cc" * 10), s1=True, native_call=True)
    assert result["attributes"]["a2"]["kind"] == "ghidra-internal-inconsistency", result["attributes"]["a2"]


@needs
def test_r2_a2_derived_beyond_the_verified_bytes_is_unobserved():
    """Astra impl r1 P2-2 pinned: S1 native CALL without length, continuation start + 10, 6 verified bytes."""
    import compare
    import decoders
    import lifting

    facts = _row(None, _push(START + 10) + [_op("CALL", [_a(START + 0x40)])], flow=_flow("call_direct"))
    facts["fallthrough"] = START + 10
    data = bytes.fromhex("e83b000000cc")
    window = {"bytes": data, "verified": 6, "stop": "test", "relocations": []}
    result = compare.compare_row(facts, lifting.identify(facts), window, decoders.ballot(data, START), s1=True,
                                 native_call=True, premise=True)
    assert result["state"] == "unobserved" and "claimed range" in result["reason"], result


def test_r2_guard_cross_checks_cmov_flow_bits():
    """Astra impl r2 P2-3: a cmov lift whose exported flow still says call -> unobserved."""
    import guards
    import lifting

    facts = _row(4, _cmov(4), flow={"is_call": True})
    assert lifting.identify(facts).pattern == "cmov"
    assert guards.row_condition(facts, bytes.fromhex("660f44c1"), lifting.identify(facts)) == "unobserved"


def test_r2_voter_conflict_never_confirms_agreement():
    """Fable impl r2 P2-2 (r4 s3): one voter's target beyond its own IP width does not agree with a voter
    that truncates; a target within the width is the plain value."""
    import compare
    import decoders

    def voter(name, target, bits):
        return decoders.Decoded(voter=name, version="t", amd=False, status="ok", length=4, flow="jmp_near",
                                target=target, target_ip_bits=bits)

    wide = compare.voter_values(voter("a", 0x140001004, 16), START)["a5"]
    assert wide[0] == "voter-conflict"
    assert compare.voter_values(voter("b", 0x1004, 16), START)["a5"] == 0x1004
    ghidra = {"a5": 0x1004}
    item = compare._attribute("a5", ghidra, {}, [compare.voter_values(voter("a", 0x140001004, 16), START),
                                                 compare.voter_values(voter("b", 0x1004, 16), START)],
                              [compare.voter_values(voter("b", 0x1004, 16), START)], {"flow": {"is_override": False}})
    assert (item["state"], item["kind"]) == ("withheld", "decoder-disagreement"), item


@needs
def test_r2_66_e9_a5_itself_splits():
    facts = _row(4, [_op("BRANCH", [_a(0x1004)])], fallthrough=False, flow=_flow("jmp_direct"))
    _, result = _compare(facts, bytes.fromhex("66e900000000" + "cc" * 9))
    assert result["attributes"]["a5"]["state"] == "withheld", result["attributes"]["a5"]


def test_r2_elf_plt_entries_pltent_and_nested_loads():
    """Astra impl r2 P1-4: JUMP_SLOT r_addend entries written under PLT rewrite; DT_X86_64_PLTENT required and
    never duplicated; three nested PT_LOADs (first and third share a page); several PT_DYNAMIC."""
    import _elf_fixture as ef
    import elf_map

    seg = [ef.Segment(0x1000, b"\x90" * 0x40)]
    tags = [(0x70000000, 0x1000), (0x70000001, 0x10), (0x70000003, 0x10)]
    image = _elf(seg, extra_dynamic=tags, jmprel=[ef.Reloc(0x3800, 7, addend=0x1020)])
    assert image.written.state == "complete", image.written.why
    assert (0x1020, 0x1030, "plt-rewrite-entry") in image.written.ranges
    duplicate = _elf(seg, extra_dynamic=tags + [(0x70000003, 0x10)])
    assert duplicate.written.state == "indeterminate" and "DT_X86_64_PLTENT" in duplicate.written.why
    several = _elf(seg, second_dynamic=True)
    assert several.written.state == "indeterminate" and "more than one PT_DYNAMIC" in several.written.why
    nested = elf_map.parse(ef.make_elf([ef.Segment(0x1000, b"\x90" * 0x10), ef.Segment(0x1010, b"\x91" * 0x10,
                                                                                     offset=0x2010),
                                        ef.Segment(0x1800, b"\x92" * 0x10, offset=0x3800)]).data)
    assert nested.at(0x1000).kind == "ambiguous" and nested.at(0x1800).kind == "ambiguous"


# -- Astra impl r4 final specification (.census6/g1_impl_astra4.md): the acceptance vectors

PLT_TAGS = [(0x70000000, 0x1000), (0x70000001, 0x10), (0x70000003, 0x10)]   # declared [0x1000, 0x1010), E 16


def test_r4_s1_plt_rewrite_entry_is_aligned_down_to_pltent():
    import _elf_fixture as ef
    import check

    seg = [ef.Segment(0x1000, b"\x90" * 0x40)]
    image = _elf(seg, extra_dynamic=PLT_TAGS, jmprel=[ef.Reloc(0x3800, 7, addend=0x1024)])
    assert image.written.state == "complete", image.written.why
    entries = [item for item in image.written.ranges if item[2] == "plt-rewrite-entry"]
    assert entries == [(0x1020, 0x1030, "plt-rewrite-entry")]
    written = check.Intervals(image.written.ranges)
    assert all(written.find(point) for point in (0x1020, 0x1023, 0x102F)) and written.find(0x1030) is None
    aligned = _elf(seg, extra_dynamic=PLT_TAGS, jmprel=[ef.Reloc(0x3800, 7, addend=0x1020)])
    assert [item for item in aligned.written.ranges if item[2] == "plt-rewrite-entry"] == entries
    irelative = _elf(seg, extra_dynamic=PLT_TAGS, jmprel=[ef.Reloc(0x3800, 37, addend=0x1024)])
    assert not [item for item in irelative.written.ranges if item[2] == "plt-rewrite-entry"]


@pytest.mark.parametrize("tags, why", [
    (PLT_TAGS[:2], "DT_X86_64_PLTENT"),                                       # PLTENT missing
    (PLT_TAGS + [(0x70000003, 0x10)], "DT_X86_64_PLTENT"),                   # duplicated
    (PLT_TAGS[:2] + [(0x70000003, 0)], "supported power of two"),            # E = 0
    (PLT_TAGS[:2] + [(0x70000003, 24)], "supported power of two"),           # E = 24
    ([(0x70000000, 0x1000), (0x70000001, 0x18), (0x70000003, 0x10)], "multiple"),   # PLTSZ % E
])
def test_r4_s1_plt_rewrite_indeterminate_cases(tags, why):
    import _elf_fixture as ef

    image = _elf([ef.Segment(0x1000, b"\x90" * 0x40)], extra_dynamic=tags, jmprel=[ef.Reloc(0x3800, 7, addend=0x1024)])
    assert image.written.state == "indeterminate" and why in image.written.why, image.written.why


def test_r4_s1_truncated_jmprel_table_is_indeterminate():
    import _elf_fixture as ef

    image = _elf([ef.Segment(0x1000, b"\x90" * 0x40)],
                 extra_dynamic=PLT_TAGS + [(23, 0x3000), (2, 0x20), (20, 7)])   # JMPREL with PLTRELSZ 0x20
    assert image.written.state == "indeterminate"


@needs
def test_r4_s1_a_row_inside_a_rewritable_plt_entry_is_unobserved(tmp_path):
    import _elf_fixture as ef
    import _sealed as s

    functions, code = _pair(s, code=ELF_CODE)
    tags = [(0x70000000, 0x1040), (0x70000001, 0x10), (0x70000003, 0x10)]
    elf = ef.make_elf([ef.Segment(0x1000, code + b"\xCC" * 0x40)], extra_dynamic=tags,
                      jmprel=[ef.Reloc(0x3800, 7, addend=0x1014)])     # (entry [0x1010, 0x1020): B's rows)
    _, rows = _run(_elf_bundle(tmp_path, functions, elf))
    row = rows[("decode", "row", "function-000001/1:101010")]
    assert row.run_state == "unobserved" and "plt-rewrite-entry" in row.detail["reason"], row.detail
    assert rows[("decode", "row", "function-000000/1:101000")].verdict == "applied"


def _ret(*ops):
    return _row(len(ops), list(ops), fallthrough=False, flow=_flow("ret"))


RIP8, RIP2 = _r(RIP_), _r(RIP_, 2)
LOAD8 = _op("LOAD", [_c(1), _r(RSP_)], RIP8)
ADD8 = _op("INT_ADD", [_r(RSP_), _c(8)], _r(RSP_))


@pytest.mark.parametrize("name, facts, pattern", [
    ("ADD before LOAD", _ret(ADD8, LOAD8, _op("RETURN", [RIP8])), "unidentified"),
    ("T overwritten", _ret(LOAD8, ADD8, _op("COPY", [_r(RAX_)], RIP8), _op("RETURN", [RIP8])), "unidentified"),
    ("T partly overwritten", _ret(LOAD8, ADD8, _op("COPY", [_r(RAX_, 2)], RIP2), _op("RETURN", [RIP8])),
     "unidentified"),
    ("another T returned", _ret(LOAD8, ADD8, _op("RETURN", [_r(RAX_)])), "unidentified"),
    ("ESP adjust", _ret(LOAD8, _op("INT_ADD", [_r(RSP_, 4), _c(8)], _r(RSP_, 4)), _op("RETURN", [RIP8])),
     "unidentified"),
    ("LOAD from another space", _ret(_op("LOAD", [_c(7), _r(RSP_)], RIP8), ADD8, _op("RETURN", [RIP8])),
     "unidentified"),
    ("extra stack write", _ret(LOAD8, ADD8, _op("INT_SUB", [_r(RSP_), _c(8)], _r(RSP_)), _op("RETURN", [RIP8])),
     "unidentified"),
    ("66 C3", _ret(_op("LOAD", [_c(1), _r(RSP_)], RIP2), _op("INT_ADD", [_r(RSP_), _c(2)], _r(RSP_)),
                   _op("RETURN", [RIP2])), "ret"),
    # (Fable final check: T is a UNIQUE or the IP register of width W, never another register)
    ("T = RAX:8", _ret(_op("LOAD", [_c(1), _r(RSP_)], _r(RAX_)), ADD8, _op("RETURN", [_r(RAX_)])), "unidentified"),
    ("T = AX:2", _ret(_op("LOAD", [_c(1), _r(RSP_)], _r(RAX_, 2)), _op("INT_ADD", [_r(RSP_), _c(2)], _r(RSP_)),
                      _op("RETURN", [_r(RAX_, 2)])), "unidentified"),
    ("T = UNIQUE:8", _ret(_op("LOAD", [_c(1), _r(RSP_)], _u(0x50)), ADD8, _op("RETURN", [_u(0x50)])), "ret"),
], ids=lambda v: v if isinstance(v, str) else None)
def test_r4_s2_ret_shape_is_the_exact_sequence(name, facts, pattern):
    import lifting

    lift = lifting.identify(facts)
    assert lift.pattern == pattern, (name, lift)
    if name == "66 C3":
        assert lift.values["a11a"] == 64 and lift.values["a11b"] == 2 and lift.values["a9"] == "near"


@needs
@pytest.mark.parametrize("data, facts, a9", [
    ("c3", _ret(LOAD8, ADD8, _op("RETURN", [RIP8])), "near"),
    ("c21000", _ret(LOAD8, ADD8, _op("INT_ADD", [_r(RSP_), _c(16)], _r(RSP_)), _op("RETURN", [RIP8])), "near_imm"),
    ("c20000", _ret(LOAD8, ADD8, _op("INT_ADD", [_r(RSP_), _c(0)], _r(RSP_)), _op("RETURN", [RIP8])), "near_imm"),
])
def test_r4_s2_ret_vectors_against_the_voters(data, facts, a9):
    facts["length"] = len(bytes.fromhex(data))
    _, result = _compare(facts, bytes.fromhex(data + "cc" * (15 - len(bytes.fromhex(data)))))
    attributes = result["attributes"]
    assert attributes["a9"]["state"] == "applied" and attributes["a9"]["value"] == a9, attributes["a9"]
    assert attributes["a11b"]["state"] == "applied" and attributes["a11b"]["value"] == 8
    if data == "c3":
        assert attributes["a11a"]["value"] == 64 and result["state"] == "applied", result
    # a wrong shape with the same votes: A9 and the row are unobserved
    wrong = _ret(ADD8, LOAD8, _op("RETURN", [RIP8]))
    wrong["length"] = facts["length"]
    _, result = _compare(wrong, bytes.fromhex(data + "cc" * (15 - len(bytes.fromhex(data)))))
    assert result["attributes"]["a9"]["state"] == "unobserved" and result["state"] == "unobserved"


MEMORY_CALL = [_op("LOAD", [_c(1), _c(START + 0x106)], _u(0x40))] + _push(START + 6) + [_op("CALLIND", [_u(0x40)])]


@needs
@pytest.mark.parametrize("name, data, ops, expected", [
    ("FF 15 memory lift", "ff1500010000", MEMORY_CALL, ("applied", 64)),
    ("FF D0 register lift", "ffd0", _push(START + 2) + [_op("CALLIND", [_r(RAX_)])], ("not_applicable", None)),
    ("67 FF D0 register lift", "67ffd0", _push(START + 3) + [_op("CALLIND", [_r(RAX_)])], ("not_applicable", None)),
    ("FF D0 with a memory lift", "ffd0", [_op("LOAD", [_c(1), _r(RAX_)], _u(0x40))] + _push(START + 2)
     + [_op("CALLIND", [_u(0x40)])], ("unrecognized", None)),
    ("FF 15 with a register lift", "ff1500010000", _push(START + 6) + [_op("CALLIND", [_r(RAX_)])],
     ("unrecognized", None)),
    ("67 FF 10 memory lift, 32-bit extension", "67ff10", [_op("INT_ZEXT", [_r(RAX_, 4)], _u(0x30)),
                                                       _op("LOAD", [_c(1), _u(0x30)], _u(0x40))] + _push(START + 3)
     + [_op("CALLIND", [_u(0x40)])], ("applied", 32)),
], ids=lambda v: v if isinstance(v, str) else None)
def test_r4_s3_a11c_vectors(name, data, ops, expected):
    raw = bytes.fromhex(data)
    facts = _row(len(raw), ops, flow=_flow("call_indirect"))
    _, result = _compare(facts, raw + b"\xCC" * (15 - len(raw)), native_call=True)
    item = result["attributes"]["a11c"]
    assert item["state"] == expected[0], (name, item)
    if expected[1] is not None:
        assert item["value"] == expected[1]
    if expected[0] == "unrecognized":
        assert item["kind"] == "ghidra-decode-suspect"


@needs
@pytest.mark.parametrize("name, data, ops, form", [
    # (shapes seen in a real Ghidra 12.0.4 Bundle: LOAD -> COPY -> CALLIND, and BRANCHIND of a ram slot)
    ("FF 50 30 call [rax+0x30]: LOAD then COPY", "ff5030",
     [_op("INT_ADD", [_r(RAX_), _c(0x30)], _u(0x10)), _op("LOAD", [_c(1), _u(0x10)], _u(0x20)),
      _op("COPY", [_u(0x20)], _u(0x30))] + _push(START + 3) + [_op("CALLIND", [_u(0x30)])], "call_indirect"),
    ("48 FF 25 jmp [rip+x]: BRANCHIND of the slot", "48ff2500010000",
     [_op("BRANCHIND", [_a(START + 7 + 0x100)])], "jmp_indirect"),
], ids=lambda v: v if isinstance(v, str) else None)
def test_r4_s3_a11c_real_ghidra_memory_shapes(name, data, ops, form):
    raw = bytes.fromhex(data)
    facts = _row(len(raw), ops, fallthrough=form.startswith("call"), flow=_flow(form))
    lift, result = _compare(facts, raw + b"\xCC" * (15 - len(raw)), native_call=form.startswith("call"))
    assert lift.values.get("a11c") == 64, (name, lift)
    assert result["attributes"]["a11c"]["state"] == "applied", (name, result["attributes"]["a11c"])
    assert result["state"] == "applied", (name, result["attributes"])


def test_r4_s3_a11c_unknown_voter_or_split():
    import compare
    import decoders

    def voter(name, kind, amd=False):
        return decoders.Decoded(voter=name, version="t", amd=amd, status="ok", length=6, flow="call_near",
                                indirect=kind != "direct", address_bits=64, target_kind=kind)

    facts = {"flow": {"is_override": False}}
    ghidra = {"a11c": 64}

    def a11c(intel, amd):
        return compare._attribute("a11c", ghidra, {}, [compare.voter_values(d, START) for d in intel],
                                  [compare.voter_values(d, START) for d in amd], facts)

    assert a11c([voter("a", "memory"), voter("b", "unknown")], [voter("a", "memory", True)])["state"] == "unobserved"
    split = a11c([voter("a", "memory"), voter("b", "register")], [voter("a", "memory", True)])
    assert (split["state"], split["kind"]) == ("withheld", "decoder-disagreement")
    amd = a11c([voter("a", "memory")], [voter("a", "memory", True), voter("b", "register", True)])
    assert (amd["state"], amd["kind"]) == ("withheld", "amd-disagreement")
    vendor = a11c([voter("a", "memory")], [voter("a", "register", True)])
    assert (vendor["state"], vendor["kind"]) == ("withheld", "vendor")


def _kind4(length, target_space, target_offset):
    facts = _row(length, _push(START + 5) + [_op("CALL", [_a(START + 0x40)])], flow=_flow("call_direct"))
    facts["fallthrough"] = None
    facts["exit"] = {"target": target_offset, "target_space": target_space, "kind": 4, "function": None}
    return facts


@needs
@pytest.mark.parametrize("name, facts, a2, a4", [
    ("length 5, exit (1, X+5)", _kind4(5, 1, START + 5), ("applied", None), ("applied", None)),
    ("length 5, exit (1, X+6)", _kind4(5, 1, START + 6), ("unrecognized", "ghidra-internal-inconsistency"),
     ("unrecognized", "cause-unknown")),
    ("length 5, exit (2, X+5)", _kind4(5, 2, START + 5), ("unrecognized", "ghidra-internal-inconsistency"),
     ("unrecognized", "cause-unknown")),
    ("no length, exit (2, X+5)", _kind4(None, 2, START + 5), ("unobserved", None), ("unrecognized", "cause-unknown")),
    ("no length, exit (1, X+5)", _kind4(None, 1, START + 5), ("applied", None), ("applied", None)),
], ids=lambda v: v if isinstance(v, str) else None)
def test_r4_s4_kind4_continuation_space_and_contract(name, facts, a2, a4):
    _, result = _compare(facts, bytes.fromhex("e83b000000" + "cc" * 10), s1=True, native_call=True)
    attributes = result["attributes"]
    for attribute, (state, kind) in (("a2", a2), ("a4", a4)):
        item = attributes[attribute]
        assert item["state"] == state, (name, attribute, item)
        if kind:
            assert item["kind"] == kind, (name, attribute, item)
    if name == "no length, exit (1, X+5)":
        assert attributes["a2"].get("provenance") == "via A4 (counted once)"


@needs
def test_r4_s4_row_facts_keeps_the_exit_space():
    """At least one vector through row_facts: a kind-4 exit to the same offset in another space."""
    from types import SimpleNamespace as N

    import lifting

    def coord(space, offset):
        return N(space_id=space, byte_offset=offset)

    def varnode(item):
        return None if item is None else N(kind=N(name=item["kind"]), coordinate=coord(item["space"], item["offset"]),
                                           byte_size=item["size"])

    ops = _push(START + 5) + [_op("CALL", [_a(START + 0x40)])]
    instruction = N(address=coord(1, START), length=5, fallthrough=None, flow_targets=[],
                    flow=N(**_flow("call_direct")),
                    operations=[N(opcode=op["opcode"], inputs=[varnode(item) for item in op["inputs"]],
                                  output=varnode(op["output"])) for op in ops])
    exit_row = N(target=coord(2, START + 5), kind=4, function=None)
    facts = lifting.row_facts(instruction, exit_row)
    assert facts["exit"]["target_space"] == 2
    _, result = _compare(facts, bytes.fromhex("e83b000000" + "cc" * 10), s1=True, native_call=True)
    assert result["attributes"]["a2"]["kind"] == "ghidra-internal-inconsistency"
    assert result["attributes"]["a4"]["state"] == "unrecognized"


def test_r4_s5_l2_blocking_names_the_attribute_and_the_cause():
    for bad in ("a7", "a1", "a2"):
        judged = _judged(_fn([{"space": 1, "address": 0x10, "native_call": False}]),
                         {(1, 0x10): {bad: "unrecognized", "+": _ok(bad)}})
        run_state, verdict, detail = judged[("s1_l2_estimate", "f")]
        assert (run_state, verdict) == ("evaluated", "withheld"), bad
        assert detail["would_block"] and detail["cause"] == "disagreement"
        assert detail["blocking"] == [["1:10", bad, "unrecognized"]] and detail["blocking_count"] == 1
        s1 = judged[("s1", "f")]
        assert (s1[0], s1[1]) == ("evaluated", "applied") and not s1[2]["would_block"]


def test_all_invalid_rows_block_every_fact_through_a1():
    """Fable evidence r2 P1-1: when every voter says invalid encoding, the other attributes are not applicable
    (read as confirmed); A1 is the disagreement -- every fact reads it, so S1 / push / seed are withheld."""
    rows = [{"space": 1, "address": 0x10, "native_call": True}]
    call = {"op": "1:10:2:CALL", "address": (1, 0x10), "opcode": "CALL",
            "facts": {"naming": "applied", "push_projection": "applied", "push_relation": "applied",
                      "plain_push": "applied"}}
    judged = _judged(_fn(rows, calls=[call]),
                     {(1, 0x10): {"a1": "unrecognized", "+": _ok("a1")}})   # (all other attributes n/a)
    for consumer, key in (("s1", "f"), ("push_projection", "f/1:10:2:CALL"), ("call_seed", "f/1:10:2:CALL"),
                          ("plain_push", "f/1:10:2:CALL")):
        run_state, verdict, detail = judged[(consumer, key)]
        assert verdict == "withheld" and detail["cause"] == "disagreement", consumer
        assert ["1:10", "a1", "unrecognized"] in detail["blocking"], consumer


def test_r4_s5_first_and_third_pt_load_share_a_page():
    """L1 [0x1000, 0x3800), L2 [0x2100, 0x2120), L3 [0x3400, 0x3420): 0x3200 is covered by L1 only, and its page
    is shared by L1 and L3 only -> ambiguous; 0x1800 stays file."""
    import _elf_fixture as ef
    import elf_map

    image = elf_map.parse(ef.make_elf([ef.Segment(0x1000, b"\x90" * 0x2800, offset=0x1000),
                                       ef.Segment(0x2100, b"\x91" * 0x20, offset=0x5100),
                                       ef.Segment(0x3400, b"\x92" * 0x20, offset=0x6400)]).data)
    assert image.at(0x3200).kind == "ambiguous"
    assert image.at(0x1800).kind == "file"


# -- engine evidence file g1-decode-evidence-1 (design .census6/design_g1_engine_evidence_r3.md, s8 vectors)

EV_BUNDLE = {"generation_id": "g" * 64, "manifest_sha256": "m" * 64, "original_sha256": "o" * 64}
EV_PRODUCER = {"decode_check_revision": 2, "tool_digest": "t" * 64, "decoders": {"zydis": "x"},
               "voters": {"intel": ["iced", "zydis", "xed"], "amd": ["iced", "zydis"]}, "rules": "pe-loader-rules-6",
               "lift_table": "x86-64-lift-table-7", "diagnosis_engine": {"source_digest": "e" * 64},
               "naming_source_sha256": "n" * 64}


def _ev_function(fid, rows, states=None, observation="s" * 64):
    return {"function_id": fid, "observation_sha256": observation, "rows": rows, "states": states or {}}


def _ev_confirmed():
    import compare

    return {"+": frozenset(compare.COMPARED)}


def _ev_doc(functions, *, table_applied=True, premises=None, global_reason=None):
    import evidence

    if premises is None:
        premises = ["decoder-matches-cpu"] + (["stock-ghidra-translator"] if table_applied else [])
    return evidence.build(bundle=dict(EV_BUNDLE), producer=dict(EV_PRODUCER),
                          mapping={"format": "pe", "mapping_id": "p" * 64}, premises=premises,
                          table_applied=table_applied, global_reason=global_reason, functions=functions)


def _ev_view(functions, kept=None):
    """The engine's own Bundle view (here equal to what G1 processed)."""
    view = dict(EV_BUNDLE)
    view["functions"] = {f["function_id"]: {"observation_sha256": f["observation_sha256"], "rows": set(f["rows"]),
                                            "kept": (kept or {}).get(f["function_id"], True)} for f in functions}
    return view


def _ev_accept(document, view, allowlist=None):
    import evidence

    allowlist = [evidence.allowlist_entry(document)] if allowlist is None else allowlist
    tables = None
    if document.get("schema") == "g1-decode-evidence-2":
        import isa_tables

        tables = isa_tables.load()
    return evidence.accept(evidence.parse(evidence.dumps(document)), view, allowlist, tables=tables)


def test_evidence_consumers_2_bytes_and_digest():
    import copy
    import hashlib

    import evidence

    data = evidence.consumers_bytes()
    assert len(data) == 500 and hashlib.sha256(data).hexdigest() == evidence.CONSUMERS_DIGEST
    reordered = dict(reversed(list(evidence.CONSUMERS_2.items())))
    assert evidence.consumers_bytes(reordered) == data
    variants = []
    dropped = copy.deepcopy(evidence.CONSUMERS_2)
    del dropped["push_relation"]
    variants.append(evidence.consumers_digest(dropped))
    flipped = copy.deepcopy(evidence.CONSUMERS_2)
    flipped["s1"]["s1_exit_source"] = ["a4", "a1"]
    variants.append(evidence.consumers_digest(flipped))
    variants.append(hashlib.sha256(data + b"\n").hexdigest())
    functions = [_ev_function("function-000000", [(1, 0x10)], {(1, 0x10): _ev_confirmed()})]
    for digest in variants:
        assert digest != evidence.CONSUMERS_DIGEST
        document = _ev_doc(functions)
        document["consumers"]["digest"] = digest
        with pytest.raises(evidence.Rejected, match="consumers"):
            _ev_accept(document, _ev_view(functions))


def test_evidence_rows_digest_sorts_by_integer_pair():
    import hashlib

    import evidence

    assert evidence.rows_digest([(1, 0x100), (1, 0xFF), (1, 0xFF)]) == \
        hashlib.sha256(b"1:ff\n1:100\n").hexdigest()


def test_evidence_producer_completeness_and_kinds():
    import compare
    import evidence

    states = {"a2": "unrecognized", "~": {"a2": "ghidra-decode-suspect"},
              "+": frozenset(compare.COMPARED) - {"a2", "a5"}}
    assert evidence.exception_of(states) == {"a2": "unrecognized:ghidra-decode-suspect", "a5": "unobserved"}
    assert evidence.exception_of({"*": "unobserved"}) == {"*": "unobserved"}
    assert evidence.exception_of(_ev_confirmed()) is None


@pytest.mark.parametrize("table_applied, premises, accepted, expected", [
    (False, [], False, None),
    (False, ["decoder-matches-cpu"], True, {"decoder-matches-cpu", "g1-evidence-from-allowlisted-build"}),
    (True, ["decoder-matches-cpu"], False, None),
    (True, ["stock-ghidra-translator"], False, None),
    (True, ["decoder-matches-cpu", "stock-ghidra-translator"], True,
     {"decoder-matches-cpu", "stock-ghidra-translator", "g1-evidence-from-allowlisted-build"}),
])
def test_evidence_required_premises(table_applied, premises, accepted, expected):
    import evidence

    functions = [_ev_function("function-000000", [(1, 0x10)], {(1, 0x10): _ev_confirmed()})]
    document = _ev_doc(functions, table_applied=table_applied, premises=premises)
    if not accepted:
        with pytest.raises(evidence.Rejected, match="premise"):
            _ev_accept(document, _ev_view(functions))
        return
    assert _ev_accept(document, _ev_view(functions)).premises == expected


def test_evidence_s5_order_with_table_not_applied():
    """Item 1: explicit disagreement survives table_applied = false; unexcepted table attributes unobserved."""
    import evidence

    reads = evidence.CONSUMERS_2["push_projection"]["call_op"]
    vendor = {"a3": "withheld", "~": {"a3": "vendor"}, "+": frozenset(evidence.compare.COMPARED) - {"a3"}}
    functions = [_ev_function("function-000000", [(1, 0x10)], {(1, 0x10): vendor})]
    ev = _ev_accept(_ev_doc(functions, table_applied=False), _ev_view(functions))
    results = [ev.read("function-000000", 1, 0x10, name) for name in reads]
    assert ev.read("function-000000", 1, 0x10, "a3") == "withheld:vendor"
    assert ev.read("function-000000", 1, 0x10, "F.is_call") == "unobserved"
    assert ev.read("function-000000", 1, 0x10, "a1") == "confirmed"
    for level in ("A", "B"):
        assert evidence.decide(results, level, ev.premises)["keep"] is False
    plain = [_ev_function("function-000000", [(1, 0x10)], {(1, 0x10): _ev_confirmed()})]
    ev = _ev_accept(_ev_doc(plain, table_applied=False), _ev_view(plain))
    results = [ev.read("function-000000", 1, 0x10, name) for name in reads]
    assert ev.read("function-000000", 1, 0x10, "a3") == "unobserved"
    kept = evidence.decide(results, "A", ev.premises)
    assert kept["keep"] and "TBR-G1-decode" in kept["premises"]
    assert evidence.decide(results, "B", ev.premises)["keep"] is False


def test_evidence_membership_and_premises_per_fact():
    """Item 2."""
    import evidence

    s1 = evidence.CONSUMERS_2["s1"]
    functions = [_ev_function("f", [(1, 0x20)], {(1, 0x20): _ev_confirmed()})]
    ev = _ev_accept(_ev_doc(functions), _ev_view(functions))
    outside = [ev.read("f", 2, 0x20, name) for name in s1["s1_exit_source"]]
    assert outside == ["unobserved", "unobserved"]
    native = [ev.read("f", 1, 0x20, name) for name in s1["native_call"]]
    keep_a = evidence.decide(native + outside, "A", ev.premises)
    assert keep_a["keep"] and "TBR-G1-decode" in keep_a["premises"] and not keep_a["confirmed_by_g1"]
    assert evidence.decide(native + outside, "B", ev.premises)["keep"] is False
    bad = _ev_doc(functions)
    bad["functions"][0]["exceptions"] = [{"space": 2, "offset": "20", "attributes": {"a4": "unobserved"}}]
    with pytest.raises(evidence.Rejected, match="outside"):
        _ev_accept(bad, _ev_view(functions))
    # native-call reads confirmed, a separate exit source row `*`
    two = [_ev_function("f", [(1, 0x20), (1, 0x30)], {(1, 0x20): _ev_confirmed(), (1, 0x30): {"*": "unobserved"}})]
    ev = _ev_accept(_ev_doc(two), _ev_view(two))
    reads = [ev.read("f", 1, 0x20, n) for n in s1["native_call"]] + [ev.read("f", 1, 0x30, n)
                                                                       for n in s1["s1_exit_source"]]
    decision = evidence.decide(reads, "A", ev.premises)
    assert decision["keep"] and decision["premises"] == ev.premises | {"TBR-G1-decode"}
    assert evidence.decide(reads, "B", ev.premises)["keep"] is False
    # only `*` / not covered / zero reads -> TBR-G1-decode only
    only = evidence.decide([ev.read("f", 1, 0x30, "a1")], "A", ev.premises)
    assert only["premises"] == {"TBR-G1-decode"} and evidence.decide([], "A", ev.premises)["confirmed_by_g1"] is False
    # explicit unobserved, a known attribute outside the compared set, the unexcepted mode constant a11a
    explicit = [_ev_function("f", [(1, 0x20)], {(1, 0x20): {"a4": "unobserved",
                                                             "+": frozenset(evidence.compare.COMPARED) - {"a4"}}})]
    narrow = _ev_doc(explicit)
    narrow["compared_attributes"] = [name for name in narrow["compared_attributes"] if name != "a6"]
    ev = _ev_accept(narrow, _ev_view(explicit))
    assert [ev.read("f", 1, 0x20, n) for n in ("a4", "a6", "a11a")] == ["unobserved"] * 3
    # table applied, return shape a1 / a11b confirmed -> kept at A and B, evidence premises, TBR released
    ev = _ev_accept(_ev_doc(functions), _ev_view(functions))
    reads = [ev.read("f", 1, 0x20, n) for n in evidence.CONSUMERS_2["return_shape"]["return_op"]]
    for level in ("A", "B"):
        decision = evidence.decide(reads, level, ev.premises)
        assert decision["keep"] and "TBR-G1-decode" not in decision["premises"] and decision["confirmed_by_g1"]


def test_evidence_coverage_accounting():
    """Item 5: 1/6 with each reason once; a global_reason file 0/6; a reason text change decides the same."""
    import evidence

    good = _ev_confirmed()
    produced = [_ev_function("f1", [(1, 1)], {(1, 1): good}), _ev_function("f2", [(1, 2)], {(1, 2): good}),
                _ev_function("f4", [(1, 4)], {(1, 4): good}), _ev_function("f5", [(1, 5)], {(1, 5): good}),
                _ev_function("f6", [(1, 6)], {(1, 6): good})]
    view = _ev_view(produced, kept={"f2": False})
    view["functions"]["f3"] = {"observation_sha256": "s" * 64, "rows": {(1, 3)}, "kept": True}       # absent
    view["functions"]["f4"]["observation_sha256"] = "z" * 64                                          # observation
    view["functions"]["f5"]["rows"] = {(1, 5), (1, 0x55)}                                              # total+digest
    view["functions"]["f6"]["rows"] = {(1, 0x66)}                                                      # digest only
    ev = _ev_accept(_ev_doc(produced), view)
    assert ev.coverage() == {"covered": 1, "total": 6, "global_reason": None, "not_covered": {
        "ignored_duplicate_entry": 1, "absent": 1, "observation_mismatch": 1, "rows_total_mismatch": 1,
        "rows_digest_mismatch": 1}}
    document = _ev_doc([], global_reason="not at the preferred base")
    ev = _ev_accept(document, view)
    assert ev.coverage() == {"covered": 0, "total": 6, "global_reason": "not at the preferred base",
                             "not_covered": {"global": 6}}
    with pytest.raises(evidence.Rejected, match="global_reason"):
        bad = _ev_doc(produced, global_reason="x")
        bad["functions"] = _ev_doc(produced)["functions"]
        _ev_accept(bad, view)


def test_evidence_reason_text_never_changes_decisions():
    import evidence

    states = {"a2": "unrecognized", "~": {"a2": "cause-unknown"}, "+": frozenset(evidence.compare.COMPARED) - {"a2"}}
    functions = [_ev_function("f", [(1, 0x10)], {(1, 0x10): states})]
    first = _ev_doc(functions)
    second = _ev_doc(functions)
    first["functions"][0]["exceptions"][0]["reason"] = "one wording"
    second["functions"][0]["exceptions"][0]["reason"] = "another wording"
    results = []
    for document in (first, second):
        ev = _ev_accept(document, _ev_view(functions))
        reads = [ev.read("f", 1, 0x10, n) for n in evidence.CONSUMERS_2["s1"]["native_call"]]
        results.append((reads, evidence.decide(reads, "A", ev.premises), ev.coverage()))
    assert results[0] == results[1]
    assert evidence.dumps(first) != evidence.dumps(second)


def test_evidence_all_invalid_row_withholds_s1_through_a1():
    import evidence

    states = {"a1": "unrecognized", "~": {"a1": "ghidra-decode-suspect"},
              "+": frozenset(evidence.compare.COMPARED) - {"a1"}}
    functions = [_ev_function("f", [(1, 0x10)], {(1, 0x10): states})]
    ev = _ev_accept(_ev_doc(functions), _ev_view(functions))
    reads = [ev.read("f", 1, 0x10, n) for n in evidence.CONSUMERS_2["s1"]["native_call"]]
    assert evidence.decide(reads, "A", ev.premises)["keep"] is False


@pytest.mark.parametrize("name, change, match", [
    ("manifest", lambda d: d["bundle"].update(manifest_sha256="x" * 64), "manifest_sha256"),
    ("generation", lambda d: d["bundle"].update(generation_id="x" * 64), "generation_id"),
    ("original", lambda d: d["bundle"].update(original_sha256="x" * 64), "original_sha256"),
    ("schema", lambda d: d.update(schema="g1-decode-evidence-2"), "schema"),
    ("unknown key", lambda d: d.update(extra=1), "keys"),
    ("duplicate function", lambda d: d["functions"].append(dict(d["functions"][0])), "duplicate function_id"),
    ("duplicate coordinate", lambda d: d["functions"][0]["exceptions"].append(
        dict(d["functions"][0]["exceptions"][0])), "duplicate exception"),
    ("star mixed", lambda d: d["functions"][0]["exceptions"][0]["attributes"].update({"*": "unobserved"}), "'\\*'"),
    ("unknown kind", lambda d: d["functions"][0]["exceptions"][0]["attributes"].update(
        a2="withheld:new-kind"), "unknown state"),
    ("unknown attribute", lambda d: d["functions"][0]["exceptions"][0]["attributes"].update(
        semantics="unobserved"), "unknown attribute"),
    ("bad offset", lambda d: d["functions"][0]["exceptions"][0].update(offset="0x10"), "hex"),
    ("leading zero", lambda d: d["functions"][0]["exceptions"][0].update(offset="010"), "hex"),
    ("function outside the Bundle", lambda d: d["functions"][0].update(function_id="function-999999"),
     "not in the Bundle"),
])
def test_evidence_rejections(name, change, match):
    import evidence

    states = {"a2": "unobserved", "+": frozenset(evidence.compare.COMPARED) - {"a2"}}
    functions = [_ev_function("function-000000", [(1, 0x10)], {(1, 0x10): states})]
    document = _ev_doc(functions)
    change(document)
    with pytest.raises(evidence.Rejected, match=match):
        _ev_accept(document, _ev_view(functions))


def test_evidence_strict_json_and_allowlist():
    import evidence

    functions = [_ev_function("function-000000", [(1, 0x10)], {(1, 0x10): _ev_confirmed()})]
    document = _ev_doc(functions)
    with pytest.raises(evidence.Rejected, match="duplicate JSON key"):
        evidence.parse(b'{"schema": 1, "schema": 2}')
    with pytest.raises(evidence.Rejected, match="non-finite"):
        evidence.parse(b'{"x": NaN}')
    other = evidence.allowlist_entry(document)
    other = dict(other, compared_attributes=other["compared_attributes"][:-1])
    with pytest.raises(evidence.Rejected, match="allowlist"):
        evidence.accept(evidence.parse(evidence.dumps(document)), _ev_view(functions), [other])


@needs
def test_evidence_end_to_end_on_a_synthetic_bundle(tmp_path):
    """decode_check --evidence-out on the 66 E8 pair: accepted against the engine's own view, the withheld call
    row withholds A's S1 at level A, B's S1 is confirmed by G1. The golden pins the file minus producer fields."""
    import json

    import _sealed as s
    import decode_check
    import evidence

    functions, code = _pair(s, call_bytes=b"\x66\xE8\x0A\x00\x00\x00")
    generation = _bundle(tmp_path / "b", functions, code) if (tmp_path / "b").mkdir() is None else None
    path = tmp_path / "evidence.json"
    _, _ = decode_check.run(generation, s.NAMING_SOURCE, True, full=True, evidence_out=path)
    raw = path.read_bytes()
    document = evidence.parse(raw)
    facts = decode_check.collect(generation, s.NAMING_SOURCE)
    manifest = json.loads((generation / "manifest.json").read_bytes())
    members = {row["id"]: row for row in manifest["members"]}
    seal = json.loads((generation / "seal.json").read_bytes())
    view = {"generation_id": seal["generation_id"], "manifest_sha256": seal["manifest_sha256"],
            "original_sha256": members["original"]["sha256"],
            "functions": {row["id"]: {"observation_sha256": members[row["observation_member"]]["sha256"],
                                      "rows": set(), "kept": True} for row in manifest["functions"]}}
    for function in facts["functions"]:
        view["functions"][function["function_id"]]["rows"] = {(r["space"], r["address"]) for r in function["rows"]}
    ev = evidence.accept(document, view, [evidence.allowlist_entry(document)])
    assert ev.coverage()["covered"] == 2 and ev.premises >= {"decoder-matches-cpu", "stock-ghidra-translator"}
    s1 = evidence.CONSUMERS_2["s1"]["native_call"]
    a = [ev.read("function-000000", 1, CODE, n) for n in s1]
    assert any(item.startswith("withheld") for item in a)
    assert evidence.decide(a, "A", ev.premises)["keep"] is False
    b_rows = sorted(view["functions"]["function-000001"]["rows"])
    b = [ev.read("function-000001", space, offset, n) for space, offset in b_rows for n in ("a1", "a4")]
    assert evidence.decide(b, "A", ev.premises)["confirmed_by_g1"] is True
    pinned = {k: v for k, v in document.items() if k != "producer"}
    golden = GOLDEN / "decode_check_evidence_pair_66e8.json"
    if os.environ.get("G1_REGEN_GOLDEN"):
        with open(golden, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(pinned, indent=1, sort_keys=True) + "\n")
    assert json.loads(golden.read_text(encoding="utf-8")) == pinned


# -- internal rows (lift table -6): pinned no-flow userops and intra-instruction branches only

def _co(index, *inputs, output=None):
    return _op("CALLOTHER", [_c(index, 4)] + list(inputs), output)


INTERNAL_VECTORS = [
    # (name, bytes, ops, pattern)  -- shapes seen in the UE core probe's p-code
    ("lock xadd [rcx], eax", "f00fc101", [_co(17), _op("LOAD", [_c(1), _r(RCX_)], _u(0x10, 4)),
                                          _op("INT_ADD", [_u(0x10, 4), _r(RAX_, 4)], _u(0x20, 4)),
                                          _op("STORE", [_c(1), _r(RCX_), _u(0x20, 4)]),
                                          _op("COPY", [_u(0x10, 4)], _r(RAX_, 4)), _co(18)], "internal"),
    ("lock cmpxchg [rcx], edx", "f00fb111", [_co(17), _op("LOAD", [_c(1), _r(RCX_)], _u(0x10, 4)),
                                             _op("INT_EQUAL", [_r(RAX_, 4), _u(0x10, 4)], _u(0x30, 1)),
                                             _op("CBRANCH", [_c(3), _u(0x30, 1)]),
                                             _op("COPY", [_u(0x10, 4)], _r(RAX_, 4)), _op("BRANCH", [_c(2)]),
                                             _op("STORE", [_c(1), _r(RCX_), _r(0x10, 4)]), _co(18)], "internal"),
    ("bsr eax, ecx", "0fbdc1", [_op("INT_EQUAL", [_r(RCX_, 4), _c(0, 4)], _u(0x30, 1)),
                                _op("CBRANCH", [_c(4), _u(0x30, 1)]), _op("COPY", [_c(31, 4)], _r(RAX_, 4)),
                                _op("INT_SUB", [_r(RAX_, 4), _c(1, 4)], _r(RAX_, 4)), _op("BRANCH", [_c(-2, 4)])],
     "internal"),
    ("psraw xmm0, xmm1", "660fe1c1", [_co(163, _r(0x1200, 16), _r(0x1210, 16), output=_r(0x1200, 16))], "internal"),
]


@pytest.mark.parametrize("name, data, ops, pattern", INTERNAL_VECTORS, ids=[v[0] for v in INTERNAL_VECTORS])
def test_internal_rows_identify(name, data, ops, pattern):
    import lifting

    facts = _row(len(bytes.fromhex(data)), ops)
    lift = lifting.identify(facts)
    assert lift.pattern == pattern, (name, lift)
    assert lift.values["a8"] == "none" and lift.values["a6"] == "none"


@needs
@pytest.mark.parametrize("name, data, ops, pattern", INTERNAL_VECTORS, ids=[v[0] for v in INTERNAL_VECTORS])
def test_internal_rows_against_the_voters(name, data, ops, pattern):
    raw = bytes.fromhex(data)
    facts = _row(len(raw), ops)
    _, result = _compare(facts, raw + b"\xCC" * (15 - len(raw)))
    assert result["state"] == "applied", (name, result["attributes"])


def test_userop_classes_file_is_consistent():
    """Table -7: the pinned no-flow userops come from userops_x64_classes.json (spec + test binary + voters +
    iced privilege facts); flow, privileged / OS-gated and unknown userops are never pinned."""
    import hashlib
    import json

    import lifting

    path = REPO / "tools" / "decode_check" / "userops_x64_classes.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert lifting.TABLE["no_flow_userops_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert data["sla_sha256"].startswith("d5adc314") and data["language"] == ["x86:LE:64:default", 4, 6]
    pinned = set(data["no_flow"].values())
    for group in data["excluded"].values():
        assert not pinned & set(group)
    assert {"syscall", "swi", "invalidInstructionException"} <= set(data["excluded"]["flow"])
    assert {"rdmsr", "wrmsr", "in", "out", "cpuid", "rdtsc"} <= set(data["excluded"]["privileged"])
    assert {"LOCK", "UNLOCK", "psraw", "pshufb"} <= pinned
    assert lifting.TABLE["no_flow_userops"] == {int(k): v for k, v in data["no_flow"].items()}


@pytest.mark.parametrize("name, ops", [
    ("an unpinned userop (syscall, 5)", [_co(5)]),
    ("an OS-gated userop (cpuid, 44: CPUID faulting)", [_co(44, output=_u(0x40))]),
    ("a marker next to a real branch", [_co(17), _op("BRANCH", [_a(START + 0x40)]), _co(18)]),
    ("an internal branch next to a real one", [_op("CBRANCH", [_c(2), _u(0x30, 1)]),
                                               _op("CBRANCH", [_a(START + 0x40), _u(0x30, 1)])]),
], ids=lambda v: v if isinstance(v, str) else None)
def test_internal_never_covers_other_flow(name, ops):
    import lifting

    assert lifting.identify(_row(4, ops)).pattern != "internal", name


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
    assert a.detail["s1_observed"] is True and a.detail["rows"] == ["1:140001000"]
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


def test_pe_map_overlapping_sections_are_ambiguous_on_both_sides():
    """Astra impl r1 P1-2: [0x1000, 0x2010) and a section at 0x2000 -> every shared byte is ambiguous."""
    import _pe_fixture as pf
    import pe_map

    image = pe_map.parse(pf.make_pe([pf.Section(".a", 0x1000, b"\x90" * 0x1010),
                                     pf.Section(".b", 0x2000, b"\xCC" * 0x100)]))
    assert image.at(0x1FFF).kind == "file"
    assert image.at(0x2005).kind == "ambiguous"
    starts = [item.start for item in image.ranges]
    assert starts == sorted(starts) and all(a.end <= b.start for a, b in zip(image.ranges, image.ranges[1:]))


@pytest.mark.parametrize("offset, width, label", [
    (0xC0, 8, "DynamicValueRelocTable"), (0xC8, 8, "CHPEMetadataPointer"), (0xE0, 4, "DynamicValueRelocTableOffset"),
    (0xE4, 2, "DynamicValueRelocTableSection"), (0xF0, 4, "HotPatchTableOffset"), (None, None, None)])
def test_pe_map_load_config_code_rewriting_fields(offset, width, label):
    """Fable impl r1 P1-1: a non-zero DVRT / CHPE / hot-patch field -> written indeterminate; 0 -> complete;
    the other loader pointer slots are written ranges."""
    import _pe_fixture as pf
    import pe_map
    import struct

    data, directories = _data_section_with_directories()
    data = bytearray(data.data)
    struct.pack_into("<I", data, 0x700, 0x140)
    struct.pack_into("<Q", data, 0x700 + 0xD8, BASE + 0x2880)
    struct.pack_into("<Q", data, 0x700 + 0x138, BASE + 0x2888)
    if offset is not None:
        data[0x700 + offset:0x700 + offset + width] = (1).to_bytes(width, "little")
    image = pe_map.parse(pf.make_pe([pf.Section(".text", 0x1000, b"\xC3"),
                                     pf.Section(".data", 0x2000, bytes(data), characteristics=0xC0000040)],
                                    directories=directories))
    if label is None:
        assert image.written.state == "complete", image.written.why
        labels = {item[2] for item in image.written.ranges}
        assert {"rf-failure-routine-pointer", "memcpy-pointer"} <= labels
    else:
        assert image.written.state == "indeterminate" and label in image.written.why


def _dvrt_pe(*, symbol=7, version=1, reloc_type=1, overrides_size=None, chpe=False):
    """A PE32+ whose load config points at a DVRT with one FUNCTION_OVERRIDE record: .text holds `E9 rel32` at
    0x1010 (rel32 field at 0x1011); the record's X64_REL32 relocation names 0x1011 (pe-loader-rules-6)."""
    import _pe_fixture as pf
    import struct

    text = bytearray(b"\xCC" * 0x40)
    text[0x10:0x15] = b"\xE9" + struct.pack("<i", 0x20 - 0x15)
    relocs = struct.pack("<IIHH", 0x1000, 12, reloc_type << 12 | 0x011, 0)
    record = struct.pack("<IIII", 0x1020, 0, 4, len(relocs)) + struct.pack("<I", 0x1030) + relocs
    bdd = struct.pack("<II", 1, 0)
    size = len(record) if overrides_size is None else overrides_size
    entry = struct.pack("<I", size) + record + bdd
    table = struct.pack("<II", version, 12 + len(entry)) + struct.pack("<QI", symbol, len(entry)) + entry
    data = bytearray(0x400)
    struct.pack_into("<I", data, 0, 0x140)                      # load config size
    struct.pack_into("<IH", data, 0xE0, 0x200, 2)               # DVRT offset 0x200 in section 2 (.data)
    if chpe:
        struct.pack_into("<Q", data, 0xC8, BASE + 0x2300)
    data[0x200:0x200 + len(table)] = table
    return pf.make_pe([pf.Section(".text", 0x1000, bytes(text)),
                       pf.Section(".data", 0x2000, bytes(data), characteristics=0xC0000040)],
                      directories=[pf.Directory(10, 0x2000, 0x140)])


def test_pe_map_dvrt_function_override_marks_only_the_rel32_fields():
    import pe_map

    image = pe_map.parse(_dvrt_pe())
    assert image.written.state == "complete", image.written.why
    assert (0x1011, 0x1015, "dvrt-function-override (OS-dependent rewrite)") in image.written.ranges


@pytest.mark.parametrize("change, why", [
    ({"symbol": 3}, "DVRT symbol 3 not modelled"),
    ({"version": 2}, "DVRT version 2 not modelled"),
    ({"reloc_type": 2}, "relocation type 2 not modelled"),
    ({"overrides_size": 0x400}, "truncated"),
    ({"chpe": True}, "CHPEMetadataPointer"),
])
def test_pe_map_dvrt_other_forms_stay_indeterminate(change, why):
    import pe_map

    image = pe_map.parse(_dvrt_pe(**change))
    assert image.written.state == "indeterminate" and why in image.written.why, image.written.why


def test_pe_map_marks_writable_code_sections():
    import _pe_fixture as pf
    import pe_map

    image = pe_map.parse(pf.make_pe([pf.Section(".wx", 0x1000, b"\xC3", characteristics=0xE0000020)]))
    assert image.header_fields["writable_code_sections"] == [".wx"]


def test_elf_map_missing_size_duplicate_tags_and_plt_rewrite():
    """Astra impl r1 P1-3 / Fable P2-3."""
    import _elf_fixture as ef

    seg = [ef.Segment(0x1000, b"\x90" * 0x40)]
    missing = _elf(seg, extra_dynamic=[(7, 0x3000)])                                  # DT_RELA without DT_RELASZ
    assert missing.written.state == "indeterminate" and "DT_RELA without DT_RELASZ" in missing.written.why
    duplicate = _elf(seg, relocations=[ef.Reloc(0x1000, 8)], extra_dynamic=[(7, 0x3000)])   # a second DT_RELA
    assert duplicate.written.state == "indeterminate" and "duplicated dynamic tags" in duplicate.written.why
    plt = _elf(seg, extra_dynamic=[(0x70000000, 0x1000), (0x70000001, 0x20), (0x70000003, 0x10)])
    assert plt.written.state == "complete" and (0x1000, 0x1020, "plt-rewrite") in plt.written.ranges
    no_size = _elf(seg, extra_dynamic=[(0x70000000, 0x1000)])
    assert no_size.written.state == "indeterminate"
    wx = _elf([ef.Segment(0x1000, b"\x90", flags=7)])
    assert wx.header_fields["writable_code_segments"] == [1]


def test_elf_map_rejects_other_machines_and_types():
    import _elf_fixture as ef

    assert not _elf([ef.Segment(0x1000, b"\x90")], machine=183).ok          # EM_AARCH64: later
    assert not _elf([ef.Segment(0x1000, b"\x90")], e_type=1).ok             # ET_REL


# -- ISA facts step 1: raw per-voter evidence of the shims (layout revision 3, design_tbr_isa_facts_r3) --------

ISA_PAD = b"\x90" * 14   # (whole-instruction vectors: trailing bytes never join a complete instruction)


def _votes(hexbytes: str, pad: bool = True) -> dict:
    import decoders as d

    data = bytes.fromhex(hexbytes) + (ISA_PAD if pad else b"")
    return {name: d.decode(name, data, CODE, False) for name in d.INTEL_VOTERS}


def _profiles(hexbytes: str) -> dict:
    import decoders as d

    data = bytes.fromhex(hexbytes) + ISA_PAD
    return {profile: d.decode_profile(profile, data, CODE) for profile in d.XED_PROFILES}


@needs
def test_isa_raw_privilege_evidence_keeps_each_voter_apart():
    """lgdt: iced must_be_cpl0, XED RING0, Zydis IS_PRIVILEGED not set (r3 s7: mapped says_no later)."""
    votes = _votes("0F0110")
    assert votes["iced"].extra["must_be_cpl0"] and votes["iced"].extra["is_privileged"]
    assert votes["xed"].extra["privileged_attribute"] is True
    assert votes["zydis"].extra["privileged_attribute"] is False
    io = _votes("EC")   # in al, dx: iced is_privileged (IOPL) only, neither shim attribute
    assert io["iced"].extra["is_privileged"] and not io["iced"].extra["must_be_cpl0"]
    assert not io["zydis"].extra["privileged_attribute"] and not io["xed"].extra["privileged_attribute"]
    os_gated = _votes("0F31")   # rdtsc: iced may_require_cpl0 only
    assert os_gated["iced"].extra["may_require_cpl0"] and not os_gated["iced"].extra["is_privileged"]


@needs
def test_isa_sysret_and_sysexit_forms_are_separated_and_agree_on_the_g1_flow():
    """The REX.W forms: iced names them SYSRETQ / SYSEXITQ; the G1 flow vote stays sysret for all three."""
    for hexbytes, detail, bits in (("0F07", "sysret", 32), ("480F07", "sysret", 64),
                                   ("0F35", "sysexit", 32), ("480F35", "sysexit", 64)):
        votes = _votes(hexbytes)
        assert {v.flow for v in votes.values()} == {"sysret"}, hexbytes
        assert {v.extra["flow_detail"] for v in votes.values()} == {detail}, hexbytes
        assert votes["zydis"].operand_bits == bits, hexbytes


@needs
def test_isa_fs_gs_effective_segments_and_address_only_operands():
    fs, gs = _votes("64488B042530000000"), _votes("65488B042560000000")
    assert all(v.extra["mem_segments"] == ["fs"] for v in fs.values())
    assert all(v.extra["mem_segments"] == ["gs"] for v in gs.values())
    lea = _votes("64488D042530000000")   # lea with an FS prefix touches no memory
    assert all("fs" not in v.extra["mem_segments"] for v in lea.values())


@needs
def test_isa_xed_profiles_expose_the_feature_split_and_keep_invalid_for_chip_apart():
    tz = _profiles("F30FBCC1")
    assert (tz["xed:g1"].mnemonic, tz["xed:baseline"].mnemonic, tz["xed:all"].mnemonic) == ("BSF", "BSF", "TZCNT")
    assert tz["xed:baseline"].extra["chip"] == "P4PRESCOTT_NOLAHF" and tz["xed:all"].extra["chip"] == "ALL"
    assert tz["xed:g1"].extra["chip"] == ""
    lahf = _profiles("9F")   # LAHF in 64-bit mode needs a feature the baseline chip lacks
    assert lahf["xed:baseline"].status == "invalid" and lahf["xed:baseline"].extra["error"] == "INVALID_FOR_CHIP"
    assert lahf["xed:all"].status == "ok"
    avx = _profiles("C5FC58C1")   # without AVX the VEX prefix is not recognised: XED reports a general error
    assert avx["xed:baseline"].status == "invalid" and avx["xed:baseline"].extra["error"] == "GENERAL_ERROR"
    assert avx["xed:all"].status == "ok" and avx["xed:all"].mnemonic == "VADDPS"


@needs
def test_isa_raw_error_names_and_truncation():
    lock = _votes("F083C001")
    assert {v.status for v in lock.values()} == {"invalid"}
    assert (lock["zydis"].extra["error"], lock["xed"].extra["error"]) == ("ILLEGAL_LOCK", "BAD_LOCK_PREFIX")
    cut = _votes("0F", pad=False)
    assert {v.status for v in cut.values()} == {"no_more_data"}
    assert cut["xed"].extra["error"] == "BUFFER_TOO_SHORT"


@needs
def test_isa_profile_catalogue_and_unsupported_profiles():
    import decoders as d

    catalogue = d.profile_catalogue()
    assert catalogue["xed:g1"] == {"chip": None, "isa_sets": None}
    baseline, full = catalogue["xed:baseline"]["isa_sets"], catalogue["xed:all"]["isa_sets"]
    assert "LONGMODE" in baseline and "LAHF" not in baseline and set(baseline) < set(full)
    assert d.voter("xed").chip_isa_sets("NO_SUCH_CHIP") is None
    assert d.voter("zydis").chip_isa_sets("ALL") is None
    bad = d.voter("xed").decode(b"\x90" * 15, CODE, False, "NO_SUCH_CHIP")
    assert bad.status == "error" and bad.extra["error"] == "unknown chip profile"
    assert d.voter("zydis").decode(b"\x90" * 15, CODE, False, "ALL").status == "error"


@needs
def test_isa_raw_evidence_never_enters_the_g1_vote_json():
    vote = _votes("0F0110")["xed"]
    assert "extra" not in vote.as_json() and "privileged_attribute" not in vote.as_json()
    assert vote == type(vote)(**{**vote.__dict__, "extra": {}})   # (extra is not compared)


# -- ISA facts step 2: the three data files (isa_tables.py) ----------------------------------------------------

# every vector of design r3 s7 / s7a with the canonical key all three voters must land on
ISA_KEYS = {
    "0F0110": "LGDT", "0F0118": "LIDT", "0F0010": "LLDT", "0F0018": "LTR", "0F06": "CLTS", "0F0130": "LMSW",
    "0F08": "INVD", "0F09": "WBINVD", "0F0138": "INVLPG", "0F01F8": "SWAPGS", "0F32": "RDMSR", "0F30": "WRMSR",
    "0F20C0": "MOV_CR", "0F22C0": "MOV_CR", "0F21C0": "MOV_DR", "0F23C0": "MOV_DR", "F4": "HLT",
    "EC": "IN", "E4FF": "IN", "ED": "IN", "66E5FF": "IN", "E6FF": "OUT", "EE": "OUT", "66EF": "OUT",
    "6C": "INSB", "666D": "INSW", "6D": "INSD", "6E": "OUTSB", "6F": "OUTSD", "FA": "CLI", "FB": "STI",
    "9D": "POPFQ", "669D": "POPF", "0FA2": "CPUID", "0F31": "RDTSC", "0F01F9": "RDTSCP", "0F33": "RDPMC",
    "0F01EE": "RDPKRU", "0F01EF": "WRPKRU", "0F01D0": "XGETBV", "0F05": "SYSCALL", "0F34": "SYSENTER",
    "0F07": "SYSRET", "480F07": "SYSRETQ", "0F35": "SYSEXIT", "480F35": "SYSEXITQ", "CC": "INT3", "CD29": "INT",
    "F1": "INT1", "0FFF00": "UD0", "0FB900": "UD1", "0F0B": "UD2", "CF": "IRETD", "66CF": "IRET", "48CF": "IRETQ",
    "CB": "RET_FAR", "FF2C2500100000": "JMP_FAR", "FF18": "CALL_FAR", "C3": "RET_NEAR", "F3C3": "RET_NEAR",
    "FFD0": "CALL_NEAR_INDIRECT", "FFE0": "JMP_NEAR_INDIRECT", "C7F810000000": "XBEGIN", "0F01D5": "XEND",
    "C6F805": "XABORT", "0F0100": "SGDT", "0F0108": "SIDT", "0F0000": "SLDT", "0F0120": "SMSW", "0F0008": "STR",
    "0F02C0": "LAR", "0F03C0": "LSL", "F3480FAEC0": "RDFSBASE", "F3480FAEC8": "RDGSBASE",
    "F3480FAED0": "WRFSBASE", "F3480FAED8": "WRGSBASE", "0FC7F0": "RDRAND", "0FC7F8": "RDSEED",
    "F30FC7F8": "RDPID", "8EE0": "MOV_TO_FS", "8EE8": "MOV_TO_GS", "0FA1": "POP_FS", "0FA9": "POP_GS",
    "0FB400": "LFS", "0FB500": "LGS", "6690": "NOP", "0F1F00": "NOP",
    # 2b additions (design_tbr_isa_ordinary_r3: r2 B, r3 s1 / s8)
    "E800000000": "CALL_NEAR", "E900000000": "JMP_NEAR", "EB00": "JMP_SHORT", "740A": "JCC_SHORT",
    "0F8400000000": "JCC_NEAR", "E2FE": "LOOP_JCXZ", "E3FE": "LOOP_JCXZ", "C20800": "RET_NEAR_IMM",
    "8EC0": "MOV_TO_DS_ES", "8ED8": "MOV_TO_DS_ES", "8ED0": "MOV_TO_SS", "8CC0": "MOV_FROM_SREG",
    "0FA0": "PUSH_FS", "0FA8": "PUSH_GS", "9C": "PUSHFQ", "669C": "PUSHF", "660FC8": "BSWAP16", "0FB200": "LSS",
    "F36C": "INSB", "F36E": "OUTSB",
}
# split vectors: the G1 voters land on the main and the fallback of one split (design r3 s3, isa_splits_x64.json)
ISA_SPLIT_VECTORS = {"F30FBCC1": "tzcnt-bsf", "F30FBDC1": "lzcnt-bsr", "F30F1EFA": "endbr64-nop",
                     "F30F1EFB": "endbr32-nop", "F390": "pause-nop"}
# forms outside the table: absent for every voter (unobserved, never "no condition")
ISA_ABSENT = ("4889C8", "0FC8", "0F1800", "F20F7CC1", "0F1E00")


def _keys(tables, hexbytes: str) -> dict:
    import isa_tables

    data = bytes.fromhex(hexbytes) + ISA_PAD
    return {name: isa_tables.lookup(tables, vote, data) for name, vote in _votes(hexbytes).items()}


def test_isa_tables_load_validate_and_digest():
    import isa_tables

    tables = isa_tables.load()
    assert set(tables.digests) == {"conditions", "map", "splits", "ordinary"}
    assert all(len(digest) == 64 for digest in tables.digests.values())
    assert isa_tables.load().digests == tables.digests
    for key, entry in tables.conditions["entries"].items():
        assert entry["cite"], key
    rdpkru = tables.entry("RDPKRU")   # s7a: CR4.PKE gate, EAX os_set_or_program_set, EDX constant 0
    assert rdpkru["f2"]["enable"] == [["CR4.PKE=1"]]
    assert {o["output"]: o["source"] for o in rdpkru["f6"]} == {"EAX (PKRU)": "os_set_or_program_set",
                                                                 "EDX": "constant"}
    assert tables.entry("STI")["f2"]["enable"][1][-1] == "RFLAGS.VIP=0" and "RFLAGS.VIP=0" not in str(tables.entry("CLI"))
    assert tables.entry("SYSEXIT")["f3"]["tags"] == ["privileged_return", "may_change_mode"]
    assert tables.entry("SYSEXITQ")["f3"]["tags"] == ["privileged_return"]
    popf = {o["output"]: o for o in tables.conditions["f2_meanings"]["POPF_FLAGS"]["outputs"]}
    assert popf["RFLAGS.AC"]["loaded_when"] == [] and popf["RFLAGS.IF"]["loaded_when"] == ["CPL<=IOPL"]


@pytest.mark.parametrize("break_it", ["unknown condition", "no citation", "map key missing", "split main missing",
                                      "unknown f3 tag", "constant without value", "schema"])
def test_isa_tables_reject_a_malformed_file(break_it):
    import copy
    import json

    import isa_tables

    root = Path(isa_tables.__file__).parent
    conditions, mapping, splits = (json.loads((root / isa_tables.FILES[name]).read_text(encoding="utf-8"))
                                   for name in ("conditions", "map", "splits"))
    conditions, mapping, splits = copy.deepcopy(conditions), copy.deepcopy(mapping), copy.deepcopy(splits)
    if break_it == "unknown condition":
        conditions["entries"]["HLT"]["f2"]["enable"] = [["CPL=7"]]
    elif break_it == "no citation":
        conditions["entries"]["HLT"]["cite"] = []
    elif break_it == "map key missing":
        mapping["rules"].append({"mnemonic": ["ADD"], "key": "="})
    elif break_it == "split main missing":
        del conditions["entries"]["TZCNT"]
    elif break_it == "unknown f3 tag":
        conditions["entries"]["HLT"]["f3"]["tags"] = ["sleeps"]
    elif break_it == "constant without value":
        del conditions["entries"]["RDPKRU"]["f6"][1]["value"]
    else:
        splits["schema"] = "tbr-isa-splits-0"
    with pytest.raises(isa_tables.TableError):
        isa_tables.validate(conditions, mapping, splits)


@needs
@pytest.mark.parametrize("hexbytes", sorted(ISA_KEYS))
def test_isa_every_voter_lands_on_the_same_key(hexbytes):
    import isa_tables

    keys = _keys(isa_tables.load(), hexbytes)
    assert set(keys.values()) == {ISA_KEYS[hexbytes]}, keys


@needs
@pytest.mark.parametrize("hexbytes", sorted(ISA_SPLIT_VECTORS))
def test_isa_split_vectors_land_on_one_split(hexbytes):
    """XED's G1 setting reads the legacy meaning; iced / Zydis the main one: one split, not a disagreement."""
    import isa_tables

    tables = isa_tables.load()
    keys = _keys(tables, hexbytes)
    split = tables.same_split(keys.values())
    assert split is not None and split["id"] == ISA_SPLIT_VECTORS[hexbytes], keys
    assert keys["iced"] == keys["zydis"] == split["main"] and keys["xed"] == split["fallback"]


@needs
def test_isa_split_table_agrees_with_the_xed_profiles():
    """Where the baseline chip lacks the deciding feature, xed:baseline reads the fallback and xed:all the main."""
    import isa_tables

    tables = isa_tables.load()
    for split in tables.splits["splits"]:
        profiles = _profiles(split["vector"])
        data = bytes.fromhex(split["vector"]) + ISA_PAD
        main = isa_tables.lookup(tables, profiles["xed:all"], data)
        baseline = isa_tables.lookup(tables, profiles["xed:baseline"], data)
        assert main == split["main"], split["id"]
        if split["id"] == "pause-nop":
            assert baseline == "PAUSE"   # (PAUSE is in the baseline chip: only the table names this split)
        else:
            assert baseline == split["fallback"], split["id"]


@needs
@pytest.mark.parametrize("hexbytes", ISA_ABSENT)
def test_isa_forms_outside_the_table_are_absent_for_every_voter(hexbytes):
    import isa_tables

    assert set(_keys(isa_tables.load(), hexbytes).values()) == {None}


def test_isa_opcode_view_skips_prefixes_and_rex():
    import isa_tables

    assert isa_tables.opcode_view(bytes.fromhex("F3480FAED8")) == ((0xF3,), b"\x0F\xAE", 0xD8)
    assert isa_tables.opcode_view(bytes.fromhex("66E5FF")) == ((0x66,), b"\xE5", 0xFF)
    assert isa_tables.opcode_view(bytes.fromhex("8EE0")) == ((), b"\x8E", 0xE0)
    assert isa_tables.opcode_view(bytes.fromhex("660F3800C1")) == ((0x66,), b"\x0F\x38\x00", 0xC1)
    assert isa_tables.opcode_view(bytes.fromhex("C5FC58C1"))[1] == b""


# -- ISA facts 2b: classifying every form (design_tbr_isa_ordinary_r3 = r2 + r1) --------------------------------

# final classification (r2 F2 / r3 s7): expected result and class / key
ISA_CLASSIFY = {
    "4889C8": ("derived_ordinary", "plain"), "8B00": ("derived_ordinary", "plain"),
    "678B00": ("unclassified", "A"),                                  # address width 32 (r3 s3)
    "64D7": ("derived_ordinary", "plain"), "D7": ("derived_ordinary", "plain"),
    "F3A4": ("derived_ordinary", "plain"), "64F3A4": ("derived_ordinary", "plain"),
    "F0830001": ("derived_ordinary", "plain"), "8700": ("derived_ordinary", "plain"),
    "0FC8": ("derived_ordinary", "plain"), "C8000003": ("derived_ordinary", "plain"),
    "0F1800": ("derived_ordinary", "plain"), "0FAEE8": ("derived_ordinary", "plain"),     # PREFETCHNTA, LFENCE
    "660FEFC1": ("derived_ordinary", "sse_int"), "0FEFC1": ("derived_ordinary", "mmx"),
    "0F58C1": ("derived_ordinary", "sse_fp"), "F20F10C1": ("derived_ordinary", "sse_int"),
    "0F2AC1": ("derived_ordinary", "mmx_sse"), "660F2AC1": ("derived_ordinary", "mmx_sse"),
    "660F2A00": ("derived_ordinary", "sse_int"), "0F53C1": ("derived_ordinary", "sse_int"),
    "F20F2D00": ("derived_ordinary", "sse_fp"),                       # CVTSD2SI eax, [rax]: SSE without an XMM operand
    "0F10C1": ("derived_ordinary", "sse_int"),
    "9B": ("derived_ordinary", "fwait"), "0FAE00": ("derived_ordinary", "fxsave"),
    "0FAE08": ("derived_ordinary", "fxrstor"), "0FAE10": ("derived_ordinary", "mxcsr"),
    "DFE0": ("derived_ordinary", "x87_nowait"), "D9E8": ("derived_ordinary", "x87"),
    # outside the base level (r1 s1): never derived-ordinary
    "F20F7CC1": ("unclassified", "B"), "F30F16C1": ("unclassified", "B"), "F20FF008": ("unclassified", "B"),
    "9F": ("unclassified", "B"), "9E": ("unclassified", "B"), "480FC70E": ("unclassified", "B"),
    "0FAE38": ("unclassified", "B"), "0F0D08": ("unclassified", "B"), "0F01C8": ("unclassified", "B"),
    "F3480FB8C1": ("unclassified", "B"),
    # cited first (r2 A1), cited splits (r3 s3)
    "0FA2": ("cited", "CPUID"), "0F0B": ("cited", "UD2"), "660FC8": ("cited", "BSWAP16"),
    "8ED0": ("cited", "MOV_TO_SS"), "0FB200": ("cited", "LSS"), "3EFFD0": ("cited", "CALL_NEAR_INDIRECT"),
    "F3C3": ("cited", "RET_NEAR"), "EB00": ("cited", "JMP_SHORT"), "E2FE": ("cited", "LOOP_JCXZ"),
    "9D": ("cited", "POPFQ"), "9C": ("cited", "PUSHFQ"), "8CC0": ("cited", "MOV_FROM_SREG"),
    "F390": ("cited_split", "pause-nop"), "F30F1EFA": ("cited_split", "endbr64-nop"),
    "F30FBCC1": ("cited_split", "tzcnt-bsf"),
    "F083C001": ("unclassified", "no ok vote"),                        # illegal LOCK: F1, no class
    # implementation review round 1 (Astra / Fable)
    "660FA4C811": ("cited", "SHLD16"), "660FADC8": ("cited", "SHRD16"), "0FA4C811": ("derived_ordinary", "plain"),
    "678D00": ("unclassified", "address width 32"), "678D0408": ("unclassified", "address width 32"),
    "40F301C8": ("unclassified", "F2 / F3 prefix"), "F2F00100": ("unclassified", "F2 / F3 prefix"),
    "0FE4C1": ("derived_ordinary", "mmx"), "0FD4C1": ("derived_ordinary", "mmx"),     # PMULHUW mm, PADDQ mm
    "0F77": ("derived_ordinary", "emms"),
    "F20F2AC0": ("derived_ordinary", "sse_fp"), "F2480F2AC0": ("derived_ordinary", "sse_fp"),
    "669D": ("cited", "POPF"),
}


def _xed_redecode(window: bytes):
    import decoders as d

    return d.xed_redecode(window, CODE)


def _classify(tables, hexbytes: str) -> dict:
    import isa_tables

    data = bytes.fromhex(hexbytes) + ISA_PAD
    return isa_tables.classify(tables, _votes(hexbytes), data, redecode=_xed_redecode)


@needs
@pytest.mark.parametrize("hexbytes", sorted(ISA_CLASSIFY))
def test_isa_2b_final_classification(hexbytes):
    import isa_tables

    tables = isa_tables.load()
    got = _classify(tables, hexbytes)
    result, detail = ISA_CLASSIFY[hexbytes]
    assert got["result"] == result, got
    if result == "derived_ordinary":
        assert got["class"] == detail, got
    elif result == "cited":
        assert got["key"] == detail, got
    elif result == "cited_split":
        assert got["split"] == detail, got
    else:
        assert any(detail in reason for reason in got["reasons"]), got
    assert set(got["digests"]) == {"conditions", "map", "splits", "ordinary"}


@needs
def test_isa_2b_class_flags_and_per_operand_mmx():
    """r3 s4: MMX transition only with an MMX register operand; MXCSR read only by forms that round."""
    import isa_tables

    tables = isa_tables.load()
    with_mm, with_mem = _classify(tables, "660F2AC1"), _classify(tables, "660F2A00")   # CVTPI2PD xmm, mm / m64
    assert with_mm["flags"]["explicit_mmx_operand"] and not with_mem["flags"]["explicit_mmx_operand"]
    assert with_mm["flags"]["mxcsr_inputs"] == [] and not with_mm["flags"]["simd_fp_exceptions"]   # exact
    assert _classify(tables, "0F2AC1")["flags"]["mxcsr_inputs"] == ["RC"]                        # CVTPI2PS rounds
    assert _classify(tables, "0F2CC1")["flags"]["mxcsr_inputs"] == ["DAZ"]                       # CVTTPS2PI truncates
    assert _classify(tables, "0F58C1")["flags"]["mxcsr_inputs"] == ["RC", "DAZ", "FTZ"]         # ADDPS
    r32, r64 = _classify(tables, "F20F2AC0")["flags"], _classify(tables, "F2480F2AC0")["flags"]   # CVTSI2SD
    assert (r32["simd_fp_exceptions"], r32["mxcsr_inputs"]) == (False, [])
    assert (r64["simd_fp_exceptions"], r64["mxcsr_inputs"]) == (True, ["RC"])
    rcpps = _classify(tables, "0F53C1")["flags"]
    assert not rcpps["simd_fp_exceptions"]
    assert _classify(tables, "0F10C1")["flags"]["alignment"] is False  # MOVUPS (type 4M)
    assert _classify(tables, "0F2800")["flags"]["alignment"] is True   # MOVAPS xmm, m128 (type 1)


@needs
def test_isa_2b_known_positives_fail_the_rule_without_the_cited_table():
    """r2 F1 / r1 s9-2: an allowlist generated WITHOUT the cited exclusion, used WITHOUT cited lookups, must still
    never call a cited conditional form derived-ordinary (the per-row tests catch what the generator lets in)."""
    import dataclasses

    import isa_ordinary_gen
    import isa_tables

    catalogue = DECODERS / "xed_catalogue.tsv"
    if not catalogue.exists():
        pytest.skip("the XED catalogue dump is built by build_decoders.sh")
    tables = isa_tables.load()
    entries, _ = isa_ordinary_gen.generate(isa_ordinary_gen.read_catalogue(catalogue), tables.ordinary, set())
    index = {(e["iclass"], e["extension"], e["isa_set"], e["sig"]): e for e in entries}
    loose = dataclasses.replace(tables, map={**tables.map, "rules": []}, index=index)
    conditional = [key for key, entry in tables.conditions["entries"].items()
                   if set(entry) & {"f2", "f2_meaning", "f3", "f4", "f6", "f7", "cet", "state_effect",
                                    "undefined_outputs"}]
    vectors = [hexbytes for hexbytes, key in ISA_KEYS.items() if key in conditional] + [
        "F20F7CC1", "9F", "9E", "480FC70E", "0FAE38", "0F0D08", "0F01C8", "0F01C9", "660FC8", "0FA2", "0F0B"]
    passed = [hexbytes for hexbytes in vectors if _classify(loose, hexbytes)["result"] == "derived_ordinary"]
    assert passed == [], passed


@needs
def test_isa_2b_memory_access_evidence():
    """r3 s6: per access role / segment; FS source and ES destination for 64 F3 A4; iced keeps ENTER's 6 accesses."""
    movs = _votes("64F3A4")
    for name in ("iced", "zydis", "xed"):
        roles = {(m["role"], m["read"], m["write"]) for m in movs[name].extra["memory"]}
        assert ("string_source", True, False) in roles and ("string_dest", False, True) in roles, name
        source = next(m for m in movs[name].extra["memory"] if m["role"] == "string_source")
        assert source["segment"] == "fs", name
        assert movs[name].extra["rep"] == "rep"
    enter = _votes("C8000003")
    assert len(enter["iced"].extra["memory"]) == 6 and not enter["iced"].extra["mem_overflow"]
    assert len(enter["xed"].extra["memory"]) == 1   # (XED / Zydis model one access: F7 voters differ, step 3)


def test_isa_2b_ordinary_file_validation():
    import copy
    import json

    import isa_tables

    root = Path(isa_tables.__file__).parent
    files = {name: json.loads((root / isa_tables.FILES[name]).read_text(encoding="utf-8"))
             for name in isa_tables.FILES}
    isa_tables.validate(files["conditions"], files["map"], files["splits"], files["ordinary"])
    broken = copy.deepcopy(files["ordinary"])
    broken["entries"].append(dict(broken["entries"][0], iclass="CPUID"))      # cited and ordinary at once
    with pytest.raises(isa_tables.TableError):
        isa_tables.validate(files["conditions"], files["map"], files["splits"], broken)
    broken = copy.deepcopy(files["ordinary"])
    broken["entries"].append(dict(broken["entries"][0], isa_set="SSE3"))      # outside the base level
    with pytest.raises(isa_tables.TableError):
        isa_tables.validate(files["conditions"], files["map"], files["splits"], broken)
    conditions = copy.deepcopy(files["conditions"])
    conditions["entries"]["CALL_NEAR"]["cet"] = [{"name": "CET_SS", "when": "rel8 != 0"}]   # unknown expression
    with pytest.raises(isa_tables.TableError):
        isa_tables.validate(conditions, files["map"], files["splits"], files["ordinary"])
    mapping = copy.deepcopy(files["map"])
    mapping["rules"].append({"mnemonic": ["NOP"], "when": {"opcode": ["90"]}, "key": "PAUSE"})   # same selector
    with pytest.raises(isa_tables.TableError):
        isa_tables.validate(files["conditions"], mapping, files["splits"], files["ordinary"])


def test_isa_2b_mpx_set_and_bnd_direction():
    """r3 s1: the Table E-4 set excludes EB and E0-E3; the BND prefix preserves (schema 1 had it backwards)."""
    import isa_tables

    tables = isa_tables.load()
    mpx = tables.conditions["mpx_effects"]["TABLE_E4"]
    assert "EB" in mpx["not_members"] and "E0-E3" in mpx["not_members"]
    for key in ("CALL_NEAR", "CALL_NEAR_INDIRECT", "RET_NEAR", "RET_NEAR_IMM", "JMP_NEAR", "JMP_NEAR_INDIRECT",
                "JCC_SHORT", "JCC_NEAR"):
        assert tables.entry(key)["mpx"] == "TABLE_E4", key
    for key in ("JMP_SHORT", "LOOP_JCXZ"):
        assert "mpx" not in tables.entry(key), key
    bnd = tables.splits["prefix_splits"][0]
    assert "PRESERVES" in bnd["main"]
    assert tables.entry("CALL_NEAR")["cet"] == [{"name": "CET_SS", "when": "rel32 != 0"}]
    assert {"name": "CET_IBT", "unless": "NOTRACK"} in tables.entry("JMP_NEAR_INDIRECT")["cet"]
    assert tables.entry("BSF")["undefined_outputs"][0]["when"].startswith("source = 0")
    assert "state_effect" in tables.entry("MOV_TO_SS") and "state_effect" not in tables.entry("LSS")


# -- ISA facts: implementation review round 1 fixes ------------------------------------------------------------

@needs
def test_isa_impl_missing_evidence_or_form_mismatch_never_passes():
    """impl r1 P1-2: a voter without its evidence, or with another operand-kind form, is not an agreement."""
    import dataclasses

    import isa_tables

    tables = isa_tables.load()
    data = bytes.fromhex("4801C8") + ISA_PAD                      # add rax, rcx
    votes = _votes("4801C8")
    assert isa_tables.classify(tables, votes, data, redecode=_xed_redecode)["result"] == "derived_ordinary"
    for name, field in (("iced", "must_be_cpl0"), ("iced", "rflags_written"), ("zydis", "sreg_operand"),
                        ("xed", "privileged_attribute")):
        extra = {k: v for k, v in votes[name].extra.items() if k != field}
        broken = dict(votes, **{name: dataclasses.replace(votes[name], extra=extra)})
        got = isa_tables.classify(tables, broken, data, redecode=_xed_redecode)
        assert got["result"] == "unclassified" and any("evidence" in r for r in got["reasons"]), (name, field)
    zydis = dataclasses.replace(votes["zydis"], extra=dict(votes["zydis"].extra, op_sig="gi"))
    got = isa_tables.classify(tables, dict(votes, zydis=zydis), data, redecode=_xed_redecode)
    assert got["result"] == "unclassified" and any("operand kinds" in r for r in got["reasons"])


@needs
def test_isa_impl_partial_lookup_is_kept_when_a_voter_fails():
    import dataclasses

    import isa_tables

    tables = isa_tables.load()
    votes = _votes("0FA2")
    failed = dict(votes, zydis=dataclasses.replace(votes["zydis"], status="error"))
    got = isa_tables.classify(tables, failed, bytes.fromhex("0FA2") + ISA_PAD, redecode=_xed_redecode)
    assert got["result"] == "unclassified" and got["keys"] == {"iced": "CPUID", "xed": "CPUID"}


@needs
def test_isa_impl_rflags_masks_are_architectural_bits():
    """impl r1 Fable P3-1 / Astra P3: CLI writes IF; POPFQ writes IF, IOPL, AC; no bit above 21."""
    IF, IOPL, AC = 1 << 9, 3 << 12, 1 << 18
    cli, popfq = _votes("FA"), _votes("9D")
    for name in ("xed", "zydis", "iced"):
        assert cli[name].extra["rflags_written"] & IF, name
        assert popfq[name].extra["rflags_written"] & (IF | AC) == IF | AC, name
        assert (cli[name].extra["rflags_written"] | popfq[name].extra["rflags_written"]) < (1 << 22), name
    for name in ("xed", "zydis"):
        assert popfq[name].extra["rflags_written"] & IOPL, name
    assert not popfq["iced"].extra["rflags_written"] & IOPL     # (iced reports IF / AC only: capability)


@needs
def test_isa_impl_single_feature_decode_and_conditional_accesses():
    import decoders as d

    for hexbytes, isa_set, fallback in (("F30FBCC1", "BMI1", "BSF"), ("F30FBDC1", "LZCNT", "BSR"),
                                        ("F30F1EFA", "CET", "NOP")):
        got = d.decode_without(isa_set, bytes.fromhex(hexbytes) + ISA_PAD, CODE)
        assert got.status == "ok" and got.mnemonic == fallback and got.extra["chip"] == f"ALL-{isa_set}"
    assert d.decode_without("NO_SUCH_SET", b"\x90" * 15, CODE).status == "error"
    for name, vote in _votes("64F3A4").items():
        assert all(m["conditional"] for m in vote.extra["memory"]), name
    for name, vote in _votes("64A4").items():                       # movsb without REP: unconditional
        assert not any(m["conditional"] for m in vote.extra["memory"]), name


def test_isa_impl_data_fixes():
    import isa_tables

    tables = isa_tables.load()
    wrmsr = tables.entry("WRMSR")["f7"]
    assert set(wrmsr["writes_base"]) == {"fs", "gs", "kernel_gs"} and "ECX unknown" in wrmsr["when"]
    assert tables.entry("XGETBV")["f6"][0]["source"] == "os_set_or_program_set"
    assert tables.entry("POPF")["f2_meaning"] == "POPF16_FLAGS" and tables.entry("POPFQ")["f2_meaning"] == "POPF_FLAGS"
    popf16 = {o["output"]: o for o in tables.conditions["f2_meanings"]["POPF16_FLAGS"]["outputs"]}
    assert not any("loaded at any CPL" in str(o) for o in popf16.values())
    endbr32 = next(s for s in tables.splits["splits"] if s["id"] == "endbr32-nop")
    assert any(item.startswith("CS.L=0") for item in endbr32["enabled"])
    assert tables.ordinary["classes"]["fxsave"]["f6"][0]["source"] == "external"
    assert "transition" not in str(tables.ordinary["classes"]["emms"]["effects"]).replace("no x87-to-MMX transition", "")
    for name in ("SHLD", "SHRD", "BSWAP"):
        assert tables.ordinary["width_limits"][name]["widths"] == [32, 64]


def test_isa_impl_validator_rejects_overlapping_selectors():
    import copy
    import json

    import isa_tables

    root = Path(isa_tables.__file__).parent
    files = {name: json.loads((root / isa_tables.FILES[name]).read_text(encoding="utf-8")) for name in isa_tables.FILES}
    mapping = copy.deepcopy(files["map"])
    mapping["rules"].insert(0, {"mnemonic": ["NOP"], "when": {"opcode": ["90", "91"]}, "key": "PAUSE"})
    with pytest.raises(isa_tables.TableError):
        isa_tables.validate(files["conditions"], mapping, files["splits"], files["ordinary"])
    isa_tables.validate(files["conditions"], files["map"], files["splits"], files["ordinary"])


@needs
def test_isa_impl_nop_fallback_needs_the_exact_endbr_byte():
    import isa_tables

    tables = isa_tables.load()
    assert _classify(tables, "F30F1EFA")["result"] == "cited_split"
    assert _classify(tables, "F30F1EF8")["result"] != "cited"        # 0F 1E /7 but not FA / FB


# -- ISA facts: implementation review round 2 fixes ------------------------------------------------------------

@needs
def test_isa_impl2_iced_form_needs_exact_or_pinned_convention():
    """impl r2 P1-1: 48 01 C8 with iced 'gi' fails; a pinned convention (accumulator immediate) passes."""
    import dataclasses

    import isa_tables

    tables = isa_tables.load()
    data = bytes.fromhex("4801C8") + ISA_PAD
    votes = _votes("4801C8")
    iced = dataclasses.replace(votes["iced"], extra=dict(votes["iced"].extra, op_sig="gi"))
    got = isa_tables.classify(tables, dict(votes, iced=iced), data, redecode=_xed_redecode)
    assert got["result"] == "unclassified" and any("iced A" in r for r in got["reasons"])
    for field, value in (("op_sig", "g?"), ("must_be_cpl0", None), ("rflags_written", True)):
        iced = dataclasses.replace(votes["iced"], extra=dict(votes["iced"].extra, **{field: value}))
        got = isa_tables.classify(tables, dict(votes, iced=iced), data, redecode=_xed_redecode)
        assert got["result"] == "unclassified" and any("evidence" in r for r in got["reasons"]), field
    for hexbytes in ("3C05", "4883F805", "D1E8", "D3E0", "48AB", "D7", "DFE0"):   # pinned conventions
        assert _classify(tables, hexbytes)["result"] == "derived_ordinary", hexbytes


@needs
def test_isa_impl2_width_dependent_flags_need_agreeing_listed_widths():
    """impl r2 P1-2: CVTSI2SD flags only when XED and Zydis report the same listed width (iced 0 or the same)."""
    import dataclasses

    import isa_tables

    tables = isa_tables.load()
    data = bytes.fromhex("F2480F2AC0") + ISA_PAD
    votes = _votes("F2480F2AC0")
    assert _classify(tables, "F2480F2AC0")["flags"]["mxcsr_inputs"] == ["RC"]
    for xed_bits, zydis_bits in ((64, 32), (64, 0), (0, 32), (16, 16), (32, 64)):
        broken = dict(votes, xed=dataclasses.replace(votes["xed"], operand_bits=xed_bits),
                      zydis=dataclasses.replace(votes["zydis"], operand_bits=zydis_bits))
        got = isa_tables.classify(tables, broken, data, redecode=_xed_redecode)
        assert got["result"] == "unclassified", (xed_bits, zydis_bits, got)


@needs
def test_isa_impl2_nop_encoding_ranges():
    """impl r2 P2-2: only the listed prefix sets reach NOP; F3 0F 1E F8 gives no NOP lookup at all."""
    import isa_tables

    tables = isa_tables.load()
    for hexbytes in ("F3F20F1EFA", "F290", "F2F390"):
        votes = _votes(hexbytes)
        assert isa_tables.lookup(tables, votes["xed"], bytes.fromhex(hexbytes) + ISA_PAD) != "NOP", hexbytes
    for hexbytes in ("90", "6690", "0F1F00", "660F1F440000"):
        assert _classify(tables, hexbytes)["key"] == "NOP", hexbytes
    xed = _votes("F30F1EF8")["xed"]
    assert isa_tables.lookup(tables, xed, bytes.fromhex("F30F1EF8") + ISA_PAD) is None
    assert _classify(tables, "4190")["result"] != "cited" or _classify(tables, "4190").get("key") != "NOP"


@needs
def test_isa_impl2_conditional_writes_and_masked_write_flag():
    import isa_tables

    tables = isa_tables.load()
    got = _classify(tables, "660FF7C1")                               # MASKMOVDQU
    assert got["result"] == "derived_ordinary" and got["flags"]["masked_write"] is True
    for name, vote in _votes("64F3A4").items():
        source = next(m for m in vote.extra["memory"] if m["role"] == "string_source")
        dest = next(m for m in vote.extra["memory"] if m["role"] == "string_dest")
        assert (source["cond_read"], source["cond_write"]) == (True, False), name
        assert (dest["cond_read"], dest["cond_write"]) == (False, True), name
    for name, vote in _votes("480F4400").items():                    # CMOVZ rax, [rax]: the load always happens
        assert not any(m["cond_read"] for m in vote.extra["memory"]), name
    assert _votes("4801C8")["xed"].extra["iform"] == "ADD_GPRv_GPRv_01"


@needs
def test_isa_impl2_x87_flags_do_not_leak_into_rflags():
    """impl r2 P3: XED's flag-set mask carries FC0-FC3 for x87 compares; rflags_* keep bits 0-21 only."""
    for hexbytes in ("D8D1", "DBF1", "D9E4"):                       # FCOM st1, FCOMI st1, FTST
        for name, vote in _votes(hexbytes).items():
            assert vote.extra["rflags_read"] < (1 << 22) and vote.extra["rflags_written"] < (1 << 22), (hexbytes, name)


def test_isa_impl2_data_fixes():
    import isa_tables

    tables = isa_tables.load()
    popf16 = {o["output"]: o for o in tables.conditions["f2_meanings"]["POPF16_FLAGS"]["outputs"]}
    assert popf16["RFLAGS.RF"]["rule"].startswith("cleared")
    assert "SQRTPS" in tables.ordinary["mxcsr_groups"]["sqrt"]["iclasses"]
    assert "FTZ" not in tables.ordinary["mxcsr_groups"]["sqrt"]["mxcsr_inputs"]
    assert not any(n.startswith("SQRT") for n in tables.ordinary["mxcsr_groups"]["arith"]["iclasses"])


def test_isa_impl2_validator_compares_star_rules_and_exact_modrm():
    import copy
    import json

    import isa_tables

    root = Path(isa_tables.__file__).parent
    files = {name: json.loads((root / isa_tables.FILES[name]).read_text(encoding="utf-8")) for name in isa_tables.FILES}
    mapping = copy.deepcopy(files["map"])
    first_jcc = next(i for i, r in enumerate(mapping["rules"]) if r["key"] == "JCC_SHORT")
    mapping["rules"].insert(first_jcc, {"mnemonic": ["*"], "when": {"flow": "jcc", "counter": False, "opcode": ["74"]},
                                        "key": "JCC_NEAR"})
    with pytest.raises(isa_tables.TableError):
        isa_tables.validate(files["conditions"], mapping, files["splits"], files["ordinary"])
    mapping = copy.deepcopy(files["map"])                         # exact ModRM FA vs /0: never the same vote
    mapping["rules"].append({"mnemonic": ["NOP"], "when": {"opcode": ["0F1E"], "modrm_reg": [0]}, "key": "PAUSE"})
    isa_tables.validate(files["conditions"], mapping, files["splits"], files["ordinary"])


# -- ISA facts: implementation review round 3 (closing list) ---------------------------------------------------

@needs
def test_isa_impl3_xed_evidence_is_bound_to_the_bytes():
    """impl r3 P1-1: a tampered XED iform or a vote that does not match the window is unclassified."""
    import dataclasses

    import isa_tables

    tables = isa_tables.load()
    data = bytes.fromhex("4801C8") + ISA_PAD
    votes = _votes("4801C8")
    xed = dataclasses.replace(votes["xed"], extra=dict(votes["xed"].extra, iform="ADD_GPRv_GPRv_03"))
    got = isa_tables.classify(tables, dict(votes, xed=xed), data, redecode=_xed_redecode)
    assert got["result"] == "unclassified" and "verified bytes" in got["reasons"][0]
    cvtsi2sd = _votes("F20F2AC0")                                    # votes for F2 0F 2A, bytes of F3 0F 2A
    got = isa_tables.classify(tables, cvtsi2sd, bytes.fromhex("F30F2AC0") + ISA_PAD, redecode=_xed_redecode)
    assert got["result"] == "unclassified"
    assert isa_tables.classify(tables, votes, data)["result"] == "unclassified"     # no re-decode, no binding


@needs
def test_isa_impl3_malformed_evidence_is_a_reason_not_an_exception():
    import dataclasses

    import isa_tables

    tables = isa_tables.load()
    data = bytes.fromhex("8B00") + ISA_PAD
    votes = _votes("8B00")
    for name, field, value in (("xed", "op_sig", []), ("iced", "cpuid_features", [{}]), ("zydis", "memory", [None]),
                               ("iced", "memory", [{"segment": "ds"}])):
        vote = dataclasses.replace(votes[name], extra=dict(votes[name].extra, **{field: value}))
        got = isa_tables.classify(tables, dict(votes, **{name: vote}), data, redecode=_xed_redecode)
        assert got["result"] == "unclassified" and any(name in r for r in got["reasons"]), (name, field)


def test_isa_impl3_validator_matches_the_lookup():
    import copy
    import json

    import isa_tables

    root = Path(isa_tables.__file__).parent
    files = {name: json.loads((root / isa_tables.FILES[name]).read_text(encoding="utf-8")) for name in isa_tables.FILES}

    def rejects(rules):
        mapping = copy.deepcopy(files["map"])
        mapping["rules"] = rules
        with pytest.raises(isa_tables.TableError):
            isa_tables.validate(files["conditions"], mapping, files["splits"], files["ordinary"])

    rules = files["map"]["rules"]
    rejects([{"voters": ["xed"], "mnemonic": ["JZ"], "key": "JCC_NEAR"}] + rules)          # opcode-free JZ first
    rejects(rules + [{"mnemonic": ["NOP"], "when": {"opcode": ["0f1f"]}, "key": "PAUSE"}])  # lower-case hex
    rejects(rules + [{"mnemonic": ["NOP"], "when": {"opcode": ["90"], "prefix": "66"}, "key": "PAUSE"}])  # 66 + 90
    rejects(rules + [{"mnemonic": ["*"], "when": {"opcode": ["90"]}, "key": "PAUSE"}])      # wildcard
    fallback = copy.deepcopy(rules) + [
        {"mnemonic": ["NOP"], "when": {"opcode": ["0F1E"], "modrm_reg": [7]}, "key": "PAUSE", "fallback": True}]
    mapping = dict(copy.deepcopy(files["map"]), rules=fallback)                            # /7 covers FA / FB
    isa_tables.validate(files["conditions"], mapping, files["splits"], files["ordinary"])


@needs
def test_isa_impl3_nop_ranges_and_segment_prefixes():
    import isa_tables

    tables = isa_tables.load()
    for hexbytes in ("F3F390", "F3400F1EFA"):
        xed = _votes(hexbytes)["xed"]
        assert isa_tables.lookup(tables, xed, bytes.fromhex(hexbytes) + ISA_PAD) != "NOP", hexbytes
    got = _classify(tables, "662E0F1F840000000000")                 # aligned multi-byte NOP
    assert (got["result"], got.get("key")) == ("cited", "NOP")


@needs
def test_isa_impl3_conditional_writes_and_masked_semantics():
    import isa_tables

    tables = isa_tables.load()
    for name, vote in _votes("0FB108").items():                     # CMPXCHG [rax], ecx: the store is conditional
        accesses = isa_tables.memory_evidence(tables, vote)
        assert accesses and all(m["read"] for m in accesses), name
    for name, vote in _votes("660FF7C1").items():                   # MASKMOVDQU: every write conditional
        accesses = isa_tables.memory_evidence(tables, vote)
        writes = [m for m in accesses if m["write"]]
        assert writes and all(m["cond_write"] and m["semantics"] == "masked_write" for m in writes), name
    for name, vote in _votes("0FF7C1").items():                     # MASKMOVQ (outside the allowlist): same
        writes = [m for m in isa_tables.memory_evidence(tables, vote) if m["write"]]
        assert writes and all(m["cond_write"] for m in writes), name
    lea = _votes("488D0408")["iced"].extra
    assert lea["memory"] == [] and lea["memory_complete"] is True


@needs
def test_isa_impl3_shld_shrd_by_cl_convention():
    import isa_tables

    tables = isa_tables.load()
    for hexbytes in ("0FA5C8", "480FA5C8", "0FADC8", "480FADC8", "0FA508"):
        assert _classify(tables, hexbytes)["result"] == "derived_ordinary", hexbytes
    assert _classify(tables, "660FA5C8")["key"] == "SHLD16"


# -- ISA facts step 3: per-row facts and g1-decode-evidence-2 ---------------------------------------------------

def _row_facts(hexbytes: str) -> dict:
    import decoders as d
    import isa_facts
    import isa_tables

    data = bytes.fromhex(hexbytes) + ISA_PAD
    return isa_facts.row_facts(isa_tables.load(), d.ballot(data, CODE), data,
                               redecode=lambda w: d.xed_redecode(w, CODE),
                               decode_profile=lambda name, w: d.decode_profile(name, w, CODE),
                               decode_without=lambda isa_set, w: d.decode_without(isa_set, w, CODE))


@needs
def test_isa_step3_row_facts_on_the_design_vectors():
    """design r3 s7 expectations, as row facts."""
    import isa_facts

    plain = _row_facts("4889C8")
    assert plain["basis"] == "ordinary:plain" and not isa_facts.listed(plain)
    lgdt = _row_facts("0F0110")["facts"]["F2"]
    assert lgdt["voters_disagree"] == "conflict" and lgdt["table_vs_voter"]["table_requires_cpl0"] is True
    assert lgdt["voters"]["zydis"]["IS_PRIVILEGED"] is False and lgdt["voters"]["iced"]["must_be_cpl0"] is True
    rdmsr = _row_facts("0F32")
    assert rdmsr["basis"] == "cited:RDMSR" and "voters_disagree" not in rdmsr["facts"]["F2"]
    assert _row_facts("CD29")["facts"]["F3"] == {"flow": "int_n", "flow_detail": "none", "vector": 0x29}
    assert _row_facts("480F07")["facts"]["F3"]["flow_detail"] == "sysret"
    xbegin = _row_facts("C7F810000000")
    assert xbegin["facts"]["F3"]["abort_target"] == f"{CODE + 6 + 0x10:x}"
    assert xbegin["facts"]["F1"]["class"] == "invalid_for_chip"
    rdpkru = _row_facts("0F01EE")["facts"]["F1"]
    assert rdpkru["class"] == "invalid_for_chip" and rdpkru["profiles"]["xed:baseline"]["error"] == "INVALID_FOR_CHIP"
    vaddps = _row_facts("C5FC58C1")
    assert vaddps["basis"] == "unclassified" and vaddps["facts"]["F1"]["class"] == "invalid_for_chip"
    assert set(isa_facts.TABLE_SOURCED) <= set(vaddps["unobserved"])
    assert _row_facts("60")["facts"]["F1"]["class"] == "invalid_encoding"
    assert _row_facts("F083C001")["facts"]["F1"]["class"] == "invalid_encoding"
    tz = _row_facts("F30FBCC1")
    assert tz["basis"] == "split:tzcnt-bsf" and tz["facts"]["F4"]["split"]["split"] == "tzcnt-bsf"
    fs = _row_facts("64488B042530000000")
    assert fs["basis"] == "ordinary:plain" and fs["facts"]["F7"]["accesses"] == [
        {"segment": "fs", "role": "explicit", "read": True, "write": False, "cond_read": False, "cond_write": False,
         "operand_index": 1}]
    movs = _row_facts("64F3A4")["facts"]["F7"]["accesses"]
    assert movs == [{"segment": "fs", "role": "string_source", "read": True, "write": False, "cond_read": True,
                     "cond_write": False}]
    assert _row_facts("9D")["basis"] == "cited:POPFQ" and "F2p" not in _row_facts("9D")["facts"]   # (table)
    assert _row_facts("0F58C1")["facts"]["class_flags"]["mxcsr_inputs"] == ["RC", "DAZ", "FTZ"]


@needs
def test_isa_step3_single_feature_run_names_the_deciding_feature():
    """A profile split outside the split table: the deciding feature from a single-feature XED run (r3 s3)."""
    import dataclasses

    import decoders as d
    import isa_facts
    import isa_tables

    tables = isa_tables.load()
    tables = dataclasses.replace(tables, splits={**tables.splits, "splits": [s for s in tables.splits["splits"]
                                                                             if s["id"] != "lzcnt-bsr"]})
    data = bytes.fromhex("F30FBDC1") + ISA_PAD
    row = isa_facts.row_facts(tables, d.ballot(data, CODE), data, redecode=lambda w: d.xed_redecode(w, CODE),
                              decode_profile=lambda n, w: d.decode_profile(n, w, CODE),
                              decode_without=lambda s, w: d.decode_without(s, w, CODE))
    split = row["facts"]["F4"]["split"]
    assert split["source"] == "single_feature_run" and split["deciding_feature"] == "LZCNT", split


def _isa_block(rows_by_function, status=None):
    import isa_facts
    import isa_tables

    tables = isa_tables.load()
    header = isa_facts.header_block(tables, {"xed:g1": {"chip": None, "isa_sets": None},
                                             "xed:baseline": {"chip": "P4PRESCOTT_NOLAHF", "isa_sets": ["I86"]},
                                             "xed:all": {"chip": "ALL", "isa_sets": ["I86", "AVX"]}})
    functions = {fid: {"status": dict(status or {k: "checked" for k in isa_facts.KINDS}), "rows": rows}
                 for fid, rows in rows_by_function.items()}
    return {"header": header, "functions": functions}


def _ev2(functions, rows_by_function, status=None):
    import evidence

    premises = ["decoder-matches-cpu", "stock-ghidra-translator"]
    return evidence.build(bundle=dict(EV_BUNDLE), producer=dict(EV_PRODUCER),
                          mapping={"format": "pe", "mapping_id": "p" * 64}, premises=premises,
                          table_applied=True, global_reason=None, functions=functions,
                          isa=_isa_block(rows_by_function, status))


def test_isa_step3_evidence2_reader_rules():
    import isa_facts

    rows = [(1, 0x1000), (1, 0x1003), (1, 0x1007), (1, 0x100a)]
    confirmed = {r: _ev_confirmed() for r in rows[:3]}
    confirmed[rows[3]] = {"*": "unobserved"}
    functions = [_ev_function("f0", rows, confirmed)]
    call = {"basis": "cited:CALL_NEAR", "facts": {"F3": {"rel32_is_zero": False}}, "unobserved": {}}
    unclassified = {"basis": "unclassified", "facts": {}, "unobserved": {"F2": "no table basis"}}
    document = _ev2(functions, {"f0": {(1, 0x1000): call, (1, 0x1003): unclassified}})
    assert document["schema"] == "g1-decode-evidence-2"
    ev = _ev_accept(document, _ev_view(functions))
    names = isa_facts.premise_names(document["isa_facts"])
    held = {names["detection"]["F6"], names["detection"]["F2"]}
    assert ev.isa("f0", 1, 0x1000, "F3", held)["state"] == "fact"
    got = ev.isa("f0", 1, 0x1000, "F6", held)
    assert (got["state"], got["basis"], got["premises"]) == ("negative", "cited:CALL_NEAR", [names["detection"]["F6"]])
    assert ev.isa("f0", 1, 0x1000, "F6", set())["state"] == "unobserved"                 # no premise
    assert ev.isa("f0", 1, 0x1003, "F2", held)["state"] == "unobserved"                  # marker
    assert ev.isa("f0", 1, 0x1003, "F6", held)["state"] == "unobserved"                  # no table basis
    omitted = ev.isa("f0", 1, 0x1007, "F2", held)                                       # ordinary:plain row
    assert omitted["state"] == "unobserved" and names["ordinary"] in omitted["reason"]
    assert ev.isa("f0", 1, 0x1007, "F2", held | {names["ordinary"]})["state"] == "negative"
    assert ev.isa("f0", 1, 0x100a, "F2", held | {names["ordinary"]})["state"] == "unobserved"   # never compared
    wrong = names["detection"]["F6"].rsplit(":", 1)[0] + ":" + "0" * 64                    # digest mismatch, same K
    assert ev.isa("f0", 1, 0x1000, "F6", {wrong})["state"] == "unobserved"
    not_run = _ev2(functions, {"f0": {}}, status={k: "not_run" for k in isa_facts.KINDS})
    ev = _ev_accept(not_run, _ev_view(functions))
    assert ev.isa("f0", 1, 0x1007, "F2", held | {names["ordinary"]})["state"] == "unobserved"


@pytest.mark.parametrize("name", ["outside", "duplicate", "unsorted", "unknown kind", "never compared", "status",
                                  "missing section", "header kinds"])
def test_isa_step3_evidence2_rejections(name):
    import evidence

    rows = [(1, 0x1000), (1, 0x1003), (1, 0x100a)]
    states = {(1, 0x1000): _ev_confirmed(), (1, 0x1003): _ev_confirmed(), (1, 0x100a): {"*": "unobserved"}}
    functions = [_ev_function("f0", rows, states)]
    row = {"basis": "cited:RDTSC", "facts": {"F2": {}}, "unobserved": {}}
    document = _ev2(functions, {"f0": {(1, 0x1000): row, (1, 0x1003): row}})
    listed = document["functions"][0]["isa_facts"]["rows"]
    if name == "outside":
        listed[0]["offset"] = "2000"
    elif name == "duplicate":
        listed.append(dict(listed[0]))
    elif name == "unsorted":
        listed.reverse()
    elif name == "unknown kind":
        listed[0]["facts"]["F9"] = {}
    elif name == "never compared":
        listed.append(dict(listed[0], offset="100a"))
    elif name == "status":
        document["functions"][0]["isa_facts"]["status"]["F1"] = "done"
    elif name == "missing section":
        del document["functions"][0]["isa_facts"]
    else:
        document["isa_facts"]["kinds"] = ["F1"]
    with pytest.raises(evidence.Rejected):
        _ev_accept(document, _ev_view(functions))


@needs
def test_isa_step3_end_to_end_evidence2_on_a_synthetic_bundle(tmp_path):
    """decode_check --isa-facts on the 66 E8 pair writes schema -2, accepted by the reference reader."""
    import json

    import _sealed as s
    import decode_check
    import evidence
    import isa_facts

    functions, code = _pair(s)
    (tmp_path / "b").mkdir()
    generation = _bundle(tmp_path / "b", functions, code)
    path = tmp_path / "evidence2.json"
    decode_check.run(generation, s.NAMING_SOURCE, True, full=True, evidence_out=path, isa_facts=True)
    document = evidence.parse(path.read_bytes())
    assert document["schema"] == "g1-decode-evidence-2"
    facts = decode_check.collect(generation, s.NAMING_SOURCE)
    manifest = json.loads((generation / "manifest.json").read_bytes())
    members = {row["id"]: row for row in manifest["members"]}
    seal = json.loads((generation / "seal.json").read_bytes())
    view = {"generation_id": seal["generation_id"], "manifest_sha256": seal["manifest_sha256"],
            "original_sha256": members["original"]["sha256"],
            "functions": {row["id"]: {"observation_sha256": members[row["observation_member"]]["sha256"],
                                      "rows": set(), "kept": True} for row in manifest["functions"]}}
    for function in facts["functions"]:
        view["functions"][function["function_id"]]["rows"] = {(r["space"], r["address"]) for r in function["rows"]}
    import isa_tables

    ev = evidence.accept(document, view, [evidence.allowlist_entry(document)], tables=isa_tables.load())
    assert all(item["isa_facts"]["status"] == {k: "checked" for k in isa_facts.KINDS} for item in document["functions"])
    call = ev.isa("function-000000", 1, CODE, "F6", set())
    assert call["state"] == "unobserved"                                   # cited CALL_NEAR, premise not held
    names = isa_facts.premise_names(document["isa_facts"])
    assert ev.isa("function-000000", 1, CODE, "F6", {names["detection"]["F6"]})["state"] == "negative"


@needs
def test_isa_step3_iced_rip_relative_memory_is_complete():
    """iced resolves RIP / EIP-relative operands to absolute addresses (no base): still the explicit access."""
    for hexbytes in ("488B3D33711A00", "0F100598CC1A00", "FF25EAFC0700", "67488B0533221100"):
        iced = _votes(hexbytes)["iced"].extra
        assert iced["memory_complete"] is True and [m["role"] for m in iced["memory"]] == ["explicit"], hexbytes
    for hexbytes in ("0F18441140", "0F1800"):                       # PREFETCHh: an operand that accesses nothing
        iced = _votes(hexbytes)["iced"].extra
        assert iced["memory_complete"] is True and iced["memory"] == [], hexbytes


# -- ISA facts step 3: review round 1 fixes ----------------------------------------------------------------------

def test_isa_step3r1_reader_merges_table_facts():
    """review r1 P1 (Astra / Fable): a basis whose table lists K is a fact, never a negative."""
    import isa_facts

    rows = [(1, 0x1000 + 4 * i) for i in range(7)]
    functions = [_ev_function("f0", rows, {r: _ev_confirmed() for r in rows})]
    bases = ["cited:RDTSC", "cited:WRGSBASE", "cited:POP_FS", "cited:WRMSR", "ordinary:sse_fp", "split:tzcnt-bsf"]
    listed = {rows[i]: {"basis": basis, "facts": {}, "unobserved": {}} for i, basis in enumerate(bases)}
    document = _ev2(functions, {"f0": listed})
    ev = _ev_accept(document, _ev_view(functions))
    names = isa_facts.premise_names(document["isa_facts"])
    held = set(names["detection"].values()) | {names["ordinary"]}
    rdtsc = ev.isa("f0", *rows[0], "F6", held)
    assert rdtsc["state"] == "fact" and rdtsc["table"]["f6"][0]["output"] == "EDX:EAX"
    assert ev.isa("f0", *rows[1], "F7", held)["table"]["f7"]["writes_base"] == ["gs"]
    assert ev.isa("f0", *rows[2], "F7", held)["table"]["f7"]["writes_base"] == ["fs"]
    wrmsr = ev.isa("f0", *rows[3], "F7", held)["table"]["f7"]
    assert "ECX unknown" in wrmsr["when"]
    sse = ev.isa("f0", *rows[4], "F2", held)
    assert sse["state"] == "fact" and "CR4.OSFXSR=1" in str(sse["table"]["class_conditions"])
    split = ev.isa("f0", *rows[5], "F6", held)
    assert split["state"] == "fact" and "fallback.undefined_outputs" in split["table"]   # BSF fallback
    plain = ev.isa("f0", *rows[6], "F2", held)                                           # omitted row
    assert plain["state"] == "negative" and plain["basis"] == "ordinary:plain"
    assert "#GP non-canonical" in plain["out_of_scope"]
    other = _ev_accept(document, _ev_view(functions))
    other.tables = None                                                                  # tables not pinned
    assert other.isa("f0", *rows[0], "F6", held)["state"] == "unobserved"


def test_isa_step3r1_status_and_never_compared_rows():
    import isa_facts

    rows = [(1, 0x1000), (1, 0x1004)]
    functions = [_ev_function("f0", rows, {rows[0]: _ev_confirmed(), rows[1]: {"*": "unobserved"}})]
    fact = {"basis": "cited:RDTSC", "facts": {"F2": {"ring0_candidate": False}}, "unobserved": {}}
    document = _ev2(functions, {"f0": {rows[0]: fact}}, status={k: "failed:x" for k in isa_facts.KINDS})
    ev = _ev_accept(document, _ev_view(functions))
    names = isa_facts.premise_names(document["isa_facts"])
    held = set(names["detection"].values()) | {names["ordinary"]}
    assert ev.isa("f0", *rows[0], "F2", held)["state"] == "unobserved"                  # failed status wins
    assert ev.isa("f0", *rows[1], "F2", held)["state"] == "unobserved"                  # never compared


@pytest.mark.parametrize("name", ["rows dict", "unknown basis key", "unknown class", "keys on cited", "omitted basis"])
def test_isa_step3r1_more_rejections(name):
    import evidence

    rows = [(1, 0x1000)]
    functions = [_ev_function("f0", rows, {rows[0]: _ev_confirmed()})]
    document = _ev2(functions, {"f0": {rows[0]: {"basis": "cited:RDTSC", "facts": {}, "unobserved": {}}}})
    section = document["functions"][0]["isa_facts"]
    if name == "rows dict":
        section["rows"] = {}
    elif name == "unknown basis key":
        section["rows"][0]["basis"] = "cited:DOES_NOT_EXIST"
    elif name == "unknown class":
        section["rows"][0]["basis"] = "ordinary:sse"
    elif name == "keys on cited":
        section["rows"][0]["keys"] = {"xed": "RDTSC"}
    else:
        document["isa_facts"]["omitted_row_basis"] = "ordinary:sse_int"
    with pytest.raises(evidence.Rejected):
        _ev_accept(document, _ev_view(functions))


@needs
def test_isa_step3r1_encoding_discriminators():
    """review r1 P1-2: access width, CALL rel32 zero, NOTRACK, BND from the verified encoding."""
    assert _row_facts("EC")["facts"]["F2"]["access_width"] == 1
    assert _row_facts("ED")["facts"]["F2"]["access_width"] == 4
    assert _row_facts("66ED")["facts"]["F2"]["access_width"] == 2
    assert _row_facts("6D")["facts"]["F2"]["access_width"] == 4
    assert _row_facts("E800000000")["facts"]["F3"]["rel32_is_zero"] is True
    assert _row_facts("E810000000")["facts"]["F3"]["rel32_is_zero"] is False
    assert _row_facts("3EFFD0")["facts"]["F3"]["notrack_prefix"] is True
    assert "NOTRACK" in _row_facts("643EFFD0")["unobserved"]["F3"]              # (r2: order-dependent pair)
    assert _row_facts("FFD0")["facts"]["F3"]["notrack_prefix"] is False
    assert _row_facts("F2E800000000")["facts"]["F4"]["bnd_prefix"] is True
    assert _row_facts("E800000000")["facts"]["F4"]["bnd_prefix"] is False


@needs
def test_isa_step3r1_profile_failures_and_mode_agreement():
    import dataclasses

    import decoders as d
    import isa_facts
    import isa_tables

    tables = isa_tables.load()
    data = bytes.fromhex("0F01EE") + ISA_PAD                         # RDPKRU
    ballot = d.ballot(data, CODE)

    def profile_short(name, window):
        vote = d.decode_profile(name, window, CODE)
        return dataclasses.replace(vote, status="no_more_data") if name == "xed:baseline" else vote

    row = isa_facts.row_facts(tables, ballot, data, redecode=lambda w: d.xed_redecode(w, CODE),
                              decode_profile=profile_short, decode_without=lambda s, w: d.decode_without(s, w, CODE))
    assert "F1" in row["unobserved"] and row["facts"]["F1"].get("class") is None     # never invalid_for_chip
    assert row["unobserved"]["F4"] == row["unobserved"]["F1"]                          # (r2: nor a split decision)
    amd = list(ballot["amd"])
    one_off = dict(ballot, amd=(dataclasses.replace(amd[0], length=amd[0].length + 1), amd[1]))
    differences, why = isa_facts._f5(one_off)                        # only AMD iced changes: undecided
    assert differences is None and "length" in why
    assert isa_facts._f5(ballot) == (None, None)                      # agreement, no difference
    both = dict(ballot, amd=tuple(dataclasses.replace(v, operand_bits=16) for v in amd))
    differences, why = isa_facts._f5(both)                            # every reporting decoder changes it
    assert why is None and differences["operand_bits"]["zydis"]["amd"] == 16
    byte = _votes("A801")                                             # TEST AL, 1: Zydis 8, XED 32, iced 0
    import decoders as d

    assert isa_facts._f5(d.ballot(bytes.fromhex("A801") + ISA_PAD, CODE)) == (None, None)
    assert {v.operand_bits for v in byte.values()} != {byte["xed"].operand_bits}


@needs
def test_isa_step3r1_f7_compares_conditions_and_roles():
    import dataclasses

    import isa_facts
    import isa_tables

    tables = isa_tables.load()
    votes = _votes("64F3A4")
    zydis = votes["zydis"]
    memory = [dict(m, cond_read=False, cond_write=True) if m["segment"] == "fs" else m for m in zydis.extra["memory"]]
    broken = dict(votes, zydis=dataclasses.replace(zydis, extra=dict(zydis.extra, memory=memory)))
    assert isa_facts._f7(tables, broken)[1] == "voters disagree on the FS / GS accesses"


def test_isa_step3r1_checked_is_verified_against_the_rows():
    """review r1 P2-1: a G1-compared row the collector never processed fails the function's status."""
    import decode_check
    import isa_facts

    collector = decode_check.IsaCollector.__new__(decode_check.IsaCollector)
    import isa_tables

    collector.tables = isa_tables.load()
    collector.functions = {"f0": {"status": {k: "checked" for k in isa_facts.KINDS},
                                  "rows": {(1, 0x1000): {"basis": "ordinary:plain", "facts": {}, "unobserved": {}}}}}
    facts = {"functions": [{"function_id": "f0", "rows": [{"space": 1, "address": 0x1000},
                                                          {"space": 1, "address": 0x1004}]}]}
    states = {("f0", 1, 0x1000): {"+": frozenset()}, ("f0", 1, 0x1004): {"+": frozenset()}}
    collector.functions["f0"]["status"] = {k: "checked" for k in isa_facts.KINDS}
    import decoders

    original = decoders.profile_catalogue
    decoders.profile_catalogue = lambda: {}
    try:
        block = collector.block(facts, states)
    finally:
        decoders.profile_catalogue = original
    assert set(block["functions"]["f0"]["status"].values()) == {"failed:row-set-mismatch"}


# -- ISA facts step 3: review round 2 fixes ----------------------------------------------------------------------

def _r2_reader(listed_rows, tables=None):
    import isa_facts

    rows = sorted(listed_rows)
    functions = [_ev_function("f0", rows, {r: _ev_confirmed() for r in rows})]
    document = _ev2(functions, {"f0": listed_rows})
    names = isa_facts.premise_names(document["isa_facts"])
    held = set(names["detection"].values()) | {names["ordinary"]}
    return document, functions, held


def test_isa_step3r2_reader_uses_the_rows_split_and_class_flags():
    """r2 Astra P1-3 / Fable P1: a split the row identified, the row's class flags, class f5, unverified notes."""
    split = {"source": "split_table", "split": "tzcnt-bsf", "baseline": "BSF", "all": "TZCNT"}
    listed = {(1, 0x1000): {"basis": "cited:TZCNT", "facts": {"F4": {"split": split}}, "unobserved": {}},
              (1, 0x1004): {"basis": "ordinary:sse_fp", "unobserved": {},
                            "facts": {"class_flags": {"mxcsr_inputs": ["RC", "DAZ", "FTZ"], "alignment": True,
                                                      "simd_fp_exceptions": True, "writes_mxcsr_status": True}}},
              (1, 0x1008): {"basis": "ordinary:fxsave", "facts": {}, "unobserved": {}},
              (1, 0x100c): {"basis": "ordinary:fxrstor", "facts": {}, "unobserved": {}},
              (1, 0x1010): {"basis": "cited:CLI", "facts": {}, "unobserved": {}},
              (1, 0x1014): {"basis": "cited:SYSENTER", "facts": {}, "unobserved": {}}}
    document, functions, held = _r2_reader(listed)
    ev = _ev_accept(document, _ev_view(functions))
    tz = ev.isa("f0", 1, 0x1000, "F6", held)
    assert tz["state"] == "fact" and "split.fallback.undefined_outputs" in tz["table"]
    sse = ev.isa("f0", 1, 0x1004, "F6", held)
    assert sse["state"] == "fact" and sse["table"]["class_flags.mxcsr_inputs"] == ["RC", "DAZ", "FTZ"]
    assert sse["class_flags"]["alignment"] is True
    assert any(item.startswith("alignment") for item in sse["out_of_scope"])
    assert ev.isa("f0", 1, 0x1004, "F3", held)["table"]["class_flags.writes_mxcsr_status"] is True
    for offset in (0x1008, 0x100c):
        f5 = ev.isa("f0", 1, offset, "F5", held)
        assert f5["state"] == "fact" and f5["table"]["class_f5"][1]["condition"].endswith("EFER.FFXSR=1")
    cli = ev.isa("f0", 1, 0x1010, "F5", held)
    assert cli["state"] == "unobserved" and cli["reason"].startswith("table: AMD long-mode PVI")
    assert ev.isa("f0", 1, 0x1014, "F5", held)["table"]["f5"] == {"amd": "#UD in long mode"}


def test_isa_step3r2_reader_returns_copies_of_the_pinned_tables():
    """r2 Astra P2-3: mutating a reader result never changes a later answer."""
    document, functions, held = _r2_reader({(1, 0x1000): {"basis": "cited:RDTSC", "facts": {}, "unobserved": {}}})
    ev = _ev_accept(document, _ev_view(functions))
    first = ev.isa("f0", 1, 0x1000, "F6", held)
    first["table"]["f6"].clear()
    assert ev.isa("f0", 1, 0x1000, "F6", held)["state"] == "fact"
    assert ev.isa("f0", 1, 0x1000, "F6", held)["table"]["f6"]


def test_isa_step3r2_accept_pins_tables_and_checks_the_header_first():
    """r2 Astra P2-1 / Fable P2-1: the default path loads the pinned tables; other tables skip the key check and
    every read is unobserved; the header is checked before the rows."""
    import dataclasses

    import evidence
    import isa_tables

    listed = {(1, 0x1000): {"basis": "cited:RDTSC", "facts": {}, "unobserved": {}}}
    document, functions, held = _r2_reader(listed)
    view = _ev_view(functions)
    allow = [evidence.allowlist_entry(document)]
    ev = evidence.accept(document, view, allow)                                   # tables omitted
    assert ev.isa("f0", 1, 0x1000, "F6", held)["state"] == "fact"
    document["functions"][0]["isa_facts"]["rows"][0]["basis"] = "cited:DOES_NOT_EXIST"
    with pytest.raises(evidence.Rejected):
        evidence.accept(document, view, allow)
    tables = isa_tables.load()
    other = dataclasses.replace(tables, digests=dict(tables.digests, map="0" * 64))   # digest-only difference
    ev = evidence.accept(document, view, allow, tables=other)
    assert "digest mismatch" in ev.isa("f0", 1, 0x1000, "F6", held)["reason"]
    document["isa_facts"]["kinds"] = ["F1"]
    document["functions"][0]["isa_facts"]["rows"] = {}                           # the header is reported first
    with pytest.raises(evidence.Rejected, match="isa_facts schema / kinds"):
        evidence.accept(document, view, allow)


@pytest.mark.parametrize("name", ["partial no keys", "keys int", "keys unknown entry", "partial all found",
                                  "disagree one entry", "keys missing voter", "listed never compared"])
def test_isa_step3r2_keys_and_never_compared_rejections(name):
    import evidence

    rows = [(1, 0x1000), (1, 0x1004)]
    functions = [_ev_function("f0", rows, {rows[0]: _ev_confirmed(), rows[1]: {"*": "unobserved"}})]
    row = {"basis": "partial", "facts": {}, "unobserved": {}, "keys": {"iced": "RDTSC", "zydis": None, "xed": None}}
    document = _ev2(functions, {"f0": {rows[0]: row}})
    _ev_accept(document, _ev_view(functions))                                     # the well-formed file passes
    listed = document["functions"][0]["isa_facts"]["rows"]
    if name == "partial no keys":
        del listed[0]["keys"]
    elif name == "keys int":
        listed[0]["keys"]["iced"] = 7
    elif name == "keys unknown entry":
        listed[0]["keys"]["iced"] = "NOT_AN_ENTRY"
    elif name == "partial all found":
        listed[0]["keys"] = {"iced": "RDTSC", "zydis": "RDTSC", "xed": "RDTSC"}
    elif name == "disagree one entry":
        listed[0].update(basis="disagree", keys={"iced": "RDTSC", "zydis": "RDTSC", "xed": "RDTSC"})
    elif name == "keys missing voter":
        del listed[0]["keys"]["xed"]
    else:
        listed.append({"space": 1, "offset": "1004", "basis": "cited:RDTSC", "facts": {}, "unobserved": {}})
    with pytest.raises(evidence.Rejected):
        _ev_accept(document, _ev_view(functions))


@needs
def test_isa_step3r2_port_io_width_bnd_and_notrack_follow_the_effective_prefixes():
    """r2 Astra P1-5: REX only immediately before the opcode; widths confirmed by every voter; F2+F3 / 3E+segment
    left unobserved."""
    assert _row_facts("6648ED")["facts"]["F2"]["access_width"] == 4                   # in eax, dx
    assert _row_facts("4866ED")["facts"]["F2"]["access_width"] == 2                   # in ax, dx (REX ignored)
    assert _row_facts("48ED")["facts"]["F2"]["access_width"] == 4
    assert _row_facts("66E5FF")["facts"]["F2"]["access_width"] == 2
    assert _row_facts("486D")["facts"]["F2"]["access_width"] == 4                     # INSD: fixed
    for hexbytes in ("F2F3E800000000", "F3F2E800000000"):
        row = _row_facts(hexbytes)
        assert "BND" in row["unobserved"]["F4"] and "bnd_prefix" not in row["facts"].get("F4", {}), hexbytes
    assert "NOTRACK" in _row_facts("2E3EFFD0")["unobserved"]["F3"]
    assert _row_facts("2EFFD0")["facts"]["F3"]["notrack_prefix"] is False


@needs
def test_isa_step3r2_port_io_width_disagreeing_voter_is_unobserved():
    import dataclasses

    import decoders as d
    import isa_facts
    import isa_tables

    data = bytes.fromhex("66ED") + ISA_PAD
    ballot = d.ballot(data, CODE)
    intel = list(ballot["intel"])
    intel[0] = dataclasses.replace(intel[0], operand_bits=32)
    row = isa_facts.row_facts(isa_tables.load(), dict(ballot, intel=tuple(intel)), data,
                              redecode=lambda w: d.xed_redecode(w, CODE),
                              decode_profile=lambda n, w: d.decode_profile(n, w, CODE),
                              decode_without=lambda s, w: d.decode_without(s, w, CODE))
    assert "port-I/O width" in row["unobserved"]["F2"]


@needs
def test_isa_step3r2_voter_features_kept_without_a_table_f4():
    """r2 Astra P1-4: SYSENTER (no table f4) keeps the voters' features."""
    sysenter = _row_facts("0F34")
    assert sysenter["basis"] == "cited:SYSENTER"
    assert set(sysenter["facts"]["F4"]["features"]) == {"iced", "zydis", "xed"}
    assert sysenter["facts"]["F4"]["features"]["xed"]


@needs
def test_isa_step3r2_f5_compares_values_reported_in_both_modes():
    """r2 Astra P1-2: a width reported in one mode only, or a failed decode's defaults, is no difference."""
    import dataclasses

    import decoders as d
    import isa_facts

    ballot = d.ballot(bytes.fromhex("0F01EE") + ISA_PAD, CODE)
    intel, amd = list(ballot["intel"]), list(ballot["amd"])
    intel[0] = dataclasses.replace(intel[0], operand_bits=0)
    amd[0] = dataclasses.replace(amd[0], operand_bits=16)                   # iced 0 -> 16 only
    assert isa_facts._f5(dict(ballot, intel=tuple(intel), amd=tuple(amd))) == (None, None)
    failed = [dataclasses.replace(v, status="invalid", length=0) for v in ballot["amd"]]
    differences, why = isa_facts._f5(dict(ballot, amd=tuple(failed)))
    assert why is None and set(differences) == {"status"}


@needs
def test_isa_step3r2_f2_without_any_cpl0_bit_is_unobserved(monkeypatch):
    """r2 Fable P2-2 (classify would already refuse missing bits as evidence problems: bypassed to reach the rule)."""
    import dataclasses

    import decoders as d
    import isa_facts
    import isa_tables

    data = bytes.fromhex("4889C8") + ISA_PAD
    ballot = d.ballot(data, CODE)
    names = {"iced": "must_be_cpl0", "zydis": "privileged_attribute", "xed": "privileged_attribute"}
    monkeypatch.setattr(isa_tables, "evidence_problems", lambda vote: [])
    intel = tuple(dataclasses.replace(v, extra=dict(v.extra, **{names[v.voter]: None})) for v in ballot["intel"])
    row = isa_facts.row_facts(isa_tables.load(), dict(ballot, intel=intel), data,
                              redecode=lambda w: d.xed_redecode(w, CODE),
                              decode_profile=lambda n, w: d.decode_profile(n, w, CODE),
                              decode_without=lambda s, w: d.decode_without(s, w, CODE))
    assert row["unobserved"]["F2"] == "no voter provided a CPL0 bit"


@needs
def test_isa_step3r2_f7_compares_the_explicit_operand_index():
    """r2 Astra P2-2."""
    import dataclasses

    import isa_facts
    import isa_tables

    votes = _votes("64488B042530000000")
    iced = votes["iced"]
    memory = [dict(m, operand_index=0) for m in iced.extra["memory"]]
    broken = dict(votes, iced=dataclasses.replace(iced, extra=dict(iced.extra, memory=memory)))
    assert isa_facts._f7(isa_tables.load(), broken)[1] == "voters disagree on the FS / GS accesses"


@needs
def test_isa_step3r2_profile_rules():
    """r2 Astra P1-1: invalid_for_chip only when the baseline rejects; the single-feature run must match length and
    flow and must have read the row."""
    import dataclasses

    import decoders as d
    import isa_facts
    import isa_tables

    tables = isa_tables.load()
    data = bytes.fromhex("4889C8") + ISA_PAD

    def g1_rejects(name, window):
        vote = d.decode_profile(name, window, CODE)
        return dataclasses.replace(vote, status="invalid") if name == "xed:g1" else vote

    row = isa_facts.row_facts(tables, d.ballot(data, CODE), data, redecode=lambda w: d.xed_redecode(w, CODE),
                              decode_profile=g1_rejects, decode_without=lambda s, w: d.decode_without(s, w, CODE))
    assert row["facts"]["F1"]["class"] == "mixed"
    no_split = dataclasses.replace(tables, splits={**tables.splits, "splits": [
        s for s in tables.splits["splits"] if s["id"] != "lzcnt-bsr"]})
    data = bytes.fromhex("F30FBDC1") + ISA_PAD

    profiles = {name: d.decode_profile(name, data, CODE) for name in ("xed:g1", "xed:baseline", "xed:all")}

    def run(without):
        return isa_facts._split(no_split, "cited:LZCNT", profiles, data, without, 4)

    split, why = run(lambda s, w: dataclasses.replace(d.decode_without(s, w, CODE), length=9))
    assert split is None and "beyond" in why
    split, why = run(lambda s, w: dataclasses.replace(d.decode_without(s, w, CODE), status="no_more_data"))
    assert split is None and "could not read" in why
    assert run(lambda s, w: dataclasses.replace(d.decode_without(s, w, CODE), flow="call"))[0]["source"] == "profiles"
    assert run(lambda s, w: d.decode_without(s, w, CODE))[0]["source"] == "single_feature_run"
    failed = dict(profiles, **{"xed:baseline": dataclasses.replace(profiles["xed:baseline"], status="error")})
    assert isa_facts._split(no_split, "cited:LZCNT", failed, data, None, 4) == (
        None, "an XED profile could not read the row")


@needs
def test_isa_step3r2_profile_split_outside_the_tables_leaves_table_kinds_unobserved(monkeypatch):
    """A cited row whose baseline profile decodes another form with no table entry: no table negative."""
    import isa_facts

    monkeypatch.setattr(isa_facts, "_split", lambda *args: (
        {"source": "profiles", "split_feature_unknown": True, "baseline": "NOP", "all": "RDTSC"}, None))
    row = _row_facts("0F31")
    assert row["basis"] == "cited:RDTSC" and row["facts"]["F4"]["split"]["source"] == "profiles"
    assert all("outside the tables" in row["unobserved"][kind] for kind in ("F2", "F2p", "F3", "F6", "F7"))
    assert "F4" not in row["unobserved"]


# -- ISA facts step 3: review round 3 fixes (Astra's final list) --------------------------------------------------

def test_isa_step3r3_f5_is_never_negative_without_a_table_basis():
    """r3 Astra P1-1: an unclassified row (e.g. FXSAVE with a 67 prefix) cannot resolve a table f5."""
    listed = {(1, 0x1000): {"basis": "unclassified", "facts": {}, "unobserved": {"F2": "no table basis"}},
              (1, 0x1004): {"basis": "ordinary:sse_int", "facts": {}, "unobserved": {}}}
    document, functions, held = _r2_reader(listed)
    import isa_facts

    ev = _ev_accept(document, _ev_view(functions))
    assert ev.isa("f0", 1, 0x1000, "F5", held)["state"] == "unobserved"
    names = isa_facts.premise_names(document["isa_facts"])
    without_rule = held - {names["ordinary"]}
    assert ev.isa("f0", 1, 0x1004, "F5", without_rule)["state"] == "unobserved"      # class f5 needs the rule
    assert ev.isa("f0", 1, 0x1004, "F5", held)["state"] == "negative"


def _r3_row(hexbytes, decode_profile=None, ballot_edit=None):
    import decoders as d
    import isa_facts
    import isa_tables

    data = bytes.fromhex(hexbytes) + ISA_PAD
    ballot = d.ballot(data, CODE)
    if ballot_edit:
        ballot = ballot_edit(ballot)
    return isa_facts.row_facts(isa_tables.load(), ballot, data, redecode=lambda w: d.xed_redecode(w, CODE),
                               decode_profile=decode_profile or (lambda n, w: d.decode_profile(n, w, CODE)),
                               decode_without=lambda s, w: d.decode_without(s, w, CODE))


@needs
def test_isa_step3r3_profile_failure_leaves_every_table_kind_unobserved():
    """r3 Astra P1-2: an undecidable profile split may hide another form's table content (BSR's undefined output)."""
    import dataclasses

    import decoders as d
    import isa_facts

    def baseline_error(name, window):
        vote = d.decode_profile(name, window, CODE)
        return dataclasses.replace(vote, status="error") if name == "xed:baseline" else vote

    for hexbytes in ("F30FBDC1", "0F31"):
        row = _r3_row(hexbytes, baseline_error)
        assert set(isa_facts.TABLE_KINDS) <= set(row["unobserved"]), (hexbytes, row["unobserved"])


@needs
def test_isa_step3r3_checked_range_is_the_verified_window():
    """r3 Astra P2-1: a profile read inside the verified window is not 'beyond the checked bytes'."""
    import dataclasses

    import decoders as d

    def longer(name, window):
        vote = d.decode_profile(name, window, CODE)
        return dataclasses.replace(vote, length=vote.length + 3) if name == "xed:all" else vote

    row = _r3_row("4889C8", longer)
    assert "beyond" not in str(row["unobserved"])


@needs
def test_isa_step3r3_features_of_the_voters_that_decoded_the_row_are_kept():
    """r3 Astra P2-2: SYSENTER with Zydis failing keeps iced / XED features (the kind itself stays unobserved)."""
    import dataclasses

    def zydis_fails(ballot):
        intel = tuple(dataclasses.replace(v, status="invalid") if v.voter == "zydis" else v for v in ballot["intel"])
        return dict(ballot, intel=intel)

    row = _r3_row("0F34", ballot_edit=zydis_fails)
    features = row["facts"]["F4"]["features"]
    assert features["zydis"] is None and features["xed"] and features["iced"]
    assert "F4" in row["unobserved"]


@pytest.mark.parametrize("name", ["F4 not an object", "split not an object", "split_table unknown id",
                                  "split_table without id", "class_flags unknown field", "class_flags type",
                                  "mxcsr_inputs item", "reason not a string"])
def test_isa_step3r3_row_shape_rejections(name):
    """r3 Astra P2-3 / Fable r3 P3-1: what the reader dereferences is checked at acceptance."""
    import evidence

    rows = [(1, 0x1000)]
    functions = [_ev_function("f0", rows, {rows[0]: _ev_confirmed()})]
    split = {"source": "split_table", "split": "lzcnt-bsr"}
    row = {"basis": "cited:LZCNT", "facts": {"F4": {"features": {}, "split": split},
                                            "class_flags": {"mxcsr_inputs": ["RC"], "alignment": False}},
           "unobserved": {}}
    document = _ev2(functions, {"f0": {rows[0]: row}})
    _ev_accept(document, _ev_view(functions))                                     # the well-formed file passes
    facts = document["functions"][0]["isa_facts"]["rows"][0]["facts"]
    if name == "F4 not an object":
        facts["F4"] = True
    elif name == "split not an object":
        facts["F4"]["split"] = "lzcnt-bsr"
    elif name == "split_table unknown id":
        facts["F4"]["split"]["split"] = "no-such-split"
    elif name == "split_table without id":
        del facts["F4"]["split"]["split"]
    elif name == "class_flags unknown field":
        facts["class_flags"]["fast"] = True
    elif name == "class_flags type":
        facts["class_flags"]["alignment"] = "yes"
    elif name == "mxcsr_inputs item":
        facts["class_flags"]["mxcsr_inputs"] = [1]
    else:
        document["functions"][0]["isa_facts"]["rows"][0]["unobserved"]["F6"] = 3
    with pytest.raises(evidence.Rejected):
        _ev_accept(document, _ev_view(functions))


# -- G1 on X-1 producer Bundles (design .census6/design_tbr_g1_x1_r1.md + r2 / r3 deltas; impl review r1) ------

NONE_REPORT = {"flow_override": "NONE", "fallthrough_overridden": False, "length_overridden": False, "references": []}


def _profile(facts, report=None, targets=(), pads=(), external=0):
    out = dict(facts)
    out.update(override=dict(NONE_REPORT, **(report or {})), flow_target_coords=sorted(targets),
               recorded_landing_pads=sorted(pads), external_flow_targets=external,
               has_call_op=any(op["opcode"] in ("CALL", "CALLIND") for op in facts["ops"]))
    return out


def _verdict(facts, data):
    import decoders
    import producer_override

    lift, result = _compare(facts, data)
    return producer_override.row_verdict(facts, result, lift, decoders.ballot(data, facts["address"]), data)


def _plain_mov():
    return _row(3, [_op("COPY", [_r(RCX_)], _r(RAX_))])


def _syscall(inputs=None, output=None, length=2):
    return _row(length, [_op("CALLOTHER", inputs or [_c(5)], output)])


def _int_pair(vector=0x2E, tail=False, length=2):
    import producer_override

    ops = [_op("CALLOTHER", [_c(16), _c(vector)], _u(0x100)), _op("CALLIND", [_u(0x100)])]
    if tail:
        ops.append(_op("RETURN", [_c(0)]))
    flow = dict(producer_override.PINNED_BITS["interrupt"], is_override=False)
    return _row(length, ops, flow=flow, fallthrough=not tail)


def _direct_call(target):
    return _row(5, _push(START + 5) + [_op("CALL", [_a(target)])], flow=_flow("call_direct"))


@needs
def test_g1x1_effect_attested_and_reported_overrides():
    """r1 s0 / s4: a NONE report with every compared attribute confirmed is effect_attested; any reported override
    (even an effect-free non-primary reference) is override_present; an unreported effect-free reference is
    invisible (effect attestation only)."""
    facts = _plain_mov()
    assert _verdict(_profile(facts), bytes.fromhex("4889c8")) == ("A", None)
    code, detail = _verdict(_profile(facts, {"flow_override": "BRANCH"}), bytes.fromhex("4889c8"))
    assert code == "O" and detail == {"kinds": ["flow:BRANCH"], "effect": {"disagree": [], "unobserved": []}}
    reference = {"references": [{"type": "CALL_OVERRIDE_UNCONDITIONAL", "primary": False, "in_index": True}]}
    code, detail = _verdict(_profile(facts, reference), bytes.fromhex("4889c8"))
    assert code == "O" and detail["kinds"] == ["reference:CALL_OVERRIDE_UNCONDITIONAL:non-primary"]
    assert detail["effect"] == {"disagree": [], "unobserved": []}                  # (empty effect still blocks S3)
    import producer_override

    assert producer_override.row_verdict(facts, None, None, None) is None        # (no report: not a profile row)


@needs
def test_g1x1_exact_syscall_and_interrupt_pins():
    """r2 s3 / r3 s3, impl r1 Astra P1-2: exact shapes bound to the verified bytes; a3 exempt under the OS-contract
    model; a4 = va + length; pinned bits; a C / U / O row that used a pin carries `exempt`."""
    import lifting

    assert lifting.identify(_syscall()).pattern == "syscall"
    assert _verdict(_profile(_syscall()), bytes.fromhex("0f05")) == ("S", None)
    assert lifting.identify(_int_pair()).pattern == "interrupt"
    assert _verdict(_profile(_int_pair()), bytes.fromhex("cd2e")) == ("I", None)
    assert _verdict(_profile(_int_pair(0x29)), bytes.fromhex("cd29")) == ("I", None)
    rex = _verdict(_profile(_syscall(length=3)), bytes.fromhex("480f05"))          # (48 0F 05: no pin)
    assert rex[0] == "U" and "a3" in rex[1]["unobserved"] and "exempt" not in rex[1]
    int3 = _verdict(_profile(_int_pair(3, length=1)), bytes.fromhex("cc"))          # (CC with a swi(3) pair: no pin)
    assert int3[0] != "I" and "exempt" not in (int3[1] or {})
    wrong_vector = _verdict(_profile(_int_pair(0x2E)), bytes.fromhex("cd29"))
    assert wrong_vector[0] != "I"
    tail = _int_pair(3, tail=True)                                       # (int3 lifts with a trailing RETURN)
    assert lifting.identify(tail).pattern == "interrupt-return"
    code, detail = _verdict(_profile(tail), bytes.fromhex("cd03"))
    assert code == "U" and "a3" in detail["unobserved"]                  # (no exemption outside the exact shape)
    lone = _row(2, [_op("CALLOTHER", [_c(16), _c(0x2E)], _u(0x100))])  # (a lone swi: no CALLIND)
    assert lifting.identify(lone).pattern == "userop"
    assert _verdict(_profile(lone), bytes.fromhex("cd2e"))[0] == "U"
    output = _syscall(output=_u(0x10))
    assert lifting.identify(output).pattern == "userop"
    assert _verdict(_profile(output), bytes.fromhex("0f05"))[0] == "U"
    variable = _syscall(inputs=[_c(5), _r(RAX_)])
    assert _verdict(_profile(variable), bytes.fromhex("0f05"))[0] == "U"
    wrong_bits = _syscall()
    wrong_bits["flow"] = _flow("call_direct")
    code, detail = _verdict(_profile(wrong_bits), bytes.fromhex("0f05"))
    assert code == "C" and "F.is_call" in detail["disagree"] and detail["exempt"] == "S"
    elsewhere = _syscall()
    elsewhere["fallthrough"] = START + 3
    assert "a4" in _verdict(_profile(elsewhere), bytes.fromhex("0f05"))[1]["disagree"]
    # CALLOTHER_OVERRIDE_CALL on a syscall: override_present is certain; the effect is only what the exported
    # p-code / bits / targets show (getPcode(false): no a6 / a8 difference assumed)
    reference = {"references": [{"type": "CALLOTHER_OVERRIDE_CALL", "primary": True, "in_index": True}]}
    code, detail = _verdict(_profile(_syscall(), reference), bytes.fromhex("0f05"))
    assert code == "O" and detail["exempt"] == "S" and detail["effect"] == {"disagree": [], "unobserved": []}


@needs
def test_g1x1_syscall_keeps_the_g1_core_result():
    """impl r1 Astra P1-4: table -8 leaves G1's own comparison of 0F 05 as before (a3 a5 a6 a8 a9 a10 unobserved),
    so the -1 / -2 exceptions do not change."""
    import dependents
    import evidence

    _, result = _compare(_syscall(), bytes.fromhex("0f05"))
    exception = evidence.exception_of(dependents.attribute_states(result))
    assert {"a3", "a5", "a6", "a8", "a9", "a10"} <= set(exception)
    assert all(exception[name] == "unobserved" for name in ("a5", "a6", "a8", "a9", "a10"))


@needs
def test_g1x1_target_set_rules():
    """r2 s2 / r3 s2, impl r1 Astra P1-3: direct targets need every voter's own report (XED's is computed -> T
    unobserved); no-target E needs the pinned voter form; non-call rows compare the raw set; call rows with pads
    are unobserved; an external target disagrees."""
    jcc = _jcc(2, START + 0x40)
    code, detail = _verdict(_profile(jcc, targets=[(1, START + 0x40)]), bytes.fromhex("743e"))
    assert code == "U" and detail["unobserved"] == ["T"]
    call = _direct_call(START + 0x20)
    assert _verdict(_profile(call, targets=[(1, START + 0x20)]), bytes.fromhex("e81b000000"))[1]["unobserved"] == ["T"]
    plain = _plain_mov()
    data = bytes.fromhex("4889c8")
    pad = (1, START + 0x90)
    assert _verdict(_profile(plain, pads=[pad]), data) == ("A", None)
    assert _verdict(_profile(plain, targets=[pad], pads=[pad]), data)[1]["disagree"] == ["T"]   # (no subtraction)
    assert _verdict(_profile(plain, targets=[(2, START + 3)]), data)[1]["disagree"] == ["T"]
    assert _verdict(_profile(plain, external=1), data)[1]["disagree"] == ["T"]
    two_bytes = _row(2, [_op("COPY", [_r(RCX_)], _r(RAX_))])
    import decoders
    import producer_override

    lift, _ = _compare(two_bytes, bytes.fromhex("0f05"))               # (plain lift, voters: syscall form)
    state, why = producer_override.target_check(_profile(two_bytes), lift, decoders.ballot(bytes.fromhex("0f05"), START))
    assert state == "unobserved" and "not pinned for the voters' form syscall" in why
    pair = _int_pair()                                                 # (a call row: CALLIND)
    data = bytes.fromhex("cd2e")
    assert _verdict(_profile(pair), data) == ("I", None)
    code, detail = _verdict(_profile(pair, targets=[pad], pads=[pad]), data)    # ({} or {p}: not excluded)
    assert code == "U" and detail["unobserved"] == ["T"]
    assert _verdict(_profile(pair, pads=[pad]), data)[1]["disagree"] == ["T"]
    assert _verdict(_profile(pair, external=1), data)[1]["disagree"] == ["T"]


def test_g1x1_raw_state_rules():
    """r2 s4, impl r1 Astra P2-1: provenance before state; mode-constant equal -> neutral; not applicable ->
    neutral; withheld -> unobserved; an internal inconsistency disagrees only when the exported length itself
    differs from the consensus."""
    from types import SimpleNamespace

    import producer_override as po

    facts = {"address": START, "space": 1, "length": 2, "fallthrough": START + 2, "exit": None}
    exit_facts = dict(facts, fallthrough=None, exit={"target": 2})
    assert po._state("F.is_flow", {"state": "applied"}, facts, None) == "neutral"
    assert po._state("a2", {"state": "unrecognized", "kind": "cause-unknown", "provenance": "via A4"}, facts,
                     None) == "unobserved"
    assert po._state("a4", {"state": "unrecognized", "kind": "cause-unknown"}, exit_facts, None) == "unobserved"
    assert po._state("a9", {"state": "not_applicable"}, facts, None) == "neutral"
    assert po._state("a3", {"state": "withheld", "kind": "vendor"}, facts, None) == "unobserved"
    assert po._state("a3", {"state": "unrecognized", "kind": "cause-unknown"}, facts, None) == "disagree"
    voter = SimpleNamespace(status="ok", length=2)
    ballot = {"intel": [voter, voter, voter], "amd": [voter, voter]}
    inconsistency = {"state": "unrecognized", "kind": "ghidra-internal-inconsistency"}
    assert po._state("a2", inconsistency, facts, ballot) == "unobserved"            # (only the exit differs)
    assert po._state("a2", inconsistency, dict(facts, length=3), ballot) == "disagree"


ENGINE = {"package": "tdo_v2", "digest": "d" * 64, "revision": None, "dirty": None}


def _ov_document(functions, override_functions, profile="x1-producer-v1"):
    import evidence
    import producer_override

    premises = ["decoder-matches-cpu", "stock-ghidra-translator"]
    return evidence.build(bundle=dict(EV_BUNDLE), producer=dict(EV_PRODUCER),
                          mapping={"format": "pe", "mapping_id": "p" * 64}, premises=premises, table_applied=True,
                          global_reason=None, functions=functions, isa=_isa_block({}),
                          override={"header": producer_override.header_block(profile, ENGINE),
                                    "functions": override_functions})


def _ov_case(states=None):
    rows = [(1, 0x1000), (1, 0x1004), (1, 0x1008), (1, 0x100c), (1, 0x1010), (1, 0x1014)]
    states = states or {r: _ev_confirmed() for r in rows[:5]}
    states[rows[5]] = {"*": "unobserved"}
    functions = [_ev_function("f0", rows, states)]
    codes = {rows[0]: "A", rows[1]: "S", rows[2]: "C", rows[3]: "O", rows[4]: "U"}
    details = {rows[2]: {"disagree": ["T"], "exempt": "S"},
               rows[3]: {"kinds": ["length"], "effect": {"disagree": ["a2"], "unobserved": []}},
               rows[4]: {"unobserved": ["a3"]},
               rows[5]: {"star": True, "kinds": ["flow:BRANCH"], "effect": {"unobserved": ["*"]}}}
    override = {"f0": {"status": "checked", "codes": codes, "details": details}}
    return rows, functions, override


def _ov_view(functions, rows, profile="x1-producer-v1", present=None, pins=None):
    view = _ev_view(functions)
    view["producer_profile"] = profile
    reported = present if present is not None else {rows[3], rows[5]}
    pins = pins if pins is not None else {rows[1]: "S", rows[2]: "S"}
    view["functions"]["f0"]["override_report"] = None if profile is None else {
        r: {"present": r in reported, "pin": pins.get(r)} for r in rows}
    return view


def test_g1x1_evidence3_round_trip_and_reader():
    rows, functions, override = _ov_case()
    document = _ov_document(functions, override)
    assert document["schema"] == "g1-decode-evidence-3"
    assert document["functions"][0]["producer_override"]["codes"] == "ASCOU"
    ev = _ev_accept(document, _ov_view(functions, rows))
    attested = ev.override("f0", *rows[0])
    assert attested["verdict"] == "effect_attested" and attested["exemption"] is None
    assert "g1-evidence-from-allowlisted-build" in attested["premises"]
    syscall = ev.override("f0", *rows[1])
    assert syscall["exemption"]["attribute"] == "a3" and "kernel-boundary-contract" in syscall["premises"]
    contradicted = ev.override("f0", *rows[2])
    assert contradicted["verdict"] == "contradicted" and contradicted["disagree"] == ["T"]
    assert contradicted["exemption"]["pattern"] == "syscall" and "kernel-boundary-contract" in contradicted["premises"]
    assert ev.override("f0", *rows[3])["verdict"] == "override_present"
    assert ev.override("f0", *rows[4]) == {"verdict": "unobserved", "unobserved": ["a3"]}
    star = ev.override("f0", *rows[5])
    assert star["verdict"] == "override_present" and star["effect"] == {"unobserved": ["*"]}
    two = _ev2(functions, {"f0": {}})                                         # schema -2: no override section
    assert _ev_accept(two, _ev_view(functions)).override("f0", *rows[0])["verdict"] == "unobserved"
    legacy = _ov_document(functions, {"f0": {"status": "not_reported", "codes": {}, "details": {}}}, profile=None)
    assert _ev_accept(legacy, _ov_view(functions, rows, profile=None)).override("f0", *rows[0])["verdict"] == \
        "not_reported"
    ev = _ev_accept(_ov_document(functions, override), _ov_view(functions, rows))
    ev.compared = ev.compared - {"a9"}                                          # (a required comparison missing)
    assert ev.override("f0", *rows[0])["verdict"] == "unobserved"


@pytest.mark.parametrize("name", ["code dropped", "detail dropped", "T-only row deleted", "listed A detail",
                                  "unknown code", "star detail missing", "star at compared row", "C fields",
                                  "O effect keys", "codes without checked", "spec changed", "unsorted details",
                                  "header profile null", "O turned A", "A with an exception", "S with a2 exception",
                                  "view without reports", "view without profile", "unknown exempt",
                                  "S without the Bundle shape", "I turned S", "exempt dropped", "report None",
                                  "exempt list", "no functions, profile differs"])
def test_g1x1_evidence3_rejections(name):
    """r2 s5 / r3 s5 / r3 s8, impl r1 Astra P1-1 / Fable P2-1: a detail or code deleted after serialization, and any
    contradiction with the Bundle's reports or G1's own exceptions, rejects the file."""
    import evidence

    states = None
    rows = [(1, 0x1000), (1, 0x1004), (1, 0x1008), (1, 0x100c), (1, 0x1010), (1, 0x1014)]
    if name == "A with an exception":
        states = {r: _ev_confirmed() for r in rows[:5]}
        states[rows[0]] = {"a2": "withheld", "~": {"a2": "vendor"}, "+": frozenset()}
    if name == "S with a2 exception":
        states = {r: _ev_confirmed() for r in rows[:5]}
        states[rows[1]] = {"a2": "unobserved", "+": frozenset()}
    rows, functions, override = _ov_case(states)
    document = _ov_document(functions, override)
    view = _ov_view(functions, rows)
    if name not in ("A with an exception", "S with a2 exception"):
        _ev_accept(document, view)                                             # the well-formed file passes
    section = document["functions"][0]["producer_override"]
    details = section["details"]
    if name == "code dropped":
        section["codes"] = section["codes"][:-1]
    elif name == "detail dropped":
        del details[1]                                                          # (the O row's detail)
    elif name == "T-only row deleted":                                        # (the C row: code and detail)
        section["codes"] = "ASOU"
        del details[0]
    elif name == "listed A detail":
        details.insert(0, {"space": 1, "offset": "1000", "disagree": ["T"]})
    elif name == "unknown code":
        section["codes"] = "ASCOX"
    elif name == "star detail missing":
        del details[-1]
    elif name == "star at compared row":
        details[-1]["offset"] = "1000"
        details.sort(key=lambda item: int(item["offset"], 16))
    elif name == "C fields":
        details[0]["unobserved"] = ["a3"]
    elif name == "O effect keys":
        details[1]["effect"] = {"disagree": []}
    elif name == "codes without checked":
        section["status"] = "not_reported"
    elif name == "spec changed":
        document["producer_override"]["spec"]["direct_e"] = ["call"]
    elif name == "unsorted details":
        details.reverse()
    elif name == "header profile null":
        document["producer_override"]["profile"] = None
    elif name == "O turned A":
        section["codes"] = "ASCAU"
        del details[1]
    elif name == "view without reports":
        del view["functions"]["f0"]["override_report"]
    elif name == "view without profile":
        del view["producer_profile"]
    elif name == "unknown exempt":
        details[0]["exempt"] = "X"
    elif name == "S without the Bundle shape":                                # (48 0F 05 relabelled S)
        view["functions"]["f0"]["override_report"][rows[1]]["pin"] = None
    elif name == "I turned S":
        view["functions"]["f0"]["override_report"][rows[1]]["pin"] = "I"
    elif name == "exempt dropped":
        del details[0]["exempt"]
    elif name == "report None":
        view["functions"]["f0"]["override_report"][rows[3]] = None
    elif name == "exempt list":
        details[0]["exempt"] = ["S"]
    elif name == "no functions, profile differs":
        document["functions"] = []
        view["producer_profile"] = None
    with pytest.raises(evidence.Rejected):
        _ev_accept(document, view, [evidence.allowlist_entry(document)])


def test_g1x1_collector_statuses():
    """r1 s7 / r2 s5, impl r1 Astra P2-2: legacy Bundle -> not_reported; declared profile with a parser that exposes
    none -> failed:parser-without-profile; profile mismatch; a profile row without fields; a compared row without a
    code, a missing detail or a missing star detail -> failed:row-set-mismatch."""
    import decode_check

    fields = {"external_flow_targets": 0, "recorded_landing_pads": []}
    rows = [{"space": 1, "address": 0x1000, "override": dict(NONE_REPORT), **fields},
            {"space": 1, "address": 0x1004, "override": dict(NONE_REPORT), **fields},
            {"space": 1, "address": 0x1008, "override": dict(NONE_REPORT, length_overridden=True), **fields}]
    states = {("f0", 1, 0x1000): {"+": frozenset()}, ("f0", 1, 0x1004): {"+": frozenset()},
              ("f0", 1, 0x1008): {"*": "unobserved"}}
    facts = {"functions": [{"function_id": "f0", "rows": rows, "producer_profile": None}]}
    assert decode_check.OverrideCollector(None).block(facts, states, ENGINE)["functions"]["f0"]["status"] == \
        "not_reported"
    assert decode_check.OverrideCollector("x1-producer-v1").block(facts, states, ENGINE)["functions"]["f0"][
        "status"] == "failed:parser-without-profile"
    facts["functions"][0]["producer_profile"] = "x1-producer-v1"
    assert decode_check.OverrideCollector(None).block(facts, states, ENGINE)["functions"]["f0"]["status"] == \
        "failed:profile-mismatch"
    star = {"star": True, "kinds": ["length"], "effect": {"unobserved": ["*"]}}
    collector = decode_check.OverrideCollector("x1-producer-v1")
    collector.functions["f0"] = {"codes": {(1, 0x1000): "A"}, "details": {(1, 0x1008): star}, "rows": {},
                                 "error": None}
    assert collector.block(facts, states, ENGINE)["functions"]["f0"]["status"] == "failed:row-set-mismatch"
    collector.functions["f0"]["codes"][(1, 0x1004)] = "U"                       # (U without its detail)
    assert collector.block(facts, states, ENGINE)["functions"]["f0"]["status"] == "failed:row-set-mismatch"
    collector.functions["f0"]["codes"][(1, 0x1004)] = "A"
    assert collector.block(facts, states, ENGINE)["functions"]["f0"]["status"] == "checked"
    del collector.functions["f0"]["details"][(1, 0x1008)]                        # (the star callback lost)
    assert collector.block(facts, states, ENGINE)["functions"]["f0"]["status"] == "failed:row-set-mismatch"
    rows[1]["recorded_landing_pads"] = None                                     # ([] recorded vs None missing)
    assert collector.block(facts, states, ENGINE)["functions"]["f0"]["status"] == "failed:missing-row-fields"
    rows[1]["recorded_landing_pads"] = []
    rows[1]["override"] = None
    assert collector.block(facts, states, ENGINE)["functions"]["f0"]["status"] == "failed:missing-row-fields"


def test_g1x1_g3b7b_reproduces_the_exporter():
    """r1 s6 / r2 s6, impl r1 Astra P2-3: per-row inputs; a length override blocks; a fallthrough override that
    keeps address + length passes, one that misses it blocks; a flow override on a call row blocks; the
    entry-reference input is unobserved on call rows only; the result names producer-override-report."""
    import dependents

    reads = frozenset(("a1", "a2", "a3", "a4", "a5", "a8", "F.has_fallthrough"))

    def run(info, kinds, fallthrough=0x1004, call_row=False):
        row = {"space": 1, "address": 0x1002, "length": 2, "ops": [], "flow": {}, "fallthrough": fallthrough,
               "exit": None, "native_call": False}
        states = {(1, 0x1002): {"+": reads}}
        override = {"status": "checked", "codes": {(1, 0x1002): "O" if kinds else "A"}, "details": {},
                    "rows": {(1, 0x1002): {"isa_fallthrough": info, "call_row": call_row, "kinds": kinds,
                                           "consensus_length": 2}}}
        function = {"function_id": "f0", "s1": False, "rows": [row], "baseline": {}, "override": override}
        found = {item[0]: item for item in dependents.function_rows(function, states)}
        return found["g3b7b_none_estimate"]

    applied = run(True, [])
    assert applied[3] == "applied" and applied[4]["would_block"] is False
    assert applied[4]["premises"] == ["producer-override-report"]
    assert dependents.summary([applied])["g3b7b_none_estimate"]["premises"] == ["producer-override-report"]
    blocked = run(True, ["length"])
    assert blocked[4]["cause"] == "override" and "length" in blocked[4]["blocking"][0][1]
    assert run(True, ["fallthrough"])[4]["would_block"] is False                 # (keeps address + length)
    missed = run(True, ["fallthrough"], fallthrough=0x1010)
    assert missed[4]["cause"] == "override"
    call = run(True, ["flow:CALL_RETURN"], call_row=True)
    assert call[4]["cause"] == "override"
    names = [item[1] for item in call[4]["blocking"]]
    assert any("call row" in name for name in names)
    assert run(None, [])[4]["cause"] == "unobserved"                            # (undecided prototype form)
    plain_call = run(True, [], call_row=True)
    assert plain_call[4]["cause"] == "unobserved" and plain_call[4]["blocking"][0][1] == dependents.G3B7B_X1_MISSING
    assert run(True, ["reference:JUMP_OVERRIDE_UNCONDITIONAL:primary"])[4]["would_block"] is False


@needs
def test_g1x1_end_to_end_legacy_bundle_writes_schema3_not_reported(tmp_path):
    """decode_check --producer-override on a legacy synthetic Bundle: schema -3, every function not_reported,
    accepted by the reference reader with a legacy view."""
    import _sealed as s
    import decode_check
    import evidence

    functions, code = _pair(s)
    (tmp_path / "b").mkdir()
    generation = _bundle(tmp_path / "b", functions, code)
    out = tmp_path / "evidence3.json"
    decode_check.run(generation, s.NAMING_SOURCE, True, full=True, evidence_out=out, producer_override=True)
    document = evidence.parse(out.read_bytes())
    assert document["schema"] == "g1-decode-evidence-3"
    assert document["producer_override"]["profile"] is None
    assert document["producer_override"]["engine_source"]["package"] == "tdo_v2"
    assert all(item["producer_override"] == {"status": "not_reported", "codes": "", "details": []}
               for item in document["functions"])
    facts = decode_check.collect(generation, s.NAMING_SOURCE)
    import json

    manifest = json.loads((generation / "manifest.json").read_bytes())
    members = {row["id"]: row for row in manifest["members"]}
    seal = json.loads((generation / "seal.json").read_bytes())
    view = {"generation_id": seal["generation_id"], "manifest_sha256": seal["manifest_sha256"],
            "original_sha256": members["original"]["sha256"], "producer_profile": None,
            "functions": {row["id"]: {"observation_sha256": members[row["observation_member"]]["sha256"],
                                      "rows": set(), "kept": True, "override_report": None}
                          for row in manifest["functions"]}}
    for function in facts["functions"]:
        view["functions"][function["function_id"]]["rows"] = {(r["space"], r["address"]) for r in function["rows"]}
    ev = evidence.accept(document, view, [evidence.allowlist_entry(document)])
    first = facts["functions"][0]["rows"][0]
    assert ev.override(facts["functions"][0]["function_id"], first["space"], first["address"])["verdict"] == \
        "not_reported"


@needs
def test_g1x1_generated_verdicts_round_trip_through_the_reader():
    """impl r2 Astra P3: verdicts the judge generated (I for CD 29, U with `exempt` when the voters do not agree)
    serialize and read back against the Bundle-side shape."""
    import dataclasses

    import decoders
    import producer_override

    pair = _profile(_int_pair(0x29))
    data = bytes.fromhex("cd29")
    lift, result = _compare(pair, data)
    ballot = decoders.ballot(data, START)
    code, detail = producer_override.row_verdict(pair, result, lift, ballot, data)
    assert (code, detail) == ("I", None)
    assert producer_override.shape_code(pair, lift, data) == "I"
    split = dict(ballot, amd=tuple(dataclasses.replace(v, int_vector=0x2A) for v in ballot["amd"]))
    code2, detail2 = producer_override.row_verdict(pair, result, lift, split, data)
    assert code2 == "U" and detail2["exempt"] == "I"                    # (shape kept, pinned values unobserved)
    rows = [(1, 0x1000), (1, 0x1004)]
    functions = [_ev_function("f0", rows, {r: _ev_confirmed() for r in rows})]
    override = {"f0": {"status": "checked", "codes": {rows[0]: code, rows[1]: code2},
                       "details": {rows[1]: detail2}}}
    document = _ov_document(functions, override)
    view = _ev_view(functions)
    view["producer_profile"] = "x1-producer-v1"
    view["functions"]["f0"]["override_report"] = {r: {"present": False, "pin": "I"} for r in rows}
    ev = _ev_accept(document, view)
    first = ev.override("f0", *rows[0])
    assert first["verdict"] == "effect_attested" and first["exemption"]["pattern"] == "interrupt"
    second = ev.override("f0", *rows[1])
    assert second["verdict"] == "unobserved" and "kernel-boundary-contract" in second["premises"]


# -- G2a: common facts derived from Ghidra p-code -----------------------------------------------

def _g2_fields(units):
    import common_facts as cf

    return {(u["path"], cf.triple(u["edge"]) if "edge" in u else None,
             (u["op"]["ordinal"], u["op"]["opcode"]) if "op" in u else None): u["code"] for u in units}


def _g2_code(units, path, edge=None):
    return _g2_fields(units).get((path, edge, None))


def _g2_collect(entries, isa="x86-64", regs=None):
    import decode_check

    facts = dict(registers=regs or {}, functions=[])
    c = decode_check.CommonFactsCollector(facts)
    for fid, f, lift, ballot, result, data in entries:
        c(fid, dict(f, isa=isa), result, lift, ballot, data)
    c.finish(True)
    return c


def _g2_golden():
    import json
    import decoders
    import lifting

    doc = json.loads((REPO / "tests/intra/golden/decode_check_pair_66e8.json").read_bytes())
    detail = next(r["detail"] for r in doc["rows"]
                  if r["detail"].get("window", {}).get("hex", "").startswith("66e8"))
    ballot = {v: tuple(decoders.Decoded(**d) for d in ds) for v, ds in detail["votes"].items()}
    data = bytes.fromhex(detail["window"]["hex"])
    f = _row(6, _push(START + 6) + [_op("CALL", [_a(START + 0x10)])], flow=_flow("call_direct"))
    return "f0", f, lifting.identify(f), ballot, detail, data


def _g2_live(f, hexbytes, fid="f0"):
    import decoders

    data = (bytes.fromhex(hexbytes) + ISA_PAD)[:15]
    lift, result = _compare(f, data)
    return fid, f, lift, decoders.ballot(data, f["address"]), result, data


def _g2_document(c):
    import common_facts as cf

    return cf.document({k: EV_BUNDLE[k] for k in ("generation_id", "manifest_sha256")},
                       {"name": "fixture"}, {"isa": "x86-64"}, list(c.rows.values()))


def _g2_binding(c):
    import common_facts as cf
    import evidence

    doc = _g2_document(c)
    block = cf.verdict_block(doc, c.units)
    coordinates = {}
    for (_, fid), f in c.raw.items():
        coordinates.setdefault(fid, set()).add((f["space"], f["address"]))
    functions = [_ev_function(fid, sorted(cs), {xy: _ev_confirmed() for xy in cs})
                 for fid, cs in coordinates.items()]
    ev = _ov_document(functions, {}, profile=None)
    ev.update(schema=evidence.SCHEMA4, common_facts=block)
    view = _ev_view(functions)
    view["producer_profile"] = None
    for fn in view["functions"].values():
        fn["override_report"] = None
    args = dict(bundle=view, allowlist=[evidence.allowlist_entry(ev)], observations=c.raw)
    return doc, ev, args


def _g2_binding5(c):
    import common_facts as cf
    import evidence

    doc, ev, args = _g2_binding(c)
    block = cf.verdict_block5(doc, cf.digest(doc), c.unit_sets, c.row_set)
    ev5 = dict(ev, schema=evidence.SCHEMA5, common_facts=block)
    args = dict(args, allowlist=[evidence.allowlist_entry(ev5)])
    return doc, ev5, args


def test_g2a_required_vendor():
    from copy import deepcopy

    import common_facts as cf

    entry = _g2_golden()
    c = _g2_collect([entry])
    k, r = next(iter(c.rows.items()))
    for v, n, width, stored in (("intel", 6, 64, START + 6), ("amd", 4, 16, 0x1004)):
        p = "vendor_views." + v + "."
        m = r["vendor_views"][v]
        assert m["length"] == n and m["bytes"] == [f"{START:x}", f"{START+n:x}"]
        assert [cf.triple(e) for e in m["edges"]] == [cf.DIRECT]
        assert "lands_on" in m["edges"][0]
        link = m["link_write"]
        assert link["continuation"] == cf.addr(1, START + n)
        assert link["value"] == {"width": width, "bits": f"{stored:x}"}
        assert link["location"]["memory"]["slot_offset"] == link["sp_delta"] == -(width // 8)
        for field in ("length", "bytes", "link_write.value.width", "link_write.value.bits", "link_write.continuation",
                      "link_write.location.memory.slot_offset", "link_write.sp_delta"):
            assert _g2_code(c.units[k], p + field) == "c", field
        assert _g2_code(c.units[k], p + "edges.to", cf.DIRECT) == "u"
    changed = deepcopy(r)
    changed["vendor_views"]["amd"]["link_write"]["continuation"] = cf.addr(1, 0x1004)
    for v, expected in (("intel", "c"), ("amd", "x")):
        units = cf.row_verdicts(changed, cf.votes(entry[3], entry[4], v), cf.Index([], True), {}, v)
        assert _g2_code(units, f"vendor_views.{v}.link_write.continuation") == expected
    assert not cf.votes(entry[3], dict(entry[4], attributes={}), "amd")


@needs
def test_g2a_required_xbegin():
    from copy import deepcopy

    import common_facts as cf

    entry = _g2_live(_row(6, [_op("CALLOTHER", [_c(85)])]), "c7f810000000")
    c = _g2_collect([entry])
    k, r = next(iter(c.rows.items()))
    t = r["transfer"]
    assert t["kind"] == "conditional" and t["condition"] is None
    assert [cf.triple(e) for e in t["edges"]] == [cf.NORMAL, cf.OUTER, cf.NESTED]
    normal, outer, nested = t["edges"]
    assert normal["to"] == cf.addr(1, START + 6) and outer["to"] == cf.addr(1, START + 22)
    assert nested["to"] is None and nested["lands_on"] == {"class": "unresolved"}
    assert _g2_code(c.units[k], "transfer.condition") == "n"
    assert _g2_code(c.units[k], "transfer.edges.to", cf.NORMAL) == "c"
    assert _g2_code(c.units[k], "transfer.edges.lands_on.class", cf.NESTED) == "c"

    before = cf.digest(_g2_document(c))
    t["edges"].reverse()
    assert cf.digest(_g2_document(c)) == before
    for variant in ("missing", "duplicate", "placeholder", "wrong-guard"):
        changed = deepcopy(r)
        es = changed["transfer"]["edges"]
        es[:] = [e for e in es if cf.triple(e) != cf.NESTED]
        if variant == "duplicate":
            es.append(deepcopy(outer))
        if variant == "placeholder":
            es.append(dict(zip(cf.EC, cf.NESTED), unobserved="unavailable"))
        if variant == "wrong-guard":
            es.append(dict(nested, requires=None))
        units = cf.row_verdicts(changed, cf.votes(entry[3], entry[4]), cf.Index([], True), {})
        expected = "u" if variant == "placeholder" else "x"
        assert _g2_code(units, "transfer.edges", cf.NESTED) == expected
        assert _g2_code(units, "transfer.edges.to", cf.NESTED) is None
        assert _g2_code(units, "transfer.edges.to", cf.NORMAL) == "c"
        assert _g2_code(units, "transfer.edges", cf.OUTER) == ("x" if variant == "duplicate" else "c")


def _g2_unit(arm=False, constant_link=False):
    from dataclasses import replace

    import common_facts as cf
    import lifting
    from synthetic import (AARCH64, CODE_BASE, X30, X64, FunctionBuilder, const, copy, program_units,
                           reg, register_evidence)
    from tdo_v2.call_relations import call_relations
    from tdo_v2.isa_identity import link_register, program_counter, stack_register

    arch = AARCH64 if arm else X64
    dest = CODE_BASE + 0x800
    main = FunctionBuilder(entry=CODE_BASE, arch=arch)
    main = main.call_indirect(X30) if arm else main.call(dest)
    if constant_link:
        main._rows[0].ops[-2] = copy(reg(X30), const(CODE_BASE + 4))
    units = program_units(main.ret(), FunctionBuilder(entry=dest, arch=arch).ret(),
                          registers=register_evidence(arch))
    unit = next(u for u in units if u.scopes.function.entry.byte_offset == CODE_BASE)
    evidence = unit.scopes.program.evidence
    regs = {k: cf.register(fn(evidence)) for k, fn in
            (("sp", stack_register), ("lr", link_register), ("pc", program_counter))}
    ins = replace(unit.observation.instructions[0], length=4)
    obs = replace(unit.observation, instructions=(ins, *unit.observation.instructions[1:]))
    relations = {k: cf.engine_fields(rel) for k, rel in call_relations(obs, unit.scopes).items()}
    f = dict(lifting.row_facts(ins), isa="aarch64" if arm else "x86-64")
    entry = "f0", f, None if arm else lifting.identify(f), None, None, b""
    c = _g2_collect([entry], isa=f["isa"], regs=regs)
    fn = dict(function_id="f0", rows=[f], engine_relations=relations, engine_error=None)
    return c, fn, regs


def test_g2a_required_push_parity():
    from copy import deepcopy

    import common_facts as cf

    c, fn, regs = _g2_unit()
    k, r = next(iter(c.rows.items()))
    f = fn["rows"][0]
    assert len(fn["engine_relations"]) == 1
    p, why = cf.projection(r, f, regs)
    assert why is None and p == next(iter(fn["engine_relations"].values()))
    assert cf.parity(fn, c.rows, regs, {})[0]["status"] == "matched"
    assert cf.push_gate(dict(f, fallthrough=None), regs["sp"])[1] == "no-fallthrough"
    assert cf.push_gate(f, None)[1] == "no-stack-register"
    assert cf.push_gate(dict(f, flow=dict(f["flow"], is_call=False)), regs["sp"])[1] == "not-call-flow"
    for field in ("continuation", "width", "bits", "slot", "sp", "setup", "transient", "entry", "transfer"):
        changed = deepcopy(r)
        t = changed["transfer"]
        link, keys = t["link_write"], t["op_keys"]
        if field == "continuation":
            link["continuation"]["offset"] = "0"
        elif field == "width":
            link["value"]["width"] = 16
        elif field == "bits":
            link["value"]["bits"] = "0"
        elif field == "slot":
            link["location"]["memory"]["slot_offset"] = -2
        elif field == "sp":
            link["location"]["memory"]["base"]["space"] += 1
        elif field in ("setup", "transient"):
            keys[field] = []
        elif field == "entry":
            keys["entry_ordinal"] += 1
        else:
            keys["transfer"]["opcode"] = "CALLIND"
        rec, = cf.parity(fn, {k: changed}, regs, {})
        assert rec["status"] in ("missing", "differs"), field
        if field == "sp":
            assert "sp" in rec["differences"]

    bad = deepcopy(f)
    bad["ops"][1]["inputs"][2]["size"] = 2
    assert cf.push_gate(bad, regs["sp"])[1] == "stored-width-or-fallthrough"
    bad = deepcopy(f)
    bad["ops"][1]["inputs"][0]["offset"] += 1
    assert cf.push_gate(bad, regs["sp"])[1] == "store-space-or-base"


def test_g2a_required_blr_x30():
    import json

    import common_facts as cf

    for constant in (False, True):
        c, fn, regs = _g2_unit(True, constant)
        k, r = next(iter(c.rows.items()))
        t = r["transfer"]
        assert json.loads(cf.canonical(r)) == r
        assert t["kind"] == "indirect" and t["target_auth"] is None
        assert cf.coord(t["target_value"]["pre_register"]) == cf.coord(regs["lr"])
        assert t["target_value"]["width"] == 64
        assert t["link_write"]["location"]["register"] == regs["lr"]
        assert t["link_write"]["sp_delta"] == 0
        assert t["link_write"]["continuation"] == cf.addr(r["space"], int(r["offset"], 16) + 4)
        assert t["link_write"]["derivation"] == ("constant" if constant else "pc_plus_4")
        keys = t["op_keys"]
        assert [x["opcode"] for x in keys["setup"]] == ["COPY", "COPY" if constant else "INT_ADD"]
        assert keys["target"] == keys["setup"][:1]
        assert keys["persistent"] == keys["link"] == keys["setup"][1:]
        assert keys["transient"] == [] and keys["entry_ordinal"] == 2
        assert keys["transfer"] == {"ordinal": 2, "opcode": "CALLIND"}
        assert {u["code"] for u in c.units[k]} == {"?"}
        assert cf.parity(fn, c.rows, regs, {})[0]["status"] == "matched"


@pytest.mark.parametrize("binding", [_g2_binding, _g2_binding5])
def test_g2a_required_binding(binding):
    from copy import deepcopy

    import common_facts as cf
    import evidence

    fid, f, lift, ballot, result, data = _g2_golden()
    c = _g2_collect([(fid, f, lift, ballot, result, data),
                     ("other", f, None, None, None, b""),
                     (fid, dict(f, view="1"), None, None, None, b"")])
    doc, ev, args = binding(c)
    lookup = evidence.bind_common_facts(ev, doc, **args)
    base = cf.identity(f, fid)
    row = cf.ref(c.rows[base])
    assert lookup(dict(row=row, path="transfer.kind")) == "confirmed"
    assert lookup(dict(row=dict(row, observation="other"), path="transfer.kind")) == "unobserved"
    alt = cf.ref(c.rows[cf.identity(dict(f, view="1"), fid)])
    assert lookup(dict(row=alt, path="transfer.kind")) == "unobserved"
    vpath = "vendor_views.intel.link_write.value.width"
    assert lookup(dict(row=row, path=vpath)) == "confirmed"
    assert lookup(dict(row=alt, path=vpath)) is None
    assert lookup(dict(row=row, path="vendor_views.amd.edges.to", edge=dict(zip(cf.EC, cf.DIRECT)))) == "unobserved"
    assert lookup(dict(row=row, path="vendor_views.amd.edges.to", edge=dict(zip(cf.EC, cf.NEXT)))) is None

    # Different outcomes at the same path suffix prove that no vendor fallback occurs.
    changed = deepcopy(c.rows[base])
    changed["vendor_views"]["amd"]["link_write"]["continuation"] = cf.addr(1, 0x1004)
    c.rows[base] = changed
    old = c.units[base]
    c.units[base] = [u for u in old if not u["path"].startswith("vendor_views.amd.")]
    c.units[base] += cf.row_verdicts(changed, cf.votes(ballot, result, "amd"), cf.Index([], True), {}, "amd")
    doc2, ev2, args2 = binding(c)
    lookup2 = evidence.bind_common_facts(ev2, doc2, **args2)
    assert lookup2(dict(row=row, path="vendor_views.intel.link_write.continuation")) == "confirmed"
    assert lookup2(dict(row=row, path="vendor_views.amd.link_write.continuation")) == "contradicted"

    # Rebind the facts digest alone so the row-set check is exercised independently.
    fewer, evidence2 = deepcopy(doc), deepcopy(ev)
    fewer["rows"].pop()
    evidence2["common_facts"]["facts_sha256"] = cf.digest(fewer)
    with pytest.raises(evidence.Rejected):
        evidence.bind_common_facts(evidence2, fewer, **args)
    for name in ("generation_id", "manifest_sha256"):
        changed = deepcopy(doc)
        changed["bundle"][name] = "different"
        e = deepcopy(ev)
        e["common_facts"]["facts_sha256"] = cf.digest(changed)
        with pytest.raises(evidence.Rejected):
            evidence.bind_common_facts(e, changed, **args)
    changed = deepcopy(ev)
    changed["common_facts"]["rule_version"] = "another rule"
    with pytest.raises(evidence.Rejected):
        evidence.bind_common_facts(changed, doc, **args)
    broken = deepcopy(doc)
    root = next(r for r in broken["rows"] if cf.rr(r) == base)
    root["transfer"]["op_keys"]["transfer"]["ordinal"] = 300
    e = deepcopy(ev)
    e["common_facts"]["facts_sha256"] = cf.digest(broken)
    with pytest.raises(evidence.Rejected):
        evidence.bind_common_facts(e, broken, **args)


def test_g2a_required_values_and_index():
    import common_facts as cf

    load = [_op("INT_ADD", [_r(RSP_), _c(8)], _u(0x10)), _op("LOAD", [_c(1), _u(0x10)], _u(0x20))]
    f = _row(4, load + _push(START + 4) + [_op("CALLIND", [_u(0x20)])])
    target, defs = cf.value(f, _u(0x20), 4, call_cut=2)
    assert defs == [0, 1]
    assert target["memory"]["address"]["add"][0]["pre_register"]["offset"] == RSP_
    f = _row(6, [_op("BRANCHIND", [_a(START + 0x40)])])
    target, _ = cf.value(f, f["ops"][0]["inputs"][0], 0)
    assert target["memory"]["address"] == {"constant": f"{START + 0x40:x}", "width": 64}
    assert target["memory"]["size"] == 8
    f = _row(2, [_op("CALLOTHER", [_c(7)], _u(1)), _op("BRANCHIND", [_u(1)])])
    assert cf.unknown(cf.value(f, _u(1), 1)[0])
    f = _row(2, [_op("STORE", [_c(1), _r(RAX_), _r(RCX_)]),
                 _op("LOAD", [_c(1), _r(RSP_)], _u(1)), _op("BRANCHIND", [_u(1)])])
    assert cf.unknown(cf.value(f, _u(1), 2)[0])
    f = _row(2, [_op("INT_ADD", [_r(0x110), _r(RAX_)], _u(0x80)),
                 _op("LOAD", [_c(1), _u(0x80)], _u(0x90)), _op("BRANCHIND", [_u(0x90)])])
    mem = cf.value(f, _u(0x90), 2, segment=0x110)[0]["memory"]
    assert mem["segment_base"]["pre_register"]["offset"] == 0x110
    assert mem["address"]["pre_register"]["offset"] == RAX_

    idx = cf.Index([(1, START, 6, ("a", "f0")), (1, START + 2, None, ("b", "f1")),
                    (1, START + 2, 2, ("c", "f1")), (2, START + 2, 1, ("d", "f2"))], True)
    land = idx.landing(cf.addr(1, START + 2))
    assert land["class"] == "row_start"
    assert land["starts"] == [dict(id="b", observation="f1"), dict(id="c", observation="f1")]
    assert land["inside"] == [dict(id="a", observation="f0")]
    assert cf.unknown(idx.landing(cf.addr(1, START + 3))["inside"])


@needs
def test_g2a_required_conditions_and_traps():
    import common_facts as cf

    for f, data, key in (
        (_jcc(2, START + 6, []), "7404", "flags"),
        (_jcc(2, START, JRCXZ), "e3fe", "zero"),
        (_jcc(2, START, LOOP), "e2fe", "nonzero"),
        (_jcc(2, START, LOOP), "e1fe", "unobserved"),
        (_jcc(2, START, LOOP), "e0fe", "unobserved"),
    ):
        c = _g2_collect([_g2_live(f, data)])
        k, r = next(iter(c.rows.items()))
        assert key in r["transfer"]["condition"]["test"]
        if key == "flags":
            assert r["transfer"]["condition"]["test"][key] == "e"
        assert _g2_code(c.units[k], "transfer.edges", cf.TAKEN) == "c"
    for f, data, saved in ((_int_pair(0x29), "cd29", cf.addr(1, START + 2)),
                           (_syscall(), "0f05", cf.addr(1, START + 2)),
                           (_row(2, [_op("CALLOTHER", [_c(3)])]), "0f34", None)):
        c = _g2_collect([_g2_live(f, data)])
        k, r = next(iter(c.rows.items()))
        es = r["transfer"]["edges"]
        assert [cf.triple(e) for e in es] == [cf.OS, cf.SAVED]
        assert es[1]["to"] == saved
        assert _g2_code(c.units[k], "transfer.edges.to", cf.SAVED) == ("c" if saved is None else "u")

    f = _int_pair(0x29)
    c = _g2_collect([_g2_live(f, "cd29")])
    fn = dict(function_id="f0", rows=[f], engine_relations={}, engine_error=None)
    record, = cf.parity(fn, c.rows, {}, {})
    assert record["status"] == "neither" and "swi+CALLIND" in record["reason"]


@needs
def test_g2a_end_to_end(tmp_path):
    import json
    import _sealed as s
    import common_facts as cf
    import decode_check
    import evidence

    functions, code = _pair(s)
    directory = tmp_path / "b"
    directory.mkdir()
    generation = _bundle(directory, functions, code)
    out, facts_out = tmp_path / "ev.json", tmp_path / "facts.json"
    header, _ = decode_check.run(generation, s.NAMING_SOURCE, True, full=True,
                                 evidence_out=out, common_facts_out=facts_out)
    ev = evidence.parse(out.read_bytes())
    doc = json.loads(facts_out.read_bytes())
    assert ev["schema"] == evidence.SCHEMA5 and doc["schema"] == cf.SCHEMA
    block = ev["common_facts"]
    assert (block["schema"], block["rule_version"]) == (cf.VERDICT_SCHEMA2, cf.VERDICT_RULE)
    assert doc["producer"]["rule"] == cf.FACTS_RULE == "g2a-3" and header["common_facts"]["rule"] == "g2a-4"
    # (r2 D4) the whole file is canonical(doc) + LF; the block digest excludes the LF
    import hashlib
    assert facts_out.read_bytes() == cf.canonical(doc) + b"\n"
    assert block["facts_sha256"] == hashlib.sha256(cf.canonical(doc)).hexdigest() == cf.digest(doc)
    assert ev["common_facts"]["row_set_sha256"] == cf.row_set_digest(doc["rows"])
    report = header["common_facts"]
    assert report["parity"]["base_joins"] == report["parity"]["source_ops"]
    assert len(report["fixtures"]["required"]) == 7 and all(n.startswith("test_g2a_required_") for n in report["fixtures"]["required"])   # (not run here)
    for counts in report["fields"].values():
        assert counts["N_considered"] == (counts["N_applicable"] + counts["N_not_applicable"]
                                          + counts["N_applicability_unknown"])
        assert counts["unobserved"] == counts["unobserved_applicable"] + counts["N_applicability_unknown"]


def test_g2a_round2_bound_units():
    from copy import deepcopy
    import common_facts as cf
    import evidence

    c = _g2_collect([_g2_golden()])
    doc, ev, args = _g2_binding(c)
    for path in ("transfer.op_keys.setup", "transfer.does_not_exist",
                 "transfer.edges", "vendor_views.amd.op_keys.transfer"):
        bad = deepcopy(ev)
        vr = bad["common_facts"]["rows"][0]
        vr["units"].append(cf.unit(path, "c"))
        vr["state"] = cf.row_state(vr["units"])
        with pytest.raises(evidence.Rejected):
            evidence.bind_common_facts(bad, doc, **args)


def test_g2a_round2_transient_and_coverage():
    from copy import deepcopy
    import common_facts as cf
    import lifting

    _, fn, regs = _g2_unit()
    f = deepcopy(fn["rows"][0])
    for bad in (dict(f, length=f["length"] + 1), dict(f, fallthrough_space=f["space"] + 1)):
        r = cf.derive_row(bad, lifting.identify(bad), "f0", regs)
        assert r["transfer"]["op_keys"]["transient"] == []
        assert cf.projection(r, bad, regs)[0] is None

    entry = _g2_golden()
    c = _g2_collect([entry])
    r = next(iter(c.rows.values()))
    r["vendor_views"]["intel"]["link_write"] = cf.U("link unavailable")
    units = cf.row_verdicts(r, cf.votes(entry[3], entry[4], "intel"), cf.Index([], True), {}, "intel")
    assert all(_g2_code(units, "vendor_views.intel.link_write." + p) == "u" for p in cf.LINK_FIELDS)


def test_g2a_round2_path_and_address_size():
    from dataclasses import replace
    import common_facts as cf
    import lifting

    entry = _g2_golden()
    r = next(iter(_g2_collect([entry]).rows.values()))
    vs = [replace(v, flow="syscall", length=2) for v in entry[3]["intel"]]
    r["transfer"]["edges"] = cf.make_edges(("syscall", False), entry[1], 2, None)
    units = cf.row_verdicts(r, vs, cf.Index([], True), {"facts": {"F3": {"flow": "syscall"}}})
    assert _g2_code(units, "transfer.edges.to", cf.SAVED) == "u"

    ops = [_op("LOAD", [_c(1), _r(RAX_)], _u(0x40))] + _push(START + 3)
    f = _row(3, ops + [_op("CALLIND", [_u(0x40)])], flow=_flow("call_indirect"))
    r = cf.derive_row(f, lifting.identify(f), "f0", {}, bytes.fromhex("67ff10"))
    assert cf.unknown(r["transfer"]["target_value"])


def test_g2a_round2_different_lift_relocation():
    from copy import deepcopy
    import common_facts as cf

    c, fn, regs = _g2_unit()
    k, r = next(iter(c.rows.items()))
    f = fn["rows"][0]
    f2 = deepcopy(f)
    f2["ops"][0]["inputs"][1]["size"] = 4 if f2["ops"][0]["inputs"][1]["size"] == 8 else 8
    r2 = deepcopy(r)
    r2["observation"] = "f1"
    r2["transfer"]["link_write"]["relocation"] = "unknown"
    k2 = cf.rr(r2)
    groups = {(f["isa"], f["space"], f["address"], r["view"], b"same"): [k, k2]}
    group, = cf.different_lifts(groups, {k: r, k2: r2}, {k: f, k2: f2}, regs)
    assert [x["relocation_check"] for x in group["lifts"]] == ["c", "x"]


def test_g2a_round2_producer_abstention_is_unobserved():
    # Fable r2 P2-1: kind "unknown" with no edges is an abstention; voters' decided form cannot contradict it.
    import common_facts as cf

    entry = _g2_golden()
    r = next(iter(_g2_collect([entry]).rows.values()))
    r["transfer"]["kind"], r["transfer"]["edges"] = "unknown", []
    units = cf.row_verdicts(r, cf.votes(entry[3], entry[4], "intel"), cf.Index([], True), {})
    assert _g2_code(units, "transfer.kind") == "u"
    assert not [u for u in units if u["path"] == "transfer.edges" and u["code"] == "x"]
    r["transfer"]["kind"] = "indirect"
    units = cf.row_verdicts(r, cf.votes(entry[3], entry[4], "intel"), cf.Index([], True), {})
    assert _g2_code(units, "transfer.kind") == "x"


def _g2_jrcxz():
    import decoders
    import lifting

    data = bytes.fromhex("e3fe")
    f = _jcc(len(data), START, JRCXZ)
    ballot = {
        vendor: tuple(
            decoders.Decoded(
                voter=name, version="fixture", amd=(vendor == "amd"), status="ok",
                length=2, flow="jcc", mnemonic="jrcxz", counter=True, address_bits=64,
                target=START, target_ip_bits=64, encoded_disp_bits=8,
                target_derivation="decoder",
            )
            for name in names
        )
        for vendor, names in (("intel", decoders.INTEL_VOTERS), ("amd", decoders.AMD_VOTERS))
    }
    result = {"window": {"verified": len(data), "relocations": []},
              "attributes": {"a2": {"state": "applied", "value": len(data)}}}
    return "f0", f, lifting.identify(f), ballot, result, data


@pytest.mark.parametrize("binding", [_g2_binding, _g2_binding5])
def test_g2a_round3_opaque_op_output_binding(monkeypatch, binding):
    import common_facts as cf
    import evidence

    # Model a producer that supplies only the reaching definition for the predicate.
    def opaque_predicate(f, i, b, prefix):
        return cf.value(f, f["ops"][i]["inputs"][1], i)

    monkeypatch.setattr(cf, "predicate", opaque_predicate)
    c = _g2_collect([_g2_jrcxz()])
    k, r = next(iter(c.rows.items()))
    path = "transfer.condition.test"
    assert r["transfer"]["condition"]["test"] == {"op_output": {"ordinal": 0, "opcode": "INT_EQUAL"}}
    assert _g2_code(c.units[k], path) == "u"

    doc, ev, args = binding(c)
    query = dict(row=cf.ref(r), path=path)
    lookup = evidence.bind_common_facts(ev, doc, **args)
    assert lookup(query) == "unobserved"
    assert lookup(dict(query, path="transfer.condition")) == "confirmed"

    c.units[k] = [dict(u, code="c") if u["path"] == path else u for u in c.units[k]]
    bad_doc, bad_ev, bad_args = binding(c)
    with pytest.raises(evidence.Rejected, match="confirmed opaque op_output"):
        evidence.bind_common_facts(bad_ev, bad_doc, **bad_args)


@pytest.mark.parametrize("fixture,parent,roles", [
    (_g2_golden, "link_write", ("DIRECT",)),
    (_g2_jrcxz, "condition", ("TAKEN", "NEXT")),
], ids=["66e8-call", "jrcxz"])
def test_g2a_round3_collector_abstention(fixture, parent, roles):
    import common_facts as cf

    fid, f, _, ballot, result, data = fixture()
    c = _g2_collect([(fid, f, None, ballot, result, data)])
    k, r = next(iter(c.rows.items()))
    t = r["transfer"]
    assert t["kind"] == "unknown" and t["edges"] == []
    assert t["link_write"] is None and t["condition"] is None
    units = c.units[k]
    assert _g2_code(units, "transfer.kind") == "u"
    assert _g2_code(units, "transfer." + parent) == "u"
    for role in roles:
        assert _g2_code(units, "transfer.edges", getattr(cf, role)) == "u"
    assert cf.row_state(units) == "u"


def test_g2a_round3_abstention_preserves_length_contradiction():
    import common_facts as cf

    fid, f, _, ballot, result, data = _g2_jrcxz()
    f = dict(f, length=3, fallthrough=START + 3)
    c = _g2_collect([(fid, f, None, ballot, result, data)])
    units, = c.units.values()
    assert _g2_code(units, "transfer.condition") == "u"
    assert _g2_code(units, "length") == "x"
    assert cf.row_state(units) == "x"


def test_g2a_round3_trap_return_input_not_applicable():
    import common_facts as cf

    f = _row(2, [_co(1, _c(0x29, 4)), _op("RETURN", [_r(RAX_)])], fallthrough=False)
    fid = "f0"
    r = dict(id=cf.identity(f, fid)[0], observation=fid,
             transfer=dict(kind="trap", target_value=None,
                           op_keys=dict(transfer=cf.opref(f["ops"], 0))))
    fn = {"function_id": fid, "rows": [f], "tails": {}}
    checks = cf.input_checks(fn, {cf.identity(f, fid): r})
    assert [c["fields"] for c in checks] == [{"transfer": "n", "target_value": "n"}]
    r["transfer"]["kind"] = "return"
    r["transfer"]["op_keys"]["transfer"] = cf.opref(f["ops"], 1)
    assert cf.input_checks(fn, {cf.identity(f, fid): r})[0]["fields"]["transfer"] == "c"


# -- G2a cost compaction (design_tbr_g2a_cost r1 + r2): -5 interned verdicts, vote summaries, streamed facts ------

def _g2_all_queries(c, doc):
    import common_facts as cf

    queries = []
    for r in doc["rows"]:
        for u in c.units[cf.rr(r)]:
            q = dict(row=cf.ref(r), path=u["path"])
            if "edge" in u:
                q["edge"] = u["edge"]
            if "op" in u:
                q["op"] = u["op"]
            queries.append(q)
    return queries


def test_g2a_cost_field_paths_match_binding():
    import common_facts as cf
    import evidence

    edge_fields, _, shared, transfer = evidence.common_path_sets()
    allowed = ({"length", "bytes.range"} | {"transfer." + s for s in transfer}
               | {f"vendor_views.{v}.{s}" for v in cf.VENDORS for s in shared | edge_fields | {"length", "bytes"}})
    assert set(cf.FIELD_PATHS) == allowed and len(cf.FIELD_PATHS) == len(set(cf.FIELD_PATHS))


def test_g2a_cost_streamed_facts_bytes(tmp_path):
    import hashlib
    import common_facts as cf

    c = _g2_collect([_g2_golden(), _g2_jrcxz()])
    doc = _g2_document(c)
    path = tmp_path / "facts.json"
    sha = cf.write_canonical(path, doc)
    assert path.read_bytes() == cf.canonical(doc) + b"\n"
    assert sha == hashlib.sha256(cf.canonical(doc)).hexdigest() == cf.streamed_digest(doc) == cf.digest(doc)


def test_g2a_cost_block5_expands_to_block4():
    import common_facts as cf

    c = _g2_collect([_g2_golden(), _g2_jrcxz(), ("f1", *_g2_golden()[1:])])
    doc = _g2_document(c)
    four = cf.verdict_block(doc, c.units)
    five = cf.verdict_block5(doc, cf.digest(doc), c.unit_sets, c.row_set)
    assert cf.expand_block5(five) == [dict(id=r["id"], observation=r["observation"], units=r["units"],
                                           state=r["state"]) for r in four["rows"]]
    # two rows with the same verdicts share one set; numbering is by first use
    ids = [r["set"] for r in five["rows"]]
    assert list(dict.fromkeys(ids)) == list(range(len(five["unit_sets"])))
    # (Astra impl r1: an independent 798b903 oracle value for the same three-row fixture)
    assert cf.digest(cf.expand_block5(five)) == "067dd5124bc0e4878f18e2c049ba19d5a805ba4ff565d8b9308d22025ea1bf2a"
    assert len(five["unit_sets"]) < len(five["rows"])


def test_g2a_cost_lookups_equal_on_four_and_five():
    import common_facts as cf
    import evidence

    fid, f, _, ballot, result, data = _g2_jrcxz()
    entries = [_g2_golden(), ("f1", *_g2_golden()[1:]), (fid, dict(f, address=START + 0x40), None, ballot, result, data)]
    c = _g2_collect(entries)
    doc, ev4, args4 = _g2_binding(c)
    _, ev5, args5 = _g2_binding5(c)
    four = evidence.bind_common_facts(ev4, doc, **args4)
    five = evidence.bind_common_facts(ev5, doc, **args5)
    queries = _g2_all_queries(c, doc)
    assert queries and all(four(q) == five(q) for q in queries)
    assert any(five(q) == "unobserved" for q in queries if q["path"] == "transfer.edges")   # (D1: abstention row)
    row = queries[0]["row"]
    for q in (dict(row=row, path="transfer.nope"), dict(row=row, path="transfer.kind", extra=1),
              dict(row=dict(row, observation="zz"), path="transfer.kind"),
              dict(row=row, path="transfer.op_keys.transfer", op={"ordinal": 99, "opcode": "CALL"})):
        assert four(q) is None and five(q) is None


def test_g2a_cost_block5_rejections():
    from copy import deepcopy

    import common_facts as cf
    import evidence

    c = _g2_collect([_g2_golden(), ("f1", *_g2_golden()[1:]), _g2_jrcxz()])
    doc, ev, args = _g2_binding5(c)
    evidence.bind_common_facts(ev, doc, **args)

    def bad(change, match=None):
        e = deepcopy(ev)
        change(e["common_facts"])
        with pytest.raises(evidence.Rejected, match=match):
            evidence.bind_common_facts(e, doc, **dict(args, allowlist=[evidence.allowlist_entry(e)]))

    def wrong_first_use(block):
        sets = block["unit_sets"]
        sets[0], sets[1] = sets[1], sets[0]
        for row in block["rows"]:
            if row["set"] in (0, 1):
                row["set"] = 1 - row["set"]

    bad(wrong_first_use, "not numbered by first use")
    for pid in (True, -1, len(cf.FIELD_PATHS)):
        bad(lambda b, pid=pid: b["unit_sets"][0][0].__setitem__(0, pid), "unit path id or code")

    def setfield(i, value):
        return lambda b: b["rows"][i].__setitem__("set", value)

    bad(setfield(0, True))
    bad(setfield(0, 99))
    bad(lambda b: b["field_paths"].reverse())
    bad(lambda b: b["rows"][0].__setitem__("state", "c" if b["rows"][0]["state"] != "c" else "x"))
    bad(lambda b: b["unit_sets"].append(deepcopy(b["unit_sets"][0])))                  # duplicate, unused
    bad(lambda b: b["unit_sets"].append([[0, "u"]]))                                    # unused
    bad(lambda b: b["unit_sets"][0].append([0, "u", None]))                             # arity 3 bad edge
    bad(lambda b: b["unit_sets"][0].append([0, "u", ["always", "encoded_target", None], {"ordinal": 0, "opcode": "X"}]))
    bad(lambda b: b["unit_sets"][0].append(deepcopy(b["unit_sets"][0][0])))             # duplicate selector
    opaque = cf.PATH_ID["transfer.link_write.relocation"]           # confirmed opaque field

    def confirm_opaque(b):
        b["unit_sets"] = [[[opaque, "c"] if u[0] == opaque else u for u in s] for s in b["unit_sets"]]
        for r in b["rows"]:
            r["state"] = cf.row_state([cf.unit_from_json(u) for u in b["unit_sets"][r["set"]]])

    bad(confirm_opaque)


def test_g2a_cost_shared_set_binding_fails_for_one_row():
    from copy import deepcopy

    import evidence

    c = _g2_collect([_g2_golden(), ("f1", *_g2_golden()[1:])])
    doc, ev, args = _g2_binding5(c)
    assert len(ev["common_facts"]["unit_sets"]) == 1          # both rows share the set
    broken = deepcopy(doc)
    broken["rows"][1]["transfer"]["edges"] = []               # the shared set has edge-subfield units
    e = deepcopy(ev)
    import common_facts as cf
    e["common_facts"]["facts_sha256"] = cf.digest(broken)
    with pytest.raises(evidence.Rejected):
        evidence.bind_common_facts(e, broken, **dict(args, allowlist=[evidence.allowlist_entry(e)]))


def _g2_votes_variants():
    from dataclasses import replace

    fid, f, lift, ballot, result, data = _g2_golden()
    intel = list(ballot["intel"])
    amd = list(ballot["amd"])
    yield "golden", intel + amd
    yield "empty", []
    yield "all-invalid", [replace(v, status="invalid") for v in intel]
    yield "mixed-status", [replace(intel[0], status="invalid")] + intel[1:]
    yield "a7-bits-split", [replace(v, length=v.length + (i % 2)) for i, v in enumerate(intel)]
    yield "a5-non-decoder", [replace(intel[0], target_derivation="computed")] + intel[1:]
    yield "intel-only", intel
    yield "amd-only", amd


def test_g2a_cost_summary_equals_reference():
    import _g2a_reference as ref
    import common_facts as cf

    fid, f, lift, ballot, result, data = _g2_golden()
    c = _g2_collect([_g2_golden()])
    r = next(iter(c.rows.values()))
    address = int(r["offset"], 16)
    f1 = {"facts": {"F1": {"class": "invalid_encoding"}}}
    for name, vs in _g2_votes_variants():
        for isa in ({}, f1, dict(f1, unobserved={"F1": "late failure"})):
            for vendor in (None, "intel", "amd"):
                s = cf.summarize_votes(vs, address)            # (no raise on any variant: r2 D2)
                assert cf.row_verdicts(r, s, cf.Index([], True), isa, vendor) == \
                    ref.row_verdicts(r, vs, cf.Index([], True), isa, vendor), (name, isa, vendor)
    invalid = [v for n, v in _g2_votes_variants() if n == "all-invalid"][0]
    assert cf.vote_form(cf.summarize_votes(invalid, address), f1) == ("invalid", False)
    assert cf.vote_form(cf.summarize_votes(invalid, address), dict(f1, unobserved={"F1": "x"})) is cf.MISS
    assert cf.summarize_votes([], address) is cf.EMPTY


def test_g2a_cost_crosscheck_switch(monkeypatch):
    monkeypatch.setenv("TDO_V2_G2A_COST_CROSSCHECK", "1")
    c = _g2_collect([_g2_golden(), _g2_jrcxz(), ("f1", *_g2_golden()[1:])])
    assert c.crosscheck and c.crosschecked == 7 and not c.checked


@pytest.mark.parametrize("binding", [_g2_binding, _g2_binding5])
@pytest.mark.parametrize("mode", ["star", "uncovered"])
def test_g2a_shared_set_coverage(binding, mode):
    import common_facts as cf
    import evidence

    c = _g2_collect([_g2_golden(), ("f1", *_g2_golden()[1:])])
    doc, ev, args = binding(c)
    first, second = doc["rows"]
    if mode == "star":
        ev["functions"][1]["exceptions"] = [
            dict(space=second["space"], offset=second["offset"], attributes={"*": "unobserved"})]
    else:
        args["bundle"]["functions"]["f1"]["kept"] = False
    lookup = evidence.bind_common_facts(ev, doc, **args)
    assert lookup(dict(row=cf.ref(first), path="transfer.kind")) == "confirmed"
    assert lookup(dict(row=cf.ref(second), path="transfer.kind")) == "unobserved"


def test_g2a_explicit_owner_and_normalized_duplicate():
    import common_facts as cf
    import evidence

    doc, ev, args = _g2_binding5(_g2_collect([_g2_golden()]))
    row = cf.ref(doc["rows"][0])
    units = ev["common_facts"]["unit_sets"][0]
    u = next(u for u in units if len(u) == 4)
    implicit = dict(u[3])
    u[3]["row"] = row
    query = dict(row=row, path=cf.FIELD_PATHS[u[0]])
    lookup = evidence.bind_common_facts(ev, doc, **args)
    assert lookup(dict(query, op=implicit)) == "unobserved"
    assert lookup(dict(query, op=u[3])) == "unobserved"
    assert lookup(dict(query, op=dict(implicit, row=dict(row, observation="other")))) is None   # (Fable P2-1)
    units.append([u[0], u[1], None, implicit])
    with pytest.raises(evidence.Rejected, match="duplicate normalized lookup"):
        evidence.bind_common_facts(ev, doc, **args)


def test_g2a_one_vendor_rejected_at_collection():
    import common_facts as cf
    import decode_check

    fid, f, lift, ballot, result, data = _g2_golden()
    c = decode_check.CommonFactsCollector({"functions": [], "registers": {}})
    c(fid, dict(f, isa="x86-64"), result, lift, dict(ballot, amd=()), data)
    union, intel, amd = next(iter(c.summaries.values()))
    assert union is cf.EMPTY and amd is cf.EMPTY
    assert (intel.length, intel.a7_width, intel.a7_bits) == (6, 64, START + 6)


def test_g2a_vendor_path_on_row_without_view():
    import common_facts as cf
    import evidence

    c = _g2_collect([_g2_jrcxz()])                 # (no vendor views)
    doc, ev, args = _g2_binding5(c)
    lookup = evidence.bind_common_facts(ev, doc, **args)
    assert lookup(dict(row=cf.ref(doc["rows"][0]), path="vendor_views.intel.length")) is None


def test_g2a_crosscheck_reports_one_sided_exception(monkeypatch):
    import common_facts as cf

    monkeypatch.setenv("TDO_V2_G2A_COST_CROSSCHECK", "1")
    real = cf.row_verdicts

    def broken(r, vs, index, isa, vendor=None):
        raise ValueError("summary path only")

    monkeypatch.setattr(cf, "row_verdicts", broken)
    with pytest.raises(AssertionError, match="summary=ValueError"):
        _g2_collect([_g2_jrcxz()])
    monkeypatch.setattr(cf, "row_verdicts", real)


def test_g2a_verdicts5_schema_file():
    import json
    import common_facts as cf

    schema = json.loads((REPO / "tools/decode_check/common_facts_verdicts5.schema.json").read_bytes())
    assert schema["properties"]["field_paths"]["const"] == list(cf.FIELD_PATHS)
    assert schema["properties"]["schema"]["const"] == cf.VERDICT_SCHEMA2
    assert schema["properties"]["rule_version"]["const"] == cf.VERDICT_RULE


@pytest.mark.parametrize("failing", ["all", "intel"])
def test_g2a_crosscheck_collection_exception(monkeypatch, failing):
    # (Astra impl r2 item 1) a summarize_votes failure at collection reaches the crosscheck, also on rows
    # without vendor views
    import common_facts as cf

    monkeypatch.setenv("TDO_V2_G2A_COST_CROSSCHECK", "1")
    real = cf.summarize_votes
    calls = []

    def summarize(vs, address):
        calls.append(len(calls))
        if failing == "all" or len(calls) == 2:
            raise ValueError("summary failed")
        return real(vs, address)

    monkeypatch.setattr(cf, "summarize_votes", summarize)
    with pytest.raises(AssertionError, match="ValueError" if failing == "all" else "intel"):
        _g2_collect([_g2_jrcxz()])


def test_g2a_write_canonical_keeps_other_files(tmp_path):
    import common_facts as cf

    doc = _g2_document(_g2_collect([_g2_jrcxz()]))
    target = tmp_path / "facts.json"
    other = tmp_path / "facts.json.partial"
    other.write_bytes(b"someone else's file")
    cf.write_canonical(target, doc)
    assert other.read_bytes() == b"someone else's file"
    assert target.read_bytes() == cf.canonical(doc) + b"\n"
    assert sorted(x.name for x in tmp_path.iterdir()) == ["facts.json", "facts.json.partial"]

    class Boom:
        pass

    try:
        cf.write_canonical(target, dict(doc, rows=[*doc["rows"], Boom()]))
    except TypeError:
        pass
    assert target.read_bytes() == cf.canonical(doc) + b"\n"           # (the old file survives a failed write)
    assert sorted(x.name for x in tmp_path.iterdir()) == ["facts.json", "facts.json.partial"]


# -- G2b code-byte facts (design_tbr_g2b_code_facts r1 + r2 + r3): file layer ---------------------------------------

def _g2b_pe(bound=False):
    import struct
    import _pe_fixture as pf

    text = bytes([0xC3]) * 0x30
    rdata = bytearray(0x500)
    descs = [(0x2100, 0, 0, 0x2200, 0x4000),
             (0, 7 if bound else 0, 0, 0x2210, 0x4020)]
    for i, d in enumerate(descs):
        struct.pack_into("<IIIII", rdata, 20 * i, *d)
    struct.pack_into("<QQQ", rdata, 0x100, 0x2300, 1 << 63 | 5, 0)
    rdata[0x200:0x20D] = b"kernel32.dll\0"
    rdata[0x210:0x21B] = b"user32.dll\0"
    rdata[0x300:0x302 + 15] = b"\0\0VirtualProtect\0"
    rdata[0x320:0x322 + 15] = b"\0\0GetProcAddress\0"
    rdata[0x400:0x408] = bytes([0x01, 0x04, 0x02, 0x00]) + bytes(4)            # v1, no flags, 2 codes
    rdata[0x410:0x41C] = bytes([0x01 | 1 << 3, 0x04, 0x01, 0x00]) + bytes(4) + struct.pack("<I", 0x1000)  # EHANDLER
    rdata[0x430:0x440] = bytes([0x01 | 4 << 3, 0, 0, 0]) + struct.pack("<III", 0x1000, 0x1010, 0x2400)  # CHAININFO
    pdata = struct.pack("<III", 0x1000, 0x1010, 0x2400) + struct.pack("<III", 0x1010, 0x1020, 0x2410) + \
        struct.pack("<III", 0x1020, 0x1030, 0x2430)
    data = struct.pack("<QQQ", 0x2300, 1 << 63 | 5, 0) + bytes(8) + struct.pack("<QQ", 0x2320, 0)
    sections = [pf.Section(".text", 0x1000, text),
                pf.Section(".rdata", 0x2000, bytes(rdata), characteristics=0x40000040),
                pf.Section(".pdata", 0x3000, pdata, characteristics=0x40000040),
                pf.Section(".data", 0x4000, data, characteristics=0xC0000040)]
    return pf.make_pe(sections, directories=[pf.Directory(1, 0x2000, 60), pf.Directory(3, 0x3000, 36)])


def test_g2b_pe_file_facts():
    import code_facts as cf2
    import pe_map

    raw = _g2b_pe()
    image = pe_map.parse(raw)
    ff = cf2.file_facts(image, raw)
    assert ff.ok and [(r.start, r.end, r.executable, r.writable) for r in ff.code] == [(0x1000, 0x1030, True, False)]
    unwind = sorted((r.name, r.start, r.end) for r in ff.unwind)
    assert unwind == [(".pdata", 0x3000, 0x3024), (".xdata", 0x2400, 0x2408), (".xdata", 0x2410, 0x241C),
                      (".xdata", 0x2430, 0x2440)]
    assert ff.diagnostics == [{"reason": "HANDLER_DATA_LENGTH", "range": {"start": 0x241C, "end": None}}]
    names = {slot: item["name"] for slot, item in ff.imports.items()}
    assert names == {0x4000: "VirtualProtect", 0x4008: "#5", 0x4020: "GetProcAddress"}
    assert ff.imports[0x4000]["dll"] == "kernel32.dll" and ff.import_state == "complete"
    # the IAT is loader-written: a record read works, a runtime read does not
    assert cf2.record_read(image, raw, 0x4000, 8)[0] == (0x2300).to_bytes(8, "little")
    with pytest.raises(cf2.Unread, match="LOADER_WRITTEN"):
        cf2.runtime_read(image, raw, 0x4000, 8)
    assert cf2.runtime_read(image, raw, 0x2200, 4)[0] == b"kern"


def test_g2b_pe_bound_iat_without_ilt():
    import code_facts as cf2
    import pe_map

    raw = _g2b_pe(bound=True)
    ff = cf2.file_facts(pe_map.parse(raw), raw)
    assert ff.import_state == "partial" and 0x4020 not in ff.imports
    assert [p["reason"] for p in ff.import_problems] == ["BOUND_IAT_NO_ILT"]


def _g2b_elf():
    import struct
    import _elf_fixture as ef

    symtab = bytes(24) + struct.pack("<IBBHQQ", 1, 0x12, 0, 0, 0, 0) + struct.pack("<IBBHQQ", 10, 0x12, 0, 5, 0, 0)
    strtab = b"\0mprotect\0dlsym\0"
    ro = bytearray(0x300)
    ro[0:len(symtab)] = symtab
    ro[0x100:0x100 + len(strtab)] = strtab
    ro[0x200:0x208] = struct.pack("<II", 1, 3)                     # DT_HASH: nbucket 1, nchain 3
    segments = [ef.Segment(0x1000, bytes([0xC3]) * 0x20), ef.Segment(0x3000, bytes(ro), flags=4),
                ef.Segment(0x5000, bytes(16), flags=6)]
    extra = [(6, 0x3000), (11, 24), (5, 0x3100), (10, len(strtab)), (4, 0x3200)]
    return ef.make_elf(segments, jmprel=[ef.Reloc(0x5000, 7, 1), ef.Reloc(0x5008, 7, 2)], extra_dynamic=extra)


def test_g2b_elf_imports_with_dynamic_in_written():
    import code_facts as cf2
    import elf_map

    elf = _g2b_elf()
    image = elf_map.parse(elf.data)
    dynamic = [p for p in image.phdrs if p[0] == 2][0]
    assert any(a <= dynamic[3] - image.image_base < b for a, b, _ in image.written.ranges)   # PT_DYNAMIC written
    ff = cf2.file_facts(image, elf.data)
    assert ff.import_state == "complete" and [(r.start, r.end) for r in ff.code] == [(0x1000, 0x1020)]
    assert {s: (i["name"], i["undefined"]) for s, i in ff.imports.items()} == {0x5000: ("mprotect", True),
                                                                                0x5008: ("dlsym", False)}
    assert {"reason": "NO_SECTION_HEADERS", "what": "eh_frame"} in ff.diagnostics
