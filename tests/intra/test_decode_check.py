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
                             "would_block_unobserved": 0, "would_block_refused": 0, "loss_disagreement": 0,
                             "loss_unobserved": 0, "loss_refused": 0, "loss_unknown": 0}
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
    return evidence.accept(evidence.parse(evidence.dumps(document)), view, allowlist)


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
