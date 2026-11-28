"""Require agreeing mapped unwind records before graphing a symbol-free range."""

import json
from pathlib import Path
import struct
import sys

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "bundle_export"))

import arm64_local
from arm64_elf_unwind import unwind_ranges, select_unwind
import elf_map
import _elf_fixture as ef

BASE, CODE, HEADER, FRAME = 0x400000, 0x401000, 0x401100, 0x401200
CODE_FILE, HEADER_FILE, FRAME_FILE = 0x1000, 0x1100, 0x1200
BODY = bytes.fromhex("e10700f9 e80740f9 c0035fd6")


def _elf(spans=((CODE, len(BODY)),), *, indexed=None, with_exception=False, symbols=(), relocations=()):
    augmentation = b"\x01zR\0\x01\x7c\x1e\x01\x1b"
    if with_exception:
        augmentation = b"\x01zPLR\0\x01\x7c\x1e\x0b\x9c" + bytes(8) + b"\x1c\x1b"
    cie = bytes(4) + augmentation
    cie += bytes(-len(cie) % 4)
    frames = bytearray(struct.pack("<I", len(cie)) + cie)
    index = []
    for entry, size in spans:
        offset = len(frames)
        index.append((entry - HEADER, FRAME + offset - HEADER))
        rhs = b"\x08" + bytes(8) if with_exception else b"\0"
        fde = struct.pack("<Iii", offset + 4, entry - (FRAME + offset + 8), size) + rhs
        fde += bytes(-len(fde) % 4)
        frames.extend(struct.pack("<I", len(fde)) + fde)
    frames.extend(bytes(4))
    if indexed is not None:
        index = [index[i] for i in indexed]

    header = b"\x01\x1b\x03\x3b" + struct.pack("<iI", FRAME - (HEADER + 4), len(index))
    header += b"".join(struct.pack("<ii", *item) for item in index)
    image_body = (BODY * 4).ljust(HEADER - CODE, b"\0") + header
    image_body = image_body.ljust(FRAME - CODE, b"\0") + frames
    image = bytearray(ef.make_elf([ef.Segment(CODE, image_body, offset=CODE_FILE)], e_type=2, link_base=BASE,
                                 machine=183, dynamic=bool(relocations), relocations=relocations).data)
    phnum, = struct.unpack_from("<H", image, 56)
    struct.pack_into("<H", image, 56, phnum + 1)
    struct.pack_into("<IIQQQQQQ", image, 64 + phnum * 56, 0x6474E550, 4,
                     HEADER_FILE, HEADER, HEADER, len(header), len(header), 4)

    names = b"\0.text\0.eh_frame_hdr\0.eh_frame\0.shstrtab\0"
    sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                (names.index(b".text"), 1, 6, CODE, CODE_FILE, len(BODY) * 4, 0, 0, 4, 0),
                (names.index(b".eh_frame_hdr"), 1, 2, HEADER, HEADER_FILE, len(header), 0, 0, 4, 0),
                (names.index(b".eh_frame\0"), 1, 2, FRAME, FRAME_FILE, len(frames), 0, 0, 4, 0),
                (names.index(b".shstrtab"), 3, 0, 0, len(image), len(names), 0, 0, 1, 0)]
    image.extend(names)
    if symbols:
        strings = bytearray(b"\0")
        rows = bytearray(24)
        for name, info, entry, size in symbols:
            rows.extend(struct.pack("<IBBHQQ", len(strings), info, 0, 1, entry, size))
            strings.extend(name.encode("ascii") + b"\0")
        sections.append((0, 3, 0, 0, len(image), len(strings), 0, 0, 1, 0))
        image.extend(strings)
        image.extend(bytes(-len(image) % 8))
        local_boundary = 1 + sum(info >> 4 == 0 for _, info, _, _ in symbols)
        sections.append((0, 2, 0, 0, len(image), len(rows), 5, local_boundary, 8, 24))
        image.extend(rows)
    image.extend(bytes(-len(image) % 8))
    struct.pack_into("<Q", image, 40, len(image))
    struct.pack_into("<HHH", image, 58, 64, len(sections), 4)
    for row in sections:
        image.extend(struct.pack("<IIQQQQIIQQ", *row))
    return image


def discover(data):
    data = bytes(data)
    mapping = elf_map.parse(data, arm64_page=4096)
    assert mapping.ok, mapping.why
    return unwind_ranges(data, mapping, 65536)


@pytest.mark.parametrize("change,reason", [
    ("wrong_header_coverage", "section and program header disagree"),
    ("wrong_frame_pointer", "wrong frame pointer"),
    ("index_interior_pointer", "index and FDE range disagree"),
    ("index_wrong_start", "index and FDE range disagree"),
    ("cie_backpointer", "valid preceding CIE"),
    ("indirect_encoding", "unsupported ELF unwind pointer encoding"),
    ("negative_length", "index and FDE range disagree"),
    ("truncated_augmentation", "augmentation exceeds its record"),
    ("metadata_relocation", "may be modified"),
    ("missing_index_record", "index and FDE range disagree"),
])
def test_unwind_evidence_rejects_inconsistent_elf_records(change, reason):
    if change == "metadata_relocation":
        data = _elf(relocations=(ef.Reloc(FRAME + 8, 1027),))
    elif change == "missing_index_record":
        data = _elf(((CODE, 12), (CODE + 12, 12)), indexed=(0,))
    else:
        data = _elf()
        fde_offset = FRAME_FILE + struct.unpack_from("<I", data, FRAME_FILE)[0] + 4
        if change == "wrong_header_coverage":
            struct.pack_into("<Q", data, 64 + 2 * 56 + 8, HEADER_FILE + 4)
        elif change == "wrong_frame_pointer":
            data[HEADER_FILE + 4] ^= 1
        elif change == "index_interior_pointer":
            data[HEADER_FILE + 16] += 4
        elif change == "index_wrong_start":
            data[HEADER_FILE + 12] += 4
        elif change == "cie_backpointer":
            data[fde_offset + 4] -= 4
        elif change == "indirect_encoding":
            data[FRAME_FILE + 16] = 0x9B
        elif change == "negative_length":
            struct.pack_into("<i", data, fde_offset + 12, -4)
        else:
            data[fde_offset + 16] = 0x7F
    with pytest.raises(ValueError, match=reason):
        discover(data)


def test_unwind_overlaps_with_other_frames_are_refused():
    rows = discover(_elf(((CODE, 20), (CODE + 12, 12))))
    assert len(rows) == 2 and all("overlaps another FDE" in row.unavailable for row in rows)


@pytest.mark.parametrize("symbol,reason", [
    (("outer", 0x12, CODE, 24), "conflicts with a function symbol"),
    (("resolver", 0x1A, CODE, 12), "indirect-function resolver"),
    (("resolver", 0x1A, CODE, 0), "indirect-function resolver"),
    (("$d.1", 0, CODE + 4, 0), r"\$d data interval"),
])
def test_unwind_discovery_preserves_symbol_and_data_restrictions(symbol, reason):
    row, = discover(_elf(symbols=(symbol,)))
    with pytest.raises(ValueError, match=reason):
        select_unwind((row,), row.id)


def test_unwind_with_exception_personality_is_counted_but_not_exportable():
    row, = discover(_elf(with_exception=True))
    assert (row.link_entry, row.size) == (CODE, 12)
    assert "exception data outside" in row.unavailable


def test_unwind_exact_ordinary_symbol_can_share_its_range():
    row, = discover(_elf(symbols=(("known", 0x12, CODE, 12),)))
    assert row.unavailable is None


def test_unwind_cli_selects_and_exports_without_a_code_address(tmp_path, capsys):
    pytest.importorskip("pypcode")
    file = tmp_path / "without-symbols.elf"
    file.write_bytes(_elf())
    assert arm64_local.main([str(file), "--list-unwind-ranges"]) == 0
    row, = json.loads(capsys.readouterr().out)["unwind_ranges"]
    assert row["basis"] == "eh_frame_fde"
    assert (row["entry"], row["file_offset"], row["size"]) == (CODE, CODE_FILE, len(BODY))
    assert row["index_row_file_offset"] == HEADER_FILE + 12
    report = tmp_path / "result.json"
    assert arm64_local.main([str(file), str(tmp_path / "from-fde"), "--unwind-fde", row["id"],
                             "--g2-out", str(report)]) == 0
    producer = Path(capsys.readouterr().out.strip())
    manual = arm64_local.export(file, tmp_path / "manual", entry=CODE, size=len(BODY))
    assert producer.name == manual.name
    assert (producer / "manifest.json").read_bytes() == (manual / "manifest.json").read_bytes()
    assert json.loads(report.read_bytes())["unwind_range"] == row


def test_unwind_does_not_publish_when_the_selected_graph_is_refused(tmp_path):
    pytest.importorskip("pypcode")
    # One FDE covers two function bodies. The first RET is interior and
    # the existing graph admission path refuses the whole declared range.
    file = tmp_path / "interior-ret.elf"
    data = _elf(((CODE, len(BODY) * 2),))
    file.write_bytes(data)
    row, = discover(data)
    assert row.unavailable is None
    output = tmp_path / "refused"
    with pytest.raises(ValueError, match="misplaced RET"):
        arm64_local.export(file, output, unwind_fde=row.id)
    assert not output.exists()


@pytest.mark.parametrize("entry,size,exec_section", [(FRAME + 8, 4, 3), (HEADER + 8, 4, 2), (HEADER - 4, 8, 1)])
def test_unwind_metadata_cannot_be_selected_as_code_even_with_executable_flags(entry, size, exec_section):
    data = _elf(((entry, size),))
    shoff, = struct.unpack_from("<Q", data, 40)
    struct.pack_into("<Q", data, shoff + exec_section * 64 + 8, 6)
    if exec_section == 1:
        struct.pack_into("<Q", data, shoff + 64 + 32, HEADER - CODE + 4)
    row, = discover(data)
    assert row.unavailable == "unwind code range overlaps ELF unwind metadata"
