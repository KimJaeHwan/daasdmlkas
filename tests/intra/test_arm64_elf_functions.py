"""Symbol ranges are reconciled with the ELF mapping before a graph is published."""

import json
from pathlib import Path
import struct
import sys

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "bundle_export"))

import arm64_local
import _elf_fixture as ef
import elf_map
from arm64_elf_functions import function_ranges, select_range

ENTRY = 0x401000
BASE = 0x400000
BODY = bytes.fromhex("e10700f9 e80740f9 c0035fd6")


def _elf(*tables, code=BODY * 4, relocations=(), e_type=2, code_offset=0x1000, elf_entry=ENTRY):
    image = bytearray(ef.make_elf([ef.Segment(ENTRY, code, offset=0x1000)], e_type=e_type, link_base=BASE,
                                 machine=183, dynamic=bool(relocations), relocations=relocations).data)
    sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
                (0, 1, 6, ENTRY, code_offset, len(code), 0, 0, 4, 0)]
    for table_kind, symbols in tables:
        strings = bytearray(b"\0")
        entries = bytearray(24)
        for name, info, section_index, entry, size in symbols:
            name_offset = len(strings)
            strings.extend(name.encode("utf-8") + b"\0")
            entries.extend(struct.pack("<IBBHQQ", name_offset, info, 0, section_index, entry, size))
        section = len(sections)
        local_boundary = 1 + sum(row[1] >> 4 == 0 for row in symbols)
        sections.append((0, 3, 0, 0, len(image), len(strings), 0, 0, 1, 0))
        image.extend(strings)
        image.extend(bytes(-len(image) % 8))
        sections.append((0, table_kind, 0, 0, len(image), len(entries), section, local_boundary, 8, 24))
        image.extend(entries)
    image.extend(bytes(-len(image) % 8))
    struct.pack_into("<Q", image, 24, elf_entry)
    struct.pack_into("<Q", image, 40, len(image))
    struct.pack_into("<HHH", image, 58, 64, len(sections), 0)
    for row in sections:
        image.extend(struct.pack("<IIQQQQIIQQ", *row))
    return image


def fn(name, entry=ENTRY, size=len(BODY), *, info=0x12):
    return name, info, 1, entry, size


def discover(data):
    mapping = elf_map.parse(data, arm64_page=4096)
    assert mapping.ok
    return function_ranges(data, mapping, 65536)


def test_symbol_aliases_discovery_and_exact_name():
    data = _elf((2, [fn("first"), fn("alias")]),
                (11, [fn("first"), fn("another", ENTRY + 12)]))
    ranges = discover(data)
    first, following = ranges
    assert first.unavailable is following.unavailable is None
    assert first.names == ("alias", "first")
    assert (first.link_entry, first.size, first.file_offset) == (ENTRY, len(BODY), 0x1000)
    assert [(origin.table, origin.table_index, origin.symbol_index) for origin in first.origins] == [
        ("symtab", 3, 1), ("symtab", 3, 2), ("dynsym", 5, 1),
    ]
    assert select_range(ranges, name="alias") == select_range(ranges, elf_entry=ENTRY) == first
    with pytest.raises(ValueError, match="no defined function range"):
        select_range(ranges, name="First")


@pytest.mark.parametrize("symbols,name,reason", [
    ([fn("older", size=24), fn("inner", ENTRY + 4, 8)], "inner", "overlaps another"),
    ([fn("same"), fn("same", ENTRY + 12)], "same", "ambiguous function"),
    ([fn("same"), fn("same", ENTRY + 12, 0)], "same", "ambiguous function"),
    ([fn("unknown", size=0)], "unknown", "zero size"),
    ([fn("resolver", info=0x1A)], "resolver", "indirect-function"),
    ([fn("cross", size=52)], "cross", "within its executable file section"),
    ([fn("unaligned", ENTRY + 1, 12)], "unaligned", "not aligned"),
    ([fn("$d.extra", ENTRY, 0, info=0), fn("$x.1", ENTRY + 16, 0, info=0),
      fn("inline", ENTRY + 4, 12)], "inline", r"\$d data interval"),
])
def test_uncertain_symbol_ranges_are_refused(symbols, name, reason):
    with pytest.raises(ValueError, match=reason):
        select_range(discover(_elf((2, symbols))), name=name)


def test_mapping_data_interval_ends_at_the_next_code_marker():
    data = _elf((2, [fn("$d", ENTRY, 0, info=0), fn("$x", ENTRY + 12, 0, info=0),
                     fn("starts_after_data", ENTRY + 12)]))
    assert select_range(discover(data), name="starts_after_data").unavailable is None


def test_section_load_mapping_disagreement_is_refused():
    ranges = discover(_elf((2, [fn("different_bytes")]), code_offset=0x1004))
    with pytest.raises(ValueError, match="refer to different file bytes"):
        select_range(ranges, name="different_bytes")


def test_loader_write_does_not_hide_a_range_collision():
    data = _elf((2, [fn("outer", size=28), fn("inner", ENTRY + 4, 8)]),
                relocations=[ef.Reloc(ENTRY + 16, 1027)])
    outer, inner = discover(data)
    assert "loader write" in outer.unavailable
    assert "overlaps another" in outer.unavailable
    assert inner.unavailable == "function range overlaps another symbol range"


def test_allocated_symbol_table_must_match_its_loaded_bytes():
    data = _elf((11, [fn("wrong_table")]))
    shoff = struct.unpack_from("<Q", data, 40)[0]
    struct.pack_into("<QQ", data, shoff + 3 * 64 + 8, 2, ENTRY)
    with pytest.raises(ValueError, match="symbol metadata does not name its mapped file bytes"):
        discover(data)


def test_symbol_string_bounds_are_checked():
    data = _elf((2, [fn("name")]))
    shoff = struct.unpack_from("<Q", data, 40)[0]
    table_offset = struct.unpack_from("<Q", data, shoff + 3 * 64 + 24)[0]
    struct.pack_into("<I", data, table_offset + 24, 0xFFFFFFFF)
    with pytest.raises(ValueError, match="symbol name is outside"):
        discover(data)


def test_no_function_symbols_or_exact_entry_does_not_guess():
    assert discover(_elf()) == ()
    with pytest.raises(ValueError, match="exact ELF entry point has no defined"):
        select_range(discover(_elf((2, [fn("other", ENTRY + 12)]))), elf_entry=ENTRY)


def test_exact_entry_and_symbol_export_same_bundle_and_graph(tmp_path, capsys):
    pytest.importorskip("pypcode")
    from tdo_v2.integration.standalone_arm64 import build_standalone_arm64_graphs

    elf = tmp_path / "a.elf"
    elf.write_bytes(_elf((2, [fn("selected")])))
    old = arm64_local.export(elf, tmp_path / "manual", entry=ENTRY, size=len(BODY))
    found = arm64_local.export(elf, tmp_path / "auto")
    assert (old / "manifest.json").read_bytes() == (found / "manifest.json").read_bytes()

    report = tmp_path / "graph.json"
    assert arm64_local.main([str(elf), str(tmp_path / "named"), "--function", "selected",
                             "--g2-out", str(report)]) == 0
    named = Path(capsys.readouterr().out.strip())
    ranges = json.loads(report.read_bytes())["function_range"]
    assert old.name == found.name == named.name
    assert (ranges["names"], ranges["entry"], ranges["size"]) == (["selected"], ENTRY, len(BODY))
    snapshot, _ = build_standalone_arm64_graphs(named)
    assert len(snapshot.graphs) == 1


def test_automatic_export_keeps_refused_graph_out_of_output(tmp_path, monkeypatch):
    pytest.importorskip("pypcode")
    elf = tmp_path / "a.elf"
    elf.write_bytes(_elf((2, [fn("selected")])))

    def rejected(path):
        assert (path / "seal.json").exists()
        raise ValueError("graph was refused")

    monkeypatch.setattr(arm64_local, "_check_graph", rejected)
    output = tmp_path / "auto"
    with pytest.raises(ValueError, match="graph was refused"):
        arm64_local.export(elf, output, function="selected")
    assert list(output.iterdir()) == []


def test_rebased_listing_has_in_range_loaded_address_and_refuses_overflow(tmp_path, capsys):
    elf = tmp_path / "a.elf"
    elf.write_bytes(_elf((2, [fn("selected")]), e_type=3))
    assert arm64_local.main([str(elf), "--base", "0x800000", "--list-functions"]) == 0
    found = json.loads(capsys.readouterr().out)["functions"][0]
    assert found["entry"] == 0x801000 and found["load_bias"] == 0x400000
    assert arm64_local.main([str(elf), "--base", "0xfffffffffffff000", "--list-functions"]) == 1
    assert "incompatible" in capsys.readouterr().err


@pytest.mark.parametrize("defect", ["null", "partition", "table_overlap"])
def test_malformed_symbol_tables_are_refused(defect):
    data = _elf((2, [fn("name")]), (11, [fn("next", ENTRY + 12)]))
    shoff = struct.unpack_from("<Q", data, 40)[0]
    table_offset = struct.unpack_from("<Q", data, shoff + 3 * 64 + 24)[0]
    if defect == "null":
        data[table_offset] = 1
    elif defect == "partition":
        struct.pack_into("<I", data, shoff + 3 * 64 + 44, 2)
    else:
        struct.pack_into("<Q", data, shoff + 5 * 64 + 24, table_offset)
    with pytest.raises(ValueError, match="local boundary|tables overlap"):
        discover(data)
