"""Resolve function ranges from ARM64 ELF symbols against the executable file mapping."""

from bisect import bisect_left
from collections import defaultdict
from dataclasses import dataclass
import struct
from typing import NamedTuple

import elf_map


_SECTION = struct.Struct("<IIQQQQIIQQ")
_SYMBOL = struct.Struct("<IBBHQQ")
_PROGBITS, _SYMTAB, _STRTAB, _DYNSYM = 1, 2, 3, 11
_ALLOC_EXEC, _COMPRESSED = elf_map.SHF_ALLOC | 0x4, 0x800
_STT_FUNC, _STT_GNU_IFUNC, _RESERVED_SECTION = 2, 10, 0xFF00


class _Section(NamedTuple):
    name: int
    kind: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int


@dataclass(frozen=True)
class SymbolOrigin:
    name: str
    table: str
    table_index: int
    symbol_index: int
    section_index: int


@dataclass(frozen=True)
class FunctionRange:
    link_entry: int
    size: int
    file_offset: int | None
    origins: tuple[SymbolOrigin, ...]
    unavailable: str | None

    @property
    def names(self):
        return tuple(sorted({origin.name for origin in self.origins if origin.name}))


def _executable_offset(mapping, link_entry, size):
    start = link_entry - mapping.image_base
    end = start + size
    span = mapping.at(start)
    containing = [segment for segment in mapping.segments if segment["flags"] & 1
                  and segment["vaddr"] <= link_entry
                  and link_entry + size <= segment["vaddr"] + segment["filesz"]]
    if span is None or span.kind != "file" or end > span.end or len(containing) != 1:
        raise ValueError("function bytes require one file-backed executable PT_LOAD span")
    return span.file_offset + start - span.start


def _require_loader_stable(mapping, link_entry, size):
    start = link_entry - mapping.image_base
    end = start + size
    if mapping.written.state != "complete" or any(a < end and start < b for a, b, _ in mapping.written.ranges):
        raise ValueError("function span may be modified by a modeled ELF loader write")


def code_file_offset(mapping, link_entry, size):
    offset = _executable_offset(mapping, link_entry, size)
    _require_loader_stable(mapping, link_entry, size)
    return offset


def _sections(data, mapping):
    start, count, stride = (mapping.header_fields[key] for key in ("e_shoff", "e_shnum", "e_shentsize"))
    if start == count == 0:
        return ()
    if start < 64 or not 0 < count < _RESERVED_SECTION or stride != _SECTION.size or start + count * stride > len(data):
        raise ValueError("ARM64 ELF section table is malformed or uses extended indexing")
    return tuple(_Section(*_SECTION.unpack_from(data, start + i * stride)) for i in range(count))


def _string_table(data, mapping, sections, table):
    if (not 0 < table.link < len(sections) or table.entry_size != _SYMBOL.size
            or not table.size or table.size % _SYMBOL.size or table.offset + table.size > len(data)
            or table.flags & _COMPRESSED):
        raise ValueError("malformed ARM64 ELF symbol table")
    if (not 1 <= table.info <= table.size // _SYMBOL.size
            or any(data[table.offset:table.offset + _SYMBOL.size])):
        raise ValueError("ARM64 ELF symbol table has invalid null entry or local boundary")
    strings = sections[table.link]
    start, end = strings.offset, strings.offset + strings.size
    if (strings.kind != _STRTAB or strings.flags & _COMPRESSED or start >= end or end > len(data)
            or data[start] != 0 or data[end - 1] != 0):
        raise ValueError("malformed ARM64 ELF symbol string table")
    for section in (table, strings):
        if section.flags & elf_map.SHF_ALLOC and not elf_map._maps_file_table(
                mapping, section.address, section.offset, section.size):
            raise ValueError("allocated ARM64 ELF symbol metadata does not name its mapped file bytes")
    return start, end


def _marker(name):
    for kind in ("$x", "$d"):
        if name == kind or name.startswith(kind + "."):
            return kind
    return None


def _symbol_rows(data, mapping, sections):
    tables = [(index, section) for index, section in enumerate(sections) if section.kind in (_SYMTAB, _DYNSYM)]
    extents = sorted((table.offset, table.offset + table.size) for _, table in tables)
    if any(left[1] > right[0] for left, right in zip(extents, extents[1:])):
        raise ValueError("ARM64 ELF symbol tables overlap in the file")
    for table_index, table in tables:
        start, end = _string_table(data, mapping, sections, table)
        names = {0: ""}
        table_name = "symtab" if table.kind == _SYMTAB else "dynsym"
        for index in range(1, table.size // _SYMBOL.size):
            name_offset, info, _, section, entry, size = _SYMBOL.unpack_from(data, table.offset + index * _SYMBOL.size)
            if (info >> 4 == 0) != (index < table.info):
                raise ValueError("ARM64 ELF symbol bindings disagree with the local boundary")
            sym_type = info & 0xF
            if section == 0 or (sym_type not in (_STT_FUNC, _STT_GNU_IFUNC) and info != 0):
                continue
            if not start <= start + name_offset < end:
                raise ValueError("ARM64 ELF symbol name is outside its string table")
            if name_offset not in names:
                last = data.index(b"\x00", start + name_offset, end)
                names[name_offset] = data[start + name_offset:last].decode("utf-8", errors="surrogateescape")
            origin = SymbolOrigin(names[name_offset], table_name, table_index, index, section)
            yield sym_type, origin, entry, size


def _data_intervals(sections, markers):
    result = {}
    for index, values in markers.items():
        points = sorted(values)
        end = sections[index].address + sections[index].size
        bounds = points[1:] + [end]
        result[index] = [(start, following) for start, following in zip(points, bounds)
                         if "$d" in values[start] and start < following]
    return result


def _section_offset(entry, size, section, data_size):
    if (section.kind != _PROGBITS or section.flags & _ALLOC_EXEC != _ALLOC_EXEC or section.flags & _COMPRESSED
            or section.offset + section.size > data_size or section.address + section.size > elf_map.U64_END
            or not section.address <= entry < entry + size <= section.address + section.size):
        raise ValueError("symbol is not wholly within its executable file section")
    return section.offset + entry - section.address


def _overlaps(ranges):
    """Exact aliases are grouped first. Adjacent half-open ranges never overlap."""
    conflicts = set()
    widest = None
    end = 0
    for entry, size in sorted(ranges):
        current = (entry, size)
        if widest is not None and entry < end:
            conflicts.update((widest, current))
        if entry + size > end:
            widest, end = current, entry + size
    return conflicts


def _symbol_inputs(data, mapping, sections):
    groups = defaultdict(list)
    markers = defaultdict(lambda: defaultdict(set))
    for kind, origin, entry, size in _symbol_rows(data, mapping, sections):
        if kind == 0:
            marker = _marker(origin.name)
            if marker is not None:
                index = origin.section_index
                if size or not 0 < index < len(sections):
                    raise ValueError("malformed ARM64 ELF mapping symbol")
                section = sections[index]
                if not section.address <= entry <= section.address + section.size:
                    raise ValueError("ARM64 ELF mapping symbol is outside its section")
                markers[index][entry].add(marker)
        else:
            groups[entry, size].append((kind, origin))
    return groups, _data_intervals(sections, markers)


def _touches_data(data_intervals, section, entry, size):
    intervals = data_intervals.get(section, ())
    position = bisect_left(intervals, (entry + size,))
    return bool(position and intervals[position - 1][1] > entry)


def function_ranges(data, mapping, max_size):
    sections = _sections(data, mapping)
    groups, data_intervals = _symbol_inputs(data, mapping, sections)
    return _function_ranges(data, mapping, sections, groups, data_intervals, max_size)


def _function_ranges(data, mapping, sections, groups, data_intervals, max_size):
    offsets, unavailable = {}, {}
    for (entry, size), rows in groups.items():
        try:
            indexes = {origin.section_index for _, origin in rows}
            if len(indexes) != 1 or not all(0 < i < len(sections) for i in indexes):
                raise ValueError("function symbols have conflicting or unsupported section indices")
            index, = indexes
            if not size:
                raise ValueError("function symbol has zero size")
            offset = _section_offset(entry, size, sections[index], len(data))
            if offset != _executable_offset(mapping, entry, size):
                raise ValueError("function section and PT_LOAD refer to different file bytes")
            offsets[entry, size] = offset
            _require_loader_stable(mapping, entry, size)
            if _touches_data(data_intervals, index, entry, size):
                raise ValueError("function range overlaps an AArch64 $d data interval")
            if any(kind == _STT_GNU_IFUNC for kind, _ in rows):
                raise ValueError("indirect-function resolver symbol is outside the standalone profile")
            if entry % 4 or size % 4 or size > max_size:
                raise ValueError(f"function range is not aligned or exceeds {max_size} bytes")
        except ValueError as error:
            unavailable[entry, size] = str(error)

    for key in _overlaps(offsets):
        reason = "function range overlaps another symbol range"
        if key in unavailable:
            reason = f"{unavailable[key]}; {reason}"
        unavailable[key] = reason
    return tuple(FunctionRange(entry, size, offsets.get((entry, size)), tuple(origin for _, origin in rows),
                               unavailable.get((entry, size)))
                 for (entry, size), rows in sorted(groups.items()))


def select_range(ranges, *, name=None, elf_entry=0):
    if name is None:
        candidates = [function for function in ranges if elf_entry and function.link_entry == elf_entry]
        label = "exact ELF entry point"
    else:
        candidates = [function for function in ranges if name in function.names]
        label = f"function symbol {name!r}"
    if not candidates:
        raise ValueError(f"{label} has no defined function range; use --list-functions to inspect available symbols")
    if len(candidates) != 1:
        raise ValueError(f"{label} has ambiguous function ranges")
    selected, = candidates
    if selected.unavailable is not None:
        raise ValueError(f"{label}: {selected.unavailable}")
    return selected
