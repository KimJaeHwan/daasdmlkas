"""Read bounded ARM64 unwind extents from agreeing ELF frame and index records."""

from dataclasses import dataclass
import struct

import elf_map
from arm64_elf_functions import (
    _COMPRESSED, _PROGBITS, _STRTAB, _STT_GNU_IFUNC, _executable_offset, _function_ranges, _overlaps,
    _require_loader_stable, _section_offset, _sections, _symbol_inputs, _touches_data,
)


_PT_GNU_EH_FRAME = 0x6474E550
_HEADER_FORMAT = bytes((1, 0x1B, 0x03, 0x3B))
_PCREL_SDATA4 = 0x1B
_PERSONALITY_WIDTHS = {0x9B: 4, 0x9C: 8}


@dataclass(frozen=True)
class UnwindRange:
    link_entry: int
    size: int
    file_offset: int | None
    cie_offset: int
    fde_offset: int
    fde_file_offset: int
    index_row_file_offset: int
    frame_section_index: int
    header_segment_index: int
    unavailable: str | None

    @property
    def id(self):
        return f"fde-{self.fde_offset:08x}"


def _named_sections(data, sections):
    names_index = struct.unpack_from("<H", data, 62)[0]
    if not 0 < names_index < len(sections):
        raise ValueError("ELF unwind discovery requires named section headers")
    names = sections[names_index]
    first, end = names.offset, names.offset + names.size
    if (names.kind != _STRTAB or names.flags & _COMPRESSED or not first < end <= len(data)
            or data[first] != 0 or data[end - 1] != 0):
        raise ValueError("malformed ELF section name table")
    wanted = {b".eh_frame": [], b".eh_frame_hdr": []}
    for index, section in enumerate(sections):
        if not first <= first + section.name < end:
            raise ValueError("ELF section name is outside the string table")
        start = first + section.name
        name = data[start:data.index(b"\0", start, end)]
        if name in wanted:
            wanted[name].append((index, section))
    if any(len(entries) != 1 for entries in wanted.values()):
        raise ValueError("ELF unwind discovery requires one .eh_frame and one .eh_frame_hdr")
    return wanted[b".eh_frame"][0], wanted[b".eh_frame_hdr"][0]


def _metadata_bytes(data, mapping, section):
    if (section.kind != _PROGBITS or not section.flags & elf_map.SHF_ALLOC or section.flags & _COMPRESSED
            or not section.size or section.offset + section.size > len(data)
            or not elf_map._maps_file_table(mapping, section.address, section.offset, section.size)):
        raise ValueError("ELF unwind metadata does not name uniquely mapped file bytes")
    _require_loader_stable(mapping, section.address, section.size)
    return data[section.offset:section.offset + section.size]


def _header_index(data, mapping, header, frame_address):
    phdrs = [(index, ph) for index, ph in enumerate(mapping.phdrs) if ph[0] == _PT_GNU_EH_FRAME]
    if len(phdrs) != 1:
        raise ValueError("ELF unwind discovery requires one PT_GNU_EH_FRAME")
    (segment_index, (_, _, offset, address, _, filesz, memsz, _)), = phdrs
    if (offset, address, filesz, memsz) != (header.offset, header.address, header.size, header.size):
        raise ValueError("ELF unwind header section and program header disagree")
    payload = _metadata_bytes(data, mapping, header)
    if len(payload) < 12 or payload[:4] != _HEADER_FORMAT:
        raise ValueError("unsupported ELF unwind header encoding")
    relative_frame, count = struct.unpack_from("<iI", payload, 4)
    if header.address + 4 + relative_frame != frame_address or len(payload) != 12 + count * 8:
        raise ValueError("ELF unwind header has a wrong frame pointer or table size")

    result = {}
    previous = -1
    for offset in range(12, len(payload), 8):
        relative_start, relative_fde = struct.unpack_from("<ii", payload, offset)
        entry = header.address + relative_start
        fde_offset = header.address + relative_fde - frame_address
        if not previous < entry < elf_map.U64_END or fde_offset in result:
            raise ValueError("ELF unwind index has duplicate or unordered entries")
        result[fde_offset] = (entry, header.offset + offset)
        previous = entry
    return segment_index, result


def _leb(data, position, limit, *, signed=False):
    value = 0
    for shift in range(0, 70, 7):
        if position >= limit:
            break
        byte = data[position]
        position += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80:
            continue
        if signed and byte & 0x40:
            value -= 1 << (shift + 7)
        lower, upper = (-(1 << 63), 1 << 63) if signed else (0, elf_map.U64_END)
        if lower <= value < upper:
            return value, position
        break
    raise ValueError("truncated or oversized LEB128 in ELF unwind record")


def _augmentation(data, position, limit):
    size, first = _leb(data, position, limit)
    end = first + size
    if end > limit:
        raise ValueError("ELF unwind augmentation exceeds its record")
    return data[first:end]


def _cie_profile(data, start, end):
    if start >= end or data[start] != 1:
        raise ValueError("unsupported ELF unwind CIE version")
    stop = data.find(b"\0", start + 1, end)
    if stop < 0:
        raise ValueError("unterminated ELF unwind CIE augmentation name")
    name = data[start + 1:stop]
    if name not in (b"zR", b"zPLR"):
        raise ValueError("unsupported ELF unwind CIE augmentation")
    code_alignment, position = _leb(data, stop + 1, end)
    data_alignment, position = _leb(data, position, end, signed=True)
    if not code_alignment or not data_alignment or position >= end or data[position] != 30:
        raise ValueError("unsupported ARM64 unwind CIE alignment or return register")
    augmentation = _augmentation(data, position + 1, end)
    if name == b"zR" and augmentation == bytes((_PCREL_SDATA4,)):
        return 0
    if name == b"zPLR" and augmentation:
        width = _PERSONALITY_WIDTHS.get(augmentation[0])
        if width is not None and augmentation[width + 1:] == bytes((0x1C, _PCREL_SDATA4)):
            # Only its extent is decoded. The personality and LSDA are not resolved.
            return 8
    raise ValueError("unsupported ELF unwind pointer encoding")


def _frame_entries(data, section, index):
    cies, frames = {}, {}
    offset = 0
    while offset < len(data):
        if offset + 4 > len(data):
            raise ValueError("truncated ELF unwind record length")
        length, = struct.unpack_from("<I", data, offset)
        if length == 0:
            if any(data[offset + 4:]):
                raise ValueError("ELF unwind section has data after its terminator")
            break
        end = offset + 4 + length
        if length < 4 or length % 4 or end > len(data):
            raise ValueError("unsupported or truncated ELF unwind record")
        reference, = struct.unpack_from("<I", data, offset + 4)
        if reference == 0:
            cies[offset] = _cie_profile(data, offset + 8, end)
        else:
            cie_offset = offset + 4 - reference
            if cie_offset not in cies or end < offset + 17:
                raise ValueError("ELF unwind FDE lacks a valid preceding CIE or range")
            delta, size = struct.unpack_from("<ii", data, offset + 8)
            entry = section.address + offset + 8 + delta
            expected = index.get(offset)
            if (not 0 <= entry < entry + size <= elf_map.U64_END
                    or expected is None or expected[0] != entry):
                raise ValueError("ELF unwind index and FDE range disagree")
            if len(_augmentation(data, offset + 16, end)) != cies[cie_offset]:
                raise ValueError("ELF unwind FDE augmentation disagrees with its CIE")
            frames[offset] = (entry, size, cie_offset, expected[1], bool(cies[cie_offset]))
        offset = end
    if frames.keys() != index.keys():
        raise ValueError("ELF unwind index does not identify exactly the FDE records")
    return frames


def _code_range(data, mapping, sections, data_intervals, entry, size):
    offsets = []
    for index, section in enumerate(sections):
        if section.flags & 0x4 and section.address <= entry < entry + size <= section.address + section.size:
            offsets.append((index, _section_offset(entry, size, section, len(data))))
    if len(offsets) != 1 or offsets[0][1] != _executable_offset(mapping, entry, size):
        raise ValueError("unwind code range section and PT_LOAD do not agree")
    (section_index, offset), = offsets
    if _touches_data(data_intervals, section_index, entry, size):
        raise ValueError("unwind code range overlaps an AArch64 $d data interval")
    _require_loader_stable(mapping, entry, size)
    return offset


def unwind_ranges(data, mapping, max_size):
    sections = _sections(data, mapping)
    (frame_index, frame), (_, header) = _named_sections(data, sections)
    header_segment, index = _header_index(data, mapping, header, frame.address)
    frames = _frame_entries(_metadata_bytes(data, mapping, frame), frame, index)
    groups, data_intervals = _symbol_inputs(data, mapping, sections)
    symbols = _function_ranges(data, mapping, sections, groups, data_intervals, max_size)
    symbol_spans = [(s.link_entry, s.size) for s in symbols if s.file_offset is not None]
    unavailable_symbols = {(s.link_entry, s.size) for s in symbols if s.unavailable is not None}
    resolver_starts = {entry for (entry, _size), records in groups.items()
                       if any(kind == _STT_GNU_IFUNC for kind, _ in records)}
    conflicts = _overlaps([(entry, size) for entry, size, *_ in frames.values()])
    result = []
    for fde_offset, (entry, size, cie_offset, index_offset, exception_data) in sorted(frames.items()):
        reason = offset = None
        try:
            if exception_data:
                raise ValueError("unwind range has personality or exception data outside the standalone profile")
            if entry % 4 or size % 4 or not 4 <= size <= max_size:
                raise ValueError(f"unwind code range is not aligned or exceeds {max_size} bytes")
            if any(section.address < entry + size and entry < section.address + section.size
                   for section in (frame, header)):
                raise ValueError("unwind code range overlaps ELF unwind metadata")
            if (entry, size) in conflicts:
                raise ValueError("unwind code range overlaps another FDE")
            if entry in resolver_starts:
                raise ValueError("unwind code range starts at an ELF indirect-function resolver")
            if (entry, size) in unavailable_symbols:
                raise ValueError("unwind code range matches a refused function symbol")
            if any((start, length) != (entry, size) and start < entry + size and entry < start + length
                   for start, length in symbol_spans):
                raise ValueError("unwind code range conflicts with a function symbol")
            offset = _code_range(data, mapping, sections, data_intervals, entry, size)
        except ValueError as error:
            reason = str(error)
        result.append(UnwindRange(entry, size, offset, cie_offset, fde_offset, frame.offset + fde_offset,
                                  index_offset, frame_index, header_segment, reason))
    return tuple(result)


def select_unwind(ranges, identifier):
    for row in ranges:
        if row.id == identifier:
            if row.unavailable is not None:
                raise ValueError(f"ELF unwind range {identifier}: {row.unavailable}")
            return row
    raise ValueError(f"ELF unwind range {identifier!r} is absent. Use --list-unwind-ranges on this file")
