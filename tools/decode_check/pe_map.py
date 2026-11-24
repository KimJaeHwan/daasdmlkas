"""PE32+ file mapping of G1 decode_check (design r1 s2, r2 s3, r3 s5, r4 s4 / s7):
``pe-loader-rules-4``. Only the file's own headers are read (never Ghidra data).

A range of the image is ``file`` (bytes at a file offset), ``zero`` (zero-fill),
or ``ambiguous`` (the rules do not decide its bytes: never used). Loader- or
runtime-written ranges and relocation ranges are parsed from the file's own
directories; each parse ends ``absent`` / ``complete`` / ``indeterminate``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import struct

RULES = "pe-loader-rules-4"
IMAGE_FILE_MACHINE_AMD64 = 0x8664
PE32_PLUS = 0x20B
PAGE = 0x1000


@dataclass(frozen=True)
class Range:
    start: int            # RVA
    end: int
    kind: str             # file | zero | ambiguous
    file_offset: int = -1
    why: str = ""


@dataclass
class Parsed:
    state: str            # absent | complete | indeterminate
    ranges: list = field(default_factory=list)   # [(rva start, rva end, label)]
    why: str = ""


@dataclass
class PeImage:
    ok: bool
    why: str = ""
    image_base: int = 0
    section_alignment: int = 0
    file_alignment: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    ranges: list = field(default_factory=list)
    sections: list = field(default_factory=list)   # dicts: name, va, vsize, raw, rawsize, state, why
    header_fields: dict = field(default_factory=dict)
    relocations: Parsed = None
    written: Parsed = None                          # IAT, delay-load IAT / handle, TLS index, load-config slots
    mapping_id: str = ""

    def at(self, rva: int) -> Range | None:
        for item in self.ranges:
            if item.start <= rva < item.end:
                return item
        return None


def _u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data, offset):
    return struct.unpack_from("<Q", data, offset)[0]


def _pow2(value):
    return value > 0 and value & (value - 1) == 0


def _align_up(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def parse(data: bytes) -> PeImage:
    try:
        image = _parse(data)
    except (struct.error, IndexError, ValueError) as error:
        image = PeImage(False, f"header parse failed: {error}")
    return image if image.mapping_id else _finish(image)


def _parse(data: bytes) -> PeImage:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return PeImage(False, "not an MZ image")
    lfanew = _u32(data, 0x3C)
    if lfanew + 24 > len(data) or data[lfanew:lfanew + 4] != b"PE\0\0":
        return PeImage(False, "no PE signature")
    coff = lfanew + 4
    machine = _u16(data, coff)
    sections_count = _u16(data, coff + 2)
    optional_size = _u16(data, coff + 16)
    optional = coff + 20
    if machine != IMAGE_FILE_MACHINE_AMD64:
        return PeImage(False, f"machine {machine:#x} is not AMD64")
    if optional + optional_size > len(data) or optional_size < 112:
        return PeImage(False, "optional header outside the file")
    if _u16(data, optional) != PE32_PLUS:
        return PeImage(False, "not PE32+")
    image_base = _u64(data, optional + 24)
    section_alignment = _u32(data, optional + 32)
    file_alignment = _u32(data, optional + 36)
    size_of_image = _u32(data, optional + 56)
    size_of_headers = _u32(data, optional + 60)
    rva_count = _u32(data, optional + 108)
    fields = {"machine": machine, "magic": PE32_PLUS, "image_base": image_base,
              "section_alignment": section_alignment, "file_alignment": file_alignment,
              "size_of_image": size_of_image, "size_of_headers": size_of_headers,
              "number_of_rva_and_sizes": rva_count, "number_of_sections": sections_count,
              "size_of_optional_header": optional_size, "file_size": len(data),
              "file_sha256": hashlib.sha256(data).hexdigest()}
    image = PeImage(True, image_base=image_base, section_alignment=section_alignment, file_alignment=file_alignment,
                    size_of_image=size_of_image, size_of_headers=size_of_headers, header_fields=fields)
    low = section_alignment < PAGE
    # -- global boundaries (r3 s5): a boundary that cannot be trusted makes the whole mapping unusable
    table = optional + optional_size
    table_end = table + 40 * sections_count
    problems = []
    if not (_pow2(section_alignment) and _pow2(file_alignment)):
        problems.append("alignment not a power of two")
    elif low and file_alignment != section_alignment:
        problems.append("low-alignment image with FileAlignment != SectionAlignment")
    elif not low and not (512 <= file_alignment <= 0x10000 and file_alignment <= section_alignment):
        problems.append("FileAlignment out of range")
    if not problems:
        if table_end > len(data):
            problems.append("section table outside the file")
        elif _align_up(table_end, file_alignment) > size_of_headers:
            problems.append("section table end beyond SizeOfHeaders")
        if size_of_headers % file_alignment or size_of_image % section_alignment:
            problems.append("header / image size not aligned")
        if size_of_headers > len(data) or size_of_headers > size_of_image:
            problems.append("SizeOfHeaders beyond the file or the image")
    if problems:
        image.ok = False
        image.why = "; ".join(problems)
        return _finish(image)
    sections = []
    for index in range(sections_count):
        base = table + 40 * index
        sections.append({"index": index, "name": data[base:base + 8].rstrip(b"\0").decode("latin-1"),
                         "va": _u32(data, base + 12), "vsize": _u32(data, base + 8), "rawsize": _u32(data, base + 16),
                         "raw": _u32(data, base + 20), "characteristics": _u32(data, base + 36),
                         "state": "mapped", "why": ""})
    first_va = min((item["va"] for item in sections), default=size_of_image)
    ranges = []
    if size_of_headers > first_va:
        ranges.append(Range(0, size_of_headers, "ambiguous", why="headers overlap the first section"))
    else:
        ranges.append(Range(0, size_of_headers, "file", 0))
    previous_end = size_of_headers
    for item in sorted(sections, key=lambda row: row["va"]):
        va, vsize, raw, rawsize = item["va"], item["vsize"], item["raw"], item["rawsize"]
        why = ""
        if va % section_alignment:
            why = "VirtualAddress not aligned to SectionAlignment"
        elif vsize == 0:
            why = "VirtualSize == 0 (not an adopted loader behaviour, rules v3)"
        elif va < previous_end:
            why = "section overlaps or is out of order"
        elif va + vsize > size_of_image:
            why = "section beyond SizeOfImage"
        elif rawsize and (raw % file_alignment or rawsize % file_alignment):
            why = "raw pointer / size not a multiple of FileAlignment"
        elif rawsize and raw + rawsize > len(data):
            why = "raw data beyond the end of the file"
        elif low and rawsize and raw != va:
            why = "low-alignment section with PointerToRawData != VirtualAddress"
        if why:
            item["state"], item["why"] = "ambiguous", why
            ranges.append(Range(va, va + max(vsize, rawsize, 1), "ambiguous", why=why))
            previous_end = max(previous_end, va + max(vsize, rawsize, 1))
            continue
        mapped = min(rawsize, vsize)
        if mapped:
            ranges.append(Range(va, va + mapped, "file", raw))
        if vsize > mapped:
            ranges.append(Range(va + mapped, va + vsize, "zero"))
        if rawsize > vsize:
            # raw data past VirtualSize up to the section-alignment boundary: the rules do not decide it
            ranges.append(Range(va + vsize, min(va + _align_up(vsize, section_alignment), va + rawsize), "ambiguous",
                                why="raw data beyond VirtualSize"))
        previous_end = va + _align_up(vsize, section_alignment)
    image.sections = sections
    image.ranges = sorted(ranges, key=lambda item: item.start)
    directories = []
    count = min(rva_count, (optional_size - 112) // 8)
    for index in range(count):
        directories.append((_u32(data, optional + 112 + 8 * index), _u32(data, optional + 116 + 8 * index)))
    image.relocations = _relocations(image, data, directories)
    image.written = _written(image, data, directories)
    return _finish(image)


def _finish(image: PeImage) -> PeImage:
    payload = {"rules": RULES, "fields": image.header_fields, "ok": image.ok,
               "ranges": [[r.start, r.end, r.kind, r.file_offset] for r in image.ranges]}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    image.mapping_id = hashlib.sha256(canonical).hexdigest()
    if image.relocations is None:
        image.relocations = Parsed("indeterminate", why=image.why or "no mapping")
    if image.written is None:
        image.written = Parsed("indeterminate", why=image.why or "no mapping")
    return image


class _Unreadable(Exception):
    pass


def _read(image: PeImage, data: bytes, rva: int, size: int) -> bytes:
    """Bytes at an RVA through the mapping (file or zero-fill only)."""
    out = bytearray()
    cursor = rva
    while cursor < rva + size:
        item = image.at(cursor)
        if item is None or item.kind == "ambiguous":
            raise _Unreadable(f"RVA {cursor:#x} not readable")
        take = min(item.end, rva + size) - cursor
        if item.kind == "zero":
            out += bytes(take)
        else:
            offset = item.file_offset + (cursor - item.start)
            out += data[offset:offset + take]
            if offset + take > len(data):
                raise _Unreadable("past the end of the file")
        cursor += take
    return bytes(out)


def _relocations(image, data, directories) -> Parsed:
    if len(directories) <= 5 or directories[5] == (0, 0):
        return Parsed("absent")
    rva, size = directories[5]
    ranges = []
    try:
        block = _read(image, data, rva, size)
        cursor = 0
        while cursor + 8 <= len(block):
            page, block_size = struct.unpack_from("<II", block, cursor)
            if block_size < 8 or cursor + block_size > len(block):
                return Parsed("indeterminate", ranges, "malformed relocation block")
            for entry_at in range(cursor + 8, cursor + block_size - 1, 2):
                entry = _u16(block, entry_at)
                kind, offset = entry >> 12, entry & 0xFFF
                if kind == 0:          # IMAGE_REL_BASED_ABSOLUTE: padding, writes nothing
                    continue
                if kind == 10:         # IMAGE_REL_BASED_DIR64
                    ranges.append((page + offset, page + offset + 8, "DIR64"))
                else:                  # any other type in PE32+: the range is ambiguous (rules v2)
                    ranges.append((page + offset, page + offset + 8, f"type{kind}"))
            cursor += block_size
    except _Unreadable as error:
        return Parsed("indeterminate", ranges, str(error))
    return Parsed("complete", ranges)


def _thunk_count(image, data, rva, limit=1 << 16) -> int:
    count = 0
    while count < limit:
        if _u64(_read(image, data, rva + 8 * count, 8), 0) == 0:
            return count
        count += 1
    raise _Unreadable("thunk array without terminator")


def _written(image, data, directories) -> Parsed:
    ranges = []
    states = []

    def directory(index):
        return directories[index] if len(directories) > index and directories[index] != (0, 0) else None

    # import directory: [FirstThunk, FirstThunk + 8 n), n from OriginalFirstThunk when non-zero (r3 s5)
    entry = directory(1)
    if entry:
        try:
            cursor = entry[0]
            for _ in range(1 << 14):
                descriptor = _read(image, data, cursor, 20)
                if descriptor == bytes(20):
                    break
                oft, first = _u32(descriptor, 0), _u32(descriptor, 16)
                n = _thunk_count(image, data, oft if oft else first)
                ranges.append((first, first + 8 * n, "iat"))
                cursor += 20
            states.append("complete")
        except _Unreadable as error:
            states.append(f"indeterminate: import directory: {error}")
    # delay-load: the module handle and the IAT the helper writes at run time (r2 s4, r4 s4)
    entry = directory(13)
    if entry:
        try:
            cursor = entry[0]
            for _ in range(1 << 12):
                descriptor = _read(image, data, cursor, 32)
                if descriptor == bytes(32):
                    break
                handle, iat, names = _u32(descriptor, 8), _u32(descriptor, 12), _u32(descriptor, 16)
                if handle:
                    ranges.append((handle, handle + 8, "delay-module-handle"))
                n = _thunk_count(image, data, names if names else iat)
                ranges.append((iat, iat + 8 * n, "delay-iat"))
                cursor += 32
            states.append("complete")
        except _Unreadable as error:
            states.append(f"indeterminate: delay-load directory: {error}")
    # TLS: the 4-byte index slot AddressOfIndex designates
    entry = directory(9)
    if entry:
        try:
            tls = _read(image, data, entry[0], 40)
            index_va = _u64(tls, 16)
            if index_va:
                rva = index_va - image.image_base
                ranges.append((rva, rva + 4, "tls-index"))
            states.append("complete")
        except _Unreadable as error:
            states.append(f"indeterminate: TLS directory: {error}")
    # load config: the security cookie (CRT, run time) and the CFG check / dispatch pointer slots (loader)
    entry = directory(10)
    if entry:
        try:
            head = _read(image, data, entry[0], 4)
            size = _u32(head, 0)
            config = _read(image, data, entry[0], min(size, 0x100))
            for offset, label in ((0x58, "security-cookie"), (0x70, "cfg-check-pointer"),
                                  (0x78, "cfg-dispatch-pointer")):
                if offset + 8 <= len(config):
                    va = _u64(config, offset)
                    if va:
                        rva = va - image.image_base
                        ranges.append((rva, rva + 8, label))
            states.append("complete")
        except _Unreadable as error:
            states.append(f"indeterminate: load config: {error}")
    if not states:
        return Parsed("absent")
    bad = [item for item in states if item.startswith("indeterminate")]
    return Parsed("indeterminate" if bad else "complete", ranges, "; ".join(bad))
