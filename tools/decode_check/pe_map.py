"""PE32+ file mapping of G1 decode_check (design r1 s2, r2 s3, r3 s5, r4 s4 / s7):
``pe-loader-rules-6``. Only the file's own headers are read (never Ghidra data).

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

RULES = "pe-loader-rules-6"
IMAGE_FILE_MACHINE_AMD64 = 0x8664
PE32_PLUS = 0x20B
PAGE = 0x1000
LOAD_CONFIG_READ = 0x140
# (offset, label) of IMAGE_LOAD_CONFIG_DIRECTORY64 VA fields whose 8-byte target the loader / CRT writes
LOAD_CONFIG_SLOTS = ((0x58, "security-cookie"), (0x70, "cfg-check-pointer"), (0x78, "cfg-dispatch-pointer"),
                     (0xD8, "rf-failure-routine-pointer"), (0xE8, "rf-verify-sp-pointer"),
                     (0x118, "xfg-check-pointer"), (0x120, "xfg-dispatch-pointer"),
                     (0x128, "xfg-table-dispatch-pointer"),
                     # (winnt.h IMAGE_LOAD_CONFIG_DIRECTORY64.CastGuardOsDeterminedFailureMode: a VA the OS fills)
                     (0x130, "castguard-failure-mode"),
                     (0x138, "memcpy-pointer"))
# (offset, width, label): non-zero -> the loader rewrites code (DVRT) / hybrid image (CHPE) / hot patching
LOAD_CONFIG_REWRITING = ((0xC0, 8, "DynamicValueRelocTable"), (0xC8, 8, "CHPEMetadataPointer"),
                         (0xE0, 4, "DynamicValueRelocTableOffset"), (0xE4, 2, "DynamicValueRelocTableSection"),
                         (0xF0, 4, "HotPatchTableOffset"))


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
    format: str = "pe"
    rules: str = RULES
    fixed_base: bool = True          # (base relocations change code bytes away from the preferred base)
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
    directories: list = field(default_factory=list)  # (rva, size) per data directory (G2b; not in mapping_id)

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
    image.ranges = disjoint(ranges)
    image.header_fields["writable_code_sections"] = [item["name"] for item in sections
                                                     if item["characteristics"] & 0xA0000000 == 0xA0000000]
    directories = []
    count = min(rva_count, (optional_size - 112) // 8)
    for index in range(count):
        directories.append((_u32(data, optional + 112 + 8 * index), _u32(data, optional + 116 + 8 * index)))
    image.directories = directories
    image.relocations = _relocations(image, data, directories)
    image.written = _written(image, data, directories)
    return _finish(image)


def disjoint(ranges: list) -> list:
    """Disjoint, sorted ranges: a byte covered by two or more ranges is ambiguous ("overlapping ranges"),
    whichever came first (rules v5). Shared by elf_map."""
    bounds = sorted({point for item in ranges for point in (item.start, item.end)})
    out = []
    for left, right in zip(bounds, bounds[1:]):
        covering = [item for item in ranges if item.start <= left and right <= item.end]
        if not covering:
            continue
        if len(covering) > 1:
            piece = Range(left, right, "ambiguous", why="overlapping ranges")
        else:
            item = covering[0]
            offset = item.file_offset + (left - item.start) if item.kind == "file" else -1
            piece = Range(left, right, item.kind, offset, item.why)
        last = out[-1] if out else None
        if last and last.end == left and last.kind == piece.kind and last.why == piece.why and \
                (piece.kind != "file" or last.file_offset + (last.end - last.start) == piece.file_offset):
            out[-1] = Range(last.start, right, last.kind, last.file_offset, last.why)
        else:
            out.append(piece)
    return out


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


DVRT_FUNCTION_OVERRIDE = 7
FUNCTION_OVERRIDE_X64_REL32 = 1


def _dvrt(image, data, offset, section, ranges) -> list:
    """The dynamic value relocation table (rules v6): version 1 and FUNCTION_OVERRIDE entries only (winnt.h
    IMAGE_FUNCTION_OVERRIDE_HEADER / _DYNAMIC_RELOCATION / IMAGE_BDD_INFO). Each X64_REL32 relocation is a 4-byte
    rel32 field the loader may rewrite at load time depending on OS state (BDD): written, so those bytes stay
    unobserved without a named load-model premise; the rest of the image is still checked. Layout checked
    against ntdll / kernelbase (every location is the rel32 of an E9 jmp to the overridden function). Any other
    version, symbol, relocation type or a size inconsistency -> a problem (indeterminate). Returns problems."""
    if not section or section > len(image.sections) or not offset:
        return [f"DVRT offset {offset:#x} / section {section} not usable"]
    try:
        table_rva = image.sections[section - 1]["va"] + offset
        version, total = struct.unpack_from("<II", _read(image, data, table_rva, 8))
        if version != 1:
            return [f"DVRT version {version} not modelled"]
        body = _read(image, data, table_rva + 8, total)
    except (_Unreadable, struct.error) as error:
        return [f"DVRT unreadable: {error}"]
    found = []
    cursor = 0
    while cursor < len(body):
        if cursor + 12 > len(body):
            return ["DVRT entry header truncated"]
        symbol, size = struct.unpack_from("<QI", body, cursor)
        entry = body[cursor + 12:cursor + 12 + size]
        if len(entry) != size:
            return ["DVRT entry truncated"]
        cursor += 12 + size
        if symbol != DVRT_FUNCTION_OVERRIDE:
            return [f"DVRT symbol {symbol} not modelled"]
        if size < 4:
            return ["FUNCTION_OVERRIDE header truncated"]
        overrides_size = struct.unpack_from("<I", entry, 0)[0]
        overrides = entry[4:4 + overrides_size]
        if len(overrides) != overrides_size:
            return ["FUNCTION_OVERRIDE records truncated"]
        inner = 0
        while inner < overrides_size:
            if inner + 16 > overrides_size:
                return ["FUNCTION_OVERRIDE record header truncated"]
            _, _, rva_size, reloc_size = struct.unpack_from("<IIII", overrides, inner)
            start = inner + 16 + rva_size
            if rva_size % 4 or start + reloc_size > overrides_size:
                return ["FUNCTION_OVERRIDE record sizes inconsistent"]
            relocs = overrides[start:start + reloc_size]
            r = 0
            while r < reloc_size:
                if r + 8 > reloc_size:
                    return ["FUNCTION_OVERRIDE relocation block truncated"]
                page, block = struct.unpack_from("<II", relocs, r)
                if block < 8 or r + block > reloc_size or block % 2:
                    return ["FUNCTION_OVERRIDE relocation block size inconsistent"]
                for at in range(r + 8, r + block, 2):
                    word = struct.unpack_from("<H", relocs, at)[0]
                    kind, low = word >> 12, word & 0xFFF
                    if kind == 0:
                        continue
                    if kind != FUNCTION_OVERRIDE_X64_REL32:
                        return [f"FUNCTION_OVERRIDE relocation type {kind} not modelled"]
                    found.append((page + low, page + low + 4, "dvrt-function-override (OS-dependent rewrite)"))
                r += block
            inner = start + reloc_size
    ranges.extend(found)
    return []


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
    # load config (IMAGE_LOAD_CONFIG_DIRECTORY64, read up to 0x140): the slots the loader / CRT write, and
    # the fields whose presence means the loader rewrites code bytes or the image is hybrid (rules v5)
    entry = directory(10)
    if entry:
        try:
            head = _read(image, data, entry[0], 4)
            size = _u32(head, 0)
            config = _read(image, data, entry[0], min(size, LOAD_CONFIG_READ))
            for offset, label in LOAD_CONFIG_SLOTS:
                if offset + 8 <= len(config):
                    va = _u64(config, offset)
                    if va:
                        rva = va - image.image_base
                        ranges.append((rva, rva + 8, label))
            present = {label: int.from_bytes(config[offset:offset + width], "little")
                       for offset, width, label in LOAD_CONFIG_REWRITING if offset + width <= len(config)}
            problems = []
            if present.get("DynamicValueRelocTableOffset") or present.get("DynamicValueRelocTableSection"):
                problems.extend("DynamicValueRelocTableOffset / DynamicValueRelocTableSection: " + item
                                for item in _dvrt(image, data, present.get("DynamicValueRelocTableOffset", 0),
                                                  present.get("DynamicValueRelocTableSection", 0), ranges))
            elif present.get("DynamicValueRelocTable"):
                problems.append("DynamicValueRelocTable VA without offset / section (older form, not modelled)")
            for label in ("CHPEMetadataPointer", "HotPatchTableOffset"):
                if present.get(label):
                    problems.append(f"{label} (hybrid / hot-patch metadata not modelled)")
            if problems:
                states.append("indeterminate: load-config code rewriting / hybrid metadata not modelled ("
                              + "; ".join(problems) + ")")
            else:
                states.append("complete")
        except _Unreadable as error:
            states.append(f"indeterminate: load config: {error}")
    if not states:
        return Parsed("absent")
    bad = [item for item in states if item.startswith("indeterminate")]
    return Parsed("indeterminate" if bad else "complete", ranges, "; ".join(bad))
