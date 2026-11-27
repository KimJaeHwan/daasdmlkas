"""G2b code-byte facts (design_tbr_g2b_code_facts r1 + r2 + r3; closed G2 design r5 s5 / s9).

File layer (this part): Bundle-independent parsing of the original file into file coordinates (offsets from the
map's ``image_base``: the PE RVA / the ELF offset from the lowest PT_LOAD page). Two byte bases (r2 E1):

- ``file_record``: what the file records as lookup data (import / delay-import tables, ILT and initial FirstThunk,
  ELF dynamic tags, relocation tables, dynsym / dynstr, section headers, the exception directory and UNWIND_INFO
  read as table structure). Read only from ``file`` ranges of the map (never zero-fill or ambiguous), allowed inside
  loader-written ranges: the basis is the pre-load value.
- ``file_runtime``: bytes as they are at run time (register-pointed strings). Additionally not loader-written, not
  relocated, and the written / relocation parses must be complete (else MAP_INDETERMINATE).

Everything here reads the file through the G1 maps (``pe_map`` / ``elf_map``); nothing reads Ghidra data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import struct

FACTS_RULE = "g2b-1"
PREMISE = "image-code-unmodified-at-runtime"
IMPORT_PREMISE = "import-slot-holds-loader-bound-import"
LINEAR_PREMISE = "linear-entry-at-first-path-row"
VERIFIED_THRESHOLD = 8_388_608          # canonical UTF-8 bytes of all explicit verified lists of one Bundle (r3 E6)

# closed reason-code enum (r1 s1); a code not listed here is a programming error
REASONS = frozenset({
    # byte bases
    "ZERO_FILL", "AMBIGUOUS_MAPPING", "LOADER_WRITTEN", "RELOCATED", "OUTSIDE_FILE", "TRUNCATED",
    "NONCONTIGUOUS", "MAP_INDETERMINATE",
    # regions / unwind
    "HANDLER_DATA_LENGTH", "UNWIND_VERSION", "UNWIND_FLAGS", "UNWIND_INDIRECT", "CHAIN_CYCLE", "NO_SECTION_HEADERS",
    "EH_FRAME_PTR_ENCODING", "EH_FRAME_PTR_OMITTED", "SECTION_NOT_LOADED", "MAP_NOT_OK",
    # trap
    "NO_WINDOW", "GLOBAL_REASON", "BALLOT_MISSING", "RELOCATED_OPCODE", "TRAP_FORM_UNDECIDED", "VENDOR_SPLIT_FORM",
    "ALL_INVALID_NOT_CE", "NO_ABI_BASIS", "G2C",
    # imports and transfers
    "TRANSFER_UNBOUND", "SEGMENT_BASE", "POINTER_WIDTH", "SPACE_MISMATCH", "VENDOR_VIEW_CONFLICT", "FORM_MISMATCH",
    "SLOT_NOT_IMPORT", "PARSER_UNSUPPORTED", "SLOT_NAME_U", "NO_IMPORT_DIRECTORY", "IMPORT_BY_ORDINAL",
    "TARGET_LIFT_U", "ELF_STUB_UNSUPPORTED", "ELF_RELOC_UNSUPPORTED", "MULTI_HOP", "TARGET_NOT_ROW_START",
    "TARGET_OUTSIDE_ROWS", "INDEX_INCOMPLETE", "COMPUTED_TARGET", "BOUND_IAT_NO_ILT", "ILT_ENTRY_INVALID",
    "DELAY_FORMAT", "SYM_COUNT_U", "NO_RWX_REGISTER",
    # stores / values
    "STORE_ADDRESS_NOT_CONSTANT", "STORE_WIDTH_U", "STORE_SPACE_U", "ADDRESS_WRAP", "TARGET_MAPPING_U",
    "INTRA_ROW_FLOW",
    # survey
    "NOT_X86",
})


class Unread(Exception):
    """A read that fails a byte-basis test; ``reason`` is in REASONS."""

    def __init__(self, reason, detail=""):
        assert reason in REASONS, reason
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


def _intersects(ranges, start, end):
    return any(a < end and start < b for a, b, *_ in ranges)


def record_read(image, data: bytes, rva: int, size: int):
    """``file_record`` bytes at a map coordinate: one contiguous ``file`` run. Returns (bytes, basis)."""
    if size <= 0:
        return b"", {"file_record": [0, 0]}
    item = image.at(rva)
    if item is None:
        raise Unread("OUTSIDE_FILE", f"{rva:#x}")
    if item.kind == "ambiguous":
        raise Unread("AMBIGUOUS_MAPPING", f"{rva:#x}")
    if item.kind == "zero":
        raise Unread("ZERO_FILL", f"{rva:#x}")
    if rva + size > item.end:
        nxt = image.at(item.end)
        contiguous = nxt is not None and nxt.kind == "file" and \
            nxt.file_offset == item.file_offset + (item.end - item.start)
        if not contiguous:
            raise Unread("NONCONTIGUOUS" if nxt is not None and nxt.kind == "file" else "TRUNCATED", f"{rva:#x}")
        if rva + size > nxt.end:
            raise Unread("TRUNCATED", f"{rva:#x}+{size}")
    offset = item.file_offset + (rva - item.start)
    if offset + size > len(data):
        raise Unread("OUTSIDE_FILE", "past the end of the file")
    return data[offset:offset + size], {"file_record": [offset, size]}


def runtime_read(image, data: bytes, rva: int, size: int):
    """``file_runtime`` bytes: a file_record read that is also not loader-written and not relocated."""
    for parsed in (image.written, image.relocations):
        if parsed is not None and parsed.state == "indeterminate":
            raise Unread("MAP_INDETERMINATE", parsed.why)
    raw, basis = record_read(image, data, rva, size)
    if _intersects(image.written.ranges, rva, rva + size):
        raise Unread("LOADER_WRITTEN", f"{rva:#x}")
    if _intersects(image.relocations.ranges, rva, rva + size):
        raise Unread("RELOCATED", f"{rva:#x}")
    return raw, {"file_runtime": basis["file_record"]}


def record_cstring(image, data: bytes, rva: int, limit: int = 4096, reader=record_read):
    """A NUL-terminated string within one contiguous run (at most ``limit`` bytes). Returns (text, basis)."""
    item = image.at(rva)
    if item is None:
        raise Unread("OUTSIDE_FILE", f"{rva:#x}")
    run = min(item.end - rva, limit)
    raw, _ = reader(image, data, rva, max(run, 1))
    end = raw.find(b"\0")
    if end < 0:
        raise Unread("TRUNCATED", f"string at {rva:#x}")
    text, basis = reader(image, data, rva, end + 1)
    return text[:-1].decode("latin-1"), basis


@dataclass
class Region:
    """A file-coordinate region (r5 s5): ``end`` None means U (start known)."""
    start: int
    end: int | None
    role: str                       # code | unwind_metadata
    executable: bool | None = None
    writable: bool | None = None
    name: str = ""
    basis: dict = field(default_factory=dict)


@dataclass
class FileFacts:
    format: str                     # pe | elf | none
    ok: bool
    why: str = ""
    image_base: int = 0
    code: list = field(default_factory=list)          # [Region]
    unwind: list = field(default_factory=list)        # [Region] (merged where contiguous)
    diagnostics: list = field(default_factory=list)   # [{"range": {start, end|None} | "what": str, reason, basis}]
    imports: dict = field(default_factory=dict)       # slot coordinate -> {dll?, name, ordinal?, kind, basis}
    import_state: str = "absent"                      # absent | complete | partial | indeterminate
    import_problems: list = field(default_factory=list)   # [{"range"|"what", reason, basis?}]
    slot_failures: dict = field(default_factory=dict)  # slot coordinate -> reason
    import_ranges: list = field(default_factory=list)  # [(start, end)] of every parsed import slot table (IAT / GOT)


def _diag(out, reason, *, start=None, end=None, what=None, basis=None):
    assert reason in REASONS, reason
    item = {"reason": reason}
    if start is not None:
        item["range"] = {"start": start, "end": end}
    else:
        item["what"] = what
    if basis:
        item["basis"] = basis
    out.append(item)


def _merge(regions):
    """Merge contiguous / overlapping unwind regions with a known end; U-ended ones stay separate."""
    known = sorted((r for r in regions if r.end is not None), key=lambda r: (r.start, r.end))
    out = []
    for r in known:
        if out and out[-1].end is not None and r.start <= out[-1].end and out[-1].name == r.name:
            out[-1].end = max(out[-1].end, r.end)
        else:
            out.append(Region(r.start, r.end, r.role, name=r.name, basis=dict(r.basis)))
    return out + [r for r in regions if r.end is None]


def file_facts(image, data: bytes) -> FileFacts:
    if image is None or not image.ok:
        return FileFacts(getattr(image, "format", "none"), False, getattr(image, "why", "no file map"))
    if image.format == "pe":
        return _pe(image, data)
    return _elf(image, data)


# -- PE32+ ------------------------------------------------------------------------------------------------------------

SCN_EXECUTE, SCN_WRITE = 0x20000000, 0x80000000
UNW_EHANDLER, UNW_UHANDLER, UNW_CHAININFO = 1, 2, 4


def _pe(image, data) -> FileFacts:
    out = FileFacts("pe", True, image_base=image.image_base)
    for s in image.sections:
        if s["characteristics"] & SCN_EXECUTE:
            if s["state"] != "mapped":
                _diag(out.diagnostics, "AMBIGUOUS_MAPPING", start=s["va"], end=s["va"] + max(s["vsize"], 1),
                      basis={"section": s["name"]})
                continue
            out.code.append(Region(s["va"], s["va"] + s["vsize"], "code", True,
                                   bool(s["characteristics"] & SCN_WRITE), s["name"],
                                   {"pe_section": [s["index"], s["name"], s["characteristics"]]}))
    directories = image.directories
    if len(directories) > 3 and directories[3][1]:
        _pe_unwind(image, data, directories[3], out)
    _pe_imports(image, data, directories, out)
    out.unwind = _merge(out.unwind)
    return out


def _pe_unwind(image, data, directory, out):
    rva, size = directory
    try:
        _, basis = record_read(image, data, rva, size)
    except Unread as error:
        _diag(out.diagnostics, error.reason, start=rva, end=rva + size, basis={"pe_directory": 3})
        return
    out.unwind.append(Region(rva, rva + size, "unwind_metadata", name=".pdata", basis=basis))
    count = size // 12
    if size % 12:
        _diag(out.diagnostics, "TRUNCATED", start=rva + 12 * count, end=rva + size, basis={"pe_directory": 3})
    seen = set()
    for index in range(count):
        entry, _ = record_read(image, data, rva + 12 * index, 12)
        _, _, unwind = struct.unpack("<III", entry)
        _pe_unwind_info(image, data, unwind, out, seen, rva + 12 * index)


def _pe_unwind_info(image, data, unwind, out, seen, entry_rva):
    chain = set()
    while True:
        if unwind & 1:
            _diag(out.diagnostics, "UNWIND_INDIRECT", start=entry_rva, end=entry_rva + 12)
            return
        if unwind in chain:
            _diag(out.diagnostics, "CHAIN_CYCLE", start=unwind, end=unwind + 4)
            return
        chain.add(unwind)
        if unwind in seen:
            return
        seen.add(unwind)
        try:
            head, basis = record_read(image, data, unwind, 4)
        except Unread as error:
            _diag(out.diagnostics, error.reason, start=unwind, end=unwind + 4)
            return
        version, flags, count = head[0] & 7, head[0] >> 3, head[2]
        if version not in (1, 2):
            _diag(out.diagnostics, "UNWIND_VERSION", start=unwind, end=unwind + 4, basis=basis)
            return
        if flags & ~(UNW_EHANDLER | UNW_UHANDLER | UNW_CHAININFO) or \
                (flags & UNW_CHAININFO and flags & (UNW_EHANDLER | UNW_UHANDLER)):
            _diag(out.diagnostics, "UNWIND_FLAGS", start=unwind, end=unwind + 4, basis=basis)
            return
        codes_end = unwind + 4 + 2 * (count + (count & 1))
        try:
            _, basis = record_read(image, data, unwind, codes_end - unwind)
        except Unread as error:
            _diag(out.diagnostics, error.reason, start=unwind, end=codes_end)
            return
        if flags & UNW_CHAININFO:
            try:
                raw, basis = record_read(image, data, codes_end, 12)
            except Unread as error:
                _diag(out.diagnostics, error.reason, start=codes_end, end=codes_end + 12)
                return
            out.unwind.append(Region(unwind, codes_end + 12, "unwind_metadata", name=".xdata", basis=basis))
            entry_rva, unwind = codes_end, struct.unpack_from("<I", raw, 8)[0]
            continue
        if flags & (UNW_EHANDLER | UNW_UHANDLER):
            try:
                _, basis = record_read(image, data, codes_end, 4)
            except Unread as error:
                _diag(out.diagnostics, error.reason, start=codes_end, end=codes_end + 4)
                return
            out.unwind.append(Region(unwind, codes_end + 4, "unwind_metadata", name=".xdata", basis=basis))
            # (the language-specific data follows the handler RVA field; its length is not in the format)
            _diag(out.diagnostics, "HANDLER_DATA_LENGTH", start=codes_end + 4, end=None)
            return
        out.unwind.append(Region(unwind, codes_end, "unwind_metadata", name=".xdata", basis=basis))
        return


def _pe_imports(image, data, directories, out):
    have_import = len(directories) > 1 and directories[1][0]
    have_delay = len(directories) > 13 and directories[13][0]
    if not have_import and not have_delay:
        out.import_state = "absent"
        return
    partial = False
    if have_import:
        partial |= _pe_import_table(image, data, directories[1], out)
    if have_delay:
        partial |= _pe_delay_table(image, data, directories[13], out)
    out.import_state = "partial" if partial else "complete"


def _pe_import_table(image, data, directory, out) -> bool:
    rva, _ = directory
    partial = False
    for index in range(1 << 14):
        at = rva + 20 * index
        try:
            raw, _ = record_read(image, data, at, 20)
        except Unread as error:
            _diag(out.import_problems, error.reason, start=at, end=at + 20, basis={"pe_directory": 1})
            return True
        oft, stamp, _, name_rva, first = struct.unpack("<IIIII", raw)
        if not (oft or stamp or name_rva or first):
            return partial
        try:
            dll, _ = record_cstring(image, data, name_rva, 512)
        except Unread as error:
            _diag(out.import_problems, error.reason, start=at, end=at + 20, basis={"pe_directory": 1})
            partial = True
            continue
        lookup = oft
        fallback = False
        if not oft:
            if stamp != 0:
                _diag(out.import_problems, "BOUND_IAT_NO_ILT", start=at, end=at + 20, basis={"dll": dll})
                partial = True
                continue
            lookup, fallback = first, True
        partial |= _pe_thunks(image, data, dll, lookup, first, "import", out, fallback, at)
    _diag(out.import_problems, "TRUNCATED", start=rva, end=None, basis={"pe_directory": 1})
    return True


def _pe_thunks(image, data, dll, lookup, slots, kind, out, validate, descriptor) -> bool:
    entries = []
    for index in range(1 << 16):
        try:
            raw, basis = record_read(image, data, lookup + 8 * index, 8)
        except Unread as error:
            _diag(out.import_problems, error.reason, start=lookup + 8 * index, end=lookup + 8 * index + 8,
                  basis={"dll": dll})
            return True
        value, = struct.unpack("<Q", raw)
        if value == 0:
            break
        entries.append((index, value, basis))
    else:
        _diag(out.import_problems, "TRUNCATED", start=lookup, end=None, basis={"dll": dll})
        return True
    resolved = []
    for index, value, basis in entries:
        slot = slots + 8 * index
        if value >> 63:
            resolved.append((slot, {"dll": dll, "name": f"#{value & 0xFFFF}", "ordinal": value & 0xFFFF,
                                    "kind": kind, "basis": {"pe_import": {"dll": dll, "ordinal": value & 0xFFFF,
                                                                          "slot": slot, "lookup": basis}}}))
            continue
        if value >> 31:
            if validate:
                _diag(out.import_problems, "ILT_ENTRY_INVALID", start=descriptor, end=descriptor + 20,
                      basis={"dll": dll})
                return True
            out.slot_failures[slot] = "ILT_ENTRY_INVALID"
            continue
        try:
            text, name_basis = record_cstring(image, data, (value & 0x7FFFFFFF) + 2, 1024)
        except Unread as error:
            if validate:
                _diag(out.import_problems, "ILT_ENTRY_INVALID", start=descriptor, end=descriptor + 20,
                      basis={"dll": dll})
                return True
            out.slot_failures[slot] = "SLOT_NAME_U"
            continue
        resolved.append((slot, {"dll": dll, "name": text, "kind": kind,
                                "basis": {"pe_import": {"dll": dll, "name": text, "slot": slot, "lookup": basis,
                                                        "hint_name": name_basis}}}))
    for slot, item in resolved:
        out.imports[slot] = item
    if entries:
        out.import_ranges.append((slots, slots + 8 * len(entries)))
    return False


def _pe_delay_table(image, data, directory, out) -> bool:
    rva, _ = directory
    partial = False
    for index in range(1 << 14):
        at = rva + 32 * index
        try:
            raw, _ = record_read(image, data, at, 32)
        except Unread as error:
            _diag(out.import_problems, error.reason, start=at, end=at + 32, basis={"pe_directory": 13})
            return True
        attributes, name_rva, _, iat, int_rva, _, _, _ = struct.unpack("<IIIIIIII", raw)
        if not any(struct.unpack("<IIIIIIII", raw)):
            return partial
        if not attributes & 1:
            _diag(out.import_problems, "DELAY_FORMAT", start=at, end=at + 32, basis={"pe_directory": 13})
            partial = True
            continue
        try:
            dll, _ = record_cstring(image, data, name_rva, 512)
        except Unread as error:
            _diag(out.import_problems, error.reason, start=at, end=at + 32, basis={"pe_directory": 13})
            partial = True
            continue
        partial |= _pe_thunks(image, data, dll, int_rva, iat, "delay", out, False, at)
    _diag(out.import_problems, "TRUNCATED", start=rva, end=None, basis={"pe_directory": 13})
    return True


# -- ELF64 ------------------------------------------------------------------------------------------------------------

PF_X, PF_W = 1, 2
PT_DYNAMIC, PT_GNU_EH_FRAME = 2, 0x6474E550
SHT_DYNSYM = 11
DT_STRTAB, DT_STRSZ, DT_HASH, DT_GNU_HASH = 5, 10, 4, 0x6FFFFEF5
R_GLOB_DAT, R_JUMP_SLOT = 6, 7


def _elf_sections(data, out):
    """Section headers read by file offset (unmapped): [{name, type, flags, addr, offset, size, link, entsize}]."""
    e_shoff, = struct.unpack_from("<Q", data, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)
    if not e_shoff or not e_shnum:
        return None
    if e_shentsize != 64 or e_shoff + 64 * e_shnum > len(data) or e_shstrndx >= e_shnum:
        _diag(out.diagnostics, "TRUNCATED", what="section headers", basis={"file_record": [e_shoff, 64 * e_shnum]})
        return None
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, e_shoff + 64 * i) for i in range(e_shnum)]
    strtab = rows[e_shstrndx]
    sections = []
    for name, kind, flags, addr, offset, size, link, _, _, entsize in rows:
        at = strtab[4] + name
        end = data.find(b"\0", at, strtab[4] + strtab[5]) if at < strtab[4] + strtab[5] else -1
        text = data[at:end].decode("latin-1") if end >= 0 else ""
        sections.append({"name": text, "type": kind, "flags": flags, "addr": addr, "offset": offset, "size": size,
                         "link": link, "entsize": entsize})
    return sections


def _loaded(image, va, size):
    for p in image.phdrs:
        if p[0] == 1 and p[3] <= va and va + size <= p[3] + p[6]:
            return True
    return False


def _elf(image, data) -> FileFacts:
    out = FileFacts("elf", True, image_base=image.image_base)
    base = image.image_base
    for s in image.segments:
        if s["flags"] & PF_X:
            if s["state"] != "mapped":
                _diag(out.diagnostics, "AMBIGUOUS_MAPPING", start=s["vaddr"] - base,
                      end=s["vaddr"] - base + max(s["memsz"], 1), basis={"segment": s["index"]})
                continue
            out.code.append(Region(s["vaddr"] - base, s["vaddr"] - base + s["memsz"], "code", True,
                                   bool(s["flags"] & PF_W), f"PT_LOAD[{s['index']}]",
                                   {"elf_segment": [s["index"], s["flags"]]}))
    sections = _elf_sections(data, out)
    by_name = {s["name"]: s for s in sections or () if s["name"]}
    hdr = [p for p in image.phdrs if p[0] == PT_GNU_EH_FRAME]
    eh_frame = by_name.get(".eh_frame")
    for name in (".eh_frame", ".gcc_except_table"):
        s = by_name.get(name)
        if s is None:
            continue
        if not s["flags"] & 2 or not _loaded(image, s["addr"], s["size"]):
            _diag(out.diagnostics, "SECTION_NOT_LOADED", what=name)
            continue
        out.unwind.append(Region(s["addr"] - base, s["addr"] - base + s["size"], "unwind_metadata", name=name,
                                 basis={"elf_section": [name, s["offset"], s["size"]]}))
    if hdr:
        _, _, offset, vaddr, _, filesz, memsz, _ = hdr[0]
        start = vaddr - base
        try:
            head, basis = record_read(image, data, start, min(filesz, 8))
            out.unwind.append(Region(start, start + memsz, "unwind_metadata", name=".eh_frame_hdr", basis=basis))
            if eh_frame is None:
                _elf_eh_frame_ptr(image, data, start, head, out)
        except Unread as error:
            _diag(out.diagnostics, error.reason, start=start, end=start + memsz, basis={"phdr": "PT_GNU_EH_FRAME"})
    elif eh_frame is None and sections is None:
        _diag(out.diagnostics, "NO_SECTION_HEADERS", what="eh_frame")
    _elf_imports(image, data, sections, out)
    out.unwind = _merge(out.unwind)
    return out


def _elf_eh_frame_ptr(image, data, hdr_start, head, out):
    if len(head) < 8 or head[0] != 1:
        _diag(out.diagnostics, "EH_FRAME_PTR_ENCODING", what="eh_frame", basis={"eh_frame_hdr": hdr_start})
        return
    encoding = head[1]
    if encoding == 0xFF:
        _diag(out.diagnostics, "EH_FRAME_PTR_OMITTED", what="eh_frame", basis={"eh_frame_hdr": hdr_start})
        return
    form, application = encoding & 0x0F, encoding & 0x70
    if form not in (0x03, 0x0B) or application not in (0x00, 0x10):
        _diag(out.diagnostics, "EH_FRAME_PTR_ENCODING", what="eh_frame", basis={"eh_frame_hdr": hdr_start})
        return
    value, = struct.unpack_from("<i" if form == 0x0B else "<I", head, 4)
    target = (hdr_start + out.image_base + 4 + value) if application == 0x10 else value
    start = target - out.image_base
    out.unwind.append(Region(start, None, "unwind_metadata", name=".eh_frame",
                             basis={"eh_frame_ptr": {"hdr": hdr_start, "encoding": encoding}}))
    _diag(out.diagnostics, "NO_SECTION_HEADERS", start=start, end=None, basis={"eh_frame_ptr": hdr_start})


def _elf_dynamic_tags(image, data, out):
    dynamic = [p for p in image.phdrs if p[0] == PT_DYNAMIC]
    if len(dynamic) != 1:
        return None
    _, _, _, vaddr, _, filesz, _, _ = dynamic[0]
    try:
        raw, _ = record_read(image, data, vaddr - image.image_base, filesz)
    except Unread as error:
        _diag(out.import_problems, error.reason, what="PT_DYNAMIC")
        return None
    tags = {}
    for cursor in range(0, len(raw) - 15, 16):
        tag, value = struct.unpack_from("<qQ", raw, cursor)
        if tag == 0:
            break
        tags[tag] = value
    return tags


def _elf_symbol_count(image, data, tags, sections):
    for s in sections or ():
        if s["type"] == SHT_DYNSYM and s["entsize"] == 24:
            return s["size"] // 24
    base = image.image_base
    if DT_HASH in tags:
        try:
            raw, _ = record_read(image, data, tags[DT_HASH] - base, 8)
            return struct.unpack("<II", raw)[1]
        except Unread:
            return None
    if DT_GNU_HASH in tags:
        try:
            at = tags[DT_GNU_HASH] - base
            head, _ = record_read(image, data, at, 16)
            nbuckets, symoffset, bloom_size, _ = struct.unpack("<IIII", head)
            buckets_at = at + 16 + 8 * bloom_size
            raw, _ = record_read(image, data, buckets_at, 4 * nbuckets)
            buckets = struct.unpack(f"<{nbuckets}I", raw)
            last = max(buckets, default=0)
            if last < symoffset:
                return symoffset
            chains_at = buckets_at + 4 * nbuckets
            index = last
            while True:
                value, _ = record_read(image, data, chains_at + 4 * (index - symoffset), 4)
                if struct.unpack("<I", value)[0] & 1:
                    return index + 1
                index += 1
        except (Unread, struct.error):
            return None
    return None


def _elf_imports(image, data, sections, out):
    tags = _elf_dynamic_tags(image, data, out)
    if tags is None:
        out.import_state = "absent" if not any(p[0] == PT_DYNAMIC for p in image.phdrs) else "indeterminate"
        return
    base = image.image_base
    needed = (6, DT_STRTAB, DT_STRSZ)          # DT_SYMTAB, DT_STRTAB, DT_STRSZ
    if not all(t in tags for t in needed):
        out.import_state = "absent" if not (23 in tags or 7 in tags) else "indeterminate"
        if out.import_state == "indeterminate":
            _diag(out.import_problems, "PARSER_UNSUPPORTED", what="dynamic symbol tables")
        return
    symtab, strtab, strsz = tags[6] - base, tags[DT_STRTAB] - base, tags[DT_STRSZ]
    syment = tags.get(11, 24)
    count = _elf_symbol_count(image, data, tags, sections)
    partial = False
    tables = []
    if 23 in tags:                               # DT_JMPREL
        if tags.get(20, 7) != 7:
            _diag(out.import_problems, "ELF_RELOC_UNSUPPORTED", what="DT_PLTREL REL")
            partial = True
        else:
            tables.append(("DT_JMPREL", tags[23] - base, tags.get(2, 0), 24))
    if 7 in tags:                                # DT_RELA
        tables.append(("DT_RELA", tags[7] - base, tags.get(8, 0), tags.get(9, 24)))
    for label, at, size, entsize in tables:
        if entsize != 24 or size % 24:
            _diag(out.import_problems, "ELF_RELOC_UNSUPPORTED", what=label)
            partial = True
            continue
        try:
            raw, table_basis = record_read(image, data, at, size)
        except Unread as error:
            _diag(out.import_problems, error.reason, what=label)
            partial = True
            continue
        for cursor in range(0, size, 24):
            r_offset, info, _ = struct.unpack_from("<QQq", raw, cursor)
            kind, index = info & 0xFFFFFFFF, info >> 32
            if kind not in (R_GLOB_DAT, R_JUMP_SLOT):
                continue
            slot = r_offset - base
            if syment != 24 or count is None or index >= count:
                out.slot_failures[slot] = "SYM_COUNT_U"
                continue
            try:
                sym, sym_basis = record_read(image, data, symtab + 24 * index, 24)
                st_name, _, _, st_shndx = struct.unpack_from("<IBBH", sym, 0)
                if st_name >= strsz:
                    raise Unread("TRUNCATED", "st_name")
                name, name_basis = record_cstring(image, data, strtab + st_name, strsz - st_name)
            except Unread:
                out.slot_failures[slot] = "SLOT_NAME_U"
                continue
            out.imports[slot] = {"name": name, "kind": "JUMP_SLOT" if kind == R_JUMP_SLOT else "GLOB_DAT",
                                 "undefined": st_shndx == 0,
                                 "basis": {"elf_reloc": {"name": name, "slot": slot, "type": kind, "table": label,
                                                         "entry": table_basis["file_record"][0] + cursor,
                                                         "symbol": sym_basis, "string": name_basis}}}
    out.import_state = "partial" if partial else "complete"
