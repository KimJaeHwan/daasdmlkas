## 1. `tools/decode_check/code_facts.py`

`fde5afb` 기준 교체 블록입니다. 기존 모듈에서 다음 정의와 이들이 사용하는 import를 유지하고, 그 뒤에 아래 블록을 둡니다. 이 방식이면 변경되지 않은 G2a 표현식 평가기나 x86 opcode 표를 옮겨 적을 필요가 없습니다.

- 상수 `FACTS_RULE`, `PREMISE`, `IMPORT_PREMISE`, `LINEAR_PREMISE`, `VERIFIED_THRESHOLD`, `REASONS`, `SCN_*`, `UNW_*`, `PF_*`, `PT_*`, `SHT_DYNSYM`, `DT_*`, `R_*`, `TRAP_BYTES`, `TRAP_FLOWS`, `GPR`, `TRANSFER_OPS`, `DECODER_FORMS`, `RWX`, `ENDBR64`
- `Unread`, `Region`, `FileFacts`, `_diag`, `_ballot_ok`, `_byte_form`, `_vote_form`, `name_table`, `_hx`, `_canonical`, `_item_key`, `_union_length`, `_gpr`, `_overlaps`, `_leaves`, `_evaluate`

```python
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from dataclasses import replace

REASONS |= {"NOT_A64", "SECTION_EXTENT_U"}
RWX_KIND = "rwx_allocation_constant_args"


def record_read(image, data, rva, size):
    if size < 0:
        raise Unread("OUTSIDE_FILE")
    if not size:
        return b"", {"file_record": [0, 0]}

    first = None
    cursor = rva
    end = rva + size
    while cursor < end:
        item = image.at(cursor)
        if item is None:
            raise Unread("OUTSIDE_FILE" if cursor == rva else "TRUNCATED")
        if item.kind != "file":
            raise Unread({"zero": "ZERO_FILL", "ambiguous": "AMBIGUOUS_MAPPING"}
                         .get(item.kind, "OUTSIDE_FILE"))
        offset = item.file_offset + cursor - item.start
        if first is None:
            first = offset
        if offset != first + cursor - rva:
            raise Unread("NONCONTIGUOUS")
        stop = min(end, item.end)
        if stop <= cursor or offset < 0 or offset + stop - cursor > len(data):
            raise Unread("OUTSIDE_FILE")
        cursor = stop
    return data[first:first + size], {"file_record": [first, size]}


def _touches(parsed, start, end):
    # G1 has finished constructing this Parsed object before file_facts runs.
    index = getattr(parsed, "_g2_intervals", None)
    if index is None:
        starts, ends = [], []
        for a, z, *_ in sorted(parsed.ranges):
            if starts and a <= ends[-1]:
                ends[-1] = max(z, ends[-1])
            else:
                starts.append(a)
                ends.append(z)
        index = parsed._g2_intervals = starts, ends
    starts, ends = index
    j = bisect_right(ends, start)
    return start < end and j < len(starts) and starts[j] < end


def runtime_read(image, data, rva, size):
    for parsed, why in ((image.written, "LOADER_WRITTEN"), (image.relocations, "RELOCATED")):
        if parsed is None or parsed.state not in ("complete", "absent"):
            raise Unread("MAP_INDETERMINATE")
        if _touches(parsed, rva, rva + size):
            raise Unread(why)
    raw, basis = record_read(image, data, rva, size)
    return raw, {"file_runtime": basis["file_record"]}


def record_cstring(image, data, rva, limit=4096):
    _, ref = record_read(image, data, rva, 1)
    off = ref["file_record"][0]
    nul = data.find(b"\0", off, off + limit)
    if nul < off:
        raise Unread("TRUNCATED")
    raw, ref = record_read(image, data, rva, nul - off + 1)
    return raw[:-1].decode("latin-1"), ref


def _issue(out, reason, start, end, basis):
    _diag(out, reason, start=start, end=end, basis=basis)


def _code_region(out, image, region, valid):
    cursor = region.start
    for m in image.ranges:
        lo, hi = max(cursor, m.start), min(region.end, m.end)
        if hi <= lo:
            continue
        if cursor < lo:
            _issue(out.diagnostics, "AMBIGUOUS_MAPPING", cursor, lo, region.basis)
        if valid and m.kind in ("file", "zero"):
            if out.code and out.code[-1].basis == region.basis and out.code[-1].end == lo:
                out.code[-1].end = hi
            else:
                out.code.append(replace(region, start=lo, end=hi))
        else:
            _issue(out.diagnostics, "AMBIGUOUS_MAPPING", lo, hi, region.basis)
        cursor = hi
    if cursor < region.end:
        _issue(out.diagnostics, "AMBIGUOUS_MAPPING", cursor, region.end, region.basis)


def file_facts(image, data):
    if image is None or not image.ok:
        return FileFacts(getattr(image, "format", "none"), False,
                         getattr(image, "why", "no map"), import_state="indeterminate")

    out = FileFacts(image.format, True, image_base=image.image_base)
    if image.format == "pe":
        for s in image.sections:
            flags = s["characteristics"]
            if flags & SCN_EXECUTE:
                region = Region(s["va"], s["va"] + s["vsize"], "code", True,
                                bool(flags & SCN_WRITE), s["name"],
                                {"pe_section": [s["index"], s["name"], flags]})
                _code_region(out, image, region, s["state"] == "mapped")
        for n, directory in enumerate(image.directories):
            if n == 3 and any(directory):
                _pe_unwind(image, data, directory, out)
            if n in (1, 13) and any(directory):
                out.import_state = "complete"
                _pe_table(image, data, directory, n, out)
    elif image.format == "elf":
        _elf_file(image, data, out)
    else:
        return FileFacts(image.format, False, "unsupported format", import_state="indeterminate")

    if (out.import_problems or out.slot_failures) and out.import_state != "indeterminate":
        out.import_state = "partial"
    return out


def _pe_unwind(image, data, directory, out):
    start, size = directory
    ref = {"pe_directory": 3}
    out.unwind.append(Region(start, start + size, "unwind_metadata", name=".pdata", basis=ref))
    seen = set()

    for pos in range(start, start + size, 12):
        if pos + 12 > start + size:
            _issue(out.diagnostics, "TRUNCATED", pos, start + size, ref)
            break
        try:
            entry, parent = record_read(image, data, pos, 12)
        except Unread as exc:
            _issue(out.diagnostics, exc.reason, pos, pos + 12, ref)
            continue

        u = struct.unpack_from("<I", entry, 8)[0]
        path = set()
        while True:
            if u & 1 or u in path:
                _issue(out.diagnostics, "UNWIND_INDIRECT" if u & 1 else "CHAIN_CYCLE",
                       u, u + 4, parent)
                break
            if u in seen:
                break
            seen.add(u)
            path.add(u)
            lo, hi = u, u + 4
            known = 0
            basis = parent
            try:
                head, basis = runtime_read(image, data, u, 4)
                flags = head[0] >> 3
                if (head[0] & 7) not in (1, 2):
                    raise Unread("UNWIND_VERSION")
                if flags not in (0, 1, 2, 3, 4):
                    raise Unread("UNWIND_FLAGS")
                known = 4
                hi = u + 4 + 2 * ((head[2] + 1) & ~1)
                _, basis = runtime_read(image, data, u, hi - u)
                known = hi - u
                lo = hi
                hi += 12 if flags == 4 else 4 if flags else 0
                raw, whole = runtime_read(image, data, u, hi - u)
                out.unwind.append(Region(u, hi, "unwind_metadata", name=".xdata", basis=whole))
                if flags == 4:
                    parent = whole
                    u = struct.unpack_from("<I", raw, len(raw) - 4)[0]
                    continue
                if flags:
                    _issue(out.diagnostics, "HANDLER_DATA_LENGTH", hi, None, whole)
            except Unread as exc:
                if known:
                    out.unwind.append(Region(u, u + known, "unwind_metadata", name=".xdata", basis=basis))
                _issue(out.diagnostics, exc.reason, lo, hi, basis)
            break


def _publish(out, slot, item, reason=None):
    if slot in out.imports or slot in out.slot_failures:
        out.imports.pop(slot, None)
        reason = "SLOT_NAME_U"
    if reason:
        out.slot_failures[slot] = reason
    else:
        out.imports[slot] = item


def _mapped_slot(image, slot):
    m = image.at(slot)
    return m is not None and m.kind in ("file", "zero") and slot + 8 <= m.end


def _pe_table(image, data, directory, n, out):
    start, size = directory
    stride = 20 if n == 1 else 32
    parent = {"pe_directory": n}
    for pos in range(start, start + size - stride + 1, stride):
        basis = parent
        staged = []
        fallback = False
        try:
            raw, basis = record_read(image, data, pos, stride)
            if not any(raw):
                return
            if n == 1:
                lookup, stamp, _, name, slots = struct.unpack("<5I", raw)
                if not lookup and stamp:
                    raise Unread("BOUND_IAT_NO_ILT")
                fallback = not lookup
                lookup = lookup or slots
                if not name or not slots:
                    raise Unread("ILT_ENTRY_INVALID")
            else:
                attr, name, _, slots, lookup, _, _, _ = struct.unpack("<8I", raw)
                if attr != 1 or not all((name, slots, lookup)):
                    raise Unread("DELAY_FORMAT")

            dll, dll_ref = record_cstring(image, data, name)
            if not dll:
                raise Unread("SLOT_NAME_U")
            index = 0
            while True:
                slot = slots + 8 * index
                raw, entry = record_read(image, data, lookup + 8 * index, 8)
                v = int.from_bytes(raw, "little")
                if not v:
                    break
                try:
                    if not _mapped_slot(image, slot):
                        raise Unread("ILT_ENTRY_INVALID")
                    fact = dict(dll=dll, descriptor=basis, dll_record=dll_ref, lookup=entry)
                    item = dict(dll=dll, kind="import" if n == 1 else "delay")
                    if v >> 63:
                        if v & ~((1 << 63) | 0xffff):
                            raise Unread("ILT_ENTRY_INVALID")
                        item["ordinal"] = fact["ordinal"] = v & 0xffff
                        text = "#" + str(item["ordinal"])
                    else:
                        if v >= 1 << 31:
                            raise Unread("ILT_ENTRY_INVALID")
                        text, string = record_cstring(image, data, v + 2)
                        if not text:
                            raise Unread("SLOT_NAME_U")
                        _, fact["hint_name"] = record_read(image, data, v, 2 + string["file_record"][1])
                    fact["name"] = item["name"] = text
                    item["basis"] = {"pe_import": fact}
                    if fallback:
                        staged.append((slot, item))
                    else:
                        _publish(out, slot, item)
                except Unread as exc:
                    if fallback:
                        _publish(out, slot, None, "ILT_ENTRY_INVALID")
                        raise Unread("ILT_ENTRY_INVALID") from exc
                    _publish(out, slot, None, exc.reason)
                index += 1
            for slot, item in staged:
                _publish(out, slot, item)
        except Unread as exc:
            for slot, _ in staged:
                _publish(out, slot, None, "ILT_ENTRY_INVALID")
            why = "ILT_ENTRY_INVALID" if fallback and staged else exc.reason
            _issue(out.import_problems, why, pos, pos + stride, basis)
    _issue(out.import_problems, "TRUNCATED", start, start + size, parent)


def _sections(image, data, out):
    shoff, = struct.unpack_from("<Q", data, 40)
    stride, count, names = struct.unpack_from("<3H", data, 58)
    if not shoff and not count:
        return [], False
    if not shoff or stride != 64 or not count or shoff + 64 * count > len(data) or names >= count:
        raise Unread("TRUNCATED")

    sections = []
    for i in range(count):
        at = shoff + 64 * i
        n, t, flags, va, off, size, link, _, _, ent = struct.unpack_from("<IIQQQQIIQQ", data, at)
        sections.append(dict(n=n, type=t, flags=flags, va=va, off=off, size=size,
                             link=link, ent=ent, ref={"file_record": [at, 64]}))
    strings = sections[names]
    if names and (strings["type"] != 3 or strings["off"] + strings["size"] > len(data)):
        raise Unread("TRUNCATED")
    for s in sections:
        s["name"] = ""
        if s["type"] != 8 and s["off"] + s["size"] > len(data):
            _issue(out.diagnostics, "TRUNCATED", s["va"] - image.image_base, None, s["ref"])
        if names:
            a = strings["off"] + s["n"]
            z = data.find(b"\0", a, strings["off"] + strings["size"])
            if z < 0:
                _issue(out.diagnostics, "TRUNCATED", s["va"] - image.image_base, None, s["ref"])
            else:
                s["name"] = data[a:z].decode("latin-1")
    return sections, True


def _loaded_section(image, data, s):
    if not s["flags"] & 2 or s["type"] == 8 or s["off"] + s["size"] > len(data):
        raise Unread("SECTION_NOT_LOADED")
    loads = [p for p in image.phdrs if p[0] == 1 and p[3] <= s["va"]
             and s["va"] + s["size"] <= p[3] + min(p[5], p[6])
             and p[2] + s["va"] - p[3] == s["off"]]
    if len(loads) != 1:
        raise Unread("SECTION_NOT_LOADED")
    if s["size"]:
        _, ref = record_read(image, data, s["va"] - image.image_base, s["size"])
        if ref["file_record"][0] != s["off"]:
            raise Unread("AMBIGUOUS_MAPPING")


def _elf_file(image, data, out):
    base = image.image_base
    for s in image.segments:
        if s["flags"] & PF_X:
            a = s["vaddr"] - base
            region = Region(a, a + s["memsz"], "code", True, bool(s["flags"] & PF_W),
                            f"PT_LOAD[{s['index']}]", {"elf_segment": [s["index"], s["flags"]]})
            _code_region(out, image, region, s["state"] == "mapped")
    try:
        sections, present = _sections(image, data, out)
    except Unread as exc:
        sections, present = [], True
        for problems in (out.diagnostics, out.import_problems):
            _diag(problems, exc.reason, what="section headers", basis={"file_record": [0, 64]})

    body = False
    for s in sections:
        if s["name"] not in (".eh_frame", ".gcc_except_table"):
            continue
        a = s["va"] - base
        try:
            _loaded_section(image, data, s)
        except Unread as exc:
            _issue(out.diagnostics, exc.reason, a, a + s["size"], s["ref"])
            continue
        out.unwind.append(Region(a, a + s["size"], "unwind_metadata", name=s["name"], basis=s["ref"]))
        body |= s["name"] == ".eh_frame"

    hdrs = [(i, p) for i, p in enumerate(image.phdrs) if p[0] == PT_GNU_EH_FRAME]
    if not hdrs and not present:
        _diag(out.diagnostics, "NO_SECTION_HEADERS", what="eh_frame", basis={"file_record": [0, 64]})
    for i, p in hdrs:
        a = p[3] - base
        basis = {"phdr": i}
        out.unwind.append(Region(a, a + p[6], "unwind_metadata", name=".eh_frame_hdr", basis=basis))
        if body:
            continue
        try:
            head, basis = runtime_read(image, data, a, min(p[5], p[6], 8))
            if len(head) < 2 or head[0] != 1:
                raise Unread("EH_FRAME_PTR_ENCODING")
            enc = head[1]
            if enc == 255:
                raise Unread("EH_FRAME_PTR_OMITTED")
            if enc not in (3, 11, 0x13, 0x1b) or len(head) != 8:
                raise Unread("EH_FRAME_PTR_ENCODING")
            value = int.from_bytes(head[4:], "little", signed=bool(enc & 8))
            start = value + (a + 4 if enc & 0x10 else -base)
            if not 0 <= base + start < 1 << 64:
                raise Unread("EH_FRAME_PTR_ENCODING")
            why = "SECTION_EXTENT_U" if present else "NO_SECTION_HEADERS"
            ref = dict(basis, encoding=enc)
            out.unwind.append(Region(start, None, "unwind_metadata", name=".eh_frame", basis=ref))
            _issue(out.diagnostics, why, start, None, ref)
        except Unread as exc:
            _diag(out.diagnostics, exc.reason, what="eh_frame", basis=basis)
    _elf_tables(image, data, sections, out)


def _dynamic_symbol_count(image, data, tags):
    base = image.image_base
    try:
        if DT_HASH in tags:
            at = tags[DT_HASH] - base
            raw, _ = record_read(image, data, at, 8)
            buckets, count = struct.unpack("<II", raw)
            if not buckets:
                return None
            record_read(image, data, at, 8 + 4 * (buckets + count))
            return count
        if DT_GNU_HASH in tags:
            at = tags[DT_GNU_HASH] - base
            head, _ = record_read(image, data, at, 16)
            buckets, first, bloom, _ = struct.unpack("<4I", head)
            if not buckets or not bloom:
                return None
            at += 16 + 8 * bloom
            raw, _ = record_read(image, data, at, 4 * buckets)
            last = max(n for n, in struct.iter_unpack("<I", raw))
            if last == 0:
                return first
            if last < first:
                return None
            at += 4 * (buckets + last - first)
            while True:
                raw, _ = record_read(image, data, at, 4)
                last += 1
                if raw[0] & 1:
                    return last
                at += 4
    except Unread:
        pass
    return None


def _elf_tables(image, data, sections, out):
    base = image.image_base
    dynamic = [p for p in image.phdrs if p[0] == PT_DYNAMIC]
    tags = {}
    table_ref = {"file_record": [0, 64]}
    try:
        if dynamic:
            if len(dynamic) != 1:
                raise Unread("PARSER_UNSUPPORTED")
            p = dynamic[0]
            raw, table_ref = record_read(image, data, p[3] - base, p[5])
            for at in range(0, len(raw) - 15, 16):
                tag, val = struct.unpack_from("<qQ", raw, at)
                if not tag:
                    break
                if tag in {2, 4, 5, 6, 7, 8, 9, 10, 11, 20, 23, DT_GNU_HASH}:
                    if tag in tags and tags[tag] != val:
                        raise Unread("PARSER_UNSUPPORTED")
                    tags[tag] = val
                elif tag in (17, 18) and val:
                    _diag(out.import_problems, "ELF_RELOC_UNSUPPORTED", what="DT_REL", basis=table_ref)
            else:
                raise Unread("TRUNCATED")
    except Unread as exc:
        out.import_state = "indeterminate"
        _diag(out.import_problems, exc.reason, what="PT_DYNAMIC", basis=table_ref)
        return

    def linked(sym):
        if sym["type"] != 11 or sym["ent"] != 24 or sym["size"] % 24 or sym["link"] >= len(sections):
            raise Unread("SYM_COUNT_U")
        st = sections[sym["link"]]
        if st["type"] != 3:
            raise Unread("SLOT_NAME_U")
        for s in (sym, st):
            _loaded_section(image, data, s)
        if any(k in tags and tags[k] != v for k, v in
               ((6, sym["va"]), (11, 24), (5, st["va"]), (10, st["size"]))):
            raise Unread("SYM_COUNT_U")
        return sym["va"], sym["size"] // 24, st["va"], st["size"]

    def symbols(section):
        if section:
            if section["link"] >= len(sections):
                raise Unread("SYM_COUNT_U")
            return linked(sections[section["link"]])
        matches = [s for s in sections if s["type"] == 11 and s["va"] == tags.get(6)]
        if len(matches) == 1:
            return linked(matches[0])
        if matches or not {5, 6, 10, 11} <= tags.keys() or tags[11] != 24:
            raise Unread("SYM_COUNT_U")
        return tags[6], _dynamic_symbol_count(image, data, tags), tags[5], tags[10]

    for label, ptr, sz, expected, names in (
            ("DT_JMPREL", 23, 2, 7, (".rela.plt", ".rela.plt.sec")),
            ("DT_RELA", 7, 8, 6, (".rela.dyn",))):
        ss = [s for s in sections if s["type"] == 4 and s["name"] in names and s["flags"] & 2]
        if ptr not in tags and sz not in tags and not ss:
            continue
        out.import_state = "complete"
        try:
            if ptr in tags or sz in tags:
                encoding_ok = tags.get(20) == 7 if ptr == 23 else tags.get(9) == 24
                if ptr not in tags or sz not in tags or not encoding_ok:
                    raise Unread("ELF_RELOC_UNSUPPORTED")
                matches = [s for s in sections if s["type"] == 4 and s["va"] == tags[ptr] and s["flags"] & 2]
                if len(matches) > 1:
                    raise Unread("ELF_RELOC_UNSUPPORTED")
                tables = [(tags[ptr], tags[sz], next(iter(matches), None))]
            else:
                tables = [(s["va"], s["size"], s) for s in ss]

            for va, size, section in tables:
                if size % 24:
                    raise Unread("ELF_RELOC_UNSUPPORTED")
                if section:
                    _loaded_section(image, data, section)
                    if section["ent"] != 24 or section["size"] != size:
                        raise Unread("ELF_RELOC_UNSUPPORTED")
                symbol_error = None
                try:
                    symva, count, strva, strsz = symbols(section)
                except Unread as exc:
                    symbol_error = exc.reason
                    _diag(out.import_problems, exc.reason, what=label, basis=table_ref)

                for off in range(0, size, 24):
                    raw, entry = record_read(image, data, va - base + off, 24)
                    dest, info, _ = struct.unpack("<QQq", raw)
                    slot, index, kind = dest - base, info >> 32, info & 0xffffffff
                    try:
                        if kind != expected:
                            raise Unread("ELF_RELOC_UNSUPPORTED")
                        if symbol_error:
                            raise Unread(symbol_error)
                        if count is None or index >= count:
                            raise Unread("SYM_COUNT_U")
                        if not _mapped_slot(image, slot):
                            raise Unread("TARGET_MAPPING_U")
                        raw, sym = record_read(image, data, symva - base + 24 * index, 24)
                        n, _, _, shndx = struct.unpack_from("<IBBH", raw)
                        if n >= strsz:
                            raise Unread("SLOT_NAME_U")
                        name, st = record_cstring(image, data, strva - base + n, strsz - n)
                        if not name:
                            raise Unread("SLOT_NAME_U")
                        basis = {"elf_reloc": dict(name=name, type=kind, table=label, entry=entry,
                                                   symbol=sym, string=st)}
                        _publish(out, slot, dict(name=name, undefined=shndx == 0, basis=basis))
                    except Unread as exc:
                        _publish(out, slot, None, exc.reason)
        except Unread as exc:
            _diag(out.import_problems, exc.reason, what=label, basis=table_ref)


def ballot_digest(votes):
    import common_facts as cf
    import decoders

    by_name = {d.voter: d for d in votes}
    names = decoders.AMD_VOTERS if votes[0].amd else decoders.INTEL_VOTERS
    return cf.digest([by_name[name].as_json() for name in names])


def trap_outcome(result, ballot, window_bytes, global_reason=False):
    if result is None:
        return "unresolved", "GLOBAL_REASON" if global_reason else "NO_WINDOW"
    w = result.get("window") or {}
    data = (window_bytes or b"")[:w.get("verified", 0)]
    if not data:
        return "unresolved", "NO_WINDOW"
    if not _ballot_ok(ballot):
        return "unresolved", "BALLOT_MISSING"
    intel, amd = ballot["intel"], ballot["amd"]
    votes = (*intel, *amd)
    shape = _byte_form(data)
    undecided = "unresolved", "TRAP_FORM_UNDECIDED"
    invalid = all(d.status == "invalid" for d in votes)
    if invalid and (shape is None or shape[0] != "ce"):
        return *undecided, "ALL_INVALID_NOT_CE"
    if shape is None:
        return undecided
    form, length, vector, immediate = shape
    reloc = w.get("relocations") or ()

    if form == "none":
        n = votes[0].length
        if (not 0 < n <= len(data) or any(d.status != "ok" or d.length != n or
                _vote_form(d) != _vote_form(votes[0]) or d.flow in TRAP_FLOWS for d in votes)):
            return undecided
        for a, size, _ in reloc:
            for pos in range(max(a, 0), min(a + size, n)):
                if not all(any(x <= pos < x + width for x, width in d.value_fields) for d in votes):
                    return "unresolved", "RELOCATED_OPCODE"
        return None

    if length > len(data):
        return undecided
    if any(a < length and a + size > 0 for a, size, _ in reloc):
        return "unresolved", "RELOCATED_OPCODE"
    if form == "ce":
        return None if invalid else undecided

    want = (form, vector if form == "int_n" else None)

    def agreed(group):
        return all(d.status == "ok" and d.length == length and _vote_form(d) == want for d in group)

    if not agreed(intel):
        return undecided
    split = form == "sysenter"
    if not agreed(amd) and not (split and all(d.status == "invalid" for d in amd)):
        return undecided
    site = dict(form=form, length=length, vector=vector, immediate=immediate,
                syscall_abi=None if form in ("int1", "int3") else {"unobserved": "NO_ABI_BASIS"},
                basis={"decoders": {v: ballot_digest(ballot[v]) for v in ("intel", "amd")}})
    if split:
        site["form"] = {"unobserved": "VENDOR_SPLIT_FORM"}
        site["vendor_views"] = {"intel": {"form": "sysenter"},
                                "amd": {"form": "invalid_encoding",
                                        "basis": {"isa_conditions": "SYSENTER.f5.amd"}}}
    return "site", site


@dataclass(frozen=True, slots=True)
class Proof:
    isa: str | None
    verified: int
    trap: tuple | None
    raw_ops: tuple
    candidate: bool
    signature: tuple | None
    failure: str | None
    form: tuple
    segment: bool


def row_proof(f, result, lift, ballot, window, global_reason=False):
    import common_facts as cf
    import compare
    import decoders

    w = (result or {}).get("window", {})
    n = w.get("verified", 0)
    data = (window or b"")[:n]
    isa = f.get("isa")
    if isa != "x86-64":
        return Proof(isa, n, None, (), False, None, None, (None, False), False)

    skip = set(lift.skipped if lift else ())
    if lift and lift.pattern in ("interrupt", "interrupt-return", "fault"):
        skip.add(1)
    ops = tuple(i for i, op in enumerate(f["ops"]) if i not in skip and op["opcode"] in TRANSFER_OPS)
    trap = trap_outcome(result, ballot, data, global_reason)
    votes = [d for v, names in (("intel", decoders.INTEL_VOTERS), ("amd", decoders.AMD_VOTERS))
             for d in (ballot or {}).get(v, ()) if d.voter in names and d.amd == (v == "amd")]
    candidate = any(d.status == "ok" and d.flow in DECODER_FORMS for d in votes)
    sig = failure = None
    if not _ballot_ok(ballot):
        failure = "BALLOT_MISSING"
    elif any(d.status != "ok" or not 0 < d.length <= len(data) for d in votes):
        failure = "VENDOR_VIEW_CONFLICT"
    else:
        signatures = {(d.flow, d.indirect, d.length, None if d.indirect else d.target) for d in votes}
        if len(signatures) == 1:
            sig = signatures.pop()
        else:
            failure = "VENDOR_VIEW_CONFLICT"
    prefix = compare._prefix_run(data)
    return Proof(isa, n, trap, ops, candidate, sig, failure, cf.producer_form(f, lift, data),
                 any(b in (0x64, 0x65) for b in prefix))


def window_ref(rows, i):
    return {"g1_window": {"row": i, "decode_row": [rows[i]["space"], rows[i]["offset"]]}}


def _groups(pairs):
    grouped = defaultdict(dict)
    for why, item in pairs:
        if why not in REASONS:
            raise ValueError(why)
        grouped[why][_canonical(item)] = item
    return [{"reason": why, "items": [items[k] for k in sorted(items, key=lambda k: (_item_key(items[k]), k))]}
            for why, items in sorted(grouped.items())]


def verified_lists(rows, regions, lengths):
    windows = defaultdict(list)
    for i, (r, n) in enumerate(zip(rows, lengths, strict=True)):
        if n:
            a = int(r["offset"], 16)
            windows[r["space"]].append((a, i, a + n))
    for wins in windows.values():
        wins.sort()

    result, totals = [], []
    for item in regions:
        r = item["range"]
        spans, refs = [], []
        if isinstance(r["end"], str):
            a, z = int(r["start"], 16), int(r["end"], 16)
            wins = windows.get(r["space"], [])
            j = bisect_left(wins, (a - 14,))
            while j < len(wins) and wins[j][0] < z:
                x, i, y = wins[j]
                lo, hi = max(a, x), min(z, y)
                if lo < hi:
                    spans.append((lo, hi))
                    refs.append((i, lo, hi))
                j += 1
        result.append([{"interval": [_hx(lo), _hx(hi)], "basis": window_ref(rows, i)}
                       for i, lo, hi in sorted(refs)])
        totals.append(_union_length(spans))
    return result, totals


def verified_encoding(size):
    return {"form": "compact" if size > VERIFIED_THRESHOLD else "explicit",
            "explicit_bytes": size, "threshold": VERIFIED_THRESHOLD}


class CodeBinder:
    def __init__(self, ff, base, space, rows, code_rows, row_set_sha256, missing=()):
        import common_facts as cf

        self.ff, self.base, self.space, self.rows = ff, base, space, rows
        self.keys = [cf.rr(r) for r in rows]
        self.proofs = [code_rows[k] for k in self.keys]
        self.va = [int(r["offset"], 16) for r in rows]
        self.digest = row_set_sha256
        self.missing = sorted(missing)

    def _range(self, start, end, why="SECTION_EXTENT_U"):
        return {"space": self.space, "load_base": _hx(self.base), "start": _hx(self.base + start),
                "end": {"unobserved": why} if end is None else _hx(self.base + end)}

    def diagnostic(self, d):
        why = d["reason"]
        if "range" in d:
            result = {"reason": why, "scope_item": {"basis": d["basis"],
                      "range": self._range(**d["range"], why=why)}}
        else:
            result = dict(d)
        if "file_runtime" in d["basis"]:
            result["holds_if"] = [PREMISE]
        return result

    def coverage(self, kind, method, unresolved=(), unsupported=(), ranges=(), groups=None):
        arm = method == "a64_instruction"
        excluded = [{"row": i, "reason": "NOT_A64" if arm else "NOT_X86"}
                    for i, p in enumerate(self.proofs) if p.isa != ("aarch64" if arm else "x86-64")]
        scope = {"facts_rows": self.digest, "excluded": excluded}
        if len(excluded) == len(self.rows):
            scope["empty"] = True
        return dict(kind=kind, method=method, rows_examined=scope, ranges_examined=list(ranges),
                    unresolved=_groups(unresolved) if groups is None else groups,
                    unsupported=_groups(unsupported), missing_functions=self.missing)

    def program_code(self, sha, imports=None):
        regions = []
        diagnostics = [self.diagnostic(d) for d in self.ff.diagnostics]
        unknown = {(d["range"]["start"], _canonical(d["basis"])): d["reason"] for d in self.ff.diagnostics
                   if "range" in d and d["range"]["end"] is None}
        for r in self.ff.code + self.ff.unwind:
            why = unknown.get((r.start, _canonical(r.basis)), "SECTION_EXTENT_U") if r.end is None else None
            item = dict(range=self._range(r.start, r.end, why), role=r.role, name=r.name, basis=r.basis)
            if r.role == "code":
                item.update(executable=r.executable, writable=r.writable)
            if "file_runtime" in r.basis:
                item["holds_if"] = [PREMISE]
            regions.append(item)

        lengths = [p.verified for p in self.proofs]
        verified, totals = verified_lists(self.rows, regions, lengths)
        enc = verified_encoding(len(_canonical(verified)))
        out = dict(premise=PREMISE, name_table_sha256=sha,
                   file=dict(format=self.ff.format, ok=self.ff.ok, why=self.ff.why),
                   regions=regions, diagnostics=diagnostics, verified_encoding=enc)
        for r, v, total in zip(regions, verified, totals, strict=True):
            r["verified_bytes"] = total
            if enc["form"] == "explicit":
                r["verified"] = v
        if enc["form"] == "compact":
            out.update(verified_lengths=lengths, verified_rule={"per_row_window": self.digest})
        out["rows_outside_code"] = [i for i, a in enumerate(self.va) if self.rows[i]["space"] != self.space or
                                    not any(r.start <= a - self.base < r.end for r in self.ff.code)]

        sites, unresolved, syscalls, arm, details = [], [], [], [], Counter()
        for i, p in enumerate(self.proofs):
            at = {"row": i, "op": None}
            if p.isa == "aarch64":
                arm.append(("G2C", at))
            if not p.trap:
                continue
            state, value, *detail = p.trap
            if state == "unresolved":
                unresolved.append((value, at))
                details.update(detail)
                continue
            site = dict(value, row=i, kind="trap_instruction", symbol=None, arguments=[], holds_if=[PREMISE],
                        basis=dict(value["basis"], **window_ref(self.rows, i)))
            sites.append(site)
            if "vendor_views" in site or site["form"] in ("syscall", "int_n"):
                syscalls.append(("NO_ABI_BASIS", at))

        surveys = [self.coverage("trap_instruction", "x86_instruction", unresolved),
                   self.coverage("cache_maintenance", "syscall", unresolved, syscalls)]
        for kind in ("trap_instruction", "cache_maintenance"):
            surveys.append(self.coverage(kind, "a64_instruction", unsupported=arm))

        if imports is not None:
            found, us = imports.run()
            sites.extend(found)
            groups = _groups((w, it) for w, it in us if w not in ("NO_RWX_REGISTER", "PARSER_UNSUPPORTED"))
            rwx = _groups((w, it) for w, it in us if w == "NO_RWX_REGISTER")
            failures = [(w, it) for w, it in us if w == "PARSER_UNSUPPORTED"]
            problems = [self.diagnostic(d) for d in self.ff.import_problems]
            for d in problems:
                if "scope_item" in d:
                    failures.append((d["reason"], d["scope_item"]))
            for kind in sorted(set(imports.kind_of.values())):
                selected = sorted(groups + rwx, key=lambda g: g["reason"]) if kind == RWX_KIND else groups
                cov = self.coverage(kind, "import_transfer", unsupported=failures, groups=selected)
                cov["import_table"] = {"state": self.ff.import_state, "problems": problems}
                surveys.append(cov)

            found, us = imports.stores()
            sites.extend(found)
            ranges = [dict(range=r["range"], basis=r["basis"]) for r in regions if r["role"] == "code"]
            surveys.append(dict(self.coverage("code_write", "static_store", us, ranges=ranges),
                                write="static_store_candidate"))
        return dict(out, sites=sorted(sites, key=lambda s: (s["row"], s["kind"], s.get("op", -1))),
                    survey=surveys, trap_unresolved_details=dict(details))


class ImportSites:
    def __init__(self, binder, raw, kinds, complete, image=None, original=None):
        b = self.b = binder
        self.ff = b.ff
        self.raw = [raw[k] for k in b.keys]
        self.kind_of = {name: kind for kind, names in kinds.items() for name in names}
        self.complete = complete
        self.image, self.original = image, original
        self.starts, self.by_space = defaultdict(list), defaultdict(list)
        self.entries, self.unknown_edges = defaultdict(set), set()
        self.parents, self.endbr, self.stubs, self.states = {}, {}, {}, {}

        for i, r in enumerate(b.rows):
            space, a = r["space"], b.va[i]
            self.starts[space, a].append(i)
            self.by_space[space].append((a, i))
            f = self.raw[i]
            for target in f.get("flow_target_coords", ()):
                self.entries[tuple(target)].add((i, "encoded_target"))
            for target in f.get("recorded_landing_pads") or ():
                self.entries[tuple(target)].add((i, "pad"))
            for t in (r["transfer"], *(r.get("vendor_views") or {}).values()):
                edges = t.get("edges")
                if not isinstance(edges, list):
                    self.unknown_edges.add(space)
                    continue
                for e in edges:
                    to = e.get("to")
                    if isinstance(to, dict) and "offset" in to:
                        self.entries[to["space"], int(to["offset"], 16)].add((i, e["source"]))
                    elif e.get("source") in ("encoded_target", "sequential"):
                        self.unknown_edges.add(space)
        for spans in self.by_space.values():
            spans.sort()

    def between(self, space, a, z):
        spans = self.by_space.get(space, ())
        return spans[bisect_left(spans, (a,)):bisect_left(spans, (z,))]

    def covering(self, space, va):
        for a, j in self.between(space, va - 14, va):
            n = self.b.rows[j]["length"]
            known = type(n) is int and 0 < n <= 15
            if not known or a + n > va:
                yield j, known

    def predecessor(self, i):
        import lifting

        if i in self.parents:
            return self.parents[i]
        b = self.b
        r = b.rows[i]

        def same(j):
            s = b.rows[j]
            return (s["observation"], s["view"]) == (r["observation"], r["view"])

        here = r["space"], b.va[i]
        seq = [j for j, role in self.entries[here] if role == "sequential" and same(j)]
        parent = None
        if len(seq) == 1:
            j = seq[0]
            s = b.rows[j]
            edges = s["transfer"].get("edges")
            if (self.entries[here] == {(j, "sequential")} and type(s["length"]) is int
                    and 0 < s["length"] <= 15 and b.va[j] + s["length"] == here[1]
                    and s["transfer"]["kind"] == "none" and isinstance(edges, list) and len(edges) == 1
                    and edges[0]["source"] == "sequential"
                    and not any(same(k) for k, _ in self.covering(*here))
                    and not any(same(k) for k, _ in self.covering(r["space"], b.va[j]))
                    and not any(a > b.va[j] and same(k) for a, k in self.between(r["space"], b.va[j], here[1]))
                    and sum(same(k) for k in self.starts[r["space"], b.va[j]]) == 1
                    and sum(same(k) for k in self.starts[here]) == 1
                    and not any(o["opcode"] in lifting.FLOW_OPS for o in self.raw[j]["ops"])):
                parent = j
        self.parents[i] = parent
        return parent

    def _apply(self, defs, j):
        for n, op in enumerate(self.raw[j]["ops"]):
            out = op.get("output")
            if not out:
                continue
            s, a, w = key = out["space"], out["offset"], out["size"]
            args = op["inputs"]
            value = None
            if _gpr(out):
                if (op["opcode"] == "COPY" and len(args) == 1 and args[0]
                        and args[0]["kind"] == "CONSTANT" and args[0]["size"] == w):
                    value = args[0]["offset"] % (1 << (8 * w))
                elif (op["opcode"] in ("INT_XOR", "INT_SUB") and len(args) == 2
                      and args[0] == args[1] and _gpr(args[0]) and args[0]["size"] == w):
                    value = 0
                elif (op["opcode"] == "INT_ZEXT" and w == 8 and a % 8 == 0
                      and len(args) == 1 and args[0] == dict(out, size=4)):
                    prior = defs.get((s, a, 4))
                    if prior and prior[1:] == (j, n - 1):
                        value = prior[0]
            for k in list(defs):
                if k[0] == s and k[1] < a + w and a < k[1] + k[2]:
                    del defs[k]
            if value is not None:
                defs[key] = value, j, n

    def register_values(self, i, ordinal, wanted=None):
        if not self.complete or self.b.rows[i]["space"] in self.unknown_edges:
            return [], "INDEX_INCOMPLETE"
        j, todo = i, []
        while j not in self.states:
            j = self.predecessor(j)
            if j is None:
                break
            todo.append(j)
        defs = self.states.get(j, {}).copy()
        for k in reversed(todo):
            self._apply(defs, k)
        if i not in self.states:
            if len(self.states) >= 1024:
                self.states.pop(next(iter(self.states)))
            self.states[i] = defs

        values = []
        for key, (v, j, n) in sorted(defs.items()):
            if wanted is not None and key not in wanted:
                continue
            path = [i]
            while path[-1] != j:
                path.append(self.predecessor(path[-1]))
            s, a, w = key
            values.append(dict(register=dict(name=GPR[a & ~7], space=s, offset=a, size=w),
                               value=dict(constant=_hx(v), width=8 * w), definition=dict(row=j, op=n),
                               use=dict(row=i, op=ordinal), path=path[::-1], basis="ghidra_pcode",
                               holds_if=[PREMISE, LINEAR_PREMISE]))
        return values, None

    def exact(self, i):
        import common_facts as cf

        r, p = self.b.rows[i], self.b.proofs[i]
        keys = r["transfer"].get("op_keys")
        op = keys.get("transfer") if isinstance(keys, dict) else None
        if not op or op.get("ordinal") not in p.raw_ops:
            return None
        try:
            cf.resolve(op, r, self.raw[i])
        except ValueError:
            return None
        return op["ordinal"]

    def transfer(self, i, n):
        import common_facts as cf

        b = self.b
        r, p = b.rows[i], b.proofs[i]
        flow, ind = p.form
        opcode = self.raw[i]["ops"][n]["opcode"]
        mem = (r["transfer"].get("target_value") or {}).get("memory", {})
        if ind:
            operand = self.raw[i]["ops"][n]["inputs"][0]
            if p.segment or mem.get("segment_base") is not None:
                raise Unread("SEGMENT_BASE")
            if (operand and operand["size"] != 8) or (mem and mem["size"] != 8):
                raise Unread("POINTER_WIDTH")
            if r["space"] != b.space or (mem and mem["space"] != b.space):
                raise Unread("SPACE_MISMATCH")
            if operand and operand["kind"] in ("REGISTER", "UNIQUE"):
                for op in reversed(self.raw[i]["ops"][:n]):
                    o = op.get("output")
                    if o and _overlaps(o, operand):
                        if o == operand and op["opcode"] == "LOAD":
                            sel = op["inputs"][0]
                            if sel and sel["kind"] == "CONSTANT" and sel["offset"] != b.space:
                                raise Unread("SPACE_MISMATCH")
                        break

        if p.failure:
            raise Unread(p.failure)
        fl, indirect, length, dst = p.signature
        if (fl, indirect) != (flow, ind) or fl not in DECODER_FORMS:
            raise Unread("FORM_MISMATCH")
        form = DECODER_FORMS[fl]
        if r["space"] != b.space:
            raise Unread("SPACE_MISMATCH")
        if length != r["length"]:
            raise Unread("FORM_MISMATCH")
        if (ind != (opcode in ("CALLIND", "BRANCHIND")) or
                TRANSFER_OPS[opcode] != form and not (form == "call" and opcode == "BRANCH")):
            raise Unread("FORM_MISMATCH")

        role = cf.TAKEN if form == "jcc" else cf.DIRECT
        edge = None
        for vendor in (None, *cf.VENDORS) if r.get("vendor_views") else (None,):
            m = cf.member(r, vendor)
            if m["length"] != length or ind and m.get("target_value") != r["transfer"]["target_value"]:
                raise Unread("VENDOR_VIEW_CONFLICT")
            if not ind:
                es = [e for e in m["edges"] if cf.triple(e) == role] if isinstance(m["edges"], list) else []
                if len(es) != 1 or not isinstance(es[0].get("to"), dict) or "offset" not in es[0]["to"]:
                    raise Unread("VENDOR_VIEW_CONFLICT" if vendor else "TARGET_LIFT_U")
                to = es[0]["to"]
                if to["space"] != b.space:
                    raise Unread("SPACE_MISMATCH")
                if dst != int(to["offset"], 16):
                    raise Unread("VENDOR_VIEW_CONFLICT" if vendor or r.get("vendor_views") else "FORM_MISMATCH")
                edge = dict(zip(cf.EC, role), to=to)

        step = dict(row=i, op=n, step="ghidra_pcode")
        if edge is not None:
            step["edge"] = edge
            return form, False, dst, step
        addr = mem.get("address", {})
        if set(addr) != {"constant", "width"} or addr["width"] != 64:
            raise Unread("COMPUTED_TARGET")
        return form, True, int(addr["constant"], 16), step

    def read_endbr(self, i):
        if self.b.rows[i]["length"] != 4:
            return False
        va = self.b.va[i]
        if va not in self.endbr:
            try:
                if self.image is None:
                    raise Unread("MAP_INDETERMINATE")
                raw, basis = runtime_read(self.image, self.original, va - self.b.base, 4)
                self.endbr[va] = (basis if raw == ENDBR64 else False), None
            except Unread as exc:
                self.endbr[va] = None, exc.reason
        result, why = self.endbr[va]
        if why:
            raise Unread(why)
        return result

    def stub(self, space, va):
        """Fourth route for an unlisted [ENDBR64] [BND] RIP-relative slot jump in decided executable bytes."""
        import decoders

        b = self.b
        if space != b.space or not self.image or not self.ff.ok:
            return None
        if va in self.stubs:
            return self.stubs[va]
        self.stubs[va] = None
        start = va - b.base

        def read(offset, n):
            return runtime_read(self.image, self.original, start + offset, n)

        try:
            first, _ = read(0, 1)
            skip = 0
            if first == b"\xf3":
                if read(0, 4)[0] != ENDBR64:
                    return None
                skip = 4
            bnd = int(read(skip, 1)[0] == b"\xf2")
            n = bnd + 6
            size = skip + n
            if not any(r.executable and r.start <= start and start + size <= r.end for r in self.ff.code):
                return None
            raw, basis = read(0, size)
        except Unread:
            return None
        jump = raw[skip:]
        if jump[bnd:bnd + 2] != b"\xff\x25":
            return None
        votes = decoders.ballot(jump, va + skip)
        if not _ballot_ok(votes) or any(d.status != "ok" or d.flow != "jmp_near" or
                not d.indirect or d.length != n for v in ("intel", "amd") for d in votes[v]):
            return None
        slot = (va + size + int.from_bytes(jump[-4:], "little", signed=True)) % (1 << 64)
        step = dict(stub=_hx(va), space=space, load_base=_hx(b.base), length=size, jump_offset=skip,
                    decoders={v: ballot_digest(votes[v]) for v in ("intel", "amd")}, **basis)
        self.stubs[va] = slot, [step]
        return self.stubs[va]

    def thunk(self, j):
        b = self.b
        path = []
        if b.rows[j]["transfer"]["kind"] == "none":
            marker = self.read_endbr(j)
            if marker:
                if b.proofs[j].signature != ("none", False, 4, None):
                    raise Unread("TARGET_LIFT_U")
                path.append(dict(row=j, op=None, **marker))
                r = b.rows[j]
                va = b.va[j] + 4
                ns = [k for k in self.starts[r["space"], va] if b.rows[k]["view"] == r["view"]
                      and b.rows[k]["observation"] == r["observation"]]
                edges = r["transfer"]["edges"]
                if (len(ns) != 1 or len(edges) != 1 or edges[0]["source"] != "sequential"
                        or edges[0].get("to") != {"space": r["space"], "offset": _hx(va)}
                        or any(b.rows[k]["observation"] == r["observation"] and b.rows[k]["view"] == r["view"]
                               for k, _ in self.covering(r["space"], va))):
                    raise Unread("TARGET_LIFT_U")
                j = ns[0]
        p = b.proofs[j]
        n = self.exact(j)
        if n is None:
            if p.raw_ops or p.candidate or b.rows[j]["transfer"]["kind"] == "unknown" or p.failure:
                raise Unread("TARGET_LIFT_U")
            if path:
                raise Unread("ELF_STUB_UNSUPPORTED" if self.ff.format == "elf" else "TARGET_LIFT_U")
            return None
        form, ind, dst, step = self.transfer(j, n)
        if form == "jump":
            if not ind:
                raise Unread("MULTI_HOP")
            return dst, path + [step]
        if path:
            raise Unread("ELF_STUB_UNSUPPORTED" if self.ff.format == "elf" else "TARGET_LIFT_U")
        return None

    def direct(self, i, va):
        b = self.b
        space = b.rows[i]["space"]
        candidates = self.starts.get((space, va), ())
        inside = list(self.covering(space, va))
        if any(known for _, known in inside):
            raise Unread("VENDOR_VIEW_CONFLICT" if candidates else "TARGET_NOT_ROW_START")
        if inside:
            raise Unread("INDEX_INCOMPLETE")
        if not candidates:
            if not self.complete:
                raise Unread("INDEX_INCOMPLETE")
            result = self.stub(space, va)
            if result is None:
                raise Unread("TARGET_OUTSIDE_ROWS")
            return *result, [], "via_stub_bytes"
        if any(b.rows[j]["view"] != b.rows[i]["view"] for j in candidates):
            raise Unread("VENDOR_VIEW_CONFLICT")

        outcomes = []
        for j in candidates:
            try:
                outcomes.append((self.thunk(j), None))
            except Unread as exc:
                outcomes.append((None, exc.reason))

        def meaning(result, why):
            if result is None:
                return why, None
            return None, (result[0], tuple((b.va[s["row"]], s["op"]) for s in result[1]))

        if len({meaning(*v) for v in outcomes}) != 1:
            raise Unread("VENDOR_VIEW_CONFLICT")
        first, why = outcomes[0]
        if why:
            raise Unread(why)
        if first is None:
            return None
        paths = [v[0][1] for v in outcomes]
        return first[0], paths[0], paths[1:], "via_thunk"

    def run(self):
        b = self.b
        sites, unresolved, reached = [], [], set()
        for i, p in enumerate(b.proofs):
            if p.isa != "x86-64":
                continue
            n = self.exact(i)
            for k in p.raw_ops:
                if k != n:
                    unresolved.append(("TRANSFER_UNBOUND", dict(row=i, op=k)))
            if n is None:
                if not p.raw_ops and (p.candidate or b.rows[i]["transfer"]["kind"] == "unknown" and p.failure):
                    unresolved.append(("TRANSFER_UNBOUND", dict(row=i, op=None)))
                continue

            at = dict(row=i, op=n)
            try:
                form, ind, slot, source = self.transfer(i, n)
                hop, alternatives, route = [], [], "direct_slot"
                if not ind:
                    result = self.direct(i, slot)
                    if result is None:
                        continue
                    slot, hop, alternatives, route = result

                coord = slot - b.base
                if coord in self.ff.slot_failures:
                    raise Unread(self.ff.slot_failures[coord])
                item = self.ff.imports.get(coord)
                if item is None:
                    raise Unread({"complete": "SLOT_NOT_IMPORT", "absent": "NO_IMPORT_DIRECTORY"}
                                 .get(self.ff.import_state, "PARSER_UNSUPPORTED"))
                if "ordinal" in item:
                    raise Unread("IMPORT_BY_ORDINAL")
                if not item.get("undefined", True):
                    raise Unread("SLOT_NOT_IMPORT")
                name = item["name"]
                kind = self.kind_of.get(name)
                if kind is None:
                    continue
                if route == "via_thunk":
                    reached.update((q[-1]["row"], q[-1]["op"], kind) for q in [hop, *alternatives])
                values, reason = self.register_values(i, n)
                basis = {k: dict(v, slot_va=_hx(slot)) for k, v in item["basis"].items()}
                basis.update(path=[source, *hop], step="ghidra_pcode")
                if alternatives:
                    basis["equivalent_paths"] = [[source, *q] for q in alternatives]
                site = dict(at, form=form, kind=kind, route=route, arguments=[], register_values=values,
                            symbol=dict(name=name, dll=item.get("dll"), slot=_hx(slot), basis=basis),
                            holds_if=[PREMISE, IMPORT_PREMISE] + ([LINEAR_PREMISE] if values else []))
                if reason:
                    site["register_values_reason"] = reason
                if kind == RWX_KIND:
                    hits = [v["register"]["name"] for v in values if v["register"]["offset"] % 8 == 0
                            and v["value"]["width"] in (32, 64)
                            and int(v["value"]["constant"], 16) in RWX[self.ff.format]]
                    if not hits:
                        unresolved.append(("NO_RWX_REGISTER", dict(at, api=name)))
                        continue
                    site.update(candidate=True, rwx_registers=hits, protection_argument={"unobserved": "NO_ABI_BASIS"})
                if kind == "dynamic_resolution":
                    site["requested_name"] = {"unobserved": "NO_ABI_BASIS"}
                sites.append(site)
            except Unread as exc:
                unresolved.append((exc.reason, at))

        for s in sites:
            if s["route"] == "direct_slot" and (s["row"], s["op"], s["kind"]) in reached:
                s["route"] = "thunk_row"
        return sites, unresolved

    def stores(self):
        import common_facts as cf
        import lifting

        b = self.b
        sites, unresolved = [], []
        for i, (p, f) in enumerate(zip(b.proofs, self.raw, strict=True)):
            if p.isa != "x86-64":
                continue
            for n, op in enumerate(f["ops"]):
                if op["opcode"] != "STORE":
                    continue
                at = dict(row=i, op=n)
                try:
                    args = op["inputs"]
                    if len(args) != 3 or not cf.const(args[0]):
                        raise Unread("STORE_SPACE_U")
                    if not args[2] or type(args[2]["size"]) is not int or args[2]["size"] <= 0:
                        raise Unread("STORE_WIDTH_U")
                    if b.space is None:
                        raise Unread("TARGET_MAPPING_U")
                    if args[0]["offset"] != b.space:
                        continue
                    if any(o["opcode"] in lifting.FLOW_OPS for o in f["ops"][:n]):
                        raise Unread("INTRA_ROW_FLOW")
                    expr, used = cf.value(f, args[1], n)
                    defs, regs = [], {}
                    wanted = {(r["space"], r["offset"], r["size"])
                              for leaf in _leaves(expr) for r in [leaf["pre_register"]]}
                    if wanted:
                        defs, why = self.register_values(i, n, wanted)
                        if why:
                            raise Unread(why)
                        for v in defs:
                            r = v["register"]
                            regs[r["space"], r["offset"], r["size"]] = int(v["value"]["constant"], 16)
                    address = _evaluate(expr, regs) if expr.get("width") == 64 else None
                    if address is None:
                        raise Unread("STORE_ADDRESS_NOT_CONSTANT")
                    end = address + args[2]["size"]
                    if end > 1 << 64:
                        raise Unread("ADDRESS_WRAP")
                    if not self.ff.ok:
                        raise Unread("TARGET_MAPPING_U")
                    a, z = address - b.base, end - b.base
                    hit = [j for j, r in enumerate(self.ff.code) if r.start < z and a < r.end]
                    if not hit:
                        if any(d.get("basis", {}).keys() & {"pe_section", "elf_segment"} and
                               d["range"]["start"] < z and a < d["range"]["end"] for d in self.ff.diagnostics):
                            raise Unread("TARGET_MAPPING_U")
                        continue
                    basis = dict(step="ghidra_pcode", use=at, in_row=[dict(row=i, op=j) for j in sorted(used)],
                                 expression=expr, register_values=defs)
                    sites.append(dict(at, form="store", kind="code_write", write="static_store_candidate",
                                      symbol=None, arguments=[], target_range=b._range(a, z), regions=hit,
                                      static_basis=basis, holds_if=[PREMISE] + ([LINEAR_PREMISE] if defs else [])))
                except Unread as exc:
                    unresolved.append((exc.reason, at))
        return sites, unresolved


def build_code(rows, raw, proofs, image, original, space, base, complete, missing):
    import common_facts as cf

    ff = file_facts(image, original)
    if ff.ok and image.fixed_base and image.image_base != base:
        ff = FileFacts(ff.format, False, "fixed load base mismatch", import_state="indeterminate")
    kinds, sha = name_table()
    binder = CodeBinder(ff, base, space, rows, proofs, cf.row_set_digest(rows), missing)
    return binder.program_code(sha, ImportSites(binder, raw, kinds, complete, image, original))


def summary(code):
    if code["name_table_sha256"] != name_table()[1]:
        raise ValueError("name table digest mismatch")
    sites = code["sites"]
    counts = Counter(s["kind"] for s in sites)
    forms = Counter(s["form"] if isinstance(s["form"], str) else "vendor_split"
                    for s in sites if s["kind"] == "trap_instruction")
    api = Counter((s["symbol"]["name"], "candidate") for s in sites if s.get("candidate"))
    methods, unresolved, unsupported = {}, {}, {}
    for c in code["survey"]:
        k, m = c["kind"], c["method"]
        key = k + "/" + m
        if m == "import_transfer":
            selected = [s for s in sites if s["kind"] == k and "route" in s]
        elif m in ("x86_instruction", "static_store"):
            selected = [s for s in sites if s["kind"] == k and "route" not in s]
        else:
            selected = []
        for field, target in (("unsupported", unsupported), ("unresolved", unresolved)):
            target[key] = {g["reason"]: len(g["items"]) for g in c[field]}
        methods[key] = dict(sites=len(selected), candidates=sum(bool(s.get("candidate")) for s in selected),
                            excluded=len(c["rows_examined"]["excluded"]),
                            unresolved=unresolved[key], unsupported=unsupported[key])
        for g in c["unresolved"]:
            if g["reason"] == "NO_RWX_REGISTER":
                api.update((it["api"], g["reason"]) for it in g["items"])
    return dict(rule=FACTS_RULE, sites=dict(counts), trap_forms=dict(forms), methods=methods,
                unresolved=unresolved, unsupported=unsupported, trap_unresolved_details=code["trap_unresolved_details"],
                import_routes=dict(Counter(s["route"] for s in sites if "route" in s)),
                rwx_per_api={a + "/" + why: n for (a, why), n in sorted(api.items())},
                regions=[{k: r[k] for k in ("name", "role", "verified_bytes")} for r in code["regions"]],
                rows_outside_code=len(code["rows_outside_code"]), verified_encoding=code["verified_encoding"],
                name_table_sha256=code["name_table_sha256"])
```

## 2. `tools/decode_check/decode_check.py`

```python
# collect().keep(): replace the existing found.update(...) after ns is assigned.
        found.update(language=ns.language_id, language_version=(ns.major_version, ns.minor_version),
                     image_base=ev.image_base.byte_offset, image_space=ev.image_base.space_id)

# CommonFactsCollector.__call__(): replace the G2b block after self.branch_self
# and before the existing "# Retain only the comparison inputs" comment.
        import code_facts

        self.code_rows[k] = code_facts.row_proof(facts, result, lift, ballot, window, self.global_reason)

# run(): replace the block from "names, names_sha256 = code_facts.name_table()"
# through the assignment to doc["program"]["code"]. Use the existing `complete`.
        missing_functions = {m["id"] for m in manifest["functions"]} - seen
        doc["program"]["code"] = code_facts.build_code(
            doc["rows"], common.raw, common.code_rows, mapping, original,
            facts["image_space"], base, complete, missing_functions,
        )

# run(): replace the two header["common_facts"] assignments, after common_block.
        header["common_facts"] = common_summary(
            facts, common, doc, complete=complete, missing_functions=missing_functions,
        )
        header["common_facts"]["code"] = dict(
            code_facts.summary(doc["program"]["code"]), bundle=doc["bundle"],
        )
```

## 3. `tools/decode_check/evidence.py`

`g2b`는 reader 호출자가 같은 admitted generation에서 구성하는 입력입니다. `report`는 `report.dumps()`의 JSON 객체이며 기본 report와 `--full` report를 모두 지원합니다. `lookup.code`에서 확장된 verified 목록과 survey를 읽을 수 있습니다.

```python
# Add this function at module scope.

def read_g2b(document, facts, observations, context):
    import hashlib
    import check
    import code_facts as g
    import common_facts as cf
    import decoders
    import lifting

    try:
        if context is None:
            raise ValueError("g2b-1 requires the admitted image inputs and its G1 report")
        rows = facts["rows"]
        code = facts["program"]["code"]
        if code["name_table_sha256"] != g.name_table()[1]:
            raise ValueError("name table digest")
        report = context["report"]
        header = report["header"]
        original = context["original"]
        if (hashlib.sha256(original).hexdigest() != document["bundle"]["original_sha256"]
                or header["common_facts"]["code"]["bundle"] != facts["bundle"]
                or header["mapping_id"] != document["mapping"]["mapping_id"]):
            raise ValueError("report or original belongs to a different Bundle")
        image = check.parse_original(original)
        if image.mapping_id != header["mapping_id"]:
            raise ValueError("file mapping")

        expected = {f"{r['observation']}/{r['space']:x}:{r['offset']}" for r in rows}
        details = {}
        for row in report["rows"]:
            if (row["layer"], row["check"]) == ("decode", "row"):
                key = row["key"]
                if key in details:
                    raise ValueError("duplicate G1 row " + key)
                details[key] = row["detail"]
        if expected != details.keys() or len(rows) != len(expected):
            raise ValueError("G1 row set")

        lengths, proofs = [], {}
        global_reason = document["global_reason"] is not None
        for r in rows:
            k = cf.rr(r)
            f = observations[k]
            detail = details[f"{k[1]}/{r['space']:x}:{r['offset']}"]
            w = detail.get("window")
            raw = b"" if w is None else bytes.fromhex(w["hex"])
            n = 0 if w is None else w["verified"]
            if type(n) is not int or not 0 <= n <= 15 or n != len(raw):
                raise ValueError("G1 window length")
            lengths.append(n)
            ballot = None
            if w is not None and f.get("isa") == "x86-64":
                if "votes" in detail:
                    ballot = {v: tuple(decoders.Decoded(**d) for d in ds) for v, ds in detail["votes"].items()}
                else:
                    ballot = decoders.ballot(raw, f["address"])
            lift = lifting.identify(f) if document["translation"]["table_applied"] and not global_reason else None
            proofs[k] = g.row_proof(f, detail if w is not None else None, lift, ballot, raw, global_reason)

        digest = cf.row_set_digest(rows)
        if code["verified_encoding"]["form"] == "compact":
            stored = code["verified_lengths"]
            if (code["verified_rule"] != {"per_row_window": digest} or type(stored) is not list
                    or any(type(n) is not int for n in stored) or stored != lengths):
                raise ValueError("compact G1 binding")

        # Reconstruct before exposing references. This checks the threshold, explicit
        # bytes, bases, union lengths, exclusions, op ordinals, paths and API scopes.
        rebuilt = g.build_code(rows, observations, proofs, image, original, context["image_space"],
                               context["image_base"], context["complete"], context["missing_functions"])
        if cf.streamed_digest(code) != cf.streamed_digest(rebuilt):
            raise ValueError("program.code differs from its bound inputs")
        if cf.canonical(dict(g.summary(code), bundle=facts["bundle"])) != cf.canonical(header["common_facts"]["code"]):
            raise ValueError("G2b report summary")

        lists, totals = g.verified_lists(rows, code["regions"], lengths)

        def expand(group):
            for item in group["items"]:
                entry = dict(item, reason=group["reason"])
                if "row" in item:
                    i, n = item["row"], item["op"]
                    entry["row"] = cf.ref(rows[i])
                    if n is not None:
                        entry["op"] = cf.opref(observations[cf.rr(rows[i])]["ops"], n)
                yield entry

        return dict(verified=lists, verified_bytes=totals, survey=[
            dict(c, **{field: [it for group in c[field] for it in expand(group)]
                       for field in ("unsupported", "unresolved")}) for c in code["survey"]])
    except (AttributeError, IndexError, KeyError, TypeError, ValueError, OverflowError) as exc:
        raise Rejected(f"invalid g2b-1 binding: {exc}") from exc


# Replace the signature of bind_common_facts. Keep its existing body up to and
# including the definition of exact_lookup.
def bind_common_facts(document, facts_document, *, bundle, allowlist, observations, g2b=None):

# Replace the final "return exact_lookup" of that function with this block.
    rule = facts_document.get("producer", {}).get("rule")
    code = facts_document.get("program", {}).get("code")
    if rule == "g2b-1":
        exact_lookup.code = read_g2b(document, facts_document, observations, g2b)
    elif isinstance(code, dict) and ("verified_encoding" in code or "survey" in code):
        raise Rejected("program.code requires producer.rule g2b-1")
    return exact_lookup
```

## 4. `tests/intra/test_decode_check.py`

아래는 `# -- G2b code-byte facts`부터 파일 끝까지의 교체본입니다.

```python
# -- G2b code-byte facts -----------------------------------------------------

import copy
import hashlib
import struct

import code_facts as g
import common_facts as cf
import decoders
import evidence
import lifting


def _g2b_pe(name="VirtualProtect", *, text=b"\x90" * 128, delay=False, attr=1,
            lookup=0x2100, stamp=0, second=0, uflags=9, tail=0x2400, count=1,
            pointer=0x2400, directory_size=None, first=0x2300):
    import _pe_fixture as pf

    ro = bytearray(0x500)
    if delay:
        desc = struct.pack("<8I", attr, 0x2200, 0, 0x4000, lookup, 0, 0, 0)
    else:
        desc = struct.pack("<5I", lookup, stamp, 0, 0x2200, 0x4000)
    ro[:len(desc)] = desc
    table = struct.pack("<3Q", first, second, 0)
    ro[0x100:0x118] = table
    ro[0x200:0x206] = b"k.dll\0"
    payload = b"\0\0" + name.encode() + b"\0"
    ro[0x300:0x300 + len(payload)] = payload
    ro[0x400:0x404] = bytes([uflags, 0, count, 0])
    struct.pack_into("<3I", ro, 0x404 + 2 * ((count + 1) & ~1), 0x1000, 0x1010, tail)
    pdata = struct.pack("<3I", 0x1000, 0x1010, pointer)
    sections = [
        pf.Section(".text", 0x1000, text),
        pf.Section(".rdata", 0x2000, bytes(ro), characteristics=0x40000040),
        pf.Section(".pdata", 0x3000, pdata, characteristics=0x40000040),
        pf.Section(".data", 0x4000, table, characteristics=0xc0000040),
    ]
    dirs = [pf.Directory(13 if delay else 1, 0x2000,
                         directory_size if directory_size is not None else 2 * len(desc)),
            pf.Directory(3, 0x3000, len(pdata))]
    return pf.make_pe(sections, size_of_headers=0x400, directories=dirs)


def _g2b_elf(kind=7, sym=1, defined=0, linked=False):
    import _elf_fixture as ef
    import elf_map

    ro = bytearray(0x300)
    struct.pack_into("<IBBHQQ", ro, 24, 1, 0x12, 0, defined, 0, 0)
    ro[0x100:0x10a] = b"\0mprotect\0"
    struct.pack_into("<5I", ro, 0x200, 1, 2, 1, 0, 0)
    rel = [ef.Reloc(0x5000, kind, sym)]
    kwargs = {"relocations" if kind == 6 else "jmprel": rel}
    tags = [] if linked else [(6, 0x3000), (11, 24), (5, 0x3100), (10, 10), (4, 0x3200)]
    elf = ef.make_elf([ef.Segment(0x1000, g.ENDBR64 + bytes(124)), ef.Segment(0x3000, ro, flags=4),
                       ef.Segment(0x5000, bytes(16), flags=6)], extra_dynamic=tags, **kwargs)
    if not linked:
        return elf.data

    data = bytearray(elf.data)
    image = elf_map.parse(elf.data)
    dyn = next(p for p in image.phdrs if p[0] == 2)
    va = next(v for t, v in struct.iter_unpack("<qQ", data[dyn[2]:dyn[2] + dyn[5]]) if t in (7, 23))
    names = b"\0.shstrtab\0.dynsym\0.dynstr\0.rela.plt\0.rela.dyn\0"
    off = len(data)
    data.extend(names)
    sh = len(data)

    def header(name, t, flags, a, fileoff, size, link=0, ent=0):
        return struct.pack("<IIQQQQIIQQ", names.index(name.encode() + b"\0"), t, flags, a, fileoff,
                           size, link, 0, 1, ent)

    data.extend(bytes(64) + header(".shstrtab", 3, 0, 0, off, len(names)))
    for name, t, a, size, link, ent in ((".dynsym", 11, 0x3000, 48, 3, 24),
                                        (".dynstr", 3, 0x3100, 10, 0, 0),
                                        (".rela.dyn" if kind == 6 else ".rela.plt", 4, va, 24, 2, 24)):
        fileoff = g.record_read(image, elf.data, a - image.image_base, 1)[1]["file_record"][0]
        data.extend(header(name, t, 2, a, fileoff, size, link, ent))
    struct.pack_into("<Q", data, 40, sh)
    struct.pack_into("<3H", data, 58, 64, 5, 1)
    return bytes(data)


def _g2b_votes(flow="none", length=1, indirect=False, target=None, status="ok", vector=None):
    return {v: tuple(decoders.Decoded(n, "fixture", v == "amd", status, length if status == "ok" else 0,
                                      flow=flow, indirect=indirect, target=target, int_vector=vector)
                     for n in names)
            for v, names in (("intel", decoders.INTEL_VOTERS), ("amd", decoders.AMD_VOTERS))}


def _entry(f, data, votes=None, *, fid="f0", rel=(), missing=False):
    data = bytes.fromhex(data) if isinstance(data, str) else data
    result = dict(window=dict(verified=len(data), hex=data.hex(), relocations=rel), attributes={})
    return (fid, f, lifting.identify(f), None if missing else votes or _g2b_votes(length=len(data)),
            result, data)


def _plain(ops, at=START, n=1, **kw):
    return dict(_row(n, ops), address=at, fallthrough=at + n, **kw)


def _slot(at, slot, call=True):
    ops = [_op("LOAD", [_c(1), _c(slot)], _u(0x30))]
    if call:
        ops += _push(at + 6)
    op = "CALLIND" if call else "BRANCHIND"
    f = dict(_row(6, ops + [_op(op, [_u(0x30)])], flow=_flow("call_indirect" if call else "jmp_indirect")),
             address=at, fallthrough=at + 6 if call else None)
    data = (b"\xff\x15" if call else b"\xff\x25") + struct.pack("<i", slot - at - 6)
    return _entry(f, data, _g2b_votes("call_near" if call else "jmp_near", 6, True))


def _direct(at, dst, cond=False):
    if cond:
        f = dict(_jcc(2, dst), address=at, fallthrough=at + 2)
        return _entry(f, bytes([0x75, (dst - at - 2) & 255]), _g2b_votes("jcc", 2, target=dst))
    f = dict(_row(5, [_op("BRANCH", [_a(dst)])], fallthrough=False, flow=_flow("jmp_direct")), address=at)
    return _entry(f, b"\xe9" + struct.pack("<i", dst - at - 5), _g2b_votes("jmp_near", 5, target=dst))


def _case(entries, raw=None, *, isa="x86-64", complete=True, missing=(), reader=False):
    import check

    raw = _g2b_pe() if raw is None else raw
    image = check.parse_original(raw)
    c = _g2_collect(entries, isa=isa)
    doc = _g2_document(c)
    doc["producer"]["rule"] = g.FACTS_RULE
    doc["program"]["isa"] = isa
    code = g.build_code(doc["rows"], c.raw, c.code_rows, image, raw, 1, BASE, complete, missing)
    doc["program"]["code"] = code
    if not reader:
        return code

    _, ev, args = _g2_binding5(c)
    ev["bundle"]["original_sha256"] = args["bundle"]["original_sha256"] = hashlib.sha256(raw).hexdigest()
    ev["mapping"].update(format=image.format, mapping_id=image.mapping_id)
    report = {"header": {"mapping_id": image.mapping_id, "common_facts": {
        "code": dict(g.summary(code), bundle=doc["bundle"])}}, "rows": []}
    for fid, f, _, ballot, result, _ in entries:
        detail = dict(result or {})
        if result and ballot is not None:
            detail["votes"] = {v: [d.as_json() for d in ds] for v, ds in ballot.items()}
        report["rows"].append(dict(layer="decode", check="row", key=f"{fid}/{f['space']:x}:{f['address']:x}",
                                   detail=detail))
    args.update(g2b=dict(original=raw, image_base=BASE, image_space=1, complete=complete,
                         missing_functions=missing, report=report))
    ev["common_facts"]["facts_sha256"] = cf.digest(doc)
    args["allowlist"] = [evidence.allowlist_entry(ev)]
    return doc, ev, args


def _reasons(code, kind=g.RWX_KIND, method="import_transfer", field="unresolved"):
    cov, = [c for c in code["survey"] if (c["kind"], c["method"]) == (kind, method)]
    return {group["reason"]: group["items"] for group in cov[field]}


@pytest.mark.parametrize("data,flow,status,vector,rel,expected", [
    ("cc", "int3", "ok", None, (), "int3"),
    ("f1", "int1", "ok", None, (), "int1"),
    ("48cd29", "int_n", "ok", 41, (), "int_n"),
    ("cd03", "int3", "ok", None, (), "TRAP_FORM_UNDECIDED"),
    ("0f05", "syscall", "ok", None, (), "syscall"),
    ("ce", "none", "invalid", None, (), None),
    ("ffff", "none", "invalid", None, (), "TRAP_FORM_UNDECIDED"),
    ("cd29", "int_n", "ok", 41, ((1, 1, "R"),), "RELOCATED_OPCODE"),
    ("90", "none", "ok", None, ((0, 1, "R"),), "RELOCATED_OPCODE"),
])
def test_g2b_traps(data, flow, status, vector, rel, expected):
    raw = bytes.fromhex(data)
    votes = _g2b_votes(flow, len(raw), status=status, vector=vector)
    doc, ev, args = _case([_entry(_row(6, []), raw, votes, rel=rel)], reader=True)
    evidence.bind_common_facts(ev, doc, **args)
    code = doc["program"]["code"]
    sites = code["sites"]
    u = _reasons(code, "trap_instruction", "x86_instruction")
    if expected in g.REASONS:
        assert not sites and u == {expected: [{"row": 0, "op": None}]}
        assert _reasons(code, "cache_maintenance", "syscall") == u
    elif expected is None:
        assert not sites and not u
    else:
        site, = sites
        assert (site["form"], site["vector"], site["immediate"]) == (
            expected, {"int3": 3, "int1": 1}.get(expected, vector), vector)
        assert site["basis"]["g1_window"] == {"row": 0, "decode_row": [1, f"{START:x}"]}
        assert site["basis"]["decoders"] == {v: cf.digest([d.as_json() for d in ds]) for v, ds in votes.items()}
        assert site["syscall_abi"] == (None if expected in ("int3", "int1") else {"unobserved": "NO_ABI_BASIS"})
    if status == "invalid" and data != "ce":
        assert g.summary(code)["trap_unresolved_details"] == {"ALL_INVALID_NOT_CE": 1}


@needs
def test_g2b_real_split_and_ce():
    import json

    for data in (b"\xce", b"\x0f\x34"):
        ballot = decoders.ballot(data, START)
        signatures = [(d.voter, d.amd, d.status, d.flow, d.length) for ds in ballot.values() for d in ds]
        ce = len(data) == 1
        assert signatures == [(n, amd, "invalid" if ce else "ok", "none" if ce else "sysenter", 0 if ce else 2)
                              for amd, names in [(False, decoders.INTEL_VOTERS), (True, decoders.AMD_VOTERS)]
                              for n in names]
        sites = _case([_entry(_row(len(data), []), data, ballot)])["sites"]
        if ce:
            assert sites == []
        else:
            site, = sites
            assert site["form"] == {"unobserved": "VENDOR_SPLIT_FORM"}
            assert site["vendor_views"]["amd"]["basis"] == {"isa_conditions": "SYSENTER.f5.amd"}
            table = json.loads((REPO / "tools/decode_check/isa_conditions_x64.json").read_bytes())
            assert table["entries"]["SYSENTER"]["f5"]["amd"] == "#UD in long mode"
            assert site["basis"]["decoders"] == {v: cf.digest([d.as_json() for d in ds]) for v, ds in ballot.items()}


def test_g2b_length_rejection_and_amd_split():
    from dataclasses import replace
    import compare

    votes = _g2b_votes("sysenter", 2)
    invalid = tuple(replace(d, status="invalid", flow="none", length=0) for d in votes["amd"])
    for amd, result in [(invalid, "site"), ((invalid[0], votes["amd"][1]), "unresolved")]:
        got = g.trap_outcome({"window": {"verified": 2}}, dict(votes, amd=amd), bytes.fromhex("0f34"))
        assert got[0] == result
    e = _entry(_row(5, []), "cc", _g2b_votes("int3", 1))
    w = dict(bytes=e[-1], verified=1, relocations=[], stop="test")
    result = compare.compare_row(e[1], e[2], w, e[3], s1=False, native_call=False, premise=True)
    assert not result["attributes"]
    assert [s["form"] for s in _case([(*e[:4], result, e[-1])])["sites"]] == ["int3"]


def test_g2b_missing_and_candidates():
    assert g.trap_outcome(None, None, None, True) == ("unresolved", "GLOBAL_REASON")
    assert g.trap_outcome(None, None, None) == ("unresolved", "NO_WINDOW")
    votes = _g2b_votes("call_near", 1)
    votes["amd"] = ()
    code = _case([_entry(_row(1, []), "90", votes)])
    assert _reasons(code) == {"TRANSFER_UNBOUND": [dict(row=0, op=None)]}
    assert _reasons(code, "trap_instruction", "x86_instruction") == {"BALLOT_MISSING": [dict(row=0, op=None)]}
    code = _case([_entry(_row(4, _cmov(4)), "660f44c1")])
    assert not _reasons(code) and not code["sites"]
    e = _slot(START, BASE + 0x4000)
    for ballot, reason in [(None, "BALLOT_MISSING"), (_g2b_votes("call_near", 6), "FORM_MISMATCH")]:
        code = _case([(*e[:3], ballot, *e[4:])])
        assert not code["sites"] and _reasons(code) == {reason: [dict(row=0, op=3)]}
    assert "VENDOR_VIEW_CONFLICT" in _reasons(_case([_g2_golden()]))


@pytest.mark.parametrize("name,kw,state,why", [
    ("VirtualProtect", {}, "complete", None),
    ("#named", {"lookup": 0}, "complete", None),
    ("x", {"first": (1 << 63) | 5}, "complete", "IMPORT_BY_ORDINAL"),
    ("x", {"lookup": 0, "stamp": 1}, "partial", "BOUND_IAT_NO_ILT"),
    ("VirtualProtect", {"lookup": 0, "second": (1 << 63) | 0x10005}, "partial", "ILT_ENTRY_INVALID"),
    ("VirtualProtect", {"delay": True}, "complete", None),
    ("x", {"delay": True, "lookup": 0}, "partial", "DELAY_FORMAT"),
    ("x", {"directory_size": 19}, "partial", "TRUNCATED"),
])
def test_g2b_pe(name, kw, state, why):
    import pe_map

    data = _g2b_pe(name, **kw)
    image = pe_map.parse(data)
    ff = g.file_facts(image, data)
    assert ff.import_state == state
    code = _case([_slot(START, BASE + 0x4000)], data)
    if why is None:
        assert ff.imports[0x4000]["name"] == name
        assert len(code["sites"]) == int(name == "VirtualProtect")
        ref = ff.imports[0x4000]["basis"]["pe_import"]
        assert ref["descriptor"]["file_record"][1] == (32 if kw.get("delay") else 20)
        assert ref["hint_name"]["file_record"][1] == 3 + len(name)
        with pytest.raises(g.Unread, match="LOADER_WRITTEN"):
            g.runtime_read(image, data, 0x4000, 8)
    elif why == "IMPORT_BY_ORDINAL":
        assert why in _reasons(code)
    else:
        assert why in [p["reason"] for p in ff.import_problems]
        assert not code["sites"] and 0x4000 not in ff.imports


@pytest.mark.parametrize("kind,sym,defined,linked,delta,why", [
    (7, 1, 0, False, 0, None), (6, 1, 0, False, 0, None),
    (7, 1, 0, True, 0, None), (6, 1, 0, True, 0, None),
    (7, 2, 0, False, 0, "SYM_COUNT_U"), (7, 1, 4, False, 0, "SLOT_NOT_IMPORT"),
    (8, 1, 0, False, 0, "ELF_RELOC_UNSUPPORTED"), (7, 1, 0, False, 8, "SLOT_NOT_IMPORT"),
])
def test_g2b_elf(kind, sym, defined, linked, delta, why):
    raw = _g2b_elf(kind, sym, defined, linked)
    code = _case([_slot(START, BASE + 0x5000 + delta)], raw)
    if why:
        assert not code["sites"] and _reasons(code) == {why: [dict(row=0, op=3)]}
    else:
        site, = code["sites"]
        assert site["symbol"]["basis"]["elf_reloc"]["slot_va"] == f"{BASE+0x5000:x}"
        assert (site["symbol"]["name"], site["route"]) == ("mprotect", "direct_slot")


def test_g2b_transfer_precedence_and_observations():
    e = _slot(START, BASE + 0x4000)
    for segment, width, space, expected in [(True, 4, 7, "SEGMENT_BASE"), (False, 4, 7, "POINTER_WIDTH"),
                                            (False, 8, 7, "SPACE_MISMATCH")]:
        f = copy.deepcopy(e[1])
        f["ops"][0]["inputs"][0] = _c(space)
        f["ops"][0]["output"]["size"] = width
        f["ops"][-1]["inputs"][0]["size"] = width
        data = b"\x64" + e[-1] if segment else e[-1]
        assert _reasons(_case([_entry(f, data, missing=True)])) == {expected: [dict(row=0, op=3)]}
    f = _row(1, [])
    assert _reasons(_case([("f0", f, None, None, None, b"")])) == {"TRANSFER_UNBOUND": [dict(row=0, op=None)]}
    target = _slot(START + 8, BASE + 0x4000, False)
    alt = _slot(START + 8, BASE + 0x4008, False)
    code = _case([_direct(START, START + 8), target, ("another", *alt[1:])])
    assert _reasons(code)["VENDOR_VIEW_CONFLICT"] == [dict(row=0, op=0)]


def test_g2b_thunks():
    caller = _direct(START + 32, START, True)
    marker = _entry(_plain([], START, 4), g.ENDBR64)
    jmp = _slot(START + 4, BASE + 0x5000, False)
    raw = _g2b_elf()
    code = _case([caller, marker, jmp], raw)
    assert g.summary(code)["import_routes"] == {"via_thunk": 1, "thunk_row": 1}
    s, = [s for s in code["sites"] if s["form"] == "jcc"]
    path = s["symbol"]["basis"]["path"]
    assert (path[0]["edge"]["when"], path[0]["edge"]["source"]) == ("taken", "encoded_target")
    assert [x["op"] for x in path] == [1, None, 1]
    code = _case([caller, _direct(START, START + 4), jmp], raw)
    assert len(_reasons(code)["MULTI_HOP"]) == 1
    for target, complete, why in [(START + 5, True, "TARGET_NOT_ROW_START"), (START + 64, False, "INDEX_INCOMPLETE")]:
        assert why in _reasons(_case([_direct(START + 32, target), jmp], raw, complete=complete))


@pytest.mark.parametrize("marker,bnd", [(b"", b""), (b"", b"\xf2"), (g.ENDBR64, b""), (g.ENDBR64, b"\xf2")])
def test_g2b_stub_exact_extent(monkeypatch, marker, bnd):
    calls = []

    def vote(raw, at):
        calls.append(at)
        return _g2b_votes("jmp_near", len(raw), True)

    monkeypatch.setattr(decoders, "ballot", vote)
    size = len(marker) + len(bnd) + 6
    stub = marker + bnd + b"\xff\x25" + struct.pack("<i", BASE + 0x4000 - START - size)
    data = _g2b_pe(text=stub)
    entries = [_direct(START + 32, START), _direct(START + 64, START)]
    code = _case(entries, data)
    assert len(calls) == 1 and g.summary(code)["import_routes"] == {"via_stub_bytes": 2}
    assert all(s["symbol"]["basis"]["path"][1]["file_runtime"][1] == size for s in code["sites"])
    assert not _case(entries, data, complete=False)["sites"]


def test_g2b_unreadable_endbr_and_unknown_targets():
    e = _direct(START + 32, START)
    code = _case([e, _entry(_plain([], START, 4), "90909090")], _g2b_pe(text=b"\x90"))
    assert not code["sites"] and _reasons(code)
    for addr, space, expected in [(START + 64, 2, "SPACE_MISMATCH"), (START + 1, 1, "INDEX_INCOMPLETE")]:
        src = dict(e[1], space=space)
        src["ops"][0]["inputs"][0] = dict(_a(addr), space=space)
        target = _entry(dict(_row(None, []), address=START), "")
        code = _case([target, _entry(src, e[-1], _g2b_votes("jmp_near", 5, target=addr))])
        assert expected in _reasons(code)


@pytest.mark.parametrize("ops,rwx", [
    ([_op("COPY", [_c(0x40, 4)], _r(0x88, 4)), _op("INT_ZEXT", [_r(0x88, 4)], _r(0x88))], True),
    ([_op("COPY", [_c(0x40, 1)], _r(RAX_, 1))], False),
    ([_op("COPY", [_c(0x40)], _r(RCX_)), _op("COPY", [_r(RAX_, 1)], _r(RCX_, 1))], False),
])
def test_g2b_rwx(ops, rwx):
    entries = [_entry(_plain(ops), "90"), _slot(START + 1, BASE + 0x4000)]
    code = _case(entries, _g2b_pe("VirtualAlloc"))
    if rwx:
        s, = code["sites"]
        v, = s["register_values"]
        assert s["rwx_registers"] == ["R9"] and s["arguments"] == []
        assert s["protection_argument"] == {"unobserved": "NO_ABI_BASIS"}
        assert v["value"] == {"width": 64, "constant": "40"} and v["path"] == [0, 1]
        assert v["definition"] == dict(row=0, op=1) and v["use"] == dict(row=1, op=3)
    else:
        assert not code["sites"] and _reasons(code)["NO_RWX_REGISTER"] == [dict(row=1, op=3, api="VirtualAlloc")]


def _store(addr, space=1):
    return _op("STORE", [_c(space), addr, _r(RCX_, 4)])


def test_g2b_stores_and_linear_path():
    for reg in (RAX_, RSP_):
        rows = [_entry(_plain([_op("COPY", [_c(START + 126)], _r(reg))]), "90")]
        rows += [_entry(_plain([], START + i), "90") for i in range(1, 66)]
        ops = [_store(_r(reg)), _store(_r(RCX_)), _store(_c(1), 9), _store(_c((1 << 64) - 1))]
        rows.append(_entry(_plain(ops, START + 66), "90"))
        code = _case(rows)
        s, = code["sites"]
        assert s["target_range"]["end"] == f"{START+130:x}" and s["regions"] == [0]
        assert s["static_basis"]["register_values"][0]["path"] == list(range(67))
        reasons = _reasons(code, "code_write", "static_store")
        assert reasons == {"STORE_ADDRESS_NOT_CONSTANT": [dict(row=66, op=1)], "ADDRESS_WRAP": [dict(row=66, op=3)]}

    f = _row(4, _cmov(4))
    f["ops"][-1] = _op("COPY", [_c(START)], _r(RAX_))
    use = _entry(_plain([_store(_r(RAX_))], START + 4), "90")
    for prev in (_entry(f, "660f44c1"), _entry(_plain([_op("COPY", [_c(START)], _r(RAX_))]), "90")):
        assert not _case([prev, use])["sites"]
    code = _case([_entry(_plain([_op("CBRANCH", [_a(START + 1), _r(RCX_, 1)]), _store(_c(START))]), "90")])
    assert _reasons(code, "code_write", "static_store") == {"INTRA_ROW_FLOW": [dict(row=0, op=1)]}


@pytest.mark.parametrize("opc", ["INT_XOR", "INT_SUB"])
def test_g2b_zero_and_entry_barriers(opc):
    prev = _entry(_plain([_op(opc, [_r(RCX_), _r(RCX_)], _r(RCX_))]), "90")
    call = _slot(START + 1, BASE + 0x4000)
    s, = _case([prev, call])["sites"]
    assert s["register_values"][0]["value"] == {"width": 64, "constant": "0"}
    for field in ("flow_target_coords", "recorded_landing_pads"):
        extra = _entry(_plain([], START + 64, **{field: [(1, START + 1)]}), "90", fid="f1")
        assert _case([prev, call, extra])["sites"][0]["register_values"] == []


def test_g2b_store_map_and_input_failures():
    from dataclasses import replace
    import check

    data = _g2b_pe()
    ops = [_store(_c(START + 9)), _store(_c(START + 30)), _store(_c(START + 200)),
           _op("STORE", [_r(RAX_), _c(START), _c(2)]), _op("STORE", [_c(1), _c(START), None])]
    c = _g2_collect([_entry(_plain(ops), "90")])
    rows = _g2_document(c)["rows"]
    image = check.parse_original(data)
    old = image.at(0x1009)
    image.ranges = [m for m in image.ranges if m != old] + [
        replace(old, end=0x100a), replace(old, start=0x100a, end=0x1028, kind="ambiguous"),
        replace(old, start=0x1028, file_offset=old.file_offset + 40)]
    image.ranges.sort(key=lambda m: m.start)
    code = g.build_code(rows, c.raw, c.code_rows, image, data, 1, BASE, True, ())
    s, = code["sites"]
    assert s["op"] == 0 and s["form"] == "store"
    assert _reasons(code, "code_write", "static_store") == {
        w: [dict(row=0, op=n)] for w, n in
        (("TARGET_MAPPING_U", 1), ("STORE_SPACE_U", 3), ("STORE_WIDTH_U", 4))}
    image.ok = False
    code = g.build_code(rows, c.raw, c.code_rows, image, data, 1, BASE, True, ())
    assert [x["op"] for x in _reasons(code, "code_write", "static_store")["TARGET_MAPPING_U"]] == [0, 1, 2]


def test_g2b_unwind():
    import pe_map

    for kw, why in [({}, "HANDLER_DATA_LENGTH"), ({"uflags": 3}, "UNWIND_VERSION"),
                    ({"uflags": 33, "count": 0}, "CHAIN_CYCLE"),
                    ({"pointer": 0x24ff}, "UNWIND_INDIRECT"), ({"pointer": 0x24fe}, "AMBIGUOUS_MAPPING")]:
        data = _g2b_pe(**kw)
        image = pe_map.parse(data)
        ff = g.file_facts(image, data)
        d, = ff.diagnostics
        assert d["reason"] == why and d["basis"] and any(r.name == ".pdata" for r in ff.unwind)
        if not kw:
            assert d["range"] == {"start": 0x240c, "end": None} and d["basis"]["file_runtime"][1] == 12
            image.written = pe_map.Parsed("complete", [(0x2400, 0x2404, "test")])
            assert g.file_facts(image, data).diagnostics[0]["reason"] == "LOADER_WRITTEN"
            image.written = None
            with pytest.raises(g.Unread, match="MAP_INDETERMINATE"):
                g.runtime_read(image, data, 0x2400, 4)


def test_g2b_boundaries_and_partial_unwind():
    from dataclasses import replace
    from types import SimpleNamespace
    import pe_map

    for last, reason in [("zero", "ZERO_FILL"), ("ambiguous", "AMBIGUOUS_MAPPING")]:
        ranges = [pe_map.Range(0, 1, "file", 0), pe_map.Range(1, 2, "file", 1), pe_map.Range(2, 3, last, 2)]
        image = SimpleNamespace(at=lambda a: next((m for m in ranges if m.start <= a < m.end), None))
        assert g.record_read(image, b"abc", 0, 2)[0] == b"ab"
        with pytest.raises(g.Unread, match=reason):
            g.record_read(image, b"abc", 0, 3)

    data = _g2b_pe()
    image = pe_map.parse(data)
    image.ranges = [replace(m, end=0x240a) if m.start <= 0x2408 < m.end else m for m in image.ranges]
    ff = g.file_facts(image, data)
    assert [(r.start, r.end) for r in ff.unwind if r.name == ".xdata"] == [(0x2400, 0x2408)]
    assert ff.diagnostics[0]["reason"] == "TRUNCATED"
    assert ff.diagnostics[0]["basis"]["file_runtime"][1] == 8


def test_g2b_elf_pointer():
    import elf_map

    data = bytearray(_g2b_elf())
    image = elf_map.parse(data)
    va = 0x3280
    off = g.record_read(image, data, va, 8)[1]["file_record"][0]
    n = len(image.phdrs)
    struct.pack_into("<H", data, 56, n + 1)
    struct.pack_into("<IIQQQQQQ", data, 64 + 56*n, g.PT_GNU_EH_FRAME, 4, off, va, 0, 8, 8, 4)
    for enc, why in [(0x1b, "NO_SECTION_HEADERS"), (0x9b, "EH_FRAME_PTR_ENCODING")]:
        data[off:off + 8] = bytes([1, enc, 0, 0]) + struct.pack("<i", 0x3100 - va - 4)
        code = _case([], bytes(data))
        d, = code["diagnostics"]
        assert d["reason"] == why
        if enc == 0x1b:
            r, = [r for r in code["regions"] if r["name"] == ".eh_frame"]
            assert r["range"]["start"] == f"{BASE+0x3100:x}" and r["range"]["end"] == {"unobserved": why}
            assert r["verified_bytes"] == 0 and d["scope_item"]["basis"]["file_runtime"][1] == 8
        else:
            assert d["what"] == "eh_frame"


def test_g2b_regions_reader_and_tamper(monkeypatch):
    es = [_entry(_plain([], START - 1, 3, view=v), "909090", fid=f) for v, f in [("0", "f0"), ("1", "f1")]]
    es.append(_entry(dict(_plain([], START, 3), space=2), "909090", fid="f2"))

    def bind(threshold, entries):
        monkeypatch.setattr(g, "VERIFIED_THRESHOLD", threshold)
        doc, ev, args = _case(entries, reader=True)
        result = evidence.bind_common_facts(ev, doc, **args).code
        return doc, ev, args, result

    _, _, _, x = bind(8_388_608, es)
    doc, ev, args, y = bind(1, es[::-1])
    code = doc["program"]["code"]
    assert code["verified_lengths"] == [3, 3, 3] and x == y
    assert y["verified_bytes"][0] == 2 and len(y["verified"][0]) == 2
    assert code["rows_outside_code"] == [0, 1, 2]
    for change in (
        lambda c: c.update(name_table_sha256="x"),
        lambda c: c["verified_lengths"].__setitem__(0, 2),
        lambda c: c["verified_rule"].update(per_row_window="x"),
        lambda c: c["survey"][0]["rows_examined"].update(facts_rows="x"),
        lambda c: c["survey"][0]["unsupported"].append({"reason": "G2C", "items": [dict(row=-1, op=0)]}),
    ):
        bad = copy.deepcopy(doc)
        change(bad["program"]["code"])
        ev["common_facts"]["facts_sha256"] = cf.digest(bad)
        with pytest.raises(evidence.Rejected):
            evidence.bind_common_facts(ev, bad, **args)
    monkeypatch.setattr(g, "VERIFIED_THRESHOLD", 8_388_608)
    assert [g.verified_encoding(n)["form"] for n in (8_388_608, 8_388_609)] == ["explicit", "compact"]


def test_g2b_reader_rejects_resigned_op_and_missing_report_row():
    doc, ev, args = _case([_slot(START, BASE + 0x4000)], reader=True)
    evidence.bind_common_facts(ev, doc, **args)
    bad = copy.deepcopy(doc)
    bad["program"]["code"]["sites"][0]["symbol"]["basis"]["path"][0]["op"] = 2
    ev["common_facts"]["facts_sha256"] = cf.digest(bad)
    with pytest.raises(evidence.Rejected):
        evidence.bind_common_facts(ev, bad, **args)
    ev["common_facts"]["facts_sha256"] = cf.digest(doc)
    row, = args["g2b"]["report"]["rows"]
    for records in ([], [row, row]):
        args["g2b"]["report"]["rows"] = records
        with pytest.raises(evidence.Rejected):
            evidence.bind_common_facts(ev, doc, **args)


def test_g2b_empty_arm_and_order():
    empty = _case([], missing=["f1"])
    assert all(c["rows_examined"]["empty"] and c["missing_functions"] == ["f1"] for c in empty["survey"])
    arm = _case([_entry(_row(4, []), "00000000")], isa="aarch64")
    assert _reasons(arm, "trap_instruction", "a64_instruction", "unsupported") == {"G2C": [dict(row=0, op=None)]}
    assert all(c["method"] != "run" for c in arm["survey"])
    pairs = [("NO_RWX_REGISTER", dict(row=0, op=2, api=s)) for s in ("B", "A", "B")]
    assert [i["api"] for i in g._groups(pairs)[0]["items"]] == ["A", "B"]
    assert g._groups(pairs) == g._groups(reversed(pairs))
```

## 5. `.census6/cost_probe/equiv_g2b.py`

Astra §6의 E7 검사를 위해 기존 `# report header`부터 `print("SUMMARY", ...)` **직전까지** 교체합니다. 기존 facts·evidence 검사, `FACTS_BYTES` 출력 및 종료 코드는 그대로 사용합니다.

```python
# Compare the complete report. Each side's explicitly requested evidence output
# path is checked before normalizing the two run directories.
rb = json.loads((BASE / f"{NAME}.json").read_bytes())
rn = json.loads((NEW / f"{NAME}.json").read_bytes())
summary = rn["header"]["common_facts"].pop("code", None)
check("new report has G2b summary", isinstance(summary, dict) and summary.get("rule") == "g2b-1")
for directory, report in ((BASE, rb), (NEW, rn)):
    supplied = report["header"].get("evidence_out")
    expected_path = directory / f"{NAME}.evidence5.json"
    check("report evidence output matches requested path",
          isinstance(supplied, str) and Path(supplied).resolve() == expected_path.resolve())
    report["header"]["evidence_out"] = expected_path.name
check("complete report header and rows otherwise identical", rb == rn)
```

### 리뷰 대응과 적용 확인

- **Astra §1 · Fable P1/P2/P3 transfer** — `row_proof`, `exact`, `transfer`, `direct`, `thunk`가 부분 ballot 후보, `(row,null)`, CMOV/REP/trap 내부 op, E3 우선순위, vendor별 길이·목적지, taken edge, 관찰 간 충돌, ENDBR 후속 행을 처리합니다. **chain은 Astra 우선**입니다. 추가 direct jump를 확인하는 즉시 `MULTI_HOP`을 기록합니다.
- **Astra §2 · Fable P1/P3 값·STORE** — `predecessor`, `_apply`, `register_values`, `stores`가 모든 flow op, 외부 진입, 길이·겹침·gap, partial kill, GPR 시작점과 폭, 실제 실행 순서, 알려진 RSP, STORE별 in-row op와 register basis를 처리합니다. **multi-space는 Astra 우선**입니다. `image_base.space_id`와 확정 selector로 비교합니다. 동적 이름의 **string fact와 LEA register fact는 둘 다 후속 작업**입니다.
- **Astra §3 · Fable P1/P3 파일 파싱** — `record_read`와 `runtime_read`가 여러 mapping 경계와 불명 map을 처리합니다. PE는 descriptor 경계, delay INT, OFT fallback 전체 검증, ordinal 필드, 부분 unwind와 handler basis를 기록합니다. ELF는 relocation 종류·크기, 동적 심볼 수 또는 연결된 section, undefined symbol, 실제 load mapping, 간접 EH encoding을 검사합니다.
- **Astra §4 · Fable P1/P3 trap** — 원본 voter 순서 digest, `F1`, prefix, 실제 G1 claimed-length 거부, relocated `ib`·non-trap opcode, `CE`, AMD F5 split을 검사합니다. all-invalid non-CE의 외부 reason은 `TRAP_FORM_UNDECIDED`이고 `ALL_INVALID_NOT_CE`는 별도 집계입니다.
- **Astra §5 · Fable P1 reader 및 P2/P3 survey** — `CodeBinder`, `verified_lists`, `read_g2b`, `summary`가 space·base, 두 verified 표현, union, window·range basis, `empty`, A64, syscall 미해결, `missing_functions`, API별 집계를 처리합니다. 다섯 import method는 그룹 계산을 공유합니다. **직렬화는 r3 우선**으로 각 method에 자체 `unresolved` 목록을 둡니다.
- **`via_stub_bytes` 설계 개정문** — “네 번째 route `via_stub_bytes`는 source의 확정 direct edge가 같은 image space·load base에서 완전한 행 인덱스의 시작점과 내부에 모두 속하지 않을 때 적용한다. 하나의 확정 executable region 안에서 `[ENDBR64] [BND] FF 25 disp32` 전체 6/7/10/11바이트를 `file_runtime`으로 읽고, 모든 필수 voter가 jump의 길이·near form·indirect 여부에 동의해야 한다. path에는 stub VA, space, load base, 전체 길이, jump offset, file basis와 vendor별 digest를 기록한다. 계산한 slot은 일반 import lookup을 거친다. 이 route는 `thunk_row`를 생성하지 않는다.”
- **적용 전제** — collector가 추가하는 필드는 `image_space`와 행별 `Proof`입니다. reader의 `g2b`에는 **admitted 입력**에서 얻은 `original`, `image_space`, `image_base`, `complete`, `missing_functions`, 같은 실행의 `report`를 전달해야 합니다. `observations`에는 collector와 같은 `isa` 및 raw op 좌표가 필요합니다. 기본 report가 ballot을 생략한 행과 file stub 재검증에는 생산 때와 같은 decoder 빌드가 필요합니다.
- **Astra §6 · Fable P1 golden/P2 비용 검증 상태** — 파일 편집 없이 메모리에서 collector·parser·reader의 synthetic 회귀 사례를 실행했습니다. 최종 정리본 전체의 pytest 실행, 실제 Linux voter golden, 다섯 Bundle E7·시간·peak RSS는 미검증입니다. WSL 실행이 `E_ACCESSDENIED`로 차단됐습니다. **+10% 예산은 열린 게이트**입니다. 기존 `fde5afb` 측정의 facts 증가는 zlib `+9.6%`, clang `+8.8%`, v3 `+9.9%`, ntdll `+1.1%`, UE `+2.7%`였습니다. 이번 코드의 수치는 다섯 Bundle을 같은 입력·옵션으로 재측정하고, UE는 base/new 각각 두 번 이상 측정해야 확정할 수 있습니다.