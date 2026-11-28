"""Produce a sealed Bundle for a bounded, straight-line ARM64 ELF function."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import shutil
import sys
import tempfile
from xml.etree import ElementTree


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "decode_check"))

import elf_map
from tdo_v2.integration.standalone_arm64 import (
    LANGUAGE, LOCAL_OPERATIONS, MAX_CODE_BYTES, PROFILE, RAM, instruction_form, language_id,
)


SPACES = {"const": (0, 1), "ram": (1, 4), "register": (2, 2), "unique": (3, 3)}


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(data):
    return sha256(data).hexdigest()


def coord(offset):
    return {"space_id": RAM, "byte_offset": offset}


def varnode(item):
    try:
        space, kind = SPACES[item.space.name]
    except KeyError as error:
        raise ValueError(f"unsupported p-code space {item.space.name}") from error
    return {"kind_code": kind, "space_id": space, "byte_offset": item.offset, "byte_size": item.size}


def operation(ordinal, op):
    name = op.opcode.name
    inputs = []
    for index, item in enumerate(op.inputs):
        value = varnode(item)
        if index == 0 and name in ("LOAD", "STORE"):
            if item.space.name != "const" or item.getSpaceFromConst().name != "ram":
                raise ValueError("p-code memory selector is outside ARM64 RAM")
            value["byte_offset"] = RAM
        inputs.append(value)
    return {"ordinal": ordinal, "opcode": name, "inputs": inputs, "output_present": op.output is not None,
            "output": varnode(op.output) if op.output is not None else None}


def _row(ctx, address, data, last):
    word = int.from_bytes(data, "little")
    name = instruction_form(word)
    if name is None or (name == "ret") != last:
        raise ValueError(f"unsupported ARM64 instruction or misplaced RET at {address:#x}")
    insns = ctx.disassemble(data, base_address=address, max_instructions=1).instructions
    names = {name}
    if name == "add" and (word >> 10) & 0x1FFF == 0 and (word & 31 == 31 or (word >> 5) & 31 == 31):
        names.add("mov")
    if len(insns) != 1 or insns[0].addr.offset != address or insns[0].length != 4 or insns[0].mnem.lower() not in names:
        raise ValueError(f"pypcode disassembly contradicts the selected instruction at {address:#x}")
    mark, *ops = ctx.translate(data, base_address=address, max_instructions=1).ops
    if mark.opcode.name != "IMARK" or len(mark.inputs) != 1:
        raise ValueError(f"missing exact IMARK at {address:#x}")
    marker, = mark.inputs
    if (marker.space.name, marker.offset, marker.size) != ("ram", address, 4):
        raise ValueError(f"pypcode instruction extent disagrees at {address:#x}")
    opcodes = tuple(op.opcode.name for op in ops)
    if not (opcodes == ("COPY", "RETURN") if last else bool(ops) and set(opcodes) <= LOCAL_OPERATIONS):
        raise ValueError(f"pypcode did not produce an ordinary local instruction at {address:#x}")
    return {"address": coord(address), "length": 4, "data_references": [], "flow_targets": [],
            "fallthrough_present": not last, "fallthrough": None if last else coord(address + 4),
            "flow_type": {"is_flow": True, "has_fallthrough": not last, "is_terminal": last,
                          "is_call": False, "is_jump": False, "is_computed": False, "is_conditional": False,
                          "is_unconditional": True, "is_override": False},
            "operations": [operation(i, op) for i, op in enumerate(ops)]}


def _load_code(data, entry, size, base, page):
    mapping = elf_map.parse(data, arm64_page=page)
    if not mapping.ok:
        raise ValueError(mapping.why)
    if base is None:
        base = mapping.image_base
    bias = base - mapping.image_base
    if base < 0 or (mapping.fixed_base and bias) or bias % page or any(
            segment["state"] != "mapped" or segment["align"] > 1 and bias % segment["align"]
            for segment in mapping.segments):
        raise ValueError("ELF load bias or segment layout is incompatible with the selected model")
    start = entry - base
    end = start + size
    span = mapping.at(start)
    containing = [s for s in mapping.segments if s["flags"] & 1
                  and s["vaddr"] <= entry - bias and entry - bias + size <= s["vaddr"] + s["filesz"]]
    if span is None or span.kind != "file" or end > span.end or len(containing) != 1:
        raise ValueError("function bytes require one file-backed executable PT_LOAD span")
    if mapping.written.state != "complete" or any(a < end and start < b for a, b, _ in mapping.written.ranges):
        raise ValueError("function span may be modified by a modeled ELF loader write")
    offset = span.file_offset + start - span.start
    code = data[offset:offset + size]
    blocks = [(entry, code)]
    if entry != base:
        # Scope validation needs a committed image-base coordinate. Keep only
        # its first byte and the function bytes in the loaded-memory snapshot.
        anchor = mapping.at(0)
        if anchor is None or anchor.kind != "file" or any(a == 0 < b for a, b, _ in mapping.written.ranges):
            raise ValueError("ELF image base requires a stable file-backed byte")
        blocks.insert(0, (base, data[anchor.file_offset:anchor.file_offset + 1]))
    return base, blocks, code


def _context(sla_directory, original, page):
    try:
        import pypcode
        import pypcode.pypcode_native as native
    except ImportError as error:
        raise ValueError("standalone ARM64 export requires pypcode in the selected Python environment") from error
    if sla_directory is None:
        lang = pypcode.ArchLanguage.from_id(LANGUAGE)
        sla_directory = Path(lang.archdir)
    ldefs = (Path(sla_directory) / "AARCH64.ldefs").read_bytes()
    selected = next((item for item in ElementTree.fromstring(ldefs) if item.get("id") == LANGUAGE), None)
    if selected is None:
        raise ValueError("SLEIGH definitions do not contain the AArch64 little-endian v8A language")
    lang = pypcode.ArchLanguage(str(sla_directory), selected)
    spec = Path(lang.slafile_path)
    pspec = Path(lang.pspec_path)
    backend = Path(native.__file__)
    paths = {"sla_sha256": spec, "pspec_sha256": pspec, "lifter_sha256": backend}
    hashes = {k: digest(p.read_bytes()) for k, p in paths.items()}
    profile = json_bytes(dict(schema=PROFILE, lifter_version=pypcode.__version__, context=f"{LANGUAGE} default", page_size=page,
                              original_sha256=digest(original), language_sha256=digest(ldefs), **hashes))
    ctx = pypcode.Context(lang)
    if hashes != {k: digest(p.read_bytes()) for k, p in paths.items()}:
        raise ValueError("SLEIGH specification or lifter changed during initialization")
    return ctx, profile


def _program(base, ctx, profile):
    roles = {"const": "constant", "ram": "memory", "register": "register", "unique": "unique"}
    spaces = []
    for name, (index, _) in SPACES.items():
        flags = {f"is_{role}_space": role == roles[name] for role in roles.values()}
        address_bits = 32 if name in ("register", "unique") else 64
        spaces.append(dict(space_id=index, address_size_bits=address_bits, addressable_unit_bytes=1, **flags,
                           is_overlay_space=False, is_external_space=False, is_loaded_memory_space=name == "ram",
                           is_non_loaded_memory_space=False, has_signed_offset=False))
    registers = [{"name": name, "space_id": SPACES["register"][0], "byte_offset": v.offset, "byte_size": v.size}
                 for name, v in ctx.registers.items() if v.space.name == "register"]
    registers.sort(key=lambda r: (r["space_id"], r["byte_offset"], r["byte_size"], r["name"]))
    return json_bytes(dict(address_space_classification_revision=2, address_spaces=spaces,
                           translation_namespace=dict(language_id=language_id(profile), major_version=1,
                                                      minor_version=0), image_base=coord(base),
                           register_evidence=dict(revision=1, registers=registers)))


def _write_bundle(root, original, profile, program, blocks, observation):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    generation = digest(json_bytes([digest(data) for data in (profile, program, observation)]))
    destination = root / generation
    if destination.exists():
        raise FileExistsError(destination)
    staging = Path(tempfile.mkdtemp(prefix=".arm64-local-", dir=root))
    members, block_rows = [], []

    def write(name, data):
        path = staging / name
        path.write_bytes(data)
        path.chmod(0o644)

    def member(key, name, data):
        write(name, data)
        members.append(dict(id=key, path=name, size=len(data), sha256=digest(data)))
        return key

    try:
        original_id = member("original", "original.bin", original)
        program_id = member("program", "program.json", program)
        profile_id = member("call-interface-profile", "call-interface-profile.json", profile)
        for i, (start, data) in enumerate(blocks):
            key = f"memory-{i:06d}"
            block_rows.append(dict(id=f"block-{i:06d}", space_id=RAM, byte_start=start, byte_size=len(data),
                                   is_loaded=True, is_initialized=True, is_overlay=False, is_external=False,
                                   is_mapped=False, member_id=member(key, key + ".bin", data)))
        function_id = member("function-000000", "function-000000.json", observation)
        no_call = json_bytes(dict(schema=PROFILE, state="unsupported", reason="local graph scope"))
        naming = member("call-names-000000", "call-names-000000.json", no_call)
        effects = member("call-effects-000000", "call-effects-000000.json", no_call)
        manifest = json_bytes(dict(schema_version=2, generation_id=generation, original_member_id=original_id,
                                   program_member_id=program_id, call_interface_profile_member=profile_id,
                                   blocks=block_rows, members=members,
                                   functions=[dict(id=function_id, observation_member=function_id,
                                                   call_names_member=naming, call_effects_member=effects)]))
        write("manifest.json", manifest)
        write("seal.json", json_bytes(dict(schema_version=2, generation_id=generation,
                                           manifest_sha256=digest(manifest), manifest_size=len(manifest))))
        staging.rename(destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return destination


def export(elf, output_root, *, entry, size, base=None, page=4096, sla_directory=None):
    if (type(entry) is not int or type(size) is not int or entry < 0 or entry % 4
            or not 4 <= size <= MAX_CODE_BYTES or size % 4 or entry + size > elf_map.U64_END):
        raise ValueError("provide one aligned ARM64 function range of 4 to 65536 bytes")
    original = Path(elf).read_bytes()
    base, blocks, code = _load_code(original, entry, size, base, page)
    ctx, profile = _context(sla_directory, original, page)
    rows = [_row(ctx, entry + i, code[i:i + 4], last=i + 4 == size) for i in range(0, size, 4)]
    observation = json_bytes(dict(entry=coord(entry), instructions=rows))
    return _write_bundle(output_root, original, profile, _program(base, ctx, profile), blocks, observation)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("output_root", type=Path)
    parser.add_argument("--entry", type=lambda v: int(v, 0), required=True)
    parser.add_argument("--size", type=lambda v: int(v, 0), required=True)
    parser.add_argument("--base", type=lambda v: int(v, 0))
    parser.add_argument("--page-size", type=int, choices=elf_map.ARM64_PAGES, default=4096)
    parser.add_argument("--sla-directory", type=Path)
    parser.add_argument("--g2-out", type=Path, help="write local G2 memory comparisons linked to TDO graph operations")
    args = parser.parse_args(argv)
    try:
        generation = export(args.elf, args.output_root, entry=args.entry, size=args.size, base=args.base,
                            page=args.page_size, sla_directory=args.sla_directory)
        if args.g2_out is not None:
            from arm64_local_facts import describe
            args.g2_out.write_bytes(json_bytes(describe(generation)) + b"\n")
        print(generation)
    except (ValueError, OSError, RuntimeError) as error:
        print(f"arm64_local: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
