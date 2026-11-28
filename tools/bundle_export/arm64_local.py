"""Produce a sealed Bundle for a bounded, call-free ARM64 ELF function."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile
from xml.etree import ElementTree


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "decode_check"))

from arm64_elf_functions import FunctionRange, code_file_offset, function_ranges, select_range
from arm64_elf_unwind import select_unwind, unwind_ranges
import elf_map
from tdo_v2.integration.standalone_arm64 import (
    BRANCH_PROFILE, CMP_OPERATIONS, CONDITION_NAMES, LANGUAGE, LOCAL_OPERATIONS, MAX_CODE_BYTES,
    PAIR_PROFILE, PROFILE, RAM, instruction_form, language_id, local_successors,
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


def _row(ctx, address, data, limit, branches, pairs=False):
    word = int.from_bytes(data, "little")
    last = address + 4 == limit
    name = instruction_form(word, branches, pairs=pairs)
    if name is None or (name == "ret") != last:
        raise ValueError(f"unsupported ARM64 instruction or misplaced RET at {address:#x}")
    insns = ctx.disassemble(data, base_address=address, max_instructions=1).instructions
    names = {f"b.{CONDITION_NAMES[word & 15]}" if name == "b.cond" else name}
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
    next_address, target = local_successors(name, word, address, limit)
    conditional = name in ("cbz", "b.cond")
    if name == "ret":
        valid = opcodes == ("COPY", "RETURN")
    elif target is not None:
        valid = bool(ops) and opcodes[-1] == ("CBRANCH" if conditional else "BRANCH")
        if valid:
            destination = ops[-1].inputs[0]
            valid = (destination.space.name, destination.offset, destination.size) == ("ram", target, 8)
    else:
        valid = bool(ops) and set(opcodes) <= (CMP_OPERATIONS if name == "cmp" else LOCAL_OPERATIONS)
    if not valid:
        raise ValueError(f"pypcode did not produce the expected local ARM64 flow at {address:#x}")
    return {"address": coord(address), "length": 4, "data_references": [],
            "flow_targets": [coord(target)] if target is not None else [],
            "fallthrough_present": next_address is not None,
            "fallthrough": coord(next_address) if next_address is not None else None,
            "flow_type": {"is_flow": True, "has_fallthrough": next_address is not None, "is_terminal": last,
                          "is_call": False, "is_jump": target is not None, "is_computed": False,
                          "is_conditional": conditional, "is_unconditional": not conditional, "is_override": False},
            "operations": [operation(i, op) for i, op in enumerate(ops)]}


def _load_mapping(data, base, page):
    mapping = elf_map.parse(data, arm64_page=page)
    if not mapping.ok:
        raise ValueError(mapping.why)
    if base is None:
        base = mapping.image_base
    if type(base) is not int or not 0 <= base < elf_map.U64_END:
        raise ValueError("ELF loaded base must be a 64-bit address")
    bias = base - mapping.image_base
    if (mapping.fixed_base and bias) or bias % page or any(
            segment["state"] != "mapped" or segment["align"] > 1 and bias % segment["align"]
            or segment["vaddr"] + segment["memsz"] + bias > elf_map.U64_END
            for segment in mapping.segments):
        raise ValueError("ELF load bias or segment layout is incompatible with the selected model")
    return mapping, base


def _code_blocks(data, mapping, base, entry, size):
    link_entry = entry - (base - mapping.image_base)
    offset = code_file_offset(mapping, link_entry, size)
    code = data[offset:offset + size]
    blocks = [(entry, code)]
    if entry != base:
        # Scope validation needs a committed image-base coordinate. Keep only
        # its first byte and the function bytes in the loaded-memory snapshot.
        anchor = mapping.at(0)
        if anchor is None or anchor.kind != "file" or any(a == 0 < b for a, b, _ in mapping.written.ranges):
            raise ValueError("ELF image base requires a stable file-backed byte")
        blocks.insert(0, (base, data[anchor.file_offset:anchor.file_offset + 1]))
    return blocks, code


def _context(sla_directory, original, page, producer):
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
    profile = json_bytes(dict(schema=producer, lifter_version=pypcode.__version__, context=f"{LANGUAGE} default", page_size=page,
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


def _write_bundle(root, original, profile, program, blocks, observation, *, before_publish=None):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    generation = digest(json_bytes([digest(data) for data in (profile, program, observation)]))
    destination = root / generation
    if destination.exists():
        raise FileExistsError(destination)
    temporary = Path(tempfile.mkdtemp(prefix=".arm64-local-", dir=root))
    staging = temporary / generation
    staging.mkdir(mode=0o700)
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
        no_call = json_bytes(dict(schema=json.loads(profile)["schema"], state="unsupported", reason="local graph scope"))
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
        if before_publish is not None:
            before_publish(staging)
        staging.rename(destination)
    finally:
        shutil.rmtree(temporary)
    return destination


def _check_graph(generation):
    from tdo_v2.integration.standalone_arm64 import build_standalone_arm64_graphs

    snapshot, _ = build_standalone_arm64_graphs(generation)
    if len(snapshot.graphs) != 1:
        raise ValueError(f"standalone ARM64 graph was not published ({snapshot.stop})")


def _range_record(selected, mapping, base):
    bias = base - mapping.image_base
    entry = selected.link_entry + bias
    details = {"names": selected.names} if isinstance(selected, FunctionRange) else {
        "basis": "eh_frame_fde", "id": selected.id,
    }
    return {**asdict(selected), **details, "load_bias": bias,
            "entry": entry if 0 <= entry < elf_map.U64_END else None,
            "original_sha256": mapping.header_fields["file_sha256"]}


def _export(original, output_root, *, entry=None, size=None, function=None, unwind_fde=None, base=None, page=4096,
            sla_directory=None, branches=False, pairs=False, before_publish=None,
            llvm_objdump=None, gnu_objdump=None, encoding_archive=None):
    if (entry is None) != (size is None) or sum(value is not None for value in (entry, function, unwind_fde)) > 1:
        raise ValueError("use --entry with --size, or select one ELF symbol or unwind record")
    source_inputs = (llvm_objdump, gnu_objdump, encoding_archive)
    check_source = any(value is not None for value in source_inputs)
    if check_source:
        if any(value is None for value in source_inputs):
            raise ValueError("ARM64 source adjudication requires --llvm-objdump, --gnu-objdump and --encoding-archive")
        original = bytes(original)
    mapping, base = _load_mapping(original, base, page)
    selection = None
    if entry is None:
        if unwind_fde is None:
            selected = select_range(function_ranges(original, mapping, MAX_CODE_BYTES),
                                    name=function, elf_entry=struct.unpack_from("<Q", original, 24)[0])
        else:
            selected = select_unwind(unwind_ranges(original, mapping, MAX_CODE_BYTES), unwind_fde)
        selection = _range_record(selected, mapping, base)
        entry, size = selection["entry"], selected.size
        if before_publish is None:
            before_publish = _check_graph
    if (type(entry) is not int or type(size) is not int or entry < 0 or entry % 4
            or not 4 <= size <= MAX_CODE_BYTES or size % 4 or entry + size > elf_map.U64_END):
        raise ValueError("provide one aligned ARM64 function range of 4 to 65536 bytes")
    blocks, code = _code_blocks(original, mapping, base, entry, size)
    if check_source:
        from arm64_source_evidence import check_source_export

        check_source_export(original, code, entry=entry, base=base, page=page, llvm_objdump=llvm_objdump,
                            gnu_objdump=gnu_objdump, encoding_archive=encoding_archive)
    if pairs and before_publish is None:
        before_publish = _check_graph
    branches = branches or pairs
    producer = PAIR_PROFILE if pairs else BRANCH_PROFILE if branches else PROFILE
    ctx, profile = _context(sla_directory, original, page, producer)
    rows = []
    reachable = {entry}
    for i in range(0, size, 4):
        address = entry + i
        if address not in reachable:
            raise ValueError(f"unreachable instruction in standalone ARM64 range at {address:#x}")
        row = _row(ctx, address, code[i:i + 4], entry + size, branches, pairs)
        if row["fallthrough"] is not None:
            reachable.add(row["fallthrough"]["byte_offset"])
        reachable.update(c["byte_offset"] for c in row["flow_targets"])
        rows.append(row)
    observation = json_bytes(dict(entry=coord(entry), instructions=rows))
    generation = _write_bundle(output_root, original, profile, _program(base, ctx, profile), blocks, observation,
                               before_publish=before_publish)
    return generation, selection


def export(elf, output_root, *, entry=None, size=None, function=None, unwind_fde=None, base=None, page=4096,
           sla_directory=None, branches=False, pairs=False, llvm_objdump=None, gnu_objdump=None,
           encoding_archive=None):
    """Export one explicit range, ELF symbol or unwind record."""
    generation, _ = _export(Path(elf).read_bytes(), output_root, entry=entry, size=size, function=function,
                            unwind_fde=unwind_fde, base=base, page=page, sla_directory=sla_directory,
                            branches=branches, pairs=pairs, llvm_objdump=llvm_objdump,
                            gnu_objdump=gnu_objdump, encoding_archive=encoding_archive)
    return generation


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("output_root", type=Path, nargs="?")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--function", help="exact defined ELF function symbol name")
    selection.add_argument("--list-functions", action="store_true", help="list ELF symbol ranges as JSON")
    selection.add_argument("--list-unwind-ranges", action="store_true", help="list ELF unwind-covered ranges as JSON")
    selection.add_argument("--unwind-fde", help="exact unwind record ID from --list-unwind-ranges")
    selection.add_argument("--entry", type=lambda v: int(v, 0))
    parser.add_argument("--size", type=lambda v: int(v, 0))
    parser.add_argument("--base", type=lambda v: int(v, 0))
    parser.add_argument("--page-size", type=int, choices=elf_map.ARM64_PAGES, default=4096)
    parser.add_argument("--sla-directory", type=Path)
    parser.add_argument("--branches", action="store_true", help="allow the bounded direct-branch profile")
    parser.add_argument("--pairs", action="store_true", help="also allow integer STP and LDP in the branch profile")
    parser.add_argument("--llvm-objdump", type=Path, help="LLVM disassembler for the v3 source check")
    parser.add_argument("--gnu-objdump", type=Path, help="AArch64 GNU disassembler for the v3 source check")
    parser.add_argument("--encoding-archive", type=Path, help="pinned Arm archive for the v3 source check")
    parser.add_argument("--g2-out", type=Path, help="write local G2 memory comparisons linked to TDO graph operations")
    args = parser.parse_args(argv)
    listing = args.list_functions or args.list_unwind_ranges
    if listing:
        if args.output_root is not None or args.size is not None or args.g2_out is not None:
            parser.error("range listing takes no output root, --size or --g2-out")
        if any(value is not None for value in (args.llvm_objdump, args.gnu_objdump, args.encoding_archive)):
            parser.error("source adjudication applies to Bundle export")
    elif args.output_root is None:
        parser.error("output_root is required to export a Bundle")
    try:
        original = args.elf.read_bytes()
        if listing:
            mapping, base = _load_mapping(original, args.base, args.page_size)
            inventory = dict(original_sha256=mapping.header_fields["file_sha256"],
                             elf_entry=struct.unpack_from("<Q", original, 24)[0])
            if args.list_unwind_ranges:
                inventory["unwind_ranges"] = [_range_record(item, mapping, base)
                                              for item in unwind_ranges(original, mapping, MAX_CODE_BYTES)]
            else:
                functions = function_ranges(original, mapping, MAX_CODE_BYTES)
                inventory["functions"] = [_range_record(item, mapping, base) for item in functions]
                if not functions:
                    inventory["unavailable"] = "no defined function symbols in supported ELF section tables"
            print(json.dumps(inventory, sort_keys=True))
            return 0

        report = None
        def build_report(generation):
            from arm64_local_facts import describe

            nonlocal report
            report = describe(generation)

        generation, selected = _export(
            original, args.output_root, entry=args.entry, size=args.size, function=args.function,
            unwind_fde=args.unwind_fde, base=args.base, page=args.page_size,
            sla_directory=args.sla_directory, branches=args.branches, pairs=args.pairs, before_publish=build_report if args.g2_out is not None else None,
            llvm_objdump=args.llvm_objdump, gnu_objdump=args.gnu_objdump, encoding_archive=args.encoding_archive,
        )
        if report is not None:
            if selected is not None:
                key = "unwind_range" if args.unwind_fde is not None else "function_range"
                report[key] = selected
            args.g2_out.write_text(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        print(generation)
    except (ValueError, OSError, RuntimeError) as error:
        print(f"arm64_local: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
