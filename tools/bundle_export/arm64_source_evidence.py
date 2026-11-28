#!/usr/bin/env python3
"""Collect and replay independent ARM64 source-byte decoding evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile

from arm64_local import _load_mapping, digest, json_bytes
from arm64_elf_functions import _sections, _symbol_inputs
from arm64_elf_unwind import _code_range
from arm64_encoding_index import load_index
from arm64_source_decode import ALL_INSTRUCTIONS_PROFILE_V3, SOURCE_DECODE_PROFILES, SOURCE_DECODE_RULES, observe
from tdo_v2.integration.standalone_arm64 import MAX_CODE_BYTES


DECODE_SCHEMA = "tbr-a64-source-decode-1"
PROFILED_DECODE_SCHEMA = "tbr-a64-source-decode-2"


def _source_range(original, entry, size, base, page):
    mapping, base = _load_mapping(original, base, page)
    if (type(entry) is not int or type(size) is not int or entry < 0 or entry % 4
            or not 4 <= size <= MAX_CODE_BYTES or size % 4 or entry + size >= 1 << 64):
        raise ValueError("instruction evidence requires one aligned 4–65536 byte range")
    bias = base - mapping.image_base
    sections = _sections(original, mapping)
    _, data_intervals = _symbol_inputs(original, mapping, sections)
    file_offset = _code_range(original, mapping, sections, data_intervals, entry - bias, size)
    source = dict(kind="explicit-executable-range", entry=entry, size=size, link_entry=entry-bias,
                  loaded_base=base, load_bias=bias, page_size=page, file_offset=file_offset)
    return source, original[file_offset:file_offset + size]


def _decode_record(original, *, entry, size, llvm_objdump, gnu_objdump, encoding_archive, base=None, page=4096,
                   decode_profile=None):
    source, code = _source_range(original, entry, size, base, page)
    reference, identity = load_index(encoding_archive)
    words = [(entry + offset, int.from_bytes(code[offset:offset+4], "little")) for offset in range(0, size, 4)]
    decoders, rows = observe(words, reference, llvm_objdump, gnu_objdump, profile=decode_profile,
                            encoding_archive=encoding_archive)
    for offset, row in enumerate(rows):
        row["file_offset"] = source["file_offset"] + offset * 4
    record = dict(schema=DECODE_SCHEMA, source=source, original_sha256=digest(original), code_sha256=digest(code),
                  encoding_index=identity, decoders=decoders, slots=rows)
    if decode_profile is not None:
        record.update(schema=PROFILED_DECODE_SCHEMA, decode_profile=decode_profile,
                      common_facts_rule=SOURCE_DECODE_RULES[decode_profile],
                      runtime=dict(cpu_features="unobserved", streaming_mode="unobserved", za_state="unobserved",
                                   vector_length="unobserved"))
    return record


def collect_decode(original, *, entry, size, llvm_objdump, gnu_objdump, encoding_archive, base=None, page=4096,
                   decode_profile=None):
    """Compare the two independent decoders without building a lift or Bundle."""
    record = _decode_record(original, entry=entry, size=size, llvm_objdump=llvm_objdump, gnu_objdump=gnu_objdump,
                            encoding_archive=encoding_archive, base=base, page=page, decode_profile=decode_profile)
    return json_bytes(dict(digest=digest(json_bytes(record)), evidence=record)) + b"\n"


def check_source_export(original, code, *, entry, base, page, llvm_objdump, gnu_objdump, encoding_archive):
    """Reject a selected Bundle range with a v3 Arm verdict before lifting."""
    record = _decode_record(original, entry=entry, size=len(code), base=base, page=page,
                            llvm_objdump=llvm_objdump, gnu_objdump=gnu_objdump, encoding_archive=encoding_archive,
                            decode_profile=ALL_INSTRUCTIONS_PROFILE_V3)
    if record["code_sha256"] != digest(code):
        raise ValueError("ARM64 source adjudication and Bundle caller bytes differ")
    for slot in record["slots"]:
        verdict = slot.get("arm_check", {}).get("verdict")
        if verdict in ("UNDEFINED", "CONSTRAINED_UNPREDICTABLE"):
            raise ValueError(f"ARM64 source profile {ALL_INSTRUCTIONS_PROFILE_V3} refused Bundle at "
                             f"{slot['address']:#x}: {verdict} ({slot['bytes_le']} little-endian)")


def verify_decode(original, encoded, *, llvm_objdump, gnu_objdump, encoding_archive):
    try:
        record = json.loads(encoded)["evidence"]
        source = record["source"]
        schema = record["schema"]
        if schema not in (DECODE_SCHEMA, PROFILED_DECODE_SCHEMA) or digest(original) != record["original_sha256"]:
            raise ValueError("source decode schema or original file digest differs")
        profile = record["decode_profile"] if schema == PROFILED_DECODE_SCHEMA else None
        if schema == PROFILED_DECODE_SCHEMA and not isinstance(profile, str):
            raise ValueError("profiled source decode evidence requires a named profile")
        expected = collect_decode(original, entry=source["entry"], size=source["size"], base=source["loaded_base"],
                                  page=source["page_size"], llvm_objdump=llvm_objdump, gnu_objdump=gnu_objdump,
                                  encoding_archive=encoding_archive, decode_profile=profile)
    except (KeyError, TypeError) as error:
        raise ValueError("invalid source decode metadata") from error
    if encoded != expected:
        raise ValueError("source decode evidence differs from replay")
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--entry", type=lambda raw: int(raw, 0))
    parser.add_argument("--size", type=lambda raw: int(raw, 0))
    parser.add_argument("--base", type=lambda raw: int(raw, 0))
    parser.add_argument("--page-size", type=int, choices=(4096, 16384, 65536))
    parser.add_argument("--encoding-archive", type=Path, required=True)
    parser.add_argument("--llvm-objdump", type=Path, required=True)
    parser.add_argument("--gnu-objdump", type=Path, required=True)
    parser.add_argument("--decode-profile", choices=SOURCE_DECODE_PROFILES)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args(argv)
    if args.verify:
        if any(value is not None for value in (args.entry, args.size, args.base, args.page_size, args.decode_profile)):
            parser.error("--verify replays the recorded range and profile; omit collection options")
    elif args.entry is None or args.size is None:
        parser.error("--entry and --size are required to collect source decode evidence")

    options = dict(llvm_objdump=args.llvm_objdump, gnu_objdump=args.gnu_objdump, encoding_archive=args.encoding_archive)
    try:
        original = args.elf.read_bytes()
        if args.verify:
            verify_decode(original, args.artifact.read_bytes(), **options)
        else:
            if args.artifact.resolve() in {item.resolve() for item in (args.elf, *options.values())}:
                raise ValueError("source decode output would overwrite an input file")
            encoded = collect_decode(original, entry=args.entry, size=args.size, base=args.base,
                                     page=args.page_size or 4096, decode_profile=args.decode_profile, **options)
            with tempfile.NamedTemporaryFile(mode="wb", dir=args.artifact.parent, delete=False) as staged:
                path = Path(staged.name)
                try:
                    staged.write(encoded)
                    staged.close()
                    path.replace(args.artifact)
                finally:
                    path.unlink(missing_ok=True)
    except (OSError, ValueError) as error:
        parser.exit(1, f"{parser.prog}: {error}\n")
    print(args.artifact)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
