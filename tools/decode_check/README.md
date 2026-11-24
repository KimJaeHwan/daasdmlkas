# decode_check (G1)

Checks one sealed Bundle against its own `original` file, without Ghidra:

1. **Mapping (layer `mapping`)** — the original is mapped by pinned loader rules
   (PE32+: `pe-loader-rules-4`, ELF64: `elf-loader-rules-1`) and every sealed
   block byte is compared with the byte the loader would place there.
2. **Decode (layer `decode`)** — every Ghidra-listed instruction row is decoded
   again from *verified* bytes only (sealed byte == loader byte) by pinned
   independent decoders and the attributes are compared (design
   `.census6/design_g1_decode_check_r0..r4.md`).

Design records and reviews live in `.census6/` (local). Scope, premises, the lift
table, the decoder manifest and the mapping identity are written into every report
header.

## Running

POSIX / WSL only. The decoders are built once (pinned commits, sha256 manifest);
the engine venv is not touched:

    bash tools/decode_check/build_decoders.sh /root/g1_decoders
    PYTHONPATH=src python3 tools/decode_check/decode_check.py <generation> --out report.json \
        [--assume-stock-ghidra-translator] [--full]

- `--assume-stock-ghidra-translator` — named premise `stock-ghidra-translator`: the
  Bundle's p-code comes from the stock Ghidra 12.0.4 `x86:LE:64:default` translator.
  A Bundle carries no compiled-SLEIGH identity, so without the premise only A1
  (valid), an explicit A2 (length) and A4 (listing continuation) are compared and
  the table-dependent attributes are `unobserved` ("translation-unverified").
- `--full` — keep every attribute and vote of applied rows (large).

Reports made from real binaries stay local; never commit them.

## Voters

| mode | voters | rule |
|---|---|---|
| Intel | iced-x86 1.22.0, Zydis 4.1.1, Intel XED v2026.08.23 | all must agree |
| AMD | iced (AMD), Zydis (AMD_BRANCHES) | all must agree |

No majority vote. Precedence: `unobserved` > `withheld` (decoder / AMD / vendor
split) > `unrecognized` (internal inconsistency, analysis override, cause unknown,
Ghidra decode suspect) > `applied`.

## File mapping

Both mappings expose the same shape (`check.parse_original` picks one by magic):
`ok`, `why`, `format`, `rules`, `image_base`, `fixed_base`, `ranges` (offsets from
`image_base`: `file` / `zero` / `ambiguous`), `at(offset)`, `header_fields`,
`relocations`, `written` (each `absent` / `complete` / `indeterminate`) and the
canonical `mapping_id`.

- **PE32+** (`pe_map.py`) — AMD64 only; the Bundle must sit at the file's
  ImageBase (base relocations change code bytes elsewhere). DIR64 relocation
  ranges are listed per window; loader-written ranges: IAT, delay-load IAT and
  module handle, TLS index, load-config cookie and CFG pointer slots.
- **ELF64** (`elf_map.py`) — EM_X86_64, ET_EXEC or ET_DYN. ET_EXEC must sit at its
  linked base; ET_DYN may sit anywhere (Ghidra uses 0x100000), because every byte
  the loader changes is a relocation target and every relocation target is a
  loader-written range: DT_RELA / DT_REL / DT_JMPREL / DT_RELR (and Android RELR),
  SHF_ALLOC relocation sections, the whole PT_DYNAMIC, GOT[1..2]. Android packed
  relocations and static images without section headers are `indeterminate`.
  Pages two PT_LOADs share are ambiguous.

Written bytes are never used in a decode window and are counted, not compared, in
block rows. A block whose bytes are all written is `unobserved`.

Known, expected block differences: Ghidra rebases ELF `GOT[0]` (the link-time
`_DYNAMIC` address the runtime loader leaves unrelocated). That is a real
difference between Ghidra's image and the runtime image, reported as
`unrecognized`; it is data, not code.

## Rust port

`compare.py`, `lifting.py`, `pe_map.py`, `elf_map.py` and `check.Intervals` are
plain functions over plain data (bytes, dicts, tuples) with no engine objects; the
engine is reached only through G0's `engine_api` in `decode_check.collect`, which
reduces rows to plain facts first. The decoder adapters (`decoders.py`, C shims
with a fixed `dc_decoded` struct) map one-to-one to Rust FFI or to the Rust
`iced-x86` crate.

## Tests

`tests/intra/test_decode_check.py`: synthetic PE32+ (`_pe_fixture.py`) and ELF64
(`_elf_fixture.py`) Bundles. The decoder tests need POSIX and the built decoders
(`$G1_DECODERS`, default `/root/g1_decoders`); the ELF mapping unit tests need
neither.
