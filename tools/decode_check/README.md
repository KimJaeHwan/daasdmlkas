# decode_check (G1)

Checks one sealed Bundle against its own `original` file, without Ghidra:

1. **Mapping (layer `mapping`)** — the original is mapped by pinned loader rules
   (PE32+: `pe-loader-rules-5`, ELF64: `elf-loader-rules-4`) and every sealed
   block byte is compared with the byte the loader would place there.
2. **Decode (layer `decode`)** — every Ghidra-listed instruction row is decoded
   again from *verified* bytes only (sealed byte == loader byte) by pinned
   independent decoders and the attributes are compared (design
   `.census6/design_g1_decode_check_r0..r4.md`).

3. **Dependents (layer `dependents`)** — which engine facts read which compared
   attribute (`dependents.CONSUMERS`), from G0's operation rows of the same
   function: S1, push projection / relation, plain push, call seed, return shape,
   unknown-transfer site (baseline), and the future-L2 S1 and G3b-7b `none`
   estimates. Per unit: `confirmed`, or `would_block` (a read attribute is a
   disagreement or unobserved) with `loss` 1 when the engine fact exists, 0 when it
   is already absent, `unknown` for an estimate without a baseline. RP and
   pass-through stay undetermined (no unwind-PC evidence in a Bundle). The header
   summary counts every unit; rows are written for would-block units only unless
   `--full`.

4. **S1 guard (rows `decode/s1_guard`, per function)** — the exporter's
   `cpuDependentLength` guard (G3b-7b r9g, main 18a5f5e) recomputed from verified
   bytes: a control-transfer row whose prefix run holds `66` or a repeated prefix
   would withhold S1. `recomputed` is true / false / unobserved (a row without a
   CALL op whose scan fires depends on the prototype flow, which a Bundle does not
   carry); `fired_at_production` is always `unobserved`; the observed S1 presence
   sits beside it and is never used to infer firing.

Mode constants: A11a and `F.is_flow` are fixed by the 64-bit mode on the voter side; their applied
attributes carry `provenance: mode-constant`. They still count in a row's aggregate and in
`header.counts`; no dependents read uses them.

Layers: G1 counts (`header.counts`) cover `mapping` and `decode` only;
`dependents` is derived; `semantics` is reserved for TBR (A3 / C1 semantic
checks, its own revision) and is never counted as G1 `applied`.

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

Golden vectors (`tests/intra/golden/decode_check_*.json`, synthetic Bundles only): the full
report of the reference pair, the `66 E8` pair (withheld row, guard true, blocked S1) and an
ELF PIE with a text relocation, minus the host's decoder build manifest. They are the
parity reference for a Rust port. `G1_REGEN_GOLDEN=1` rewrites them after a reviewed change.

## Engine evidence file

`decode_check.py ... --evidence-out <path>` also writes `g1-decode-evidence-1`, the file the TDO engine reads to
replace its premise "Ghidra decode = CPU" row by row (design `.census6/design_g1_engine_evidence_r3.md`, closed:
Astra final specification `g1_evidence_astra4.md`, Fable APPROVE `g1_evidence_fable4.md`). It lives outside the
Bundle (admission refuses unlisted entries) and is passed by explicit path.

- Header: Bundle binding (generation id, the seal's `manifest_sha256`, the original's sha256), the producer
  tuple an engine allowlists, premises (`decoder-matches-cpu` always; `stock-ghidra-translator` when the table
  applied), compared / mode-constant attribute sets, `consumers-2` (500 canonical bytes, SHA-256 pinned in
  `evidence.CONSUMERS_DIGEST`), `global_reason`.
- Body: per function `observation_sha256`, `rows_total`, `rows_digest` (every processed row) and only the
  exception rows (`state:kind` per non-confirmed attribute; `*` for a never-compared row).
- `evidence.py` also holds a reference reader (`parse`, `accept`, `Evidence.read`, `decide`, `coverage`):
  the six-step read, level A / B decisions and premise attachment exactly as the design states. The engine's
  reader is TDO work; this one is its executable specification.

## Open items

- **PE load-config code rewriting (owner, 2026-11-25).** Today a non-zero DynamicValueRelocTable /
  DVRT offset / CHPEMetadataPointer / HotPatchTableOffset makes the written ranges indeterminate, so the
  whole image is unobserved. This is temporary, not a permanent limit:
  1. a later `pe-loader-rules` version parses the DVRT entries and marks only the rewritten bytes as
     loader-written, so the rest of the image keeps being checked;
  2. the TBR G3 loader / LoadState model computes the post-rewrite bytes, so those rows can be decoded too;
  3. DVRT entries whose rewrite depends on the OS version or settings (e.g. retpoline enabled) need a named
     load-model premise; without it those bytes stay unobserved.
- (done, lift table -5) cmov / rep listing bits pinned to the no-transfer form after a real-Bundle data check:
  all 2,487 cmov and 5 rep rows of the UE core probe and the ELF test Bundles export the plain rows' bits.
- (done, lift table -6) rows whose only flow ops are pinned no-flow userops (LOCK / UNLOCK, the observed SIMD
  ops, the cpuid family) and intra-instruction branches (CONSTANT destination) are compared as "internal"
  (no transfer); pinned only from the UE data check. Other userops stay unobserved.
- Far call / far ret lift patterns (today unidentified, never a false near-call suspect).
- Block rows: count the "outside" tail beyond the file mapping apart from real differences.
