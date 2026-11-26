# decode_check (G1)

Checks one sealed Bundle against its own `original` file, without Ghidra:

1. **Mapping (layer `mapping`)** — the original is mapped by pinned loader rules
   (PE32+: `pe-loader-rules-6`, ELF64: `elf-loader-rules-4`) and every sealed
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

### Raw ISA-fact evidence (TBR ISA facts, design `.census6/design_tbr_isa_facts_r3.md`)

The shims fill the fields after `target_kind` (layout revision 3), and `decoders.py` keeps them in
`Decoded.extra`. They never enter a G1 vote or `as_json`. Per voter they hold:

- the privilege attribute: Zydis `IS_PRIVILEGED`, XED `RING0`, and iced `must_be_cpl0` /
  `is_privileged` / `may_require_cpl0`;
- `flow_detail`: whether a `sysret` vote is a sysret or a sysexit; the form comes from `operand_bits`;
- the effective segments of memory operands. XED reports only FS / GS overrides in 64-bit mode;
- the raw error name. XED `INVALID_FOR_CHIP` is kept apart, while the G1 status stays `invalid`;
- each decoder's own ISA-set / extension names; iced reports its CPUID features.

There are three XED chip profiles (`decoders.XED_PROFILES`, `decode_profile`). They are one decoder,
not voters:
- `xed:g1`: the G1 voter setting. The input chip is unset, so XED decodes feature-dependent
  encodings in their legacy meaning, e.g. `F3 0F BC` = BSF.
- `xed:baseline` = `P4PRESCOTT_NOLAHF`: the smallest chip with LONGMODE in the pinned build.
- `xed:all` = `XED_CHIP_ALL`.

`profile_catalogue()` lists the ISA sets each profile enables, for the evidence header digest.

Data files (`isa_tables.py` loads them, checks them together, and digests each over its canonical bytes):

- `isa_conditions_x64.json`: the ISA condition table. Each entry cites its SDM / APM reference
  entry. It holds:
  - privilege / OS alternatives (f2) and privilege-dependent meanings (f2');
  - continuation tags with target source and return mode (f3);
  - CPU features (f4) and vendor notes (f5);
  - per-output sources (f6) and base / state writers (f7);
  - CET conditions, state-dependent and data-dependent faults.

  Only the listed forms are covered. Any other form is `unobserved`, never "no condition".
- `iclass_map_x64.json`: maps each voter's mnemonic to a canonical key. A rule can be qualified by
  operand size, flow, target kind, opcode bytes or ModRM.reg.
- `isa_splits_x64.json`: holds three kinds of entry:
  - feature splits: main meaning, fallback meaning and deciding feature;
  - the BND prefix split;
  - negative entries (`66 90`, `F3 C3`).

  Voters that land on the main and fallback keys of one split record a split, not a lookup
  disagreement.
- `isa_ordinary_x64.json` (2b, design `.census6/design_tbr_isa_ordinary_r3.md`): classifies every
  ordinary form, so that it does not stay `unobserved`. It holds:
  - the cited 64-bit base level (XED ISA sets; the iced CPUID features mapped from them);
  - the allowed categories;
  - the per-form class conditions (plain / x87 / x87_nowait / fwait / mmx / sse_fp / sse_int / mmx_sse
    / fxsave / fxrstor / mxcsr);
  - the generated, reviewed allowlist.

  `isa_ordinary_gen.py <xed_catalogue.tsv> [--write]` regenerates the allowlist from the pinned XED
  instruction table (`decoders/xed_catalogue.c`, built by `build_decoders.sh`).
- `isa_tables.classify(tables, votes, window)` decides one row:
  - the cited table comes first: cited / cited_split / table_lookup_disagree / partial_lookup;
  - only when no voter's form is cited, the allowlist: every voter must pass tests A-F from its own
    evidence (form and aliases, base ISA, privilege, system flags with per-voter capability,
    segment-register operand, kind). The result is derived_ordinary(class, flags), or unclassified with
    reasons per voter and test.

  TDO may use a derived-ordinary row only under the premise `isa-ordinary-rule`.

Shim layout revision 4 adds the form evidence: category, RFLAGS read / written, segment-register
operands, explicit operand kinds, effective LOCK / REP, and up to 8 memory accesses with role, segment and
read / write.

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

- **PE load-config code rewriting.** Done in `pe-loader-rules-6` for DVRT version 1 FUNCTION_OVERRIDE entries
  (the form found in ntdll / kernelbase): only each X64_REL32 rel32 field (4 bytes) is loader-written, so those
  OS-dependent bytes stay unobserved and the rest of the image is checked. Still indeterminate (whole image):
  other DVRT symbols (retpoline, import / indirect control transfer, switch table, ARM64X), other DVRT versions,
  CHPE (hybrid), hot patch. Follow-ups (owner, 2026-11-25): the TBR G3 LoadState model computes post-rewrite
  bytes; OS / setting-dependent entries need a named load-model premise, else unobserved.
- (done, lift table -5) cmov / rep listing bits pinned to the no-transfer form after a real-Bundle data check:
  all 2,487 cmov and 5 rep rows of the UE core probe and the ELF test Bundles export the plain rows' bits.
- (done, lift table -7) all 1,756 x86-64 userops classified once, from Ghidra's own SLEIGH sources and a test
  binary (`sleigh_userops.py` -> `userop_testbin.py` -> Ghidra export -> `userop_classify.py`): 1,259 no-flow
  (pinned, `userops_x64_classes.json`), 12 flow, 89 privileged / OS-gated (iced: is_privileged / must_be_cpl0 /
  may_require_cpl0 -- never pinned; cpuid and rdtsc are here), 396 not exercised. A row whose only flow ops are
  pinned no-flow userops and intra-instruction branches is "internal". The test binary and its Bundle stay local.
- repe / repne string compares (conditional loop-back CBRANCH): a named shape to add after a data check.
- Far call / far ret lift patterns (today unidentified, never a false near-call suspect).
- Block rows: count the "outside" tail beyond the file mapping apart from real differences.
