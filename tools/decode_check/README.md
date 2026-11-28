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

### AArch64 snapshot decode

For an admitted AArch64 Bundle, add `--common-facts facts.json --arm64-objdump /path/to/llvm-objdump`.
The report's `header.arm64_decode` records the decoder version, executable hash and options, and compares
the listed instruction forms, direct targets, conditions and operands against the G2c facts for each row.
The decoder reads authenticated snapshot words at their recorded addresses. Rows and fields without a shared
claim are `unobserved`. The report preserves separate counts for decoded observations and matched claims.
An observer error returns exit status 1. This option leaves the default G1 counts and engine evidence unchanged.
Original-file mapping and runtime byte provenance are outside this comparison.

Add `--arm64-gnu-objdump /path/to/aarch64-linux-gnu-objdump` for the feature audit of G2c's
PAC and BTI forms and LDADDAL. This writes `header.arm64_decode.feature_audit` under the same
admitted row and facts binding. LLVM and GNU compare encoded form and explicit operands.
Decoder disagreements are withheld, and missing comparable fields remain unobserved.
The audit records GNU's version, hash and options. GNU's ordinary AArch64 mode supplies encoding
observations. The pilot was verified with GNU binutils 2.45. LLVM is also run with each selected
feature disabled individually. A failed feature-specific observation leaves the encoding comparison available. Raw output
is kept so that a HINT printed in both settings does not imply equal CPU effects. The report
links to the applicable G2c ISA conditions and includes the Bundle's Ghidra flow and p-code
observation. Effective CPU and OS behavior remains unobserved, and formal engine evidence retains
its existing policy.

### AArch64 ELF file provenance

Add `--common-facts facts.json --arm64-elf-page-size 4096` to check the admitted snapshot against
its original little-endian AArch64 ELF64 file. Page sizes are explicit model inputs (4096, 16384 or
65536 bytes). The report records the linked base, snapshot base and load bias.
`header.arm64_elf_mapping` gives an original file offset and program-header index for each
four-byte word in a single file-backed executable PT_LOAD, then reports byte equality and possible
loader writes separately. A matching word can overlap a relocation. An ambiguous segment, zero-fill,
or a row in another address space supplies no file comparison. The original and memory members are
checked against the same admitted Bundle.

The loader model covers the listed AArch64 relocation widths, standard and dynamic Android RELR,
PT_DYNAMIC and reserved PLT GOT slots. `elf-aarch64-loader-rules-2` models the aligned 16-byte
`R_AARCH64_TLSDESC` write and the 8-byte resolver slot addressed by a paired `DT_TLSDESC_GOT`.
`DT_TLSDESC_PLT` names executable code. The tag itself introduces no write to that code.
The footprint includes the optional legacy lazy resolver write described by glibc and the
two pointer-sized fields specified by AAELF64. A descriptor relocation can occur without the
lazy tags. Malformed or ambiguous addresses, duplicate or unpaired tags, and writes that can
change the relocation inputs under the TLS descriptor model withhold loader completeness.
[Arm ELF ABI](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst#relocations-for-thread-local-storage) ·
[glibc loader change](https://ecos.sourceware.org/ml/libc-alpha/2017-10/msg00320.html) ·
[GNU linker behavior](https://sourceware.org/pipermail/binutils-cvs/2019-April/050454.html)

Unsupported encodings, malformed tables and unresolved widths
(including COPY) leave loader coverage indeterminate. The report describes the captured snapshot and
the selected loader model. Its results stay in the diagnostic report, with the existing G2c facts
and engine evidence retaining their original format and meaning.

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
- `--isa-facts` writes `g1-decode-evidence-2`: -1 plus the per-row ISA facts F1-F7 (design
  `.census6/design_tbr_isa_facts_r3.md`, 2b `.census6/design_tbr_isa_ordinary_r3.md`); reader `Evidence.isa`.
- `--producer-override` writes `g1-decode-evidence-3`: -2 plus one producer-override verdict code per compared row
  of X-1 producer-profile Bundles (design `.census6/design_tbr_g1_x1_r1.md` + r2 / r3, closed;
  `producer_override.py`). Codes: A effect_attested, S / I effect_attested with the syscall / interrupt a3
  exemption (OS-contract model), C contradicted, U unobserved, O override_present; details for C / U / O and for
  never-compared rows with a reported override. effect_attested attests effects only (the exported row equals the
  bytes on every compared attribute and the target set T), never the completeness of the producer's report;
  whether it discharges `producer-override-report` is TDO's choice. Legacy Bundles: every function
  `not_reported`. Reader `Evidence.override`. Until X-1 lands on main, run X-1 Bundles with `PYTHONPATH` set to
  the X-1 tree (no admission copy); the header's `engine_source` records the imported `tdo_v2` digest.

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

## G2a common facts and the -5 verdict block

`--common-facts FILE` writes the derived claims (schema `tbr-common-facts-1`, `producer.rule` `g2a-3`;
`common_facts.py`) and, with `--evidence-out`, evidence `g1-decode-evidence-5`: -3 plus a `common_facts` block
`tbr-common-facts-verdicts-2`, rule `g2a-4` (design_tbr_g2a_cost r1 + r2). The reader still accepts -4
(`tbr-common-facts-verdicts-1`, rule `g2a-3`, one unit list per row).

-5 block: `{schema, rule_version, facts_sha256, row_set_sha256, field_paths, unit_sets, rows}`.

- `field_paths` must equal `common_facts.FIELD_PATHS` in order; a unit names its field by index.
- `unit_sets` is a list of non-empty ordered unit lists. A unit is `[path_id, code]`, `[path_id, code, edge]` or
  `[path_id, code, null, op]`, with edge `[when, source, requires]` (values from `ORDERS`) and op
  `{ordinal, opcode}`. The writer never emits `op.row`; a reader accepts it only through per-row binding. Codes are
  `c x u n ?`.
- `rows` is `[{id, observation, set, state}]` in `(id, observation)` order. Sets are numbered by first use in that
  order; every set is used, none is repeated, and `state == row_state(set)`.
- Denominators count a set once per row that uses it.
- Binding is per referencing row, so two rows sharing a set can bind differently (coverage, `*`). A violation in any
  row rejects the whole file.
- `facts_sha256` is the SHA-256 of the facts file without its final LF. The facts file is streamed and is
  byte-identical to `canonical(doc) + LF`.

Port notes (Rust kernels later):
- Pure functions: `derive_row`, `summarize_votes(votes, row_address) -> VoteSummary` (`None` = ABSENT) and
  `row_verdicts(row, summary, final isa, vendor, landing index)`. Units become values only after `row_verdicts`
  returns.
- Conformance vectors: `TDO_V2_G2A_COST_CROSSCHECK=1` checks every row view against the frozen 798b903 functions in
  `_g2a_reference.py`. The `test_g2a_cost_*` tests are the positive and negative vectors for the -5 reader.
- The -5 structure check is stricter than -4: an empty opcode or a path outside FIELD_PATHS is rejected when the file
  is accepted, not later at binding.
- Exception timing differs from 798b903. `summarize_votes` reads voter values for every row view whose votes are all
  ok, at collection time; the reference read them only on the call_near, encoded_target and jcc paths. Both are total
  for ok voters. The crosscheck runs both paths and reports a one-sided exception with its row and view.
- `common_facts_verdicts5.schema.json` gives the structure as JSON Schema; the cross-reference rules above are prose
  only.

## ARM64 source decode profiles

To cross-check original bytes before lifting, supply both `--llvm-objdump` and
`--gnu-objdump` along with `--encoding-archive`. The tool checks the executable
ELF range, passes the same four-byte words at their loaded PCs to both decoders,
and records tool digests, raw outputs, and Arm encoding candidates. For example:

```sh
PYTHONPATH=src python tools/bundle_export/arm64_source_evidence.py lib.so decode.json \
    --entry 0x184cd0 --size 80 --base 0x100000 --encoding-archive arm-a64.tar.gz \
    --llvm-objdump /path/to/llvm-objdump --gnu-objdump /path/to/aarch64-linux-gnu-objdump
```

Replay uses `--verify` and the same archive and decoder paths. The cross-check
runs before SLEIGH, Bundle admission, or TDO. `different-rendering` preserves
different disassembly text for review. The Arm checks in this mode cover the
encoded B.cond target and condition, and the feature-dependent PACIASP/HINT
encoding. They leave CPU features and execution effects unobserved.

Add `--decode-profile sve-sme-v1` for the versioned SVE/SME cross-check. Both
decoders read every selected word. The v2 evidence records the named profile,
actual decoder options and executable digests, and probe results for SVE/SME
operands and scaled versus unscaled addresses. Replay selects the recorded
profile from the registry. Baseline evidence also replays through `--verify`.

V2 slots retain both raw renderings. A `common_facts` record contains the Arm
encoding and only the checked fields for that encoding. These include register
offsets for GPR and SIMD/FP loads and stores, the address operand of PRFM, the
encoded start address of SVE LD1W (32- or 64-bit lanes), and operand shapes for
BFMMLA, merging BFCVT, BFCVTN/BFCVTN2, FMOPA (32/64), and ZERO ZA. Per-field
`field_evidence` marks a tool's stated value confirmed, contradicted or
unobserved. A tool's wrong shift remains visible beside the Arm address. The
LD1W address comparison checks the printed base and multiplier. Arm provides
the vector-length scaling rule. Register-offset addresses contain the effective
shift and extension. The original word preserves the option and scale bits,
including byte accesses for which both scale bits produce a shift of zero.
The payload uses named registers and applies to the source ELF word. CPU
features, streaming mode, ZA state, vector length and lane access sets require
runtime evidence.

Select `--decode-profile sve-sme-v2` to include the Arm encodings for scalar
integer unsigned-offset loads and stores and the `MOVZ` and `MOVN` forms of
immediate `MOV`. The memory check compares the byte displacement, including an
omitted zero. The move check compares the destination operand and the immediate
value at the encoded width. `MOV` aliases report the effective value. Explicit
`MOVZ` and `MOVN` also report the encoded immediate and shift. The original
renderings remain available for both checks. `sve-sme-v1` evidence replays with
its original rules.

Select `--decode-profile a64-all-instructions-v2` for the Arm operand rejection
rules. A matched word can carry an `arm_check` with `verdict: UNDEFINED`,
the pinned candidate, the reason and the examined bits. A tool that reports a
normal instruction is marked contradicted. The original renderings and their
comparison remain available. The verdict covers the audited LSE128 and
D128+THE register forms and SVE immediate `CPY` and `DUP`. Other words
continue through the usual verification. See the [Arm rejection design](../../docs/handoff_tbr/design/design_tbr_arm64_undefined.md).

## A64 encoding table coverage

`arm64_encoding_coverage.py` generates original instruction words from the
pinned Arm encoding index. It records every allocated row by section and ordinal,
including rows with the same encoding name. Each reachable row has a witness, and
the sample set exercises both values of every bit that can vary within that row.
It also uses the instruction diagrams to sample distinct operand size combinations
that the per-bit pass missed, including vector length selectors such as `Q`.
MOPS copy and set rows also get a word with distinct operand registers.
The report retains alternate table candidates and both decoder outputs at a
fixed synthetic address. For example:

```sh
PYTHONPATH=src python tools/decode_check/arm64_encoding_coverage.py arm-a64.tar.gz coverage.json \
    --llvm-objdump /path/to/llvm-objdump --gnu-objdump /path/to/aarch64-linux-gnu-objdump \
    --profile a64-all-instructions-v1 --words-out coverage.bin
```

The default uses `sve-sme-v2`. `a64-all-instructions-v1` requests LLVM's `+all`
option for a broader decoder comparison. The selected executable and exact
options are recorded. Operand size combinations are constrained by the table
guards. Other combinations, instruction-specific decode constraints, feature
availability on hardware and p-code effects need separate evidence. `unobserved`
identifies a word for which at least one decoder produced no comparable normalized
rendering. See [GNU's A64 UAO rendering discrepancy](ARM64_GNU_UAO.md) for a case
where the printed operation needs to be checked against Arm's instruction definition.
See [GNU renderings of undefined A64 words](ARM64_GNU_UNDEFINED.md) for the
operand restrictions and native CPU results for the 407 GNU-only words.
