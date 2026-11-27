# TBR G2b: code-byte facts, design r2 (delta over r1)

r2 is design_tbr_g2b_code_facts_r1.md with the changes below. It folds:
- Astra r2 (.census6/g2b_design_astra2.md): 8 items.
- Fable r2 (APPROVE on condition P1-1): P1-1, P2-2..6, P3. Relayed in .census6/g2b_design_fable2.md.

Fable P1-1 and Astra item 1 are the same fix (E1).

## E1. Two file bases: on-disk lookup data vs runtime content (Astra 1, Fable P1-1)

§2 `file_map` is split into two bases. Each basis records which kind it is.

- **`file_record`** claims what the file records as lookup data, not a runtime value. It covers:
  - PE import and delay-import descriptors, ILT entries and the initial FirstThunk entries;
  - ELF dynamic tags, DT_JMPREL / DT_RELA entries, `.dynsym`, `.dynstr`;
  - ELF section headers and their name table;
  - the exception directory and RUNTIME_FUNCTION entries, read as table structure.

  Reads are by file identity, plus a verified file offset and length:
  - A read through a VA checks one unique file mapping and its bounds.
  - Section headers and their name table, which are not mapped, are bounded by file offsets.
  - A read inside a loader-written range (`written`, e.g. the IAT, the whole PT_DYNAMIC) is allowed: the basis is the
    pre-load value.

  Basis: `{"file_record": [file_offset, length]}`.
- **`file_runtime`** claims bytes as they are at run time: strings pointed to by registers, UNWIND_INFO / handler
  bytes read as content, code bytes. It keeps every r1 test:
  - inside the file;
  - unique mapping;
  - not zero-filled where read;
  - not ambiguous;
  - not in `written`;
  - not relocated.

  If `written` or relocation state is `indeterminate`, a range's absence from the lists does not establish a safe
  runtime read; the result is U (`MAP_INDETERMINATE`). Basis: `{"file_runtime": [file_offset, length]}`.
- **PE OFT = 0 fallback.** FirstThunk is read as `file_record` only when all of these hold:
  - the descriptor's TimeDateStamp = 0;
  - every entry is a valid ordinal, or a hint/name RVA in range and readable as `file_record`.

  Otherwise U (`BOUND_IAT_NO_ILT` / `ILT_ENTRY_INVALID`).

## E2. Trap inputs and boundaries (Astra 2, Fable P2-4, P2-5, P3)

- **Inputs.** The trap site is decided inside the per-row `override` hook (`check.py`, before the G1 comparison
  returns), from:
  - the raw window;
  - its relocation list;
  - the raw Intel and AMD ballots.

  `common_facts.votes()` filtering is not used. That filter drops ballots when G1's attributes are empty (e.g.
  Ghidra claims a longer length; `compare_row()` returns early).

  Ballots are not kept after the hook (cost compaction), so `trap_site` runs there.
- **Required ballot checks, per vendor:**
  - the full voter set;
  - the vendor mode;
  - status ok;
  - one form;
  - one consumed length.
- **Value conditions.** A value is produced only when the whole instruction, from the first prefix (REX 0x40–0x4F
  included, as in `compare._prefix_run`) through `ib` for `CD`, lies inside the verified window and overlaps no
  relocation.
- **Decoder flow → site form** (`decoders.py` vocabulary):
  - `int_n` with `int_vector` = n → int_n (the bytes give the opcode `CD`);
  - `int3` → int3 (`CC`);
  - `int1` → int1 (`F1`);
  - `syscall` → syscall;
  - `sysenter` → sysenter;
  - `into` → no x86-64 site.
- **Bytes and ballot must agree** (for example, `CD 03` is int_n vector 3 and is not int3). Otherwise the row is
  unresolved (`TRAP_FORM_UNDECIDED`).
- **Vendors.** Intel and AMD must agree, except for the encoding `0F 34`:
  - In long mode, Intel decodes `0F 34` as sysenter and AMD as #UD.
  - The site then carries `vendor_views: {"intel": {"form": "sysenter"}, "amd": {"form": "invalid_encoding"}}`
    (r5 vendor views) and the top-level `form: U("VENDOR_SPLIT_FORM")`.
  - It is counted separately.
  - A test pins what the AMD voter returns for `0F 34`.
- **Decided non-trap**, all of:
  - the window covers the whole instruction;
  - the byte test is negative;
  - no accepted voter in either vendor reports a trap flow.

  An agreed long-mode `CE` is also a decided non-trap.
- **Unresolved** with a location: no window or verified = 0 (`NO_WINDOW`), a missing required ballot
  (`BALLOT_MISSING`), incomplete consumption, a relocation over the opcode or `ib` (`RELOCATED_OPCODE`), or a
  disagreement.
- **Positive site basis:** the g1_window ref, plus the decoder ballot digest of each vendor
  (`{"decoders": {"intel": sha, "amd": sha}}`).
- §1 clarification: FIELD_PATHS is the existing path table, and "g2a-4" is the VERDICT_RULE value. Neither changes.

## E3. Import search: transfers, failure precedence, thunks, counts (Astra 3, Fable P2-2, P2-3, P2-6)

**Examined rows.** Every x86-64 row with a CALL, CALLIND, BRANCH, BRANCHIND or CBRANCH op:
- the G2a transfer op when the lift identifies one;
- otherwise every such raw op of the row.

CBRANCH is examined on its taken edge.

**Precedence, the first that applies:**
1. The raw op lies inside an identified trap lift (a CALLIND in a swi pattern): decided non-candidate.
2. A raw candidate op that cannot be bound to an exact transfer, because the lift is unknown or `op_keys.transfer` is
   null: unresolved (`TRANSFER_UNBOUND`).
3. Call-to-slot checks fail: unresolved, reason by check:
   - `SEGMENT_BASE`;
   - `POINTER_WIDTH`;
   - `SPACE_MISMATCH`;
   - `VENDOR_VIEW_CONFLICT`;
   - `FORM_MISMATCH`.
4. The target is a constant slot:
   - an import slot → name lookup (E1);
   - a constant slot that is not an import slot (a `.data` function pointer) → unresolved (`SLOT_NOT_IMPORT`);
   - the import or delay directory parse is indeterminate → `PARSER_UNSUPPORTED` or `SLOT_NAME_U`, never a negative.
5. The target is a direct row start. The target row is interpreted:
   - a slot-jump thunk (optionally after one `endbr64` row that is the unique contiguous successor in the same
     observation / view) → one hop, then (4);
   - an interpreted non-thunk row → decided negative;
   - otherwise, unresolved by reason:
     - target lift missing → `TARGET_LIFT_U`;
     - view conflict → `VENDOR_VIEW_CONFLICT`;
     - unsupported stub → `ELF_STUB_UNSUPPORTED`;
     - a second hop → `MULTI_HOP`;
     - not a row start → `TARGET_NOT_ROW_START`;
     - outside the row set → `TARGET_OUTSIDE_ROWS`.
6. A computed target that is not a constant slot: unresolved (`COMPUTED_TARGET`).

**Path.** The site's path keeps every row and op on it: the call / jcc / jmp, the `endbr64`, and the indirect jump.

**ELF checks:**
- slot VA = `r_offset` + load bias;
- relocation entry size (DT_RELAENT / DT_PLTREL = RELA);
- the symbol index inside the real `.dynsym` range;
- `.dynstr` NUL termination;
- the symbol is undefined (`st_shndx` = SHN_UNDEF), i.e. an external import.

The image's own definition of a same-named symbol is never an import site.

**Separate counts.** The thunk row `jmp [slot]` is itself a site (form jump, via slot). Counted separately:
- direct-slot sites;
- via-thunk sites (calls / jumps into a thunk);
- thunk rows.

## E4. Use point, width and premises (Astra 4, Fable P3)

**Call or jump site.** The value is the row-entry state: before any op of the use row.

**STORE.** The value is the state actually reaching that op.
- If a branch, flow op or opaque CALLOTHER precedes the STORE inside its row, a value the path cannot prove is
  unresolved (`INTRA_ROW_FLOW`).
- When `value()` returns U for that reason, no constant from an earlier row may substitute.

**Width.**
- A value states the width it is known at. Example: only `AL = 0x40` gives an 8-bit fact on AL. The full RAX value is
  then not claimed.
- `rwx_registers` accepts a register only when its known width covers the compared constant (≥ 8 bits for 0x40 /
  0x80 / 7) and the full register value equals the constant. Only a write that defines the whole 32- or 64-bit
  register qualifies (the zext pair, COPY64, `xor r,r`).
- A 64-bit address uses only values whose upper bits are established.

**The RWX constant follows the file format, not the API name:** PE gives 0x40 / 0x80, ELF gives 7.

**Basis of every register or STORE value:**
- `ghidra_pcode`;
- the definition row and op;
- the use row and op;
- the path, as row indexes.

**Premises.** `holds_if` is a list naming every premise the conclusion depends on:
- `image-code-unmodified-at-runtime`;
- `linear-entry-at-first-path-row`;
- for import sites, `import-slot-holds-loader-bound-import`.

**The walk stops after a predecessor with two outgoing edges** (`jcc`). This is intentionally conservative.

## E5. Range scope items, region diagnostics, coverage scopes (Astra 5)

**Scope items** (survey groups and region diagnostics):

```
{"row": idx, "op": n | null} | {"range": {"space", "start", "end" | U}, "basis"}
```

- `start` is always known when emitted. An unknown start is a `{"what": "eh_frame", "reason"}` diagnostic with no
  range.

**Region diagnostics.** Each region list carries `diagnostics: [{scope_item, reason}]` for:
- a truncated `.pdata` entry;
- a chain cycle;
- an unsupported UNWIND_INFO version or flags;
- handler data of unknown length (start known, `end: U`);
- an undecodable `eh_frame_ptr` encoding or base, or an omitted pointer (start unknown).

Only fully decided intervals enter the intersections, totals and `ranges_examined`. A code range the mapper marks
ambiguous is not used for a STORE negative; the STORE is unresolved (`TARGET_MAPPING_U`).

**Coverage records** have `{kind, method, ...}`, with one record per search method inside a kind. Examples:
- cache_maintenance: method `import_call` (`__clear_cache`) and method `syscall` (`unsupported`, `NO_ABI_BASIS`);
- the A64 instruction methods (`unsupported`, `G2C`).

An `__clear_cache` positive and an unsupported syscall search therefore coexist, and no zero is inferred from the
latter.

Each record also states:
- an empty search scope: `rows_examined` is empty after exclusions, with `empty: true`;
- a parser partial failure, as a scope item with its rows or ranges.

Run coverage stays absent.

**API recovery.** `NO_RWX_REGISTER` items carry the identified API (`items: [[idx, op, "VirtualAllocEx"], ...]`), so
per-API counts can be rebuilt from the facts.

## E6. Amendments and the compact form (Astra 6, Fable P3)

§8 becomes the following list.

1. **`rows_examined`** = the bound facts rows minus the valid `excluded` indexes.
2. **Grouped exceptions** (E5 scope items, range form included). A row index `i` stands for the r5 `row_ref` of
   `rows[i]`. This applies to every index field: `path`, `rows_outside_code`, `items`.
3. **`verified` explicit or compact.**
   - The threshold is 8,388,608 bytes of canonical UTF-8 encoding of all regions' explicit `verified` lists of the
     Bundle. It is fixed in FACTS_RULE g2b-1.
   - Compact form:
     - `program.code.verified_rule = {"per_row_window": row_set_sha256}`;
     - `program.code.verified_lengths`: one integer per facts row, in row order. 0 means no window. The length is
       checked against the row's window when read.
   - Both forms expand to the same per-region intersections, union totals and g1_window basis. The test checks this
     on both sides of the threshold.
   - Preference (Fable): if UE is above the threshold, the compact form is used for every Bundle. The choice is made
     on the measurement before implementation is final, so readers implement one form per FACTS_RULE.
4. **RWX `candidate` / `protection_argument: U`.**
5. **`register_values`.**
6. New members and meanings r5 lacks:
   - `rows_outside_code`;
   - jump-form and jcc-form sites under the `*_import_call` / `dynamic_resolution` / `dynamic_unwind_registration`
     kinds (the kinds are about transfers to the API, not calls only);
   - `regions: [...]` on code_write sites;
   - `path` and `holds_if` lists on values;
   - `string`;
   - `vendor_views` on trap sites;
   - region `diagnostics`;
   - coverage `method`;
   - the name-table digest.

**Site shape** keeps the r5 common fields: `row`, `form`, `kind`, `symbol`, `arguments`. A code_write site is
`kind: "code_write"` with `write: "static_store_candidate"` and the r5 write fields.

**Parsing is two-stage (§10).** The file parsers return file coordinates. A separate binding step attaches the
Bundle's image space, base and rows.

## E7. Equivalence allow-list (Astra 7)

- The name-table digest lives at `program.code.name_table_sha256`. The report checks it against the SHA-256 of the
  actual JSON bytes. The facts `producer` is unchanged except `producer.rule`.
- **Facts.** The allowed differences from c15a29a are `producer.rule` and `program.code`.
- **Evidence, inside the `common_facts` block.** Only `facts_sha256` differs. It is recomputed after checking that the
  facts file ends with one LF, and that LF alone is excluded.
- **Evidence outside the block.** Only `producer.tool_digest` differs (code changed).
- **Report.** Equal except the new `header.common_facts.code`.
- Time and peak RSS are judged per Bundle and per metric, against +10%.

## E8. Added golden cases (Astra 8, Fable tests)

Each case checks the exact counts, locations and bases of its sites and exceptions.

- Imports and the name table:
  - an ordinary OFT = 0 import against a bound IAT;
  - a PT_DYNAMIC-in-`written` ELF without section headers that still resolves;
  - an ELF self-definition with the same name (no site);
  - a non-import constant slot (`SLOT_NOT_IMPORT`);
  - a jcc into a thunk (a site, form jcc);
  - a thunk row and its caller, with three separate counts;
  - a name-table byte change fails the digest check.
- Trap:
  - a `CC` that is a site although G1 rejects Ghidra's claimed length;
  - a relocation over the `ib` of `CD ib` (unresolved);
  - verified = 0 (`NO_WINDOW`);
  - `0F 34` with the vendor split.
- Transfers and values:
  - a raw transfer op that cannot be bound (`TRANSFER_UNBOUND`);
  - a STORE after an intra-row branch (`INTRA_ROW_FLOW`);
  - only `AL = 0x40` known (8-bit fact, not an RWX register).
- Regions and survey:
  - a range-only unwind diagnostic, with start known and `end: U`;
  - one kind with a positive method and an unsupported method;
  - `verified` expansion equal on both sides of the threshold.
