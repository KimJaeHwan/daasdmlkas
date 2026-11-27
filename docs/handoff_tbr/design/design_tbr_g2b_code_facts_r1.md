# TBR G2b: code-byte facts, implementation design r1

Base: feat/g1-decode-check c15a29a. r1 is self-contained.
- It replaces r0 and folds Astra r1 (.census6/g2b_design_astra1.md, 12 items) and Fable r1 (P1-1..5, P2-6..10, P3).
- Where the two differ, Astra is followed: the trap form comes from verified bytes and decoders, not from the lift.
- It implements the closed G2 design r5 §5 and §9 G2b, with the representation amendments named in §8.

Owner decisions in force:
- **No ABI.** Call-argument facts are register values at the call; argument indexes are U; no named ABI opt-in.
- Ghidra independence. A basis comes from the file or the decoders. A step that uses Ghidra observations is labeled
  `ghidra_pcode`.

## 1. Scope and versions

- x86-64 PE32+ and ELF64.
- AArch64 static kinds (SVC / HVC / SMC, IC IVAU / DC CVAU): coverage is `unsupported` with reason `G2C`.
- Run surveys have no records, so no run coverage is written: absent, never empty.
- Facts only.
  - G2b sites are uncompared claims. An existing `transfer.kind` confirmation or row state does not confirm them.
  - The r5 §8 "site, trap_instruction" comparison stays an open follow-up. It compares the bytes' `CD ib` with each
    decoder's `int_vector`, independently.
- Versions:
  - FACTS_RULE "g2b-1" (facts `producer.rule`).
  - FIELD_PATHS and VERDICT_RULE "g2a-4" unchanged.
  - `program.code.premise` = `image-code-unmodified-at-runtime`.
  - Every fact that reads code or unwind bytes carries that premise in `holds_if` (r5).
- Reason codes are a closed enum (`REASONS` in `code_facts.py`), recorded with FACTS_RULE.
- The name table (`code_site_names.json`) is data. Its SHA-256 is written in the facts `producer` and checked by the
  report, because `tool_digest()` does not cover JSON files.

## 2. Byte bases

There are two distinct bases; neither stands in for the other.

- `g1_window`: the bytes G1 compared for one instruction row.
  - Reference `{"row": row_ref, "decode_row": [space, offset]}`: the full row_ref distinguishes observations and views.
  - Interval `[row_va, row_va + result.window.verified)` with verified > 0 only.
  - This is not the collector's relocation-cut `data`, the claimed length, or the voter-consumed length.
- `file_map`: bytes read from the original file through the `pe_map` / `elf_map` discipline:
  - inside the file;
  - one unique mapping;
  - not zero-filled where a value is read;
  - not ambiguous;
  - not loader-written (not in `written`);
  - not relocated.

  Each read records `{"file_map": [file_offset, length]}`. A read that fails one test gives U with its reason code:
  `ZERO_FILL`, `AMBIGUOUS_MAPPING`, `LOADER_WRITTEN`, `RELOCATED`, `OUTSIDE_FILE` or `TRUNCATED`.

  Metadata (`.pdata`, UNWIND_INFO, import and dynamic tables, strings) uses `file_map`. G1 does not compare these
  bytes, and IAT slots are loader-written by design.

## 3. Regions (r5 §5 `regions`)

- **`code`.**
  - PE: each section with IMAGE_SCN_MEM_EXECUTE. The range is `bundle_base + VirtualAddress` with `VirtualSize`.
  - ELF: each PT_LOAD with PF_X. The range is `p_vaddr + load_bias` with `p_memsz`.
  - `executable` and `writable` come from the same characteristics / flags.
  - Each range carries its space and load base.
- **`unwind_metadata`, PE.**
  - The exception directory (dir 3) range.
  - Each 12-byte RUNTIME_FUNCTION read inside it through `file_map`.
  - For each referenced UNWIND_INFO of a supported version (1, 2) and flags:
    - the header plus the aligned unwind-code slots (4 + 2·count, rounded to 4);
    - then, by flags, CHAININFO (a 12-byte RUNTIME_FUNCTION) or EHANDLER / UHANDLER (a 4-byte handler RVA).
    - The language-specific data follows that RVA field. Its length is U (`HANDLER_DATA_LENGTH`).
  - Truncation, a chain cycle, an unsupported version or unsupported flags record a scope item with its location and
    reason.
  - Known regions survive other entries' failures.
- **`unwind_metadata`, ELF.**
  - The PT_GNU_EH_FRAME range (`.eh_frame_hdr`).
  - The `.eh_frame` body:
    - from section headers when present (name table, bounds, SHF_ALLOC, contained in a PT_LOAD);
    - else its start from `eh_frame_ptr` in the header, with its end U (`NO_SECTION_HEADERS`).
  - `.gcc_except_table` by section name when section headers exist.
- **`verified`** (per region): one record per g1_window, `{"interval": window ∩ region, "basis": g1_window ref}`.
  - Any window intersecting the region is included, even one starting outside it.
  - The same bytes may belong to `code` and `unwind_metadata`.
- **Size rule.**
  - The per-window list is written when its encoded size is at most 8 MB per Bundle.
  - Above that, the region carries `verified_rule: {"per_row_window": row_set_sha256}`, and the per-row verified
    length goes into a compact array `verified_lengths` in facts row order. This is a declared third representation.
  - Measured on UE before choosing; the threshold is reported.
- **Totals.** Per-region verified-byte totals are union lengths, not sums of windows.
- **Rows outside regions.** Rows that start outside every `code` region are listed in `code.rows_outside_code`, as
  row indexes (§6).

## 4. Sites (r5 §5 `sites`)

### 4.1 trap_instruction (Astra 4, Fable 6)

- Every x86-64 row is examined, with or without a lift, independently of G1 verdicts.
- The form comes from the row's g1_window bytes (after prefixes) and the decoder ballot (consensus form, both vendor
  views agreeing).

| x86-64 encoding | form | vector | immediate |
|---|---|---|---|
| `CD ib` | int_n | ib | ib |
| `CC` | int3 | 3 | null |
| `F1` | int1 | 1 | null |
| `0F 05` / `0F 34` | syscall / sysenter | null | null |
| `CE` | (invalid in long mode: no site) | | |

- The opcode bytes must be inside the verified window and not relocated. A prefix run is allowed. A disagreement
  between bytes and ballot, between vendors, or a truncated window makes the row `unresolved` (`TRAP_FORM_UNDECIDED`).
- `syscall_abi`:
  - null for int3 / int1, where the field does not apply;
  - U (`NO_ABI_BASIS`) for int_n, syscall and sysenter.
- No syscall is identified as `cacheflush`, so the `cache_maintenance` syscall survey is `unsupported`
  (`NO_ABI_BASIS`).

### 4.2 Call and jump sites through imports (Astra 6, Fable 1, 2, 10)

Examined: every x86-64 row with a CALL, CALLIND, BRANCH or BRANCHIND op that is the row's G2a transfer op
(`op_keys.transfer`). CALLINDs inside trap lifts are not transfer ops.

**Call to slot.** The call or jump target is taken from the G2a claim (`target_value` memory at a constant address,
or the direct edge's `to`). That step is labeled `ghidra_pcode` with its row and op. Restoring targets from bytes is a
follow-up. The checks:
- form (call_near / jmp_near);
- exact op;
- address space;
- pointer width 64;
- no segment base;
- vendor views agree.

**One hop.** A direct call or jump whose target row is a G2a `jmp_near` indirect through a constant memory slot:
- one leading `endbr64` row is allowed (`.plt.sec`);
- a second hop, an intermediate address, or a view conflict is unresolved (`MULTI_HOP` / `TARGET_NOT_ROW_START`).

**Slot to name** (file_map; premise `import-slot-holds-loader-bound-import`):
- **PE import.** Descriptor, ILT (OriginalFirstThunk), then IAT slot address, DLL and name or ordinal.
  - With OFT = 0: fall back to FirstThunk only when the descriptor's TimeDateStamp = 0. Otherwise U
    (`BOUND_IAT_NO_ILT`).
- **PE delay import.** Same, with the attribute-relative addressing checked. Unsupported forms are U
  (`DELAY_FORMAT`).
- **ELF.**
  - The slot's relocation in DT_JMPREL (JUMP_SLOT; DT_PLTREL = RELA) or DT_RELA (GLOB_DAT, for `-fno-plt`
    `call [GOT]`), matched on `r_offset`.
  - The symbol index from `r_info`.
  - `.dynsym` entry and `.dynstr` name, bounds-checked and NUL-terminated (DT_SYMTAB / DT_STRTAB / DT_STRSZ /
    DT_SYMENT), or the section headers' linked tables.
  - No guess from PLT order or addends. An unsupported stub or relocation type is unresolved
    (`ELF_STUB_UNSUPPORTED` / `ELF_RELOC_UNSUPPORTED`).

**Basis**:
- `{"pe_import": {dll, name | "#ordinal", slot_va, ilt}}` or `{"elf_reloc": {name, slot_va, type}}`;
- plus `{"path": [call row/op ghidra_pcode, thunk row?]}`.

Names match the table case-sensitively, independent of DLL (API-set DLLs); the DLL is recorded.

**Kinds and names** (data):

| kind | names |
|---|---|
| self_modify_import_call | VirtualProtect, VirtualProtectEx, NtProtectVirtualMemory, ZwProtectVirtualMemory, WriteProcessMemory, NtWriteVirtualMemory, ZwWriteVirtualMemory, FlushInstructionCache, NtFlushInstructionCache, mprotect, pkey_mprotect |
| dynamic_resolution | GetProcAddress, LdrGetProcedureAddress, LdrGetProcedureAddressForCaller, dlsym, dlvsym |
| rwx_allocation_constant_args | VirtualAlloc, VirtualAllocEx, VirtualAlloc2, NtAllocateVirtualMemory, ZwAllocateVirtualMemory, mmap, mmap64 |
| cache_maintenance | `__clear_cache` |
| dynamic_unwind_registration | RtlAddFunctionTable, RtlInstallFunctionTableCallback, RtlAddGrowableFunctionTable, `__register_frame`, `__register_frame_info` |

A site carries its `form` (call or jump) and `symbol`.

**Decided negatives (not listed).** These are examined, not excluded:
- an identified import whose name is not in the table;
- a direct transfer landing on an in-image row start that is not a slot-jump thunk.

**Unresolved** (for every call kind, by reason):
- `IMPORT_BY_ORDINAL`;
- `COMPUTED_TARGET` (target not a constant slot or row);
- `MULTI_HOP`;
- `TARGET_OUTSIDE_ROWS`;
- `INDEX_INCOMPLETE` (the Bundle's row set is incomplete for that target);
- `SLOT_NAME_U` (a slot whose name read failed).

The image's own exports are not import calls. A zero on ntdll means zero import calls of these names.

### 4.3 Register values at a use point (Astra 7, 8; Fable 4, 7, 8)

**Use point.**
- For a call or jump site: the input state of the row before its call setup ops.
- For a STORE: the state just before that op.

**Path.** Walk backward through earlier rows only while all of these hold:
- the predecessor is in the same observation, space and view;
- the predecessor's end equals the row's start;
- the predecessor has exactly one sequential edge, to this row;
- this row (including the use row itself) is not the target of any other edge in the Bundle and is not a recorded
  landing pad;
- the predecessor has no flow op and no opaque CALLOTHER.

The walk stops at:
- an address gap;
- an unknown length;
- an overlap;
- several candidates;
- the observation's first row.

Function row order and facts sort order are never used as execution order.

**Value.**
- The last definition reaching the use point of each general register: the 16 GPRs, at their widest written width.
- Any later op output overlapping `(space, offset, size)`, in intermediate rows or earlier ops of the use row, kills
  it. Example: `RAX = 0x40` then `AL = ?` gives no RAX value.
- Accepted definitions:
  - COPY of a constant;
  - COPY constant into a 32-bit register followed by INT_ZEXT of that same def to 64 bits (`mov r32, imm`);
  - INT_XOR / INT_SUB of a register with itself (`xor r,r` = 0);
  - LEA giving a constant address (the `value()` expressions `constant` / `add` of constants at 64 bits, evaluated
    with wrap at the width).
- Memory loads are never constants.
- Flags and UNIQUE registers are not listed.
- Each entry is `{"register": reg (with width), "value": {"constant": hex, "width": w}, "definition": {row, op},
  "path": [row indexes]}`.

**Premise.** Every value carries `holds_if: "linear-entry-at-first-path-row"`: no unobserved entry, such as a
computed-jump target or an unwind landing, into the path rows. When the Bundle's row set or edge index is incomplete,
the walk is limited to the use row itself, reason `INDEX_INCOMPLETE`.

**No ABI in the output.**
- `arguments: []` means "no argument identified by index". The argument index is U.
- `register_values` carries the facts above.
- `rwx_allocation_constant_args` (amendment):
  - `candidate: true`;
  - `protection_argument: U("NO_ABI_BASIS")`;
  - `rwx_registers: [reg]` whose value is exactly 0x40 or 0x80 (PE) or exactly 7 (ELF). No masks, so 0x107 does not
    match.
  - Meaning: at an identified allocation call, a register holding a RWX value is observed. It does not claim the
    protection argument or a successful RWX allocation.
  - Allocation calls without such a register are unresolved (`NO_RWX_REGISTER`). This includes VirtualAllocEx,
    VirtualAlloc2 and Nt/ZwAllocateVirtualMemory, which pass protection on the stack. Constant stack stores at
    `[rsp+k]` are a follow-up.
  - Report candidate and unresolved counts per API.
- `dynamic_resolution`: `requested_name: U("NO_ABI_BASIS")`. A register value pointing into a NUL-terminated string
  within file_map read-only bytes adds `"string": {text, file_map, register}`. That is a fact about the register only.

### 4.4 code_write static candidates (Astra 9)

- The unit is (row, STORE op), over every STORE op of every x86-64 row.
- The interval is `[address, address + byte width)` in the STORE's space selector. The address resolves through the
  in-row `value()` or a §4.3 register constant (same path premise).
- If the interval intersects a `code` region of the same space and load base:
  - site `static_store_candidate` with `op`, `target_range` (the full interval), `regions: [index, ...]` (all
    intersected) and `static_basis`.
- A concrete address outside every searched region is an examined non-match.
- Unresolved, by op:
  - `STORE_ADDRESS_NOT_CONSTANT`;
  - `STORE_WIDTH_U`;
  - `STORE_SPACE_U`;
  - `ADDRESS_WRAP`;
  - `TARGET_MAPPING_U`.
- Every op of a row is reported on its own, so a positive and an unresolved op of one row both appear.
- No stack or heap disjointness is assumed. A reported zero covers only the explicit STOREs examined and the code
  regions.
- No run coverage (§1).

## 5. Survey (r5 §5 `survey`; amendment)

One coverage record per kind; for code_write, per `write` discriminant (`static_store_candidate` only).

- **`rows_examined`** = `{"facts_rows": row_set_sha256, "excluded": [{row, reason}]}`.
  - Meaning: examined = the bound facts rows − excluded.
  - `excluded` lists only rows truly not searched: non-x86 rows (`NOT_X86`). Rows inspected and found without a
    CALL / STORE are examined negatives and are not listed.
  - A digest mismatch, a missing ref or a duplicate ref is a reader error.
- **`ranges_examined`**: the code regions (code_write); [] otherwise.
- **`unsupported` and `unresolved`**: grouped as `[{"reason": code, "items": [[row_index, op_ordinal | null], ...]}]`.
  - `row_index` is the position in the facts row order bound by `row_set_sha256`.
  - Expansion to the r5 `scope_item` is defined: `{row: rows[i] ref, op?, reason}`.
  - The expanded count equals the listed count. Items are sorted, with no duplicates.
- Distinct states are never merged: decided non-target, target not identified, ordinal only, no import directory
  (`NO_IMPORT_DIRECTORY`), parser unsupported (`PARSER_UNSUPPORTED`), partial failure.
- A Bundle with missing functions reports only observed rows; `missing_functions` is carried.

## 6. Row indexes

`row_index` means the index in the facts document's `rows` array, which is sorted by (id, observation) and bound by
`row_set_sha256`. Row references are never written out in full in survey lists.

## 7. Report, equivalence and budget

- **Report header** `common_facts.code`:
  - per kind: site, candidate, unresolved-by-reason, unsupported and excluded counts;
  - per API: candidate and unresolved counts;
  - region summary and union verified totals;
  - `rows_outside_code` count;
  - name table digest;
  - the chosen `verified` representation.
- **Equivalence, against c15a29a** on the same five Bundles (ntdll, UE core probe, zlib, clang ELF,
  v3-win-release-full), with the same generation, decoders and options:
  - facts rows identical; only `producer.rule` and `program.code` differ;
  - -5: only `facts_sha256` differs, and it equals SHA-256 of the new file without the LF, recomputed independently;
  - row_set_sha256, field_paths, unit_sets, per-row set / state and all old report aggregates equal.
  - Implemented as a new `cost_probe/equiv_g2b.py`, -5 against -5.
- **Budget:**
  - time and peak RSS at most +10% over c15a29a, per Bundle and per metric;
  - facts-file growth reported, and checked against the §3 size rule;
  - a hand-checked site count on one PE (v3-win-release-full) and one ELF (clang).

## 8. r5 representation amendments (named)

1. `rows_examined` by digest plus `excluded` (§5).
2. Grouped `unresolved` / `unsupported` with row indexes (§5).
3. `verified` per window, or the `per_row_window` rule above the size threshold (§3).
4. RWX site `candidate` / `protection_argument: U` (§4.3).
5. `register_values` on call sites, which r5 lacks, under the owner's no-ABI decision.

## 9. Tests (each with exact expected sites, null / U, basis refs and scope items)

1. Duplicate address with different observation / view; a window crossing a region end; a window starting outside a
   region; union totals.
2. PE unwind: truncated, chained, handler with U length, unsupported version. ELF without section headers
   (`eh_frame_ptr`, end U).
3. The trap table rows; a prefix run; a byte / ballot disagreement; a vendor disagreement; a truncated window;
   `CE` gives no site; a row without a lift is still examined.
4. PE import, delay import, bound with OFT = 0 (TimeDateStamp ≠ 0 gives U), ordinal (unresolved); a one-hop thunk;
   a two-hop chain (unresolved); a `jmp [IAT]` tail site.
5. ELF: ordinary PLT without mark-plt tags; `.plt.sec` with endbr64; `-fno-plt call [GOT]`; a wrong slot; a bad
   dynsym index.
6. Register walk: a branch into the call row; a computed-jump label (premise only); an address gap; a non-contiguous
   predecessor; the `mov r9d` zext pair; an `mov cl` partial kill; `xor r,r`; flags not listed.
7. Several STOREs in one row (positive and unresolved); another space; a store crossing a region end; a concrete
   address outside the regions (examined non-match).
8. Survey: digest tampering is rejected; an empty scope; A64 unsupported; run coverage absent; expansion round trip;
   canonical order stable under input reordering.

## 10. Port notes

- Pure functions over values: `regions(file_image, windows)`, `import_names(file_image)`, `trap_site(window, ballot)`,
  `block_constants(rows, predecessor_index, incoming_edges, index_complete)`, `sites(...)`, `survey(...)`.
- File parsing takes no Bundle state.
- Reason codes, the name table and the survey representation are data.
