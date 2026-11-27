# X-1 implementation plan r3 -- producer evidence for S3 (2026-11-27)

This is a delta on `design_x1_r2.md`, which stays the base text. r3 replaces part 4 and amends parts 1 and 5.
r2 reviews:
- Astra `x1_astra2.md`: REJECT (3 P1, 3 P2). The X-1a / X-1b split and the legacy encoding are accepted.
- Fable `x1_fable2.md`: APPROVE WITH FIXES (1 P1, 3 P2, 4 P3). Parts 1-3 and 5 can go to code.

Tags below: [A2-n] = Astra r2 item n, [F2-...] = Fable r2.

## Part 1 amendment -- one atomic producer profile [A2-5, F2-P3-2]

- The three capabilities of r2 become one atomic profile: `producer_profile: "x1-producer-v1"`.
- A Bundle that declares it carries all of the following:
  - the `override` object and `exceptional_targets` on every instruction row;
  - a sealed `stack_switch_evidence` member whose role is checked at normal admission.
- Anything less is an admission defect with its own reason: a missing row object, a missing or unsealed member, or a
  member with a wrong role. It is never read as "legacy" or "no evidence".
- No other subset is defined. A Bundle without the profile is legacy and is encoded exactly as today (r2 part 1).
- Tests:
  - reseal with only one row object missing;
  - with `exceptional_targets` missing on one row;
  - with the profile declared but no evidence member;
  - with an evidence member whose role is wrong.

  Each gives the defect with its own reason.

## Part 4 (replaces r2 part 4) -- stack-switch evidence

### 4.1 One scanner routine, called on the locked program [A2-3]

- `runScript` cannot run under the exporter's publish lock (`GhidraV2BundleExport.java:240`): a child script starts a
  transaction, and the lock rejects it.
- The scan logic moves into a plain read-only class, `GhidraV2StackSwitchScanner` (same script directory, same
  bundle). It takes a `Program`, a policy set and a monitor, and returns the evidence object. It opens no
  transaction.
- `GhidraV2StackSwitchScan.java` becomes a thin wrapper for standalone runs.
- The exporter calls the routine directly on the locked `Program` inside `publish`, after the observations are
  collected and before sealing.
- A scan failure fails the export.
- Test: a real headless export through `tools/bundle_export/export_bundle.py` (the harness
  `test_gt_b7b_exception_handlers.py` already uses) publishes, reopens, and admits the sealed evidence. The fixture
  carries an actual length override and an exceptional-target row.

### 4.2 Binding: three digests, two of them verifiable by TDO [F2-P2-2, A2-2]

The exporter computes the listing digest at three points and fails the export unless all three are equal:
1. when the observations are collected;
2. inside the scan;
3. just before sealing.

The digest is split in two:
- **(a) TDO-verifiable part:**
  - each exported function's instruction rows (address, length, bytes from the sealed `original` mapping, the three
    override facts);
  - every initialized block's bytes.

  TDO recomputes (a) at admission, and a mismatch is an admission defect.
- **(b) The rest:**
  - instructions outside the exported functions;
  - Ghidra's analysis state the scan read.

  (b) is an exporter attestation under the named premise `producer-program-facts-accurate`, whose registry sentence
  says so.

### 4.3 Classification by bytes, prefixes included [A2-4, F2-P1-1, F2-P2-3]

The scanner decodes the bytes at every listed instruction start, in functions and outside them.

| bytes (no prefix) | form | class |
|---|---|---|
| `0F 05` | syscall | `covered` |
| `CD 2E` | int 2e | `covered` |
| `CC`, `CD 03` | int3 | `trap`, vector 3 |
| `CD 29` | int 29h (fast fail) | `trap`, vector 0x29 |
| `0F 0B` | ud2 | `trap`, vector `ud` |
| `F1`, `CE`, other `CD xx` | int1 / into / int xx | `uncovered` |
| `0F 34`, `0F 07`, `0F 35` | sysenter / sysret / sysexit | `uncovered` |
| `F4`, `0F 01 C1`, `0F 01 D9` | hlt / vmcall / vmmcall | `uncovered` |

- Any legacy prefix (`66 67 F0 F2 F3 2E 36 3E 26 64 65`) or REX byte (`40`-`4F`) before one of these opcodes, in any
  mix, is `undecidable`, and so are bytes that cannot be read.
- Every row of these classes goes into `kernel_transfers` with:
  - address, bytes, class and vector;
  - whether it is inside an exported function;
  - the lift summary: CALLOTHER name and constant inputs, or "empty" / "contradictory".

### 4.4 The two verdicts [A2-1, A2-4, F2-P1-1, F2-P2-1]

**`s3-off`:** today's v4 rule, byte for byte. Trap rows continue as today.

**`s3-on`:** the same detector with these changes.

1. **Entry seeding.** At every function entry, and at every non-entry seed, every register **and every unique
   location** reads as UNKNOWN unless written first. `initialState(true)` today leaves registers at 0 at a function
   entry (`:221`), and `readLocation` applies UNKNOWN only in register space (`:280`); s3-on extends both. So a
   helper reached by a tail after a syscall, through any number of wrappers and anywhere in the program, cannot
   accept `add rsp,rbx`: the first read is UNKNOWN in the helper itself [A2-1]. First reads and partial aliases follow
   the existing overlap rules in both spaces.
2. **`covered` rows.** The row's p-code must not read or write the stack pointer. The SP identity comes from the
   program's stack pointer register (the scanner's `sp`), which the Bundle's sealed register table also records.
   Otherwise the row is UNCHECKED, and so is a row with no SP identity.

   No SP operand is required: a bare CALLOTHER has constant inputs, and the paired CALLIND consumes a UNIQUE
   [A2-4, F2-P2-1]. After the row only the stack pointer keeps its coefficient, and everything else becomes UNKNOWN.

   An empty or contradictory lift is UNCHECKED: no CALLOTHER, or a lift whose shape does not match the bytes per the
   S3 r16 shape checks.
3. **`trap` rows.** The path ends at the row, with no successor state. This is what the scan assumes when the run's
   trap premise holds for that vector:
   - `debug-break-traps-do-not-return` for 3 and 0x29;
   - the F1 fault premise for `ud`.

   The scanner records the trap rows; it does not decide the premise.
4. **`uncovered` and `undecidable` rows:** UNCHECKED (a possible switch).
5. Images S3 does not apply to (not x86-64 PE) record `s3-on: not-applicable`. Their consumers use `s3-off`
   [F2-P2-3].

**What a clean s3-on verdict certifies.** Clean if all of the following hold:
- every `covered` row is an admitted S3 site of the run;
- every `trap` row's vector is covered by a trap premise the run holds.

Otherwise the verdict is withdrawn. This is the consumer rule, implemented in `authority` (4.5) with admission
supplied by S3. Test: a function ending `call f; int3` is clean under the trap premise and withdrawn without it
[F2-P1-1].

### 4.5 One authority check, including caches and templates [A2-2, F2-P2-2 r1, F2-P3-1]

```
authority(evidence_or_template, *, policy, bundle=None, admitted=None, trap_premises=())
    -> (allowed, reasons)
```

This is the only reader: `.clean` is removed. Callers:
- `assumption_allowed`;
- refused-member coverage (`summary_engine.py:515`);
- linking (`linking.py:365`, and the cache path at `:406`);
- derivation;
- direct template application (`summary_store.py:709` area).

Rules:
- **`s3-off`:** v1 / v2 as today.
- **`s3-on`:**
  - only Bundle-sealed v2 evidence whose seal matches a verified Bundle;
  - plus `admitted` covering every `covered` row and `trap_premises` covering every `trap` row;
  - otherwise withdrawn with the reason.
- **Templates (derived summaries):**
  - Templates record what they were derived under: the evidence digest, policy, seal id and the coverage decision
    (admitted sites and trap premises). `producer` stays optional for old s3-off templates only.
  - An s3-on consumer accepts a template only with all four present. It first resolves and verifies the library's
    Bundle seal, so a warm cache hit no longer skips the seal check: under s3-on, the library Bundle is opened before
    the lookup at `:406`.
  - The cache key adds the seal id, evidence digest, policy and coverage decision.
  - Missing authority withdraws the assumption for that template's dependent facts.
- In X-1a every caller passes `s3-off`. The s3-on paths are implemented and tested now, with `admitted` supplied by
  test fixtures, and S3 supplies the real admission.

Tests [A2-2]:
- warm the linker cache, change the prepared listing under the same DLL hash, and re-export: s3-on withdraws through
  both linking and direct template loading;
- vary the coverage decision with the seal fixed: a distinct cache entry, and withdrawal when not covered;
- v1 evidence and an OFF-clean / ON-dirty v2 file through refused-member coverage, linking, derivation and the
  summary store.

### 4.6 Scanner tests [A2-1, A2-4, F2-P1-1, F2-P2-3, F2-P3-3 r1]

Java scanner on recorded fixtures plus a headless export.

- Unprefixed `0F 05` and `CD 2E`, both conditionally clean (positive cases).
- REX + `0F 05`, a mixed REX / legacy prefix, and an undecidable prefix: UNCHECKED.
- An empty lift and a contradictory lift at `0F 05`: UNCHECKED.
- `mov rbx,rsp; syscall; mov rsp,rbx`: s3-on switch.
- syscall, then a tail through one and through two wrappers into a helper whose first instruction is
  `add rsp,rbx`, with the helper inside and outside the exported closure: s3-on switch in the helper. s3-off is
  unchanged.
- `int 29h`, `int3` and `ud2` rows: recorded as `trap` with their vectors.
- `int 80h` and `sysenter`: UNCHECKED.
- `cpuid`: clean under both.
- A kernel transfer outside every function.
- Every case: s3-off equals v4 byte for byte (the switch lists are compared).

### 4.7 Versions

- Evidence format version 2, detector `stack-switch-coefficient-v5`.
- Both verdicts and the per-policy exception lists are stored. Under s3-on, `stack-switch-check-exceptions` still
  covers non-kernel CALLOTHERs (r2 F-P3-2).
- The UE template names v3 evidence (`ue_core_win64_fstring.json:65`). Until X-1b re-derives it, an s3-on run cannot
  use it under 4.5. The S3 plan records this dependency, so "S3 ON by default" is not measured with a template that
  is silently dropped [F2-P3-4].

## Part 5 amendment -- X-1b inventory and paired comparison [A2-6, F2-P3-3]

- The inventory checks each image against its **actual machine**: x86-64, Win32 / x86 and others in
  `snapshot_expected.txt`. RSP and the s3-on verdict are required only where S3 applies.
- It records the Ghidra release separately from the language id / version, and the **per-function S1 status**. A
  fresh export may withhold S1 for a function (`GhidraV2BundleExport.java:1502`), and that is recorded, not failed.
- Each old / new pair is pinned to the same original executable SHA-256. A swapped original fails.
- The paired comparison generates both sides' support and premise-use records explicitly, because
  `semantic_snapshot.py` omits `premise_uses` / `supports` (`:60`, `:83`).
- The DF identity moving from the inferred certificate to the table row is a provenance difference only. The paired
  comparison must show identical rep-site decisions [F2-P3-3].
- Tests:
  - a genuine Win32 control and a mixed-S1 image pass;
  - a swapped original fails;
  - a change in premise use only fails.

## Order (unchanged)

X-1a: part 1 decision -> part 3 -> part 2 -> part 4. Each part: focused tests + mutants, then the full suite. One
full gate vs `ped6`, then the code review, then the owner's merge OK. After that, X-1b.
