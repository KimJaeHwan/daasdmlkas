# X-1 implementation plan r4 -- producer evidence for S3 (2026-11-27)

Delta on `design_x1_r3.md` (which amends `design_x1_r2.md`). r4.1: item 4.4-4 restored to UNKNOWN at call entries (Astra r4 P1, the only open item; Astra r4 confirmed A3-2..A3-8). r3 reviews:
- Astra `x1_astra3.md`: the COMPLETE list (4 P1, 4 P2), ending "With these changes: APPROVE";
- Fable `x1_fable3.md`: APPROVE WITH FIXES (3 P2, 4 P3).

Tags: [A3-n] Astra item n, [F3-...] Fable. Where the two differ (UD2), Astra's rule is taken, per the owner's
process, and Fable's cost concern becomes a measured acceptance item (4.8).

## 4.3 amendment -- byte reading and applicability [A3-5, F3-P3-2]

- **Applicability.** It uses the existing sealed predicate from `design_s3_r16.md:22` (PE32+, AMD64, and an allowed
  subsystem). `s3-on: not-applicable` is recorded only for an affirmatively inapplicable image. An image whose
  applicability cannot be decided is UNCHECKED under s3-on, and S3 is "not evaluated" for it, in r16's words (the
  consumer cannot fall back to s3-off there either; Fable r4 P3-3).
- **RSP identity.** On applicable images, the compiler-spec stack pointer coordinate and width must equal the unique
  sealed eight-byte RSP of the register table, with overlapping aliases checked. A mismatch makes the whole s3-on
  verdict UNCHECKED.
- **Classification bytes.**
  - Classification reads from each listed instruction start independently of the declared row length.
  - It stops at a decisive mismatch, at a gap in initialized bytes, or at the 15-byte instruction limit.
  - A row whose declared length disagrees with the classified form is UNCHECKED: for example a falsely short
    syscall row, or a syscall form that extends into the next row.
  - A form cut off by a gap is `undecidable`.
- **Trap vectors.** The vector is recorded twice: from the bytes, and from the lifting's constant operand. If the
  two disagree, the row is `undecidable` [F3-P3-2].
- Tests:
  - an excluded AMD64 PE subsystem;
  - a mismatched SP coordinate;
  - a falsely short syscall row;
  - a final-byte NOP after `0F 05`;
  - a truncated prefix at a gap;
  - `CD 03` vs `CC`, each with a matching and a contradictory lift.

## 4.4 amendment -- cross-region destinations and traps

**Cross-region destinations [A3-1, F3-P2-3].** r3's "UNKNOWN at every function entry" is kept, and extended by
"UNKNOWN at every possible cross-region destination, including mid-body" (r4.1: the narrowing to call-only entries
in item 4 was withdrawn after Astra r4).

1. Under s3-on the scanner collects, program-wide, every non-call transfer whose destination lies outside the
   source region (the function body, or the outside-functions region): direct jumps, tails, listed indirect
   targets, and fallthrough exits.
2. At each destination row it merges a state in which every register and every unique location is UNKNOWN and only
   the stack pointer keeps coefficient 1. This holds whether the destination is a function entry or the middle of
   an already-scanned body: the merge re-enters the worklist, so a row reached from the helper's normal entry is
   re-decided.
3. A transfer whose destination set cannot be bounded (a BRANCHIND with no listed targets, an unresolved computed
   jump) is UNCHECKED. (r4.1, Fable r4 P2-2) An indirect jump whose only destinations are imports or other
   addresses outside the program (a thunk's `jmp [__imp_X]`) is bounded: there is no destination row to seed. A
   truly unbounded jump stays UNCHECKED. 4.8 cause 5 also reports, separately, the verdict under the fallback "merge
   at every instruction start", so the owner can choose between the two from numbers.
4. (r4.1, Astra r4) Entries reached only by calls also read every register and unique location as UNKNOWN under
   s3-on (the r3 rule). The v4 reading is unsound here: a caller passing its RSP in RCX gives `sub rsp,rcx` a
   coefficient of 0 (a switch), while the v4 entry seed computes 1 and accepts it. The cost is measured in 4.8,
   cause 1. Test: `lea rcx,[rsp]; call f` with `f: sub rsp,rcx` -> s3-on switch; s3-off as v4.
5. Post-kernel-transfer state inside one region stays as in r3: only the stack pointer is kept.
6. (r4.1, Fable r4 P2-1) Under s3-off the v4 entry reading stays, and is named: the `stack-switch-check-exceptions`
   registry sentence and the v5 evidence file's s3-off exception list add "an entry register holds no
   stack-derived value". Its failure mode is a caller passing a stack-relative delta that the callee adds to the
   stack pointer. If the registry sentence enters snapshots, the line is recorded in the docs and the evidence file
   only, keeping the `ped6` compare strict.

Tests:
- the helper's normal entry clears RBX before `add rsp,rbx`, and a post-syscall tail lands directly on the `add`,
  directly and through an unresolved tail -> s3-on withdrawal, with the helper inside and outside the export
  closure;
- s3-off equals v4 in every case.

**Traps are decided per site, by the run [A3-2, F3-P2-1, F3-P3-1, F3-P3-3].**
- The scanner records each `trap` row; it does not end the path itself:
  - its successor state under s3-on is "path ended at this row";
  - the next listed instruction is scanned as its own seed, with the s3-on seed state [F3-P3-1].
- `authority` receives `trap_decisions`: a set of seal- and site-qualified decisions [F3-P3-3]. A trap row counts as
  resolved only with a matching decision:
  - **Debug traps inside the analysed closure:** the run's own decision that the site was cut as a dead trap under
    `debug-break-traps-do-not-return`, with the active pcodeop model and lifting.
  - **Debug traps outside the closure:** affirmative evidence of the matching lift, model and enabled premise for
    that row. The evidence comes from the scanner's recorded lift summary for the row (its CALLOTHER and constant
    vector), together with the run's switch vector and its pcodeop model. The run has no observation of that row
    (Fable r4 P3-2).
  - **UD2:** an F1 discharge valid for the consuming analysis. A revoked or hazardous site has none.
- An unresolved trap row withdraws the s3-on verdict.
- Decisions enter every reuse check (templates and caches, 4.5).
- Tests:
  - two UD2 sites under identical switches, one discharged and one hazardous or later revoked -> withdrawn;
  - `CC` with a contradictory lift -> withdrawn;
  - `CC` with its trap model disabled -> withdrawn;
  - a function ending `call f; int3` that the run cut -> resolved.

## 4.2 amendment -- the verifiable digest [A3-3]

- The exporter passes the scanner the exact exported map: function entry -> rows, including rows added by
  exception-region expansion (`GhidraV2BundleExport.java:1252`).
- There is one canonical digest, the **verifiable part**, over:
  - those coordinates, lengths and override facts;
  - the loaded bytes read from the sealed block members (`:798`). Bytes unavailable there are encoded explicitly as
    unavailable.
- The original image is pinned separately (its sealed SHA-256).
- Everything else the scan read goes into the **attested part**: rows outside the export, and analysis state.
- Both parts are compared at all three checkpoints (collection, scan, before sealing).
- TDO recomputes the verifiable part from the sealed members at admission.
- Tests:
  - same original SHA, one patched loaded opcode -> a different verifiable part;
  - two different closures of one program, including an exception-expanded row -> Java and TDO agree on each;
  - substituting earlier evidence, or changing one checkpoint's input -> failure.

## 4.5 amendment -- authority covers the whole run [A3-4, A3-6]

1. **Every image.** For an applicable s3-on run, an authority result is resolved for the main image **and every
   participating linked image** before any dependent fact is derived or reused.
2. **No evidence is a failure.** An image with no evidence object (no scan, or a failed library scan, today `None`
   at `linking.py:465`) is a failure with its reason. An empty evidence list no longer passes (`summary_engine.py:517`).
3. **Aggregation.** Failures are aggregated per run: any failure withdraws `globals-disjoint-from-stack` for the
   main image and for every sibling fact that depends on it.
4. **Template application.** The shared template application check (`summary_templates.py:873`) compares the
   verified manifest digest, evidence digest, effective policy, and current site coverage (admitted sites and trap
   decisions) with the template's record.
5. **One library Bundle.** One verified library Bundle object is used for both the cache lookup and the derivation.
6. **The override premise is conditional** [A3-6]. `producer-override-report` is registered as a conditional premise.
   It is reported only when a consumer relies on the profile's override claim, so legacy Bundles keep their exact
   `base_premises` (`assumptions.py:474`, `semantic_snapshot.py:347` / `:364`).

Tests:
- [A3-4] a clean main image and two DLLs; one DLL unavailable, then dirty -> main and sibling dependent facts lose
  disjointness, cold and warm. Direct template application rejects stale authority, and an unchanged verified
  Bundle still permits a warm hit.
- [A3-6] a legacy Bundle keeps its exact `base_premises` and its strict `ped6` snapshot in both engine modes, and an
  applicable use reports the new premise.

## 4.7 amendment -- UE template migration [A3-7]

- X-1b measures the shipped v3 evidence against the v5 s3-off verdict for the UE image separately (r2 4.5,
  reinstated), and records both switch lists and the template decisions.
- X-1b re-derives the UE template under s3-off only.
- An s3-on-eligible template needs a later derivation with real S3 coverage (S3 step). "S3 ON by default" is
  measured only after that template is actually applied at the UE import.
- Tests:
  - the s3-off template is rejected under s3-on;
  - an eligible s3-on-derived template is applied at the UE import (S3 step; X-1b records the dependency).

## 4.8 X-1a acceptance -- measure the s3-on verdict [A3-8, F3-P2-3, F3-P2-2 concern]

Before S3, run the scanner alone on every gate image and ntdll. Report:
- the s3-off result vs v4 (must be identical);
- the s3-on verdict, with switch rows by cause:
  1. cross-region seeding (entry or mid-body);
  2. kernel rows (uncovered / undecidable);
  3. covered rows needing admission;
  4. unresolved traps, split by `CC` / `CD 03` / `CD 29` / `UD2`;
  5. unbounded transfers, with the verdict under the "merge at every instruction start" fallback reported alongside;
  6. none, conditionally clean: the number of covered rows and trap rows the verdict depends on, i.e. what S3 still
     has to admit (Fable r4 P3-1).

UD2 follows Astra's rule (an F1 discharge or withdrawal). If cause 4 alone withdraws the verdict on ordinary
binaries (Fable r3 P2-2), the count goes to the owner as a decision before S3: whether to keep the F1 requirement or
give UD2 a fault class under a named premise.

Tests:
- a frame-pointer save / restore stays clean;
- an adjustment from an unwritten register at a cross-region destination is reported;
- an adjustment from a freshly established constant stays clean.

## Part 5 amendment [F3-P3-4]

The X-1b report counts, per Bundle, the functions with a `covered` row but no S1 status: those are the functions S3
will refuse.

## Order (unchanged)

X-1a: part 1 decision -> part 3 -> part 2 -> part 4 (including the 4.8 measurement). One full gate vs `ped6`, the
code review, then the owner's merge OK. Then X-1b.
