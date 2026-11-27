# Design review: X-1b paired-comparison method delta r1 -- Fable 5.2 (2026-11-27)

Scope: `design_x1b_method_r1.md` against part 5 of `design_x1_r2.md` and the part-5 amendments in
`design_x1_r3.md` / `design_x1_r4.md`; I read `x1b_strip.py` and `x1b_reexport.py`. Read-only; I ran nothing
and did not reproduce the trial. I did not check how the engine's caches and snapshot files are keyed (see
P2-4). Producer trust is out of scope and not raised.

**Verdict: APPROVE WITH FIXES -- no P1, four P2.** The two-stage idea is right: the allowlist comparison of
part 5 cannot work once identities depend on content, and "strip to the old shape, compare strictly, add the
groups back" is the correct replacement. The fixes make stage 0 a proof about the Bundle rather than about the
engine's output, pin down what the stage-1 projection must keep, and bound the reuse of the generation id.

---

## 1. The four questions

**Is stage 0 a sound proof of "same program"?** Not quite as written. A strictly identical snapshot proves that
the engine *computed* the same results from the stripped Bundle. It does not prove the Bundles are the same:
whatever the gate roots do not reach, and whatever the engine does not read, is not compared. Stage 0 should
compare the Bundles directly (P2-1); the snapshot comparison then stays as the second check.

**Is the stage-1 projection complete enough?** The list of things is complete against part 5. The way three of
them are reduced is too lossy (P2-2), and the part-5 tests of the comparison itself are not restated for the
projection (P2-3).

**Is anything from part 5 lost?** Three things are not restated and should be, in one line each (P3-1): the
strict same-generation gate stays; stage 1 runs in both profiles (the text says so only for stage 0); TBR is
told and checks one Bundle of each kind before the run. The r3 / r4 amendments (per-function S1 status, pair
pinned to the same original SHA-256, identical rep-site decisions, count of covered-row functions without S1)
are covered by "the inventory ... and tests stay", which I read as including them.

**Is reusing the old generation id in a new root safe?** For the scratch comparisons, yes. For the permanent
baseline it needs one check and one guard (P2-4).

## 2. Findings

### P2

**P2-1. Stage 0 should compare the stripped Bundle with the old Bundle member by member.**
After the strip, every observation, the program member, the blocks and the original of the new Bundle should
equal the old Bundle's: JSON members by canonical form (sorted keys, since `x1b_strip.py` rewrites with compact
separators), binary members by hash. This is the direct statement of "the producer added facts and changed
nothing else", it is cheaper than a gate run, and it covers every function, not only what the gate analyses.
It also catches what the strict snapshot cannot: a seventh addition nobody listed (the strip removes only the
six known groups, so an unknown new field would survive and show up here), and a changed value in a field the
engine does not read. Keep the strict snapshot comparison and the oracle as the second check.

**P2-2. The projection must resolve references to coordinates, not erase them.**
As written, three reductions lose the decisions part 5 asked to compare directly:
* "debts (kind and count)": a debt that moves from one site to another keeps kind and count. Key each debt by
  kind and its site and storage coordinates.
* "edges by kind": compare the multiset of (kind, source coordinate, destination coordinate), where a
  coordinate is function entry plus instruction address and ordinal.
* "digests replaced by the function entry / space name": values and proven effects contain identity atoms and
  index references (`definition_ids`, dependency node numbers). Each must be replaced by the coordinate of the
  thing it refers to. If a reference is dropped instead, two different dependency structures compare equal.
The delta should list every field the projection erases outright, with the reason it is identity-only. Anything
not on that list is compared.

**P2-3. Keep part 5's tests of the comparison, applied to the projection.**
Part 5 required: a generation-only change passes; a changed debt, support, proof, edge, refusal, completeness
or oracle result fails; r3 added that a change in premise use only fails. The projection is a new comparator
and needs the same, plus two that are specific to it: a debt moved to another site with the count unchanged
fails, and a dependency re-pointed to another definition with values unchanged fails. One positive control is
free: old versus strip-all must be projection-identical, since it is strictly identical.

**P2-4. Reusing the generation id: check what is keyed by it, and record the seal in the snapshot.**
After X-1b there are several different Bundles with one generation id: the old one, the stripped copies, the
group copies and the new baseline. That is safe only if nothing treats the id as the content's identity.
* Before the run, check every cache and stored artefact that is keyed by generation id without the manifest
  digest (template cache, summary cache, receipts, snapshot files). I did not check this. Run the stripped and
  group copies with cold caches or separate cache roots regardless.
* `semantic_snapshot.py` stops on a changed generation today; that guard is what part 5 relied on to keep an
  old baseline from being compared with new Bundles. With the id reused it no longer fires. Record the
  manifest SHA-256 in the snapshot header and make the strict compare stop on it (the paired mode overrides
  it explicitly). Without this, a later gate run against `ped6` by mistake compares silently.
If either point is awkward, the alternative is to keep the old id for stages 0 and 1 only and give the baseline
Bundles fresh ids; but that is a second export, which then needs its own equality check against the compared
one, so I prefer the guard.

### P3

* P3-1. Restate the three part-5 lines named in section 1 (strict same-generation gate; both profiles in stage
  1; TBR notified with a decode check per kind).
* P3-2. Stage 0 says any difference blocks the baseline. The old Bundles predate S1, and S1 changed the
  exporter's analysis options, not only added a field. If a Bundle's listing differs for that reason, stage 0
  will fail on it legitimately. Decide now what happens then: I suggest the difference is listed per function
  with its cause and reviewed, as in stage 1, instead of being forced to zero. The trial Bundle being identical
  does not settle this for the other twenty.
* P3-3. Interactions: groups are added one at a time and then all together. State the rule that a difference in
  "all" which appears in no single group must be explained as an interaction, or it blocks.
* P3-4. `x1b_reexport.py` replays only `-import` exports found under `tdo_bundles3`. Part 5 also names the
  ntdll closure, the field cases with system calls and the UE template producer Bundle. Say how each of those
  is re-exported and paired, or that they get the inventory only.
* P3-5. `x1b_strip.py` rebinds digests by replacing the hex text in every other member, binary ones included.
  Acceptable for a comparison tool because a wrong rebind fails admission visibly; restricting it to JSON
  members would remove the theoretical false replacement.
* P3-6. "`len` must be projection-identical" is a strong claim for a field the engine now reads. Keeping it as a
  blocking expectation is the conservative choice and I agree; just be ready for a listed cause there.

## 3. Summary

| | count | items |
|---|---|---|
| P1 | 0 | -- |
| P2 | 4 | stage 0 compares Bundle members directly; projection resolves references to coordinates and lists what it erases; part-5 comparator tests applied to the projection; generation-id reuse needs a keying check and the manifest digest in the snapshot guard |
| P3 | 6 | restate three part-5 lines; rule for S1-caused listing differences in stage 0; interaction rule; the non-gate Bundle kinds; rebind by text replacement; `len` expectation |

Verdict: **APPROVE WITH FIXES.**
