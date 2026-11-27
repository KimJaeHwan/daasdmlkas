# Design review round 2: X-1b paired-comparison method delta r2 -- Fable 5.2 (2026-11-27)

Scope: `design_x1b_method_r2.md` against my round 1 (`x1b_method_fable1.md`) and Astra's round 1
(`x1b_method_astra1.md`). Read-only; I ran nothing and did not re-read the tools (r2 describes changes to them
that are not written yet).

**Verdict: APPROVE WITH FIXES -- no P1, one P2.** All four of my P2s and the six P3s are answered, and Astra's
additions are compatible with mine. The one new gap comes from the fresh generation ids: the Bundle that is
published is no longer the Bundle that stage 0 proved.

---

## 1. Round-1 items

| item | state |
|---|---|
| F-P2-1 member-by-member stage 0 | Closed (section 2 step 4): canonical JSON, binary by hash, manifest structure, instruction and p-code order; the only allowed difference is listed. |
| F-P2-2 references resolved to coordinates | Closed (section 3): definitions, storage objects and dependency nodes resolve to coordinates; edges as a multiset with endpoints; debts, proofs and refusals keyed by site; the erased fields are listed with reasons; ambiguity is an error. |
| F-P2-3 comparator tests | Closed: part 5's and r3's cases, my two (moved debt, re-pointed dependency) and the strip-all positive control. |
| F-P2-4 generation id | Closed by Astra's stricter rule (fresh ids for published Bundles, old id in disposable copies, isolated caches) plus the manifest digest in the snapshot guard. It creates P2-1 below. |
| F-P3s | Part-5 lines restated (section 0); the S1 rule for stage 0 is the one I suggested, with rep-site decisions still identical; interaction rule stated; the four kinds have a replay path; byte replacement removed; `len` expectation kept. |

Where Astra and I differed (I preferred keeping the id with a guard, Astra wanted fresh ids for anything
published), r2 takes Astra's rule. I agree with that, given P2-1.

## 2. Finding

### P2

**P2-1. The published Bundle and the compared Bundle are two separate exports; nothing ties them together.**
Section 5 step 2 replays every kind twice: once with the old id (the comparison copy) and once with a fresh id
(the published Bundle). Stage 0 -- pin, strip, member comparison, engine check -- is described for the
comparison copy. The published Bundle enters only at the end of stage 1, through the coordinate projection. So
the "same program" proof is about an export that is then deleted, and the baseline is cut from a different
Ghidra run whose members were never compared with anything.
Fix, either of:
* apply stage 0 steps 1 to 4 (pin, strip relative to the old input, member-by-member comparison) to the
  **published** Bundle as well, with the generation id and the fields derived from it as one more listed
  allowed difference. Only step 5, the strict engine check, needs the old id;
* or export once, and make the comparison copy from the published Bundle by rewriting the generation id in its
  declared places with the same declared-field re-binding as the stripper. Then both are one export by
  construction, and the replay runs once per pair.
I prefer the second if the id sits only in declared fields: it halves the Ghidra time and removes the question.
Either way, `x1b_pairs.json` should record which rule tied the two together.

### P3

* P3-1. Say which side stage 1 compares against. When stage 0 is identical it does not matter; when stage 0 has
  an accepted S1 difference, a group copy compared with the old Bundle shows that difference again in every
  group. Comparing each group against the strip-all copy isolates the group's own effect; the full Bundle is
  then compared against the old one.
* P3-2. "An ambiguous coordinate mapping is an error" is the right default. If real Bundles turn out to have two
  definitions with one coordinate (same site, storage and span), the answer is a finer coordinate decided in
  review, not a silent merge; one sentence saying so avoids an improvised fix during the run.
* P3-3. The interaction rule says the full Bundle's differences "must be" the union of the single-group ones and
  then that an extra one is "listed and explained". Read together that is fine; state it once: an extra
  difference is an interaction, blocks until explained.

## 3. Summary

| | count | items |
|---|---|---|
| P1 | 0 | -- |
| P2 | 1 | the published Bundle is a second export never tied to the one stage 0 proved -- run the member comparison on it, or derive the comparison copy from it |
| P3 | 3 | which side stage 1 compares against; what happens on a real ambiguous coordinate; wording of the interaction rule |

Verdict: **APPROVE WITH FIXES.**
