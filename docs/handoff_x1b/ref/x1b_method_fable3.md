# Design review round 3 (closing): X-1b paired-comparison method delta r3 -- Fable 5.2 (2026-11-27)

Scope: `design_x1b_method_r3.md` against `design_x1b_method_r2.md`, Astra's round-2 list
(`x1b_method_astra2.md`, 7 items) and my round 2 (`x1b_method_fable2.md`). Read-only; I ran nothing and read no
code this round.

**Verdict: APPROVE -- no P1, no P2.** The fold is faithful: every Astra item and every item of mine is
answered, and I found no contradiction with r2. Three P3 clarifications, none blocking.

---

## 1. Item check

| item | answered in | state |
|---|---|---|
| A2-1 verification separate from strict comparison; ped6 reads old snapshots | B | Answered. A verified pair compares all sections strictly; the ordinary guard stays; a plain `dump` writes today's document, so the `ped6` gate is untouched. |
| A2-2 stage 0 bound to the published bytes | A | Answered. One export; raw verification of sizes, hashes, seal, receipt and transport references; comparison copy derived from the published Bundle; canonical JSON plus resolved bindings. |
| A2-3 decisions lost by the snapshot encoding | C | Answered. A `decisions` section taken from the engine objects (full verdict enums, control sites, run-level records, supports, premise uses); digest erasure limited to named paths, semantic pins compared; the verdict-only mutant and the renumbering control. |
| A2-4 control for an accepted S1 difference | D | Answered, all four parts: row-level evidence tied to the analyzer option, everything else still equal, groups against the stripped control, old against published for the cut, oracle on every stage-1 comparison. |
| A2-5 decidable interaction rule | E | Answered. Differences in either direction between the full delta and the union are listed and need an explanation; `len` and DF / rep equality unconditional. |
| A2-6 inventory for prepared projects | G | Answered. Attestation applicability per function, both failure directions, the three inventory tests restored. |
| A2-7 UE migration in the cut | H | Answered. v3 against v5 `s3-off` switch lists with template decisions, the template re-derived under `s3-off`, both in the report and the checklist. |
| F2-P2-1 published and compared Bundles tied together | A | Answered with the option I preferred (derive the copy from the published Bundle); the rule is recorded in `x1b_pairs.json`. |
| F2-P3-1 which side stage 1 compares against | D | Answered: the stripped control per group, old against published for the cut. |
| F2-P3-2 ambiguous coordinates | F | Answered: the pair stops, a finer coordinate is decided in review. |
| F2-P3-3 interaction wording | E | Answered. |

## 2. Consistency with r2

No contradiction found. The three places where r3 replaces r2 are marked and consistent with what remains:

* r2 section 5 step 2 ("replay twice") is replaced by one export; r2 section 4 (replay verifies every expected
  pair) and r2 section 1 (disposable copies, isolated caches, the receipt test) still apply to it.
* r2's manifest-guard bullet is replaced by B. Because published Bundles have fresh ids, the existing
  generation guard keeps protecting the new baseline even though a plain `dump` records no manifest digest.
* r2's interaction bullet is replaced by E; r2 section 3's group list and projection rules stand, with the
  comparison side fixed by D.

## 3. P3

* P3-1. Three similar names now exist: `compare --pair <entry>` (verify inputs, then strict), `compare --paired`
  (the coordinate projection, r2) and `dump --paired-sections`. State in the tool's help that the projection
  mode also verifies both inputs against the pair record, as the strict mode does; r3 says it only for the
  strict path.
* P3-2. The derived comparison copy is tied to the published Bundle by construction. A cheap post-check makes it
  verified rather than trusted: published against derived, member by member, must differ only in the declared
  generation-id fields and the digests bound to them.
* P3-3. The old side of every comparison needs a fresh dump with `--paired-sections` from the X-1b tree (the
  stored `ped6` snapshots have no `decisions` section). That follows from C; one line in the order of work
  avoids someone comparing against a stored snapshot.

Verdict: **APPROVE.** The method is closed from my side.
