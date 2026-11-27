# X-1b paired comparison -- method delta r3 (2026-11-27, closing)

r2 (`design_x1b_method_r2.md`) + Astra round 2 complete list (`x1b_method_astra2.md`: 3 P1 + 4 P2, "With these
changes: APPROVE") + Fable round 2 (`x1b_method_fable2.md`: APPROVE WITH FIXES, 1 P2 + 3 P3). r3 = r2 with the
changes below; where r3 and r2 differ, r3 holds. Tags [A2-n] Astra round-2 item n, [F2-..] Fable round 2.

## A. One export per pair; the comparison copy derives from the published Bundle [A2-2, F2-P2-1]

Replaces r2 section 1 first bullet and section 5 step 2 ("replay twice").
- Each pair is exported **once**, with a fresh generation id, into `/root/tdo_bundles4` (the published Bundle).
- Before anything else, the published Bundle is verified raw: every member's size and SHA-256 against the
  manifest, the manifest against the seal, the receipt, and every transport reference (observation digests in the
  sidecars, program / call-interface-profile digests in the transports) resolved to the member it names.
- The comparison copy (old generation id) is **derived from the published Bundle** by rewriting the generation id
  in its declared places only (manifest `generation_id`, the transports' `generation_id`, the seal) and resealing;
  if the published generation id occurs anywhere else in any member, the derivation fails. `x1b_pairs.json` records
  the rule ("derived-from-published") and both seals.
- The member comparison of stage 0 (r2 2.4) compares canonical JSON **and resolved bindings** (a transport digest
  is compared as "names the member whose canonical content is X"), so a serialization change or the listed
  exporter class-hash change can propagate through digests without masking a payload change.

## B. Verified-pair strict comparison; the ped6 gate unchanged [A2-1]

Replaces r2 section 1's manifest-guard bullet.
- `semantic_snapshot.py compare --pair <x1b_pairs.json entry>`: each side's snapshot meta (manifest SHA-256, seal
  digest) must equal the recorded input of that pair; then all semantic sections are compared **strictly** (no
  projection). Without `--pair`, the ordinary strict guard applies (and now also stops on a differing manifest
  digest when both snapshots record one).
- The new meta fields and the decision section (C) are written only when `dump` is given `--paired-sections`; a
  plain `dump` writes exactly today's document, so the unchanged `ped6` gate keeps reading its existing snapshots
  and producing comparable ones (section 0 of r2 stands).

## C. Decisions captured before the snapshot's legacy encoding [A2-3]

Amends r2 section 3.
- `--paired-sections` adds a `decisions` section built from the engine objects directly, before any legacy
  encoding: full verdict enums (e.g. stack restoration `UNKNOWN` vs `DISPROVEN`, which the snapshot encodes both as
  `restores_stack=false`, `semantic_snapshot.py:144`), control sites, run-level records (failed functions, admission
  failures, refused control graphs, fault report, control contexts / exemptions), supports and premise uses. Both
  the strict and the projected comparison use it.
- Digest erasure in the projection is limited to **named transport / identity paths** (listed in the tool, each with
  its reason); semantic input pins (model digests, template digests, assumption labels) are compared as values.
- Comparator tests add: a verdict-only change (`UNKNOWN` -> `DISPROVEN`, nothing else) fails; a consistent
  renumbering of dependency nodes / definitions passes.

## D. Controls for stage 1 and the cut decision [A2-4, F2-P3-1]

Amends r2 sections 2-3.
- An accepted stage-0 S1 listing difference needs evidence tying each changed row to the analyzer option (the rows
  that differ are the ones the turned-off flow-guess analyzers decide: the call / fallthrough rows with their
  before / after flow facts); original bytes, block mappings and every unrelated field stay under the equality
  requirement.
- Each feature group is compared against the **stripped control** (the published Bundle stripped of every addition
  that old input lacks), so an accepted stage-0 difference is not charged to every group; the cut decision also
  compares **old directly against published** (projection + oracle).
- The program oracle runs on every stage-1 comparison (each group vs control, and old vs published).

## E. Interaction rule [A2-5, F2-P3-3]

Replaces r2's interaction bullet. Let D(g) be group g's differences against the control and D(full) the full
published Bundle's. Every element of D(full) \ union(D(g)) and of union(D(g)) \ D(full) -- including a single-group
effect that disappears or changes value in the full run -- is listed and needs an explanation; an unexplained one
blocks the baseline. `len` projection-equality and per-site DF / rep equality stay unconditional.

## F. Ambiguous coordinates [F2-P3-2]

If real Bundles produce an ambiguous coordinate (two referents, one coordinate), the comparison stops for that
pair; the finer coordinate (e.g. adding the p-code ordinal or the operand index) is decided in review and added to
the tool -- never merged.

## G. Inventory for prepared projects [A2-6]

Amends r2 section 0 (inventory) and section 4.
- The inventory records **attestation applicability per function**: `proof_input` is required on a fresh-import
  export for every function where the exporter emits S1, and must be absent on `-process -noanalysis` exports and on
  functions where S1 is withheld (`GhidraV2BundleExport.java:1558`); a missing required attestation and a falsely
  asserted one both fail.
- Inventory tests restored from the closed plan: a genuine Win32 control passes; a mixed-S1 image passes; a swapped
  original fails.

## H. UE migration in the cut checklist [A2-7]

Amends r2 sections 1 and 5 (closed plan r4 4.7).
- The report includes, for the published UE Bundle: the shipped v3 evidence's switch list vs the v5 `s3-off`
  verdict's switch list, both recorded, with the template decisions under each; and the UE template re-derived
  under `s3-off` from the published producer Bundle (explicit path) for the new gate.
- The cut checklist: stage 0 per pair, stage 1 per group + interaction set, oracle per comparison, inventory, r4 S1
  count, DF / rep identity, UE migration outputs, TBR check per kind, strict ped6 gate (old Bundles) green.

## Closing notes (Fable round 3 APPROVE, P3s folded)

- `compare --paired` (projection) verifies both inputs against the pair record exactly as `--pair` (strict) does.
- After deriving the comparison copy, a post-check confirms it differs from the published Bundle only in the
  declared generation-id fields and the digests bound to them (seal / manifest / transport digests).
- The old side needs a fresh `dump --paired-sections` from the X-1b tree: the stored `ped6` snapshots have no
  `decisions` section.
Status: method CLOSED 2026-11-27 (Astra round-2 complete list folded per the closing rule; Fable APPROVE r3).
