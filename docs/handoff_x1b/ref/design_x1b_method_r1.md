# X-1b paired comparison -- method delta r1 (2026-11-27)

Amends design_x1_r2.md part 5 (+ r3 / r4 part-5 amendments). Everything else in part 5 stays.

## Findings (trial: corpus clang-x64-O0, replayed export with the wt_x1b exporter)

1. **The old gate Bundles (`/root/tdo_bundles3`, 21 Bundles) predate five producer additions, not only X-1.**
   No old Bundle has `proof_input` (attested fresh import), `fallthrough_exits` / `call_fallthrough` (G-T / S1),
   `producer_profile` + row `override` / `recorded_landing_pads` (X-1), row `length`, or `program.register_evidence`
   (only ue-core-probe's second export has S1 + length). The re-export therefore brings all of them at once.
2. **Identity values depend on content.** Function scope digests, space keys and the values derived from them
   (address atoms, node keys / labels) change with row `length` and with the register table. The engine orders
   some lists by these digests, so list order and index references (`definition_ids`, dependency node numbers)
   change too. A metadata allowlist or a value renaming cannot align such snapshots (trial: 79/84 sections differ;
   renaming leaves 390 conflicts; erasing identities + sorting still leaves index-reference differences).
3. **With the old generation id and every new part removed, the re-export is strictly identical.** Re-exported
   with `--generation <old id>` and stripped of all six additions (resealed, transport bindings re-bound), the
   snapshot equals the old one exactly: default 84/84, legacy 28/28 sections. Ghidra produced the same program.
4. Per group (added back alone): `proof` alone -> identical; `s1` needs `fte` (and vice versa) to be admitted;
   `x1` needs `len`; `len` alone and `reg` alone each change 20 sections (identity; `reg` may also change results:
   `isa_identity`, `normalize.py:850`).

## Method (replaces the allowlist comparison)

Tools in `.census6`: `x1b_reexport.py` (replays each old export command with this tree's exporter, `--same-generation`
reuses the old generation id), `x1b_strip.py` (copy + remove feature groups + re-bind transport digests + reseal).

For every gate Bundle (and the paired-comparison runs of the other re-exported kinds):

- **Stage 0 -- same program (strict).** New Bundle stripped of every addition vs old Bundle: the existing strict
  `semantic_snapshot.py compare`, default and legacy, plus the program oracle. Must be identical. Any difference
  blocks the baseline (the producer changed the program, not only added facts).
- **Stage 1 -- feature effects, one group at a time.** Groups: `proof`; `s1+fte`; `reg`; `len`; `x1+len`; all.
  Groups that keep identities (`proof`, and `s1+fte` if it does) are compared strictly. Groups that change identities
  (`len`, `reg`, `x1+len`, all) are compared through an **identity-free projection**: per function and per run, the
  decisions -- completeness, debts (kind and count), refusals and admission failures, proven call effects, summary
  values by storage kind and offset, edges by kind, control sites, premise uses and supports (generated explicitly,
  r3 part 5) -- with digests replaced by the function entry / space name and lists sorted; plus the program oracle.
  `len` must be projection-identical (a pure input outside X-1 evidence). Every other difference is listed with its
  cause and reviewed; unexplained ones block the baseline.
- The inventory (part 5, items 1-8) and the swapped-original / mixed-S1 / Win32 tests stay.
- New baseline: the full re-exported Bundles (fresh generation ids are not needed: the old id is reused only in a new
  root, `/root/tdo_bundles4`), cut after stages 0 and 1 pass review.

## What this means for the baseline

The new baseline is the first gate run of S1 / G-T exits, the attested fresh import, the register table and X-1 on
real Bundles (they were tested on test Bundles and field cases only). Their effects are expected and must each be
explained in the stage-1 report; a regression found there is fixed before the baseline is cut.
