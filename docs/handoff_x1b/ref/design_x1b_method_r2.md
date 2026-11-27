# X-1b paired comparison -- method delta r2 (2026-11-27)

r1 (`design_x1b_method_r1.md`) + reviews: Astra `x1b_method_astra1.md` (CHANGES REQUIRED, 3 P1 + 2 P2), Fable
`x1b_method_fable1.md` (APPROVE WITH FIXES, 4 P2 + 6 P3). r2 replaces r1's "Method" and "What this means" sections;
r1's findings stand. Tags: [A-Pn] Astra, [F-Pn] Fable.

## 0. What stays from the closed plan (part 5 + r3 / r4 amendments) [A-P2-2, F-P3-1]

Unchanged and required before the baseline is cut:
- the strict same-generation `ped6` gate stays as it is (the X-1b tree gated against ped6 on the OLD Bundles);
- all four Bundle kinds are re-exported and paired: gate Bundles, the ntdll closure, the field cases with system
  calls, the UE template producer bundle; TBR is told before the run and checks one Bundle per kind;
- every comparison runs in both profiles (default and legacy);
- per-site DF / rep decisions stay **identical** -- no "explained difference" exception for them [r3 part 5];
- r4's per-Bundle count of functions with a `covered` row but no S1 status;
- the inventory (r2 part 5 items 1-8, r3 machine-aware) passes for every new Bundle;
- the comparator's tests: a generation-only change passes; a changed debt, support, proof, edge, refusal,
  completeness, oracle result or premise use fails (section 3).

## 1. Generation ids and caches [A-P2-1, F-P2-4]

- **Published Bundles get fresh generation ids** (`/root/tdo_bundles4/<name>/<new gen>`). The old id is used only in
  disposable comparison copies under `/root/x1b_pair/<name>/<old gen>/...`, deleted after the comparison.
- A mapping file `x1b_pairs.json` records per pair: Bundle name, old generation + seal digest + manifest digest,
  comparison copy generation (= old) + seal, published generation + seal + manifest digest, original SHA-256.
- Comparison runs use cold, isolated caches: a fresh `TDO_V2_*` cache / linker cache directory per run
  (`linking.py:374` cache keyed by DLL and profile), and the UE template check pointed at an explicit Bundle path
  (`check_ue_template.py:23` resolves `source.producer.bundle` under the configured root -- never the comparison
  root).
- `semantic_snapshot.py dump` records the manifest SHA-256 and seal digest in `meta`; strict `compare` stops on a
  differing manifest digest unless `--paired` is given (section 3), so a reused id can no longer hide a different
  Bundle.
- Test: the old Bundle's receipt rejects its resealed comparison copy (`configured_bundle.py:300`).

## 2. Stage 0 -- same program [A-P1-1, F-P2-1, F-P3 S1 rule, A-P1-3]

Pairs are enumerated **per Bundle and generation** from the old root (ue-core-probe has two old generations; both
are paired). For each pair:

1. **Pin**: both sides name the same original SHA-256 (a swapped original fails).
2. **Strip relative to that old input**: the stripper removes only the additions that the specific old Bundle lacks
   (computed per pair from the old Bundle's schema use: e.g. ue-core-probe's second export keeps S1 + length), never
   a field the old input already carries.
3. **Re-bind only schema-declared transport fields** [A-P1-1]: observation digest references in the naming /
   effect sidecars (their declared observation-digest field), `call-interface-profile.transport.program_member_sha256`,
   `call-effects.transport.call_interface_profile_member_sha256`; nothing else is rewritten (no byte replacement
   across members). A digest that appears anywhere else is an error.
4. **Member-by-member comparison** [F-P2-1, A-P1-1]: every member of the stripped copy vs the old Bundle -- JSON
   members in canonical form (sorted keys), binary members (original, blocks) by hash -- plus the manifest
   (blocks and mappings, function list and entries, member list) and the instruction / p-code order inside each
   observation. Allowed differences: exactly the transport metadata of the exporter version
   (`transport.runtime_classes[].class_sha256`), listed. Any other difference -- including an unlisted seventh
   addition -- is reported per member and field.
5. **Engine check**: strict `semantic_snapshot.py compare` (default + legacy, supports and premise uses included,
   section 3) and the program oracle on the stripped copy vs the old Bundle.

Rule [F-P3 S1]: a stage-0 difference blocks the baseline unless it is attributed, per function, to a listed
producer change (today one: S1 turned off Ghidra's four flow-guess analyzers, which may change a listing) with the
evidence shown (the rows that differ and the option that explains them) and accepted in review. Rep-site decisions
must still be identical. An unattributed difference always blocks.

## 3. Stage 1 -- feature effects [A-P1-2, F-P2-2, F-P2-3, F-P3 interaction]

Groups (added back to the stripped copy one at a time): `proof`; `s1+fte`; `reg`; `len`; `x1+len`; then the full
published Bundle (not a re-assembled copy) [A-P1-3].

- **Both sides of every comparison generate supports and premise uses explicitly**, strict paths included [A-P1-2]
  (`EngineRun.supports`, `premise_uses`: a `--with-premises` dump section).
- Groups that keep identities: strict compare.
- Groups that change identities: the **coordinate projection** (`--paired` compare):
  - every identity atom and index reference is **resolved to the coordinate of what it refers to**, never erased
    [F-P2-2, A-P1-2]: a storage object -> (function entry, object kind, space name, offset); a definition id ->
    the definition's (site coordinate = function entry + instruction address + p-code ordinal, storage, span); a
    dependency node -> its resolved key; operand order is kept; an ambiguous mapping (two referents with one
    coordinate) is an error, not a merge;
  - edges: the multiset of (kind, resolved source, resolved destination, payload) with multiplicity;
  - roots: root occurrence and resolved origins per sink;
  - debts, proofs, refusals, admission failures: keyed by kind + site + storage coordinate, not counted;
  - completeness, summary values (by resolved storage), proven call effects, control sites, supports, premise uses;
  - unordered collections are sorted only after resolution;
  - the fields erased outright are listed in the tool with a reason each (identity-only: digests, space keys,
    generation id, manifest / seal digests, exporter class hashes); anything not on that list is compared.
- `len` must be projection-identical (a pure input outside X-1 evidence) [F-P3 len].
- Interaction rule [F-P3]: the full Bundle's differences must be the union of the single-group differences; a
  difference that appears only in the full run is an interaction and is listed and explained like any other.
- Every other difference is listed with its cause and reviewed; rep-site decisions stay identical (section 0);
  unexplained differences block the baseline.

**Comparator tests** (part 5 + r3 + reviews), on a small corpus pair:
- positive controls: generation-only change passes; old vs strip-all is projection-identical;
- each fails: a changed debt, support, proof, edge, refusal, completeness result, oracle result, premise use
  only [r3]; a debt moved to another site with the count unchanged [F-P2-3]; a dependency re-pointed to another
  definition / writer with values unchanged (same-kind edge rewiring) [F-P2-3, A-P1-2]; an ambiguous coordinate
  mapping.

## 4. Replay [A-P1-3, F-P3 kinds]

- `x1b_reexport.py` enumerates the expected pairs (Bundle + old generation); an existing output is accepted only if
  it is a verified published generation for that pair (receipt checked, original SHA-256 equal, recorded in
  `x1b_pairs.json`); a skip is never counted as success otherwise; the run fails if any expected pair has no
  verified output.
- The non-gate kinds: the ntdll closure and the UE producer bundle are project exports (`-process -noanalysis
  -readOnly` from the prepared projects), replayed from their command logs the same way; the field cases from their
  recorded commands. Each kind gets stage 0 and stage 1.

## 5. Order

1. Comparator (`--with-premises`, manifest guard, `--paired` coordinate projection) + its tests; stripper with
   declared re-binding + member comparison; replay with pair verification.
2. Tell TBR; replay all four kinds twice (comparison copies with the old id; published with fresh ids).
3. Stage 0 and stage 1 for every pair; report (`.census6/x1b_report.md`): per Bundle the stage-0 result, per group
   the differences with causes, the r4 S1 count, the inventory.
4. Review of the report; then the new baseline from the published Bundles, the strict gate on them, code review,
   owner's merge OK.
