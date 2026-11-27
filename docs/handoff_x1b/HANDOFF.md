# Handoff: X-1b (paired re-export comparison) -- home work, 2026-11-27

This folder (`docs/handoff_x1b/`) is **home-only**: it never goes into main. Everything meant for main goes into
normal repo paths (`tools/`, `src/`, `tests/`, `docs/interprocedural_design.md`).

## 0. House rules (non-negotiable)

* Repo: PUBLIC GitHub repo. **Never commit** Bundles, binaries, snapshots, dumps or anything from the data pack.
* Owner philosophy: **no ABI / calling-convention assumptions**; soundness first -- when unsure, refuse / cut with a
  named reason, never guess. Never discard a computable result.
* Commits: `git -c user.name="김재환2 [rfkjh22]" -c user.email="rfkjh22@nexon.co.kr" commit ...`; the message ends with
  the co-author line used in this repo (see `git log -1`). **Pushes need the owner's OK.**
* Talk to the owner in easy Korean, no analogies. Explain the next step before starting a new one.
* WSL: `~/venvs/tdo/bin/python`, tests with `PYTHONHASHSEED=0 PYTHONPATH=src:tests/intra`. Heavy jobs one at a time
  (`ulimit -v 12000000`). Never edit src/tests of a tree while a suite / long run reads it.
* Reviews (when the owner wants them at home): Astra (Codex `gpt-6.2-astra`, read-only) + Fable; on conflict follow
  Astra; on a repeated REJECT ask Astra for the COMPLETE list, fold it, close.
* Producer trust (is Ghidra's listing / lift right) is the TBR side's (tags `[TBR-G1-*]`, `[TBR-G2-*]`, `[TBR-G3-*]`);
  do not prove it inside TDO.
* TBR works on its own home branch (`home/tbr-g2b-2026-11-27`, area `tools/decode_check`, G1/G2b). **Do not edit
  `tools/decode_check/`** here.

## 1. Where things stand

* main = `1828683` (X-1a merged; origin/main may still be older -- the owner pushes).
* This branch = `feature/x1b-reexport` (from main) + this handoff commit:
  * `f68d4c3` bounded descriptor cache (Astra X-1a r5 [ASTRA-OPEN]);
  * `3e52614` / `aebde4c` paired snapshots (`semantic_snapshot dump --paired-sections`, `compare --pair / --paired`)
    + the coordinate projection `tools/graph_fidelity/paired_projection.py` + tests;
  * `38eb6bc` exporter: **S1 withheld per function** (owner) instead of refusing the Bundle; scanner captures keep
    32-byte line digests (UE Core ran out of heap);
  * `232303c`, `3eb9482`, `e331d66` projection fixes found on the real pairs; `MAX_FROZEN_BUNDLE_BYTES` 512 MiB -> 1 GiB
    (owner); `export_bundle.py --no-s1-prescript` (attribution evidence);
  * `1b20dee` the tools in `tools/x1b/` (README there).
* Method (closed with Astra + Fable): `ref/design_x1b_method_r3.md` (read r1 findings, r2, r3 closing notes).
  Plan context: `ref/design_x1_r2.md` part 5 + r3 / r4 part-5 amendments. S3 prerequisites: `ref/s3_prereqs_from_x1.md`.
* Owner decisions today: legacy profile only on the corpus + v2-win-debug-full + v3-win-release-full (zlib legacy
  > 1 h per snapshot); S1 withheld per function; 1 GiB Bundle bound; G1 use = cross-check only (option a).

## 2. Results so far (`ref/x1b_report_full.md` is partial; `ref/x1b_report_interim2.md` older)

Re-export: 21 gate-tree pairs + 5 DLL pairs (ntdll closure, ntdll_small, kernel32, KernelBase, user32) + the UE template
producer -- all verified. TBR's G1 check per kind passed.

Stage 0 (re-export stripped of every addition == old Bundle): identical except, **all attributed with evidence**:
* S1's pre-script (Ghidra's flow-guess analyzers off): zlib (call rows gain a fallthrough, data refs move), gcc
  corpus x2 (`.bss` / `__CTOR_LIST__` / `__DTOR_LIST__` leave the exports), v3 (signature source IMPORTED -> DEFAULT).
  Evidence: `export_bundle.py --no-s1-prescript` re-exports, stripped, == old (zlib, v2, ntdll_small; v3 / ntdll by
  function entry) and `tools/x1b/DumpExports.java` (63 vs 60 exports).
* G-T G2 (`ea1a058`, internal thunks stay in the Bundle): v3 x64 +6, v3 win32 +1, ntdll +5 single-row BRANCH thunks;
  every old function identical by entry.

Stage 1 (feature groups s1+fte, s1+fte+len, s1+fte+len+proof, reg, len, x1+len vs the stripped control; projected):
* identical everywhere: corpus x7, KernelBase, kernel32, user32 (both profiles where run);
* **real effects, still to explain**: v3-win-release-full -- S1 groups: root 49 gains `control_obligations`
  (`continuation:1b1:140002290:*`, `control:...:memory-writes`) and `run:control_contexts` changes; reg group: one
  `call_clobber_reads` span's base object moves from `entry register_file+0x0` to `entry address_space+0x14000c378`;
  v2-win-debug-full -- the proof group (exception-handlers fact) changes 20 sections;
* projection not finished: zlib, ue-dll-debuggame, ue-dll-development (latest fixes untested there: the projection
  loads two whole snapshots -- zlib took > 13 GB);
* ntdll / ntdll_small: `semantic_snapshot dump` fails even on the OLD Bundle ("observed function scope could not be
  constructed") -> member comparison only.

UE migration (closed plan r4 4.7, method H): the shipped UE template rests on v3 stack evidence (0 switches, legacy
nonvolatile-preservation exception). The v5 s3-off verdict of the published UE Core has **88 switches** in 83
functions, all `SUB RSP,RAX` after `__chkstk` (v4 / v5 keep post-call registers unknown -- the owner's no-ABI rule).
Re-derived under s3-off, the template loses `globals-disjoint-from-stack` and `FString::AppendChar` changes. The gate's
template check still uses the v3 evidence and the old producer, so the gate is unaffected. **Owner decision pending:**
when to migrate (now, or with S3 / a `__chkstk` model).

## 3. Tasks (in order; each one its own commits)

**T1 -- projection: memory + finish the pairs.** `tools/graph_fidelity/paired_projection.py`.
* Make `project_document` stream: build the tokens with one pass, then project one section at a time and keep only
  its digest (and, for reports, the first difference) -- target < 3 GB on zlib.
* Re-run the comparisons for zlib, ue-dll-debuggame, ue-dll-development (`tools/x1b/x1b_stages.py ... --compare-only`
  on the packed run folders) and resolve what remains, one rule at a time, each rule with a reason in the tables at
  the top of the module (`IDENTITY_RENAMED`, `DIGEST_FIELDS_ERASED`, `TREE_LINKS_ERASED`, `STRUCTURAL`). Never merge two
  referents; when a coordinate is ambiguous, make it finer.
* Tests (`tests/intra/test_x1b_paired_projection.py`): one per rule added since `aebde4c` (guarded image candidates,
  per-function / shape-named atoms, unaccessed duplicates, raw unrecorded space keys, structural coordinates,
  state arenas through reach sets, whole-hash elision, unpaired local reads) -- each with a passing renumbering case
  and a failing decision-change case.
* Done when: every pair in the pack is projection-identical or its differences are listed by cause; tests pass.

**T2 -- explain the real stage-1 effects** (v3-win-release-full S1 + reg, v2-win-debug-full proof).
* For each: find the engine path (S1 / `call_fallthrough`, register table `isa_identity` / `normalize.py:850`,
  exception-handlers fact) that makes the decision, show the before / after facts, and classify: expected (a fact the
  new producer field adds) or a regression. A regression gets a fix + a test; an expected one gets a one-paragraph
  explanation for the report.
* The Bundles are in the pack (old `tdo_bundles3/...`, published `tdo_bundles4/...`); re-derive a group copy with
  `tools/x1b/x1b_bundle_tools.py strip <published> <out> --old <old> --keep <groups>`.

**T3 -- the X-1b report + docs.** `docs/interprocedural_design.md`: a new section after 25.121 (X-1b): method, stage-0
attributions, stage-1 results, owner decisions, open items. Keep the report table generator (`tools/x1b/x1b_report.py`)
in sync (pair attributions there).

**T4 -- S3 design delta (draft for review).** From `ref/design_s3_r18.md` + `ref/s3_prereqs_from_x1.md` + what X-1b found
(per-function S1 withholding, UE `__chkstk` switches, G1 use = cross-check). Write `docs/handoff_x1b/design_s3_r19_draft.md`
(home-only; it is reviewed and copied over here).

**T5 (optional) -- UE template migration options** for the owner: what a `__chkstk` summary / model would need under
the no-ABI rule (DLL summaries as models), and what the template loses meanwhile. Notes only.

**T6 (optional) -- why `semantic_snapshot dump` cannot build ntdll's scopes** (old and new alike); fix only if small.

## 4. Data pack (private -- never commit, never publish; contains specimen binaries)

`x1b_home_2026-11-27.tar` (+ `.sha256`) from the owner. Restore in WSL: `cd /root && tar -xf <tar>`. It holds:
`x1b_pairs.json`, `x1b_attr_pairs.json`, run folders `x1b_runs/<pair>/` (dumps, `pairs.json`, `result.json`) for
zlib, ue-dll x2, v3 x64 / win32, v2-win-debug-full, corpus clang-x64-O2; the old / published Bundles of those
(`tdo_bundles3/...`, `tdo_bundles4/...`); the attribution exports (`x1b_attr/...`); the UE outputs
(`x1b_ue_template/`) and the old UE evidence (`ghidra_link_evidence/core.stack.json`); the X-1 test export
(`x1_export_test/...`, default of `TDO_X1_EXPORTED_BUNDLE`).
Paths inside `pairs.json` / `result.json` are the office's `/root/...` paths: restoring under `/root` keeps them valid.
Also `x1_scan_ntdll5/x1.json`: set `TDO_X1_STANDALONE_SCAN=/root/x1_scan_ntdll5/x1.json` for `test_x1_stack_authority.py` (its default `/root/x1_scan_ntdll2` no longer exists; the test skips without it).
Size ~683 MB (`Downloads/x1b_home_2026-11-27.tar`, sha256 next to it). Bundle folders must keep their modes (owner uid, no group / other write): restore as root with plain `tar -xf`.

## 5. Merging back (what the office session will do -- keep it fast)

* Work only on this branch; commit per topic; **never mix `docs/handoff_x1b/` changes into a code commit** (prefix
  those commits with `handoff:`). The office cherry-picks every non-`handoff:` commit onto `feature/x1b-reexport`
  (frozen at `1b20dee` until you return) -- so a clean history merges by fast-forward.
* Do not touch: `ghidra/` (a change there needs a re-export only the office can run), `tools/decode_check/` (TBR).
  `src/` changes are fine with tests; say in the commit message which gate effect you expect.
* Leave a short `docs/handoff_x1b/RESULTS.md` (handoff commit): what was done, what is open, test commands and their
  results, anything the office must re-run (e.g. a re-export).
* The office then runs: focused tests, the compare-only pass on all pairs, the full suite, the gate, Astra + Fable.

## 6. Commands

```bash
# tests
PYTHONHASHSEED=0 PYTHONPATH=src:tests/intra ~/venvs/tdo/bin/python -m pytest -q -p no:cacheprovider \
  tests/intra/test_x1b_paired_projection.py tests/intra/test_x1_bundle_evidence.py
# one pair, comparisons only (dumps reused)
~/venvs/tdo/bin/python tools/x1b/x1b_stages.py . /root/x1b_pairs.json 'zlib#53a9289fedd5' --configs default --compare-only
# develop the projection on two dumps
~/venvs/tdo/bin/python tools/x1b/x1b_projdev.py /root/x1b_runs/zlib@53a9289fedd5/control.default.json.gz \
  /root/x1b_runs/zlib@53a9289fedd5/s1+fte.default.json.gz
# report
~/venvs/tdo/bin/python tools/x1b/x1b_report.py --runs /root/x1b_runs > /tmp/x1b_report.md
```
