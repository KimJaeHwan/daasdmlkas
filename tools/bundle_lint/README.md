# bundle_lint (G0)

What of a Bundle the TDO engine **accepts, uses and loses** -- the producer-side check of the Ghidra-independence plan
(docs/ghidra_independence_plan.md stage G0; design `.census6/design_g0_bundle_lint_r0..r6.md`). POSIX / WSL only
(Bundle admission checks owner, mode and `fcntl`).

```
PYTHONPATH=src python3 tools/bundle_lint/lint.py <generation> --out report.json [--expect expect.json]
    [--normalize] [--pcodeop-models models/pcodeops/x86.json] [--no-summary] [--options options.json] [--timeout 600]
PYTHONPATH=src python3 tools/bundle_lint/mutate.py <generation> <out_root> <variant> [--function ID] [--site KEY]
```

The tool calls engine code for its decisions. Where it must restate an engine rule to report it (the read-only block
condition, the S1 reach rule, the Win64 home-space rule, the fixed register offsets, the summary's context variables),
the engine's own source line is pinned by a guard test, as are the private helpers it drives
(`tests/intra/test_bundle_lint.py`, `test_guard_*`).

## Processes

- **Diagnosis pass** (`diagnose.py`, own process, on the engine's analysis worker): a fresh admission; one guarded
  claim per function (scope -> call / tail seeds -> naming); stop predictions per pipeline path; layers 1-3.
- **Pipeline paths** (`children.py`, one process each, fresh admission, `PYTHONHASHSEED=0`, the engine's own worker
  setting kept): summary strict (`iter_functions`), summary retain (`iter_outcomes`), base_graph. Each path's actual
  stop must match the prediction (class and message) or the stop row is `error`.

## Rows

`run_state`: `evaluated`, `not_reached`, `not_run`, `unobserved`, `timeout`, `error`. `verdict` (only when
evaluated): `applied`, `not_applicable`, `unrecognized`, `withheld`, `refused`, `unsupported`, `error`. `source`:
`engine` (an engine function's answer) or `lint` (the lint's mapping of engine facts); only the engine refuses.

Keys: validated operations `<function id>/<operation key>`; rows of a member's own array (S1 exits, source rows of a
refused function) `<function id>/#<index>`.

| layer | checks |
|---|---|
| transport | admission, program, image_info, readonly_block, function_scope, seeds, naming, scoped_iterator |
| operations | language, stack / link / pc register, fixed_register (engine literals), pcodeop_language, call, push_projection, plain_push, push_relation (push ISAs), link_relation (link-register ISAs), tail_call, s1_exit, branchind (engine `unknown_transfer_sites`), rep_site, callother_model_match, source_row(s), layer_error |
| features | stack_pointer, standalone_context / standalone_normalize / readonly_use / standalone_rep (`--normalize`), trap_application, rep_application |
| pipeline | stop, completion (applied only when nothing was lost; error for resource failures, unpredicted stops or a failed diagnosis), run_columns (assumptions, control exemptions, fault report, control sites), branchind_final (candidate / exemption / final per BRANCHIND site) |

Per-site rows (trap_application, rep_application, branchind_final) read the strict summary when it completed, else
the retain summary (`detail.run`); not_run (path / option off), timeout, error (resource), not_reached (a predicted
pre-analysis stop, or a member replaced by a later one of its entry), unobserved (anything else not public).

Recognisers: `push_projection` / `push_relation` on every native call (unrecognized on a push ISA, not_applicable on a
link-register ISA unless the engine recognises a push; `push_relation` withheld without stack-register evidence);
`plain_push` only on an x86-64 direct CALL (the engine's literal shape); `link_relation` on a link-register ISA
(withheld without link / pc / sp evidence); an ISA in neither `isa_identity` table: all not_applicable.

`--expect`: rows by `(layer, check, key)`; `run_state`, `verdict`, `source` and every listed `detail` key (a missing
key is a difference); `"exhaustive": true` also fails on rows not listed.

## Not in G0 (reported as `not_run` rows, check `excluded`)

- **Ignored keys and proof fields** (design r0 s5-6, r1 s4): the function JSON is lenient (unknown keys ignored). Listing
  what the engine ignores needs the engine to expose the key sets it reads; re-listing them here would re-implement the
  reader. Deferred until the reader exposes them.
- **Per-site application inside the summary run** (traps, rep): not public in `EngineRun` -> `unobserved` rows.
- **Convention keys beyond RSP / RIP** (design r1 s5): the engine files that compare language-id literals are
  inventoried by `test_guard_engine_language_literals_are_inventoried` (a new file fails it); individually reported
  in G0 are only the x86-64 RSP / RIP offsets and the p-code op model language. Not yet rows: the x86 flag offsets
  (`interprocedural._X64_FLAGS`), `may_alias.CALL_PRESERVED`, the language-id string checks (summary_engine,
  operation_records, configured_finite_byte_kernel, ...), the user-op tables (code_only_profile, fault_premise).
- **The standalone `--normalize`** has no proven call effects: its rows are labelled `standalone`, never the summary's
  result. `stack_evidence` is not modelled (the summary's default is none).

## Variant tool limits

- `call-reshape` on a Bundle with a real call-effects sidecar is refused before anything is written: moving the CALL
  ordinal changes that sidecar's row and content digests; the engine has the encoders (`effect_row_digest`,
  `effect_content_digest`) but no JSON-to-row decoder, and the tool never writes an inconsistent sidecar. So 3b is
  tested on the synthetic fixtures only.
- Every variant admits its source first (its target function must be admitted with its names), copies only listed
  members, and post-checks that only the target changed: other functions identical, the target's other call rows
  identical, the target still admitted with its names (`call-ordinal`: only its names refused), `drop-pad`: the
  validated pad set lost exactly the selected pad. `drop-pad` and `exit-kind4` also compare the target's
  inter-function reach edges over the results a real summary run passes to `control_contexts` (so they run the summary
  on both sides). A source refused by its conditions writes nothing; a failure after the copy is renamed
  `<generation>.failed[.N]` (nothing is deleted). `--naming-source` for other exporter revisions.

Synthetic fixtures only in tests (`_sealed.py`); never commit a real Bundle, binary or report of one.
