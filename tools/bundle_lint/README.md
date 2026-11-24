# bundle_lint (G0)

What of a Bundle the TDO engine **accepts, uses and loses** -- the producer-side check of the Ghidra-independence plan
(docs/ghidra_independence_plan.md stage G0; design `.census6/design_g0_bundle_lint_r0..r6.md`). POSIX / WSL only
(Bundle admission checks owner, mode and `fcntl`).

```
PYTHONPATH=src python3 tools/bundle_lint/lint.py <generation> --out report.json [--expect expect.json]
    [--normalize] [--pcodeop-models models/pcodeops/x86.json] [--no-summary] [--options options.json] [--timeout 600]
PYTHONPATH=src python3 tools/bundle_lint/mutate.py <generation> <out_root> <variant> [--function ID] [--site KEY]
```

The tool calls engine code and never re-implements an engine decision; the private engine helpers it drives are pinned
by guard tests (`tests/intra/test_bundle_lint.py`, `test_guard_*`).

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
| operations | language, stack / link / pc register, fixed_register (engine literals), pcodeop_language, call, push_projection, plain_push, push_relation, tail_call, s1_exit, branchind, callother_model_match, source_row(s) |
| features | stack_pointer, standalone_context / standalone_normalize / readonly_use / standalone_rep (`--normalize`), trap_application |
| pipeline | stop, completion (applied only when nothing was lost), run_columns (assumptions, control exemptions, fault report, control sites) |

`--expect`: rows by `(layer, check, key)`; `run_state`, `verdict`, `source` and every listed `detail` key (a missing
key is a difference); `"exhaustive": true` also fails on rows not listed.

## Not in G0 (reported as `not_run` rows, check `excluded`)

- **Ignored keys and proof fields** (design r0 s5-6, r1 s4): the function JSON is lenient (unknown keys ignored). Listing
  what the engine ignores needs the engine to expose the key sets it reads; re-listing them here would re-implement the
  reader. Deferred until the reader exposes them.
- **Per-site application inside the summary run** (traps, rep): not public in `EngineRun` -> `unobserved` rows.
- **The standalone `--normalize`** has no proven call effects: its rows are labelled `standalone`, never the summary's
  result. `stack_evidence` is not modelled (the summary's default is none).

## Variant tool limits

- `call-reshape` on a Bundle with a real call-effects sidecar is refused: moving the CALL ordinal changes that sidecar's
  row and content digests, and no engine decoder exists to rebuild them; the tool never writes an inconsistent
  sidecar. On the synthetic fixtures (placeholder call-effects) it runs.
- Every variant admits its source first, copies only listed members, and post-checks that only the target function
  changed (target still admitted with its names; `call-ordinal`: only its names refused).

Synthetic fixtures only in tests (`_sealed.py`); never commit a real Bundle, binary or report of one.
