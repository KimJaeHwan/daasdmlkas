# Design brief (d): interprocedural freshness / pointer identity across calls

Repository: TDO_v2, a Ghidra Low P-code backward data-origin slicing engine (Python, `src/tdo_v2`).
Principles: soundness first — never silently miss a dependency; anything unknown stays debt (the root is
reported "unsure"); every assumption is named and labelled; external functions are modelled in
function-summary form in `models/external/*.json` (`summary_store.py`). Read
`docs/interprocedural_design.md` sections 1-3, 10, 13-14, 18-19 for the current design.

## Current machinery (relevant parts)

- `relative_memory.py`: address expressions = (atoms, displacement). Atoms: ENTRY values of registers or
  memory (`_stable_storage_key`), opaque-value tokens, and *definition atoms* (`_definition_atom`): a value
  defined once per activation by a call effect row `~<i>` or a LOAD (blocks on no CFG cycle,
  `single_execution_keys`). Definition atoms are *wild* (may point anywhere incl. the private frame)
  unless the call is a model declaring the register `fresh` (malloc) — then *fresh*. Model
  `same_object_as` (realloc) makes the result's expression equal to the argument's.
- `may_alias.py`: per-byte "writes to other objects since last write" analysis; private-frame rule with
  per-point stack escape (`_stack_taint`); wild objects break privacy; fresh objects are disjoint from
  ADDRESS_SPACE (globals), the stack object and other fresh objects (not from entry-register objects:
  after an opaque call a register's SSA value is stale).
- `function_summary.py`: bottom-up summaries per function: terminal-state runs IDENTITY / COMPUTED /
  UNKNOWN over registers and memory objects; memory objects are exported to callers only through
  *anchors* (`interprocedural._relative_anchors`: FUNCTION_RELATIVE objects based on one entry register,
  or on a pointer the entry memory holds — `AnchoredSpan.pointer`, depth 2). `writer_conditions` (S3).
- `call_summary_effects.derive_proven_call_effect`: summary -> `ProvenCallEffect` at a call site (register
  runs, memory runs anchored at caller-evaluated addresses, `preserves_memory`, `fresh_registers`,
  `same_object_registers`, ...). `normalize` materializes it as rows `~in<i>`, `~ld<j>`, `~<i>`.
- Interpreter oracle (`tests/intra/pcode_interpreter.py`, `program_oracle.check_program`) runs whole
  programs with real externals (malloc/realloc move blocks) and checks no silent miss.

## The problem (measured)

UE plugin DLL cases (TArray/TMap, Development + DebugGame builds) now mostly reduce to this shape
(case TV2R001, Development):

```
caller:
  Arr.Data = 0 (at [rsp+0x20]); Arr.Num/Max at [rsp+0x28..]
  helper(&Arr)                      ; TArray::ResizeGrow-like: QuantizeSize, then
                                    ;   this->Data = FMemory::Realloc(this->Data, n)   (UE core import, modelled)
  rbx = [rsp+0x20]                  ; reload Arr.Data
  [rbx] = A                         ; write the new element
  ... read Arr.Num at [rsp+0x28] ...; -> may-alias debt: is rbx (a LOAD-defined, wild atom) pointing into
                                    ;    the caller's frame? (the frame escaped: &Arr was passed)
  sink(*rbx)
```

Inside the helper the engine knows `this->Data` holds a Realloc result (same object as the old
`this->Data`, or fresh when that was null). At the caller, after the call, the slot `[rsp+0x20]` is
defined by the helper's memory run (COMPUTED from inputs), so the reloaded `rbx` is a wild definition atom:
may-alias with the caller's escaped frame and with everything else -> unsure, and extra origins.

Other remaining blockers (lower priority): virtual calls (register CALLIND), FString internals, writes in
loops (definition atoms excluded in cycles).

## Questions for the design

1. What summary-level fact should cross the call boundary? Candidates:
   (a) "pointer provenance" per exported pointer-sized value (register run or memory run): FRESH (allocated
   inside the callee, not escaped before return), SAME_OBJECT_AS(entry anchor) (e.g. realloc of an entry
   pointer), or UNKNOWN; caller turns FRESH into a fresh atom for that definition, SAME_OBJECT_AS into the
   anchor's caller expression.
   (b) a weaker "not a stack address of the caller" fact (non-stack) — enough to make the caller frame
   private again for that pointer; cheaper to prove.
   (c) something else.
2. How to prove these facts soundly in the callee summary: e.g. the run's value comes only from a fresh
   call result / same_object_as result / a value that is itself proven fresh; across joins (both paths
   fresh, or one path keeps the old value -> SAME_OBJECT_AS entry), loops, recursion (S5 fixpoint), and
   when the callee also stores the pointer elsewhere (escape -> FRESH is no longer "unaliased" for the
   caller; is "non-stack" still valid?).
3. The caller side: the slot `[rsp+0x20]` after the call holds the helper's memory run value; a later LOAD of
   it must get the fact (definition atom of the LOAD inherits from the slot's defining run). How to carry
   provenance through the memory SSA (store/load forwarding already exists in `_expression_from_memory_read`)?
4. Interaction with existing rules: fresh disjointness (globals/stack/other fresh), wild objects, private
   frame + escape, writer_conditions, below-frame folding, SCC hypotheses.
5. Minimal first increment with the best measured gain, and concrete oracle tests + mutations that must
   fail (e.g. "callee returns a pointer into the caller's frame but is marked non-stack", "callee frees and
   reallocates", "join of fresh and caller-frame pointer").

Keep answers concrete (file/function level), under ~900 words, with a recommended order.
