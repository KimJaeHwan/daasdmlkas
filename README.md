# Low-Pcode data-origin engine snapshot

This repository contains the **engine runtime**, extracted from the
`trace_data_origin_lowpcode_v2` working tree on 2026-10-04. It retains the
configured physical-state path used by that project's corpus runner, its local
byte-range graph, call/memory composition, conditional path construction, and
the separately selectable finite-recursion engine. It does **not** contain the
corpus evaluator, independent path-grading shadow, test suite, historical ADRs,
replay scripts, fixtures, or output reports. Those remain in the original
repository; this is not a claim that they are unnecessary for development.

## Engine boundary

```text
admitted Low-Pcode Bundle + caller-supplied boundary policy
  -> local physical storage and byte-range graph
  -> configured call/memory completion
  -> root-local backward query
  -> source candidates, intermediate path segments, and explicit gaps
```

The public entry point is `tdo_v2.engine.analyze_frozen_bundle`. It requires a
format-2 Ghidra Bundle, the exact source file used by the Bundle's naming
exporter, and a `BoundaryProvider` that identifies source/sink calls and their
**observed physical state**. `tdo_v2.boundary_rules.SymbolBoundaryProvider` is
a generic table-based implementation; no calling convention or benchmark names
are built into the engine. The four retained `ghidra/*.java` files are the input
exporter sources. A generic binary-to-Bundle command has not yet been split
from the old repository's benchmark runner, so use an existing Bundle for this
snapshot.

```python
from tdo_v2.engine import analyze_frozen_bundle

result = analyze_frozen_bundle(
    "/path/to/frozen-bundle/generation",
    naming_exporter_source="ghidra/GhidraV2CallNaming.java",
    boundary_provider=your_boundary_provider,
)
for root in result.roots:
    print(root.label, root.reached_origin_labels)
    print(root.explanation["conditional_source_to_sink_paths"])
```

Supply `external_provider` only when external effects are independently known;
unknown effects must not be replaced with guessed source transport. The lower
level `replay_selected_finite_root` in
`tdo_v2.integration.configured_finite_root_replay` remains available for an
explicitly selected finite recursive root and its conditional premises. It is
not silently applied to ordinary roots.

## Current limits

The returned path data is **conditional engine output**, not an independently
verified whole backward slice. In particular, the out-pointer writer
STORE-to-caller-LOAD path for the previously studied 54th case is still
incomplete. The old global configured fixed point does not finish the
recursive case without a separate finite request. An empty or incomplete path
must never be interpreted as proof that no source exists. No Suite09 score or
release-readiness claim is transferred to this repository.

The immediate engineering target is one coherent graph/query result in which
the actual writer STORE, intervening memory effects, caller LOAD, and sink are
connected or reported as a typed gap. The original repository remains the
external regression and verification workspace.
