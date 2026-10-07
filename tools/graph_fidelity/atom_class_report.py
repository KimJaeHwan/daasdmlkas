"""Atom classes on a real Bundle: verify and size the sparse work (WSL).

usage: atom_class_report.py <generation> [--assume-boundary-effects] [--top N]

Normalizes every function with the dense engine while checking every memory
SSA unit (including relative-memory re-projection passes) with
``check_atom_classes``, and reports per unit: atoms, classes, blocks, the
dense work estimate (blocks x atoms) and the sparse estimate (sum over
classes of the blocks that write or read the class, plus entry and terminal
blocks; the iterated dominance frontier adds to this in step 3).
"""

from __future__ import annotations

import argparse
import sys
import time
from hashlib import sha256
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

from tdo_v2 import memory_ssa  # noqa: E402
from tdo_v2._memory_ssa_classes import check_atom_classes  # noqa: E402
from tdo_v2.configured_naming_contracts import (  # noqa: E402
    CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation,
)
from tdo_v2.integration.configured_bundle import admit_frozen_bundle  # noqa: E402
from tdo_v2.integration.observed_function_session import open_observed_function_session  # noqa: E402
from tdo_v2.memory_ssa import _build_partition  # noqa: E402
from tdo_v2.normalize import FunctionNormalizer  # noqa: E402

rows: list[dict] = []


def _checked(unit):
    began = time.time()
    classes = check_atom_classes(unit)
    partition = _build_partition(unit)
    touched: list[set[str]] = [set() for _ in classes.classes]
    for block in unit.blocks:
        for action in block.actions:
            for span in (*action.reads, *action.writes):
                start, stop = partition.covered_range(span)
                for atom in range(start, stop):
                    touched[classes.class_of_atom[atom]].add(block.key)
    fixed = {unit.entry_block_key, *unit.observed_terminal_block_keys}
    rows.append({
        "atoms": len(partition.atoms), "classes": len(classes.classes),
        "blocks": len(unit.blocks),
        "dense": len(unit.blocks) * len(partition.atoms),
        "sparse": sum(len(item | fixed) for item in touched),
        "check_seconds": time.time() - began,
    })
    return memory_ssa._ENGINES["dense"](unit)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("generation", type=Path)
    parser.add_argument("--assume-boundary-effects", action="store_true",
                        help="TEST-ONLY special condition: declared boundary call effects")
    parser.add_argument("--top", type=int, default=5)
    args = parser.parse_args()
    memory_ssa.register_memory_ssa_engine("dense-classcheck", _checked)
    import os
    os.environ[memory_ssa.MEMORY_SSA_ENGINE_ENV] = "dense-classcheck"
    provider = None
    if args.assume_boundary_effects:
        sys.path.insert(0, str(REPO / "tools" / "bundle_export"))
        import run_dfbench
        from tdo_v2.engine import assumed_boundary_effects
        provider = run_dfbench.boundary_provider(
            assume_call_effect=True, abi=run_dfbench.abi_of(args.generation))
    binding = NamingBindingExpectation(
        sha256((REPO / "ghidra" / "GhidraV2CallNaming.java").read_bytes()).digest(),
        CALL_NAMING_GHIDRA_VERSION,
    )
    functions = 0
    with open_observed_function_session(admit_frozen_bundle(args.generation),
                                        naming_binding=binding) as session:
        for evidence in session.iter_functions():
            assumed = assumed_boundary_effects(evidence, provider) if provider else {}
            FunctionNormalizer().normalize(evidence.unit, assumed_call_effects=assumed)
            functions += 1
    dense = sum(row["dense"] for row in rows)
    sparse = sum(row["sparse"] for row in rows)
    print(f"functions={functions} units={len(rows)} class-check OK "
          f"atoms={sum(r['atoms'] for r in rows)} classes={sum(r['classes'] for r in rows)} "
          f"dense-work={dense} sparse-work~{sparse} ratio~{dense / max(sparse, 1):.1f}x")
    for row in sorted(rows, key=lambda r: -r["dense"])[:args.top]:
        print(f"  blocks={row['blocks']:5} atoms={row['atoms']:5} classes={row['classes']:5} "
              f"dense={row['dense']:9} sparse~{row['sparse']:7} "
              f"ratio~{row['dense'] / max(row['sparse'], 1):.1f}x check={row['check_seconds']:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
