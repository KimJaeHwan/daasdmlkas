"""Profile normalization of one Bundle function (WSL).

usage: ~/venvs/tdo/bin/python tools/graph_fidelity/profile_function.py <generation> <entry-hex> [top]
"""

from __future__ import annotations

import cProfile
import pstats
import sys
from hashlib import sha256
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

from tdo_v2.configured_naming_contracts import (  # noqa: E402
    CALL_NAMING_GHIDRA_VERSION, NamingBindingExpectation,
)
from tdo_v2.integration.configured_bundle import admit_frozen_bundle  # noqa: E402
from tdo_v2.integration.observed_function_session import open_observed_function_session  # noqa: E402
from tdo_v2.normalize import FunctionNormalizer  # noqa: E402


def main() -> int:
    generation, entry = Path(sys.argv[1]), int(sys.argv[2], 16)
    top = int(sys.argv[3]) if len(sys.argv) > 3 else 30
    binding = NamingBindingExpectation(
        sha256((REPO / "ghidra" / "GhidraV2CallNaming.java").read_bytes()).digest(),
        CALL_NAMING_GHIDRA_VERSION,
    )
    with open_observed_function_session(admit_frozen_bundle(generation), naming_binding=binding) as session:
        for evidence in session.iter_functions():
            if evidence.unit.scopes.function.entry.byte_offset != entry:
                continue
            profile = cProfile.Profile()
            profile.enable()
            FunctionNormalizer().normalize(evidence.unit)
            profile.disable()
            pstats.Stats(profile).sort_stats("cumulative").print_stats(top)
            return 0
    print("entry not found", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
