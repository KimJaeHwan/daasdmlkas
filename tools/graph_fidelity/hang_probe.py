"""Probe a long-running interprocedural analysis (WSL).

usage: hang_probe.py <generation> [seconds] [--assume-boundary-effects]
Runs run_dfbench's analysis for ``seconds`` (default 120) while counting
calls and distinct argument identities of suspected hot functions in the
interprocedural layer, then prints the counts every 20 s and exits. A
growing call count with a flat distinct count means repeated identical work
(missing memoization); both growing means an expanding search.
"""

from __future__ import annotations

import collections
import functools
import importlib
import os
import sys
import threading
import time
import traceback
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "bundle_export"))

TARGETS = {
    "tdo_v2.integration.configured_write_event_engine": (
        "_stabilized_write_events", "_caller_write_events", "_callee_write_events",
    ),
    "tdo_v2.integration.configured_function_memory": (
        "resolve_local_pointer_prefix", "latest_definition", "_latest_definition",
    ),
    "tdo_v2.integration.configured_origin_projection": (
        "_value_origins", "_origins_from_latest_state", "_origins_from_parent_entries",
    ),
}
calls = collections.Counter()
distinct: dict[str, set] = collections.defaultdict(set)
depth = collections.Counter()
max_depth = collections.Counter()


def _identity(args, kwargs):
    try:
        return hash((tuple(id(a) if not isinstance(a, (int, str, tuple)) else a for a in args),
                     tuple(sorted(kwargs.items()))))
    except TypeError:
        return id(args[0]) if args else 0


def _wrap(name, function):
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        calls[name] += 1
        if len(distinct[name]) < 2_000_000:
            distinct[name].add(_identity(args, kwargs))
        depth[name] += 1
        max_depth[name] = max(max_depth[name], depth[name])
        try:
            return function(*args, **kwargs)
        finally:
            depth[name] -= 1
    return wrapper


def _install():
    for module_name, names in TARGETS.items():
        module = importlib.import_module(module_name)
        for name in names:
            target = module
            attribute = name
            if not hasattr(module, name):
                # methods: search classes
                for value in vars(module).values():
                    if isinstance(value, type) and name in vars(value):
                        setattr(value, name, _wrap(f"{value.__name__}.{name}", vars(value)[name]))
                continue
            setattr(target, attribute, _wrap(name, getattr(module, name)))


def main() -> int:
    generation = sys.argv[1]
    seconds = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 120
    assume = "--assume-boundary-effects" in sys.argv
    _install()
    main_thread = threading.main_thread().ident
    started = time.time()

    def report():
        while True:
            time.sleep(20)
            elapsed = time.time() - started
            frame = sys._current_frames().get(main_thread)
            stack = [f"{item.name}" for item in traceback.extract_stack(frame)][-6:]
            print(f"--- {elapsed:.0f}s  stack: {' > '.join(stack)}", flush=True)
            for name in sorted(calls, key=lambda key: -calls[key]):
                print(f"  {name:45} calls={calls[name]:10} distinct={len(distinct[name]):9} "
                      f"max_depth={max_depth[name]}", flush=True)
            if elapsed >= seconds:
                os._exit(0)

    threading.Thread(target=report, daemon=True).start()
    import run_dfbench
    sys.argv = ["run_dfbench.py", generation, "--json", "/tmp/hang_probe.json"] + (
        ["--assume-boundary-effects"] if assume else [])
    run_dfbench.main()
    print(f"--- finished in {time.time() - started:.0f}s", flush=True)
    for name in sorted(calls, key=lambda key: -calls[key]):
        print(f"  {name:45} calls={calls[name]:10} distinct={len(distinct[name]):9} max_depth={max_depth[name]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
