"""The time spent in G2b's own code during one decode_check run (wrappers around code_facts entry points)."""
import sys
import time
from pathlib import Path

WT = Path(sys.argv[1])
sys.path[:0] = [str(WT / "src"), str(WT / "tools/decode_check")]
import code_facts  # noqa: E402
import decode_check as dc  # noqa: E402

spent = {}


def wrap(owner, name):
    real = getattr(owner, name)

    def timed(*args, **kwargs):
        t = time.perf_counter()
        try:
            return real(*args, **kwargs)
        finally:
            spent[name] = spent.get(name, 0.0) + time.perf_counter() - t
    setattr(owner, name, timed)


for name in ("trap_outcome", "decoder_flows", "file_facts", "name_table", "summary"):
    wrap(code_facts, name)
for name in ("program_code",):
    wrap(code_facts.CodeBinder, name)
start = time.perf_counter()
out = Path(sys.argv[3])
dc.run(Path(sys.argv[2]), WT / "ghidra" / "GhidraV2CallNaming.java", True, False, out / "own.evidence5.json",
       True, True, out / "own.facts.json")
total = time.perf_counter() - start
print(f"total run() {total:.1f} s")
for name, seconds in sorted(spent.items(), key=lambda kv: -kv[1]):
    print(f"  {name:16s} {seconds:7.2f} s  {100 * seconds / total:5.1f}%")
print(f"  G2b own total    {sum(spent.values()):7.2f} s  {100 * sum(spent.values()) / total:5.1f}%")
