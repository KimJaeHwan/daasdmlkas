import json, sys, time
from collections import Counter
from pathlib import Path
WT = Path(sys.argv[1]); sys.path[:0] = [str(WT / "src"), str(WT / "tools/decode_check")]
import check, code_facts as cf2
for gen in sys.argv[2:]:
    g = Path(gen)
    m = json.loads((g / "manifest.json").read_bytes())
    path = next(r["path"] for r in m["members"] if r["id"] == m["original_member_id"])
    raw = (g / path).read_bytes()
    t = time.time()
    image = check.parse_original(raw)
    ff = cf2.file_facts(image, raw)
    names = Counter(i["name"] for i in ff.imports.values())
    interesting = sorted(n for n in names if any(k in n for k in ("VirtualProtect", "GetProcAddress", "VirtualAlloc", "mprotect", "dlsym", "mmap", "RtlAddFunctionTable", "FlushInstructionCache", "WriteProcessMemory", "register_frame", "clear_cache", "LdrGetProcedure")))
    print(f"== {g.parent.name} {ff.format} ok={ff.ok} {time.time()-t:.2f}s code={[(r.name, hex(r.start), hex(r.end), r.writable) for r in ff.code]}")
    print(f"   unwind regions={len(ff.unwind)} bytes={sum((r.end or r.start) - r.start for r in ff.unwind)} diags={Counter(d['reason'] for d in ff.diagnostics)}")
    print(f"   imports={len(ff.imports)} state={ff.import_state} problems={Counter(p['reason'] for p in ff.import_problems)} slot_failures={Counter(ff.slot_failures.values())}")
    print(f"   interesting={interesting}")
