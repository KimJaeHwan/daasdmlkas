"""Generate models/external/crt_aarch64_android.json (run from the repository root): the C runtime declared models of crt_sysv64.json carried to
AArch64 / AAPCS64 (Android bionic), plus the C++ runtime operator new / delete. Hand models (declared assumptions):
to be replaced by models derived from the device's libc.so / libc++.so where their code is analyzable."""
import json
from pathlib import Path

src = json.loads(Path("models/external/crt_sysv64.json").read_text(encoding="utf-8"))

X = lambda n: 0x4000 + 8 * n          # AArch64 register file offsets (exported register evidence)
SYSV_TO_A64 = {56: X(0), 48: X(1), 16: X(2), 8: X(3), 0: X(0)}   # rdi, rsi, rdx, rcx, rax


def carry(value):
    """Translate every [offset, size] register slice of an entry."""
    if isinstance(value, list) and len(value) == 2 and all(isinstance(item, int) for item in value) \
            and value[0] in SYSV_TO_A64 and value[1] == 8:
        return [SYSV_TO_A64[value[0]], 8]
    if isinstance(value, list):
        return [carry(item) for item in value]
    if isinstance(value, dict):
        return {key: carry(item) for key, item in value.items()}
    return value


def bionic_text(text):
    return (text.replace("rdi", "x0").replace("rsi", "x1").replace("rdx", "x2")
            .replace("glibc's", "bionic's").replace("glibc", "the C library"))


BIONIC_EVIDENCE = ("ISO C17 / POSIX semantics as implemented by Android bionic (AOSP libc); hand model carried "
                   "from crt-sysv64 v8 on 2026-10-30, NOT yet audited against the device libc.so "
                   "(Android 9, SM-G955N, saved for derivation)")

BIONIC_HOOKS = "bionic malloc hooks / malloc debug (libc.debug.malloc.*, malloc_hooks: __malloc_hook, __free_hook, ...)"
entries = []
for entry in src["entries"]:
    item = carry(entry)
    item["notes"] = bionic_text(item["notes"])
    if "callbacks_evidence" in item:
        item["callbacks_evidence"] = BIONIC_EVIDENCE
    if isinstance(item.get("callbacks"), dict):
        registered = item["callbacks"].get("registered", [])
        item["callbacks"]["registered"] = [
            BIONIC_HOOKS if "hook" in row.lower()
            else bionic_text(row) + " (carried from glibc: bionic's longjmp not audited; kept as declared handlers)"
            if "_longjmp_unwind" in row else bionic_text(row) for row in registered]
    entries.append(item)

malloc = next(item for item in entries if item["name"] == "malloc")
free = next(item for item in entries if item["name"] == "free")
new = json.loads(json.dumps(malloc))
new.update(name="_Znwm", aliases=["_Znam"],
           notes="C++ operator new(size_t) / new[](size_t) (libc++): returns a new block's address of x0 bytes "
                 "(no program data flows into it; fresh), or does not return normally (throws std::bad_alloc: "
                 "exception paths are not modeled -- the call is taken to return); null is still allowed (no "
                 "never-null claim). Heap bookkeeping is not program-visible memory (assumption).",
           callbacks={"registered": ["std::set_new_handler handler (invoked on allocation failure)",
                                     BIONIC_HOOKS + " (operator new calls malloc)"]},
           callbacks_evidence="ISO C++17 [new.delete.single] / [new.handling]; libc++ new.cpp (calls malloc); "
                              "bionic malloc_hooks (API 28+); hand model 2026-10-30, NOT yet derived from the "
                              "device libc++.so")
delete = json.loads(json.dumps(free))
delete.update(name="_ZdlPv", aliases=["_ZdaPv"],
              notes="C++ operator delete(void*) / delete[](void*) (libc++): releases x0's block. Assumes no use "
                    "after free. Uses no pointer it receives on program-visible memory (observes nothing).",
              callbacks={"registered": [BIONIC_HOOKS + " (operator delete calls free)"]},
              callbacks_evidence="ISO C++17 [new.delete.single]; libc++ new.cpp (calls free); bionic malloc_hooks "
                                 "(API 28+: __free_hook); hand model 2026-10-30, NOT yet derived from the device "
                                 "libc++.so")
entries += [new, delete]

model = {
    "format_version": 1,
    "kind": "declared",
    "id": "crt-aarch64-android",
    "version": 1,
    "language_id": "AARCH64:LE:64:v8A",
    "abi_tag": "aapcs64",
    "notes": "C runtime (Android bionic) and C++ runtime (libc++) functions under AAPCS64 (args x0, x1, x2, x3; "
             "result x0; the call writes x30 and moves no stack pointer). Preserved: x19-x29 (AAPCS64 6.1.1 "
             "callee-saved -- a declared assumption of this file, like every entry). Carried from crt-sysv64 v8; "
             "hand models to be replaced by models derived from the device's libc.so / libc++.so where their "
             "code is analyzable (walls: allocator internals, system calls, ifunc dispatch stay declared).",
    "stack_pointer": [8, 8],
    "stack_delta": 0,
    "preserved": [[X(n), 8] for n in range(19, 30)],
    "entries": entries,
}
Path("models/external/crt_aarch64_android.json").write_text(json.dumps(model, indent=1) + "\n", encoding="utf-8",
                                                              newline="\n")
print(len(entries), "entries:", [item["name"] for item in entries])
