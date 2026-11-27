# S3 -- kernel boundary OS contract in the F tier, standalone -- r16 (2026-11-24)

Status: DRAFT r16, review round 6 (S3 only). Owner 2026-11-24: finish S3 first; K0 (fixed addresses outside the image)
gets its own design later with a different approach (rounds 3-5 kept finding constant-address forwarding paths).
This text is **self-contained** and replaces the S3 parts of r13 / r14 / r15 (`design_k0_s3_r13..15.md`); the K0 parts
of those documents are input for the K0 design only. Reviews of the S3 parts so far: Astra r11-r15
(`scc_r11_astra1.md` .. `scc_r15_astra5.md`), Fable r11-r15 (`scc_r11_fable1.md` .. `scc_r15_fable5.md`). Base main 18a5f5e.

## 0. Decisions

* Owner 2026-11-16 / 11-17: the kernel boundary gets a named OS-contract model in F; minimal contract (continuation,
  RSP unchanged, every other register unknown, memory unknown), label `os-contract:windows-x64-kernel@v1` in support.
* Owner 2026-11-24: ON by default in both profiles (code-only through its allowlist); recognition by instruction bytes
  (producer independence, no translator premise); no ABI; no OS names in engine src (OS identity in the model file).
* Scope note: in ntdll the service stubs also read the page 0x7FFE0000 and are refused today until K0; S3 alone acts
  on stubs without that read -- direct system calls in samples (`mov r10, rcx; mov eax, N; syscall; ret`) and any
  stub form without the page test.

## 1. Kernel-byte rows and the one decision

### 1.1 Candidates
* Applicability (image facts, sealed): `pe_header_facts(original.bin)` (a named header reader next to
  `exception_directory.py`'s PE parsing) reports PE32+ magic, COFF machine 0x8664 and subsystem 1 / 2 / 3. Any other
  image: no candidates at all (x86-32 `int 2e` is never considered).
* A **kernel-byte row** is an admitted row whose instruction start (the row address) holds, in the Bundle's sealed
  block bytes, exactly `0F 05` (`syscall`) or `CD 2E` (`int 2e`) with no prefix byte before it in the row. The byte
  test runs **before** any length test (Astra r5 P1-4): a row with these two bytes at its start is a kernel-byte row
  whether or not it carries `length`.
* Every admitted Bundle carries `original.bin` (required manifest member) and the bytes of every committed initialised
  block (where code rows live); template derivation opens the frozen Bundle and passes this evidence separately from
  its disabled read-only value folding (`tools/derive_models/derive_models.py:143, 167, 213`). A run that cannot read
  them refuses (configuration error), never "no sites". The original's SHA-256 is in the normalization identity of every
  function with a kernel-byte row.

### 1.2 `kernel_site_decision(row, observation, program) -> ADMITTED | DECLINED(reason)`
Computed once per kernel-byte row, before normalization and before any model / marker / intrinsic map is built. A row
is **ADMITTED** only when all hold, else **DECLINED** with the first failing reason:
1. `length` present and equal to 2.
2. Exact p-code: `syscall` = exactly one op, `CALLOTHER`, all inputs constant, no output; `int 2e` = exactly
   `t = CALLOTHER(c...)` with `t` a UNIQUE of 8 bytes, then `CALLIND t` with `t` its sole input and no output, no
   `RETURN`, and `t` read nowhere else in the row. (A different but correct lifting is DECLINED, not refused.)
3. Flow: observed fallthrough present, `flow.has_fallthrough` true, fallthrough = `address + 2`, no flow override, no
   flow target -- including EXTERNAL targets the validator drops: the raw row's "had an external target" flag is kept
   in the validated observation and its digest (`_scope_observation.py:545`, `_scope_wire.py:330`) -- no
   `exception_targets`, the source not in S1 `fallthrough_exits` (`function_summary.py:684`), and the next row a local
   row of the same function.
4. RSP resolvable from register evidence (`isa_identity.py:65`, name `RSP`, 8 bytes).
5. Switch `kernel-boundary-contract` ON.
No kernel-byte row ever refuses its function (Fable r5 P2-2, Astra r5 P2): contradictions decline.

### 1.3 Precedence (switch ON)
Every operation of a kernel-byte row (ADMITTED or DECLINED) is decided **only** by its S3 decision: the builders of
code-only pcodeop markers (`pcodeop_models.py:57, 81`, `code_only_profile.py:66`), trap premises and intrinsic
refinements skip those operations; `assumed_call_effects` for proofs are built from the same maps; the delta checker
(`register_delta_proofs.py:132, 147, 158, 165-178, 229, 237, 294-298`) refuses any kernel-byte row whose decision is
not ADMITTED and treats an ADMITTED one only through its effect. `normalize.py:1805-1809` never sees a key in both maps.
**Switch OFF: no decisions, no suppression -- exactly today** (incl. `CALLOTHER(17)` marker behaviour), the gate
identity test compares OFF with main 18a5f5e.

## 2. One effect function, two outcomes (switch ON)

`kernel_site_effect(row, decision)` produces the row's only effect, keyed by the CALLOTHER (`syscall`) or the CALLIND
(`int 2e`, the CALLOTHER + CALLIND pair consumed as one effect).

| | ADMITTED | DECLINED |
|---|---|---|
| continuation | observed fallthrough (no added edge) | observed fallthrough kept as a successor, **continuation unknown** (key below) |
| `preserved` | exactly the RSP span | nothing |
| `stack_restoration` | UNKNOWN | UNKNOWN |
| other registers incl. RFLAGS / vectors | opaque clobbers, debt on dependent reads | opaque clobbers incl. RSP |
| memory | RAM-class unknown-address writer (B' `memory-writes` key, may-alias debts) | WILD writer |
| `preserves_memory` / `clobbers_below` / `escapes_stack` | False / True / True | False / True / True |
| `control_sites` | `control:<f>:<space>:<offset>:kernel-return` | `control:<f>:<space>:<offset>:kernel-declined` |
| premise use | `os-contract:windows-x64-kernel@v1` | none |
| callee id | `kernel:<model id>@<version>` (synthetic, never a function key, never in call graphs / SCC) | same id with `:declined` |

* `control_sites` reach support in both effect representations (`summary_engine.py:1004-1007`);
  `continuation:<f>:*` follows by the existing rule (`function_summary.py:664-666`). A DECLINED row's key makes every
  dependent root non-complete (Astra r5 P1-5: a constant root after a declined `syscall` is never complete).
* Report-time invariant: every kernel-byte row has its effect in both representations, its writer in the B' / write
  inventory, and its key in the function's support; anything missing is `ControlSupportViolation`.
* Static inventories from round 1: every kernel-byte row is a static memory writer and wildcard holder
  (`control_context.py:169-171`, `fault_premise.observed_calls` :134-135) and counts for `relies_on_graph`
  (`interprocedural.py:795-802`); its key enters `binding_support()` before cut selection (`interprocedural.py:757, 804,
  1332, 1354`).
* Delta proofs: effects whose `control_sites` hold a `kernel-return` or `kernel-declined` key are refused by
  `derive_register_delta_proof` (fingerprint gains the key list, `register_delta_proofs.py:80-85`); `memory-writes`
  keys keep today's behaviour. Certificate counts before / after reported on the gate.
* The saved return address lies in unknown memory: a stub's later `ret` target is not proven (RETURN-as-exit premise
  unchanged; RP follow-up).

## 3. Switch, profiles, templates, reports

* `kernel-boundary-contract` (kind model) is wired explicitly into `switches()` (`assumptions.py:403`), the code-only
  vector (`code_only_profile.py:90`) and template serialization (`summary_templates.py:1050`). Default ON in the default
  profile; the code-only profile admits it through an allowlist entry (model id, version, file SHA-256, label in
  `ALLOWED_LABELS`) and turns it on by default. docs/assumptions.md row with failure modes (another kernel / Wine /
  emulators, a process instrumentation callback, a debugger setting the context, a modified kernel).
* Templates (Fable r5 P2-3, Astra r5 P2): a function whose template closure (the function and every callee summary it
  consumed) contains a kernel-byte row is **not exported** in this step (S3-T follow-up), so no decision ever has to
  be matched on import. Every template records the S3 switch; import requires it to equal the consumer's
  (must-match in `code_only_profile.py:246`); template version bump refuses older templates.
* Run report and templates read the site kind from one function (`summary_engine.py:936`,
  `summary_templates.py:358`): `kernel-return`, `kernel-declined`.

## 4. Tests and verification

* Both encodings ADMITTED: `mov r10, rcx; mov eax, N; syscall; ret` and the `int 2e` form -- the caller gets SP
  restoration under the labels; no delta proof; invariant parts present.
* DECLINED by each 1.2 reason (no `length`, prefixed, other lifting incl. `CALLOTHER(17)` and a `COPY` lifting, flow
  override, external target, listed exit, non-local next row, no RSP evidence): opaque effect with the declined key; no
  marker claim; no proof; no complete root after it.
* Precedence in proof replay: a declined row never yields an RSP certificate.
* Switch OFF: gate identity with main 18a5f5e; code-only allowlist round trip; template refusal for closures with
  kernel-byte rows; switch must-match on import.
* Measurement: gate Bundles (kernel-byte rows expected 0 -> no change), ntdll closure (admitted / declined counts;
  stubs still refused until K0), a direct-syscall sample if available in the field corpus.
* Verification tiers as usual; code review Astra + Fable; owner OK for merge.

## 5. Findings -> fixes (S3 parts, rounds 3-5)

| finding | fix |
|---|---|
| Astra r5 P1-4 (byte test before length; missing length; external-target flag) | 1.1, 1.2 (1, 3) |
| Astra r5 P1-5 (declined syscall continuation obligation) | 2 (DECLINED column, key, invariant) |
| Fable r5 P2-2 / Astra r5 P2 (refusal vs producer independence, x86-32, OFF identity) | 1.1 applicability, 1.2 "never refuses", 1.3 OFF = today |
| Fable r5 P2-3 / Astra r5 P2 (template decision matching) | 3 (closure not exported, switch must-match) |
| Astra r4 P1-4 / Fable r4 P2-4 (decline vs proofs, precedence) | 1.3, 2 delta proofs |
| Astra r4 P1-5 (S3-OFF templates in ON runs) | 3 |
| Astra r4 P2 / Fable r4 P2-3 (bytes in derivation runs) | 1.1 |
| Astra r3 Q2 P1-1..3, Fable r3 (shape, flow, RSP, numeric models, binding support, callee id, proof scope) | 1.2, 1.3, 2 |
| Astra r3 P2 / P3 (switch wiring, report kind) | 3 |
