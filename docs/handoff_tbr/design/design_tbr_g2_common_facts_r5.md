# TBR G2 -- x86 / ARM common fact layer, consolidated design r5 (2026-11-27)

One self-contained document: r4 with the replacement text Astra drafted on the owner's instruction ("when Astra
rejects, have Astra write it; Claude reviews"). Sources: Astra's verification REJECT `g2_design_astra5.md`
(6 P1, 5 P2), Fable's APPROVE with 4 P3 `g2_design_fable6.md`, Astra's drop-in blocks `g2_design_astra6_draft.md`
(sections 2, 3.1-3.8, 4-8 and G2a replaced; s0, s1, G2b, G2c as in r4), reviewed by Claude for consistency with
the rest of the design and the project principles (no return, no OS resumption decision and no premise default
stated by TBR; claims in the facts file, verdicts in -4). Earlier: r4 folded g2_design_astra4.md /
g2_design_fable5.md; rounds g2_design_astra1-3.md, g2_design_fable1-4.md. Stage G2 of
docs/ghidra_independence_plan.md. TBR format design; engine reading is main-session work after S3.

## 0. Necessity, and how the effect is measured

**Necessity**, measured on today's Bundles (ntdll, UE core probe, zlib, clang-x64-O2, v3-win-release):
1. **The engine derives call relations from Ghidra's p-code shapes.**
   - `call_relations.py` matches the x86 push shape and the AArch64 `x30 = inst_start + 4` shape, then fills
     `CallRelation`: sp, link, delta, continuation, relocation, length, entry_ordinal, setup_ops, transient_ops.
   - 59 engine files key on CALL / CALLIND / RETURN, and 37 read Ghidra flow bits.
   - A producer with other shapes loses these relations silently.
2. **Rows resting on Ghidra's CALL / CALLIND / RETURN labels:** ntdll 8,083; UE 26,422.
   - Rows with an x86 push link: ntdll 6,331; UE 20,779.
   - CALL + CALLIND exceeds the push count by 145 in ntdll and by 2 in UE (a G2a parity class, s9).
3. **The code-bytes premise `image-code-unmodified-at-runtime`** (assumptions.py:100: runtime, default on, no
   separate switch) has no facts behind it in the Bundle.
   - ntdll and UE import VirtualProtect / VirtualAlloc / FlushInstructionCache (UE also mprotect); v3-win-release
     imports VirtualProtect.
   - No sampled PE has a writable+executable section.
4. **Exported targets outside the exported rows** (ntdll 1,037; UE 590) are unclassified.
   - These Ghidra Bundles have no mid-row target. That says nothing about overlap: Ghidra's listing avoids
     overlaps.
5. **No ARM-side TBR facts**, while the Android corpus has PAC / BTI code.

**Effect: measured per phase (s9), not claimed in advance.**
- **Known limit:** direct-target verdicts need every voter's own report, and XED's targets are computed by G1, so
  they stay unobserved until an XED shim reports its own target.
- Today's voters also give `target_kind = register` but not the register's name, so pre-register target verdicts
  are unobserved too.

## 1. Scope and policy

- Facts on top of p-code; effects stay in p-code.
- Claims only in the facts file (`source: "producer" | "derived"`). A fact TBR derives from a Ghidra Bundle is still
  a claim.
- Verdicts only in G1 evidence `-4` (s8).
- **TBR never states:**
  - a return: a call's continuation is `link_write`, and only TDO decides a return from evidence that an indirect
    target equals the continuation at entry;
  - whether the OS resumes at an address (the OS-contract model);
  - a default state for any premise. TDO's registry governs: today `image-code-unmodified-at-runtime` is default
    on. A future reader policy (for example "needs proof" for a range and a period) is the reader's, not this
    format's [F5-7, A4-11].
- **Out of scope:**
  - x86-32 and AArch32 / Thumb;
  - multi-row link writes (`adr x30, L; br x16`);
  - far call / jmp forms (FF /3, FF /5 m16:64 push CS:RIP, two slots): kind `unknown` [F5-P3-1];
  - unpacking and re-decoding written bytes;
  - the engine reader;
  - an ARM voter (a follow-up).

## 2. Document structure and common JSON rules [A4-9]

```
{"schema": "tbr-common-facts-1", "source": "producer" | "derived",
 "bundle": {"generation_id", "manifest_sha256"}, "producer": {...identity...},
 "program": {"isa": "x86-64" | "aarch64", "address_spaces": [...],
             "stack_register": reg | {"unobserved": reason}, "code": {...s5...}, "tbi": {...s7...}},
 "rows": [row, ...]}

row = {"id": "space:offset:length:view", "space", "offset", "length", "view",
       "observation": "function observation id",
       "transfer": {...s3...}, "bytes": {"range": [start, end), "holds_if": "image-code-unmodified-at-runtime"},
       "isa": [...s6...], "vendor_views": null | {"intel": vview, "amd": vview}}

row_ref = {"id": "space:offset:length:view", "observation": "function observation id"}
U = {"unobserved": reason}
```

- Addresses are `{"space": int, "offset": "hex"}`. Registers are `{"space", "offset", "size"}` plus a display
  name. Register size and memory size are in bytes. Value widths are in bits. Byte displacements are signed
  integers. Ranges are half-open, in one address space and load-base context.
- An absent field makes no claim. `U` explicitly records why the producer cannot state a value. `null` has
  only the meaning assigned to that position by the schema. It can denote an inapplicable field, the absence
  of an edge guard, or a required edge with no concrete address. The last two are comparable values in s8.
  A missing required edge has its own rule in s3.2 and s8.
- `(id, observation)` identifies one row in this Bundle. The components encoded in `id` must match the row.
  Length in `id` is the producer's length. A vendor length belongs to its named `vendor_views` member.
  Equal ids in different function observations are permitted. A duplicate `(id, observation)` is invalid.
- Every reference outside its containing row uses `row_ref`, including site rows, landing rows, survey rows
  and both ends of a BTI pair. An op resolves within exactly one such row. For a vendor-specific value the
  lookup also retains the `vendor_views.intel` or `vendor_views.amd` path through the entire comparison.
- Sort rows and sets of row references by `(id, observation)` in ascending string order. Sort edges and
  keyed unobserved edges by the rule in s3.2. Within one row, op lists are in ordinal order. Operand lists
  retain operand order. The facts digest is SHA-256 of the canonical UTF-8 JSON bytes with sorted object
  keys and no insignificant whitespace. Explicit `null`, `U` and absence have distinct encodings.

## 3. Control transfer

### 3.1 The form table: one normalization for producer and verifier [A4-1, F5-3]

The producer uses its own decode. G1 applies the same table to the voters' consensus form, within the named
vendor when applicable. A split or missing vote leaves the affected comparison unobserved. It never edits
the producer's claim.

Each edge below is `when / source / requires`. A dash in the guard position means the JSON value `null`.
Each `trap_return` has the guard `os-contract`. A dash in the extras column means no form-specific extra.
An ordinary non-transfer form must be positively identified. An unsupported or unclassified form has
`kind: "unknown"` and `edges: []`.

| form | kind | required edges | link_write / extras |
|---|---|---|---|
| x86 recognized no transfer, including REP, CMOV and lift-internal flow | none | always / sequential / — | — |
| x86 Jcc, JRCXZ / JECXZ, LOOP / LOOPE / LOOPNE and aliases | conditional | taken / encoded_target / —, not_taken / sequential / — | condition (s3.4) |
| x86 near direct JMP | direct | always / encoded_target / — | — |
| x86 near direct CALL | direct | always / encoded_target / — | push link |
| x86 near indirect CALL | indirect | always / computed / — | push link, target_value |
| x86 near indirect JMP, near RET including imm | indirect | always / computed / — | target_value |
| x86 IRET, far RET | indirect | always / computed / — | target_value, or `U` |
| x86 SYSCALL, INT n, INT3, INT1 | trap | trap / os / —, trap_return / os_return / os-contract | s3.3 |
| x86 SYSENTER | trap | trap / os / —, trap_return / os_return / os-contract | no saved PC (s3.3) |
| x86 HLT | trap | trap / os / —, trap_return / os_return / os-contract | F2 (s3.3) |
| x86 UD2, encoding invalid in this mode | trap | trap / os / — | exception_basis |
| x86 XBEGIN | conditional | normal_entry / sequential / normal-transaction-start, abort / encoded_target / outermost-transaction, abort / computed / nested-transaction | `condition: null` |
| A64 B | direct | always / encoded_target / — | — |
| A64 BL | direct | always / encoded_target / — | register link x30 |
| A64 BR | indirect | always / computed / — | target_value, `target_auth: null` |
| A64 BRAA / BRAB / BRAAZ / BRABZ | indirect | always / computed / — | target_value, target_auth |
| A64 BLR | indirect | always / computed / — | register link x30, target_value, `target_auth: null` |
| A64 BLRAA / BLRAB / BLRAAZ / BLRABZ | indirect | always / computed / — | register link x30, target_value, target_auth |
| A64 RET | indirect | always / computed / — | target_value from the encoded register, x30 by default, `target_auth: null` |
| A64 RETAA / RETAB | indirect | always / computed / — | target_value from x30, target_auth with pre-state SP modifier |
| A64 B.cond, CBZ / CBNZ, TBZ / TBNZ | conditional | taken / encoded_target / —, not_taken / sequential / — | condition (s3.4) |
| A64 BTI, hint-space PAC including PACIASP / AUTIASP | none | always / sequential / — | ISA facts, including the F4 split |
| A64 other recognized non-transfer forms, including LDXR / STXR | none | always / sequential / — | applicable ISA facts, including `exclusive` (s6) |
| A64 SVC | trap | trap / os / —, trap_return / os_return / os-contract | s3.3 |
| A64 HVC / SMC | trap | trap / os / —, trap_return / os_return / os-contract | F2 (s3.3) |
| A64 BRK | trap | trap / os / —, trap_return / os_return / os-contract | saved PC is the BRK address |
| A64 HLT | trap | trap / os / —, trap_return / os_return / os-contract | external-debug halt or UNDEFINED, F2 / F3 |
| A64 UDF | trap | trap / os / — | exception_basis `defined_ud` |
| A64 ERET | indirect | always / computed / — | target_value from pre-state ELR_ELx on the EL1+ path, F2 |

- A recognized UD2 / UDF has `exception_basis: "defined_ud"`. An encoding the decoders identify as invalid
  in this mode, including INTO in x86-64, has `exception_basis: "invalid_encoding"` with F1 evidence.
- The specific transfer and trap rows take precedence over the ordinary non-transfer rows. The far CALL /
  JMP forms excluded by s1 remain `unknown`.
- A producer may claim `terminate` with its own proof. No consensus form in this table derives `terminate`.
  With a decided form, `-4` contradicts that kind.

### 3.2 Edges [A4-2, A4-3, F5-5]

```
edge_key = {"when": "always" | "taken" | "not_taken" | "normal_entry" | "abort" | "trap" | "trap_return",
            "source": "sequential" | "encoded_target" | "computed" | "os" | "os_return",
            "requires": null | "os-contract" | "normal-transaction-start"
                             | "outermost-transaction" | "nested-transaction"}

edge = {<edge_key>, "to": addr | null | U, "lands_on": lands_on | U}
     | {<edge_key>, "unobserved": reason}

"edges": [edge, ...]
```

`<edge_key>` denotes the three named members at the top level of the object. A producer that cannot state an
entire required edge can still identify its role. For example, this is a single unobserved nested-abort edge:

```
{"when": "abort", "source": "computed", "requires": "nested-transaction",
 "unobserved": "no observation of this edge"}
```

A placeholder has no `to` or `lands_on`. An ordinary edge whose address alone is unknown retains its key and
uses the `to` rule below. A bare `U` cannot identify an edge.

- Match one member per required triple, including the guard. Preserve both roles when two targets coincide.
  A missing triple, a duplicate or an extra triple is a set difference. A placeholder occupies its own triple
  once and leaves its edge claim unobserved.
- Sort by `when` in the order always, taken, not_taken, normal_entry, abort, trap, trap_return. Break ties by
  `source` in the order sequential, encoded_target, computed, os, os_return, then by `requires` in the order
  null, os-contract, normal-transaction-start, outermost-transaction, nested-transaction. Apply the same
  order to placeholders and to each vendor's edges.
- `sequential.to` is PC + length in this view. `encoded_target.to` is the encoded destination in this view.
  Use `U` if the applicable address cannot be stated. A call has no sequential edge.
- `computed.to` and `os.to` are required literal `null`. An indirect operand can have a `target_value` even
  though `computed.to` is null. The nested XBEGIN fallback belongs to the outermost transaction and has
  `computed.to: null` at the nested instruction. [Intel SDM, XBEGIN](https://cdrdv2-public.intel.com/929356/334569-093-sdm-vol-2d.pdf)
- `os_return.to` follows s3.3. `requires` is the edge guard. Only ordinary taken / not_taken forms use the
  transfer-level predicate in s3.4.

### 3.3 Trap resumption: saved PC versus OS choice [F5-4, A4-8]

`trap / os` always has `to: null`. Where the form requires `trap_return / os_return`, its guard is always
`os-contract`, including when its `to` is null. An address on this edge describes the architecturally saved
PC on the specified path. TBR makes no OS resumption decision.

| form and condition | architectural PC evidence | `os_return.to` |
|---|---|---|
| x86 SYSCALL, INT n / INT3 / INT1, taken as that call or trap | next PC in RCX for SYSCALL, pushed next PC for INT | PC + verified length on that path |
| A64 SVC taken as a supervisor call | ELR holds the next PC | PC + 4 on that path |
| x86 SYSENTER | the instruction saves no continuation PC | literal `null`, comparable from the form |
| x86 HLT | CPL > 0 gives a #GP at the current PC. At CPL 0 an interrupt after halt can save the next PC | `null` with F2 for the condition-dependent form. With CPL or path undecided, the saved address is unobserved |
| A64 BRK taken as a breakpoint | ELR identifies the BRK instruction | current PC |
| A64 HVC / SMC | UNDEFINED at EL0, next PC on the enabled exception-call path | `null` with F2 for the condition-dependent form |
| A64 HLT | external-debug halt or UNDEFINED according to the debug controls | `null` with F2 / F3 |
| UD2, UDF, invalid encoding | fault at this instruction | no `os_return` edge |

The referenced F2 / F3 fact carries the execution condition for a condition-dependent form. Its null address
preserves the common row representation. It cannot confirm a concrete saved PC on an undecided path. For a
path-qualified address such as SVC's next PC, a missing basis for taking that path leaves the address
comparison unobserved.

### 3.4 Condition [A4-5]

```
"condition": null | U | {"test": bool_ref | U, "taken_when": "true"}
bool_ref = {"nonzero": value_ref} | {"zero": value_ref}
         | {"bit_set": [value_ref, n]} | {"bit_clear": [value_ref, n]}
         | {"flags": "cc name", "inputs": [value_ref, ...] | U}
         | {"op_output": op_ref}
```

`test` denotes the predicate for the `taken` edge. `taken_when: "true"` fixes its polarity. An `op_output`
must denote the whole Boolean predicate at its use and pass s3.5. The following expressions abbreviate the
typed nodes in s3.5.

| form | predicate when taken |
|---|---|
| x86 Jcc, A64 B.cond | `flags` for the encoded condition code, using the incoming flags. Keep the cc when the input identities are `U` |
| x86 JRCXZ / JECXZ | `zero(pre_register(counter))` on the original address-size-selected RCX / ECX |
| x86 LOOP | `nonzero(sub(pre_register(counter), constant(0x1)))`, with both inputs and the subtraction at address size |
| x86 LOOPE / LOOPZ | the same decremented counter is nonzero **and** incoming ZF is set |
| x86 LOOPNE / LOOPNZ | the same decremented counter is nonzero **and** incoming ZF is clear |
| A64 CBZ / CBNZ | `zero` / `nonzero` of the encoded register at operand width |
| A64 TBZ / TBNZ | `bit_clear` / `bit_set` of the encoded bit number in the operand |

In x86-64 the loop counter has width 64 or, with the address-size override, 32. The subtraction wraps at that
width. For LOOPE / LOOPNE the grammar has no conjunction node. Use a checked Boolean `op_output` covering
both inputs, or mark the test `U`. A counter-only test is wrong. [Intel SDM, LOOP and Jcc](https://cdrdv2-public.intel.com/868140/253666-089-sdm-vol-2a.pdf)

XBEGIN uses `condition: null`. Its three guards are compared on their edges. An unavailable predicate on an
ordinary conditional leaves the form, both edge keys and each independently known destination in place.

### 3.5 value_ref: typed, pre-state, reaching definitions [A4-5]

```
value_ref = {"pre_register": reg, "width": bits}
          | {"constant": "hex", "width": bits}
          | {"add" | "sub" | "mul": [value_ref, value_ref], "width": bits}
          | {"zext" | "sext" | "trunc": value_ref, "width": bits}
          | {"memory": {"space": int, "address": value_ref, "size": bytes,
                        "segment_base": null | value_ref}}
          | {"op_output": op_ref}
          | U
```

- A register leaf denotes its entry-state bytes. A constant is an unsigned bit string of the stated width.
  Arithmetic takes operands of the node width and wraps there. Use explicit extension or truncation to
  change width. Memory yields `8 * size` bits. An op reference obtains its width from the referenced output.
- On x86, `memory.address` contains only the effective offset. Compute base, scaled index and displacement
  at the decoded address size, truncating there. Zero-extend that offset to the linear-address width, then
  add `memory.segment_base` once at linear-address width. `null` supplies zero for a flat operand. An
  effective FS / GS override supplies its pre-state base, or `U` if that base cannot be identified.
  `memory.space` identifies the space of the resulting access.
- For an IP-relative operand, the effective offset is the view's next IP plus the sign-extended displacement,
  reduced to address size. With FS / GS the `address` member still contains just that offset. Only
  `segment_base` supplies FS / GS.
- Validate `op_output` at its actual use for both target and condition. Resolve the op in the same
  observation, row and view. Check output kind, space, byte range and width. Its definition must reach
  every consumed byte on every relevant path, without an intervening overlapping redefinition.
- Recursively check each defining op's inputs at that op. A register leaf used as pre-state must still
  denote the entry bytes there. A row-local definition can contribute only through its own checked
  expression. For example, a capture of old x30 before the link write can reach a later branch. A read of
  the overwritten x30 cannot establish that old target. A checked subtraction from the entry counter can
  establish the post-decrement LOOP test.
- For every LOAD in the chain, validate its address inputs, space and access width. Exclude a preceding
  STORE on any reaching path that may alias any byte of that load in that space. Unknown aliasing, an
  ambiguous definition or an unsupported operation leaves the dependent value `U` with a reason.
- Record failure at the affected value or test. The form still determines `when`, `source` and `requires`.
  In particular an unobserved Jcc test leaves its taken edge `encoded_target`.

### 3.6 link_write: one shape, with vendor views [F5-6, A4-4, F5-2]

```
"link_write": null | U | {
  "location": {"register": reg} |
              {"memory": {"space": int, "base": reg, "relative_to": "pre_sp", "slot_offset": signed_int}},
  "sp_delta": signed_int,
  "value": {"bits": "hex", "width": bits},
  "continuation": addr,
  "relocation": "instruction_relative" | "unknown",
  "derivation": "isa_next_ip" | "pc_plus_4" | "constant"}

vview = {"length": bytes | U, "bytes": [start, end) | U, "edges": [edge, ...],
         "link_write": <same link_write shape>, "target_value": null | value_ref}
```

- `slot_offset` and `sp_delta` are signed byte counts. A push claims a memory slot relative to pre-SP.
  Check `slot_offset == sp_delta == -(value.width / 8)` at the stated whole-byte width. A register link
  has `sp_delta == 0` and no slot offset.
- `value` is the stored bit string. `continuation` is the full next-instruction address in this view.
  Check `value.bits == continuation.offset mod 2^value.width` in the same address space. This consistency
  check alone verifies neither claim against a voter.
- Every G1 vendor split carries separate `intel` and `amd` members for the affected length, interval, edges
  including `lands_on`, link and target operand. Known families include 66 E8, 66 C3 / C2, 66 FF /2 and /4,
  66 E9 / EB and 66 Jcc rel16. Apply s2 field states within each member. An unsupplied vendor value cannot
  be filled from its sibling or from the producer's row length. A wholly unobserved edge uses the keyed
  placeholder in s3.2.
- In the 66 E8 vector at `0x140001000`, Intel has length 6, width 64, stored `0x140001006`, full continuation
  `0x140001006`, slot offset and SP delta both `-8`. AMD has length 4, width 16, stored `0x1004`, full
  continuation `0x140001004`, slot offset and SP delta both `-2`. G1 a7 compares width and stored bits.
  Verified length establishes the full continuation. G1 a5 concerns the direct callee destination alone.
- The x86 near-call push derives the link by `isa_next_ip`, with `instruction_relative` relocation even
  when the lift stores a constant. An A64 `INT_ADD` of instruction start and 4 uses `pc_plus_4` and
  `instruction_relative`. A bare constant COPY uses `constant` and `unknown`. A constant sum accepted by
  the engine with a base other than instruction start likewise has only constant derivation. The
  projection additionally requires the observed fallthrough and op checks in s3.8. [call_relations.py](wt_main/src/tdo_v2/call_relations.py)

### 3.7 target_value and target_auth [A4-13]

`target_value` is the indirect target operand in the pre-state (s3.5). An x86 indirect CALL reads it before
the push. `BLR x30` uses incoming x30 and writes the continuation to x30. For an authenticated form, record
the target operand and the authentication applied to it separately.

```
"target_auth": null | U | {
  "key": "ia" | "ib", "modifier": value_ref,
  "conditions": [{"what": "FEAT_PAuth" | "SCTLR_ELx.EnIA" | "SCTLR_ELx.EnIB",
                  "source": "profile" | "os_model", "state": "holds" | "does_not_hold" | "unknown"}],
  "on_failure": "F3 reference"}
```

- The encoding selects IA for the A-key variants and IB for the B-key variants. Record the selected key's
  effective enable control for the relevant EL. A profile can establish feature absence and an OS model can
  establish a disabled key. Both use `does_not_hold` for the corresponding condition. `unknown` means the
  named source cannot settle it.
- BRAA / BRAB and BLRAA / BLRAB use the pre-state modifier operand Xm or SP. Their Z forms use a
  pointer-width zero. RETAA / RETAB use pre-state SP in the supported profile. A FEAT_PAuth_LR variant
  outside that profile uses `U` with the profile reason.
- `on_failure` refers to the conditional F3 result in s6. A disabled key establishes no authentication
  failure. Feature absence on a non-hint encoding follows F1. Plain BR, BLR and RET have `target_auth: null`.

### 3.8 op references and the CallRelation projection [A4-6, A4-7, A4-9]

```
op_ref = {"row": row_ref, "ordinal": int, "opcode": "OPCODE"}

"op_keys": {"transfer": op_ref | null, "target": [op_ref, ...], "condition": [op_ref, ...],
            "auth": [op_ref, ...], "link": [op_ref, ...], "sp_adjust": [op_ref, ...],
            "setup": [op_ref, ...], "transient": [op_ref, ...], "persistent": [op_ref, ...],
            "entry_ordinal": int | null, "encoding_only": ["target_auth", "link_write", ...]}
```

Resolve the row, then check the opcode at the stated ordinal. The enclosing vendor path applies to a
vendor-specific use. `entry_ordinal` is the transfer ordinal, or null with a null transfer. `setup` lists
all operations before the transfer in order. `encoding_only` names exactly the facts with no supporting op.
A link claim established by the encoding survives a failed relation check.

**Push recognizer.** Apply the following checks to the observed instruction before projecting a Ghidra push
relation or marking its push effects transient.

1. Require call flow, an observed fallthrough, exactly one CALL or CALLIND in the instruction and no
   BRANCH, CBRANCH, BRANCHIND or RETURN before that call.
2. Require one accepted adjustment `INT_SUB R, constant(w) -> R`. The input and output register varnodes
   match exactly and `w` equals the register's size in bytes. Between adjustment and call require exactly
   one matching three-input STORE. Its constant space selector is the instruction address space, its
   address is the adjustment output, and its stored constant equals the observed fallthrough offset at
   width `w` bytes.
3. That STORE is the **only** op strictly between adjustment and call. Reject the instruction if any other
   op anywhere in it writes any byte overlapping the adjusted register. A COPY that merely reads SP
   between the adjustment and call also fails the interval check. Target calculations before adjustment
   are permitted subject to the other checks. Require exactly one accepted projection.
4. Require the program's validated stack register. Both caller and callee base slices match its offset and
   size. The adjustment output matches its register kind, space, offset and size. The projected coordinate
   equals the observed fallthrough, including space. Match the claimed slot, width, delta and continuation
   in this view. Only the adjust and STORE are transient, in that order. Persistent-effect removal requires
   both transient keys to occur in the effect unit. [observed_call_state.py, projection and removal](wt_main/src/tdo_v2/observed_call_state.py) · [call_relations.py, push checks](wt_main/src/tdo_v2/call_relations.py)

**Register-link recognizer.** Require validated SP, link and PC registers, call flow with fallthrough, and a
final CALL or CALLIND. The immediately preceding op writes the exact link register. Accept the engine's
two-constant INT_ADD or one-constant COPY when the result modulo the link width equals the observed
fallthrough offset. INT_ADD with its first constant equal to instruction start gives instruction-relative
relocation. Other accepted constant derivations give unknown relocation.

For CALL there are no earlier ops. For CALLIND the only earlier op is `COPY pc = Rn`. Rn is a PC-width
register overlapping neither SP nor PC. The CALLIND has the captured PC as its sole input. Rn may be x30.
The capture, when present, and the link write belong to `setup_ops`. The link write is persistent.
`transient_ops` is empty for both register-link shapes. An existing push match takes precedence for the
same call key. [call_relations.py, `_link_relation`](wt_main/src/tdo_v2/call_relations.py)

**Projection fields.** First select the observation, row, view and applicable vendor member. Resolve each
op there. In the emitted engine relation use `_operation_key` for `call_key` and for each member of both op
tuples: `space:offset:ordinal:OPCODE`, with space and offset in lowercase hex and ordinal decimal.
Observation, row length, view and vendor path remain lookup context outside those strings.
[call_seeds.py, `_operation_key`](wt_main/src/tdo_v2/call_seeds.py)

| CallRelation field | projected value |
|---|---|
| `call_key` | engine key of the transfer |
| `kind`, `sp` | `push` or `link`, validated architectural stack register |
| `link` | `LinkSlot(fallthrough.space_id, stored_byte_size)` for push, exact link register coordinate for link |
| `delta` | signed `sp_delta` |
| `continuation` | full observed fallthrough coordinate matching `link_write.continuation` |
| `relocation` | `instruction-relative` or `unknown` under the accepted recognizer |
| `length` | continuation byte offset minus instruction byte offset |
| `entry_ordinal` | ordinal of the call op |
| `setup_ops` | engine keys of every op before the call, in instruction order |
| `transient_ops` | push adjust and STORE engine keys, or the empty tuple for a register link |

For other lifts, a fact can describe the same architectural effect using different ops. Mark an op
transient only with evidence that the effect is equivalent and removable. Ghidra parity uses the exact
recognizers above.

## 4. lands_on [A4-10, F5-P3-3]

```
lands_on = {"class": "unresolved"}
         | {"starts": [row_ref, ...] | U, "inside": [row_ref, ...] | U,
            "mapping": "executable" | "non_executable" | "unmapped" | U,
            "import": "slot" | "external_target" | "none" | U,
            "class": "row_start" | "mid_row" | "external" | "executable_no_row"
                   | "data" | "outside_image" | "unclassified"}
```

- For `to: null`, use exactly `{"class": "unresolved"}`. For `to: U`, `lands_on` is `U`. For a concrete
  address, retain both row lists. Compute them over the bound row set in the same space and load-base
  context. `starts` has equal starts. `inside` has `start < to < end`. Use the applicable vendor intervals
  in a vendor comparison and preserve distinct observations and decode views. An empty list claims the
  complete search found zero matches. An incomplete search cannot establish an empty list.
- `import: "slot"` identifies the address of an IAT / GOT cell. `external_target` identifies an independently
  evidenced external execution destination. A call through a slot has a memory `target_value`, a computed
  edge with `to: null`, and an unresolved landing. `none` requires evidence ruling out the import roles.
  Ambiguous ELF page mapping or an unsupported mapper yields `U` for the affected input.
- Derive `class` in the following order. Stop when the answer is established. If a higher-priority result
  cannot be excluded, retain `unclassified` in the facts.

| decision in order | class |
|---|---|
| at least one start | `row_start`, including a listed PLT / IAT stub |
| no start and at least one interior match | `mid_row` |
| both lists empty and import is `external_target` | `external` |
| both lists empty, external destination excluded, mapping executable | `executable_no_row` |
| both lists empty, external destination excluded, mapping non-executable | `data`, including a non-executable import slot |
| both lists empty, external destination excluded, mapping unmapped | `outside_image` |

For `-4`, require only the evidence needed to establish the selected decision, including any necessary
higher-priority exclusions. One verified start establishes `row_start` with mapping and import unknown.
The exact contents of each list retain their own verdicts.

## 5. Program facts: code-byte dependence [A4-11, A4-12, F5-7, F5-8]

```
"code": {"premise": "image-code-unmodified-at-runtime",
         "regions": [{"range", "role": "code" | "unwind_metadata", "load_base", "executable", "writable",
                      "verified": [{"interval": [start, end), "evidence": "G1 evidence ref"}]}],
         "sites": [site, ...], "survey": [coverage, ...]}

coverage = {"kind": site_kind, "rows_examined": [row_ref, ...], "ranges_examined": [range, ...],
            "unsupported": [scope_item, ...], "unresolved": [scope_item, ...]}
scope_item = {"row": row_ref, "reason": reason} | {"range": range, "reason": reason}
identified = {"name": name, "basis": evidence_ref}
site = {"row": row_ref | U, "form": form | U, "kind": site_kind,
        "symbol": identified | null | U, "arguments": [{"index": int, "value": value_ref, "basis": evidence_ref}],
        ...kind-specific members below...}

trap_fields = {"vector": int | null | U, "immediate": int | null | U, "syscall_abi": identified | null | U}
write_fields = {"write": "static_store_candidate", "op": op_ref,
                "target_range": range | U, "static_basis": evidence_ref}
             | {"write": "run_observed_write" | "run_observed_change",
                "run": run_id, "time": time_in_run, "target_range": range, "source": evidence_ref}
```

The `trap_fields` and `write_fields` members appear directly on the corresponding site. An evidence
reference identifies the supporting Bundle record, static observation or run record. Each range identifies
its space and load base. Unwind metadata (.pdata / .xdata, .eh_frame) has its own regions. A fact reading
those bytes carries the premise in `holds_if`. Each `verified` record covers exactly the bytes checked by
the referenced G1 window.

Collect sites from their source observations independently of G1 verdicts.

| site kind | required meaning and evidence |
|---|---|
| `trap_instruction` | every surveyed SYSCALL / SYSENTER / INT family / SVC / HVC / SMC site. Record the decoded vector, including an implied vector, and any encoded immediate in their respective fields. An inapplicable operand is null. A syscall ABI name requires its own identification basis |
| `self_modify_import_call` | an evidenced call to VirtualProtect, mprotect, NtProtectVirtualMemory, WriteProcessMemory, FlushInstructionCache or a corresponding import. Preserve symbol and resolution basis |
| `dynamic_resolution` | an evidenced GetProcAddress / dlsym call. Record `requested_name: identified \| U` with the constant name and its basis when available |
| `rwx_allocation_constant_args` | an allocation with a visible constant RWX protection argument. Preserve the argument index, typed value and basis |
| `cache_maintenance` | A64 IC IVAU / DC CVAU, an evidenced `__clear_cache` call, or an identified `cacheflush` syscall. A syscall identification carries `syscall_abi` and the basis for the named operation |
| `dynamic_unwind_registration` | an evidenced RtlAddFunctionTable / RtlInstallFunctionTableCallback / RtlAddGrowableFunctionTable / `__register_frame` call |
| `code_write` | one of the three `write_fields` shapes. A static candidate requires a concrete site row, its STORE op and static basis. A run observation requires run, time, target interval and source even if the writer row is unknown |

A `run_observed_write` witnesses a write. `run_observed_change` requires evidence that bytes in the reported
interval changed. A same-value write supports only the former. A static STORE can be recorded without a run.

Coverage is per kind. `rows_examined` and `ranges_examined` name the actual search scope. The exception
lists localize unsupported and unresolved portions of that scope. For `code_write`, distinguish coverage
of static candidates and each observed run / time interval by separate coverage records with the `write`
discriminant and, for run surveys, `run` and the surveyed time interval. An empty site result means zero
found only for the stated kind, searched scope and observation period after excluding those exceptions.
Missing coverage, empty examination scope and an unsupported search establish no zero count. The survey
records evidence about the premise. Its default remains a reader policy.

## 6. ISA facts at row level [A4-13, F5-3]

```
isa = [{"kind", "value",
        "conditions": [{"what", "source": "profile" | "el" | "os_model",
                        "state": "holds" | "does_not_hold" | "unknown" | "unsupported"}]}]

exclusive_value = {"monitor": "set" | "clear" | "none" | U, "conditional_store": [op_ref, ...] | U,
                   "status_output": null | {"register": reg, "op": op_ref} | U, "unsupported": [...]}
```

`does_not_hold` records an evidenced false condition. `unknown` leaves its state open. `unsupported`
identifies a case the producer cannot model. For x86 the evidence-2 kinds keep their meanings, including
F2p by reference to evidence-2.

| kind | x86 | AArch64, per encoding and condition |
|---|---|---|
| F1 validity | XED profiles | profile validity. Non-hint PAuth encodings including RETAA, BRAA, BLRAA, LDRAA and PACIA are UNDEFINED without FEAT_PAuth. For `constrained_unpredictable`, list the architected alternatives |
| F2 privilege | CPL0 / IOPL / OS-gated, including F2p | register, access direction and EL. EL0 controls include SCTLR_EL1.UCT for CTR_EL0, DZE for DC ZVA, UCI for DC CVAU / IC IVAU, and CNTKCTL_EL1 for CNTVCT_EL0. Linux ID-register emulation covers its documented set. TPIDRRO_EL0 is read-only at EL0. ERET / HVC / SMC require EL1+ |
| F3 continuation / state | INT / SYSCALL / XBEGIN | trap PC by s3.3. For an enabled authentication that fails, distinguish standalone AUT from combined authenticate-and-branch forms as specified below |
| F4 features | CPUID and feature splits | hint-space PAC / BTI act as NOPs on older cores. Record feature conditions for LSE, MTE and other covered forms |
| F5 vendor | Intel / AMD views (s3.6) | documented implementation-defined behaviour |
| F6 output sources | undefined / external | system-register reads, including counters and IDs |
| F7 thread base | FS / GS | TPIDR_EL0 read / write at EL0, TPIDRRO_EL0 read at EL0 |
| exclusive | LOCK forms stay in the F tables | `exclusive_value` on the observed path. LDXR sets the monitor, has `conditional_store: []` and `status_output: null`. STXR records the monitor clear on the completed store-exclusive path, the conditional STORE op and the register plus defining op for its status result |

For standalone AUT, FEAT_FPAC supplies the immediate authentication-fault rule. For combined forms such
as RETAA / RETAB, BRAA / BRAB and BLRAA / BLRAB, the immediate authentication-fault rule requires
FEAT_FPACCOMBINE. Without the applicable faulting feature, record the profile's failed-pointer behaviour,
which can fault on subsequent use. With the feature state or effective enable unknown, keep the outcome
conditional. Feature absence and a disabled key follow s3.7. [Arm A-profile feature definitions, FEAT_FPAC and FEAT_FPACCOMBINE](https://documentation-service.arm.com/static/69402e206efc1635355c3bb2?token=)

The STXR STORE reference identifies the same op that memory evidence marks `cond_write`. The status
reference identifies the op defining the encoded result register. If the lift does not expose a required
op, preserve the applicable field as `U` with the reason. The references introduce no second memory
effect. Store success depends on run state.

## 7. Kept ISA-specific, exposed, not unified

- **`link_write.location`.** x86 writes a stack slot and adjusts SP. AArch64 writes x30 with zero SP delta.
- **TBI (`program.tbi`).** Per address half (TTBR0 / TTBR1), record `tbi_data` and `tbi_instruction` as
  on / off / unknown from the OS model. Data addresses ignore the top byte when TBIx = 1. Instruction
  addresses ignore it when TBIx = 1 and TBIDx = 0. Preserve the original address semantics.
- **`branch_target_check`.** AArch64 BTI is a fact about one source row and one target decode view.

  ```
  bti_pair = {"source_row": row_ref, "target_row": row_ref,
              "branch_kind", "branch_register", "source_guard": page_guard, "target_guard": page_guard,
              "landing_instruction", "conditions": [...]}

  page_guard = {"page": range,
                "elf_property": {"proposes_guard": true | false, "basis": evidence_ref} | U,
                "effective": {"guarded": true | false, "source": "os_model", "basis": evidence_ref} | U}
  ```

  Retain both guard inputs independently for each page. An ELF property can propose guarding while the
  effective guard remains unknown. An OS model can establish guarded or unguarded state for that page.
  Compute the branch-type condition from the branch kind, register (including BR x16 / x17), applicable
  source guard and PSTATE.BTYPE rules. At the target, use its effective guard and the landing instruction
  in the named view. PACIASP / PACIBSP accept the BTI jc classes when effective SCTLR_ELx.BTx = 0 and
  the BTI c class when BTx = 1. Preserve any unknown input on which the result depends.
- **x86 CET IBT.** ENDBR64 / NOTRACK stay in F3 / F4.
- **Return integrity.** AArch64 PAC (`target_auth`) and x86 shadow stack retain their ISA-specific facts.

## 8. Verdicts: G1 evidence -4 [A4-2, A4-7, A4-14]

**Binding.** Resolve a verdict only when the Bundle generation and manifest digest, facts digest,
comparison-rule version and row-set digest all match. Compute the row-set digest over the canonical
ordered list of `(space, offset, length, view, observation)` for every row in s2 row order. Preserve
distinct observations and views.

```
field_lookup = {"row": row_ref, "path": field_path,
                "edge": edge_key when applicable, "op": op_ref when applicable}
```

The path identifies the exact sub-field and includes `vendor_views.intel` or `vendor_views.amd` for a
vendor member. An edge lookup uses its complete triple. Each referenced op must resolve in its bound
row. Resolve referenced landing or site rows with their own full row references. An unmatched binding,
deleted row, sibling vendor, different observation or different view yields no reusable verdict. Evidence
from `-2` / `-3` and a field with no `-4` comparison cannot confirm a claim.

**Order of judgment**

1. Establish the consensus form in the selected view. An undecided form leaves the row comparisons
   unobserved. A disagreement on one attribute of a decided form affects only its dependents.
2. Compare `kind` and the required edge triples from s3.1. Charge a missing triple, duplicate or extra
   triple as contradicted. A wrong guard produces a missing required triple and an unexpected triple.
   A keyed `unobserved` placeholder at the correct triple leaves that edge unobserved. A missing ordinary
   member cannot be reconstructed from another role with the same address.
3. For each ordinary matching edge compare `to` by source, then `lands_on` using s4. Compare the remaining
   sub-fields independently. Missing evidence for one sub-field cannot suppress a comparison on a sibling.

**Outcomes.** `confirmed` requires an exact comparison and match. `contradicted` requires a decided
different value or a decided structural mismatch. `unobserved` covers a keyed placeholder, an applicable
value the producer cannot state, missing independent evidence or split votes. `not_applicable` requires
a decided form or variant that excludes the field. A value asserted in a forbidden position contradicts
the form. An absent claim supplies no evidence of inapplicability.

| field | applies to | expected value and comparison | without sufficient evidence |
|---|---|---|---|
| kind, exception_basis | all kinds, basis on defined UD / invalid encoding | s3.1 on the consensus form, F1 for invalid encoding | unobserved |
| edge membership, source, requires | every required role | exact s3.1 triple, including literal null guards, `os-contract` on every `trap_return`, and all three XBEGIN guards | unobserved if form undecided or role explicitly marked |
| `to`, sequential | ordinary sequential roles | PC + independently verified length in this view | unobserved |
| `to`, encoded_target | direct branch or call, conditional taken, outermost XBEGIN abort | each voter's own target report must agree. A target computed by G1 for XED does not count | unobserved, including today's missing XED report and the AMD 66 E8 a5 split |
| `to`, computed or os | all such edges, including nested abort and trap entry | required literal `null`. A supplied address is contradicted | decided by source once form and role agree |
| `to`, os_return with a saved PC | SYSCALL / INT family, SVC, BRK on the s3.3 path | compare the saved current or next PC in s3.3, with length and path evidence where required | unobserved |
| `to`, os_return with no saved PC | SYSENTER | required literal `null` from the form. A supplied address is contradicted | decided by form |
| `to`, condition-dependent os_return | x86 HLT, A64 HVC / SMC / HLT | require s3.3's null representation and F2 or F2 / F3 reference. An address supplied for the unqualified row violates that shape. A valid null on an undecided execution path yields no confirmed saved address | saved-address verdict unobserved when privilege, debug state or path is undecided |
| ordinary condition presence, polarity and test | taken / not_taken forms only | `taken_when: "true"` and the exact s3.4 predicate: cc, original counter zero, wrapped decrement then nonzero, decrement plus the required ZF sense, register zero/nonzero or selected bit and sense | unobserved for the unresolved part. An opaque op reference alone cannot confirm its predicate |
| XBEGIN condition | XBEGIN only | ordinary `condition` is inapplicable (`null`). Compare normal start, outermost abort and nested abort as edge guards | unobserved if form undecided |
| condition input identity, op references | applicable value expressions and op lists | producer's claims about the actual lift. TDO can check the p-code | unobserved from decode alone |
| length and byte interval | row or named vendor member | compare length against that view's voters and the interval against the bound start and verified length. Byte-content evidence covers only bytes actually checked | unobserved for unchecked quantity |
| link stored width and bits | links | for x86 compare the vendor's a7 `(width_in_bits, stored_bits)` and check applicable a11b byte size times eight. Compare bits at the stored width | unobserved for the unsupported component |
| link continuation | links | full address at row start + independently verified view length in the same space | unobserved |
| link slot_offset, sp_delta | pushes, or delta alone for register links | signed bytes. Push requires both equal to `-width/8`. Register link requires zero delta and has no slot offset | unobserved if applicable width or form is undecided |
| link location kind | links | push memory or link register from the form | unobserved |
| link register / SP coordinate | applicable links | independent register evidence identifies the coordinate. A claimed op write has its own evidentiary requirement | unobserved |
| link memory space | pushes | independent address-space evidence for the space classification. That evidence alone cannot confirm the STORE acted there | unobserved |
| relocation, derivation | links | require evidence of derivation. A stored-value match alone cannot establish it | unobserved |
| target_value | indirect forms including indirect CALL | require evidence of the operand, width and identity. Today's register-kind vote lacks the register name, and memory target expressions lack a full comparison | unobserved |
| target_auth key, modifier, conditions, on_failure | authenticated forms only | encoding selects IA / IB. Modifier and effective conditions need their own evidence. F3 uses the feature rule in s6 | unobserved without the applicable evidence and ARM voter |
| lands_on starts / inside | concrete addresses | exact lists require evidence over the bound rows, intervals, views and observations. A verified individual match can establish a positive witness | unobserved from decoder votes alone |
| lands_on mapping / import | concrete addresses | independent mapping and import evidence for this address and role | unobserved for an ambiguous or unsupported input |
| lands_on class | ordinary edges | use the first provable s4 decision. A confirmed null `to` suffices for `unresolved`. A confirmed start at a verified destination suffices for `row_start`. Lower decisions require their higher-priority exclusions | unobserved when a necessary input is missing. A producer's `unclassified` supplies no independent proof |
| site, trap_instruction | surveyed trap instructions | voters can compare the form and any vector / immediate they independently report. ABI and symbol basis have separate comparisons | unobserved for unsupported fields or ISA |
| other site fields, code surveys, remaining ISA claims | where applicable | require evidence specific to the field. A matching form cannot confirm a run, symbol resolution, survey coverage or OS state | unobserved |

Report contradicted and unobserved fields separately on each row. A row is contradicted if it has a
contradicted field, unobserved if any applicable comparison remains open and none is contradicted, and
confirmed only when every applicable field is confirmed. An undecided form cannot yield vacuous
confirmation. ARM row verdicts remain unobserved until an ARM voter exists. Claims stay in the facts
file and these verdicts stay in `-4`.

## 9. Phasing and completion [A4-15, F5-1, F5-9]

### G2a: x86 derived facts and -4

**Parity with the existing Ghidra observations.** On each gate Bundle, join by observation, row id, view,
applicable vendor path and call op. Within that context compare all fields of the projected `CallRelation`,
including the four-component engine `call_key`, validated `sp`, `entry_ordinal` and both ordered op tuples.
Report missing relations, extra relations and field differences separately.

- Record a missing observed fallthrough and absent validated stack-register evidence as distinct recognizer
  failures. A facts row may still claim `link_write`. For every CALL / CALLIND row outside the recognized
  push set, record the row, call op where present and the particular failed recognizer check from s3.8.
  Reconcile the source counts and join multiplicity. The published gaps of 145 in ntdll and 2 in UE are
  totals to reconcile. The size of a gap explains no individual row. Pass with zero unexplained missing,
  extra or differing relations. [call_relations.py](wt_main/src/tdo_v2/call_relations.py) · [observed_call_state.py](wt_main/src/tdo_v2/observed_call_state.py)
- For return-relation parity compare only the row inputs: RETURN's target value and the transfer op and
  edges of direct and conditional tails (`pcode_blocks.py:195`). Function closure, SSA, callee certificates
  and the return decision belong to TDO.
- For different lifts of one instruction compare the common architectural facts, then check each lift's op
  references and relocation derivation against its own observation.

**Fixtures.** Each entry has a required result. G2a passes only when all results match.

| fixture | required result |
|---|---|
| `66 E8` at `0x140001000`, Intel | length 6 and interval `[0x140001000,0x140001006)`. With this vendor's votes, confirm a7 width 64 and stored `0x140001006`, continuation `0x140001006`, slot offset `-8` and SP delta `-8`. Direct `to` remains unobserved with today's XED target provenance |
| same bytes, AMD | length 4 and interval `[0x140001000,0x140001004)`. Confirm a7 width 16 and stored `0x1004`, full continuation `0x140001004`, slot offset `-2` and SP delta `-2`. The AMD a5 disagreement leaves direct `to` unobserved. Substituting the truncated bits for the full continuation contradicts that field |
| XBEGIN with nested abort | exactly the three s3.1 triples, with `condition: null`. Normal entry is sequential. Outermost abort has the encoded-target role. Nested abort is `computed`, guarded by `nested-transaction`, with `to: null` and `lands_on.class: "unresolved"`. Interchanging input edge order gives the same canonical digest |
| colliding starts and evidence binding | two decode views at the same start retain distinct refs and verdicts. Reusing a verdict across views, across two observations with the same id, or across Intel / AMD paths fails lookup. Deleting a row invalidates the row-set binding |
| incomplete edge set | remove only the required nested-abort triple: edge membership is contradicted. Replace it instead with the exact keyed `unobserved` placeholder: that edge is unobserved and the two other roles remain comparable. A duplicate outermost role cannot satisfy the missing nested role |
| `BLR x30` schema round trip | target is incoming x30, link is x30 with zero delta and full PC + 4, `target_auth: null`. For the recognized lift, capture precedes link write, both appear in `setup_ops`, and `transient_ops` is empty. ARM voter comparisons remain unobserved in G2a |

The 66 E8 expectations use the vendor tuples in the existing [decode-check fixture](wt_lint/tests/intra/golden/decode_check_pair_66e8.json).
The architecture fixture cannot by itself create an engine relation in a vendor view that fails s3.8.

**Report.** For each sub-field give the comparison unit (row and path, including vendor and edge role where
applicable), the number of units considered and these counts:

- For decided applicability, `N_applicable = confirmed + contradicted + unobserved_applicable`. Use
  `N_applicable` as the denominator of applicable-field rates.
- Report `N_not_applicable` separately against all considered units. Keep `N_applicability_unknown` for
  undecided forms, with verdict `unobserved`. Thus `N_considered = N_applicable + N_not_applicable +
  N_applicability_unknown`, and total `unobserved = unobserved_applicable + N_applicability_unknown`.
- Count a forbidden extra role or field once as a contradicted structural comparison at its parent. It
  cannot become an applicable success or an inapplicable-field success. Report a zero denominator as a count
  with no rate. Publish the parity differences and fixture results alongside these counts.

### G2b: code-byte facts

Per corpus Bundle: the region table, the site tables by kind, and the survey scope (PE and ELF).

### G2c: AArch64 claims

- Claims per form, with the unsupported counts.
- Round trips for `BLR X30`, `RETAA` (target_auth), BTI pairs and `svc` (os_return).
- Parity with the engine's `_link_relation` on the ARM corpus, including sp and the stack-register evidence.
- The form table's completeness against the producer's AArch64 decode. The voter comes later.

**After G2:** the ARM voter, the XED shim target, and the engine reader (after S3).
