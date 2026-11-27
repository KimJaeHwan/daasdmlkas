# X-1 implementation plan r2 -- producer evidence for S3 (2026-11-26)

r1 reviews: Astra `x1_astra1.md` REJECT (3 P1, 3 P2); Fable `x1_fable1.md` APPROVE WITH FIXES (6 P2, 4 P3).
TBR's re-export requirements (message 2026-11-26) are in part 5. Every finding is answered below, marked [A-P1-n] /
[F-P2-n] / [TBR].

Source: `.census6/design_s3_r18.md` section A (X-1 row) and section B items 4, 5 and 15. Owner decisions
2026-11-26, agreed with the TBR side session (memory `x1-evidence-split`):
- the Bundle carries raw producer claims, and TBR evidence carries verdicts only;
- S3 admission uses the raw override claim under the named premise `producer-override-report` [TBR-G1-flow];
- the G1 attestation discharges that premise once TDO's G1 reader lands. Order: X-1 -> S3 -> G1 reader;
- the re-export carries row lengths and the original image.

## 0. Split and acceptance

- **X-1a (parts 1-4)**: code only. Acceptance: the same Bundles give identical results. The full gate vs `ped6`
  (strict same-generation compare) shows 0 snapshot differences and an identical oracle. Merge on that gate.
- **X-1b (part 5)**: re-export, cross-generation comparison, new baseline. This is a separate reviewed step with its
  own gate and merge [F-P2-6, A-P2-6, F section 3].
- X-1 builds evidence only. Site admission and the s3-on transfers in the engine are S3. Under S3 OFF nothing reads
  the new evidence, except report counts.

## 1. Producer capability and observation identity (decided first) [A-P1-3, A-P2-4, F-P2-3, F-P3-4]

1. The exporter declares a sealed producer capability in the manifest, within the supported envelope versions 1 / 2
   (no new envelope version): `producer_capabilities: ["instruction-override-v1", "exceptional-target-provenance-v1",
   "stack-switch-evidence-v2"]`. The field is optional, so old Bundles have none.
2. A Bundle that declares `instruction-override-v1` must carry the part-2 objects on **every** instruction row. A
   missing or malformed object is then an observation defect, marked `invalid` like other malformed row fields. It
   is not read as "legacy" [A-P2-4].
3. **Legacy encoding.** For a Bundle without the capability, both identity encoders in `_scope_wire.py`
   (`_validated_instruction_preimage` :239 and `_stream_observation` :319) produce exactly today's bytes:
   - the new raw values are not streamed;
   - the TDO-side external count of part 3 is not streamed either. On old Bundles it is a report-only number, and S3
     treats an old Bundle as "not evaluated" anyway.

   So old-Bundle digests do not move, and neither do summary caches, template source identities or the PE-a1
   certificate.
4. **New encoding.** For a Bundle with the capability, both encoders stream a tagged block after the existing row
   fields:
   - tag `override-v1`;
   - `flow_override` name, `fallthrough_overridden`, `length_overridden`;
   - the sorted override references, each a coordinate + type + in-index mark;
   - `external_flow_targets`;
   - the sorted exceptional targets.

   The domain string becomes `tdo-v2-function-observation-v3` for capability Bundles only (old ones keep `-v2`).
   Both encoders share one helper, so they cannot drift.

Tests:
- vary only override presence, flow-override name, reference type, reference coordinate, external count or one
  exceptional target -> distinct digests, and both encoders agree;
- an old fixture's digest is byte-identical before and after;
- unchanged OFF successors;
- a two-row capability Bundle with one override object removed and resealed -> the defect stays visible
  (observation invalid), not legacy.

## 2. Per-instruction override evidence (exporter + parser) [F-P2-4, A-P2-5, F-P3-1]

Problem (S3 r18 item 5). `GhidraV2BundleExport.java:2145` serializes `FlowType.isOverride()`, a property of the
computed flow type. The real per-instruction state is not in the Bundle.

Exporter, in `instruction(...)`, writes for capability Bundles one object `override`:
- `flow_override`: `getFlowOverride().name()`;
- `fallthrough_overridden`: `isFallThroughOverridden()`;
- `length_overridden`: `isLengthOverridden()` (Ghidra 12.0.4 `Instruction` API) [F-P2-4, A-P2-5];
- `override_references`: every reference from the row whose `getReferenceType().isOverride()` holds. Each is
  recorded raw: coordinate, type name, and whether the address is in the program's address index.

An out-of-index or external override reference is recorded, never a refusal [F-P2-4]. Only wrong keys or types
are malformed.

Parser (`_scope_observation.py`): exact keys and types, per the capability rule above. Instruction observations
gain `override_evidence` with three states:
- `absent`: an old Bundle;
- `none`: NONE, not fallthrough-overridden, not length-overridden, no override references;
- `present`: the raw values.

`flow_type.is_override` stays as it is (renaming it would change every snapshot). The premise registry entry
`producer-override-report` (new, in `assumptions.py`) says the override claim comes from the producer's own
listing state and that G1 attests its effect later. The docs say `flow_type.is_override` is not that claim
[F-P3-1].

**Exceptional-target provenance [A-P2-5].**
- `GhidraV2BundleExport.java:1288` keeps a landing pad only for rows with call p-code, and `:2080` unions the
  landing pads into the flow targets.
- Capability Bundles therefore also write `exceptional_targets` per row: the recorded landing pads for that row
  from the protected ranges, before the call-p-code filter.
- The existing `flow_targets` projection is unchanged (OFF equivalence).
- S3 then sees a bare CALLOTHER inside a protected range.

Tests:
- recorded-row fixtures through the parser: NONE, a BRANCH flow override, a fallthrough override, a length
  override, a CALL_OVERRIDE reference to an external address (recorded with in_index false, observation valid);
- a bare CALLOTHER in a protected range: `exceptional_targets` lists the landing pad while `flow_targets` is
  unchanged;
- a register-free body round-trips and resolves its unique eight-byte RSP and register space from the sealed
  register table [A-P2-5];
- a headless Ghidra fixture for the exporter, if the existing Java harness supports it.

## 3. The external-target indicator survives target validation

`_scope_observation.py:543-544` drops an external flow target without a trace. Instruction observations gain
`external_flow_targets: int`, the number of raw targets dropped as external. It is raw, and S3 will require 0. It
enters the identity only for capability Bundles (part 1).

Test: one local + one external target -> targets = (local,), count 1; only local targets -> 0.

## 4. Stack-switch evidence: S3-aware, byte-classified, bound to the analyzed listing [A-P1-1, A-P1-2, F-P2-1, F-P2-2, F-P2-5, F-P3-2, F-P3-3]

**4.1 Kernel transfers are classified by bytes, at every instruction start [A-P1-1, F-P2-5].**
The scanner reads the initialized bytes at every listed instruction start, in functions and outside them. It
classifies kernel transfers by encoding, not by user-op name:

| encoding | form | class |
|---|---|---|
| `0F 05` | syscall | covered candidate |
| `CD 2E` | int 2e | covered candidate |
| `0F 34` | sysenter | uncovered |
| `CD xx`, xx != 2E | `int xx`, e.g. 29h, 80h | uncovered |
| `CC` / `F1` / `CE` | int3 / int1 / into | uncovered |
| `0F 07` | sysret | uncovered |
| `0F 35` | sysexit | uncovered |

Legacy prefixes are decoded per the scanner's existing row bytes. A prefixed or undecidable form is `UNCHECKED`.
Covered means S3 may admit it; whether it is admitted is decided in S3.

**4.2 The s3-on verdict [A-P1-1, F-P2-1].** One scan computes two verdicts.
- `s3-off`: today's v4 rule, byte for byte. The byte classification is recorded but does not change it.
- `s3-on` makes the following `UNCHECKED` (a possible switch, so the assumption is withdrawn):
  - every uncovered kernel transfer;
  - a kernel-transfer row whose lifting is empty, has no CALLOTHER / CALLIND, or contradicts the bytes;
  - a candidate whose RSP the scanner cannot show is preserved (the eight-byte SP is not an operand of the lift
    shape, or a write to SP occurs in the row).

  At a covered candidate the state after the row keeps only the eight-byte stack pointer. Every other register and
  unique location becomes UNKNOWN, and this UNKNOWN is carried through joins (the MUST merge already does) and
  across calls / tails: the conservative v4 `afterCall` and entry state already make every non-SP register
  unknown at a callee entry. So a post-syscall tail into a helper starting `add rsp,rbx` is a switch in the helper
  itself.
- Every candidate goes into `kernel_transfers` with address, bytes, class and the immediate vector.
- What a clean s3-on verdict certifies: clean **if** every listed covered candidate is an admitted S3 site of the
  run. The consumer rule (implemented in S3) accepts it only then, and otherwise withdraws globals/stack
  disjointness.
- Under s3-on, `stack-switch-check-exceptions` still applies to every non-kernel CALLOTHER, and the evidence file
  says so per policy [F-P3-2].

**4.3 Identity: the evidence is bound to the analyzed listing [A-P1-2].**
- The scan runs inside the export session. The exporter invokes the scanner through `runScript` on the same
  program, read-only, after the observations are collected.
- The evidence file is added to the Bundle as a sealed blob, `stack_switch_evidence`, covered by the seal manifest
  and declared by the capability `stack-switch-evidence-v2`.
- Its authority is the seal: the same session and listing state as every observation in the Bundle.
- If the listing changes (an override, a loaded byte, a re-analysis), that is a new export with a new seal. Evidence
  from an older seal never counts for it.
- The evidence also records a listing digest it computed: every instruction start, its bytes, its length, the
  three override facts, and every block's initialized bytes in address order. The exporter's own check recomputes
  it once before sealing, as a self-check.
- Standalone scanner runs (v1, or v2 outside an export) stay supported for s3-off. They are "unbound" and carry no
  s3-on authority.

**4.4 One compatibility check everywhere [F-P2-2, A-P1-2].**
- `StackEvidence.clean` is removed. In its place, `stack_evidence.authority(evidences, *, policy, bundle=None)`
  returns (allowed, reasons). It is the only reader, used by:
  - `assumption_allowed`;
  - refused-member coverage (`summary_engine.py:515`);
  - linking (`linking.py:365`);
  - derivation (`tools/derive_models`);
  - every cache key that rests on the assumption (summary store, templates, linker cache). These add the evidence
    digest and policy to the key.
- Rules:
  - `s3-off`: v1 / v2 as today; a v2 file is read by its `s3-off` verdict.
  - `s3-on`: only Bundle-sealed v2 evidence whose seal is the run's Bundle (or, for a linked library, that
    library's Bundle), read by its `s3-on` verdict plus the admission rule above.
  - v1, unbound v2, or a seal mismatch is "incompatible" and withdraws the assumption with its reason. It is never
    upgraded.
- In X-1a every caller passes `s3-off`. S3 switches the policy.

**4.5 Versions.** Evidence format version 2, detector `stack-switch-coefficient-v5`. Both verdicts and the per-policy
exception lists are stored. The UE template names v3 evidence (`ue_core_win64_fstring.json:65`). Its s3-off delta
(v3 legacy -> v5 s3-off) is measured separately in X-1b and reported [A-P2-6].

Tests (Java scanner on recorded fixtures, plus the Python mirror where Java fixtures are impractical) [A-P1-1,
F-P3-3]:
- both encodings:
  - `mov rbx,rsp; syscall; mov rsp,rbx`: s3-off clean, s3-on switch;
  - `int 2e`: a candidate with vector 0x2E;
  - `int 29h`: s3-on UNCHECKED (uncovered), s3-off unchanged;
  - an empty lift and a contradictory lift at `0F 05`: s3-on UNCHECKED;
  - an unsupported interrupt followed by `ret`: s3-on UNCHECKED;
  - a post-syscall tail into a helper whose first instruction is `add rsp,rbx`: s3-on switch;
  - a kernel transfer outside every function;
  - an unrelated CALLOTHER (`cpuid`): both clean;
- every case: s3-off equals the v4 verdict.

Identity tests [A-P1-2]:
- change only an override or one loaded byte under the same executable hash and project path, re-export -> the old
  evidence loses s3-on authority;
- v1 evidence, and a v2 file that is OFF-clean and ON-dirty, through refused-member coverage, linking (including a
  warm linker cache), derivation and the summary store.

## 5. X-1b -- re-export, cross-generation comparison, new baseline [F-P2-6, A-P2-6, TBR]

**Bundles to re-export:** the gate Bundles, the ntdll closure, the field cases with system calls, and the UE
template producer bundle. Before running, TBR is told and checks one Bundle of each kind with decode_check.

**Each Bundle must verifiably carry (an inventory script checks every item):**
1. the sealed `original` blob: the exact PE / ELF bytes, hashed in the seal manifest [TBR 1];
2. `length` on every instruction row [TBR 2];
3. the language id and version (x86:LE:64:default, Ghidra 12.0.4) [TBR 3];
4. blocks / image base consistent with `original` (the file mapping verifies the windows) [TBR 4];
5. the register table (RSP by evidence; PE-a1's DF identity then comes from the table row instead of the inferred
   certificate on these Bundles -- an expected, listed difference);
6. the per-function S1 `call_fallthrough: "isa"` flag;
7. the fresh-import attestation;
8. the X-1a capabilities, with full override coverage and the sealed stack evidence.

**Comparison:**
- The strict same-generation `ped6` gate stays as it is.
- A new paired-generation comparison runs old vs new Bundles in both profiles (default and legacy):
  - with an explicit metadata allowlist (generation, digests, versions, report metadata);
  - with direct checks of values, debts, support, completeness, edges, refusals, proofs and premise use;
  - `semantic_snapshot.py:467` stops on a changed generation today, so a paired mode is added.
- Expected: identical except listed causes, e.g. DF identity from the table, a register space formerly inferred from
  raw operands. Any other difference blocks the baseline.
- Tests of the paired mode: a generation-only change passes; a changed debt, support, proof, edge, refusal,
  completeness result or oracle result fails.
- The new baseline is cut only after the paired comparison and the inventory pass.

## 6. Order and verification

X-1a: part 1 decision -> part 3 -> part 2 -> part 4. Each part: focused tests + mutants (`cob/x1_mutants.py`), then
the full suite. One full gate vs `ped6`, then Astra + Fable code review, then the owner's merge OK. X-1b follows as
its own step.
