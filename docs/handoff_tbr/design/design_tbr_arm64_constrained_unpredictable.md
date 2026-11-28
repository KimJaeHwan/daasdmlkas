# TBR A64 constrained-unpredictable encodings

Astra reviewed this design on 2026-11-28. It uses the pinned 2026-06 A64
instruction XML for instruction diagrams, guards, and outcome effects. The
fixed-bit choices come from [Arm DDI0487 M.d §C2.2.2](https://developer.arm.com/documentation/ddi0487/md/-Part-C-The-AArch64-Instruction-Set/-Chapter-C2-About-the-A64-instruction-descriptions/-C2-2-General-information-about-the-A64-instruction-descriptions/-C2-2-2-Fixed-values-in-AArch64-instruction-and-System-register-descriptions).

## Reviewed cases

Among the 1,107 constrained words rendered by both observers, 577 have only
a parenthesized bit violation, 458 have only an operand constraint, and 72
have both. The operand constraints on those 72 words also hold when the
relevant diagram bits take their prescribed values on that path. That gives
649 bit-rule words and 530 operand-rule words. The bit group includes 603 memory
ordering and exclusive forms, 30 multiply-high forms, and 16 flag or barrier
forms. Across this group 633 words violate `(1)` and 16 violate `(0)`.

| Source rule | Words | Arm choices at the applicable rule |
| --- | ---: | --- |
| Parenthesized `(0)` or `(1)` | 649 | `UNDEFINED`, `NOP`, execute with the prescribed bit, or destination registers become `UNKNOWN` |
| `Unpredictable_LDPOVERLAP` | 292 | `UNDEFINED`, `NOP`, or loaded destination data becomes `UNKNOWN` |
| `Unpredictable_BASEOVERLAP` | 72 | `UNDEFINED`, `NOP`, or use an `UNKNOWN` access address |
| `Unpredictable_DATAOVERLAP` | 68 | `UNDEFINED`, `NOP`, or use `UNKNOWN` store data |
| `Unpredictable_WBOVERLAPLD` | 52 | `UNDEFINED`, `NOP`, suppress writeback, or write back an `UNKNOWN` value |
| `Unpredictable_WBOVERLAPST` | 50 | `UNDEFINED`, `NOP`, use the pre-writeback register value, or use `UNKNOWN` store data for the overlapping element |
| `Unpredictable_LSE128OVERLAP` | 36 | `UNDEFINED`, `NOP`, or make the returned register data `UNKNOWN` |

Operand rule counts overlap. There are 570 incidences across the 530 operand
words. Thirty-two words reach `DATAOVERLAP` then `BASEOVERLAP` if the first
choice continues. Eight reach `WBOVERLAPLD` then `LDPOVERLAP`.

## Evidence and evaluation

Resolve the original word through the existing pinned index and bind each
rule to the exact encoding and its Arm source section. Reuse `arm_check`
with a new versioned kind for `CONSTRAINED_UNPREDICTABLE`. Keep original
bytes, observer output, and rendering comparison available. A normal
mnemonic is compatible with this verdict. The 407 definite rejections remain
`UNDEFINED` under their existing rule.

The opt-in `a64-all-instructions-v3` profile uses the
`arm-a64-constrained-operands-1` rule. It reads the pinned diagrams for the
60 instruction files covered by the audit and reads the six audited operand
clauses in their applicable instruction classes. Applying the same diagram
rules to those files also detects 147 LLVM-only words in the reference
catalogue. Twenty-four of those words reach an operand constraint on the
prescribed-bit path.

Record each triggered guard in Arm’s evaluation order. Carry its decoded
operand roles or fixed bit position, the source section, feature or decode
preconditions, and its allowed outcomes. An outcome identifies the affected
role and whether the specification continues execution. Keep the CPU's
selected outcome unobserved. The shared Arm reference pseudocode gives
implementation choices as examples of the available selections. The allowed
set for a rule comes from the instruction's own guard and outcome clauses.

- A choice of `UNDEFINED` or `NOP` ends evaluation of the instruction.
  Later rules apply on continuing paths only. Preserve dependency on earlier
  choices, including any change to writeback. Use source order for rule
  precedence and defer a combined verdict when that order is unverified.
- For violated diagram bits, record actual and prescribed values per bit.
  Keep the execute-with-prescribed-bits path conditional and recheck the
  instruction on that path. The 72 combined words reach their operand rules
  there. For the destination-UNKNOWN choice, retain the scope Arm states.
  Memory access and writeback stay unspecified unless the instruction
  description gives their effects for that choice.
- `UNKNOWN` means an architectural effect on the stated destination, store
  data, address or writeback value. Bind a target to its register bank and
  operand role before deriving an effect. A write to `WZR` or `XZR` is
  discarded, while SIMD register 31 is writable. A suppressed writeback
  can still leave a load to the same physical register.
- A pair store with writeback overlap can have an unknown overlapping data
  element and a known other element. A pair store-exclusive with
  `DATAOVERLAP` has unknown data for the entire stored pair on that choice.
  The exclusive monitor and ordinary memory checks still govern whether a
  store occurs. The unknown address from `BASEOVERLAP` is not itself a store.
  On continuing atomic paths, preserve access and writeback effects only
  where supported by the Arm operation. Keep returned data and memory effects
  distinct.

Keep the result in TBR source evidence. A consumer can use a proven CPU
choice or model the alternatives explicitly. Until then it can carry the
unresolved choice instead of asserting a memory edge or trap for every
execution. Recorded choices express architectural permission. The report
keeps handler routing, concrete CPU behavior, and any later execution
preconditions unobserved.

## Acceptance

1. Add the adjudication under a new opt-in profile with pinned rule provenance.
   Replay recomputes the rules from the original bytes and archive.
   Keep the existing profile evidence byte-replayable.
2. Match the audited population by word, encoding, violated bits, and triggered
   clauses. Require all seven rule groups, the 72 combined words, and both
   ordered multi-rule patterns.
3. Exercise `0x88608000` (`LDAXP` with an invalid `Rs` field and duplicate
   destinations), `0x28c00000` (`LDP` with two ordered operand constraints),
   and `0x08000000` (a prescribed-bit path followed by two store-exclusive
   constraints). Test `LDNP WZR,WZR` and `LDNP S31,S31` separately.
4. Verify nearby regular encodings, the existing 407 definite rejections,
   source ELF and coverage entry points, and replay after altering an allowed
   choice or the order of two clauses.
