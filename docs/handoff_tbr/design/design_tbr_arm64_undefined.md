# TBR A64 undefined operand encodings

Astra reviewed this design on 2026-11-28. It applies the instruction-specific
rules behind the [GNU observations and native CPU results](../../../tools/decode_check/ARM64_GNU_UNDEFINED.md).

## Rule and evidence

Apply the rule to each original little-endian A64 word after resolving its
candidate in the pinned Arm 2026-06 table and before deriving operand facts.
The coverage command and original-ELF evidence command share this point in
`arm64_source_decode.observe`. Match one candidate against an audited
`(section, id, XML file, feature condition)` and record the table coordinate.
An ambiguous or excluded match leaves the verdict unobserved.

| Audited Arm candidates | Rejection from the original word |
| --- | --- |
| The 36 acquire/release variants in the nine LSE128 and D128+THE instruction files listed in the GNU note, all in `memop_128` | Either `Rt[4:0]` or `Rt2[20:16]` equals 31 |
| `cpy_z_o_i_`, `cpy_z_p_i_`, and `dup_z_i_` | `size[23:22] == 0` and `sh[13] == 1` |

These predicates establish `UNDEFINED` with the extension present. The
instruction's own feature check also selects `UNDEFINED` when the extension
is absent. Keep CPU features and runtime state unobserved. If the applicable
check accepts a word, leave the verdict unset. Handle the `Rn` base register
and cases such as equal atomic data registers in 0–30 under their own rules.

Use a new kind in the existing `arm_check` record for this verdict. Record
`UNDEFINED`, the rule version, table coordinate, rejection reason, and
extracted bit values. Keep `encoding_index`, the original bytes, the raw and
normalized observer outputs, and the rendering `comparison` available.
Mark an observer that reports a normal instruction as contradicted. Keep
missing renderings unobserved. Publish the rejection evidence in place of
ordinary operand facts. Runtime exception routing belongs to the consumer.

## Replay and acceptance

The opt-in `a64-all-instructions-v2` profile uses the current all-instructions
tool options and the `arm-a64-undefined-operands-1` rule. Replay selects the recorded profile.
The original ELF, archive and observer identities already bind the evidence.
An Arm verdict depends on the original word and rule even if a GNU update
changes its output. The new profile should replay independently of whether
either observer printed an instruction. Existing profiles continue to
reproduce their previous evidence bytes.

1. Require all 407 known originals and their positive and negative controls
   through the coverage and original-ELF commands. The expected result on the
   72,308-word reference sample is exactly those 407 verdicts.
2. Exercise all 36 atomic variants with either data register alone set to 31,
   both set to 31, and neither set to 31. The original 396 words include 360
   with only `Rt == 31` and 36 with both set. Add the 36 `Rt2`-only words
   already corroborated by the disassembly controls. Test `Rn == 31` with
   permitted data registers and check equal non-31 data registers separately.
3. Exercise all eight `size` and `sh` combinations for each of the three SVE
   encodings. Include nearby instructions that reuse these bit positions and
   cases with ambiguous or excluded lookup results.
4. Replay the new evidence after altering the stored verdict or bit fields and
   require rejection of the change. Verify old profiles against existing evidence.
