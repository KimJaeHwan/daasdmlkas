# A64 MSR UAO disassembly in GNU Binutils

GNU objdump 2.45, 2.47.20260726 and the 2.47.50.20261128 snapshot
(`11eb291c4cc`) print a generic system-register name for `MSR (immediate)`
targeting `UAO` when the encoded immediate is 2 through 15. Apple LLVM 21.0.0
and Arm Toolchain for Embedded 23.1.0 print the named `UAO` operation.
The original catalogue sample exposed three such words. A separate sweep of
all 16 immediate values reproduced the difference for 14 words in each GNU version.

| Word | Little-endian bytes | Apple LLVM | GNU objdump with no aliases |
| --- | --- | --- | --- |
| `0xd500437f` | `7f 43 00 d5` | `msr UAO, #3` | `msr s0_0_c4_c3_3, xzr` |
| `0xd500477f` | `7f 47 00 d5` | `msr UAO, #7` | `msr s0_0_c4_c7_3, xzr` |
| `0xd5004f7f` | `7f 4f 00 d5` | `msr UAO, #15` | `msr s0_0_c4_c15_3, xzr` |

The pinned Arm A64 ISA XML for 2026-06, `msr_imm.xml` (`MSR_SI_pstate`),
uses `op1=000` and `op2=011` for `UAO` and takes the immediate from
`CRm[3:0]`. With `FEAT_UAO` and sufficient privilege, the operation assigns
the low bit of the operand to `PSTATE.UAO`. For example, immediate 3 sets the
bit to 1. The [Arm A64 ISA documentation](https://developer.arm.com/documentation/ddi0602/2026-06/)
provides the encoding and pseudocode.

GNU's `opcodes/aarch64-opc.c` declares a maximum immediate of 1 for
`AARCH64_OPND_PSTATEFIELD` entries named `uao`. The operand constraint rejects
2 through 15 for the named form. Apple Clang reassembled both tools' spellings
to the same byte sequence for all 16 values. The observed difference concerns
the named operation in the disassembly. A consumer that only sees GNU's
printed register may miss the update to `PSTATE.UAO`.

Recheck with A64 ELF instruction words `0xd500407f | (imm << 8)` for
`imm = 0..15`. Compare `llvm-objdump -d --mattr=+all` with
`aarch64-linux-gnu-objdump -d -M no-aliases`. Record the decoder version
and retain the original bytes alongside each rendering.
