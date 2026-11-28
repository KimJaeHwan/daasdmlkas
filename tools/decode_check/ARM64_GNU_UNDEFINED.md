# GNU objdump renders undefined A64 instructions

GNU objdump 2.45, 2.47.20260726 and 2.47.50.20261128 (`11eb291c4cc`) print a
mnemonic for 407 test words for which the pinned Arm A64 2026-06 rules specify
`Decode_UNDEF`. Arm Toolchain for Embedded 23.1.0 leaves all 407 unrecognized.
The test ran on A64 ELF words with `--disassembler-options=no-aliases` and used
`--mattr=+all` for the Arm LLVM observer.

| Words | Forms | Arm rejection rule |
| ---: | --- | --- |
| 132 | LSE128 `LDCLRP`, `LDSETP`, `SWPP` and their acquire/release forms | `Rt == 31` or `Rt2 == 31` |
| 264 | D128+THE `RCWCLRP`, `RCWSETP`, `RCWSWPP`, `RCWSCLRP`, `RCWSSETP`, `RCWSSWPP` and their acquire/release forms | `Rt == 31` or `Rt2 == 31` |
| 11 | SVE immediate `CPY` (zeroing and merging) and `DUP` | `size == 0` with `sh == 1` |

In the atomic family, GNU extracts the two five-bit register fields through
its register decoder and prints 31 as `xzr`. Its opcode entries use the
general register operand checks, which have no `XZR` prohibition for these
operands. Arm rejects either data register carrying 31 before the memory
operation. In a supplementary disassembly run, setting only `Rt2` to 31
reproduced the difference for all 36 encoding variants. Both observers
rendered each control word with distinct allowed data registers identically.
[Arm A64 instruction definitions, 2026-06](https://developer.arm.com/documentation/ddi0602/2026-06/)
and [GNU opcode table at the tested snapshot](https://gnu.googlesource.com/binutils-gdb/+/11eb291c4cca9ddcc5942d8fcc379e2418f92c92/opcodes/aarch64-tbl.h).

In the SVE family, `decode_sve_aimm` folds the nonzero immediate and the
encoded shift into one number. In these words the signed immediate is
`-1`, so it becomes `-256` while the recorded shift amount stays zero. The
subsequent 8-bit operand check sees the folded value and zero shift. Arm
checks the original `size` and `sh` fields and rejects the pair before the
vector operation. [GNU immediate decoder](https://gnu.googlesource.com/binutils-gdb/+/11eb291c4cca9ddcc5942d8fcc379e2418f92c92/opcodes/aarch64-dis.c#1869)
and [GNU operand checks](https://gnu.googlesource.com/binutils-gdb/+/11eb291c4cca9ddcc5942d8fcc379e2418f92c92/opcodes/aarch64-opc.c#2829).

## Native CPU results

The native probes ran on an Apple M4 Max with macOS 26.3.1 (a), build
`25D771280a`. Each probe ran in its own child process. Atomic probes used
a zeroed, 16-byte-aligned local buffer. SVE probes entered SME streaming
mode with `SMSTART SM`. A control that only entered and exited streaming
mode returned successfully.

| Original word | GNU output for the original | Paired control | Native result |
| --- | --- | --- | --- |
| `0x1920101f` | `ldclrp xzr, x0, [x0]` | `0x19201001` | Both raised `SIGILL` |
| `0x1920901f` | `rcwclrp xzr, x0, [x0]` | `0x19209001` | Both raised `SIGILL` |
| `0x05103fff` | `cpy z31.b, p0/z, #-256` | `0x05101fff` | Original raised `SIGILL`. Control returned. |
| `0x2538ffff` | `dup z31.b, #-256` | `0x2538dfff` | Original raised `SIGILL`. Control returned. |

All 11 SVE originals raised `SIGILL`. All 11 controls returned after clearing
only bit 13. The complete original SVE word list is
`05103fff`, `05107fff`, `05113fff`, `05117fff`, `05133fff`, `05137fff`,
`05173fff`, `05177fff`, `051f3fff`, `051f7fff`, and `2538ffff`.
The two atomic positive controls also trapped on this host, so the atomic
selector verdict relies on the Arm specification. The architecture defines
`UNDEFINED` as an exception when the processor attempts to execute the word.
[Arm AArch64 exception model](https://support.arm.com/documentation/102412/0103/Exception-types/Synchronous-exceptions).

The 72,308-word source sample has SHA-256
`2300f48890db7bd1036cc8009238bb3d44c3ea3e47529bde86a1b13c2ce2cd41`.
The pinned 2026-06 Arm XML archive has SHA-256
`63a01a1696483bbe2edfef9e0f0cd053d6c1c619ec0587876cb7a60bb344f354`.
