# S3 -- r17 (2026-11-24): changes to r16

Status: DRAFT r17, review round 7 (S3 only). Read with `design_s3_r16.md`; r17 replaces r16 1.1 (candidates), the
DECLINED outcome of 1.2 / 2, and adds rules. Round-6 reviews: Astra `scc_r16_astra6.md` (REJECT, 4 P1, 3 P2, 1 P3),
Fable `scc_r16_fable6.md` (APPROVE WITH FIXES, 0 P1, 4 P2, 5 P3). Base main 18a5f5e.

## Why the DECLINED effect goes away
Three of Astra's four round-6 P1s (and Fable P2-1) come from one source: a kernel-byte row whose lifting is not one of
the two exact shapes (e.g. `0F 05` lifted as `COPY RAX, 7`, or with a `CALL`) still has raw operations, and every reader
that walks raw operations (normalization, call discovery, finite replay, call-clobber, the state barrier, dynamic-alias
certificates) would need the decision to replace them. Under the engine-wide decode premise (owner 2026-11-24:
"Ghidra decode = CPU", Bundle = trust boundary) such a row is a contradiction between the bytes and the lifting.
r17 therefore **never analyses a contradicting kernel-byte row**: with S3 ON, a function holding a kernel-byte row that
is not ADMITTED is **refused** with a named reason. Only ADMITTED rows -- the exact shapes, whose raw operations are
the CALLOTHER (+ CALLIND) the effect replaces -- are analysed. Producer independence: another producer's correct
lifting is added to the shape list under that producer's identity (a reviewed table change), never inferred.

## R-1 Candidates (replaces r16 1.1 bytes rule; Astra r6 P1-4, Fable r6 P2-2)
* Applicability unchanged (sealed PE32+, AMD64, subsystem 1 / 2 / 3) **and** the Bundle is an S1 Bundle
  (`call_fallthrough: "isa"` -- rows carry `length`); otherwise no candidates, recorded in the run report as
  `kernel-sites-not-evaluated` (today's behaviour, like OFF).
* A **kernel-byte row**: at the row address, zero or more x86 prefix bytes (legacy prefixes 66 / 67 / F0 / F2 / F3 /
  2E / 36 / 3E / 26 / 64 / 65 and one REX 40-4F directly before the opcode) followed by `0F 05` or `CD 2E`, all within
  the row's `length`. Only the unprefixed form (`length` 2) can be ADMITTED.
* Bytes: read from the Bundle's sealed initialised block bytes. Three evidence states (Fable r6 P2-3): (a) Bundle-backed
  -- bytes read; (b) the entry was called **explicitly** without a Bundle (synthetic units in tests, `interprocedural.py:557-560`,
  `summary_engine.py:253`) -- no candidates, recorded; (c) Bundle-backed but the row's bytes are not readable
  (uninitialised / missing payload, Astra r6 P2) -- with S3 ON the function is refused (`kernel-bytes-unavailable`),
  with S3 OFF nothing is read. An S3 OFF run needs no bytes.

## R-2 Decision (replaces r16 1.2 outcome)
`kernel_site_decision` returns ADMITTED or REFUSED(reason) with the r16 1.2 conditions (length 2 + exact shape + flow +
RSP evidence) for an unprefixed row; a prefixed row is REFUSED(`kernel-prefixed`). With S3 ON, any REFUSED row refuses
its **function** before normalization (an admission-stage refusal of S3, reported per reason and counted; no
`control:unavailable` beyond what any refused function gets today). With S3 OFF no decision is made (today exactly).
The expected count on stock Ghidra S1 exports is 0; the implementation measures it on ntdll and the gate and reports it.
Consequences: Astra r6 P1-1 (declined lifting supplies values / call edges), P1-3 (declined continuation in the state
barrier and in alias certificates) and Fable r6 P2-1 (attach point) have no subject left; the r16 DECLINED column and
`kernel-declined` key are removed.

## R-3 ADMITTED rows in every raw reader (Astra r6 P1-2, P1-3 for the admitted case)
* The ADMITTED row's raw operations are exactly the CALLOTHER (+ CALLIND); every raw reader that interprets a CALLOTHER
  as "changes nothing" must consume the S3 effect instead. Known: the stack-switch check
  (`may_alias.py:1616, 1642`, used at `interprocedural.py:641` to select program-wide assumptions): after an ADMITTED
  site every register except RSP is unknown, so a register holding a saved RSP (`mov rbx, rsp; syscall; mov rsp, rbx`)
  no longer counts as the saved SP -- the switch check treats the later `mov rsp, rbx` as a possible stack switch.
  The state barrier (`configured_state_barrier.py:99`) and the dynamic-alias certificate's intervening-operation scan
  (`configured_dynamic_alias_explanation.py:500`) treat an ADMITTED row as a call with the S3 writer (RAM unknown
  writer -> not transparent). Implementation check: every place that tests `opcode == "CALLOTHER"` (or skips it) is
  listed in the code review with its S3 behaviour; test for each named reader.
* Writer class (Fable r6 P2-4): the S3 effect's writer is RAM **by the decision**, set where the effect is installed
  (`write_classes.py:29, 62-75` gains the kernel-site case keyed by the effect's synthetic callee id), not by opcode.

## R-4 Invariant scope (Astra r6 P2)
The report-time invariant checks every kernel-byte row in the static registry for a decision, and the effect + writer +
key only where the row is placed (reachable) in that analysis instance (`pcode_blocks.py:529`, `normalize.py:1995`).

## R-5 Templates (Astra r6 P2; Fable r6)
Closure refusal needs no new mechanism: `kernel-return` is outside `_TEMPLATE_SITE_KINDS`
(`summary_templates.py:260-261, 355`). Switch equality is enforced in the **shared** template import check
(`interprocedural.py:704`) against the consumer's effective S3 switch, in both profiles, both mismatch directions tested;
the code-only vector check stays as an extra.

## R-6 Test expectations (Astra r6 P3)
* Unprefixed `0F 05` lifted as `CALLOTHER(17)` with all other evidence valid: ADMITTED (the byte rule decides; the
  LOCK marker never claims it). The same row without `length`, or with conflicting flow: REFUSED function. Prefixed
  `48 0F 05` / `F3 0F 05` with any lifting: REFUSED function (S3 ON), today's behaviour (OFF).
* Remaining r16 section 4 tests stand, minus the DECLINED-effect ones.

## R-7 P3 carry-overs (Fable r6)
Subsystem 1 (native) is kept (drivers are out of the user-mode contract's scope but `native` user-mode images such as
smss exist; documented in docs/assumptions.md); every parser of `ProvenCallEffect.callee` accepts the non-hex synthetic
id `kernel:<model>@<version>` (list in code review); the delta-proof fingerprint change bumps PROOF_VERSION.

## Findings -> fixes (round 6)
| finding | fix |
|---|---|
| Astra P1-1, Fable P2-1 (declined lifting / attach point) | R-2 (no declined analysis) |
| Astra P1-2 (stack-switch check) | R-3 |
| Astra P1-3 (state barrier, alias certificate) | R-2 (declined) + R-3 (admitted) |
| Astra P1-4, Fable P2-2 (prefixed) | R-1, R-2 |
| Astra P2 (invariant scope) | R-4 |
| Astra P2 (byte availability), Fable P2-3 (evidence states) | R-1 |
| Astra P2 (shared template switch check) | R-5 |
| Fable P2-4 (writer class) | R-3 |
| Astra P3 (CALLOTHER(17) expectation) | R-6 |
| Fable P3s | R-5, R-7 |
