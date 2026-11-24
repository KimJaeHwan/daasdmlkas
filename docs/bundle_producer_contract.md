# Bundle producer contract (survey 2026-11-24; file:line refer to the tree at feature/gt-g3b7b 7b631de -- re-check against main)

Short version: the container (directory, manifest, seal) is strict and byte-checked; function files are lenient
(unknown keys ignored); the call-names sidecar is pinned to the Ghidra naming exporter's source hash and "12.0.4";
many engine features fire only on Ghidra's exact p-code shapes and SLEIGH register offsets.

## 1. Layout on disk
- Entry: `admit_frozen_bundle(<root>/<generation>)` (src/tdo_v2/integration/configured_bundle.py:254-326), used by
  summary_engine.py:200-203, engine.py:199-201, base_graph.py:303-311. POSIX only (O_NOFOLLOW, fcntl; 805-807).
- Generation dir = 64 lowercase hex (287, 777-780). Total manifest + seal + members <= 512 MiB (39, 301-305).
- Every entry: regular file (or the dir), owned by the current uid, link count 1, not group/other-writable, no symlink
  (791-802, 669-686); no two members the same file (445-446, 513-516); the dir holds exactly the members +
  `manifest.json` + `seal.json` (643-645); members re-hashed at admission (343-371) and on every read
  (_configured_bundle_snapshot.py:509-537).
- Control JSON: strict UTF-8, duplicate keys rejected, NaN/Infinity rejected, root object (703-724); integers are real
  ints in u64 (732-739); digests 64 lowercase hex; ids `[A-Za-z0-9][A-Za-z0-9._-]*` 1-128 (38, 748-756); member paths
  flat 1-255, not manifest/seal/.configured-bundle.lock (765-774).
- `seal.json` = exactly {schema_version: 2, generation_id (= dir name), manifest_size, manifest_sha256} (443-462);
  seal / manifest 1 B..16 MiB.
- `manifest.json` format 2 = exactly {schema_version 2, generation_id, original_member_id, program_member_id, members,
  blocks, functions, call_interface_profile_member} + optional image_info_member (465-485).
  members[] {id, path, size>0, sha256} (501-521); blocks[] {id, space_id, byte_start, byte_size>0, is_loaded,
  is_initialized, is_overlay, is_external, is_mapped, member_id|null} -- member_id non-null exactly when loaded &&
  initialized && !overlay && !external && !mapped, and its size == byte_size (535-567; snapshot 169-179);
  functions[] {id, observation_member, call_names_member, call_effects_member}, 1..4096 (582-602); every member used;
  block ids and function ids string-sorted; member order: original, program, profile, block memories in block order,
  image-info, then per function observation / call-names / call-effects (616-642).
- Limits: observation and program 256 MiB, call-names / call-effects 64 MiB, profile 1 MiB, <= 77,827 members,
  <= 65,536 blocks.
- Files the Ghidra exporter writes (GhidraV2BundleExport.java publish 667-753): `original.bin` (input copy, checked vs
  --original-size/-sha256 755-782; engine hashes it into executable_sha256; exception_directory.py re-reads it),
  `program.json`, `call-interface-profile.json` (presence / size / hash only -- contents never parsed),
  `memory-NNNNNN.bin` per included block, `image-info.json` (optional), per function `function-NNNNNN.json`,
  `call-names-NNNNNN.json`, `call-effects-NNNNNN.json` (contents never parsed).
- Publish: staging dir -> fsync -> atomic rename -> receipt "<gen>\n<nonce>\n" (exporter 670-739; export_bundle.py
  266-267, 345-351). Tool-level only; the engine does not check it.

## 2. Function observation JSON (_scope_observation.py)
- Duplicate known keys = defect; unknown keys ignored; any defect refuses the function (_scope_envelope.py:273-306).
- Root: `entry` {space_id, byte_offset} in committed loaded memory; `instructions` <= 262,144 rows, unique addresses,
  digest over the given order (emit ascending); optional `call_fallthrough: "isa"` + `fallthrough_exits`
  [{source, target, kind 2|3|4, function|null}] (kind 4: function null; kind 2: function == target; kind 3: function !=
  target; never the own entry; one per source) (298-351; _scope_contracts.py:545-573); optional `proof_input:
  "attested-fresh-import-v1"`; optional `exception_handlers: "none"` (effective only with proof_input).
- Row: `address`; `fallthrough_present` + `fallthrough` (marker rule; committed memory unless an isa kind-4 exit);
  `flow_targets` (committed or EXTERNAL; EXTERNAL dropped; sorted, deduplicated; <= 65,536 per row, 1,048,576 per
  function); optional `data_references` {space_id, byte_offset, is_read, is_write, referenced_function_entry...};
  `flow_type` = 9 required bools (is_flow, has_fallthrough, is_call, is_jump, is_terminal, is_computed, is_conditional,
  is_unconditional, is_override; not call && jump, not conditional && unconditional) -- Ghidra FlowType semantics, read
  by call_seeds.py:35-73, control_projection.py:155/206, call_relations.py:123, configured_call_memory_read_bridge.py;
  `operations`; optional `length` 1..64.
- isa cross-rules (_scope_contracts.py:577-669): every row whose fallthrough is non-local or another function's entry is
  listed; exit target == row fallthrough; a row without fallthrough only as kind 4; every native call (CALL/CALLIND not
  in the interrupt shape) has a fallthrough or a listed exit.
- exception-fact cross-rules: needs isa; no BRANCHIND; gated call rows have length and a non-local continuation ==
  address + length; then exception_targets = () on call rows.
- Operation {ordinal == position, opcode `[A-Z][A-Z0-9_]*` <= 64 not "UNKNOWN", inputs, output_present, output};
  varnode {kind_code 1 CONSTANT / 2 REGISTER / 3 UNIQUE / 4 ADDRESS / 5 STORAGE / 7 OPAQUE, space_id (must exist,
  kind matches space class), byte_offset, byte_size > 0}; extent checks (_scope_program.py:126-155): CONSTANT < 2^(8
  size), ADDRESS first byte committed (a CALL to unmapped RAM refuses the function), STORAGE whole extent committed.
- Call-names sidecar (configured_naming.py): fully strict; root {schema_id "tdo-v2-call-naming-sidecar-v2",
  schema_version 2, exporter_revision 2, exporter_source_sha256 == SHA-256 of ghidra/GhidraV2CallNaming.java,
  ghidra_version "12.0.4", inventory_completeness "COMPLETE", transport {generation_id, manifest / seal schema ids,
  observation member id + sha256, function_entry}, calls, tail_calls, semantic_content_digest}; one row per CALL /
  CALLIND op in (space, offset, ordinal) order matching the p-code; tail rows per BRANCH/CBRANCH/BRANCHIND in an
  is_call row with non-constant destination; resolution INDIRECT / UNRESOLVED / RESOLVED_NAMED / RESOLVED_UNNAMED;
  thunk chains, aliases (SYMBOL with source quality, ORIGINAL_IMPORT); row / target / content digests recomputed.

## 3. Ghidra conventions inside the engine (a different lifter silently loses these)
- Ops named: COPY, LOAD, STORE, BRANCH, CBRANCH, BRANCHIND, CALL, CALLIND, CALLOTHER, RETURN, INT_*, BOOL_*, PIECE,
  SUBPIECE, POPCOUNT, LZCOUNT, some FLOAT_*; unknown opcode = generic WRITE of its output (normalize.py:3063-3130).
- LOAD/STORE input 0 = CONSTANT space id; CALL/BRANCH input 0 = target; CALLOTHER input 0 = user-op index; constant
  BRANCH/CBRANCH destination = relative p-code index (pcode_blocks.py).
- UNIQUE keyed by offset per function; REGISTER keyed by byte offset (sub-registers overlap by byte, as SLEIGH).
- Exact shapes: interrupt `CALLOTHER; CALLIND; [RETURN]`; x86-64 CALL `INT_SUB RSP,8; STORE; CALL`; RET `LOAD; INT_ADD;
  RETURN`; AArch64 BL/BLR; `rep movs/stos` (11 / 17 ops); `ud2` (`CALLOTHER 77; BRANCHIND`, keyed to 12.0.4
  x86:LE:64:default v4.6 under `stock-ghidra-translator`); `call $+5` push + BRANCH.
- CALLOTHER index tables: LOCK 17, UNLOCK 18, transactional 84/85/86/99.
- Hard-coded SLEIGH x86-64 offsets: RSP 0x20, GPRs 0x00-0x40 / 0x80-0xC0, flags 0x200..0x20B, RIP 0x288
  (interprocedural.py:1974-1987); models carry raw offsets (AArch64 x0 = 16384); SP / PC / LR by SLEIGH name in
  register_evidence; language id parsed `proc:endian:size:variant` (isa_identity.py).
- String checks: `x86:LE:64:default`, `x86:LE:64`, `:LE:`, `executable_format.startswith("Portable Executable")`.
- Exporter-only proofs the engine trusts: S1, the exception fact, landing pads appended to flow_targets.

## 4. Program-level data
- `program.json`: translation_namespace {language_id, major_version, minor_version}; address_space_classification_
  revision 1|2; address_spaces[] (rev 2 flags); image_base (start of a committed run); register_evidence {revision 1,
  registers [{name, space_id, byte_offset, byte_size}]} (needed in practice).
- Memory blocks -> committed runs (_scope_memory.py:115-162): loaded only; a loaded overlay or mapped block makes the
  program INCOMPLETE; overlapping blocks CONFLICTING.
- `image-info.json` (plain json.loads): schema "tdo-v2-image-info-1", executable_format, block_permissions, imports
  {library, name, original_name, slots, thunks}, exports, relocations {space_id, byte_offset, byte_size}; used by
  external models, linking, read-only image values (little-endian), internal model cuts, template derivation (x86-64).
- Stack-switch evidence: separate file `tdo-v2-stack-switch-evidence` v1.

## 5. If a producer emits equal semantics with different p-code
- Changes: observation digest, function / program scope ids, naming digests, operation keys
  `space:offset:ordinal:OPCODE`; templates' proof receipts. Not automatic: ENGINE_SEMANTICS_VERSION 57,
  TEMPLATE_VERSION 7, RECORD_VERSION 19. Derived templates bind DLL SHA / image base / language / engine versions but
  not the producer -> Ghidra-derived templates would still load. Link cache profiles include Ghidra version + Java
  source hashes (linking.py:150-171) -> a new producer needs its own identity. CALLOTHER tables keyed to 12.0.4.

## 6. Existing docs
tools/bundle_export/README.md (Export, prepared project, stack-switch evidence, Linking, Admit/normalize/run, Known
issues -- EXTERNAL space id 42, S1); docs/interprocedural_design.md 15, 25.86, 25.94, 25.100, 25.101, 25.102, 25.112,
25.106, 25.115; docs/intra_function_stabilization.md 4, 7, 8, 10; docs/assumptions.md rows 18-19; README.md.
None is a complete wire spec; the code is authoritative.

UNSURE: instruction order beyond the digest; unique-before-use enforcement; relocation application in block bytes;
whether call-effects / call-interface-profile contents are decoded anywhere else.
