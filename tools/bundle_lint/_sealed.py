"""Synthetic sealed v2 Bundle writer for ``bundle_lint`` fixtures (POSIX only).

Writes a frozen generation directory the engine admits through its public
entries (``admit_frozen_bundle``, the summary engine, ``build_frozen_bundle_graphs``).
The call-names sidecar of every function is derived from its observation (one
row per CALL / CALLIND, digests from ``configured_naming_contracts``); the
call-interface profile and call-effects members are opaque to the engine and
get a placeholder. ``overrides`` replaces a member's bytes after derivation
(fixtures with a broken member: the seal stays valid, the member does not).

The directory must live on a Linux-native filesystem (owner = current uid, no
group/other write): WSL ``/mnt/*`` mounts fail the engine's ownership checks.
Synthetic data only -- never a real binary's bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NAMING_SOURCE = REPO / "ghidra" / "GhidraV2CallNaming.java"

CONST, RAM, REG, UNIQUE, EXTERNAL = 0, 1, 2, 3, 4
RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = 0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38
RIP = 0x288
LANGUAGE = ("x86:LE:64:default", 4, 6)
X64_REGISTERS = (("RAX", RAX), ("RCX", RCX), ("RDX", RDX), ("RBX", RBX), ("RSP", RSP), ("RBP", RBP),
                 ("RSI", RSI), ("RDI", RDI), ("RIP", RIP))
PLACEHOLDER = {"schema_id": "synthetic-placeholder-not-parsed"}


def dumps(value) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# -- varnodes / rows -----------------------------------------------------------------

def const(value, size=8):
    return {"kind_code": 1, "space_id": CONST, "byte_offset": value, "byte_size": size}


def reg(offset, size=8):
    return {"kind_code": 2, "space_id": REG, "byte_offset": offset, "byte_size": size}


def unique(offset, size=8):
    return {"kind_code": 3, "space_id": UNIQUE, "byte_offset": offset, "byte_size": size}


def ram(offset, size=8):
    return {"kind_code": 4, "space_id": RAM, "byte_offset": offset, "byte_size": size}


def coord(offset):
    return {"space_id": RAM, "byte_offset": offset}


_FLOW_KEYS = ("is_flow", "has_fallthrough", "is_call", "is_jump", "is_terminal", "is_computed",
              "is_conditional", "is_unconditional", "is_override")


def flow(**flags):
    unknown = set(flags) - set(_FLOW_KEYS)
    if unknown:
        raise ValueError(f"unknown flow flags {sorted(unknown)}")
    return {key: bool(flags.get(key, False)) for key in _FLOW_KEYS}


PLAIN = flow(is_flow=True, has_fallthrough=True, is_unconditional=True)   # (as Ghidra exports a plain row)
CALL_FLOW = flow(is_flow=True, has_fallthrough=True, is_call=True, is_unconditional=True)
RET_FLOW = flow(is_flow=True, is_terminal=True, is_unconditional=True)


def ops(*rows):
    """``(opcode, inputs, output|None)`` -> operation dicts with ordinals."""
    return [{"ordinal": index, "opcode": opcode, "inputs": list(inputs), "output_present": out is not None,
             "output": out} for index, (opcode, inputs, out) in enumerate(rows)]


def row(address, length, operations, flow_type=PLAIN, fallthrough=None, targets=()):
    return {"address": coord(address), "fallthrough_present": fallthrough is not None,
            "fallthrough": None if fallthrough is None else coord(fallthrough),
            "flow_targets": [coord(target) for target in targets], "data_references": [],
            "flow_type": flow_type, "operations": operations, "length": length}


def plain(address, length, *operations):
    return row(address, length, ops(*operations), PLAIN, address + length)


def call(address, target, length=5, *, targets=None):
    """``call imm``: push of the return address, then CALL (the realistic Ghidra shape)."""
    after = address + length
    return row(address, length, ops(("INT_SUB", [reg(RSP), const(8)], reg(RSP)),
                                    ("STORE", [const(RAM), reg(RSP), const(after)], None),
                                    ("CALL", [ram(target)], None)),
               CALL_FLOW, after, [target] if targets is None else targets)


def ret(address):
    return row(address, 1, ops(("LOAD", [const(RAM), reg(RSP)], reg(RIP)),
                               ("INT_ADD", [reg(RSP), const(8)], reg(RSP)),
                               ("RETURN", [reg(RIP)], None)), RET_FLOW)


def observation(entry, rows, *, exits=()):
    return {"entry": coord(entry), "instructions": list(rows), "call_fallthrough": "isa",
            "fallthrough_exits": list(exits)}


# -- program ---------------------------------------------------------------------------

def _space(index, *, const=False, reg=False, unique=False, mem=False, external=False):
    return {"space_id": index, "address_size_bits": 64, "addressable_unit_bytes": 1,
            "is_constant_space": const, "is_register_space": reg, "is_unique_space": unique,
            "is_memory_space": mem, "is_overlay_space": False, "is_external_space": external,
            "is_loaded_memory_space": mem, "is_non_loaded_memory_space": False, "has_signed_offset": False}


def program(*, image_base=0x1000, registers=X64_REGISTERS, language=LANGUAGE):
    rows = sorted(((name, offset, 8) for name, offset in registers), key=lambda r: (REG, r[1], r[2], r[0]))
    out = {
        "address_space_classification_revision": 2,
        "translation_namespace": {"language_id": language[0], "major_version": language[1],
                                  "minor_version": language[2]},
        "address_spaces": [_space(CONST, const=True), _space(RAM, mem=True), _space(REG, reg=True),
                           _space(UNIQUE, unique=True), _space(EXTERNAL, external=True)],
        "image_base": coord(image_base),
    }
    if registers is not None:
        out["register_evidence"] = {"revision": 1, "registers": [
            {"name": name, "space_id": REG, "byte_offset": offset, "byte_size": size}
            for name, offset, size in rows]}
    return out


@dataclass
class Block:
    start: int = 0x1000
    data: bytes = b"\xcc" * 0x1000
    name: str = ".text"
    write: bool = False
    execute: bool = True
    external: bool = False   # (loaded + initialized + external, no sealed member: a valid descriptor)


@dataclass
class Function:
    name: str
    observation: dict
    named: bool = True            # (RESOLVED_NAMED target alias for callers)


@dataclass
class Bundle:
    functions: list
    blocks: list = field(default_factory=lambda: [Block()])
    program: dict = field(default_factory=program)
    image_info: object = "default"    # "default" | None (no member) | dict
    overrides: dict = field(default_factory=dict)   # member id -> bytes
    generation: str = "ab" * 32


# -- naming ----------------------------------------------------------------------------

def _naming(generation, observation_id, observation_sha, data, entries, naming_sha):
    from engine_api import AddressCoordinate, ValidatedVarnode, VarnodeKindCode
    from engine_api import (CALL_NAMING_EXPORTER_REVISION, CALL_NAMING_GHIDRA_VERSION, CALL_NAMING_INVENTORY_COMPLETENESS, CALL_NAMING_SCHEMA_ID, CALL_NAMING_SCHEMA_VERSION, CapturedNamingAlias, CapturedNamingResolution, CapturedNamingRow, CapturedNamingTarget, NamingAliasKind, NamingOpcode, NamingResolutionState, NamingSourceQuality, NamingUnresolvedReason, naming_content_digest, naming_row_digest, naming_target_digest)
    from engine_api import CONFIGURED_BUNDLE_MANIFEST_SCHEMA_ID, CONFIGURED_BUNDLE_SEAL_SCHEMA_ID

    rows = []
    for instruction in data["instructions"]:
        address = instruction["address"]
        if not isinstance(address, dict) or not {"space_id", "byte_offset"} <= set(address):
            continue   # (a deliberately malformed fixture row: the scope reader refuses it)
        place = AddressCoordinate(address["space_id"], address["byte_offset"])
        for operation in instruction["operations"]:
            if operation["opcode"] not in ("CALL", "CALLIND"):
                continue
            opcode = NamingOpcode(operation["opcode"])
            first = operation["inputs"][0] if operation["inputs"] else None
            selector = None if first is None else ValidatedVarnode(
                VarnodeKindCode(first["kind_code"]), AddressCoordinate(first["space_id"], first["byte_offset"]),
                first["byte_size"])
            targets = ()
            if opcode is NamingOpcode.CALLIND:
                resolution = CapturedNamingResolution(NamingResolutionState.INDIRECT)
            elif selector is None:
                resolution = CapturedNamingResolution(NamingResolutionState.UNRESOLVED,
                                                      NamingUnresolvedReason.MISSING_SELECTOR)
            elif selector.kind is VarnodeKindCode.OPAQUE:
                resolution = CapturedNamingResolution(NamingResolutionState.UNRESOLVED,
                                                      NamingUnresolvedReason.OPAQUE_SELECTOR)
            elif selector.kind is not VarnodeKindCode.ADDRESS:
                resolution = CapturedNamingResolution(NamingResolutionState.UNRESOLVED,
                                                      NamingUnresolvedReason.NON_ADDRESS_SELECTOR)
            elif (selector.coordinate.space_id, selector.coordinate.byte_offset) in entries:
                name, named = entries[(selector.coordinate.space_id, selector.coordinate.byte_offset)]
                aliases = (CapturedNamingAlias(NamingAliasKind.SYMBOL, name, NamingSourceQuality.USER_DEFINED),) \
                    if named else ()
                digest = naming_target_digest(0, selector.coordinate, False, False, aliases)
                targets = (CapturedNamingTarget(0, selector.coordinate, False, False, aliases, digest),)
                state = NamingResolutionState.RESOLVED_NAMED if named else NamingResolutionState.RESOLVED_UNNAMED
                resolution = CapturedNamingResolution(state, terminal_target_ordinal=0)
            else:
                resolution = CapturedNamingResolution(NamingResolutionState.UNRESOLVED,
                                                      NamingUnresolvedReason.NO_EXACT_FUNCTION)
            ordinal = operation["ordinal"]
            digest = naming_row_digest(place, ordinal, opcode, selector, resolution, targets)
            rows.append(CapturedNamingRow(place, ordinal, opcode, selector, resolution, targets, digest))
    rows = tuple(sorted(rows, key=lambda item: item.canonical_key))
    content = naming_content_digest(naming_sha, rows, ())

    def selector_json(value):
        if value is None:
            return {"state": "MISSING"}
        return {"state": "PRESENT", "kind_code": int(value.kind), "space_id": value.coordinate.space_id,
                "byte_offset": value.coordinate.byte_offset, "byte_size": value.byte_size}

    def resolution_json(value):
        out = {"state": value.state.value}
        if value.reason is not None:
            out["reason"] = value.reason.value
        if value.terminal_target_ordinal is not None:
            out["terminal_target_ordinal"] = value.terminal_target_ordinal
        if value.cycle_target_ordinal is not None:
            out["cycle_target_ordinal"] = value.cycle_target_ordinal
        return out

    def alias_json(alias):
        if alias.kind is NamingAliasKind.SYMBOL:
            return {"kind": alias.kind.value, "source_quality": alias.source_quality.value, "value": alias.value}
        return {"kind": alias.kind.value, "value": alias.value}

    return {
        "schema_id": CALL_NAMING_SCHEMA_ID, "schema_version": CALL_NAMING_SCHEMA_VERSION,
        "exporter_revision": CALL_NAMING_EXPORTER_REVISION, "exporter_source_sha256": naming_sha.hex(),
        "ghidra_version": CALL_NAMING_GHIDRA_VERSION,
        "transport": {"generation_id": generation, "manifest_schema_id": CONFIGURED_BUNDLE_MANIFEST_SCHEMA_ID,
                      "seal_schema_id": CONFIGURED_BUNDLE_SEAL_SCHEMA_ID,
                      "observation_member_id": observation_id, "observation_member_sha256": observation_sha,
                      "function_entry": data["entry"]},
        "inventory_completeness": CALL_NAMING_INVENTORY_COMPLETENESS,
        "calls": [{
            "instruction": {"space_id": item.instruction.space_id, "byte_offset": item.instruction.byte_offset},
            "operation_ordinal": item.operation_ordinal, "opcode": item.opcode.value,
            "selector": selector_json(item.selector), "resolution": resolution_json(item.resolution),
            "targets": [{"target_ordinal": target.target_ordinal,
                         "coordinate": {"space_id": target.coordinate.space_id,
                                        "byte_offset": target.coordinate.byte_offset},
                         "is_external": target.is_external, "is_thunk": target.is_thunk,
                         "aliases": [alias_json(alias) for alias in target.aliases],
                         "target_digest": target.target_digest.hex()} for target in item.targets],
            "row_digest": item.row_digest.hex()} for item in rows],
        "tail_calls": [],
        "semantic_content_digest": content.hex(),
    }


# -- writer ----------------------------------------------------------------------------

def write(root, bundle: Bundle) -> Path:
    """Write ``bundle`` under ``root``; returns the generation directory."""
    root = Path(root)
    generation = bundle.generation
    gen = root / generation
    gen.mkdir(mode=0o755)
    os.chmod(gen, 0o755)
    naming_sha = hashlib.sha256(NAMING_SOURCE.read_bytes()).digest()
    members = []

    def member(member_id, name, data):
        data = bundle.overrides.get(member_id, data)
        (gen / name).write_bytes(data)
        os.chmod(gen / name, 0o644)
        members.append({"id": member_id, "path": name, "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest()})
        return members[-1]

    blocks = sorted(bundle.blocks, key=lambda block: block.start)
    member("original", "original.bin", b"".join(block.data for block in blocks if not block.external) or b"\0")
    member("program", "program.json", dumps(bundle.program))
    member("call-interface-profile", "call-interface-profile.json", dumps(PLACEHOLDER))
    block_rows = []
    for index, block in enumerate(blocks):
        if not block.external:
            member(f"memory-{index:06d}", f"memory-{index:06d}.bin", block.data)
        block_rows.append({"id": f"block-{index:06d}", "space_id": RAM, "byte_start": block.start,
                           "byte_size": len(block.data), "is_loaded": True, "is_initialized": True,
                           "is_overlay": False, "is_external": block.external, "is_mapped": False,
                           "member_id": None if block.external else f"memory-{index:06d}"})
    image_info = bundle.image_info
    if image_info == "default":
        image_info = {"schema": "tdo-v2-image-info-1", "executable_format": "Raw Binary",
                      "block_permissions": [{"block_id": f"block-{index:06d}", "name": block.name, "read": True,
                                             "write": block.write, "execute": block.execute, "volatile": False}
                                            for index, block in enumerate(blocks)],
                      "imports": [], "exports": [], "relocations": []}
    if image_info is not None:
        member("image-info", "image-info.json", dumps(image_info))
    entries = {(item.observation["entry"]["space_id"], item.observation["entry"]["byte_offset"]):
               (item.name, item.named) for item in bundle.functions}
    functions = []
    for index, item in enumerate(bundle.functions):
        fid, nid, eid = f"function-{index:06d}", f"call-names-{index:06d}", f"call-effects-{index:06d}"
        obs = member(fid, fid + ".json", dumps(item.observation))
        member(nid, nid + ".json", dumps(_naming(generation, fid, obs["sha256"], item.observation, entries,
                                                 naming_sha)))
        member(eid, eid + ".json", dumps(PLACEHOLDER))
        functions.append({"id": fid, "observation_member": fid, "call_names_member": nid,
                          "call_effects_member": eid})
    manifest = {"schema_version": 2, "generation_id": generation, "original_member_id": "original",
                "program_member_id": "program", "call_interface_profile_member": "call-interface-profile",
                "members": members, "blocks": block_rows, "functions": functions}
    if image_info is not None:
        manifest["image_info_member"] = "image-info"
    manifest_bytes = bundle.overrides.get("manifest.json", dumps(manifest))
    (gen / "manifest.json").write_bytes(manifest_bytes)
    seal = {"schema_version": 2, "generation_id": generation, "manifest_size": len(manifest_bytes),
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest()}
    (gen / "seal.json").write_bytes(bundle.overrides.get("seal.json", dumps(seal)))
    for name in ("manifest.json", "seal.json"):
        os.chmod(gen / name, 0o644)
    return gen


def two_function_bundle(**changes) -> Bundle:
    """The reference pair: A (0x1000) ``RCX = 23; call B; ret``, B (0x1800) ``RAX = RCX; ret``."""
    a = Function("A", observation(0x1000, [plain(0x1000, 7, ("COPY", [const(23)], reg(RCX))),
                                           call(0x1007, 0x1800), ret(0x100C)]))
    b = Function("B", observation(0x1800, [plain(0x1800, 3, ("COPY", [reg(RCX)], reg(RAX))), ret(0x1803)]))
    return Bundle([a, b], **changes)
