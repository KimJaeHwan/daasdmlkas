#!/usr/bin/env python3
"""``bundle_lint`` variant tool (design G0 r0..r6): copy a Bundle and change one
condition, then re-seal (member size / sha256, manifest, seal). POSIX / WSL.

    PYTHONPATH=src python3 tools/bundle_lint/mutate.py <generation> <out_root> <variant>
        [--function function-000000] [--site 1:1007:2:CALL] [--index 0]

The copy keeps the generation id (sidecar transports stay valid), is written
without hard links (nlink 1), files 0644, directory 0755.

Variants (r1 s6, r2 s7, r3 s4, r6 s2-3):
  seal           one hex digit of seal.json manifest_sha256
  call-ordinal   one naming row's operation_ordinal +1 (order / uniqueness kept), row / content digests re-derived
  call-pattern   INT_SUB RSP,8 -> INT_ADD RSP, 2^64-8 in a push-call row
  call-reshape   u = INT_SUB RSP,8; RSP = COPY u; STORE [u]; CALL (unused 8-byte UNIQUE; CALL ordinal moves)
  call-swap      STORE before INT_SUB (a meaning change, recorded as such)
  exit-kind4     S1 exit --index: kind 2 -> 4, function -> null (r6 s2)
  drop-pad       remove one local landing pad (--site's local non-fallthrough flow target) from the call row (r6 s3)

Observation changes update the observation member and the observation sha256
in the naming transport and, when the call-effects member is a real sidecar,
in its transport. The engine never decodes call-effects; when a variant moves
an ordinal, its call-effects rows are moved too but their digests are not
re-derived -- the result says so (``call_effects``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))

import _sealed  # noqa: E402

VARIANTS = ("seal", "call-ordinal", "call-pattern", "call-reshape", "call-swap", "exit-kind4", "drop-pad")
WRAP_MINUS_8 = (1 << 64) - 8


class VariantError(ValueError):
    pass


# -- copy / reseal ------------------------------------------------------------------------

def copy_bundle(source: Path, out_root: Path) -> Path:
    """Copy an admissible Bundle: the source is admitted first (the engine's own
    checks: flat safe member names, hashes, no unlisted entries), then only the
    listed members and the two control files are copied (Astra impl r1 P1)."""
    from tdo_v2.integration.configured_bundle import _safe_name, admit_frozen_bundle

    admit_frozen_bundle(source)
    manifest = _json(source / "manifest.json")
    names = [_safe_name(row["path"]) for row in manifest["members"]] + ["manifest.json", "seal.json"]
    target = out_root / source.name
    target.mkdir(mode=0o755)
    os.chmod(target, 0o755)
    for name in names:
        (target / name).write_bytes((source / name).read_bytes())
        os.chmod(target / name, 0o644)
    return target


def _json(path: Path):
    return json.loads(path.read_bytes())


def _write_member(generation: Path, manifest: dict, member_id: str, data: bytes) -> None:
    from tdo_v2.integration.configured_bundle import _safe_name

    row = next(row for row in manifest["members"] if row["id"] == member_id)
    name = _safe_name(row["path"])
    (generation / name).write_bytes(data)
    os.chmod(generation / name, 0o644)
    row["size"] = len(data)
    row["sha256"] = hashlib.sha256(data).hexdigest()


def reseal(generation: Path, manifest: dict) -> None:
    data = _sealed.dumps(manifest)
    (generation / "manifest.json").write_bytes(data)
    seal = _json(generation / "seal.json")
    seal["manifest_size"] = len(data)
    seal["manifest_sha256"] = hashlib.sha256(data).hexdigest()
    (generation / "seal.json").write_bytes(_sealed.dumps(seal))


def _function_row(manifest: dict, function_id: str) -> dict:
    row = next((row for row in manifest["functions"] if row["id"] == function_id), None)
    if row is None:
        raise VariantError(f"no function {function_id!r}")
    return row


def _member_path(generation: Path, manifest: dict, member_id: str) -> Path:
    from tdo_v2.integration.configured_bundle import _safe_name

    return generation / _safe_name(next(row["path"] for row in manifest["members"] if row["id"] == member_id))


# -- naming re-derivation (the engine's own encoders) ------------------------------------

def _typed_naming_row(raw):
    from tdo_v2._scope_contracts import AddressCoordinate, ValidatedVarnode, VarnodeKindCode
    from tdo_v2.configured_naming_contracts import (
        CapturedNamingAlias, CapturedNamingResolution, CapturedNamingTarget, NamingAliasKind, NamingOpcode,
        NamingResolutionState, NamingSourceQuality, NamingUnresolvedReason,
    )

    def coordinate(value):
        return AddressCoordinate(value["space_id"], value["byte_offset"])

    selector = raw["selector"]
    selector = None if selector["state"] == "MISSING" else ValidatedVarnode(
        VarnodeKindCode(selector["kind_code"]), AddressCoordinate(selector["space_id"], selector["byte_offset"]),
        selector["byte_size"])
    resolution = raw["resolution"]
    resolution = CapturedNamingResolution(
        NamingResolutionState(resolution["state"]),
        None if "reason" not in resolution else NamingUnresolvedReason(resolution["reason"]),
        resolution.get("terminal_target_ordinal"), resolution.get("cycle_target_ordinal"))
    targets = []
    for target in raw["targets"]:
        aliases = tuple(
            CapturedNamingAlias(NamingAliasKind(alias["kind"]), alias["value"],
                                NamingSourceQuality(alias["source_quality"]) if "source_quality" in alias else None)
            for alias in target["aliases"])
        targets.append(CapturedNamingTarget(target["target_ordinal"], coordinate(target["coordinate"]),
                                            target["is_external"], target["is_thunk"], aliases,
                                            bytes.fromhex(target["target_digest"])))
    return (coordinate(raw["instruction"]), raw["operation_ordinal"], NamingOpcode(raw["opcode"]), selector,
            resolution, tuple(targets))


def rederive_naming(naming: dict) -> dict:
    """Recompute every row digest and the content digest of a call-names sidecar."""
    from tdo_v2.configured_naming_contracts import (
        CapturedNamingRow, naming_content_digest, naming_row_digest,
    )

    def rows(raw_rows):
        typed = []
        for raw in raw_rows:
            fields = _typed_naming_row(raw)
            digest = naming_row_digest(*fields)
            raw["row_digest"] = digest.hex()
            typed.append(CapturedNamingRow(*fields, digest))
        return tuple(typed)

    calls = rows(naming["calls"])
    tails = rows(naming["tail_calls"])
    naming["semantic_content_digest"] = naming_content_digest(
        bytes.fromhex(naming["exporter_source_sha256"]), calls, tails).hex()
    return naming


# -- observation edits ---------------------------------------------------------------------

def _instruction(observation: dict, site: str) -> dict:
    space, offset = (int(part, 16) for part in site.split(":")[:2])
    for row in observation["instructions"]:
        if (row["address"]["space_id"], row["address"]["byte_offset"]) == (space, offset):
            return row
    raise VariantError(f"no instruction at {site!r}")


def _push_call(row: dict) -> tuple:
    ops = row["operations"]
    if len(ops) != 3 or [op["opcode"] for op in ops] != ["INT_SUB", "STORE", "CALL"]:
        raise VariantError("source row is not a plain push call (INT_SUB, STORE, CALL)")
    return ops


def _renumber(row: dict) -> None:
    for index, op in enumerate(row["operations"]):
        op["ordinal"] = index


def unique_space(program: dict) -> int:
    """The program's unique space id (never a fixture constant: Fable / Astra impl r1)."""
    spaces = [row["space_id"] for row in program.get("address_spaces", []) if row.get("is_unique_space")]
    if len(spaces) != 1:
        raise VariantError("the program has no single unique space")
    return spaces[0]


def _unused_unique(observation: dict, size=8) -> int:
    used = []
    for row in observation["instructions"]:
        for op in row["operations"]:
            for varnode in [*op["inputs"], *([op["output"]] if op["output"] else [])]:
                if varnode["kind_code"] == 3:
                    used.append((varnode["byte_offset"], varnode["byte_offset"] + varnode["byte_size"]))
    candidate = 0x10000
    while any(start < candidate + size and candidate < end for start, end in used):
        candidate += 0x100
    return candidate


def edit_observation(observation: dict, variant: str, site: str | None, index: int, unique=None) -> dict:
    """In-place edit; returns ``{"moved": (old ordinal, new ordinal) | None}``."""
    if variant in ("exit-kind4",):
        exits = observation.get("fallthrough_exits", [])
        if not 0 <= index < len(exits):
            raise VariantError(f"no fallthrough exit #{index}")
        row = exits[index]
        if row["kind"] != 2:
            raise VariantError("source exit is not kind 2")
        row["kind"], row["function"] = 4, None
        return {"moved": None}
    if site is None:
        raise VariantError(f"{variant} needs --site")
    row = _instruction(observation, site)
    if variant == "drop-pad":
        # a direct CALL at the named ordinal, and a pad another instruction also
        # reaches (so only the exception path is lost: r6 s3; Astra impl r1 P2)
        parts = site.split(":")
        ordinal = int(parts[2]) if len(parts) >= 4 else -1
        ops = row["operations"]
        if not (0 <= ordinal < len(ops)) or ops[ordinal]["opcode"] != "CALL" or parts[3] != "CALL" \
                or not ops[ordinal]["inputs"] or ops[ordinal]["inputs"][0]["kind_code"] != 4:
            raise VariantError("drop-pad needs a direct CALL at the named ordinal")
        fallthrough = row["fallthrough"]
        local = {(item["address"]["space_id"], item["address"]["byte_offset"]) for item in observation["instructions"]}
        others = [item for item in observation["instructions"] if item is not row]
        reached = {(t["space_id"], t["byte_offset"]) for item in others
                   for t in [*item["flow_targets"], *([item["fallthrough"]] if item["fallthrough"] else [])]}
        pads = [target for target in row["flow_targets"]
                if (target["space_id"], target["byte_offset"]) in local and target != fallthrough
                and (target["space_id"], target["byte_offset"]) in reached]
        if not pads:
            raise VariantError("the call row lists no local landing pad reached by another instruction")
        row["flow_targets"].remove(pads[0])
        return {"moved": None, "dropped": pads[0]}
    adjust, store, call = _push_call(row)
    if variant == "call-pattern":
        if adjust["inputs"][1]["byte_offset"] != 8:
            raise VariantError("adjustment is not RSP - 8")
        adjust["opcode"] = "INT_ADD"
        adjust["inputs"][1] = {**adjust["inputs"][1], "byte_offset": WRAP_MINUS_8, "byte_size": 8}
        return {"moved": None}
    if variant == "call-reshape":
        temp = {"kind_code": 3, "space_id": unique, "byte_offset": _unused_unique(observation),
                "byte_size": adjust["output"]["byte_size"]}
        rsp = adjust["output"]
        new_adjust = {**adjust, "output": temp}
        copy = {"ordinal": 0, "opcode": "COPY", "inputs": [temp], "output_present": True, "output": rsp}
        new_store = {**store, "inputs": [store["inputs"][0], temp, store["inputs"][2]]}
        row["operations"] = [new_adjust, copy, new_store, call]
        _renumber(row)
        return {"moved": (2, 3)}
    if variant == "call-swap":
        row["operations"] = [store, adjust, call]
        _renumber(row)
        return {"moved": None, "meaning_change": True}
    raise VariantError(f"unknown observation variant {variant!r}")


# -- source-row check (r3 s4) ---------------------------------------------------------------

def _survey(generation: Path) -> dict:
    """{function id: (scope, seeds, naming, observation sha256, {(check, row key): verdict})}."""
    import diagnose
    import ops_layer

    found = {}

    def keep(diagnosis):
        keys = {claim.entry for claim in diagnosis.claims if claim.entry}
        for claim in diagnosis.claims:
            rows = {}
            if claim.evidence is not None:
                rows = {(row.check, row.key): row.verdict for row in ops_layer.call_rows(claim, keys)}
            found[claim.function_id] = (claim.scope, claim.seeds, claim.naming, claim.observation_sha256, rows)

    diagnose.diagnose(generation, _sealed.NAMING_SOURCE, keep=keep)
    return found


def precheck(source: Path, function_id: str, site: str) -> dict:
    """The source row must be a recognised push call before a call-* variant:
    call-state projection, ``_plain_push_call`` and the push relation all hold
    (recognition only -- not the callee state-preservation proof)."""
    survey = _survey(source)
    rows = survey.get(function_id, (None, None, None, None, {}))[4]
    key = f"{function_id}/{site}"
    wanted = {check: rows.get((check, key)) for check in ("push_projection", "plain_push", "push_relation")}
    if any(verdict != "applied" for verdict in wanted.values()):
        raise VariantError(f"source row is not a recognised direct push call: {wanted}")
    return survey


def postcheck(survey: dict, generation: Path, variant: str, function_id: str) -> None:
    """One condition changed: every other function is unchanged; the target is
    still admitted with its names (call-ordinal: only its names refused)."""
    after = _survey(generation)
    if set(after) != set(survey):
        raise VariantError("the variant changed the function set")
    for key, before in survey.items():
        if key == function_id:
            continue
        if after[key][:4] != before[:4]:
            raise VariantError(f"the variant changed another function: {key}")
    target = after[function_id]
    expected = ("constructed", "ok", "error") if variant == "call-ordinal" else ("constructed", "ok", "ok")
    if target[:3] != expected:
        raise VariantError(f"the target function is {target[:3]}, expected {expected}")


# -- driver ---------------------------------------------------------------------------------

def mutate(source: Path, out_root: Path, variant: str, *, function_id: str = "function-000000",
           site: str | None = None, index: int = 0) -> dict:
    if variant not in VARIANTS:
        raise VariantError(f"unknown variant {variant!r}")
    survey = None
    if variant in ("call-pattern", "call-reshape", "call-swap"):
        survey = precheck(source, function_id, site)
    elif variant != "seal":
        survey = _survey(source)
    generation = copy_bundle(source, out_root)
    result = {"variant": variant, "generation": str(generation), "function": function_id, "site": site}
    if variant == "seal":
        seal = _json(generation / "seal.json")
        digest = seal["manifest_sha256"]
        seal["manifest_sha256"] = ("0" if digest[0] != "0" else "1") + digest[1:]
        (generation / "seal.json").write_bytes(_sealed.dumps(seal))
        return result
    manifest = _json(generation / "manifest.json")
    function = _function_row(manifest, function_id)
    naming_path = _member_path(generation, manifest, function["call_names_member"])
    naming = _json(naming_path)
    if variant == "call-ordinal":
        rows = naming["calls"]
        if not rows:
            raise VariantError("the function has no naming rows")
        chosen = rows[index]
        taken = {(row["instruction"]["space_id"], row["instruction"]["byte_offset"], row["operation_ordinal"])
                 for row in rows}
        new = chosen["operation_ordinal"] + 1
        place = (chosen["instruction"]["space_id"], chosen["instruction"]["byte_offset"], new)
        following = rows[index + 1] if index + 1 < len(rows) else None
        if place in taken or (following is not None and (
                following["instruction"]["space_id"], following["instruction"]["byte_offset"],
                following["operation_ordinal"]) < place):
            raise VariantError("the ordinal change would break order / uniqueness")
        chosen["operation_ordinal"] = new
        _write_member(generation, manifest, function["call_names_member"], _sealed.dumps(rederive_naming(naming)))
        reseal(generation, manifest)
        postcheck(survey, generation, variant, function_id)
        return result
    observation_path = _member_path(generation, manifest, function["observation_member"])
    observation = _json(observation_path)
    program = _json(_member_path(generation, manifest, manifest["program_member_id"]))
    effects = _json(_member_path(generation, manifest, function["call_effects_member"]))
    if variant == "call-reshape" and isinstance(effects.get("transport"), dict):
        # its rows' digests cannot be re-derived without a call-effects decoder
        # (none exists in the engine): never write an inconsistent sidecar (Astra impl r1 P1)
        raise VariantError("call-reshape on a Bundle with a real call-effects sidecar is not supported")
    edit = edit_observation(observation, variant, site, index, unique_space(program))
    result.update({key: value for key, value in edit.items() if key != "moved"})
    data = _sealed.dumps(observation)
    _write_member(generation, manifest, function["observation_member"], data)
    observation_sha = hashlib.sha256(data).hexdigest()
    naming["transport"]["observation_member_sha256"] = observation_sha
    moved = edit["moved"]
    if moved is not None:
        address = tuple(int(part, 16) for part in site.split(":")[:2])
        for row in naming["calls"]:
            if (row["instruction"]["space_id"], row["instruction"]["byte_offset"]) == address \
                    and row["operation_ordinal"] == moved[0]:
                row["operation_ordinal"] = moved[1]
        rederive_naming(naming)
    _write_member(generation, manifest, function["call_names_member"], _sealed.dumps(naming))
    if isinstance(effects.get("transport"), dict):
        # (the transport is not in the content digest; no effect row moves here)
        effects["transport"]["observation_member_sha256"] = observation_sha
        result["call_effects"] = "transport updated"
        _write_member(generation, manifest, function["call_effects_member"], _sealed.dumps(effects))
    else:
        result["call_effects"] = "placeholder (not a call-effect sidecar)"
    reseal(generation, manifest)
    postcheck(survey, generation, variant, function_id)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("generation", type=Path)
    parser.add_argument("out_root", type=Path)
    parser.add_argument("variant", choices=VARIANTS)
    parser.add_argument("--function", default="function-000000")
    parser.add_argument("--site")
    parser.add_argument("--index", type=int, default=0)
    args = parser.parse_args(argv)
    print(json.dumps(mutate(args.generation, args.out_root, args.variant, function_id=args.function,
                            site=args.site, index=args.index), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
