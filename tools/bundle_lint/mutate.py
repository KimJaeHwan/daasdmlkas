#!/usr/bin/env python3
"""``bundle_lint`` variant tool (design G0 r0..r6): copy a Bundle and change one
condition, then re-seal (member size / sha256, manifest, seal). POSIX / WSL.

    PYTHONPATH=src python3 tools/bundle_lint/mutate.py <generation> <out_root> <variant>
        [--function function-000000] [--site 1:1007:2:CALL] [--index 0] [--naming-source FILE]

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
in its transport (not part of its content digest). ``call-reshape`` moves the
CALL ordinal, which would change a real call-effects sidecar's row digests; no
engine decoder exists to rebuild them, so it is refused on such a Bundle
before anything is written (it runs on the synthetic fixtures).

The source must be admissible (it is admitted first); after the change a
post-check confirms only the target changed (other functions identical; the
target's other call rows identical; drop-pad: the validated pad set shrank).
A failed variant's directory is renamed ``<generation>.failed``.
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
    from engine_api import _safe_name, admit_frozen_bundle

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
    from engine_api import _safe_name

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
    from engine_api import _safe_name

    return generation / _safe_name(next(row["path"] for row in manifest["members"] if row["id"] == member_id))


# -- naming re-derivation (the engine's own encoders) ------------------------------------

def _typed_naming_row(raw):
    from engine_api import AddressCoordinate, ValidatedVarnode, VarnodeKindCode
    from engine_api import (CapturedNamingAlias, CapturedNamingResolution, CapturedNamingTarget, NamingAliasKind, NamingOpcode, NamingResolutionState, NamingSourceQuality, NamingUnresolvedReason)

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
    from engine_api import CapturedNamingRow, naming_content_digest, naming_row_digest

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


def edit_observation(observation: dict, variant: str, site: str | None, index: int, unique=None,
                     selected=None) -> dict:
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
        # the instruction's only CALL-family operation is the named direct CALL (a pad
        # belongs to the instruction: another CALL in it would lose it too); whether
        # the function stays the same apart from the exception path is the
        # engine-based post-check's (Astra impl r4 P1)
        parts = site.split(":")
        ordinal = int(parts[2]) if len(parts) >= 4 else -1
        ops = row["operations"]
        calls = [index for index, op in enumerate(ops) if op["opcode"] in ("CALL", "CALLIND")]
        if calls != [ordinal] or ops[ordinal]["opcode"] != "CALL" or parts[3] != "CALL" \
                or not ops[ordinal]["inputs"] or ops[ordinal]["inputs"][0]["kind_code"] != 4:
            raise VariantError("drop-pad needs an instruction whose only call is the named direct CALL")
        # (the pad comes from the engine's validated pads minus the validated
        # fallthrough, chosen by the driver; every copy of that coordinate goes --
        # compared by coordinate, not by row dict: Astra impl r5 P1)
        space, offset = (int(part, 16) for part in selected.split(":"))
        kept = [target for target in row["flow_targets"]
                if (target.get("space_id"), target.get("byte_offset")) != (space, offset)]
        if len(kept) == len(row["flow_targets"]):
            raise VariantError("the selected pad is not listed by the call row")
        row["flow_targets"] = kept
        return {"moved": None, "dropped": selected}

    adjust, store, call = _push_call(row)
    if variant == "call-pattern":
        constant = adjust["inputs"][1]
        if (constant.get("byte_offset"), constant.get("byte_size")) != (8, 8):
            raise VariantError("the adjustment is not RSP - 8 with an 8-byte constant")
        adjust["opcode"] = "INT_ADD"
        adjust["inputs"][1] = {**constant, "byte_offset": WRAP_MINUS_8}   # (width kept)
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

def _run_edges(generation: Path, naming_source, entry: str):
    """The inter-function reach edges of ``entry`` as the summary run computes
    them: ``control_context._edges`` over the very ``results`` / ``failed``
    the run passes to ``control_contexts`` (engine_api.run_control_context_inputs;
    Astra impl r5 P2). None when the run raises or publishes no result for
    ``entry`` (the caller refuses the variant: Astra impl r6 P3)."""
    import engine_api

    captured = engine_api.run_control_context_inputs(generation, naming_source or _sealed.NAMING_SOURCE)
    if captured is None:
        return None
    results, failed = captured
    if entry not in results:
        return None
    return frozenset(engine_api._edges(entry, results[entry], set(results) | set(failed)))


def _survey(generation: Path, naming_source=None, target=None, edges=False) -> dict:
    """{function id: (scope, seeds, naming, observation sha256, {(check, row key): verdict},
    {call row key: landing pads; S1 exit key: reach edge}, target extras | None)}.

    Target extras (engine functions, Astra impl r4): the entry-reachable
    instruction set over ``control_successor_coordinates``, whether a default
    ``FunctionNormalizer.normalize`` gives a ``NormalizedFunction``, the reach
    edges of ``control_context._edges``, the S1 exit tuples and the
    stack-pointer row. Reach edges and exits come from the member the summary
    keeps (the last one of an entry)."""
    import diagnose
    import feature_layer
    import ops_layer

    found = {}

    def keep(diagnosis):
        from engine_api import control_successor_coordinates
        from engine_api import FunctionNormalizer, NormalizedFunction

        keys = {claim.entry for claim in diagnosis.claims if claim.entry}
        last = {}
        for claim in diagnosis.claims:
            if claim.evidence is not None:
                last[claim.entry] = claim
        for claim in diagnosis.claims:
            rows, pads, extras = {}, {}, None
            if claim.evidence is not None:
                superseded = last.get(claim.entry) is not claim
                for row in ops_layer.call_rows(claim, keys):
                    rows[(row.check, row.key)] = (row.verdict, row.detail.get("landing_pads"))
                    if row.check == "call":
                        pads[row.key] = tuple(row.detail["landing_pads"])
                raw = ops_layer._raw_observation(generation, claim)
                exits = ops_layer.exit_rows(claim, raw, keys, superseded=superseded)
                for row in exits:
                    pads[row.key] = bool(row.detail.get("reach_edge"))
                if claim.function_id == target:
                    observation = claim.unit.observation
                    entry = claim.unit.scopes.function.entry
                    local = {row.address for row in observation.instructions}
                    by_address = {row.address: row for row in observation.instructions}
                    seen, todo = set(), [entry]
                    while todo:
                        place = todo.pop()
                        if place in seen or place not in by_address:
                            continue
                        seen.add(place)
                        todo.extend(control_successor_coordinates(by_address[place], local_addresses=local,
                                                                  function_entry=entry))
                    normalized = FunctionNormalizer().normalize(claim.unit)
                    stack = feature_layer.stack_rows(claim)[0]
                    extras = {
                        "reach": frozenset(seen),
                        "normalized": type(normalized) is NormalizedFunction,
                        "entry": claim.entry,
                        "exits": {row.key: (row.detail.get("kind"), row.detail.get("function")) for row in exits},
                        "stack": (stack.verdict, stack.detail),
                        "superseded": superseded,
                    }
            found[claim.function_id] = (claim.scope, claim.seeds, claim.naming, claim.observation_sha256, rows, pads,
                                        extras)

    diagnosis = diagnose.diagnose(generation, naming_source or _sealed.NAMING_SOURCE, keep=keep)
    found["__predictions__"] = diagnose.predict(diagnosis)
    if edges and target in found and found[target][6] is not None:
        extras = found[target][6]
        extras["edges"] = None if extras["superseded"] else _run_edges(generation, naming_source, extras["entry"])
    return found


def precheck(survey: dict, function_id: str, site: str, variant: str) -> None:
    """Source conditions: the target function is admitted with its names; a
    call-* variant needs a recognised direct push call (projection,
    ``_plain_push_call``, push relation -- recognition only, not the callee
    state proof)."""
    target = survey.get(function_id)
    if variant == "call-ordinal":
        # every path must reach the target's naming step in the source (Astra impl r5 P2)
        stops = survey["__predictions__"]
        index = _claim_index(survey, function_id)
        for path, stop in stops.items():
            if stop is None or stop.get("stage") == "publication":
                continue   # (publication comes after every naming step: the target was reached; Astra impl r6 P2)
            if stop.get("index") is None or stop["index"] <= index:
                raise VariantError(f"the {path} path stops before the target function: {stop}")
    if target is None or target[:3] != ("constructed", "ok", "ok"):
        raise VariantError(f"the source function is not admitted with its names: {None if target is None else target[:3]}")
    if variant in ("call-pattern", "call-reshape", "call-swap"):
        key = f"{function_id}/{site}"
        wanted = {check: (target[4].get((check, key)) or (None,))[0]
                  for check in ("push_projection", "plain_push", "push_relation")}
        if any(verdict != "applied" for verdict in wanted.values()):
            raise VariantError(f"source row is not a recognised direct push call: {wanted}")


def _claim_index(survey: dict, function_id: str) -> int:
    names = [key for key in survey if key != "__predictions__"]
    return names.index(function_id)


def postcheck(survey: dict, after: dict, variant: str, function_id: str, site: str | None, index: int = 0,
              selected=None) -> None:
    """One condition changed: every other function is unchanged; the target is
    still admitted with its names (call-ordinal: only its names refused); the
    target's call rows other than the site's are unchanged; drop-pad: the
    validated pad set of the site shrank (Astra impl r2 P2, Fable impl r2 P3)."""
    if set(after) != set(survey):
        raise VariantError("the variant changed the function set")
    for key, before in survey.items():
        if key == "__predictions__":
            continue
        if key != function_id and after[key][:4] != before[:4]:
            raise VariantError(f"the variant changed another function: {key}")
    target, before = after[function_id], survey[function_id]
    expected = ("constructed", "ok", "error") if variant == "call-ordinal" else ("constructed", "ok", "ok")
    if target[:3] != expected:
        raise VariantError(f"the target function is {target[:3]}, expected {expected}")
    if variant == "call-ordinal":
        # every path's first stop is now the target's naming refusal, and each real
        # child raises exactly the coverage refusal, not a resource failure (Astra impl r5 / r6 P2)
        position = _claim_index(after, function_id)
        for path, stop in after["__predictions__"].items():
            if stop is None or stop.get("index") != position or stop.get("function_id") != function_id:
                raise VariantError(f"the {path} path does not stop at the target's names: {stop}")
        return
    if variant == "drop-pad":
        # only the named operation's pads change, by exactly the dropped coordinate;
        # the entry-reachable set and the normalisation outcome stay (Astra impl r4 P1)
        key = f"{function_id}/{site}"
        exclude = {("call", key), ("push_projection", key), ("plain_push", key), ("push_relation", key),
                   ("link_relation", key)}
        if {k: v for k, v in target[4].items() if k not in exclude} != \
                {k: v for k, v in before[4].items() if k not in exclude}:
            raise VariantError("the variant changed other call rows of the target function")
        if set(target[5].get(key, ())) != set(before[5].get(key, ())) - {selected}:
            raise VariantError("the validated landing pads did not lose exactly the selected coordinate")
        if before[6]["edges"] is None or before[6]["edges"] != target[6]["edges"]:
            # the inter-function reach edges stay (a pad may be another function's entry)
            raise VariantError("dropping the pad changes the function's inter-function reach edges")
        if target[6]["reach"] != before[6]["reach"]:
            raise VariantError("dropping the pad changes what is reachable from the entry")
        if not (before[6]["normalized"] and target[6]["normalized"]):
            raise VariantError("the target function does not normalise on both sides")
        return
    prefix = None if site is None else f"{function_id}/" + ":".join(site.split(":")[:2]) + ":"
    def others(rows):
        return {key: value for key, value in rows.items() if prefix is None or not key[1].startswith(prefix)}
    if others(target[4]) != others(before[4]):
        raise VariantError("the variant changed other call rows of the target function")
    if variant in ("call-pattern", "call-reshape", "call-swap"):
        # the stack identification must survive (an independent SP evidence in the
        # same function, r5 s2; Astra impl r4 P2)
        if not (before[6]["stack"][0] == target[6]["stack"][0] == "applied"
                and before[6]["stack"][1] == target[6]["stack"][1]):
            raise VariantError(f"the variant changed the stack identification: {before[6]['stack']} -> "
                               f"{target[6]['stack']}")
    if variant == "exit-kind4":
        key = f"{function_id}/#{index}"
        if before[6]["superseded"]:
            raise VariantError("the S1 exit's member is replaced by a later member of its entry")
        old, new = before[6]["exits"].get(key), target[6]["exits"].get(key)
        if old is None or old[0] != 2 or new != (4, None):
            raise VariantError(f"the S1 exit did not change (2, B) -> (4, null): {old} -> {new}")
        if before[6]["edges"] is None or target[6]["edges"] is None:
            raise VariantError("no summary result to read the reach edges from")
        if old[1] not in before[6]["edges"] or target[6]["edges"] != before[6]["edges"] - {old[1]}:
            # the engine's reach edge to B (over the run's own results, CALLIND
            # resolutions included) must exist before and be the only one gone after
            raise VariantError("the variant does not remove exactly the engine's reach edge to the exit's function")


NAMING_COVERAGE_REFUSAL = ("builtins.ValueError", "naming row does not match its exact call occurrence")


def _check_children_refuse_names(generation: Path, naming_source) -> None:
    """call-ordinal: the three pipeline children each stop with the naming
    coverage refusal and no resource failure; any other exception, a normal
    completion or a timeout refuses the variant (Astra impl r6 P2)."""
    import children

    for path in children.PATHS:
        child = children.run_path(path, generation, naming_source or _sealed.NAMING_SOURCE, timeout=600)
        exception = child.get("exception") or {}
        if child.get("run_state") != "evaluated" or child.get("completed") or exception.get("resource") \
                or (exception.get("class"), exception.get("message")) != NAMING_COVERAGE_REFUSAL:
            raise VariantError(f"the {path} child does not stop with the naming coverage refusal: {child}")


# -- driver ---------------------------------------------------------------------------------

def mutate(source: Path, out_root: Path, variant: str, *, function_id: str = "function-000000",
           site: str | None = None, index: int = 0, naming_source=None) -> dict:
    if variant not in VARIANTS:
        raise VariantError(f"unknown variant {variant!r}")
    survey = None
    selected = None
    needs_edges = variant in ("drop-pad", "exit-kind4")
    if variant != "seal":
        survey = _survey(source, naming_source, target=function_id, edges=needs_edges)
        precheck(survey, function_id, site, variant)
        if variant == "drop-pad":
            manifest = _json(source / "manifest.json")
            observation = _json(_member_path(source, manifest, _function_row(manifest, function_id)["observation_member"]))
            row = _instruction(observation, site)
            fallthrough = row.get("fallthrough")
            fallthrough = None if not isinstance(fallthrough, dict) else \
                f"{fallthrough.get('space_id', -1):x}:{fallthrough.get('byte_offset', -1):x}"
            pads = sorted(set(survey[function_id][5].get(f"{function_id}/{site}", ())) - {fallthrough})
            if not pads:
                raise VariantError("the call row has no validated landing pad besides its fallthrough")
            selected = pads[0]
        if variant == "call-reshape":
            manifest = _json(source / "manifest.json")
            effects = _json(_member_path(source, manifest, _function_row(manifest, function_id)["call_effects_member"]))
            if isinstance(effects.get("transport"), dict):
                # its rows' digests cannot be re-derived without a call-effects decoder
                # (none exists in the engine): refused before anything is written
                raise VariantError("call-reshape on a Bundle with a real call-effects sidecar is not supported")
    generation = copy_bundle(source, out_root)
    try:
        result = _mutate_copy(generation, variant, function_id, site, index, selected)
        if variant == "call-ordinal":
            _check_children_refuse_names(generation, naming_source)
        if survey is not None:
            postcheck(survey, _survey(generation, naming_source, target=function_id, edges=needs_edges), variant,
                      function_id, site, index, selected)
        return result
    except BaseException:
        # a fresh name: an existing result is never deleted (Astra impl r3 P1)
        failed = generation.with_name(generation.name + ".failed")
        serial = 1
        while failed.exists():
            failed = generation.with_name(f"{generation.name}.failed.{serial}")
            serial += 1
        generation.rename(failed)
        raise


def _mutate_copy(generation: Path, variant: str, function_id: str, site, index: int, selected=None) -> dict:
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
        return result
    observation_path = _member_path(generation, manifest, function["observation_member"])
    observation = _json(observation_path)
    effects = _json(_member_path(generation, manifest, function["call_effects_member"]))
    unique = None
    if variant == "call-reshape":   # (only this variant needs the unique space: Astra impl r2 P2)
        unique = unique_space(_json(_member_path(generation, manifest, manifest["program_member_id"])))
    edit = edit_observation(observation, variant, site, index, unique, selected)
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
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("generation", type=Path)
    parser.add_argument("out_root", type=Path)
    parser.add_argument("variant", choices=VARIANTS)
    parser.add_argument("--function", default="function-000000")
    parser.add_argument("--site")
    parser.add_argument("--index", type=int, default=0)
    parser.add_argument("--naming-source", type=Path)
    args = parser.parse_args(argv)
    print(json.dumps(mutate(args.generation, args.out_root, args.variant, function_id=args.function,
                            site=args.site, index=args.index, naming_source=args.naming_source),
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
