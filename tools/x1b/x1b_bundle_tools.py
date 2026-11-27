"""X-1b Bundle tools (design_x1b_method_r3 A / section 2): strip additions relative to one old input, derive the
comparison copy from a published Bundle (generation id rewritten in its declared places), compare two Bundles member
by member. Only schema-declared transport fields are ever rewritten. Run in WSL (python3 or the tdo venv).

  x1b_bundle_tools.py verify  <gen>                         raw verification (sizes, hashes, seal, bindings)
  x1b_bundle_tools.py derive  <published gen> <out root> --generation <old id>
  x1b_bundle_tools.py strip   <gen> <out root> --old <old gen> [--keep group,...]
  x1b_bundle_tools.py members <old gen> <new gen> [--allow-class-hashes]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

# the only fields that name another member or the generation (schema-declared transport bindings)
OBSERVATION_BINDING = ("transport", "observation_member_sha256")              # call-names-*, call-effects-*
PROFILE_BINDING = ("transport", "call_interface_profile_member_sha256")       # call-effects-*
PROGRAM_BINDING = ("transport", "program_member_sha256")                      # call-interface-profile
GENERATION_FIELDS = ("transport", "generation_id")                            # every sidecar / profile
CLASS_HASHES = "transport.runtime_classes[].class_sha256"                    # exporter version metadata (listed)

GROUPS = {
    "s1": {"function": ["call_fallthrough"]},
    "fte": {"function": ["fallthrough_exits"]},
    # (the attested fresh import and the exception fact it enables -- G3b-7b; both need S1)
    "proof": {"function": ["proof_input", "exception_handlers"]},
    "x1": {"function": ["producer_profile"], "row": ["override", "recorded_landing_pads"],
           "manifest": ["producer_profile", "stack_switch_evidence_member"]},
    "len": {"row": ["length"]},
    "reg": {"program": ["register_evidence"]},
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dumps(value) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()


class Bundle:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.manifest = json.loads((self.path / "manifest.json").read_text())
        self.seal = json.loads((self.path / "seal.json").read_text())
        self.rows = {row["id"]: row for row in self.manifest["members"]}

    def raw(self, member: str) -> bytes:
        return (self.path / self.rows[member]["path"]).read_bytes()

    def json(self, member: str):
        return json.loads(self.raw(member))

    def write(self, member: str, data: bytes) -> str:
        row = self.rows[member]
        old = row["sha256"]
        (self.path / row["path"]).write_bytes(data)
        row["size"], row["sha256"] = len(data), sha(data)
        return old

    def sidecars(self, function_row):
        return [item for item in (function_row.get("call_names_member"), function_row.get("call_effects_member"))
                if item]

    def reseal(self):
        self.manifest["members"] = list(self.rows.values())
        data = dumps(self.manifest)
        (self.path / "manifest.json").write_bytes(data)
        self.seal["manifest_size"], self.seal["manifest_sha256"] = len(data), sha(data)
        (self.path / "seal.json").write_bytes(dumps(self.seal))


def _get(value, path):
    for key in path:
        value = value[key]
    return value


def _set(value, path, item):
    for key in path[:-1]:
        value = value[key]
    value[path[-1]] = item


def verify(path: Path) -> list[str]:
    """Raw verification: member sizes / hashes, manifest vs seal, declared bindings resolve to their members."""
    bundle, problems = Bundle(path), []
    data = (bundle.path / "manifest.json").read_bytes()
    if bundle.seal.get("manifest_sha256") != sha(data) or bundle.seal.get("manifest_size") != len(data):
        problems.append("manifest does not match the seal")
    if bundle.seal.get("generation_id") != bundle.manifest.get("generation_id") or \
            bundle.path.name != bundle.manifest.get("generation_id"):
        problems.append("generation id differs between seal / manifest / directory")
    for member, row in bundle.rows.items():
        raw = bundle.raw(member)
        if len(raw) != row["size"] or sha(raw) != row["sha256"]:
            problems.append(f"{member}: size / hash mismatch")
    for function in bundle.manifest["functions"]:
        observation = bundle.rows[function["observation_member"]]["sha256"]
        for sidecar in bundle.sidecars(function):
            value = bundle.json(sidecar)
            if _get(value, OBSERVATION_BINDING) != observation:
                problems.append(f"{sidecar}: observation binding does not name {function['observation_member']}")
            if sidecar.startswith("call-effects") and \
                    _get(value, PROFILE_BINDING) != bundle.rows[bundle.manifest["call_interface_profile_member"]]["sha256"]:
                problems.append(f"{sidecar}: profile binding does not name the profile")
            if _get(value, GENERATION_FIELDS) != bundle.manifest["generation_id"]:
                problems.append(f"{sidecar}: transport generation id differs")
    profile = bundle.json(bundle.manifest["call_interface_profile_member"])
    if _get(profile, PROGRAM_BINDING) != bundle.rows[bundle.manifest["program_member_id"]]["sha256"]:
        problems.append("call-interface-profile: program binding does not name the program")
    return problems


def _rebind_profile_chain(bundle: Bundle):
    """After the program changed: profile -> program digest; call-effects -> profile digest (declared fields)."""
    profile_id = bundle.manifest["call_interface_profile_member"]
    profile = bundle.json(profile_id)
    _set(profile, PROGRAM_BINDING, bundle.rows[bundle.manifest["program_member_id"]]["sha256"])
    bundle.write(profile_id, dumps(profile))
    for function in bundle.manifest["functions"]:
        for sidecar in bundle.sidecars(function):
            if sidecar.startswith("call-effects"):
                value = bundle.json(sidecar)
                _set(value, PROFILE_BINDING, bundle.rows[profile_id]["sha256"])
                bundle.write(sidecar, dumps(value))


def _copy(source: Path, out_root: Path, name: str) -> Path:
    out = out_root / name
    if out.exists():
        shutil.rmtree(out)
    out_root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, out)
    for path in out.rglob("*"):
        os.chmod(path, 0o700 if path.is_dir() else 0o600)
    os.chmod(out, 0o700)
    return out


def derive(published: Path, out_root: Path, generation: str) -> Path:
    """The comparison copy: the published Bundle with its generation id rewritten in the declared places only."""
    source = Bundle(published)
    new_id = source.manifest["generation_id"]
    out = _copy(source.path, out_root, generation)
    bundle = Bundle(out)
    bundle.manifest["generation_id"] = generation
    bundle.seal["generation_id"] = generation
    for function in bundle.manifest["functions"]:
        for sidecar in bundle.sidecars(function):
            value = bundle.json(sidecar)
            _set(value, GENERATION_FIELDS, generation)
            bundle.write(sidecar, dumps(value))
    profile_id = bundle.manifest["call_interface_profile_member"]
    profile = bundle.json(profile_id)
    _set(profile, GENERATION_FIELDS, generation)
    bundle.write(profile_id, dumps(profile))
    _rebind_profile_chain(bundle)
    for function in bundle.manifest["functions"]:   # (sidecars name the unchanged observations; profile re-bound)
        pass
    bundle.reseal()
    # post-check (Fable r3 P3): the published id occurs nowhere else; only declared fields differ from the source
    for path in out.rglob("*"):
        if path.is_file() and new_id.encode() in path.read_bytes():
            raise SystemExit(f"derive: the published generation id remains in {path.name}")
    differences = members(source.path, out, allow_class_hashes=False, generation_only=True)
    if differences:
        raise SystemExit("derive: undeclared differences: " + "; ".join(differences[:5]))
    return out


def strip(path: Path, out_root: Path, old: Path, keep=()) -> Path:
    """Remove the additions the given old input lacks (minus ``keep``); declared re-binding only."""
    old_bundle = Bundle(old)
    old_function = old_bundle.json(old_bundle.manifest["functions"][0]["observation_member"])
    old_row = (old_function.get("instructions") or [{}])[0]
    old_program = old_bundle.json(old_bundle.manifest["program_member_id"])
    drop = {"function": set(), "row": set(), "manifest": set(), "program": set()}
    for name, fields in GROUPS.items():
        if name in keep:
            continue
        for kind, names in fields.items():
            for field in names:
                present = {"function": field in old_function, "row": field in old_row,
                           "manifest": field in old_bundle.manifest, "program": field in old_program}[kind]
                if not present:   # (strip only what this old input lacks -- A-P1-3)
                    drop[kind].add(field)
    source = Bundle(path)
    out = _copy(source.path, out_root, source.path.name)
    bundle = Bundle(out)
    for function in bundle.manifest["functions"]:
        observation = bundle.json(function["observation_member"])
        for field in drop["function"]:
            observation.pop(field, None)
        for row in observation.get("instructions", ()):
            for field in drop["row"]:
                row.pop(field, None)
        bundle.write(function["observation_member"], dumps(observation))
        for sidecar in bundle.sidecars(function):
            value = bundle.json(sidecar)
            _set(value, OBSERVATION_BINDING, bundle.rows[function["observation_member"]]["sha256"])
            bundle.write(sidecar, dumps(value))
    if drop["program"]:
        program_id = bundle.manifest["program_member_id"]
        program = bundle.json(program_id)
        for field in drop["program"]:
            program.pop(field, None)
        bundle.write(program_id, dumps(program))
    _rebind_profile_chain(bundle)
    if "stack_switch_evidence_member" in drop["manifest"] and "stack_switch_evidence_member" in bundle.manifest:
        member = bundle.manifest["stack_switch_evidence_member"]
        (out / bundle.rows[member]["path"]).unlink()
        del bundle.rows[member]
    for field in drop["manifest"]:
        bundle.manifest.pop(field, None)
    bundle.reseal()
    problems = verify(out)
    if problems:
        raise SystemExit("strip: " + "; ".join(problems[:5]))
    print(f"[strip] {out} dropped={ {k: sorted(v) for k, v in drop.items() if v} }")
    return out


def _resolved(bundle: Bundle, member: str, value):
    """A member's canonical JSON with declared bindings replaced by what they name (A2-2: resolved bindings)."""
    def name_of(digest):
        return next((m for m, row in bundle.rows.items() if row["sha256"] == digest), f"?{digest[:12]}")

    value = json.loads(json.dumps(value))
    for path in (OBSERVATION_BINDING, PROFILE_BINDING, PROGRAM_BINDING):
        try:
            _set(value, path, {"names": name_of(_get(value, path))})
        except (KeyError, TypeError):
            pass
    return value


def members(old: Path, new: Path, *, allow_class_hashes: bool = True, generation_only: bool = False) -> list[str]:
    """Member-by-member comparison: binary members by hash, JSON members canonically with resolved bindings.
    ``allow_class_hashes``: the exporter version metadata may differ (listed); ``generation_only``: the generation
    id may differ (derived copies)."""
    a, b = Bundle(old), Bundle(new)
    out = []
    ignore_manifest = {"members", "generation_id"} if generation_only else {"members", "generation_id"}
    for key in sorted(set(a.manifest) | set(b.manifest)):
        if key not in ignore_manifest and a.manifest.get(key) != b.manifest.get(key):
            out.append(f"manifest.{key}")
    if sorted(a.rows) != sorted(b.rows):
        out.append(f"member sets differ: only old {sorted(set(a.rows) - set(b.rows))[:5]}, "
                   f"only new {sorted(set(b.rows) - set(a.rows))[:5]}")
    for member in sorted(set(a.rows) & set(b.rows)):
        raw_a, raw_b = a.raw(member), b.raw(member)
        if raw_a == raw_b:
            continue
        try:
            va, vb = _resolved(a, member, json.loads(raw_a)), _resolved(b, member, json.loads(raw_b))
        except (json.JSONDecodeError, UnicodeDecodeError):
            out.append(f"{member}: binary content differs")
            continue
        for value in (va, vb):
            transport = value.get("transport") if isinstance(value, dict) else None
            if isinstance(transport, dict):
                if generation_only or True:
                    transport.pop("generation_id", None)   # (named by the directory / manifest, compared above)
                if allow_class_hashes:
                    for item in transport.get("runtime_classes") or ():
                        item.pop("class_sha256", None)
        if json.dumps(va, sort_keys=True) != json.dumps(vb, sort_keys=True):
            out.append(f"{member}: {first_difference(va, vb)}")
    return out


def first_difference(a, b, path="$"):
    if type(a) is not type(b):
        return f"{path}: {str(a)[:80]} | {str(b)[:80]}"
    if isinstance(a, dict):
        for key in sorted(set(a) | set(b)):
            if key not in a or key not in b:
                return f"{path}.{key}: {'absent' if key not in a else 'present'} | " \
                       f"{'absent' if key not in b else 'present'}"
            found = first_difference(a[key], b[key], f"{path}.{key}")
            if found:
                return found
        return None
    if isinstance(a, list):
        for index, (x, y) in enumerate(zip(a, b)):
            found = first_difference(x, y, f"{path}[{index}]")
            if found:
                return found
        return None if len(a) == len(b) else f"{path}.length: {len(a)} | {len(b)}"
    return None if a == b else f"{path}: {str(a)[:80]} | {str(b)[:80]}"


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("verify")
    one.add_argument("generation", type=Path)
    two = sub.add_parser("derive")
    two.add_argument("published", type=Path)
    two.add_argument("out_root", type=Path)
    two.add_argument("--generation", required=True)
    three = sub.add_parser("strip")
    three.add_argument("generation", type=Path)
    three.add_argument("out_root", type=Path)
    three.add_argument("--old", type=Path, required=True)
    three.add_argument("--keep", default="")
    four = sub.add_parser("members")
    four.add_argument("old", type=Path)
    four.add_argument("new", type=Path)
    args = parser.parse_args()
    if args.command == "verify":
        problems = verify(args.generation)
        print("\n".join(problems) or "verified")
        return 1 if problems else 0
    if args.command == "derive":
        print(derive(args.published, args.out_root, args.generation))
        return 0
    if args.command == "strip":
        strip(args.generation, args.out_root, args.old, {item for item in args.keep.split(",") if item})
        return 0
    differences = members(args.old, args.new)
    print("\n".join(differences) or "members identical")
    return 1 if differences else 0


if __name__ == "__main__":
    sys.exit(main())
