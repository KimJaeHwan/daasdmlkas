"""Compare scalar ARM64 memory operands with their admitted lift and graph nodes."""

from hashlib import sha256
import json

from arm64_decode import verify_snapshot
from arm64_facts import Arm64Facts, program_fragments, tbi
import common_facts as cf
import lifting
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.integration.standalone_arm64 import build_standalone_arm64_graphs
from tdo_v2.isa_identity import link_register, program_counter, stack_register


def _definition(value, ops):
    if value and value["kind"] == "UNIQUE":
        return next(((i, op) for i, op in reversed(list(enumerate(ops))) if op["output"] == value), (None, None))
    return None, None


def _copy_value(value, ops):
    index, op = _definition(value, ops)
    while op is not None and op["opcode"] == "COPY":
        source, = op["inputs"]
        if source["size"] != value["size"]:
            break
        value = source
        ops = ops[:index]
        index, op = _definition(value, ops)
    return value, ops, op


def _register(value, regs):
    if value and value["kind"] == "REGISTER":
        return regs.get((value["space"], value["offset"], value["size"]))
    return None


def _constant(value):
    return value["offset"] if value and value["kind"] == "CONSTANT" else None


def _address(value, ops, regs):
    value, ops, setup = _copy_value(value, ops)
    if not value or value["size"] != 8:
        return None, None
    if setup is None:
        base = _register(value, regs)
        return base, 0 if base is not None else None
    if setup["opcode"] != "INT_ADD" or len(setup["inputs"]) != 2:
        return None, None
    prefix = ops[:next(i for i, op in enumerate(ops) if op is setup)]
    base, _ops, _op = _copy_value(setup["inputs"][0], prefix)
    offset, _ops, _op = _copy_value(setup["inputs"][1], prefix)
    if not base or not offset or base["size"] != 8 or offset["size"] != 8:
        return None, None
    return _register(base, regs), _constant(offset)


def compare_memory(word, row, regs):
    mask = word & 0xBFC00000
    if mask not in (0xB9000000, 0xB9400000):
        return None
    is_load = mask == 0xB9400000
    width = 8 if word & (1 << 30) else 4
    rn, rt = (word >> 5) & 31, word & 31
    expected = dict(access="LOAD" if is_load else "STORE", space=row["space"], size=width,
                    base="sp" if rn == 31 else f"x{rn}", displacement=((word >> 10) & 0xFFF) * width,
                    register=(("xzr" if width == 8 else "wzr") if rt == 31 else
                              f"{'x' if width == 8 else 'w'}{rt}"))
    ops = row["ops"]
    candidates = [(i, op) for i, op in enumerate(ops)
                  if op["opcode"] in ("LOAD", "STORE")]
    observed = {}
    identifying_op = None
    if len(candidates) == 1:
        (i, op), = candidates
        mode = op["opcode"]
        args = op["inputs"]
        if len(args) == (2 if mode == "LOAD" else 3):
            identifying_op = cf.opref(ops, i)
            base, displacement = _address(args[1], ops[:i], regs)
            value = op["output"] if mode == "LOAD" else args[2]
            if mode == "STORE":
                terminal, _ops, _op = _copy_value(value, ops[:i])
                value_name = _register(terminal, regs)
                if value_name is None and _constant(terminal) == 0:
                    value_name = "constant_zero"
            else:
                value_name = _register(value, regs)
                after = ops[i + 1:]
                if len(after) == 1 and after[0]["opcode"] == "INT_ZEXT" and after[0]["inputs"] == [value]:
                    wide = _register(after[0]["output"], regs)
                    if wide and wide.startswith("x") and value and value["size"] == 4 \
                            and after[0]["output"]["size"] == 8:
                        value_name = "w" + wide[1:]
            observed = dict(access=mode, space=_constant(args[0]), size=value["size"] if value else None,
                            base=base, displacement=displacement, register=value_name)
    fields = {}
    for name, value in expected.items():
        actual = observed.get(name)
        zero_value = name == "register" and actual == "constant_zero" and value in ("xzr", "wzr")
        fields[name] = dict(encoded=value, pcode=actual, state=(
            "unobserved" if actual is None else "match" if zero_value or actual == value else "mismatch"))
        if zero_value:
            fields[name]["basis"] = "value_only"
    states = {item["state"] for item in fields.values()}
    state = next(item for item in ("mismatch", "unobserved", "match") if item in states)
    return dict(op=identifying_op, state=state, fields=fields)


def describe(generation):
    """Keep the ordinary G2 facts and attach checks to an existing graph operation."""
    snapshot, identity = build_standalone_arm64_graphs(generation)
    if len(snapshot.graphs) != 1:
        raise ValueError(f"standalone ARM64 graph was not published ({snapshot.stop})")
    graph, = snapshot.graphs.values()
    evidence = snapshot.program.evidence
    manifest_bytes = (generation / "manifest.json").read_bytes()
    bundle = dict(generation_id=identity.generation_id.hex(), manifest_sha256=identity.manifest_sha256_digest.hex())
    if sha256(manifest_bytes).hexdigest() != bundle["manifest_sha256"]:
        raise ValueError("standalone G2 manifest differs from its admitted graph")
    manifest = json.loads(manifest_bytes)
    files = {m["id"]: generation / m["path"] for m in manifest["members"]}
    blocks = [(b, files[b["member_id"]].read_bytes() if b["member_id"] else None) for b in manifest["blocks"]]
    verify_snapshot(manifest_bytes, bundle, blocks)
    fid, = (f["id"] for f in manifest["functions"])
    names = {r.name: dict(name=r.name, space=r.space_id, offset=r.byte_offset, size=r.byte_size)
             for r in evidence.register_evidence.registers}
    regs = {(r["space"], r["offset"], r["size"]): name for name, r in names.items()}
    roles = {name: cf.register(fn(evidence)) for name, fn in (
        ("sp", stack_register), ("lr", link_register), ("pc", program_counter))}
    arm = Arm64Facts(blocks, names, roles)
    observations, rows, memory = {}, [], []
    graph_nodes = graph.normalized.dependencies
    for inst in graph.unit.observation.instructions:
        raw = lifting.row_facts(inst)
        raw["isa"] = "aarch64"
        row = arm.row(raw, fid)
        if row["aarch64"].get("observation") == "ghidra_pcode":
            row["aarch64"]["observation"] = "pypcode_sleigh"
        observations[cf.rr(row)] = raw
        rows.append(row)
        basis = row["aarch64"]["basis"]
        if cf.unknown(basis):
            raise ValueError("standalone G2 observation has no exact word")
        compared = compare_memory(int(basis["word"], 16), raw, regs)
        if compared is not None:
            linked = compared["op"]
            if linked is not None:
                key = f"op:{raw['space']:x}:{raw['address']:x}:{linked['ordinal']}:{linked['opcode']}"
                node = graph_nodes.node_for_key(key)
                if node is None or graph_nodes.node(node).kind is not NodeKind.OPERATION:
                    raise ValueError("standalone G2 comparison has no matching graph operation")
                compared["graph_operation"] = key
            memory.append(dict(row=cf.ref(row), basis=basis, **compared))
    cf.finish_landings(rows, True)
    aarch64, _ = program_fragments(rows, observations)
    program = dict(isa="aarch64", stack_register=roles["sp"], tbi=tbi(), aarch64=aarch64,
                   code=cf.U("standalone local graph evidence"))
    facts = cf.document(bundle, dict(name="tbr-arm64-local", rule="pypcode-local-v1"), program, rows)
    facts["schema"] = "tbr-arm64-local-facts-1"
    return dict(schema="tbr-arm64-local-diagnostics-1", facts=facts, facts_sha256=cf.streamed_digest(facts),
                graph=dict(program_scope=snapshot.program.scope.digest.hex(),
                           function_scope=graph.unit.scopes.function.scope.digest.hex()),
                memory=memory)
