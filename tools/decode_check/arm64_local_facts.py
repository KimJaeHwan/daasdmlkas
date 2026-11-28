"""Compare scalar ARM64 memory operands with their admitted lift and graph nodes."""

from hashlib import sha256
import json

from arm64_decode import verify_snapshot
from arm64_facts import Arm64Facts, program_fragments, tbi
import common_facts as cf
import lifting
from tdo_v2.graph_contracts import NodeKind
from tdo_v2.integration.arm64_pair import decode_pair, verify_pair
from tdo_v2.integration.standalone_arm64 import BRANCH_FORMS, RAM, _register_node, build_standalone_arm64_graphs
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


def _graph_operation(dependencies, raw, op):
    key = f"op:{raw['space']:x}:{raw['address']:x}:{op['ordinal']}:{op['opcode']}"
    node = dependencies.node_for_key(key)
    if node is None or dependencies.node(node).kind is not NodeKind.OPERATION:
        raise ValueError("standalone G2 comparison has no matching graph operation")
    return key


def _graph_branch(graph, row, raw):
    transfer = row["transfer"]
    op = transfer["op_keys"]["transfer"]
    if op is None:
        raise ValueError("standalone G2 branch has no matching p-code transfer")
    cfg = graph.normalized.cfg
    source = cfg.node_for_key(f"instruction:{raw['space']:x}:{raw['address']:x}")
    if source is None:
        raise ValueError("standalone G2 branch has no matching CFG instruction")
    observed = {cfg.node(node).key for node in cfg.successors(source)}
    destination = raw["ops"][op["ordinal"]]["inputs"][0]
    target = cf.addr(destination["space"], destination["offset"])
    outcomes = {"always": target}
    if op["opcode"] == "CBRANCH":
        outcomes = {"taken": target, "not_taken": cf.addr(raw["fallthrough_space"], raw["fallthrough"])}
    encoded = {edge["when"]: edge["to"] for edge in transfer["edges"]}
    if len(encoded) != len(transfer["edges"]) or encoded != outcomes:
        raise ValueError("standalone G2 branch outcome disagrees with observed p-code and fallthrough")
    targets = {f"instruction:{to['space']:x}:{to['offset']}" for to in outcomes.values()}
    if targets != observed:
        raise ValueError("standalone G2 branch successors disagree with the graph")
    return dict(row=cf.ref(row), op=op, graph_operation=_graph_operation(graph.normalized.dependencies, raw, op),
                condition=transfer["condition"], successors=[dict(outcome=e["when"], address=e["to"])
                                                             for e in transfer["edges"]])


def _graph_pair(form, raw, typed, registers, graph):
    observation = verify_pair(form, typed, registers, RAM)
    if observation is None:
        raise ValueError("standalone G2 pair effects disagree with the admitted graph")
    dependency = graph.normalized.dependencies

    def operation(ordinal):
        op = cf.opref(raw["ops"], ordinal)
        return dict(op=op, graph_operation=_graph_operation(dependency, raw, op))

    accesses = []
    for name, offset, ordinal in zip(form.register_names, form.access_offsets, observation.accesses):
        access = dict(register=name, width=form.width, offset_from_incoming_base=offset, **operation(ordinal))
        if name.endswith("zr"):
            access["register_effect"] = "discard_load" if form.load else "store_zero"
        accesses.append(access)
    writeback = None if observation.writeback is None else dict(
        delta=form.displacement, **operation(observation.writeback))
    return dict(form=form.mnemonic, base=form.base_name, mode=form.mode, accesses=accesses, writeback=writeback)


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
    observations, rows, memory, branches, pairs = {}, [], [], [], []
    pair_registers = None
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
        if isinstance(row["aarch64"]["form"], str) and row["aarch64"]["form"] in BRANCH_FORMS:
            branches.append(_graph_branch(graph, row, raw))
        word = int(basis["word"], 16)
        pair = decode_pair(word)
        if pair is not None:
            if pair_registers is None:
                pair_registers = {r.name: _register_node(r) for r in evidence.register_evidence.registers}
            compared_pair = _graph_pair(pair, raw, inst.operations, pair_registers, graph)
            pairs.append(dict(row=cf.ref(row), basis=basis, **compared_pair))
        compared = compare_memory(word, raw, regs)
        if compared is not None:
            linked = compared["op"]
            if linked is not None:
                compared["graph_operation"] = _graph_operation(graph_nodes, raw, linked)
            memory.append(dict(row=cf.ref(row), basis=basis, **compared))
    cf.finish_landings(rows, True)
    aarch64, _ = program_fragments(rows, observations)
    program = dict(isa="aarch64", stack_register=roles["sp"], tbi=tbi(), aarch64=aarch64,
                   code=cf.U("standalone local graph evidence"))
    facts = cf.document(bundle, dict(name="tbr-arm64-local", rule="pypcode-local-v1"), program, rows)
    facts["schema"] = "tbr-arm64-local-facts-1"
    result = dict(schema="tbr-arm64-local-diagnostics-1", facts=facts, facts_sha256=cf.streamed_digest(facts),
                graph=dict(program_scope=snapshot.program.scope.digest.hex(),
                           function_scope=graph.unit.scopes.function.scope.digest.hex()),
                memory=memory)
    if branches:
        result["branches"] = branches
    if pairs:
        result["pairs"] = pairs
    return result
