"""Independent register-only affine certificates over original observed CFGs.

No memory value, alias condition, or existing summary delta is read here.
Calls require already established, unconditional call facts. This checker
does not mint recursive hypotheses or prove the supplied callees itself.
Serialized receipts are not executable proof: use ``verify_register_delta_proof``
with the admitted unit and current call facts to recompute the certificate.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from ._scope_contracts import VarnodeKindCode
from .assumed_call_effects import AssumedCallEffect
from .call_seeds import _operation_key
from .call_summary_effects import ProvenCallEffect
from .intrinsic_refinements import refinements_for
from .model import ResolvedStorage, StorageRef, VarnodeKind
from .observed_call_state import observed_call_state_projections
from .pcode_blocks import build_pcode_block_graph
from .resource_limits import step
from .span_geometry import ByteSpan, StorageObjectKind
from .storage import _resolve_validated_storage


PROOF_VERSION = 2   # 2: AArch64 link calls (kind "link-call", delta 0)
_EXPLICIT = frozenset({"COPY", "LOAD", "STORE", "INT_ADD", "INT_SUB", "INT_MULT", "INT_DIV", "INT_REM",
    "INT_SDIV", "INT_SREM", "INT_AND", "INT_OR", "INT_XOR", "INT_NEGATE", "INT_2COMP", "INT_LEFT",
    "INT_RIGHT", "INT_SRIGHT", "INT_ZEXT", "INT_SEXT", "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS",
    "INT_LESSEQUAL", "INT_SLESS", "INT_SLESSEQUAL", "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
    "BOOL_NEGATE", "BOOL_AND", "BOOL_OR", "BOOL_XOR", "PIECE", "SUBPIECE", "POPCOUNT", "LZCOUNT"})


def _digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class RegisterDeltaCallFact:
    operation_key: str
    callee: str
    kind: str
    delta: int
    observed_push_delta: int | None
    effect_fingerprint: str


@dataclass(frozen=True, slots=True)
class RegisterDeltaBlock:
    key: str
    successors: tuple[str, ...]
    exits: bool
    entry_delta: int
    exit_delta: int


@dataclass(frozen=True, slots=True)
class RegisterDeltaProof:
    register: tuple[int, int]
    delta: int
    program_scope: str
    function_scope: str
    observation_digest: str
    executable_sha256: str
    operation_keys: tuple[str, ...]
    blocks: tuple[RegisterDeltaBlock, ...]
    exits: tuple[str, ...]
    call_facts: tuple[RegisterDeltaCallFact, ...]
    intrinsics: tuple[tuple[str, str], ...]
    assumed_no_effect: tuple[tuple[str, str], ...] = ()

    def record(self):
        payload = json.loads(json.dumps(asdict(self)))
        payload["version"] = PROOF_VERSION
        return {**payload, "content_sha256": _digest(payload)}


def _call_fingerprint(effect, register):
    # Memory result values are not premises of this register-only proof.
    return _digest({"callee": effect.callee, "restores_stack": effect.restores_stack,
                    "writer_conditions_empty": not effect.writer_conditions, "noreturn": effect.noreturn,
                    "register": list(register),
                    "tail_stack": [[str(s.object_id.kind), s.object_id.scope.digest.hex(), s.start, s.size]
                                   for s in effect.tail_stack], "tail_stack_delta": effect.tail_stack_delta})


def derive_register_delta_proof(unit, register_span, proven_call_effects, intrinsic_refinements,
                               *, assumed_call_effects=()):
    """Prove one register's delta at every reachable normal exit, or refuse.

    Full-width self ADD/SUB by a constant is the only admitted register write.
    Memory loads into that register, partial writes, unknown calls, unresolved
    tails and conflicting CFG joins refuse. Zero-delta loops are admissible;
    nonzero loop backedges conflict with the entry invariant and refuse.
    """
    if type(register_span) is not ByteSpan or register_span.object_id.kind is not StorageObjectKind.REGISTER_FILE \
            or register_span.object_id.scope != unit.scopes.program.scope \
            or register_span.size not in (4, 8) or unit.observation is None:
        return None
    spaces = {s.space_id: s for s in unit.scopes.program.evidence.address_spaces}
    register_spaces = [s.space_id for s in spaces.values() if s.is_register_space]
    if len(register_spaces) != 1:
        return None
    register_space = register_spaces[0]
    register = (register_span.start, register_span.size)
    resolved = _resolve_validated_storage(StorageRef(VarnodeKind.REGISTER, "", *register,
                                                   space_id=register_space), unit.scopes.resolution_context)
    if type(resolved) is not ResolvedStorage or resolved.span != register_span:
        return None
    modulus = 1 << (8 * register_span.size)
    def signed(value):
        value %= modulus
        return value - modulus if value >= modulus // 2 else value
    def same(value):
        return value.kind is VarnodeKindCode.REGISTER and value.coordinate.space_id == register_space \
            and (value.coordinate.byte_offset, value.byte_size) == register
    def overlaps(value):
        return value is not None and value.kind is VarnodeKindCode.REGISTER \
            and value.coordinate.space_id == register_space \
            and value.coordinate.byte_offset < register_span.end \
            and register_span.start < value.coordinate.byte_offset + value.byte_size

    graph = build_pcode_block_graph(unit.observation, unit.scopes.function.entry)
    if graph.unsupported or not graph.blocks:
        return None
    blocks = {b.key: b for b in graph.blocks}
    instructions = {row.address: row for row in unit.observation.instructions}
    calls = dict(proven_call_effects)
    supplied_intrinsics = dict(intrinsic_refinements)
    assumed = dict(assumed_call_effects)
    audited_intrinsics = refinements_for(unit)
    projections = {row.call_operation_key: row for row in observed_call_state_projections(unit.observation)}
    from .call_relations import call_relations
    links = {key: relation for key, relation in call_relations(unit.observation, unit.scopes).items()
             if relation.kind == "link"}
    incoming, pending, receipts, call_facts, intrinsic_facts = {graph.entry: 0}, [graph.entry], {}, {}, {}
    assumed_facts = {}
    original_keys = []
    while pending:
        step()
        key = pending.pop()
        block = blocks[key]
        instruction = instructions[block.instruction]
        if instruction.flow.is_override:
            return None
        delta = incoming[key]
        for ordinal in range(block.start, block.stop):
            operation = instruction.operations[ordinal]
            opkey = _operation_key(instruction.address, ordinal, operation.opcode)
            original_keys.append(opkey)
            opcode = operation.opcode
            if opcode in ("CALLIND", "BRANCHIND"):
                return None
            if opcode == "CALLOTHER":
                proof = supplied_intrinsics.get(opkey)
                if proof is not None:
                    if opkey in assumed or proof != audited_intrinsics.get(opkey) or overlaps(operation.output):
                        return None
                    intrinsic_facts[opkey] = proof.semantics.semantic_id
                else:
                    declared = assumed.get(opkey)
                    if type(declared) is not AssumedCallEffect or declared.reads or declared.writes \
                            or operation.output is not None or len(operation.inputs) != 1:
                        return None
                    index = operation.inputs[0]
                    space = spaces.get(index.coordinate.space_id)
                    if index.kind is not VarnodeKindCode.CONSTANT or index.byte_size != 4 \
                            or space is None or not space.is_constant_space:
                        return None
                    # Explicitly inherited model premise, never relabelled as
                    # an independently audited ISA fact or silently erased.
                    assumed_facts[opkey] = declared.label
                continue
            tail = opcode == "BRANCH" and block.exits
            if opcode == "CALL" or tail:
                if operation.output is not None or len(operation.inputs) != 1 \
                        or operation.inputs[0].kind is not VarnodeKindCode.ADDRESS:
                    return None
                target = operation.inputs[0].coordinate
                callee = f"{target.space_id:x}:{target.byte_offset:x}"
                effect = calls.get(opkey)
                if type(effect) is not ProvenCallEffect or effect.callee != callee \
                        or type(effect.writer_conditions) is not tuple or effect.writer_conditions \
                        or effect.noreturn is not False:
                    return None
                push = None
                kind = "tail" if tail else "call"
                if tail:
                    if block.successors or ordinal != block.stop - 1 or effect.tail_stack != (register_span,) \
                            or type(effect.tail_stack_delta) is not int:
                        return None
                    adjustment = effect.tail_stack_delta
                else:
                    projection = projections.get(opkey)
                    link = links.get(opkey)
                    if (projection is None) == (link is None) or effect.restores_stack is not True \
                            or effect.tail_stack or effect.tail_stack_delta is not None or block.exits \
                            or len(block.successors) != 1:
                        return None
                    if link is not None:
                        # the link call moves no stack pointer: the callee's entry SP is
                        # the caller's, and its restoration (callee SP delta 0) is proven
                        if (link.sp.byte_offset, link.sp.byte_size) != register or link.delta != 0:
                            return None
                        kind, adjustment = "link-call", 0
                    else:
                        base = projection.memory_transition.caller_base
                        if (base.byte_offset, base.byte_size) != register:
                            return None
                        push = projection.memory_transition.displacement_delta
                        adjustment = -push
                delta = signed(delta + adjustment)
                call_facts[opkey] = RegisterDeltaCallFact(opkey, callee, kind,
                    signed(adjustment), push, _call_fingerprint(effect, register))
                continue
            if opcode in ("BRANCH", "CBRANCH", "RETURN"):
                if operation.output is not None:
                    return None
                continue
            if opcode not in _EXPLICIT:
                return None
            if opcode == "STORE":
                if len(operation.inputs) != 3 or operation.inputs[0].kind is not VarnodeKindCode.CONSTANT:
                    return None
                space = spaces.get(operation.inputs[0].coordinate.byte_offset)
                if space is None or not space.is_memory_space:
                    return None
            if overlaps(operation.output):
                if not same(operation.output) or opcode not in ("INT_ADD", "INT_SUB") \
                        or len(operation.inputs) != 2 or not same(operation.inputs[0]):
                    return None
                constant = operation.inputs[1]
                space = spaces.get(constant.coordinate.space_id)
                if constant.kind is not VarnodeKindCode.CONSTANT or constant.byte_size != register_span.size \
                        or space is None or not space.is_constant_space:
                    return None
                adjustment = constant.coordinate.byte_offset * (1 if opcode == "INT_ADD" else -1)
                delta = signed(delta + adjustment)
        if block.exits:
            if block.successors or not block.stop:
                return None
            last = instruction.operations[block.stop - 1].opcode
            if last not in ("RETURN", "BRANCH"):
                return None
        receipts[key] = RegisterDeltaBlock(key, block.successors, block.exits, incoming[key], delta)
        for successor in block.successors:
            if successor not in blocks:
                return None
            if successor in incoming:
                if incoming[successor] != delta:
                    return None
            else:
                incoming[successor] = delta
                pending.append(successor)
    exits = tuple(sorted(key for key, block in receipts.items() if block.exits))
    values = {receipts[key].exit_delta for key in exits}
    if len(values) != 1 or set(receipts) != set(blocks):
        return None
    scope = unit.scopes
    return RegisterDeltaProof(register, values.pop(), scope.program.scope.digest.hex(),
        scope.function.scope.digest.hex(), scope.function.observation_digest.hex(),
        scope.program.evidence.executable_sha256.hex(), tuple(sorted(set(original_keys))),
        tuple(receipts[key] for key in sorted(receipts)), exits,
        tuple(call_facts[key] for key in sorted(call_facts)), tuple(sorted(intrinsic_facts.items())),
        tuple(sorted(assumed_facts.items())))


def verify_register_delta_proof(proof, unit, register_span, proven_call_effects, intrinsic_refinements,
                               *, assumed_call_effects=()):
    """Recompute against current admitted evidence; parsing a receipt is insufficient."""
    return type(proof) is RegisterDeltaProof and proof == derive_register_delta_proof(
        unit, register_span, proven_call_effects, intrinsic_refinements, assumed_call_effects=assumed_call_effects)


def validate_proof_record(record):
    """Strict structural/integrity validation, NOT re-execution or authentication.

    A rehashed fabricated receipt can pass this parser. It cannot pass
    ``verify_register_delta_proof`` against different original evidence.
    """
    keys = {"version", "register", "delta", "program_scope", "function_scope", "observation_digest",
            "executable_sha256", "operation_keys", "blocks", "exits", "call_facts", "intrinsics", "assumed_no_effect", "content_sha256"}
    def text(value):
        return type(value) is str and bool(value)
    def digest(value):
        return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    def strings(value):
        return type(value) is list and all(text(item) for item in value) and value == sorted(set(value))
    if type(record) is not dict or set(record) != keys or type(record["version"]) is not int \
            or record["version"] != PROOF_VERSION or type(record["register"]) is not list \
            or len(record["register"]) != 2 or any(type(v) is not int for v in record["register"]) \
            or record["register"][0] < 0 or record["register"][1] not in (4, 8) \
            or type(record["delta"]) is not int:
        return None
    if not all(digest(record[key]) for key in ("program_scope", "function_scope", "observation_digest",
                                               "executable_sha256", "content_sha256")) \
            or not strings(record["operation_keys"]) or not record["operation_keys"] \
            or not strings(record["exits"]) or not record["exits"]:
        return None
    bits = record["register"][1] * 8
    def delta(value):
        return type(value) is int and -(1 << (bits - 1)) <= value < 1 << (bits - 1)
    if not delta(record["delta"]) or any(type(record[key]) is not list for key in ("blocks", "call_facts", "intrinsics", "assumed_no_effect")):
        return None
    blocks, facts, intrinsics = [], [], []
    for row in record["blocks"]:
        if type(row) is not dict or set(row) != {"key", "successors", "exits", "entry_delta", "exit_delta"} \
                or not text(row["key"]) or not strings(row["successors"]) or type(row["exits"]) is not bool \
                or not delta(row["entry_delta"]) or not delta(row["exit_delta"]):
            return None
        blocks.append(RegisterDeltaBlock(row["key"], tuple(row["successors"]), row["exits"], row["entry_delta"], row["exit_delta"]))
    for row in record["call_facts"]:
        if type(row) is not dict or set(row) != {"operation_key", "callee", "kind", "delta", "observed_push_delta", "effect_fingerprint"} \
                or not text(row["operation_key"]) or not text(row["callee"]) \
                or row["kind"] not in ("call", "link-call", "tail") \
                or not delta(row["delta"]) or not digest(row["effect_fingerprint"]) \
                or (row["kind"] == "call" and (not delta(row["observed_push_delta"]) or row["observed_push_delta"] >= 0)) \
                or (row["kind"] in ("tail", "link-call") and row["observed_push_delta"] is not None):
            return None
        facts.append(RegisterDeltaCallFact(**row))
    for row in record["intrinsics"]:
        if type(row) is not list or len(row) != 2 or not all(text(value) for value in row):
            return None
        intrinsics.append(tuple(row))
    assumed = []
    for row in record["assumed_no_effect"]:
        if type(row) is not list or len(row) != 2 or not all(text(value) for value in row):
            return None
        assumed.append(tuple(row))
    block_keys = [b.key for b in blocks]
    by_key = {b.key: b for b in blocks}
    if block_keys != sorted(set(block_keys)) or not blocks \
            or [f.operation_key for f in facts] != sorted({f.operation_key for f in facts}) \
            or intrinsics != sorted(set(intrinsics)) \
            or assumed != sorted(set(assumed)) \
            or {key for key, _ in assumed} & {key for key, _ in intrinsics} \
            or set(record["exits"]) != {b.key for b in blocks if b.exits} \
            or any(b.exits and (b.successors or b.exit_delta != record["delta"]) for b in blocks) \
            or any(s not in block_keys for b in blocks for s in b.successors) \
            or any(b.exit_delta != by_key[s].entry_delta for b in blocks for s in b.successors) \
            or any(f.operation_key not in record["operation_keys"] for f in facts) \
            or any(f.kind == "call" and (f.observed_push_delta != -record["register"][1]
                                         or f.delta != record["register"][1]
                                         or not f.operation_key.endswith(":CALL")) for f in facts) \
            or any(f.kind == "link-call" and (f.delta != 0 or not f.operation_key.endswith(":CALL")) for f in facts) \
            or any(f.kind == "tail" and not f.operation_key.endswith(":BRANCH") for f in facts) \
            or any(key not in record["operation_keys"] or not key.endswith(":CALLOTHER")
                   for key, _ in (*intrinsics, *assumed)):
        return None
    payload = {key: value for key, value in record.items() if key != "content_sha256"}
    if _digest(payload) != record["content_sha256"]:
        return None
    return RegisterDeltaProof(tuple(record["register"]), record["delta"], record["program_scope"],
        record["function_scope"], record["observation_digest"], record["executable_sha256"],
        tuple(record["operation_keys"]), tuple(blocks), tuple(record["exits"]), tuple(facts), tuple(intrinsics), tuple(assumed))
