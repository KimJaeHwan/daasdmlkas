"""Whether a function returns to its caller's continuation, with the evidence
(ARM64 Stage 2b, ``.census6/design_arm64_s2_r5.md`` sections 3-5 and r6, docs
25.88). OBSERVATIONAL: no analysis reads these certificates yet (2c).

A function's ``ContinuationCertificate`` is PROVEN only when the function is
CLOSED -- its successor graph complete, every call it makes has a PROVEN
continuation certificate (the owner's rule: an opaque callee's continuation is
UNKNOWN on every ISA), no PAC instruction hides an effect -- and every exit is
proven: a RETURN whose target equals, byte for byte, the function's ENTRY link
(AArch64: x30 at entry; x86: the slot at the entry stack pointer), shown through
the SSA's reaching definitions (COPY / LOAD / STORE chains, every JOIN source),
each read settled (no call-clobber, may-alias or memory debt); or a tail jump
whose own link value at the jump is that entry link and whose target is
PROVEN (the target's proof is target-relative: substituting the jump's link
value is exactly this check). NORETURN only when CLOSED with no exit at all.
Recursion (a call back into an unfinished function) is UNKNOWN; there is no
optimistic hypothesis.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from ._scope_contracts import VarnodeKindCode
from .call_relations import call_relations
from .call_seeds import _operation_key
from .integration.configured_value_domain import storage_ref
from .isa_identity import link_register, stack_register
from .memory_contracts import MemoryDefinitionKind
from .model import ByteSpan, ResolvedStorage, StorageObjectId, StorageObjectKind
from .relative_memory import _function_relative_object_id
from .storage import _resolve_validated_storage

# Every AArch64 instruction whose effects Ghidra 12.0.4 hides under ShowPAC=0:
# the constructors that build a ``*__PACpart`` (AARCH64base.sinc), as
# (value, mask) of their 32-bit encodings (design r6 B; Astra checked all 41).
PAC_SPEC_12_0_4 = (
    "ghidra-12.0.4"
    ":AARCH64base.sinc=a02ec3681ebb32fe13c294ed146407a0017d4b1f5dcad25b170da92eb76bc39b"
    ":AARCH64_base_PACoptions.sinc=6b7c77988212836deec88f4905d7db38623ecc69f2a608b760b22489c15a0aea"
    ":AARCH64.sla=edbad5067c7cdd5f72fb5dddacc37165bc02abb63e0e05b6bb0c75fda9d72b88"
)
_FULL = 0xFFFFFFFF
PAC_TABLE_12_0_4 = (
    (0xDAC11800, 0xFFFFFC00), (0xDAC13BE0, 0xFFFFFFE0), (0xDAC11C00, 0xFFFFFC00), (0xDAC13FE0, 0xFFFFFFE0),
    (0xDAC11000, 0xFFFFFC00), (0xDAC133E0, 0xFFFFFFE0), (0xD503219F, _FULL), (0xD50323BF, _FULL),
    (0xD503239F, _FULL), (0xDAC11400, 0xFFFFFC00), (0xDAC137E0, 0xFFFFFFE0), (0xD50321DF, _FULL),
    (0xD50323FF, _FULL), (0xD50323DF, _FULL), (0xD61F081F, 0xFF9FFC1F), (0xD71F0800, 0xFF9FFC00),
    (0xD61F0C1F, 0xFF9FFC1F), (0xD71F0C00, 0xFF9FFC00), (0xD69F0BFF, _FULL), (0xD69F0FFF, _FULL),
    (0xF8200400, 0xFFA00400), (0xF8A00400, 0xFFA00400), (0xDAC10800, 0xFFFFFC00), (0xDAC12BE0, 0xFFFFFFE0),
    (0xDAC10C00, 0xFFFFFC00), (0xDAC12FE0, 0xFFFFFFE0), (0xDAC10000, 0xFFFFFC00), (0xDAC123E0, 0xFFFFFFE0),
    (0xD503211F, _FULL), (0xD503233F, _FULL), (0xD503231F, _FULL), (0xDAC10400, 0xFFFFFC00),
    (0xDAC127E0, 0xFFFFFFE0), (0xD503215F, _FULL), (0xD503237F, _FULL), (0xD503235F, _FULL),
    (0xD65F0BFF, _FULL), (0xD65F0FFF, _FULL), (0xDAC147E0, 0xFFFFFFE0), (0xDAC143E0, 0xFFFFFFE0),
    (0xD50320FF, _FULL),
)
_CALLS = ("CALL", "CALLIND")


@dataclass(frozen=True, slots=True)
class ExitRecord:
    key: str                      # the terminal operation
    kind: str                     # "return" | "tail" | "unresolved"
    proven: bool
    reason: str                   # why not proven ("" when proven)
    guard: str                    # the exit's path condition ("unknown": not derived in 2b)
    witness: tuple[str, ...]      # the operations the equality proof went through (target -> entry link)
    sp_delta: int | None          # SP at the exit - SP at entry (summary AFFINE c; tail: composed; None: unknown)
    dependencies: tuple[str, ...]  # this exit's premises (a tail: its target's certificate's)


@dataclass(frozen=True, slots=True)
class ContinuationCertificate:
    status: str                      # "proven" | "noreturn" | "unknown"
    closed: bool
    exits: tuple[ExitRecord, ...]
    culprits: tuple[str, ...]        # what keeps the function from CLOSED (operation keys / reasons)
    dependencies: tuple[str, ...]    # everything the status rests on, transitively (withdrawal invalidates it)
    entry: object = None             # the certified function's entry (None: no function -- UNKNOWN_CALLEE)


UNKNOWN_CALLEE = ContinuationCertificate("unknown", False, (), ("opaque",), ())

# how a language's calls pass their continuation, by (processor, endianness, size)
_MECHANISMS = {("AARCH64", "LE", "64"): "link", ("x86", "LE", "64"): "push", ("x86", "LE", "32"): "push"}


def function_certificate(normalized, observation, scopes, callee_certificates: dict,
                         *, code_reader=None, pac_spec: str | None = None, summary=None,
                         inherited=()) -> ContinuationCertificate:
    """``callee_certificates``: call / tail operation key -> the target's
    certificate (absent: an opaque or unresolved target -> UNKNOWN);
    ``code_reader(address, size)``: the image's bytes (AArch64's PAC scan);
    ``pac_spec``: the language spec digest the export used (``PAC_SPEC_12_0_4``
    to scan; anything else -> AArch64 functions are not CLOSED); ``summary``:
    the function's own summary (its exits' SP deltas), when available."""
    evidence = scopes.program.evidence
    entry = scopes.function.entry
    dependencies = [f"graph:{scopes.function.scope.digest.hex()}"]
    if getattr(normalized, "memory_ssa", None) is None:
        return ContinuationCertificate("unknown", False, (), ("not-normalized",), tuple(dependencies), entry)
    parts = tuple(evidence.translation_namespace.language_id.split(":"))
    mechanism = _MECHANISMS.get(parts[:3]) if len(parts) >= 4 else None
    sp = stack_register(evidence)
    link = link_register(evidence) if mechanism == "link" else None
    if mechanism is None or sp is None or (mechanism == "link" and link is None):
        # the language's mechanism decides which evidence is required; missing
        # evidence is never read as another ISA's mechanism
        return ContinuationCertificate("unknown", False, (), ("no-isa-evidence",), tuple(dependencies), entry)
    dependencies.extend(_premises(normalized))
    # the function's own summary decisions (the callers' effects rest on them;
    # a caller inherits them through this certificate)
    dependencies.extend(f"assumption:{name}" for name, _stage, _at in getattr(summary, "premise_uses", ()))
    # the analysis' own inherited labels (models, call-target resolutions,
    # activations, forward facts): a conservative function-level union until
    # each is recorded at its decision (2b-P B3-B9)
    dependencies.extend(f"inherited:{label}" for label in sorted(inherited))
    witness = _Witness(normalized, observation, scopes, sp, link)
    culprits: list[str] = []
    exits: list[ExitRecord] = []
    if mechanism == "link":
        dependencies.append(f"pac:{pac_spec}")
        culprits.extend(_pac_scan(observation, code_reader, pac_spec))
    observed = {(row.address.space_id, row.address.byte_offset) for row in observation.instructions}
    sp_delta, proof_digest = _exit_delta(normalized, observation, scopes, sp)
    if proof_digest is not None:
        dependencies.append(f"register-delta-proof:{proof_digest}")
    relations = call_relations(observation, scopes)
    for instruction in observation.instructions:
        keys = [_operation_key(instruction.address, index, op.opcode) for index, op in enumerate(instruction.operations)]
        flow = instruction.flow
        tail = flow.is_call and not flow.has_fallthrough
        # every outgoing transfer is classified (or the function is not CLOSED)
        culprits.extend(_transfer_gaps(instruction, keys, observed, tail))
        for key, operation in zip(keys, instruction.operations):
            if operation.opcode == "BRANCHIND" and not tail:
                # a listed target set (a recovered jump table) is what the
                # exporter found, not proof that the value can take no other:
                # no evidence of exhaustiveness exists yet [forward]
                culprits.append(key)
            elif operation.opcode in _CALLS and not tail:
                certificate = callee_certificates.get(key, UNKNOWN_CALLEE)
                if not _covers(certificate, instruction, operation):
                    culprits.append(f"uncertified-call-target:{key}")
                dependencies.append(f"call:{key}")
                dependencies.extend(certificate.dependencies)
                if certificate.status not in ("proven", "noreturn"):
                    culprits.append(key)
                elif certificate.status == "proven" and not _continues(relations.get(key), mechanism, instruction):
                    # the callee returns to ITS entry link: only the call's own
                    # relation proves that link is this call's fallthrough (2a)
                    culprits.append(f"no-continuation-relation:{key}")
            elif operation.opcode == "CALLOTHER":
                # an unmodeled user op may change any state (a visible PAC op
                # among them); its models come with Stage 4
                culprits.append(key)
        last = instruction.operations[-1] if instruction.operations else None
        key = keys[-1] if keys else _instruction_key(instruction)
        if last is not None and last.opcode == "RETURN":
            reason, path = witness.returns_entry_link(key, last)
            exits.append(ExitRecord(key, "return", reason == "", reason, "unknown", path, sp_delta, None))
        elif tail and last is not None and last.opcode in ("BRANCH", "BRANCHIND", "CALL", "CALLIND"):
            certificate = callee_certificates.get(key, UNKNOWN_CALLEE)
            if not _covers(certificate, instruction, last):
                culprits.append(f"uncertified-call-target:{key}")
            dependencies.append(f"tail:{key}")
            dependencies.extend(certificate.dependencies)
            if certificate.status == "noreturn":
                continue
            path: tuple = ()
            if certificate.status != "proven":
                reason = "tail-target-" + certificate.status
                culprits.append(f"tail:{key}")
            elif mechanism == "push":
                reason = "x86-tail-not-in-2b"
            else:
                reason, path = witness.link_intact_at(key)
            exits.append(ExitRecord(key, "tail", reason == "", reason, "unknown", path, None,
                                    tuple(certificate.dependencies)))
        elif instruction.fallthrough is None and not (
                last is not None and last.opcode in ("BRANCH", "BRANCHIND")):
            # control leaves the instruction neither to the next one nor by a
            # classified transfer (BRANCH: _transfer_gaps checks its target)
            exits.append(ExitRecord(key, "unresolved", False,
                                    f"terminal-{last.opcode.lower() if last is not None else 'empty'}", "unknown",
                                    (), None, ()))
    closed = not culprits and not any(record.kind == "unresolved" for record in exits)
    if closed and not exits:
        status = "noreturn"
    elif closed and all(record.proven for record in exits):
        status = "proven"
    else:
        status = "unknown"
    dependencies = tuple(sorted(set(dependencies)))
    # a return's proof rests on the whole function's premises (its normalization
    # and its calls' certificates): conservatively, the function's union
    exits = [replace(record, dependencies=dependencies) if record.dependencies is None else record
             for record in exits]
    return ContinuationCertificate(status, closed, tuple(exits), tuple(culprits), dependencies, entry)


def _continues(relation, mechanism, instruction) -> bool:
    """The call writes its fallthrough as the callee's entry link, by the
    language's mechanism (a CallRelation of that kind)."""
    return relation is not None and relation.kind == mechanism and relation.continuation == instruction.fallthrough


def _covers(certificate, instruction, operation) -> bool:
    """The certificate is the exported destination's: every exported target
    of the instruction, and a direct operand, is its function's entry (an
    indirect call with no exported target rests on the caller's resolution)."""
    if certificate.entry is None:
        return True   # no function: UNKNOWN, a culprit anyway
    destination = operation.inputs[0] if operation.inputs else None
    if operation.opcode in ("CALL", "BRANCH") and destination is not None \
            and destination.kind is VarnodeKindCode.ADDRESS and destination.coordinate != certificate.entry:
        return False
    return all(target == certificate.entry for target in instruction.flow_targets)


def _instruction_key(instruction) -> str:
    return f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}"


def _relative(varnode) -> int:
    """A p-code relative branch's signed operation offset."""
    bits = 8 * min(varnode.byte_size, 8)
    value = varnode.coordinate.byte_offset & ((1 << bits) - 1)
    return value - (1 << bits) if value >> (bits - 1) else value


def _transfer_gaps(instruction, keys, observed, tail) -> list[str]:
    """Why one instruction's outgoing transfers are not all classified (Astra
    2b r1-r4) -- an allow-list: BRANCH / CBRANCH to an address or to a p-code
    relative position inside the instruction, and RETURN / CALL / CALLIND /
    BRANCHIND only as the last operation. The successors the p-code implies
    (its address targets; the fallthrough when control can reach the end)
    must be exactly the exported ones, all observed code of this function; a
    present fallthrough agrees with its flag; a call's / tail's exported
    targets are at most the one callee its certificate covers."""
    from .control_projection import control_successor_coordinates

    operations = instruction.operations
    where = keys[-1] if keys else _instruction_key(instruction)
    flow = instruction.flow
    gaps = []
    if (instruction.fallthrough is not None) != flow.has_fallthrough:
        gaps.append(f"inconsistent-fallthrough:{where}")
    implied: set = set()
    callees = None
    reaches_end = not operations or operations[-1].opcode not in ("BRANCH", "RETURN", "BRANCHIND", *_CALLS) \
        or (operations[-1].opcode in _CALLS and not tail)
    for index, operation in enumerate(operations):
        last = index == len(operations) - 1
        if operation.opcode in ("BRANCH", "CBRANCH"):
            destination = operation.inputs[0] if operation.inputs else None
            if destination is None or len(operation.inputs) != (2 if operation.opcode == "CBRANCH" else 1):
                gaps.append(f"unsupported-branch:{keys[index]}")
            elif destination.kind is VarnodeKindCode.CONSTANT:
                position = index + _relative(destination)
                if not 0 <= position <= len(operations):
                    gaps.append(f"unsupported-branch:{keys[index]}")
                elif position == len(operations):
                    reaches_end = True
            elif destination.kind is not VarnodeKindCode.ADDRESS:
                gaps.append(f"unsupported-branch:{keys[index]}")
            elif tail and last and operation.opcode == "BRANCH":
                callees = {destination.coordinate}
            elif destination.coordinate != instruction.address:
                implied.add(destination.coordinate)
        elif operation.opcode in ("RETURN", "BRANCHIND", *_CALLS):
            if not last:
                gaps.append(f"mid-instruction-transfer:{keys[index]}")
            elif operation.opcode in _CALLS or (tail and operation.opcode == "BRANCHIND"):
                direct = operation.opcode == "CALL" and operation.inputs \
                    and operation.inputs[0].kind is VarnodeKindCode.ADDRESS
                callees = {operation.inputs[0].coordinate} if direct else set(instruction.flow_targets)
    if flow.is_call != (callees is not None):
        gaps.append(f"inconsistent-call:{where}")
    elif callees is not None and (len(callees) > 1 or not set(instruction.flow_targets) <= callees):
        gaps.append(f"uncertified-call-target:{where}")
    if reaches_end:
        if instruction.fallthrough is None:
            gaps.append(f"no-fallthrough:{where}")
        else:
            implied.add(instruction.fallthrough)
    successors = set(control_successor_coordinates(instruction))
    if successors != implied or any((target.space_id, target.byte_offset) not in observed for target in successors):
        gaps.append(f"unclassified-successor:{where}")
    return gaps


# the normalization's policy switches by their registry names (docs 25.91)
_POLICY_FIELDS = {
    "assumes_globals_disjoint_from_stack": "globals-disjoint-from-stack",
    "assumes_readonly_image_constant": "readonly-image-data-is-constant",
    "assumes_import_slots_hold_exports": "import-slots-hold-their-exports",
    "assumes_entry_values_not_frame": "entry-values-do-not-address-the-new-frame",
    "assumes_opaque_callees_leave_no_stack_addresses": "opaque-callees-leave-no-stack-addresses",
    "assumes_pre_escape_values_not_frame": "pre-escape-values-do-not-address-the-new-frame",
    "assumed_direction_flag_clear": "direction-flag-clear",
    "assumes_opaque_callees_restore_stack_pointer": "opaque-callees-restore-stack-pointer",
}


def _premises(normalized) -> list[str]:
    """What this normalization rests on: every policy switch in force (a
    superset until every producer records its uses), every recorded use
    (2b-P: incl. run-synthesized ones such as the win64 home space), every
    assumed / proven call effect, every forward proof it required -- a
    withdrawal of any invalidates the certificate. An assumption field this
    table does not know is kept under its field name (never dropped)."""
    import dataclasses

    found = []
    for field in dataclasses.fields(normalized):
        if not field.name.startswith(("assumes_", "assumed_")) or field.name == "assumed_call_effects":
            continue
        if getattr(normalized, field.name):
            found.append(f"assumption:{_POLICY_FIELDS.get(field.name, field.name)}")
    for name, _stage, _at in getattr(normalized, "premise_uses", ()):
        found.append(f"assumption:{name}")
    for key, effect in getattr(normalized, "assumed_call_effects", ()):
        found.append(f"assumed-effect:{key}:{effect.label}")
    for key, effect in getattr(normalized, "proven_call_effects", ()):
        found.append(f"effect:{key}:{effect.callee}")
    for item in getattr(normalized, "forward_memory_requires", ()):
        found.append(f"forward:{item}")
    return found


def _exit_delta(normalized, observation, scopes, sp) -> tuple[int | None, str | None]:
    """SP at a normal exit - SP at entry, from the independent register-only
    proof over the original CFG (``register_delta_proofs``, docs 25.89) --
    never the summary's own AFFINE constant; (None, None) when it refuses.
    Scope: IF a normal exit is reached; neither continuation nor termination."""
    from types import SimpleNamespace

    from .register_delta_proofs import derive_register_delta_proof

    register = StorageObjectId(StorageObjectKind.REGISTER_FILE, scopes.program.scope, 0)
    proof = derive_register_delta_proof(
        SimpleNamespace(scopes=scopes, observation=observation), ByteSpan(register, sp.byte_offset, sp.byte_size),
        dict(normalized.proven_call_effects), dict(getattr(normalized, "intrinsic_refinements", ())),
        assumed_call_effects=getattr(normalized, "assumed_call_effects", ()))
    if proof is None:
        return None, None
    return proof.delta, proof.record()["content_sha256"]


def program_certificates(functions: dict, *, code_reader=None, pac_spec=None) -> dict:
    """``functions``: key -> (normalized, observation, scopes, targets: call /
    tail operation key -> callee key or None[, the function's summary[, its
    inherited assumption labels]]). Callees first; a call into an
    unfinished function (recursion) is UNKNOWN."""
    done: dict = {}
    active: set = set()

    def certify(key):
        if key in done:
            return done[key]
        if key in active or key not in functions:
            return UNKNOWN_CALLEE
        active.add(key)
        normalized, observation, scopes, targets, *rest = functions[key]
        summary = rest[0] if rest else None
        inherited = rest[1] if len(rest) > 1 else ()
        callees = {call: certify(target) for call, target in targets.items() if target is not None}
        active.discard(key)
        done[key] = function_certificate(normalized, observation, scopes, callees,
                                         code_reader=code_reader, pac_spec=pac_spec,
                                         summary=summary, inherited=inherited)
        return done[key]

    for key in functions:
        certify(key)
    return done


def _pac_scan(observation, code_reader, pac_spec) -> list[str]:
    """Every instruction's 32-bit word against the pinned table; any missing
    byte, another spec, or no reader -> a culprit (fail closed)."""
    if pac_spec != PAC_SPEC_12_0_4:
        return ["pac-spec-unpinned"]
    if code_reader is None:
        return ["pac-bytes-unavailable"]
    found = []
    for instruction in observation.instructions:
        data = code_reader(instruction.address.byte_offset, 4)
        if data is None or len(data) != 4:
            found.append(f"pac-unreadable:{instruction.address.byte_offset:x}")
            continue
        word = int.from_bytes(data, "little")
        if any(word & mask == value for value, mask in PAC_TABLE_12_0_4):
            found.append(f"pac:{instruction.address.byte_offset:x}")
    return found


class _Witness:
    """Byte equality of a location with the function's entry link, through the
    SSA (full-width chains only: a partial or reshaped value proves nothing)."""

    def __init__(self, normalized, observation, scopes, sp, link) -> None:
        self.normalized = normalized
        self.observation = observation
        self.ssa = normalized.memory_ssa
        self.scopes = scopes
        self.link = link
        self.register = StorageObjectId(StorageObjectKind.REGISTER_FILE, scopes.program.scope, 0)
        if link is not None:
            self.entry = ByteSpan(self.register, link.byte_offset, link.byte_size)
        else:
            memory = [row for row in scopes.program.evidence.address_spaces if row.is_loaded_memory_space]
            if len(memory) != 1:
                self.entry = None
            else:
                anchor = ByteSpan(self.register, sp.byte_offset, sp.byte_size)
                obj = _function_relative_object_id(self.ssa.function_scope, anchor, memory[0].space_id)
                self.entry = ByteSpan(obj, 1 << memory[0].address_size_bits, sp.byte_size)
        self.actions = {action.operation_key: index for index, action in enumerate(self.ssa.actions)}
        self.reads: dict = {}
        for read in self.ssa.reads:
            self.reads.setdefault(read.action_id, []).append(read)
        self.joins = {row.join_definition_id: row.source_definition_ids for row in self.ssa.joins}
        self.operations: dict = {}
        self._debts = None
        self.path: list = []

    def operation(self, key):
        if not self.operations:
            for instruction in self.observation.instructions:
                for index, op in enumerate(instruction.operations):
                    self.operations[_operation_key(instruction.address, index, op.opcode)] = op
        return self.operations.get(key)

    def returns_entry_link(self, key, operation) -> tuple[str, tuple]:
        """(reason, the operations the proof went through)."""
        if self.entry is None:
            return "no-entry-link", ()
        if len(operation.inputs) != 1:
            return "return-arity", ()
        self.path = [key]
        reason = self._value_at(key, operation.inputs[0])
        return reason, tuple(self.path)

    def link_intact_at(self, key) -> tuple[str, tuple]:
        self.path = [key]
        reason = self._link_intact_at(key)
        return reason, tuple(self.path)

    def _link_intact_at(self, key) -> str:
        """The link register's value at a tail jump is the entry link: the jump
        reads nothing, so the value is the SSA's terminal state of the jump's
        block (the jump ends it), every definition held there proven."""
        blocks = {action.operation_key: block.key for block in self.normalized.memory_unit.blocks
                  for action in block.actions}
        block = blocks.get(key)
        if block is None:
            return "no-block"
        tracked = any(span.object_id == self.entry.object_id and span.overlaps(self.entry)
                      for span in self.ssa.atomic_spans)
        if not tracked:
            # the SSA tracks only bytes something reads or writes: untracked link
            # bytes are written by nothing in the function (no definition, raw or
            # modeled, overlaps them), so they still hold their entry value
            return "" if not any(row.span.object_id == self.entry.object_id and row.span.overlaps(self.entry)
                                 for row in self.ssa.definitions
                                 if row.kind is not MemoryDefinitionKind.ENTRY) else "link-untracked-but-written"
        states = [state for state in self.ssa.observed_terminal_states
                  if state.block_key == block and state.root_node_id is not None]
        if len(states) != 1:
            return "no-terminal-state"
        held = self._state(states[0].root_node_id)
        atoms = [span for span in held if span.object_id == self.entry.object_id and span.overlaps(self.entry)]
        if atoms != [self.entry]:
            return "link-atoms"
        for definition_id in held[self.entry]:
            reason = self._definition(definition_id, self.entry, set())
            if reason:
                return reason
        return ""

    def _state(self, root) -> dict:
        result, pending = {}, [root]
        while pending:
            node = self.ssa.state_nodes[pending.pop()]
            for atom in range(node.start_atom, node.stop_atom):
                result[self.ssa.atomic_spans[atom]] = node.definition_ids
            pending.extend(child for child in (node.left_node_id, node.right_node_id) if child is not None)
        return result

    # -- tracing ---------------------------------------------------------------------------
    def _value_at(self, key, varnode) -> str:
        span = self._span_of(varnode)
        if span is None:
            return "unresolved-operand"
        return self._span_at(key, span, set())

    def _span_of(self, varnode):
        resolved = _resolve_validated_storage(storage_ref(varnode), self.scopes.resolution_context)
        return resolved.span if type(resolved) is ResolvedStorage else None

    def _span_at(self, key, span, seen) -> str:
        """The bytes ``span`` read by action ``key`` are the entry link."""
        action = self.actions.get(key)
        if action is None:
            return "no-action"
        reads = [read for read in self.reads.get(action, ()) if read.span == span]
        if len(reads) != 1:
            return "no-read"
        (read,) = reads
        if not self._settled(key, action, span):
            return "debt"
        if len(read.fragments) != 1 or read.fragments[0].span != span:
            return "fragmented"
        for definition_id in read.fragments[0].definition_ids:
            reason = self._definition(definition_id, span, seen)
            if reason:
                return reason
        return ""

    def _definition(self, definition_id, span, seen) -> str:
        if (definition_id, span) in seen:
            return "cycle"
        seen = seen | {(definition_id, span)}
        definition = self.ssa.definitions[definition_id]
        if definition.kind is MemoryDefinitionKind.ENTRY:
            return "" if span == self.entry else "other-entry"
        if definition.kind is MemoryDefinitionKind.JOIN:
            for source in self.joins.get(definition_id, ()):
                reason = self._definition(source, span, seen)
                if reason:
                    return reason
            return ""
        if definition.kind is not MemoryDefinitionKind.DATA_WRITE or "~" in definition.operation_key:
            return "not-a-copy"
        self.path.append(definition.operation_key)
        operation = self.operation(definition.operation_key)
        if operation is None:
            return "no-operation"
        if operation.opcode == "COPY" and len(operation.inputs) == 1 and operation.inputs[0].byte_size == span.size:
            source = self._span_of(operation.inputs[0])
            return "unresolved-operand" if source is None else self._span_at(definition.operation_key, source, seen)
        if operation.opcode == "LOAD" and operation.output is not None and operation.output.byte_size == span.size:
            action = self.actions.get(definition.operation_key)
            address = self._span_of(operation.inputs[1]) if len(operation.inputs) > 1 else None
            if address is None or not self._slice_settled(definition.operation_key, address, set()):
                return "address-debt"
            loaded = [read for read in self.reads.get(action, ()) if read.span != address
                      and read.span.size == span.size and read.span.object_id.kind in (
                          StorageObjectKind.FUNCTION_RELATIVE, StorageObjectKind.ADDRESS_SPACE)]
            if len(loaded) != 1:
                return "load-unresolved"
            return self._span_at(definition.operation_key, loaded[0].span, seen)
        if operation.opcode == "STORE" and len(operation.inputs) == 3 and operation.inputs[2].byte_size == span.size:
            address = self._span_of(operation.inputs[1])
            if address is None or not self._slice_settled(definition.operation_key, address, set()):
                return "address-debt"
            source = self._span_of(operation.inputs[2])
            return "unresolved-operand" if source is None else self._span_at(definition.operation_key, source, seen)
        return f"computed-{operation.opcode.lower()}"

    def _slice_settled(self, key, span, seen) -> bool:
        """The value ``span`` read by action ``key`` -- a LOAD / STORE address
        the witness follows -- carries no debt anywhere in its backward slice
        (a callee's unproven stack adjustment before ``add rsp``; Astra 2b r7):
        the read itself and, transitively, every read of every definition."""
        action = self.actions.get(key)
        if action is None or not self._settled(key, action, span):
            return False
        reads = [read for read in self.reads.get(action, ()) if read.span == span]
        if len(reads) != 1:
            return False
        return all(self._definition_settled(definition_id, seen)
                   for fragment in reads[0].fragments for definition_id in fragment.definition_ids)

    def _definition_settled(self, definition_id, seen) -> bool:
        if definition_id in seen:
            return True
        seen.add(definition_id)
        definition = self.ssa.definitions[definition_id]
        if definition.kind is MemoryDefinitionKind.ENTRY:
            return True
        if definition.kind is MemoryDefinitionKind.JOIN:
            return all(self._definition_settled(source, seen) for source in self.joins.get(definition_id, ()))
        key = definition.operation_key
        action = self.actions.get(key)
        if action is None:
            return False
        return all(self._slice_settled(key, read.span, seen) for read in self.reads.get(action, ()))

    def _settled(self, key, action, span) -> bool:
        """As ``configured_state_barrier.read_settled``: no call-clobber or
        may-alias row of the action covers the span; for memory, no other
        memory debt on the action and no unresolved write in the function."""
        if self._debts is None:
            spanned: dict = {}
            for row in getattr(self.normalized, "call_clobber_reads", ()):
                spanned.setdefault(row.operation_key, []).extend(row.spans)
            for row in getattr(self.normalized, "may_alias_reads", ()):
                spanned.setdefault(row.operation_key, []).extend(row.spans or (None,))
            memory = set(getattr(self.normalized, "opaque_nodes", ()))
            memory.update(node for node, _ in getattr(self.normalized, "uncertain_nodes", ()))
            memory.update(node for node, _ in getattr(self.normalized, "open_nodes", ()))
            memory.update(self.normalized.memory_graph.unresolved_read_nodes)
            self._debts = (spanned, frozenset(memory))
        spanned, memory_debts = self._debts
        if any(item is None or item.overlaps(span) for item in spanned.get(key, ())):
            return False
        if span.object_id.kind not in (StorageObjectKind.ADDRESS_SPACE, StorageObjectKind.FUNCTION_RELATIVE):
            return True
        if self.ssa.unresolved_writes:
            return False
        node = self.normalized.memory_graph.action_nodes[action]
        return not any(item in memory_debts for item in self.normalized.dependencies.predecessors(node))


__all__ = ["ContinuationCertificate", "ExitRecord", "PAC_SPEC_12_0_4", "PAC_TABLE_12_0_4",
           "function_certificate", "program_certificates"]
