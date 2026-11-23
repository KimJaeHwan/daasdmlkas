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
from .pcode_blocks import tail_transfers
from .premises import POLICY_FIELDS as _POLICY_FIELDS  # (the normalization's policy switches, docs 25.91)
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
    observed = {row.address for row in observation.instructions}
    # S1 records the ISA continuation even when its destination is unmapped
    # and the instruction itself carries no fallthrough coordinate.
    continuation_exits = {row.source for row in getattr(observation, "fallthrough_exits", ())}
    facts = tail_transfers(observation, entry)
    sp_delta, proof_digest = _exit_delta(normalized, observation, scopes, sp)
    if proof_digest is not None:
        dependencies.append(f"register-delta-proof:{proof_digest}")
    relations = call_relations(observation, scopes)
    for instruction in observation.instructions:
        keys = [_operation_key(instruction.address, index, op.opcode) for index, op in enumerate(instruction.operations)]
        if instruction.flow.is_override:
            # (G3b-5 r6/r7; Astra r5-r6 P1, Fable r5 P3-1) a flow override's
            # behaviour, not the raw p-code (even a plain COPY), decides where
            # this row goes: unproved
            culprits.append(f"flow-override:{keys[-1] if keys else _instruction_key(instruction)}")
        unmapped_continuation = instruction.fallthrough is None and instruction.address in continuation_exits
        # every outgoing transfer is classified (or the function is not CLOSED)
        culprits.extend(_transfer_gaps(instruction, keys, observed, entry, facts))
        for key, operation in zip(keys, instruction.operations):
            # A terminal CALL / CALLIND without a continuation retains its 2b
            # tail semantics. A branch is a tail only at its exact graph site,
            # which can be the end of a split block inside the instruction.
            terminal_call = (operation.opcode in _CALLS and key == keys[-1]
                             and instruction.fallthrough is None and not unmapped_continuation)
            fact = facts.get(key)
            if fact is not None or terminal_call:
                certificate = callee_certificates.get(key, UNKNOWN_CALLEE)
                covered = _covers(certificate, instruction, operation, fact)
                dependencies.append(f"tail:{key}")
                dependencies.extend(certificate.dependencies)
                if not covered:
                    reason, path = "uncertified-call-target", ()
                    culprits.append(f"{reason}:{key}")
                elif certificate.status == "noreturn":
                    # Only this outcome cannot return. A CBRANCH's local
                    # fallthrough and its possible exits are still checked.
                    continue
                elif certificate.status != "proven":
                    reason, path = "tail-target-" + certificate.status, ()
                    culprits.append(f"tail:{key}")
                elif mechanism == "push":
                    reason, path = "x86-tail-not-in-2b", ()
                else:
                    # For a conditional tail the raw operation ends the
                    # source block, before the taken edge's staged effects.
                    reason, path = witness.link_intact_at(key, fact.edge if fact is not None else None)
                exits.append(ExitRecord(key, "tail", reason == "", reason, "unknown", path, None,
                                        tuple(certificate.dependencies)))
            elif operation.opcode == "BRANCHIND":
                # a listed target set (a recovered jump table) is what the
                # exporter found, not proof that the value can take no other:
                # no evidence of exhaustiveness exists yet [forward]
                culprits.append(key)
            elif operation.opcode in _CALLS:
                certificate = callee_certificates.get(key, UNKNOWN_CALLEE)
                covered = _covers(certificate, instruction, operation)
                if not covered:
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
        elif instruction.fallthrough is None and instruction.address not in continuation_exits and not (
                last is not None and last.opcode in ("BRANCH", "BRANCHIND", *_CALLS)):
            # control leaves the instruction neither to the next one nor by a
            # classified transfer (BRANCH: _transfer_gaps checks its target)
            exits.append(ExitRecord(key, "unresolved", False,
                                    f"terminal-{last.opcode.lower() if last is not None else 'empty'}", "unknown",
                                    (), None, ()))
        if instruction.address in continuation_exits and _reaches_end(instruction, keys, callee_certificates):
            # (G3b-5 r3/r4, R5-1; Astra r1 P1-2, r3 Q3) S1 lists this row's
            # fallthrough as leaving the function -- to an unmapped place,
            # another function's entry or interior (shared code) -- even when
            # the coordinate is local: control reaching the row's end (over its
            # reachable p-code paths, a covered noreturn call cutting only the
            # paths through it) may continue there, whose return to our caller
            # nothing proves (``function_summary`` treats the same rows as
            # exits). One record per row; a RETURN on another path keeps its own.
            unmapped_call = instruction.fallthrough is None and last is not None and last.opcode in _CALLS
            exits.append(ExitRecord(key, "unresolved", False,
                                    "unmapped-call-continuation" if unmapped_call else "s1-continuation-exit",
                                    "unknown", (), None, ()))
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


def _reaches_end(instruction, keys, callee_certificates) -> bool:
    """(R5-1) Some reachable p-code path of the row reaches its end (the
    operation count): relative branches followed (a target at or past the
    end reaches it), an address-form CBRANCH also falls through, BRANCH /
    BRANCHIND / RETURN stop a path, a CALL / CALLIND stops it only when its
    covered callee certificate is ``noreturn`` (r1's exact-entry exemption)."""
    operations = instruction.operations
    if instruction.flow.is_override:
        return True   # (r5; Astra r4: the override's behaviour, not the raw p-code, decides)
    pending, seen = [0], set()
    while pending:
        index = pending.pop()
        if index >= len(operations) or index < 0:
            return True   # (a negative target is malformed: fail toward an exit)
        if index in seen:
            continue
        seen.add(index)
        operation = operations[index]
        destination = operation.inputs[0] if operation.inputs else None
        if operation.opcode in ("BRANCH", "CBRANCH") and destination is not None \
                and destination.kind is VarnodeKindCode.CONSTANT:
            pending.append(index + _relative(destination))
            if operation.opcode == "CBRANCH":
                pending.append(index + 1)
        elif operation.opcode == "CBRANCH":
            pending.append(index + 1)
        elif operation.opcode in ("BRANCH", "BRANCHIND", "RETURN"):
            continue
        elif operation.opcode in _CALLS:
            certificate = callee_certificates.get(keys[index], UNKNOWN_CALLEE)
            if not (certificate.status == "noreturn" and _covers(certificate, instruction, operation)):
                pending.append(index + 1)
        else:
            pending.append(index + 1)
    return False


def _continues(relation, mechanism, instruction) -> bool:
    """The call writes its fallthrough as the callee's entry link, by the
    language's mechanism (a CallRelation of that kind)."""
    return relation is not None and relation.kind == mechanism and relation.continuation == instruction.fallthrough


def _covers(certificate, instruction, operation, fact=None) -> bool:
    """The direct operand and every reported callee destination are covered by
    this certificate. A conditional tail may also list its local fallthrough.
    An indirect site with no listed destination needs the caller's resolution."""
    if certificate.entry is None:
        return certificate.status == "unknown"   # an opaque target is already a culprit
    destination = operation.inputs[0] if operation.inputs else None
    if operation.opcode in ("CALL", "BRANCH", "CBRANCH"):
        if destination is None or destination.kind is not VarnodeKindCode.ADDRESS \
                or destination.coordinate != certificate.entry:
            return False
    allowed = {certificate.entry}
    if fact is not None and fact.kind == "cbranch":
        allowed.add(instruction.fallthrough)
    return set(instruction.flow_targets) <= allowed


def _instruction_key(instruction) -> str:
    return f"{instruction.address.space_id:x}:{instruction.address.byte_offset:x}"


def _relative(varnode) -> int:
    """A p-code relative branch's signed operation offset."""
    bits = 8 * min(varnode.byte_size, 8)
    value = varnode.coordinate.byte_offset & ((1 << bits) - 1)
    return value - (1 << bits) if value >> (bits - 1) else value


def _transfer_gaps(instruction, keys, observed, entry, facts) -> list[str]:
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
    tail_destinations = set()
    reaches_end = not operations or operations[-1].opcode not in ("BRANCH", "RETURN", "BRANCHIND", *_CALLS) \
        or (operations[-1].opcode in _CALLS and instruction.fallthrough is not None)
    for index, operation in enumerate(operations):
        last = index == len(operations) - 1
        fact = facts.get(keys[index])
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
            elif fact is not None:
                tail_destinations.add(fact.target)
            elif destination.coordinate != instruction.address:
                implied.add(destination.coordinate)
                if destination.coordinate in observed and destination.coordinate != instruction.fallthrough \
                        and destination.coordinate not in instruction.flow_targets:
                    # The graph can retain the operand's definite local edge.
                    # Closure independently requires the reported flow to agree.
                    gaps.append(f"unclassified-successor:{keys[index]}")
                if operation.opcode == "BRANCH" and destination.coordinate not in observed \
                        and set(instruction.flow_targets) - {destination.coordinate}:
                    gaps.append(f"uncertified-call-target:{keys[index]}")
        elif operation.opcode in ("RETURN", "BRANCHIND", *_CALLS):
            if not last:
                gaps.append(f"mid-instruction-transfer:{keys[index]}")
            if operation.opcode in _CALLS or (fact is not None and fact.kind == "branchind"):
                direct = operation.opcode == "CALL" and operation.inputs \
                    and operation.inputs[0].kind is VarnodeKindCode.ADDRESS
                callees = {operation.inputs[0].coordinate} if direct else set(instruction.flow_targets)
                if len(operation.inputs) != 1 or len(callees) > 1 or not set(instruction.flow_targets) <= callees:
                    gaps.append(f"uncertified-call-target:{keys[index]}")
                if fact is not None:
                    tail_destinations.update(callees)
    if reaches_end:
        if instruction.fallthrough is None:
            gaps.append(f"no-fallthrough:{where}")
        else:
            implied.add(instruction.fallthrough)
    successors = set(control_successor_coordinates(instruction, local_addresses=observed, function_entry=entry))
    successors -= tail_destinations
    if successors != implied or not successors <= observed:
        gaps.append(f"unclassified-successor:{where}")
    return gaps


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
    if "assumption:globals-disjoint-from-stack" in found:
        # (its withdrawal check -- the program switches no stack -- rests on this one)
        found.append("assumption:stack-switch-check-exceptions")
    return found


def _exit_delta(normalized, observation, scopes, sp) -> tuple[int | None, str | None]:
    """SP at a normal exit - SP at entry, from the independent register-only
    proof over the original CFG (``register_delta_proofs``, docs 25.89) --
    never the summary's own AFFINE constant; (None, None) when it refuses.
    Scope: IF a normal exit is reached; neither continuation nor termination."""
    proof = _delta_proof(normalized, observation, scopes, sp)
    if proof is None:
        return None, None
    return proof.delta, proof.record()["content_sha256"]


def _delta_proof(normalized, observation, scopes, sp):
    from types import SimpleNamespace

    from .register_delta_proofs import derive_register_delta_proof

    register = StorageObjectId(StorageObjectKind.REGISTER_FILE, scopes.program.scope, 0)
    return derive_register_delta_proof(
        SimpleNamespace(scopes=scopes, observation=observation), ByteSpan(register, sp.byte_offset, sp.byte_size),
        dict(normalized.proven_call_effects), dict(getattr(normalized, "intrinsic_refinements", ())),
        assumed_call_effects=getattr(normalized, "assumed_call_effects", ()))


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
        # (R5-2) callees in operation-key order, functions in key order: the
        # UNKNOWN cut inside a recursive component is at the member reached
        # first from the lowest key, whatever order the caller's dict has
        callees = {call: certify(targets[call]) for call in sorted(targets) if targets[call] is not None}
        active.discard(key)
        done[key] = function_certificate(normalized, observation, scopes, callees,
                                         code_reader=code_reader, pac_spec=pac_spec,
                                         summary=summary, inherited=inherited)
        return done[key]

    for key in sorted(functions):
        certify(key)
    return {key: done[key] for key in functions if key in done}


@dataclass(frozen=True, slots=True)
class CertificateSupport:
    """2b-P P-c3 (design r5 C): one function's typed supports. ``*_unpadded``
    rest on recorded uses and producer dependencies only (P-c5 acceptance);
    the others also carry the policy switches in force and the inherited /
    run-union bridges until their removal is reviewed. ``sp`` is independent
    of continuation: an UNKNOWN continuation leaves a proven SP delta's
    support intact (None: no independent proof)."""

    continuation: object
    continuation_unpadded: object
    sp: object = None
    sp_unpadded: object = None


def certificate_supports(certificates: dict, results: dict, resolver, *, run_bridge=()) -> dict:
    """``certificates``: ``program_certificates`` of ``results`` (the published
    ``analyze_units`` results); ``resolver``: the run's ``PremiseResolver``.
    Returns key -> ``CertificateSupport``.

    Continuation: the function's own resolved uses and the closure of every
    producer it consumed (``producer_support``) + the callee / tail
    certificates' supports (``via``); obligations: culprits, unproven exits,
    unknown labels and missing producers reached. SP: the independent proof
    (evidence: its digest and audited intrinsics, the engine and resolver
    identities); for each receipt the exact admitted effect it names
    (fingerprint re-matched), backed by the exact producer instance it was
    consumed from -- the receipt's own callee -- and that instance's closure
    (no such backing: an obligation), plus the caller's own decisions at that
    call (admission, discharge, resolution, context; an unresolved one is an
    obligation); each assumed no-effect receipt backed by the caller's
    admission of that very label at that operation, with its decisions there
    likewise. The published set
    also carries the caller's bridges (an unresolved one: an obligation)."""
    from .premises import ClaimType, EvidenceRef, Support, UnknownPremise, compose
    from .producer_support import producer_closures
    from .register_delta_proofs import _call_fingerprint
    from .summary_templates import ENGINE_SEMANTICS_VERSION

    closures = producer_closures(results, resolver, run_bridge)
    base = {EvidenceRef("engine", str(ENGINE_SEMANTICS_VERSION)), EvidenceRef("resolver", resolver.identity)}
    done: dict = {}
    active: set = set()

    def evidence_of(certificate) -> set:
        found = set(base)
        for item in certificate.dependencies:
            kind, _, value = item.partition(":")
            if kind in ("graph", "pac", "register-delta-proof"):
                found.add(EvidenceRef(kind, value))
        return found

    def continuation(key):
        if key in done:
            return done[key]
        if key in active or key not in certificates or key not in results:
            stub = Support(ClaimType.CONTINUATION, key, obligations=("recursion" if key in active else "opaque",))
            return stub, stub
        active.add(key)
        certificate, item = certificates[key], results[key]
        closure = closures.of(item)
        obligations = [*certificate.culprits, *(f"exit:{row.key}:{row.reason}" for row in certificate.exits
                                                if not row.proven)]
        if certificate.status == "unknown":
            obligations.append("status:unknown")
        obligations.extend(closure.obligations)
        targets = sorted(set(item.calls.values()))
        callees = [continuation(target) for target in targets]
        active.discard(key)
        evidence = evidence_of(certificate)
        done[key] = (
            compose(ClaimType.CONTINUATION, key, own=closure.published, evidence=evidence,
                    obligations=tuple(dict.fromkeys(obligations)), via=[row[0] for row in callees]),
            compose(ClaimType.CONTINUATION, key, own=closure.premises, evidence=evidence,
                    obligations=tuple(dict.fromkeys(obligations)), via=[row[1] for row in callees]))
        return done[key]

    def stack(key):
        certificate, item = certificates[key], results[key]
        normalized = item.normalized
        if getattr(normalized, "memory_ssa", None) is None:
            return None, None
        evidence = item.unit.scopes.program.evidence
        sp = stack_register(evidence)
        if sp is None:
            return None, None
        proof = _delta_proof(normalized, item.unit.observation, item.unit.scopes, sp)
        if proof is None:
            return None, None
        name = closures.names[id(item)]
        caller = closures.supports[name]
        effects = dict(normalized.proven_call_effects)
        unpadded, published, obligations = set(), set(), []
        found_evidence = {*base, EvidenceRef("proof", proof.record()["content_sha256"]),
                          *(EvidenceRef("intrinsic", f"{where}:{semantic}") for where, semantic in proof.intrinsics)}
        def at_call(call) -> set:
            """The caller's own decisions at ``call`` (admission of a model,
            alias discharge, a resolution, an extent / context): the resolved
            ones are premises, an unresolved one an obligation. Returns the
            labels admitted there."""
            admitted = set()
            for use in caller.uses:
                where = use.at[len(name) + 1:]
                if where == call or where.startswith(call + "~"):
                    unpadded.add(use.premise)
                    if use.stage == "admission" and where == call:
                        admitted.add(use.premise.id)
            for label, stage, where in caller.unresolved_uses:
                if where == call or where.startswith(call + "~"):
                    obligations.append(label)
                    if stage == "admission" and where == call:
                        admitted.add(label)
            return admitted

        for fact in proof.call_facts:
            effect = effects.get(fact.operation_key)
            if effect is None or _call_fingerprint(effect, proof.register) != fact.effect_fingerprint:
                obligations.append(f"receipt:{fact.operation_key}")
                continue
            at_call(fact.operation_key)
            # backing: the exact instance the effect was consumed from, and it
            # is the receipt's own callee (its summary produced the effect). A
            # receipt the checker admits names a function address, so a model
            # (labelled effect) never backs one: no other backing is accepted
            producers = item.consumed.get(fact.operation_key, ())
            if len(producers) != 1 or getattr(producers[0], "key", None) != fact.callee                     or producers[0].summary is None:
                obligations.append(f"unbacked-receipt:{fact.operation_key}")
                continue
            found = closures.of(producers[0])
            if found is None:
                obligations.append(f"unestablished-producer:{fact.operation_key}")
                continue
            unpadded |= found.premises
            published |= found.published
            obligations.extend(found.obligations)
        for where, label in proof.assumed_no_effect:
            # a no-effect p-code op: the very model the caller admitted at that
            # operation (its application), plus its other decisions there
            if label not in at_call(where):
                obligations.append(f"unbacked-receipt:{where}")
                continue
            try:
                unpadded.add(resolver.resolve(label))
            except UnknownPremise:
                obligations.append(label)
        published |= unpadded | caller.bridges
        own = tuple(dict.fromkeys(obligations))
        return (Support(ClaimType.REGISTER_DELTA, key, frozenset(published), frozenset(found_evidence),
                        tuple(dict.fromkeys((*own, *caller.unresolved_bridges)))),
                Support(ClaimType.REGISTER_DELTA, key, frozenset(unpadded), frozenset(found_evidence), own))

    result = {}
    for key in certificates:
        if key not in results:
            continue
        padded, unpadded = continuation(key)
        sp, sp_unpadded = stack(key)
        result[key] = CertificateSupport(padded, unpadded, sp, sp_unpadded)
    return result


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

    def link_intact_at(self, key, edge) -> tuple[str, tuple]:
        self.path = [key]
        reason = self._link_intact_at(key, edge)
        return reason, tuple(self.path)

    def _link_intact_at(self, key, edge) -> str:
        """Prove the incoming link at the transfer, before any staged tail writes.
        For a conditional tail only the taken edge has a terminal state. Its
        exit carries its source's link exactly when no action on the edge
        overwrites any byte of the link."""
        unit = self.normalized.memory_unit
        block = next((block for block in unit.blocks if any(action.operation_key == key for action in block.actions)),
                     None)
        if block is None:
            return "no-block"
        if edge is not None:
            taken = next((item for item in unit.blocks if item.key == edge), None)
            if taken is None or taken.predecessors != (block.key,):
                return "no-taken-edge-state"
            block = taken
        for action in block.actions:
            if edge is not None or action.operation_key.startswith(key + "~"):
                if any(span.overlaps(self.entry) for span in action.writes):
                    return "tail-staged-link-write"
        tracked = any(span.object_id == self.entry.object_id and span.overlaps(self.entry)
                      for span in self.ssa.atomic_spans)
        if not tracked:
            # the SSA tracks only bytes something reads or writes: untracked link
            # bytes are written by nothing in the function (no definition, raw or
            # modeled, overlaps them), so they still hold their entry value
            return "" if not any(row.span.object_id == self.entry.object_id and row.span.overlaps(self.entry)
                                 for row in self.ssa.definitions
                                 if row.kind is not MemoryDefinitionKind.ENTRY) else "link-untracked-but-written"
        states = [state for state in self.ssa.exit_states
                  if state.block_key == block.key and state.root_node_id is not None]
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
