"""One support contract for premises (Stage 2b-P, docs 25.91; design
``.census6/design_premise_2bp_r1.md`` .. ``_r3.md``, Astra r3 approved).

Vocabulary:

* **evidence** -- what a claim was derived from and never "withdrawn": the
  observed graph (scope digests), the language / spec identity, the engine
  semantics version (``EvidenceRef``);
* **premise** -- an unproven statement a claim may rest on (``PremiseRef``):
  a ``model`` row, an ``assumption`` (registry-backed or declared by a model
  file), an internal ``hypothesis`` (summary solving only -- never published),
  an analyst ``link`` (reserved: data claims only);
* **obligation** -- an undischarged debt; a claim with one is not established.

A ``Support`` is the conjunctive support of ONE derivation of one typed claim:
withdrawing any premise it lists invalidates that derivation (the claim is then
recomputed -- it may survive through another one).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from hashlib import sha256
import json


class PremiseKind(StrEnum):
    MODEL = "model"
    ASSUMPTION = "assumption"
    HYPOTHESIS = "hypothesis"
    LINK = "link"


class ClaimType(StrEnum):
    CONTINUATION = "continuation"
    REGISTER_DELTA = "register-delta"
    RESTORATION = "restoration"
    BYTE_EQUALITY = "byte-equality"
    PROVENANCE = "provenance"
    OWNERSHIP = "ownership"
    CONTROL_CLOSURE = "control-closure"


# which premise kinds a published claim of each type may rest on. A hypothesis
# is internal to summary solving and never published; an analyst link may only
# carry data claims -- never continuation, closure or a stack delta (the
# owner's opaque-continuation decision)
ADMISSIBLE = {
    ClaimType.CONTINUATION: frozenset({PremiseKind.MODEL, PremiseKind.ASSUMPTION}),
    ClaimType.CONTROL_CLOSURE: frozenset({PremiseKind.MODEL, PremiseKind.ASSUMPTION}),
    ClaimType.REGISTER_DELTA: frozenset({PremiseKind.MODEL, PremiseKind.ASSUMPTION}),
    ClaimType.RESTORATION: frozenset({PremiseKind.MODEL, PremiseKind.ASSUMPTION}),
    ClaimType.OWNERSHIP: frozenset({PremiseKind.MODEL, PremiseKind.ASSUMPTION}),
    ClaimType.BYTE_EQUALITY: frozenset({PremiseKind.MODEL, PremiseKind.ASSUMPTION, PremiseKind.LINK}),
    ClaimType.PROVENANCE: frozenset({PremiseKind.MODEL, PremiseKind.ASSUMPTION, PremiseKind.LINK}),
}

# where an inference decided under a premise (``PremiseUse.stage``)
STAGES = frozenset({"normalize", "summary", "condition-discharge", "refinement", "resolution", "activation",
                    "cut", "admission"})


class UnknownPremise(ValueError):
    """A label no registry row, model declaration or loaded model names: the
    claim resting on it is not established (fail closed, never dropped)."""


def _digest(value) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


@dataclass(frozen=True, slots=True, order=True)
class PremiseRef:
    kind: PremiseKind
    id: str
    digest: str        # the statement's content identity (editing it under the same id changes this)

    def __post_init__(self) -> None:
        if type(self.kind) is not PremiseKind or not self.id or len(self.digest) != 64:
            raise ValueError("a premise needs a kind, an id and a sha256 content digest")


@dataclass(frozen=True, slots=True, order=True)
class PremiseUse:
    """One decision taken under a premise: the stage that decided and where
    (an operation / call key); two applications of one premise are two uses."""

    premise: PremiseRef
    stage: str
    at: str

    def __post_init__(self) -> None:
        if self.stage not in STAGES or not self.at:
            raise ValueError(f"unknown premise-use stage {self.stage!r} or no location")


@dataclass(frozen=True, slots=True, order=True)
class EvidenceRef:
    kind: str          # "graph" | "spec" | "engine" | "proof" ...
    id: str


@dataclass(frozen=True, slots=True)
class Support:
    claim: ClaimType
    subject: str                                  # what the claim is about (a function / call / exit key)
    premises: frozenset = frozenset()             # PremiseRef, transitive (this derivation's conjunction)
    evidence: frozenset = frozenset()             # EvidenceRef
    obligations: tuple[str, ...] = ()             # undischarged debts / culprits
    via: tuple["Support", ...] = field(default=(), compare=False)   # the supports it composed (published only)

    @property
    def inadmissible(self) -> tuple[PremiseRef, ...]:
        allowed = ADMISSIBLE[self.claim]
        return tuple(sorted(item for item in self.premises if item.kind not in allowed))

    @property
    def established(self) -> bool:
        return not self.obligations and not self.inadmissible and all(item.established for item in self.via)

    @property
    def engine_proven(self) -> bool:
        """Established with no premise at all (evidence only)."""
        return self.established and not self.premises

    def by_kind(self) -> dict:
        """The premise set grouped by kind (report view; the groups compose)."""
        grouped: dict = {}
        for item in sorted(self.premises):
            grouped.setdefault(item.kind.value, []).append(item.id)
        return grouped


def compose(claim: ClaimType, subject: str, *, own=(), evidence=(), obligations=(), via=()) -> Support:
    """A support whose premises are its own plus every composed support's."""
    via = tuple(via)   # (an iterator would be exhausted before it is kept)
    premises = set(own)
    found_evidence = set(evidence)
    for item in via:
        premises |= item.premises
        found_evidence |= item.evidence
    return Support(claim, subject, frozenset(premises), frozenset(found_evidence), tuple(obligations), tuple(via))


# -- identities ------------------------------------------------------------------------

def registry_premise(name: str) -> PremiseRef:
    """A registry-backed assumption: digest = its registry row + the engine
    semantics version (a redefinition under the same name is another premise)."""
    from .assumptions import REGISTRY
    from .summary_templates import ENGINE_SEMANTICS_VERSION

    rows = [row for row in REGISTRY if row.name == name]
    if len(rows) != 1:
        raise UnknownPremise(name)
    return PremiseRef(PremiseKind.ASSUMPTION, name, _digest([asdict(rows[0]), ENGINE_SEMANTICS_VERSION]))


def declaration_premise(label: str, catalog: dict, file_digests: dict) -> PremiseRef:
    """A model-declared assumption ``<file id>:<id>``: digest = the declaration
    (statement, fails_when) + the owning model file's content digest.
    ``catalog``: ``summary_store.assumption_catalog``; ``file_digests``: file id
    -> that file's digest."""
    if label not in catalog:
        raise UnknownPremise(label)
    file_id, statement, fails_when = catalog[label]
    owner = file_digests.get(file_id)
    if owner is None:
        raise UnknownPremise(f"{label} (owning model file {file_id} not loaded)")
    return PremiseRef(PremiseKind.ASSUMPTION, label, _digest([statement, fails_when, file_id, owner]))


def model_premise(label: str, file_digest: str, entry_content=None) -> PremiseRef:
    """A model row: its label plus the model file's digest (and, when given,
    the entry's own canonical content)."""
    if not label or not file_digest:
        raise UnknownPremise(label or "<empty model label>")
    return PremiseRef(PremiseKind.MODEL, label, _digest([label, file_digest, entry_content]))


def resolve_label(label: str, *, catalog: dict | None = None, file_digests: dict | None = None,
                  model_digests: dict | None = None) -> PremiseRef:
    """The premise a reported label names, or ``UnknownPremise``. ``model_digests``:
    model label -> its file digest (the run's loaded models)."""
    from .assumptions import REGISTRY

    if any(row.name == label for row in REGISTRY):
        return registry_premise(label)
    if model_digests is not None and label in model_digests:
        return model_premise(label, model_digests[label])
    if catalog is not None and label in catalog:
        return declaration_premise(label, catalog, file_digests or {})
    raise UnknownPremise(label)


# -- provenance closure ----------------------------------------------------------------

def provenance_closure(own: dict, depends: dict) -> dict:
    """``own``: node -> frozenset of its own PremiseRefs (uses at its decisions);
    ``depends``: node -> nodes whose claims it consumed (the verified
    dependency graph of the FINAL effects -- no edge for a call left opaque).
    Returns node -> frozenset: within a strongly connected component every
    member gets the union of all members' own premises plus every dependency
    component's (dependencies first, one pass)."""
    nodes = sorted(set(own) | set(depends) | {target for targets in depends.values() for target in targets})
    index: dict = {}
    low: dict = {}
    stack: list = []
    on_stack: set = set()
    components: list = []
    counter = 0
    for root in nodes:
        if root in index:
            continue
        work = [(root, iter(sorted(depends.get(root, ()))))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, children = work[-1]
            advanced = False
            for child in children:
                if child not in index:
                    index[child] = low[child] = counter
                    counter += 1
                    stack.append(child)
                    on_stack.add(child)
                    work.append((child, iter(sorted(depends.get(child, ())))))
                    advanced = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index[child])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index[node]:
                component = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                components.append(tuple(sorted(component)))
    # Tarjan emits components dependencies-first (a component after everything it reaches)
    owner = {member: number for number, component in enumerate(components) for member in component}
    result: dict = {}
    supports: list = []
    for number, component in enumerate(components):
        total = set()
        for member in component:
            total |= own.get(member, frozenset())
            for target in depends.get(member, ()):
                if owner[target] != number:
                    total |= supports[owner[target]]
        supports.append(frozenset(total))
        for member in component:
            result[member] = supports[number]
    return result


__all__ = ["ADMISSIBLE", "ClaimType", "EvidenceRef", "PremiseKind", "PremiseRef", "PremiseUse", "STAGES",
           "Support", "UnknownPremise", "compose", "declaration_premise", "model_premise", "provenance_closure",
           "registry_premise", "resolve_label"]
