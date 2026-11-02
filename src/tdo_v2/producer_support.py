"""Producer supports and their closure (Stage 2b-P P-c2, docs 25.91; design
``.census6/design_premise_2bp_r5.md`` B, Astra r5 approved).

A published result rests on the premises of the analysis instances it
consumed, not on "the latest result of that function": every instance that
produced something a published result consumed (an ordinary summary, each
member of a multi-target composition, an activation context and the caller
analysis its entry state was read from, the callee results an accepted
lifecycle refinement read, a superseded round-1 result still consumed) gets a
``ProducerSupport``; ``producer_supports`` closes them over the exact
consumption edges (``AnalyzedFunction.consumed``) with the dependency-first
SCC union (``premises.provenance_closure``).

Two premise sets are kept apart (design r5 D1): ``uses`` -- only recorded
decisions and producer dependencies (what acceptance checks for completeness)
-- and the published set, which also carries the policy switches in force and
the inherited / declared label bridges until their removal is reviewed. The
forward-derived stages (refinement, activation, resolution) record the labels
of forward facts, whose ``requires`` carry the run's whole assumption union
(``forward._analyze_active``): a use there whose label is in that union is a
bridge, not an unpadded use, until forward facts record their own decisions
(acceptance then reports it missing -- never a masked use). A
label no loaded input names, or a consumed producer that is no analysis
instance (an undischarged recursion hypothesis), is an obligation of every
closure reaching it: not established, never dropped. Counted outside
``step()``: the solver's work units do not change.
"""

from __future__ import annotations

from dataclasses import dataclass

from .premises import POLICY_FIELDS, PremiseUse, UnknownPremise, provenance_closure


@dataclass(frozen=True, slots=True)
class ProducerSupport:
    instance: str                  # "<function key>#<n>" (n: 0 for the published result)
    uses: frozenset                # PremiseUse of its own recorded decisions (at: "<instance>/<where>")
    bridges: frozenset             # PremiseRef: policy switches in force, inherited / declared labels
    unknown: tuple[str, ...]       # labels no loaded input names
    depends: tuple[str, ...]       # the producer instances it consumed
    missing: tuple[str, ...]       # consumed producers that are no analysis instance (fail closed)
    # the unknown labels kept where they were used: (label, stage, where) of an
    # unresolved recorded use, and the unresolved bridge labels
    unresolved_uses: tuple = ()
    unresolved_bridges: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ProducerClosure:
    uses: frozenset                # transitive recorded uses only (no policy padding, no bridge)
    published: frozenset           # PremiseRef: uses' premises + every bridge reached
    obligations: tuple[str, ...]   # unknown labels and missing producers reached

    @property
    def premises(self) -> frozenset:
        return frozenset(use.premise for use in self.uses)

    @property
    def established(self) -> bool:
        return not self.obligations


def _policy_labels(normalized) -> list[str]:
    """The normalization's policy switches in force (registry names): the
    padding a published support keeps until P-c5 shows recording complete."""
    import dataclasses

    if not dataclasses.is_dataclass(normalized):
        return []
    return [POLICY_FIELDS.get(field.name, field.name) for field in dataclasses.fields(normalized)
            if field.name.startswith(("assumes_", "assumed_")) and field.name != "assumed_call_effects"
            and getattr(normalized, field.name)]


# (switch in force, the label the run synthesizes with it)
_SYNTHESIZED = (("globals-disjoint-from-stack", "stack-switch-check-exceptions"),
                ("entry-values-do-not-address-the-new-frame", "win64-home-space-callee-private"))

# stages whose recorded labels come from forward facts (their requires carry
# the run union): only a label outside that union is an unpadded use there
_FORWARD_STAGES = frozenset({"refinement", "activation", "resolution"})


def _run_union(items, run_bridge) -> frozenset:
    """Every label the run's union can carry (``summary_engine.run_assumptions``
    over all instances, plus what the caller passes as ``run_bridge`` -- the
    run's ``EngineRun.assumptions``): policy switches in force (and the labels
    the run synthesizes with them), inherited / declared labels, summary cuts."""
    found = set(run_bridge)
    for item in items:
        policies = _policy_labels(item.normalized)
        found.update(policies)
        if "globals-disjoint-from-stack" in policies:
            found.add("stack-switch-check-exceptions")
        if "entry-values-do-not-address-the-new-frame" in policies and (
                not run_bridge or "win64-home-space-callee-private" in run_bridge):
            found.add("win64-home-space-callee-private")
        found.update(item.inherited_assumptions)
        found.update(item.declared.values())
        if item.summary_inputs and len(item.summary_inputs) == 3:
            found.update(item.summary_inputs[2])
    return frozenset(found)


def _instances(results: dict, tick=None) -> tuple[dict, dict]:
    """Every instance reachable from the published results through exact
    consumption (and an activation context's caller analysis): name -> item,
    id -> name. Published results are "<key>#0"; others numbered per key in
    discovery order (sorted, deterministic)."""
    from .interprocedural import AnalyzedFunction

    names: dict = {}
    items: dict = {}
    counters: dict = {}
    pending = []

    def name_of(item):
        token = id(item)
        if token not in names:
            number = counters.get(item.key, 0)
            counters[item.key] = number + 1
            names[token] = f"{item.key}#{number}"
            items[names[token]] = item
            pending.append(item)
        return names[token]

    for key in sorted(results):
        name_of(results[key])
    while pending:
        if tick is not None:
            tick()
        item = pending.pop(0)
        for _call, rows in sorted(item.consumed.items()):
            for found in rows:
                if type(found) is AnalyzedFunction:
                    name_of(found)
        witness = item.activation_witness
        if witness and type(witness[0]) is AnalyzedFunction:
            name_of(witness[0])
    return items, names


def _support(name, item, names, resolver, union) -> ProducerSupport:
    from .interprocedural import AnalyzedFunction

    normalized = item.normalized
    unknown: set = set()
    uses: set = set()
    unresolved_uses: set = set()
    bridged: list = []
    for row in (*getattr(normalized, "premise_uses", ()), *getattr(item.summary, "premise_uses", ())):
        label, stage, at = row
        if stage in _FORWARD_STAGES and label in union:
            bridged.append(label)
            continue
        try:
            uses.add(PremiseUse(resolver.resolve(label), stage, f"{name}/{at}"))
        except UnknownPremise:
            unknown.add(label)
            unresolved_uses.add((label, stage, at))
    bridges: set = set()
    unresolved_bridges: set = set()
    labels = [*_policy_labels(normalized), *item.inherited_assumptions, *item.declared.values(), *bridged]
    # the labels the run synthesizes with a switch in force here
    # (``summary_engine.run_assumptions``): published with it, never a use
    labels.extend(label for trigger, label in _SYNTHESIZED if trigger in labels and label in union)
    for label in labels:
        try:
            bridges.add(resolver.resolve(label))
        except UnknownPremise:
            unknown.add(label)
            unresolved_bridges.add(label)
    depends: list = []
    missing: list = []
    for call, rows in sorted(item.consumed.items()):
        for found in rows:
            if type(found) is AnalyzedFunction:
                depends.append(names[id(found)])
            else:
                missing.append(f"unestablished-producer:{call}:{getattr(found, 'callee', type(found).__name__)}")
    witness = item.activation_witness
    if witness:
        if type(witness[0]) is AnalyzedFunction:
            depends.append(names[id(witness[0])])
        else:
            missing.append("unestablished-producer:activation-caller")
    return ProducerSupport(name, frozenset(uses), frozenset(bridges), tuple(sorted(unknown)),
                           tuple(dict.fromkeys(depends)), tuple(sorted(set(missing))),
                           tuple(sorted(unresolved_uses)), tuple(sorted(unresolved_bridges)))


@dataclass(frozen=True, slots=True)
class ProducerClosures:
    supports: dict      # instance name -> ProducerSupport
    instances: dict     # instance name -> ProducerClosure
    names: dict         # id(AnalyzedFunction) -> instance name (the exact consumed objects)

    def of(self, item) -> ProducerClosure | None:
        """The closure of an exact analysis instance (None: not reached)."""
        name = self.names.get(id(item))
        return None if name is None else self.instances[name]


def producer_closures(results: dict, resolver, run_bridge=(), tick=None) -> ProducerClosures:
    """Every reachable instance's support and closure (``producer_supports``
    keeps only the published keys'). ``tick``: a deadline check per step
    (the summary engine's reporting phase; charges no analysis work)."""
    items, names = _instances(results, tick)
    union = _run_union(items.values(), run_bridge)
    supports = {}
    for name, item in items.items():
        if tick is not None:
            tick()
        supports[name] = _support(name, item, names, resolver, union)
    depends = {name: support.depends for name, support in supports.items()}
    uses = provenance_closure({name: support.uses for name, support in supports.items()}, depends, tick)
    published = provenance_closure({name: frozenset(use.premise for use in support.uses) | support.bridges
                                    for name, support in supports.items()}, depends, tick)
    obligations = provenance_closure({name: frozenset(support.unknown) | frozenset(
        f"{name}:{row}" for row in support.missing) for name, support in supports.items()}, depends, tick)
    instances = {name: ProducerClosure(uses[name], published[name], tuple(sorted(obligations[name])))
                 for name in supports}
    return ProducerClosures(supports, instances, names)


@dataclass(frozen=True, slots=True)
class FunctionPremises:
    """The report row of one published function (P-c4): its producer
    closure's premise ids grouped by kind -- ``published`` (with policy
    padding and bridges, what the run rests on today) and ``unpadded``
    (recorded uses and producer dependencies only) -- and what keeps it from
    being established (unknown labels, missing producers)."""

    function: str
    published: tuple       # ((kind, (ids, ...)), ...)
    unpadded: tuple
    obligations: tuple[str, ...]

    @property
    def established(self) -> bool:
        return not self.obligations


def _grouped(premises, tick=None) -> tuple:
    found: dict = {}
    for item in sorted(premises):
        if tick is not None:
            tick()
        found.setdefault(item.kind.value, []).append(item.id)
    return tuple((kind, tuple(ids)) for kind, ids in sorted(found.items()))


def function_premises(results: dict, resolver, run_bridge=(), tick=None) -> tuple[FunctionPremises, ...]:
    """One ``FunctionPremises`` per published function (sorted by key)."""
    found = producer_closures(results, resolver, run_bridge, tick)
    rows = []
    for key, item in sorted(results.items()):
        if tick is not None:
            tick()
        closure = found.of(item)
        rows.append(FunctionPremises(key, _grouped(closure.published, tick), _grouped(closure.premises, tick),
                                     closure.obligations))
    return tuple(rows)


def producer_supports(results: dict, resolver, run_bridge=()) -> tuple[dict, dict]:
    """``results``: the published ``analyze_units`` results (key ->
    AnalyzedFunction); ``resolver``: the run's ``PremiseResolver``;
    ``run_bridge``: the run's assumption union (``EngineRun.assumptions``),
    added to what the instances themselves show. Returns (instance name ->
    ProducerSupport, published key -> ProducerClosure)."""
    found = producer_closures(results, resolver, run_bridge)
    return found.supports, {key: found.of(item) for key, item in results.items()}


__all__ = ["FunctionPremises", "ProducerClosure", "ProducerClosures", "ProducerSupport", "function_premises",
           "producer_closures", "producer_supports"]
