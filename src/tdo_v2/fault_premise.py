"""The fault premise (F1, docs 25.94): recognized fault instructions, hazards,
and the run's discharged set.

Two named assumptions, both switches, both off by default:

* ``stock-ghidra-translator`` -- the Bundle's p-code comes from the stock
  translator of its attested Ghidra version, whose user-op table is the one a
  row below was exported from. A Bundle attests the Ghidra version (admission
  compares it, ``configured_naming``) and the language, never the compiled
  translator: recognition rests on this assumption, recorded per use.
* ``faults-end-the-execution`` -- a recognized fault ends the analysed
  execution: no handler of any kind resumes into the program, observes or
  writes its state, calls back into it or lets it escape; it is not inside a
  hardware transaction; the stack at the fault is the one the observed graph
  implies.

A FAULT SITE (both rows of one instruction, nothing else): ``t =
CALLOTHER(c); BRANCHIND t`` -- ``c`` a 4-byte constant, the language's
``invalidInstructionException`` index; ``t`` UNIQUE of the pointer size; no
fallthrough, no flow target. Hazards keep a site from being discharged:
H1 the image's exception directory covers it with a handler (or is
malformed / unverifiable), H2 a transactional instruction in its function,
H3 a function that may call it (observation call graph, plus each round's
resolved targets and candidates) has H2 or a handler-covered call site.

The discharged set D shrinks only (``analyze_units`` rounds); the functions
that may reach a discharged fault (``may_reach_fault``) are fixed before the
first round over a wildcard call graph -- every CALLIND / BRANCHIND and every
call outside the analysed set reaches anything -- so no later round escapes it.
"""

from __future__ import annotations

from dataclasses import dataclass

from ._scope_contracts import VarnodeKindCode
from .call_seeds import _operation_key
from .configured_naming_contracts import CALL_NAMING_GHIDRA_VERSION

FAULT_PREMISE = "faults-end-the-execution"
TRANSLATOR_PREMISE = "stock-ghidra-translator"
LABELS = (FAULT_PREMISE, TRANSLATOR_PREMISE)


@dataclass(frozen=True, slots=True)
class FaultRow:
    index: int          # CALLOTHER user-op index
    name: str
    index_size: int     # the index operand's width
    output_size: int    # the UNIQUE the BRANCHIND reads


# (Ghidra version, language id, major, minor) -> row. Exported with
# ghidra/GhidraV2ListUserOps.java from Ghidra 12.0.4 (x86-64.sla SHA-256
# d5adc314e2278228b380d8f653b2b579fa4a65986bb1d39b095e461fd5432481); widths
# confirmed on every observed site (534 in the Mulp Bundle). x86-32 (index 75)
# and AArch64 rows wait for an observed instance (docs 25.94).
FAULT_ROWS = {
    (CALL_NAMING_GHIDRA_VERSION, "x86:LE:64:default", 4, 6): FaultRow(77, "invalidInstructionException", 4, 8),
}
TRANSACTIONAL = {
    (CALL_NAMING_GHIDRA_VERSION, "x86:LE:64:default", 4, 6): frozenset({84, 85, 86, 99}),  # xabort xbegin xend xtest
}
ROW_EVIDENCE = "ghidra-12.0.4/GhidraV2ListUserOps/x86-64.sla=d5adc314"


def _language(unit) -> tuple:
    namespace = unit.scopes.program.evidence.translation_namespace
    return (CALL_NAMING_GHIDRA_VERSION, namespace.language_id, namespace.major_version, namespace.minor_version)


def _function_key(coordinate) -> str:
    return f"{coordinate.space_id:x}:{coordinate.byte_offset:x}"


@dataclass(frozen=True, slots=True)
class FaultSite:
    key: str        # control:<function>:<space>:<address> (the U2a site key)
    cut: str        # the CALLOTHER operation key (the path ends there)
    branch: str     # the BRANCHIND operation key (the barrier's)
    address: int


def fault_sites(unit) -> tuple[FaultSite, ...]:
    """The function's recognized fault sites (exact shape, the language's row)."""
    row = FAULT_ROWS.get(_language(unit))
    observation = unit.observation
    if row is None or observation is None:
        return ()
    entry = _function_key(unit.scopes.function.entry)
    found = []
    for instruction in observation.instructions:
        operations = instruction.operations
        if len(operations) != 2 or [operation.opcode for operation in operations] != ["CALLOTHER", "BRANCHIND"]:
            continue
        call, branch = operations
        if (len(call.inputs) != 1 or call.inputs[0].kind is not VarnodeKindCode.CONSTANT
                or call.inputs[0].byte_size != row.index_size or call.inputs[0].coordinate.byte_offset != row.index
                or call.output is None or call.output.kind is not VarnodeKindCode.UNIQUE
                or call.output.byte_size != row.output_size
                or len(branch.inputs) != 1 or branch.inputs[0] != call.output
                or instruction.fallthrough is not None or instruction.flow_targets):
            continue
        address = instruction.address
        found.append(FaultSite(f"control:{entry}:{address.space_id:x}:{address.byte_offset:x}",
                               _operation_key(address, 0, "CALLOTHER"), _operation_key(address, 1, "BRANCHIND"),
                               address.byte_offset))
    return tuple(found)


def transactional(unit) -> bool:
    """A transactional instruction (xbegin / xabort / xend / xtest) in the function."""
    indices = TRANSACTIONAL.get(_language(unit), frozenset())
    observation = unit.observation
    return observation is not None and any(
        operation.opcode == "CALLOTHER" and operation.inputs and operation.inputs[0].kind is VarnodeKindCode.CONSTANT
        and operation.inputs[0].coordinate.byte_offset in indices
        for instruction in observation.instructions for operation in instruction.operations)


def observed_calls(unit, keys) -> tuple[dict, bool]:
    """({callee key: (call instruction offsets)} over direct CALL / BRANCH targets
    and listed flow targets inside ``keys``, whether a WILDCARD transfer exists:
    a CALLIND, a BRANCHIND (listed targets or not) or a direct call / tail to a
    function outside ``keys``)."""
    observation = unit.observation
    own = _function_key(unit.scopes.function.entry)   # (its own entry: a recursive call)
    found: dict = {}
    wildcard = False
    if observation is None:
        return found, True
    locals_ = {(row.address.space_id, row.address.byte_offset) for row in observation.instructions}
    for instruction in observation.instructions:
        for operation in instruction.operations:
            if operation.opcode in ("CALLIND", "BRANCHIND"):
                wildcard = True
            elif operation.opcode in ("CALL", "BRANCH") and operation.inputs \
                    and operation.inputs[0].kind is VarnodeKindCode.ADDRESS:
                coordinate = operation.inputs[0].coordinate
                if operation.opcode == "BRANCH" and (coordinate.space_id, coordinate.byte_offset) in locals_:
                    continue   # an ordinary jump inside the function
                key = _function_key(coordinate)
                if key in keys:
                    # (a recursive call too: its call site's handler is an H3 hazard)
                    found.setdefault(key, set()).add(instruction.address.byte_offset)
                else:
                    wildcard = True
        for target in instruction.flow_targets:
            key = _function_key(target)
            if key in keys and ((target.space_id, target.byte_offset) not in locals_ or key == own
                                and any(operation.opcode in ("CALL", "CALLIND")
                                        for operation in instruction.operations)):
                found.setdefault(key, set()).add(instruction.address.byte_offset)
    return {key: tuple(sorted(sites)) for key, sites in found.items()}, wildcard


@dataclass(frozen=True, slots=True)
class FaultPlan:
    """The run's fault decision: what is discharged, why the rest is not."""
    sites: dict          # function key -> tuple[FaultSite]
    discharged: frozenset  # site keys
    hazards: dict        # site key -> tuple of hazard tags
    may_reach_fault: frozenset  # function keys (fixed before round 1)
    evidence: dict       # site key -> tuple of (field, value) rows
    image_digest: str | None

    def cuts_of(self, key: str, discharged=None) -> tuple:
        """((site key, cut key, branch key, evidence rows), ...) of the function's discharged sites."""
        chosen = self.discharged if discharged is None else discharged
        return tuple((site.key, site.cut, site.branch, self.evidence[site.key])
                     for site in self.sites.get(key, ()) if site.key in chosen)


EMPTY_PLAN = FaultPlan({}, frozenset(), {}, frozenset(), {}, None)


def _h1(directory, image_base: int, offset: int) -> str:
    if directory is None:
        return "unverifiable"
    return directory.verdict(offset - image_base)


def _caller_graph(callers: dict) -> tuple[dict, dict]:
    """(calls, transactional) over every observed function -- H3's graph:
    a function a model or binding cut from the analysis still calls."""
    keys = frozenset(callers)
    return ({key: observed_calls(unit, keys)[0] for key, unit in callers.items()},
            {key: transactional(unit) for key, unit in callers.items()})


def plan_faults(units: dict, directory, image_base: int | None, callers: dict | None = None) -> FaultPlan:
    """D0 over the observation call graph and the static ``may_reach_fault``
    (both premises on: the caller checks the switches). ``units``: the
    analysed functions (sites, may-reach); ``callers``: every observed
    function of the program (H3), default ``units``."""
    keys = frozenset(units)
    sites = {key: fault_sites(unit) for key, unit in units.items()}
    sites = {key: rows for key, rows in sites.items() if rows}
    if not sites:
        return EMPTY_PLAN
    calls, wildcard = {}, set()
    for key, unit in units.items():
        calls[key], wild = observed_calls(unit, keys)
        if wild:
            wildcard.add(key)
    every_call, tsx = _caller_graph(callers if callers is not None else units)
    hazards, evidence = {}, {}
    base = 0 if image_base is None else image_base
    for key, rows in sites.items():
        contextual = sorted(contextual_hazards(key, every_call, tsx, directory, base))
        for site in rows:
            own = _h1(directory if image_base is not None else None, base, site.address)
            found = []
            if own not in ("no-handler", "no-entry"):
                found.append(f"H1:{own}")
            if tsx[key]:
                found.append("H2")
            found.extend(f"H3:{item}" for item in contextual)
            hazards[site.key] = tuple(found)
            entry = None if directory is None or image_base is None else directory.entry_range(site.address - base)
            evidence[site.key] = (
                ("row", ROW_EVIDENCE), ("language", "/".join(map(str, _language(units[key])))),
                ("image", None if directory is None else directory.image_digest),
                ("exception_entry", None if entry is None else f"{entry[0]:x}-{entry[1]:x}"),
                ("h1", own), ("h2", "transactional" if tsx[key] else "none"),
                ("h3", ",".join(contextual) or "none"), ("reader", "exception_directory/1"),
            )
    discharged = frozenset(site for site, found in hazards.items() if not found)
    return FaultPlan(sites, discharged, hazards, may_reach(keys, calls, wildcard, sites, discharged),
                     evidence, None if directory is None else directory.image_digest)


def contextual_hazards(key: str, calls: dict, tsx: dict, directory, image_base: int) -> set:
    """H3 of ``key``: every transitive caller (``calls``: caller -> {callee:
    call sites}) with a transactional instruction or a call site whose
    exception entry has a handler (or is not verifiable)."""
    callers: dict = {}
    for caller, callees in calls.items():
        for callee, offsets in callees.items():
            callers.setdefault(callee, []).append((caller, offsets))
    found, seen, pending = set(), {key}, [key]
    while pending:
        node = pending.pop()
        for caller, offsets in callers.get(node, ()):
            if tsx.get(caller):
                found.add(f"{caller}:transactional")
            for offset in offsets:
                verdict = _h1(directory, image_base, offset)
                if verdict not in ("no-handler", "no-entry"):
                    found.add(f"{caller}:{offset:x}:{verdict}")
            if caller not in seen:
                seen.add(caller)
                pending.append(caller)
    return found


def may_reach(keys, calls: dict, wildcard: set, sites: dict, discharged: frozenset) -> frozenset:
    """Functions from which a function owning a discharged site may be reached:
    the owners, every wildcard holder (when anything is discharged), and every
    function reaching one of those over direct edges."""
    if not discharged:
        return frozenset()
    targets = {key for key, rows in sites.items() if any(site.key in discharged for site in rows)} | set(wildcard)
    callers: dict = {}
    for caller, callees in calls.items():
        for callee in callees:
            callers.setdefault(callee, set()).add(caller)
    found, pending = set(targets), list(targets)
    while pending:
        node = pending.pop()
        for caller in callers.get(node, ()):
            if caller not in found:
                found.add(caller)
                pending.append(caller)
    return frozenset(found & set(keys))


def revoke(plan: FaultPlan, units: dict, discharged: frozenset, extra_edges: dict, directory,
           image_base: int | None, callers: dict | None = None) -> tuple[frozenset, dict]:
    """(``discharged`` minus every site that has an H3 hazard on the observation
    graph plus ``extra_edges`` (caller key -> {callee key: call sites}: a round's
    resolved targets and multi-target candidates), {revoked site: H3 tags})."""
    if not discharged:
        return discharged, {}
    calls, tsx = _caller_graph(callers if callers is not None else units)
    for key, rows in extra_edges.items():
        for callee, offsets in rows.items():
            calls.setdefault(key, {})[callee] = tuple(sorted(set(calls.get(key, {}).get(callee, ())) | set(offsets)))
    base = 0 if image_base is None else image_base
    kept, reasons = set(), {}
    for key, rows in plan.sites.items():
        active = [site for site in rows if site.key in discharged]
        if not active:
            continue
        found = contextual_hazards(key, calls, tsx, directory, base)
        if found:
            reasons.update((site.key, tuple(f"H3:{item}" for item in sorted(found))) for site in active)
        else:
            kept.update(site.key for site in active)
    return frozenset(kept), reasons


def decisions(plan: FaultPlan, key: str, discharged: frozenset, revoked: dict) -> tuple:
    """(site key, status, detail) of the function's recognized sites:
    "discharged", "hazard" (never discharged) or "revoked" (a later round's H3)."""
    found = []
    for site in plan.sites.get(key, ()):
        if site.key in discharged:
            found.append((site.key, "discharged", ""))
        elif site.key in revoked:
            found.append((site.key, "revoked", ",".join(revoked[site.key])))
        else:
            found.append((site.key, "hazard", ",".join(plan.hazards.get(site.key, ()))))
    return tuple(found)


__all__ = ("EMPTY_PLAN", "FAULT_PREMISE", "FAULT_ROWS", "FaultPlan", "FaultSite", "LABELS", "TRANSLATOR_PREMISE",
           "decisions", "fault_sites", "may_reach", "observed_calls", "plan_faults", "revoke", "transactional")
