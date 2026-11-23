"""P-code-level basic blocks for instructions with internal control flow.

Most instructions are one straight block, keyed by the instruction address.
An instruction with internal p-code control flow -- a relative branch
(``CBRANCH +2``), a branch to its own address (Ghidra's ``rep`` loop shape:
``CBRANCH <next instruction>`` ... ``BRANCH <self>``), or any branch that is
not its last operation -- is split into sub-blocks at every branch target and
after every branch. The first sub-block keeps the instruction key (so other
instructions' edges are unchanged); later sub-blocks are keyed
``<instruction key>#<first operation ordinal>``.

Successors come from the p-code itself (Ghidra's flow targets do not list an
instruction's own address), from ``fallthrough``, and from the instruction's
observed successors when its last operation ends it. Blocks unreachable from
the function entry (operations after an unconditional branch) execute never
and are dropped. Unsupported shapes are reported, not guessed: a relative
branch outside its instruction, an indirect branch or a return that is not
last; and,
where the observed flow and the p-code could disagree (none occurs in the
corpus, ``.census6/graph_census.py``): a call with local flow targets
(exception landing pads) unless it is one straight block ending in its only
call operation (operations after it would seem to run before the exceptional
edge); a split instruction that is a call with such targets or carries a flow
override; a split instruction whose observed successors its reachable
sub-blocks do not all reach, or whose flow targets are not all destinations of
its reachable branches.

(G-T G1, docs 25.101) A conditional jump leaving the function gets an
**outcome edge block** for its taken outcome when the shape is one the graph
can state completely (``escaping_branch``): the jump is the last operation of
an instruction without internal flow, its target an absolute address outside
the function, its fallthrough local, the row carries no S1 continuation
evidence (``fallthrough_exits``), and the observed flow agrees with the p-code
(the target listed, nothing else but the fallthrough). The edge block
``<instruction key>>{ordinal}t`` has no operations (``start == stop ==
ordinal + 1``), no successors, ``exits``, and ``edge`` naming its origin; the
jump's block then has the fallthrough and the edge block as successors and no
longer ``exits`` itself. Any other branch of a straight row whose absolute
target leaves the function forces ``exits`` from the p-code fact -- an
unknown exit at that site, never a silently missing transfer
(``unmaterialized`` lists the conditional ones with the failed condition).
Read a block's terminator through ``terminator`` and an edge's direction
through ``outcome_of``: an edge block has no operations.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from ._scope_contracts import AddressCoordinate, ValidatedFunctionObservation, VarnodeKindCode
from .control_projection import (call_explained_targets, call_explains, call_like_instruction,
                                 control_successor_coordinates)

_BRANCHES = ("BRANCH", "CBRANCH", "BRANCHIND")
_CALLS = ("CALL", "CALLIND")


@dataclass(frozen=True, slots=True)
class EdgeOrigin:
    """Where an outcome edge block comes from: the block ending in the jump,
    the jump's operation ordinal in its instruction, the outcome ("taken"),
    and the jump's target."""
    source: str
    ordinal: int
    outcome: str
    target: AddressCoordinate


@dataclass(frozen=True, slots=True)
class PcodeBlock:
    key: str
    instruction: AddressCoordinate
    start: int
    stop: int
    successors: tuple[str, ...]
    # A placed departure at block end. control_exits().may_leave separately
    # records listed departures of unknown position, before the row's actions.
    exits: bool = False
    edge: EdgeOrigin | None = None   # an outcome edge block (no operations)


@dataclass(frozen=True, slots=True)
class PcodeBlockGraph:
    entry: str
    blocks: tuple[PcodeBlock, ...]          # reachable blocks in address/ordinal order
    unsupported: str | None = None
    # (G1) conditional jumps leaving the function without an edge block:
    # (instruction address, operation ordinal, failed condition), sorted
    unmaterialized: tuple = ()

    def block_of(self, address: AddressCoordinate, ordinal: int) -> PcodeBlock | None:
        for block in self.blocks:
            if block.instruction == address and block.start <= ordinal < block.stop:
                return block
        return None


def instruction_key(address: AddressCoordinate) -> str:
    return f"{address.space_id:x}:{address.byte_offset:x}"


_CALL_LIKE = ("CALL", "CALLIND", "CALLOTHER")


def storage_overlaps(varnode, other) -> bool:
    """Whether two varnodes share a byte of the storage the memory SSA uses:
    every REGISTER-kind space is one register file and every UNIQUE-kind space
    one function temporary object, so those compare by bytes whatever their
    space ids; other kinds also need the same space (review fixes, Astra
    rounds 1-3: a write through another space id of the same storage is a write)."""
    if varnode is None or other is None or varnode.kind is not other.kind:
        return False
    if varnode.kind not in (VarnodeKindCode.UNIQUE, VarnodeKindCode.REGISTER) \
            and varnode.coordinate.space_id != other.coordinate.space_id:
        return False
    return (varnode.coordinate.byte_offset < other.coordinate.byte_offset + other.byte_size
            and other.coordinate.byte_offset < varnode.coordinate.byte_offset + varnode.byte_size)


def final_target_index(instruction, ordinal):
    """Index of the operation that supplies ``instruction.operations[ordinal]``'s
    target (input 0) in its own instruction: the last earlier operation whose
    output overlaps it by SSA storage (``storage_overlaps``). None -- no
    instruction-local producer -- when the instruction has internal flow (the
    write may be skipped), the target is not a REGISTER/UNIQUE varnode (memory
    can be written by a STORE with no output varnode), a CALL/CALLIND/CALLOTHER
    comes first, or nothing writes it (review fixes, Astra rounds 2-3)."""
    operations = instruction.operations
    target = operations[ordinal].inputs[0]
    if target.kind not in (VarnodeKindCode.UNIQUE, VarnodeKindCode.REGISTER) or has_internal_flow(instruction):
        return None
    for index in range(ordinal - 1, -1, -1):
        item = operations[index]
        if item.opcode in _CALL_LIKE:
            return None
        if storage_overlaps(item.output, target):
            return index
    return None


def has_internal_flow(instruction) -> bool:
    operations = instruction.operations
    for ordinal, operation in enumerate(operations):
        if operation.opcode not in _BRANCHES or not operation.inputs:
            continue
        if ordinal < len(operations) - 1:
            return True
        destination = operation.inputs[0]
        if operation.opcode != "BRANCHIND" and (
            destination.kind is VarnodeKindCode.CONSTANT
            or destination.coordinate == instruction.address
        ):
            return True
    return False


def edge_key(source_instruction_key: str, ordinal: int, outcome: str = "taken") -> str:
    """Key of an outcome edge block: ``>`` never occurs in a segment key."""
    return f"{source_instruction_key}>{ordinal}{outcome[0]}"


def terminator(block: PcodeBlock, row):
    """(ordinal, operation) ending a real block; None for an edge block or a
    block without operations. The one way to read a block's terminator."""
    if block.edge is not None or block.stop <= block.start:
        return None
    return block.stop - 1, row.operations[block.stop - 1]


def edge_origin(block: PcodeBlock) -> EdgeOrigin | None:
    return block.edge


def edge_site(block: PcodeBlock) -> str | None:
    """(G-T G3a) The conditional-tail site key ``space:offset:k:CBRANCH`` of
    an outcome edge block (the CBRANCH whose taken outcome it is); None for a
    real block."""
    if block.edge is None:
        return None
    return f"{block.instruction.space_id:x}:{block.instruction.byte_offset:x}:{block.edge.ordinal}:CBRANCH"


def conditional_tail_edges(graph: PcodeBlockGraph) -> dict:
    """(G-T G3a) Conditional-tail site key -> its edge block key, for every
    reachable outcome edge block of the graph (the graph keeps reachable
    blocks only); empty for an unsupported graph."""
    if graph.unsupported is not None:
        return {}
    return {edge_site(block): block.key for block in graph.blocks if block.edge is not None}


@dataclass(frozen=True, slots=True)
class TailTransfer:
    """(G-T G3b-1, docs 25.104) A jump that leaves the function by code facts.
    ``kind``: "branch" / "cbranch" / "branchind"; ``target``: the ADDRESS
    destination (None for "branchind": the slot decides); ``edge``: the
    outcome edge block key of a "cbranch" (else None). Each consumer adds its
    own target condition (a Bundle entry, an import thunk, a noreturn model, a
    slot symbol)."""

    kind: str
    target: AddressCoordinate | None
    edge: str | None = None


_TAIL_CACHE: dict = {}   # (id(observation), entry) -> (observation, mapping); identity-checked
_TAIL_CACHE_LIMIT = 4096


def tail_transfers(observation, entry):
    """(G-T G3b-1, design r11 1.1 / r12-r15) Operation key -> ``TailTransfer``
    for every jump that leaves the function, from the plain p-code block graph
    (``straight`` empty -- its edge blocks are a superset of the
    normalization's, whose ``straight`` rows are never edge-eligible):

    * "branch": a BRANCH ending a reachable block that exits, its destination
      an ADDRESS that is no instruction of the function, its instruction
      without fallthrough, S1 continuation evidence or flow override, and no
      observed flow target but that destination;
    * "cbranch": the CBRANCH of every reachable outcome edge block (G1
      eligibility);
    * "branchind": a BRANCHIND ending a reachable block that exits, its
      instruction without fallthrough, S1 evidence or flow override, and no
      observed flow target that is an instruction of the function (read from
      the row so that the fact requires independent evidence, design r14 B). An unrecovered jump table is one too -- a consumer binds only a
      slot symbol.

    An unsupported graph gives none. Cached per observation identity (only for
    validated observations; a test double may be mutated in place)."""
    from types import MappingProxyType

    cacheable = type(observation) is ValidatedFunctionObservation
    key = (id(observation), entry)
    if cacheable:
        hit = _TAIL_CACHE.get(key)
        if hit is not None and hit[0] is observation:
            return hit[1]
    graph = build_pcode_block_graph(observation, entry)
    found: dict = {}
    if graph.unsupported is None:
        rows = {row.address: row for row in observation.instructions}
        exit_rows = {item.source for item in getattr(observation, "fallthrough_exits", ())}
        for block in graph.blocks:
            if block.edge is not None:
                found[edge_site(block)] = TailTransfer("cbranch", block.edge.target, block.key)
                continue
            if not block.exits:
                continue
            row = rows[block.instruction]
            end = terminator(block, row)
            if end is None or not end[1].inputs or end[1].opcode not in ("BRANCH", "BRANCHIND"):
                continue
            if row.fallthrough is not None or row.address in exit_rows or row.flow.is_override:
                continue
            ordinal, operation = end
            operation_key = f"{row.address.space_id:x}:{row.address.byte_offset:x}:{ordinal}:{operation.opcode}"
            if operation.opcode == "BRANCH":
                target = operation.inputs[0]
                if target.kind is not VarnodeKindCode.ADDRESS or target.coordinate in rows \
                        or any(item != target.coordinate for item in row.flow_targets):
                    continue
                found[operation_key] = TailTransfer("branch", target.coordinate)
            elif not any(item in rows for item in row.flow_targets):
                found[operation_key] = TailTransfer("branchind", None)
    result = MappingProxyType(found)
    if cacheable:
        if len(_TAIL_CACHE) >= _TAIL_CACHE_LIMIT:
            _TAIL_CACHE.clear()
        _TAIL_CACHE[key] = (observation, result)
    return result


@dataclass(frozen=True, slots=True)
class ControlExits:
    """(G-T G3b-3, docs 25.108; design r18) Where control may leave a
    function other than at a RETURN, by code facts on the plain block graph.

    ``may_leave``: row instruction key -> (its first block's key, the
    operation keys of its reachable operations) for every row listing a
    non-local flow target that no reachable operation of the row transfers
    to (a leaving BRANCH / CBRANCH or a CALL with that ADDRESS destination;
    a reachable BRANCHIND / CALLIND / CALLOTHER may transfer anywhere). The
    departure point inside such a row is unknown. ``non_return_exits``:
    reachable edge blocks and reachable real blocks that exit whose
    terminator is not a RETURN."""

    may_leave: Mapping
    non_return_exits: frozenset


_EXITS_CACHE: dict = {}   # (id(observation), entry) -> (observation, ControlExits | None); identity-checked


def control_exits(observation, entry) -> ControlExits | None:
    """``ControlExits`` of the plain graph (``straight`` empty, as the
    physical-memory ``ConditionIndex`` builds it); None for an unsupported
    graph. Cached per observation like ``tail_transfers``."""
    cacheable = type(observation) is ValidatedFunctionObservation
    key = (id(observation), entry)
    if cacheable:
        hit = _EXITS_CACHE.get(key)
        if hit is not None and hit[0] is observation:
            return hit[1]
    graph = build_pcode_block_graph(observation, entry)
    result = None
    if graph.unsupported is None:
        rows = {row.address: row for row in observation.instructions}
        local = set(rows)
        by_row: dict = {}
        exits = set()
        for block in graph.blocks:
            if block.edge is not None:
                exits.add(block.key)
                continue
            by_row.setdefault(block.instruction, []).append(block)
            row = rows[block.instruction]
            end = terminator(block, row)
            if block.exits and (end is None or end[1].opcode != "RETURN"):
                exits.add(block.key)
        may_leave = {}
        for address, blocks in by_row.items():
            row = rows[address]
            listed = {target for target in row.flow_targets if target not in local}
            if not listed:
                continue
            explained, everything, keys = set(), False, []
            for block in blocks:
                for ordinal in range(block.start, block.stop):
                    operation = row.operations[ordinal]
                    keys.append(f"{address.space_id:x}:{address.byte_offset:x}:{ordinal}:{operation.opcode}")
                    if operation.opcode in ("CALL", "CALLIND"):
                        # (G3b-7 r2-r4, R7-3) the successor function's predicate
                        explained.update(target for target in listed if call_explains(row, ordinal, target, entry))
                    elif operation.opcode in ("BRANCHIND", "CALLOTHER"):
                        everything = True
                    elif operation.inputs and operation.inputs[0].kind is VarnodeKindCode.ADDRESS \
                            and _leaving(operation, local):
                        explained.add(operation.inputs[0].coordinate)
            # the row's first reached block (its ordinal-0 segment: every other
            # segment is entered through it; the lowest start fails closed)
            first = min(blocks, key=lambda block: (block.start, block.key))
            if not everything and listed - explained:
                may_leave[instruction_key(address)] = (first.key, tuple(keys))
        result = ControlExits(MappingProxyType(may_leave), frozenset(exits))
    if cacheable:
        if len(_EXITS_CACHE) >= _TAIL_CACHE_LIMIT:
            _EXITS_CACHE.clear()
        _EXITS_CACHE[key] = (observation, result)
    return result


EDGE_COMPOSED, EDGE_ESCAPE, EDGE_DEAD = "composed", "escape", "dead"


def edge_exit_kind(block: PcodeBlock, *, reached: bool, effect) -> str:
    """(G-T G3a, design r8 B) What an outcome edge block is for a summary:
    DEAD when no path reaches it (behind a cut) or its site's effect never
    returns; COMPOSED when the site's effect composes the tail (a non-empty
    ``tail_stack``); else ESCAPE -- no effect, a sink-only or refused one: an
    unknown continuation (a tail exit). ``effect``: the site's proven call
    effect or None."""
    if block.edge is None:
        raise ValueError("not an edge block")
    if not reached or (effect is not None and getattr(effect, "noreturn", False)):
        return EDGE_DEAD
    if effect is not None and effect.tail_stack:
        return EDGE_COMPOSED
    return EDGE_ESCAPE


def outcome_of(graph: PcodeBlockGraph, source: str, successor: str, rows) -> str | None:
    """Direction of the edge ``source -> successor`` when ``source`` ends in a
    CBRANCH with an absolute target: "taken" or "fallthrough", from the graph's
    edge identity (an edge block's origin; else the jump's local target / the
    instruction's fallthrough); None when it cannot be told (both directions
    reach the same block, a relative jump, or no CBRANCH ends ``source``).
    ``rows``: address -> instruction."""
    blocks = {block.key: block for block in graph.blocks}
    block, target = blocks.get(source), blocks.get(successor)
    if block is None or target is None:
        return None
    if target.edge is not None:
        return target.edge.outcome if target.edge.source == source else None
    row = rows.get(block.instruction)
    end = terminator(block, row) if row is not None else None
    if end is None or end[1].opcode != "CBRANCH" or not end[1].inputs:
        return None
    destination = end[1].inputs[0]
    if destination.kind is not VarnodeKindCode.ADDRESS:
        return None
    taken = target.instruction == destination.coordinate and target.start == 0
    if block.stop < len(row.operations):   # a split instruction: the next segment falls through
        falls = target.instruction == block.instruction and target.start == block.stop
    else:
        falls = target.instruction == row.fallthrough and target.start == 0
    if taken == falls:
        return None
    return "taken" if taken else "fallthrough"


def _leaving(operation, local) -> bool:
    """A BRANCH / CBRANCH whose destination is no local instruction: an
    ADDRESS outside the function, or any other non-CONSTANT destination (read
    as absolute, as ``_split`` reads it; p-code gives a direct branch a CONSTANT
    or an ADDRESS destination, and nothing in validation pins that, so any
    other kind fails safe to leaving). A CONSTANT destination is relative,
    inside the instruction. (``_split`` decides a non-CONSTANT destination by
    its coordinate alone; the two disagree only for a varnode whose kind
    contradicts its space -- not producible by p-code.)"""
    if operation.opcode not in ("BRANCH", "CBRANCH") or not operation.inputs:
        return False
    destination = operation.inputs[0]
    if destination.kind is VarnodeKindCode.CONSTANT:
        return False
    return destination.kind is not VarnodeKindCode.ADDRESS or destination.coordinate not in local


def escaping_branches(row, local, fallthrough_exit_rows) -> tuple:
    """Every CBRANCH of the row whose destination leaves the function
    (``_leaving``), as (ordinal, target, failed condition or None); the
    condition is None only for the one shape that gets a taken-outcome edge
    block: an ADDRESS destination, the last operation of an instruction
    without internal flow and without a flow override, a local fallthrough, no
    S1 continuation evidence, and observed flow listing the target and nothing
    but the fallthrough besides."""
    operations = row.operations
    found = []
    for ordinal, operation in enumerate(operations):
        if operation.opcode != "CBRANCH" or not _leaving(operation, local):
            continue
        target = operation.inputs[0].coordinate
        listed = set(row.flow_targets)
        if operation.inputs[0].kind is not VarnodeKindCode.ADDRESS:
            reason = "destination not an address"
        elif ordinal != len(operations) - 1:
            reason = "not the last operation"
        elif has_internal_flow(row):
            reason = "internal flow"
        elif row.flow.is_override:
            reason = "flow override"
        elif row.fallthrough is None or row.fallthrough not in local:
            reason = "fallthrough not local"
        elif row.address in fallthrough_exit_rows:
            reason = "S1 continuation evidence"
        elif target not in listed or not listed <= {target, row.fallthrough}:
            reason = "observed flow disagrees"
        else:
            reason = None
        found.append((ordinal, target, reason))
    return tuple(found)


def escaping_branch(row, local, fallthrough_exit_rows):
    """The row's last-operation entry of ``escaping_branches`` (None when its
    last operation is no CBRANCH leaving the function)."""
    last = len(row.operations) - 1
    return next((item for item in escaping_branches(row, local, fallthrough_exit_rows) if item[0] == last), None)


def _leaves_by_pcode(row, local) -> bool:
    """A branch of the row whose destination is no local instruction (``_leaving``)."""
    return any(_leaving(operation, local) for operation in row.operations)


def build_pcode_block_graph(
    observation: ValidatedFunctionObservation, entry: AddressCoordinate,
    straight: frozenset = frozenset(),
) -> PcodeBlockGraph:
    """``straight``: instruction addresses whose internal flow is modelled as
    one block (recognized ``rep`` string instructions, ``rep_strings``)."""
    instructions = {row.address: row for row in observation.instructions}
    local = set(instructions)
    exit_rows = frozenset(item.source for item in getattr(observation, "fallthrough_exits", ()))
    blocks: dict[str, PcodeBlock] = {}
    unmaterialized = []
    for address in sorted(instructions):
        row = instructions[address]
        key = instruction_key(address)
        if any(item.opcode == "RETURN" for item in row.operations[:-1]):
            return PcodeBlockGraph(instruction_key(entry), (), "a return that is not last")
        escaping = escaping_branches(row, local, exit_rows)
        if not has_internal_flow(row) or address in straight:
            raw = control_successor_coordinates(row, local_addresses=local, function_entry=entry)
            operations = row.operations
            eligible = next((item for item in escaping if item[2] is None), None) \
                if address not in straight else None
            bad_pads = bool(_landing_pads(row, local, entry, raw)) and not _sole_terminal_call(operations)
            if bad_pads:
                # An exception can leave at the call before a following operation
                # executes. Refuse the row before constructing any outcome edge.
                return PcodeBlockGraph(instruction_key(entry), (), "a call with landing pads that does not end in its call")
            if any(target not in local for target in raw) and any(
                    op.opcode == "CALLOTHER" for op in operations[:-1]):
                return PcodeBlockGraph(instruction_key(entry), (), "an opaque operation may leave before the row ends")
            if row.flow_targets and any(op.opcode in _CALLS for op in operations[:-1]) \
                    and set(raw).intersection(row.flow_targets) - local:
                return PcodeBlockGraph(instruction_key(entry), (), "a call may leave before the row ends")
            if eligible is not None:
                # (G1) the taken outcome's edge block; the fallthrough is the
                # only local successor (checked against the observed flow, so a
                # call flag's "landing pad" here is the fallthrough itself)
                ordinal, target, _ = eligible
                edge = edge_key(key, ordinal)
                blocks[edge] = PcodeBlock(edge, address, ordinal + 1, ordinal + 1, (), True,
                                          EdgeOrigin(key, ordinal, "taken", target))
                blocks[key] = PcodeBlock(
                    key, address, 0, len(row.operations), tuple(sorted({instruction_key(row.fallthrough), edge})), False,
                )
                continue
            successors = tuple(instruction_key(target) for target in raw if target in local)
            unmaterialized.extend((address, ordinal, "straight internal flow" if address in straight else reason)
                                  for ordinal, _, reason in escaping)
            # (G1) a branch whose absolute target leaves the function is an
            # exit even when the observed targets omit it.
            blocks[key] = PcodeBlock(
                key, address, 0, len(row.operations), tuple(sorted(set(successors))),
                exits=not successors or len(successors) != len(raw) or _leaves_by_pcode(row, local),
            )
            continue
        split = _split(row, local, entry)
        if isinstance(split, str):
            return PcodeBlockGraph(instruction_key(entry), (), split)
        for block in split:
            blocks[block.key] = block
        unmaterialized.extend((address, ordinal, reason) for ordinal, _, reason in escaping)
    entry_key = instruction_key(entry)
    reachable, pending = set(), [entry_key]
    while pending:
        key = pending.pop()
        if key in reachable or key not in blocks:
            continue
        reachable.add(key)
        pending.extend(blocks[key].successors)
    ordered = tuple(
        blocks[key] for key in sorted(reachable, key=lambda k: (blocks[k].instruction, blocks[k].start, k))
    )
    # an escaping branch is listed when the block holding it is reachable
    holding = {(blocks[key].instruction, ordinal) for key in reachable
               for ordinal in range(blocks[key].start, blocks[key].stop)}
    return PcodeBlockGraph(entry_key, ordered, unmaterialized=tuple(sorted(
        item for item in unmaterialized if (item[0], item[1]) in holding)))


def _split(row, local, entry):
    operations = row.operations
    count = len(operations)
    base = instruction_key(row.address)
    leaders = {0}
    targets: dict[int, object] = {}
    for ordinal, operation in enumerate(operations):
        if operation.opcode not in _BRANCHES or not operation.inputs:
            continue
        if ordinal + 1 < count:
            leaders.add(ordinal + 1)
        if operation.opcode == "BRANCHIND":
            if ordinal != count - 1:
                return "indirect branch inside an instruction"
            continue
        destination = operation.inputs[0]
        if destination.kind is VarnodeKindCode.CONSTANT:
            bits = 8 * destination.byte_size
            delta = destination.coordinate.byte_offset
            if delta >> (bits - 1) & 1:
                delta -= 1 << bits
            target = ordinal + delta
            if not 0 <= target <= count:
                return "relative branch outside its instruction"
            if target < count:
                leaders.add(target)
            targets[ordinal] = ("relative", target)
        else:
            # An absolute self destination re-enters this instruction at its
            # first operation, but remains an observed instruction successor.
            # It is not a CONSTANT-relative intra-instruction branch.
            targets[ordinal] = ("address", destination.coordinate)
    starts = sorted(leaders)
    if _landing_pads(row, local, entry):
        return "a split call with landing pads"
    if row.flow.is_override:
        return "a split instruction with a flow override"

    def segment_key(start: int) -> str:
        return base if start == 0 else f"{base}#{start}"

    def after_instruction():
        fallthrough = row.fallthrough
        return (instruction_key(fallthrough),) if fallthrough in local else ()

    def resolve(ordinal):
        kind, value = targets[ordinal]
        if kind == "relative":
            return (segment_key(value),) if value < count else after_instruction()
        return (instruction_key(value),) if value in local else ()  # leaving the function

    def leaves(ordinal):
        kind, value = targets[ordinal]
        if kind == "relative":
            return value >= count and not after_instruction()
        return value not in local

    rows = []
    for index, start in enumerate(starts):
        stop = starts[index + 1] if index + 1 < len(starts) else count
        if stop == start:
            continue
        last = stop - 1
        opcode = operations[last].opcode
        falls = (segment_key(stop),) if stop < count else after_instruction()
        falls_out = stop >= count and not after_instruction()
        exits = False
        if opcode == "BRANCH" and last in targets:
            successors, exits = resolve(last), leaves(last)
        elif opcode == "CBRANCH" and last in targets:
            successors, exits = resolve(last) + falls, leaves(last) or falls_out
        elif opcode == "BRANCHIND":
            raw = control_successor_coordinates(row, local_addresses=local, function_entry=entry)
            successors = tuple(instruction_key(target) for target in raw if target in local)
            exits = not successors or len(successors) != len(raw)
        elif opcode == "RETURN" and last == count - 1:
            successors, exits = (), True
        else:
            successors, exits = falls, falls_out
        rows.append(PcodeBlock(
            segment_key(start), row.address, start, stop, tuple(sorted(set(successors))), exits
        ))
    # the observed flow must agree with the p-code's: every observed successor
    # reached from a sub-block that runs, every flow target a destination of a
    # branch that runs (a branch in an unreachable sub-block places none)
    by_key = {block.key: block for block in rows}
    reached, pending = set(), [base]
    while pending:
        key = pending.pop()
        if key in reached or key not in by_key:
            continue
        reached.add(key)
        pending.extend(by_key[key].successors)
    # The call-observation contract binds every native call seed to an exact
    # pre-SSA action. Unreachable operations deliberately have no such action.
    if any(op.opcode in _CALLS for block in rows if block.key not in reached
           for op in operations[block.start:block.stop]):
        return "an unreachable native call has no pre-SSA action"
    leaving = {successor for key in reached for successor in by_key[key].successors if successor not in by_key}
    leaving.update(
        instruction_key(targets[by_key[key].stop - 1][1]) for key in reached
        if by_key[key].stop - 1 in targets and targets[by_key[key].stop - 1][0] == "address"
        and targets[by_key[key].stop - 1][1] in local
    )
    observed = control_successor_coordinates(row, local_addresses=local, function_entry=entry)
    placed = {
        targets[block.stop - 1][1] for block in rows
        if block.key in reached and block.stop - 1 in targets and targets[block.stop - 1][0] == "address"
    }
    # In a split row an opaque operation can leave on its own path. A later
    # branch cannot stand in for that possible exit, even with the same target.
    if any(target not in local for target in observed):
        reached_opcodes = {op.opcode for key in reached for op in operations[by_key[key].start:by_key[key].stop]}
        if "CALLOTHER" in reached_opcodes:
            return "an opaque operation may leave a split instruction"
        listed_outside = set(observed).intersection(row.flow_targets) - local
        if listed_outside and reached_opcodes.intersection(_CALLS):
            return "a call may leave a split instruction"
        # A skipped CALLOTHER or BRANCHIND explains no target. control_exits()
        # retains the unexplained departure as may_leave before the row's actions.
    if {instruction_key(target) for target in observed if target in local} - leaving:
        return "observed successors the instruction's p-code does not reach"
    # An intra-instruction re-entry (e.g. REP) need not appear in the exported
    # instruction CFG. All other reachable intra-function destinations must.
    if leaving - {base} - {instruction_key(target) for target in observed}:
        return "a reachable split branch is missing from the instruction successors"
    # (G3b-7b) the entry a call of the row explains (only with a proved pad
    # set: ``call_explains``) is the call's own destination, not a branch to place
    called_entry = {entry} & call_explained_targets(row, entry)
    if operations[-1].opcode != "BRANCHIND":  # a terminal BRANCHIND takes the observed targets
        if {target for target in row.flow_targets if target in local} - placed - called_entry:
            return "flow targets the instruction's branches do not place"
    return rows


def _landing_pads(row, local, entry, successors=None) -> tuple:
    """Listed local successors of a call-like row, including a listed fallthrough.

    A recursive callee alone is not a pad. An entry also reachable via another
    transfer is a possible pad, with the same pre-call state requirement.
    """
    if not row.flow_targets or not call_like_instruction(row):
        return ()
    if successors is None:
        successors = control_successor_coordinates(row, local_addresses=local, function_entry=entry)
    pads = getattr(row, "exception_targets", None)   # (test doubles carry rows only)
    entry_is_pad = entry in successors if pads is None else entry in pads
    return tuple(target for target in row.flow_targets if target in local and (target != entry or entry_is_pad))


def _sole_terminal_call(operations) -> bool:
    """The instruction ends in its call and holds no other call-like operation."""
    return bool(operations) and operations[-1].opcode in _CALLS \
        and not any(item.opcode in _CALLS + ("CALLOTHER",) for item in operations[:-1])


__all__ = ("EDGE_COMPOSED", "EDGE_DEAD", "EDGE_ESCAPE", "EdgeOrigin", "PcodeBlock", "PcodeBlockGraph",
           "build_pcode_block_graph", "conditional_tail_edges", "edge_exit_kind", "edge_key", "edge_origin",
           "edge_site", "escaping_branch", "escaping_branches", "has_internal_flow", "instruction_key", "outcome_of",
           "tail_transfers", "TailTransfer", "terminator")
