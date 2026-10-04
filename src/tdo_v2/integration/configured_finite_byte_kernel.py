"""Request-bound, single-operation physical byte transfer for ADR-0040.

This is an internal state transformer. It neither walks control flow nor emits
origins or a public completion. In particular, a control opcode is a frontier
that the later finite scheduler must discharge explicitly.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
import json
from sys import getsizeof

import z3

from .._scope_contracts import ValidatedOperation, ValidatedVarnode, VarnodeKindCode
from ..physical_state import PhysicalRegisterSlice
from ..model import StorageObjectKind
from .configured_finite_context_inputs import (
    AbsolutePremiseRange, ConfiguredFiniteContextRequest,
    replay_configured_finite_context_request,
)


REVISION = "configured-finite-byte-kernel-v5"
SYMBOLIC_REVISION = "configured-finite-byte-kernel-path-local-stack-v6"
MAX_OCCURRENCE_DEPTH = 32
MAX_ORDINAL = (1 << 32) - 1


class KernelDebtReason(StrEnum):
    INVALID_REQUEST = "invalid_request"
    INVALID_INPUT = "invalid_input"
    RESOURCE_BOUND = "resource_bound"
    MISSING_READ = "missing_read"
    UNKNOWN_ADDRESS = "unknown_address"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    CONTROL_FRONTIER = "control_frontier"
    NONCANONICAL_BOOLEAN = "noncanonical_boolean"


class KernelIncomplete(RuntimeError):
    def __init__(self, reason: KernelDebtReason, detail: str):
        self.reason, self.detail = reason, detail
        super().__init__(f"{reason.value}: {detail}")


def _stop(reason: KernelDebtReason, detail: str):
    raise KernelIncomplete(reason, detail)


@dataclass(frozen=True, slots=True)
class KernelLimits:
    input_bytes: int = 64
    output_bytes: int = 64
    live_bytes: int = 65536
    cumulative_bytes: int = 262144
    expression_nodes: int = 262144
    graph_nodes: int = 262144
    graph_edges: int = 524288
    memory_events: int = 262144
    artifact_bytes: int = 16777216


@dataclass(frozen=True, slots=True)
class ByteDefinition:
    node: int
    occurrence: tuple[int, ...]
    operation_ordinal: int
    storage: tuple[str, int, int, tuple[int, ...]]
    byte_index: int
    concrete: int | None
    edges: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class MemoryEvent:
    occurrence: tuple[int, ...]
    operation_ordinal: int
    kind: str
    space_id: int
    start: int  # absolute address or signed root-SP displacement
    size: int
    address_kind: str
    address_offset: int


@dataclass(frozen=True, slots=True)
class RootTokenSeed:
    role: str
    policy_revision: str
    request_digest: bytes
    root_scope_digest: bytes
    translation_language_id: str
    space_id: int
    relative_start: int
    size: int
    definition_ids: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class _Cell:
    value: z3.BitVecRef
    node: int
    form: tuple[str, int] | None = None
    canonical_bool: bool = False


_DELETED = object()


class _OverlayMap(MutableMapping):
    """Versioned physical map; fork freezes a shared base and adds two deltas.

    Values are immutable cells or forms. A frozen ancestor cannot be modified,
    so sibling overwrites and deletes never change another path's latest byte.
    """

    __slots__ = ("_base", "_delta", "_length", "_frozen")

    def __init__(self, base=None):
        self._base = base
        self._delta = {}
        self._length = 0 if base is None else len(base)
        self._frozen = False

    def __len__(self):
        return self._length

    def __getitem__(self, key):
        layer = self
        while layer is not None:
            if key in layer._delta:
                value = layer._delta[key]
                if value is _DELETED:
                    raise KeyError(key)
                return value
            layer = layer._base
        raise KeyError(key)

    def __contains__(self, key):
        try:
            self[key]
        except KeyError:
            return False
        return True

    def __setitem__(self, key, value):
        if self._frozen:
            raise TypeError("forked physical-state ancestor is immutable")
        if key not in self:
            self._length += 1
        self._delta[key] = value

    def __delitem__(self, key):
        if self._frozen:
            raise TypeError("forked physical-state ancestor is immutable")
        if key not in self:
            raise KeyError(key)
        self._length -= 1
        self._delta[key] = _DELETED

    def __iter__(self):
        seen = set()
        layer = self
        while layer is not None:
            for key, value in layer._delta.items():
                if key not in seen:
                    seen.add(key)
                    if value is not _DELETED:
                        yield key
            layer = layer._base

    def copy(self):
        return dict(self.items())

    def fork_pair(self):
        if self._frozen:
            raise TypeError("cannot fork a frozen physical-state ancestor")
        self._frozen = True
        return _OverlayMap(self), _OverlayMap(self)


@dataclass(frozen=True, slots=True)
class _FrozenChunk:
    parent: _FrozenChunk | None
    parent_length: int
    values: tuple


class _ForkList:
    """Append-only path list with a shared frozen prefix and mutable tail."""

    __slots__ = ("_prefix", "_prefix_length", "_tail", "_frozen")

    def __init__(self, prefix=None, prefix_length=0):
        self._prefix = prefix
        self._prefix_length = prefix_length
        self._tail = []
        self._frozen = False

    def __len__(self):
        return self._prefix_length + len(self._tail)

    def _lookup(self, index):
        chunk = self._prefix
        while chunk is not None:
            if index >= chunk.parent_length:
                return chunk.values[index - chunk.parent_length]
            chunk = chunk.parent
        raise IndexError(index)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[position] for position in range(*index.indices(len(self)))]
        if type(index) is not int:
            raise TypeError("definition/event index must be an integer or slice")
        if index < 0:
            index += len(self)
        if index < 0 or index >= len(self):
            raise IndexError(index)
        if index >= self._prefix_length:
            return self._tail[index - self._prefix_length]
        return self._lookup(index)

    def __iter__(self):
        segments = []
        chunk, visible = self._prefix, self._prefix_length
        while chunk is not None:
            count = max(0, visible - chunk.parent_length)
            if count:
                segments.append((chunk.values, count))
            visible = min(visible, chunk.parent_length)
            chunk = chunk.parent
        for values, count in reversed(segments):
            for index in range(count):
                yield values[index]
        yield from self._tail

    def append(self, value):
        if self._frozen:
            raise TypeError("forked definition/event ancestor is immutable")
        self._tail.append(value)

    def pop(self, index=-1):
        if self._frozen:
            raise TypeError("forked definition/event ancestor is immutable")
        length = len(self)
        if not length:
            raise IndexError("pop from empty definition/event list")
        if index < 0:
            index += length
        if index < 0 or index >= length:
            raise IndexError(index)
        if index != length - 1:
            # Rare non-tail deletion is explicit branch-local materialization.
            self._tail = list(self)
            self._prefix, self._prefix_length = None, 0
            return self._tail.pop(index)
        if self._tail:
            return self._tail.pop()
        value = self._lookup(self._prefix_length - 1)
        self._prefix_length -= 1
        return value

    def copy(self):
        return list(self)

    def fork_pair(self):
        if self._frozen:
            raise TypeError("cannot fork a frozen definition/event ancestor")
        if self._tail:
            chunk = _FrozenChunk(self._prefix, self._prefix_length, tuple(self._tail))
            visible = len(self)
        else:
            chunk, visible = self._prefix, self._prefix_length
        self._frozen = True
        return _ForkList(chunk, visible), _ForkList(chunk, visible)

    @property
    def pending_fork_refs(self):
        return len(self._tail)


class FiniteByteKernel:
    """One request's mutable byte state; all reads/writes are bounded and typed.

    ``root_sp`` must match the certified stack selector. ``absolute_ranges``
    admit absolute pointer effects. ``entry_ram_ranges`` additionally authorize
    symbolic initial reads, and are separately bound into the kernel identity.
    Image ranges alone grant neither permission nor byte contents.
    """

    def __init__(self, request: ConfiguredFiniteContextRequest, /, *,
                 root_sp: PhysicalRegisterSlice | None = None,
                 absolute_ranges: tuple[AbsolutePremiseRange, ...] = (),
                 entry_ram_ranges: tuple[AbsolutePremiseRange, ...] = (),
                 limits: KernelLimits = KernelLimits()):
        if type(request) is not ConfiguredFiniteContextRequest:
            _stop(KernelDebtReason.INVALID_REQUEST, "exact prepared request required")
        try:
            replay = replay_configured_finite_context_request(request)
        except Exception as error:
            _stop(KernelDebtReason.INVALID_REQUEST, f"request replay failed: {error}")
        if replay.input_digest != request.input_digest:
            _stop(KernelDebtReason.INVALID_REQUEST, "request identity changed")
        if any(row.evidence.unit.scopes.program.evidence.translation_namespace.language_id
               != "x86:LE:64:default" for row in request.analyses):
            _stop(KernelDebtReason.INVALID_INPUT,
                  "byte kernel admits only observed x86 little-endian 64-bit language")
        if type(limits) is not KernelLimits or any(
            type(getattr(limits, name)) is not int or not 0 < getattr(limits, name)
            <= getattr(KernelLimits(), name) for name in KernelLimits.__dataclass_fields__
        ):
            _stop(KernelDebtReason.RESOURCE_BOUND, "unsupported kernel limits")
        request_limits = request.limits
        if (limits.live_bytes > request_limits.symbolic_state_bytes
                or limits.cumulative_bytes > request_limits.symbolic_state_bytes
                or limits.expression_nodes > min(
                    getattr(request_limits, "expression_work_nodes",
                            request_limits.symbolic_state_bytes),
                    request_limits.graph_nodes)
                or limits.graph_nodes > request_limits.graph_nodes
                or limits.graph_edges > request_limits.graph_edges
                or limits.memory_events > request_limits.memory_events
                or limits.artifact_bytes > request_limits.cache_bytes):
            _stop(KernelDebtReason.RESOURCE_BOUND, "kernel ceilings exceed bound request")
        if type(root_sp) is not PhysicalRegisterSlice:
            _stop(KernelDebtReason.INVALID_INPUT, "exact root SP selector required")
        if (root_sp != request.induction.frame_step.stack_pointer
                or root_sp.byte_size * 8 != request.shared_state.binding.address_size_bits):
            _stop(KernelDebtReason.INVALID_INPUT, "root SP differs from certified address geometry")
        if type(absolute_ranges) is not tuple or type(entry_ram_ranges) is not tuple:
            _stop(KernelDebtReason.INVALID_INPUT, "exact RAM range tuples required")
        if len(absolute_ranges) + len(entry_ram_ranges) > request.limits.premise_ranges:
            _stop(KernelDebtReason.RESOURCE_BOUND, "RAM range preflight")
        space = request.shared_state.binding.address_space_id
        for ranges in (absolute_ranges, entry_ram_ranges):
            if ranges != tuple(sorted(set(ranges))):
                _stop(KernelDebtReason.INVALID_INPUT, "noncanonical RAM ranges")
            for row in ranges:
                if (type(row) is not AbsolutePremiseRange or row.space_id != space
                        or row.start < 0 or row.size <= 0 or row.start + row.size > 1 << 64):
                    _stop(KernelDebtReason.INVALID_INPUT, "invalid RAM geometry")
        if (request.symbolic_entry is not None
                and entry_ram_ranges != request.symbolic_entry.ranges):
            _stop(KernelDebtReason.INVALID_INPUT,
                  "v2 entry RAM differs from request's derived symbolic range policy")
        admitted_absolute = (request.isolated_stack.loaded_image_ranges
                             + request.isolated_stack.absolute_effect_ranges)
        if any(not self._covered(admitted_absolute, row.space_id, row.start, row.size)
               for row in absolute_ranges):
            _stop(KernelDebtReason.UNKNOWN_ADDRESS, "absolute range lacks premise separation")
        if any(not self._covered(absolute_ranges, row.space_id, row.start, row.size)
               for row in entry_ram_ranges):
            _stop(KernelDebtReason.INVALID_INPUT, "entry RAM must be admitted absolute RAM")
        if 256 + 96 * (len(absolute_ranges) + len(entry_ram_ranges)) > limits.artifact_bytes:
            _stop(KernelDebtReason.RESOURCE_BOUND, "kernel identity serialization preflight")
        self.request = request
        self.revision = SYMBOLIC_REVISION if request.symbolic_entry is not None else REVISION
        self.limits = limits
        register_spaces = tuple(row.space_id for row in
                                request.root_analysis.evidence.unit.scopes.program.evidence.address_spaces
                                if row.is_register_space)
        if len(register_spaces) != 1:
            _stop(KernelDebtReason.INVALID_INPUT, "one observed register space required")
        self.register_space = register_spaces[0]
        self.absolute_ranges = absolute_ranges
        self.entry_ram_ranges = entry_ram_ranges
        self.root_sp = root_sp
        self.root_sp_value = None
        self.cells: MutableMapping[tuple[str, int, int, tuple[int, ...]], _Cell] = _OverlayMap()
        self.definitions = _ForkList()
        self.events = _ForkList()
        self.forms: MutableMapping[tuple[int, ...], tuple[str, int]] = _OverlayMap()
        self.cumulative_bytes = 0
        self.expression_nodes = 0
        self.graph_edges = 0
        self.failed = False
        self._root_token_seeded = False
        self.root_token_seed: RootTokenSeed | None = None
        self._active: tuple[int, ...] = ()
        self._seed_initial()
        if root_sp is not None:
            keys = [("register", self.register_space, root_sp.byte_offset + i, ())
                    for i in range(root_sp.byte_size)]
            present = [key in self.cells for key in keys]
            if any(present) and not all(present):
                _stop(KernelDebtReason.INVALID_INPUT, "partially constrained root SP")
            if not all(present):
                for i, key in enumerate(keys):
                    symbol = z3.BitVec(f"root_sp_{request.input_digest.hex()}_{i}", 8)
                    self._new(key, symbol, ordinal=-2, byte_index=i)
            cells = tuple(self.cells[key] for key in keys)
            if all(z3.is_bv_value(cell.value) for cell in cells):
                self.root_sp_value = self._integer(cells)
            self.forms[tuple(cell.node for cell in cells)] = ("sp", 0)
        if request.symbolic_entry is not None and (
                request.initial_constraints or self.root_sp_value is not None):
            _stop(KernelDebtReason.INVALID_INPUT,
                  "v2 requires an unconstrained symbolic root SP")
        self._check_range_separation()
        identity = [self.revision, request.input_digest.hex(),
                    None if root_sp is None else [root_sp.byte_offset, root_sp.byte_size],
                    [[r.space_id, r.start, r.size] for r in absolute_ranges],
                    [[r.space_id, r.start, r.size] for r in entry_ram_ranges],
                    [getattr(limits, name) for name in KernelLimits.__dataclass_fields__]]
        self.identity = sha256(json.dumps(identity, separators=(",", ":")).encode()).digest()

    def _check_range_separation(self):
        if self.request.symbolic_entry is not None:
            return  # The v2 scheduler enforces each executed interval before its effect.
        if self.root_sp_value is None:
            # The exact request binds conditional-isolated-stack-v1. An
            # arbitrary root SP keeps separate root-relative/absolute key
            # families; the premise itself proves their non-alias relation.
            return
        low, high = self.request.isolated_stack.stack_relative_window
        modulus = 1 << self.request.shared_state.binding.address_size_bits
        if high - low >= modulus:
            _stop(KernelDebtReason.INVALID_INPUT, "stack window wraps entire address space")
        if high - low > self.limits.live_bytes:
            _stop(KernelDebtReason.RESOURCE_BOUND, "stack separation preflight")
        stack = {(self.root_sp_value + offset) % modulus for offset in range(low, high)}
        for row in (self.request.isolated_stack.loaded_image_ranges
                    + self.request.isolated_stack.absolute_effect_ranges):
            if any(row.start <= address < row.start + row.size for address in stack):
                _stop(KernelDebtReason.UNKNOWN_ADDRESS, "absolute/entry RAM overlaps stack premise")

    def _charge(self, *, live=0, cumulative=0, expressions=0, nodes=0, edges=0, events=0):
        if (len(self.cells) + live > self.limits.live_bytes
                or self.cumulative_bytes + cumulative > self.limits.cumulative_bytes
                or self.expression_nodes + expressions > self.limits.expression_nodes
                or len(self.definitions) + nodes > self.limits.graph_nodes
                or self.graph_edges + edges > self.limits.graph_edges
                or len(self.events) + events > self.limits.memory_events):
            _stop(KernelDebtReason.RESOURCE_BOUND, "finite byte-state budget")
        self.cumulative_bytes += cumulative
        self.expression_nodes += expressions
        self.graph_edges += edges

    def _new(self, key, value, form=None, edges=(), ordinal=-1, byte_index=0,
             canonical_bool=False):
        edges = tuple(sorted(set(edges)))
        self._charge(live=0 if key in self.cells else 1, cumulative=1,
                     expressions=1, nodes=1, edges=len(edges))
        concrete = value.as_long() if z3.is_bv_value(value) else None
        node = len(self.definitions)
        self.definitions.append(ByteDefinition(node, self._active, ordinal, key,
                                               byte_index, concrete, edges))
        cell = _Cell(value, node, form,
                     canonical_bool or (concrete is not None and concrete in (0, 1)))
        self.cells[key] = cell
        return cell

    def _entry_new(self, key, value):
        active = self._active
        try:
            self._active = ()
            return self._new(key, value, ordinal=-2)
        finally:
            self._active = active

    def _seed_initial(self):
        for constraint in self.request.initial_constraints:
            span = constraint.span
            if span.size > self.limits.output_bytes:
                _stop(KernelDebtReason.RESOURCE_BOUND, "initial constraint width")
            kind = "register" if span.object_id.kind is StorageObjectKind.REGISTER_FILE else "ram"
            space = self.register_space if kind == "register" else span.object_id.space_key
            if kind == "ram" and not self._covered(
                    self.request.isolated_stack.loaded_image_ranges
                    + self.request.isolated_stack.absolute_effect_ranges,
                    space, span.start, span.size):
                _stop(KernelDebtReason.UNKNOWN_ADDRESS, "initial RAM lacks separation premise")
            for index, byte in enumerate(constraint.value):
                self._new((kind, space, span.start + index, ()), z3.BitVecVal(byte, 8),
                          ordinal=-1, byte_index=index)

    def seed_root_return_token(self, *, offset: int, space_id: int):
        """Seed the one replayed root entry token, without assigning its target."""
        if self.failed or self._root_token_seeded or type(offset) is not int or type(space_id) is not int:
            _stop(KernelDebtReason.INVALID_INPUT, "root token may be seeded exactly once")
        if offset != 0 or space_id != self.request.shared_state.binding.address_space_id:
            _stop(KernelDebtReason.INVALID_INPUT, "root token is not [entry SP,+8) in admitted RAM")
        keys = [("ram_sp", space_id, offset + index, ()) for index in range(8)]
        if any(key in self.cells for key in keys):
            _stop(KernelDebtReason.INVALID_INPUT, "root token interval already has definitions")
        # Caller must first replay all root return observations and establish
        # the sole [entry SP,+8) interval. Reserve atomically before mutation.
        if (len(self.cells) + 8 > self.limits.live_bytes
                or self.cumulative_bytes + 8 > self.limits.cumulative_bytes
                or self.expression_nodes + 8 > self.limits.expression_nodes
                or len(self.definitions) + 8 > self.limits.graph_nodes):
            self.failed = True
            _stop(KernelDebtReason.RESOURCE_BOUND, "root token seed preflight")
        policy = "entry-ram-sp-root-return-token-v1"
        nodes = []
        for index, key in enumerate(keys):
            symbol = z3.BitVec(
                f"ENTRY_RAM_SP_{policy}_{self.request.input_digest.hex()}_"
                f"{self.request.induction.root_scope_digest.hex()}_{space_id}_{index}", 8)
            nodes.append(self._entry_new(key, symbol).node)
        self._root_token_seeded = True
        self.root_token_seed = RootTokenSeed("ENTRY_RAM_SP", policy,
            self.request.input_digest, self.request.induction.root_scope_digest,
            self.request.root_analysis.evidence.unit.scopes.program.evidence.translation_namespace.language_id,
            space_id, offset, 8, tuple(nodes))
        return tuple(self.cells[key] for key in keys)

    def fork(self):
        """Independent path state with shared immutable entry symbols."""
        if self.failed:
            _stop(KernelDebtReason.INVALID_INPUT, "stopped kernel session cannot fork")
        clone = object.__new__(FiniteByteKernel)
        clone.__dict__ = self.__dict__.copy()
        self.cells, clone.cells = self.cells.fork_pair()
        self.definitions, clone.definitions = self.definitions.fork_pair()
        self.events, clone.events = self.events.fork_pair()
        self.forms, clone.forms = self.forms.fork_pair()
        return clone

    def fork_cost(self) -> int:
        """Conservative bytes allocated by fork's shallow reference copies."""
        if self.failed:
            _stop(KernelDebtReason.INVALID_INPUT, "stopped kernel session cannot fork")
        # Only newly frozen tails are copied into tuples; earlier chunks stay
        # shared. The remainder covers instance metadata and four map deltas.
        return (getsizeof(self.__dict__) + 4 * getsizeof({})
                + 4 * getsizeof(_OverlayMap())
                + 4 * getsizeof(_ForkList())
                + 8 * (self.definitions.pending_fork_refs
                       + self.events.pending_fork_refs) + 768)

    @staticmethod
    def _join(cells):
        return z3.Concat(*(cell.value for cell in reversed(cells))) if len(cells) > 1 else cells[0].value

    @staticmethod
    def _split(value, size):
        if z3.is_bv_value(value):
            integer = value.as_long()
            return tuple(z3.BitVecVal((integer >> (8 * i)) & 255, 8)
                         for i in range(size))
        return tuple(z3.Extract(8 * i + 7, 8 * i, value) for i in range(size))

    def _integer(self, cells):
        if not all(z3.is_bv_value(cell.value) for cell in cells):
            _stop(KernelDebtReason.UNKNOWN_ADDRESS, "pointer value is not singleton")
        return sum(cell.value.as_long() << (8 * i) for i, cell in enumerate(cells))

    def _read_register(self, start, size):
        missing = [("register", self.register_space, start + i, ()) for i in range(size)
                   if ("register", self.register_space, start + i, ()) not in self.cells]
        if missing:
            if (len(self.cells) + len(missing) > self.limits.live_bytes
                    or self.cumulative_bytes + len(missing) > self.limits.cumulative_bytes
                    or self.expression_nodes + len(missing) > self.limits.expression_nodes
                    or len(self.definitions) + len(missing) > self.limits.graph_nodes):
                _stop(KernelDebtReason.RESOURCE_BOUND, "entry register byte preflight")
            for key in missing:
                symbol = z3.BitVec(f"entry_reg_{self.request.input_digest.hex()}_{key[2]}", 8)
                self._entry_new(key, symbol)
        return self._read_keys("register", self.register_space, start, size, ())

    def _read_keys(self, kind, space, start, size, activation):
        keys = [(kind, space, start + i, activation) for i in range(size)]
        if any(key not in self.cells for key in keys):
            _stop(KernelDebtReason.MISSING_READ, f"missing {kind} byte")
        return tuple(self.cells[key] for key in keys)

    def _read_ram(self, space, start, size, ordinal, *, address_kind="absolute"):
        storage_kind = "ram_sp" if address_kind == "sp" else "ram"
        keys = [(storage_kind, space, start + i, ()) for i in range(size)]
        missing = [key for key in keys if key not in self.cells]
        if missing:
            if address_kind != "absolute" or not all(
                    self._covered(self.entry_ram_ranges, space, key[2], 1) for key in missing):
                _stop(KernelDebtReason.MISSING_READ,
                      f"uninitialized RAM byte {space}:{start}+{size} ({address_kind})")
            if (len(self.cells) + len(missing) > self.limits.live_bytes
                    or self.cumulative_bytes + len(missing) > self.limits.cumulative_bytes
                    or self.expression_nodes + len(missing) > self.limits.expression_nodes
                    or len(self.definitions) + len(missing) > self.limits.graph_nodes):
                _stop(KernelDebtReason.RESOURCE_BOUND, "entry RAM byte preflight")
            for key in missing:
                symbol = z3.BitVec(f"entry_ram_{self.identity.hex()}_{space}_{key[2]}", 8)
                self._entry_new(key, symbol)
        self._charge(events=1)
        self.events.append(MemoryEvent(self._active, ordinal, "read", space, start, size,
                                       address_kind, start))
        return tuple(self.cells[key] for key in keys)

    @staticmethod
    def _covered(ranges, space, start, size):
        return any(row.space_id == space and row.start <= start and start + size <= row.start + row.size
                   for row in ranges)

    def _read(self, var, ordinal):
        kind, start, size = var.kind, var.coordinate.byte_offset, var.byte_size
        if kind is VarnodeKindCode.CONSTANT:
            value = start % (1 << (size * 8))
            return tuple(_Cell(z3.BitVecVal((value >> (i * 8)) & 255, 8), -1,
                               ("absolute", value) if i == 0 else None,
                               ((value >> (i * 8)) & 255) in (0, 1)) for i in range(size))
        if kind is VarnodeKindCode.REGISTER:
            if var.coordinate.space_id != self.register_space:
                _stop(KernelDebtReason.INVALID_INPUT, "register space mismatch")
            return self._read_register(start, size)
        if kind is VarnodeKindCode.UNIQUE:
            return self._read_keys("unique", var.coordinate.space_id, start, size, self._active)
        if kind is VarnodeKindCode.ADDRESS:
            if not self._covered(self.absolute_ranges, var.coordinate.space_id, start, size):
                _stop(KernelDebtReason.UNKNOWN_ADDRESS, "direct ADDRESS interval not admitted")
            return self._read_ram(var.coordinate.space_id, start, size, ordinal)
        _stop(KernelDebtReason.UNSUPPORTED_OPERATION, f"input kind {kind.name}")

    def _form(self, cells):
        proven = self.forms.get(tuple(cell.node for cell in cells))
        if proven is not None:
            return proven
        if all(z3.is_bv_value(cell.value) for cell in cells):
            return ("absolute", self._integer(cells))
        return None

    def _address(self, cells, size, space):
        if self.request.symbolic_entry is not None and self.root_sp_value is not None:
            _stop(KernelDebtReason.INVALID_INPUT,
                  "v2 root SP became concrete before path-local separation")
        form = self._form(cells)
        if form is None:
            _stop(KernelDebtReason.UNKNOWN_ADDRESS, "pointer is neither absolute nor root-SP-relative")
        kind, offset = form
        modulus = 1 << self.request.shared_state.binding.address_size_bits
        if kind == "sp":
            low, high = self.request.isolated_stack.stack_relative_window
            if not low <= offset or offset + size > high:
                _stop(KernelDebtReason.UNKNOWN_ADDRESS, "stack interval outside certified window")
            return offset, "sp", offset
        start = offset
        if start + size > modulus:
            _stop(KernelDebtReason.UNKNOWN_ADDRESS, "memory interval wraps")
        if self.root_sp_value is not None and self.request.symbolic_entry is None:
            low, high = self.request.isolated_stack.stack_relative_window
            delta = (start - self.root_sp_value) % modulus
            for candidate in (delta, delta - modulus):
                if low <= candidate and candidate + size <= high:
                    return candidate, "sp", candidate
        if not self._covered(self.absolute_ranges, space, start, size):
            _stop(KernelDebtReason.UNKNOWN_ADDRESS, "absolute interval not admitted")
        return start, "absolute", start

    def _write(self, var, values, edge_sets, form, ordinal, *, canonical_bool=False):
        if var.kind not in {VarnodeKindCode.REGISTER, VarnodeKindCode.UNIQUE, VarnodeKindCode.ADDRESS}:
            _stop(KernelDebtReason.UNSUPPORTED_OPERATION, "output storage kind")
        kind = "register" if var.kind is VarnodeKindCode.REGISTER else (
            "unique" if var.kind is VarnodeKindCode.UNIQUE else "ram")
        space = self.register_space if kind == "register" else var.coordinate.space_id
        if kind == "register" and var.coordinate.space_id != self.register_space:
            _stop(KernelDebtReason.INVALID_INPUT, "register space mismatch")
        if kind == "ram" and not self._covered(self.absolute_ranges, space,
                                                var.coordinate.byte_offset, var.byte_size):
            _stop(KernelDebtReason.UNKNOWN_ADDRESS, "direct ADDRESS output not admitted")
        activation = self._active if kind == "unique" else ()
        written = tuple(self._new((kind, space, var.coordinate.byte_offset + i, activation),
                                  value, None, edge_sets[i], ordinal, i,
                                  canonical_bool=canonical_bool and len(values) == 1)
                        for i, value in enumerate(values))
        if form is not None:
            self.forms[tuple(cell.node for cell in written)] = form
        if kind == "ram":
            self._charge(events=1)
            self.events.append(MemoryEvent(self._active, ordinal, "write", space,
                                           var.coordinate.byte_offset, len(values),
                                           "absolute", var.coordinate.byte_offset))

    def transfer(self, operation: ValidatedOperation, /, *,
                 occurrence: tuple[int, ...], operation_ordinal: int,
                 stack_interval_guard=None):
        if self.failed:
            _stop(KernelDebtReason.INVALID_INPUT, "stopped kernel session cannot resume")
        try:
            self._transfer_impl(operation, occurrence=occurrence,
                                operation_ordinal=operation_ordinal,
                                stack_interval_guard=stack_interval_guard)
        except KernelIncomplete as error:
            if error.reason is not KernelDebtReason.CONTROL_FRONTIER:
                self.failed = True
            raise

    @staticmethod
    def _validate_occurrence(occurrence):
        if (type(occurrence) is not tuple or not 0 < len(occurrence) <= MAX_OCCURRENCE_DEPTH
                or any(type(i) is not int or not 0 <= i <= MAX_ORDINAL for i in occurrence)):
            _stop(KernelDebtReason.INVALID_INPUT, "bounded exact occurrence required")

    def _validate_shape(self, operation):
        opcode, inputs, output = operation.opcode, operation.inputs, operation.output
        count = len(inputs)
        if opcode in {"LOAD", "STORE"}:
            expected = 2 if opcode == "LOAD" else 3
            if count == expected and inputs[0].kind is VarnodeKindCode.CONSTANT and (
                    inputs[0].coordinate.byte_offset
                    != self.request.shared_state.binding.address_space_id):
                _stop(KernelDebtReason.UNKNOWN_ADDRESS, "LOAD/STORE RAM space differs from premise")
            if (count != expected or inputs[0].kind is not VarnodeKindCode.CONSTANT
                    or inputs[1].byte_size * 8 != self.request.shared_state.binding.address_size_bits
                    or (opcode == "LOAD" and output is None)
                    or (opcode == "STORE" and output is not None)):
                _stop(KernelDebtReason.UNSUPPORTED_OPERATION, f"{opcode} shape")
            return
        if output is None:
            _stop(KernelDebtReason.UNSUPPORTED_OPERATION, "missing output")
        size = output.byte_size
        if opcode in {"COPY", "CAST"}:
            valid = count == 1 and inputs[0].byte_size == size
        elif opcode in {"INT_ZEXT", "INT_SEXT"}:
            valid = count == 1 and inputs[0].byte_size < size
        elif opcode == "SUBPIECE":
            valid = (count == 2 and inputs[1].kind is VarnodeKindCode.CONSTANT
                     and inputs[1].byte_size <= 8)
        elif opcode == "PIECE":
            valid = count == 2 and inputs[0].byte_size + inputs[1].byte_size == size
        elif opcode in {"BOOL_NEGATE", "BOOL_AND", "BOOL_OR", "BOOL_XOR"}:
            valid = (count == (1 if opcode == "BOOL_NEGATE" else 2) and size == 1
                     and all(row.byte_size == 1 for row in inputs))
        elif opcode in {"INT_2COMP", "INT_NEGATE"}:
            valid = count == 1 and inputs[0].byte_size == size
        elif opcode in {"POPCOUNT", "LZCOUNT"}:
            valid = count == 1
        elif opcode in {"INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS",
                        "INT_CARRY", "INT_SCARRY", "INT_SBORROW"}:
            valid = count == 2 and size == 1 and inputs[0].byte_size == inputs[1].byte_size
        else:
            valid = count == 2 and inputs[0].byte_size == inputs[1].byte_size == size
        if not valid:
            _stop(KernelDebtReason.UNSUPPORTED_OPERATION, f"{opcode} width/arity")

    def _reserve_expression_work(self, operation):
        # Bound each Z3 constructor in this opcode before reading operands:
        # constant input bytes, joins (at most n-1 binary concat nodes), the
        # fixed arithmetic/comparison/extension core, and output byte splits.
        # Lazy symbolic entry bytes and materialized output definitions charge
        # separately in _new. No symbolic simplify/solver call runs here.
        opcode = operation.opcode
        constants = sum(row.byte_size for row in operation.inputs
                        if row.kind is VarnodeKindCode.CONSTANT)
        if opcode in {"INT_ADD", "INT_SUB", "INT_AND", "INT_OR", "INT_XOR",
                      "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS",
                      "INT_CARRY", "INT_SCARRY", "INT_SBORROW", "BOOL_NEGATE",
                      "BOOL_AND", "BOOL_OR", "BOOL_XOR", "INT_2COMP", "INT_NEGATE",
                      "POPCOUNT", "LZCOUNT", "INT_ZEXT", "INT_SEXT"}:
            joins = sum(max(0, row.byte_size - 1) for row in operation.inputs)
            # Population/leading-zero counts construct one bounded bit test
            # and accumulator/conditional step per input bit.
            core = (6 * 8 * operation.inputs[0].byte_size + 8
                    if opcode in {"POPCOUNT", "LZCOUNT"} else 20)
            splits = operation.output.byte_size
        else:
            joins = core = splits = 0
        reserve = constants + joins + core + splits
        self._charge(expressions=reserve)

    def _concrete_arithmetic(self, opcode, inputs, size):
        left = self._integer(inputs[0])
        right = self._integer(inputs[1]) if len(inputs) == 2 else None
        width = 8 * len(inputs[0]); modulus = 1 << width
        signed = lambda value: value if value < modulus // 2 else value - modulus
        if opcode == "INT_ADD": result = left + right
        elif opcode == "INT_SUB": result = left - right
        elif opcode == "INT_AND": result = left & right
        elif opcode == "INT_OR": result = left | right
        elif opcode == "INT_XOR": result = left ^ right
        elif opcode == "INT_EQUAL": result = int(left == right)
        elif opcode == "INT_NOTEQUAL": result = int(left != right)
        elif opcode == "INT_LESS": result = int(left < right)
        elif opcode == "INT_SLESS": result = int(signed(left) < signed(right))
        elif opcode == "INT_CARRY": result = int(left + right >= modulus)
        elif opcode == "INT_SCARRY":
            total = (left + right) % modulus
            result = int(bool((left ^ total) & (right ^ total) & (modulus // 2)))
        elif opcode == "INT_SBORROW":
            difference = (left - right) % modulus
            result = int(bool((left ^ right) & (left ^ difference) & (modulus // 2)))
        elif opcode == "INT_2COMP": result = -left
        elif opcode == "INT_NEGATE": result = ~left
        elif opcode == "POPCOUNT": result = left.bit_count()
        elif opcode == "LZCOUNT": result = width - left.bit_length()
        elif opcode == "BOOL_NEGATE": result = 1 - (left & 1)
        elif opcode == "BOOL_AND": result = (left & 1) & (right & 1)
        elif opcode == "BOOL_OR": result = (left & 1) | (right & 1)
        elif opcode == "BOOL_XOR": result = (left & 1) ^ (right & 1)
        else: _stop(KernelDebtReason.UNSUPPORTED_OPERATION, opcode)
        return z3.BitVecVal(result % (1 << (8 * size)), 8 * size)

    def _transfer_impl(self, operation: ValidatedOperation, /, *,
                       occurrence: tuple[int, ...], operation_ordinal: int,
                       stack_interval_guard=None):
        if type(operation) is not ValidatedOperation:
            _stop(KernelDebtReason.INVALID_INPUT, "exact operation required")
        self._validate_occurrence(occurrence)
        if type(operation_ordinal) is not int or not 0 <= operation_ordinal <= MAX_ORDINAL:
            _stop(KernelDebtReason.INVALID_INPUT, "exact operation and occurrence required")
        opcode = operation.opcode
        if opcode in {"CALL", "CALLIND", "RETURN", "BRANCH", "BRANCHIND", "CBRANCH"}:
            _stop(KernelDebtReason.CONTROL_FRONTIER, opcode)
        admitted = {"LOAD", "STORE", "COPY", "CAST", "INT_ZEXT", "INT_SEXT", "SUBPIECE", "PIECE",
                    "INT_ADD", "INT_SUB", "INT_AND", "INT_OR", "INT_XOR", "INT_EQUAL",
                    "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_CARRY", "INT_SCARRY",
                    "INT_SBORROW", "BOOL_NEGATE", "BOOL_AND", "BOOL_OR", "BOOL_XOR",
                    "POPCOUNT", "LZCOUNT", "INT_2COMP", "INT_NEGATE"}
        if opcode not in admitted:
            _stop(KernelDebtReason.UNSUPPORTED_OPERATION, opcode)
        if any(var.byte_size > self.limits.input_bytes for var in operation.inputs):
            _stop(KernelDebtReason.RESOURCE_BOUND, "input width")
        if operation.output is not None and operation.output.byte_size > self.limits.output_bytes:
            _stop(KernelDebtReason.RESOURCE_BOUND, "output width")
        if sum(var.byte_size for var in operation.inputs) > self.limits.cumulative_bytes:
            _stop(KernelDebtReason.RESOURCE_BOUND, "operation input preflight")
        self._validate_shape(operation)
        self._reserve_expression_work(operation)
        self._active = occurrence
        if opcode in {"LOAD", "STORE"}:
            self._memory_operation(operation, operation_ordinal, stack_interval_guard)
            return
        if operation.output is None:
            _stop(KernelDebtReason.UNSUPPORTED_OPERATION, "missing output")
        inputs = tuple(self._read(var, operation_ordinal) for var in operation.inputs)
        out = operation.output
        size = out.byte_size
        if opcode in {"COPY", "CAST"} and len(inputs) == 1 and len(inputs[0]) == size:
            values = tuple(cell.value for cell in inputs[0])
            edges = tuple((("DATA", cell.node),) if cell.node >= 0 else () for cell in inputs[0])
            form = self._form(inputs[0])
        elif opcode in {"INT_ZEXT", "INT_SEXT"} and len(inputs) == 1 and len(inputs[0]) < size:
            source = inputs[0]
            if all(z3.is_bv_value(cell.value) for cell in source):
                integer = self._integer(source)
                if opcode == "INT_SEXT" and integer & (1 << (8 * len(source) - 1)):
                    integer |= ((1 << (8 * size)) - 1) ^ ((1 << (8 * len(source))) - 1)
                full = z3.BitVecVal(integer, 8 * size)
            else:
                value = self._join(source)
                full = (z3.ZeroExt(8 * (size - len(source)), value)
                        if opcode == "INT_ZEXT" else z3.SignExt(8 * (size - len(source)), value))
            values = self._split(full, size)
            extension_edges = []
            for i in range(size):
                source_cell = source[i] if i < len(source) else (
                    source[-1] if opcode == "INT_SEXT" else None)
                extension_edges.append((("DATA", source_cell.node),)
                                       if source_cell is not None and source_cell.node >= 0 else ())
            edges = tuple(extension_edges)
            form = None
        elif opcode == "SUBPIECE" and len(inputs) == 2 and len(inputs[1]) <= 8:
            offset = self._integer(inputs[1])
            if offset + size > len(inputs[0]):
                _stop(KernelDebtReason.UNSUPPORTED_OPERATION, "SUBPIECE interval")
            selected = inputs[0][offset:offset + size]
            values = tuple(cell.value for cell in selected)
            edges = tuple((("DATA", cell.node),) if cell.node >= 0 else () for cell in selected)
            form = None
        elif opcode == "PIECE" and len(inputs) == 2 and len(inputs[0]) + len(inputs[1]) == size:
            selected = inputs[1] + inputs[0]
            values = tuple(cell.value for cell in selected)
            edges = tuple((("DATA", cell.node),) if cell.node >= 0 else () for cell in selected)
            form = None
        else:
            values, edges, form = self._arithmetic(opcode, inputs, size)
        boolean_result = opcode in {
            "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS",
            "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
            "BOOL_NEGATE", "BOOL_AND", "BOOL_OR", "BOOL_XOR",
        }
        if size == 1 and opcode in {"COPY", "CAST"}:
            boolean_result = inputs[0][0].canonical_bool
        if size == 1 and opcode == "SUBPIECE":
            boolean_result = selected[0].canonical_bool
        self._write(out, values, edges, form, operation_ordinal,
                    canonical_bool=boolean_result)

    def _arithmetic(self, opcode, inputs, size):
        if opcode not in {"INT_ADD", "INT_SUB", "INT_AND", "INT_OR", "INT_XOR",
                          "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS",
                          "INT_CARRY", "INT_SCARRY", "INT_SBORROW", "BOOL_NEGATE",
                          "BOOL_AND", "BOOL_OR", "BOOL_XOR", "POPCOUNT", "LZCOUNT",
                          "INT_2COMP", "INT_NEGATE"}:
            _stop(KernelDebtReason.UNSUPPORTED_OPERATION, opcode)
        if opcode in {"BOOL_NEGATE", "BOOL_AND", "BOOL_OR", "BOOL_XOR"} and not all(
                cell.canonical_bool for row in inputs for cell in row):
            _stop(KernelDebtReason.NONCANONICAL_BOOLEAN,
                  "boolean input lacks a proven 0/1 byte definition")
        concrete = all(z3.is_bv_value(cell.value) for row in inputs for cell in row)
        if concrete:
            value = self._concrete_arithmetic(opcode, inputs, size)
        else:
            left = self._join(inputs[0]); right = self._join(inputs[1]) if len(inputs) == 2 else None
            if opcode == "INT_ADD": value = left + right
            elif opcode == "INT_SUB": value = left - right
            elif opcode == "INT_AND": value = left & right
            elif opcode == "INT_OR": value = left | right
            elif opcode == "INT_XOR": value = left ^ right
            elif opcode == "INT_2COMP": value = -left
            elif opcode == "INT_NEGATE": value = ~left
            elif opcode in {"POPCOUNT", "LZCOUNT"}:
                width = left.size()
                output_width = size * 8
                if opcode == "POPCOUNT":
                    value = z3.BitVecVal(0, output_width)
                    for bit in range(width):
                        value = value + z3.ZeroExt(output_width - 1, z3.Extract(bit, bit, left))
                else:
                    value = z3.BitVecVal(width, output_width)
                    for bit in range(width):
                        value = z3.If(z3.Extract(bit, bit, left) == z3.BitVecVal(1, 1),
                                      z3.BitVecVal(width - 1 - bit, output_width), value)
            else:
                sign_left = z3.Extract(left.size() - 1, left.size() - 1, left)
                if opcode in {"INT_CARRY", "INT_SCARRY", "INT_SBORROW"}:
                    sign_right = z3.Extract(right.size() - 1, right.size() - 1, right)
                    arithmetic = left - right if opcode == "INT_SBORROW" else left + right
                    sign_result = z3.Extract(left.size() - 1, left.size() - 1, arithmetic)
                condition = {
                    "INT_EQUAL": lambda: left == right,
                    "INT_NOTEQUAL": lambda: left != right,
                    "INT_LESS": lambda: z3.ULT(left, right),
                    "INT_SLESS": lambda: left < right,
                    "INT_CARRY": lambda: z3.ULT(left + right, left),
                    "INT_SCARRY": lambda: z3.And(sign_left == sign_right,
                                                   sign_result != sign_left),
                    "INT_SBORROW": lambda: z3.And(sign_left != sign_right,
                                                    sign_result != sign_left),
                    "BOOL_NEGATE": lambda: z3.Extract(0, 0, left) == z3.BitVecVal(0, 1),
                    "BOOL_AND": lambda: z3.And(z3.Extract(0, 0, left) == 1,
                                                z3.Extract(0, 0, right) == 1),
                    "BOOL_OR": lambda: z3.Or(z3.Extract(0, 0, left) == 1,
                                              z3.Extract(0, 0, right) == 1),
                    "BOOL_XOR": lambda: (z3.Extract(0, 0, left) != z3.Extract(0, 0, right)),
                }[opcode]()
                value = z3.If(condition, z3.BitVecVal(1, 8), z3.BitVecVal(0, 8))
        dependencies = tuple(("POTENTIAL_DATA", cell.node) for row in inputs for cell in row if cell.node >= 0)
        form = None
        if opcode in {"INT_ADD", "INT_SUB"}:
            first, second = self._form(inputs[0]), self._form(inputs[1])
            if first and first[0] == "sp" and second and second[0] == "absolute":
                modulus = 1 << (size * 8)
                raw = second[1] % modulus
                signed = raw if raw < modulus // 2 else raw - modulus
                delta = signed if opcode == "INT_ADD" else -signed
                form = ("sp", first[1] + delta)
        return self._split(value, size), (dependencies,) * size, form

    def _memory_operation(self, operation, ordinal, stack_interval_guard=None):
        opcode = operation.opcode
        expected = 2 if opcode == "LOAD" else 3
        if (len(operation.inputs) != expected
                or operation.inputs[0].kind is not VarnodeKindCode.CONSTANT
                or (opcode == "LOAD" and operation.output is None)
                or (opcode == "STORE" and operation.output is not None)):
            _stop(KernelDebtReason.UNSUPPORTED_OPERATION, f"{opcode} shape")
        space = operation.inputs[0].coordinate.byte_offset
        if space != self.request.shared_state.binding.address_space_id:
            _stop(KernelDebtReason.UNKNOWN_ADDRESS, "LOAD/STORE RAM space differs from premise")
        pointer = self._read(operation.inputs[1], ordinal)
        if len(pointer) * 8 != self.request.shared_state.binding.address_size_bits:
            _stop(KernelDebtReason.UNSUPPORTED_OPERATION, "pointer address width")
        size = operation.output.byte_size if opcode == "LOAD" else operation.inputs[2].byte_size
        start, address_kind, address_offset = self._address(pointer, size, space)
        if address_kind == "sp":
            if self.request.symbolic_entry is not None and stack_interval_guard is None:
                _stop(KernelDebtReason.INVALID_INPUT,
                      "v2 stack access requires a path-local isolation guard")
            if stack_interval_guard is not None:
                stack_interval_guard(start, size)
        address_edges = tuple(("ADDRESS", cell.node) for cell in pointer if cell.node >= 0)
        if opcode == "LOAD":
            source = self._read_ram(space, start, size, ordinal, address_kind=address_kind)
            values = tuple(cell.value for cell in source)
            edges = tuple(((("DATA", cell.node),) if cell.node >= 0 else ()) + address_edges
                          for cell in source)
            self._write(operation.output, values, edges, self._form(source), ordinal,
                        canonical_bool=len(source) == 1 and source[0].canonical_bool)
        else:
            source = self._read(operation.inputs[2], ordinal)
            self._charge(events=1)
            self.events.append(MemoryEvent(self._active, ordinal, "write", space, start, size,
                                           address_kind, address_offset))
            written = []
            for i, cell in enumerate(source):
                edges = ((("DATA", cell.node),) if cell.node >= 0 else ()) + address_edges
                written.append(self._new(("ram_sp" if address_kind == "sp" else "ram",
                                          space, start + i, ()), cell.value, None, edges, ordinal, i,
                                         canonical_bool=len(source) == 1 and cell.canonical_bool))
            form = self._form(source)
            if form is not None:
                self.forms[tuple(cell.node for cell in written)] = form

    def enter(self, occurrence: tuple[int, ...]):
        if self.failed:
            _stop(KernelDebtReason.INVALID_INPUT, "stopped kernel session cannot resume")
        self._validate_occurrence(occurrence)
        self._active = occurrence

    def read_bytes(self, var, *, occurrence: tuple[int, ...]):
        """Inspect current physical values and latest definition IDs, without origin closure."""
        try:
            if type(var) is not ValidatedVarnode:
                _stop(KernelDebtReason.INVALID_INPUT, "exact inspection varnode required")
            self.enter(occurrence)
            if var.byte_size > self.limits.input_bytes:
                _stop(KernelDebtReason.RESOURCE_BOUND, "inspection width")
            if var.kind is VarnodeKindCode.CONSTANT:
                self._charge(expressions=var.byte_size)
            cells = self._read(var, -1)
            return tuple((cell.node, cell.value) for cell in cells)
        except KernelIncomplete:
            self.failed = True
            raise

    def artifact(self) -> bytes:
        """Bounded diagnostic graph encoding, never a proof/cache identity."""
        if self.failed:
            _stop(KernelDebtReason.INVALID_INPUT, "stopped kernel session has no artifact")
        parts = [b"[", json.dumps([self.revision, self.identity.hex()], separators=(",", ":")).encode(), b",["]
        total = sum(map(len, parts)) + 4
        if total > self.limits.artifact_bytes:
            _stop(KernelDebtReason.RESOURCE_BOUND, "artifact header budget")
        for index, d in enumerate(self.definitions):
            if (256 + 11 * (len(d.occurrence) + len(d.storage[3]))
                    + 40 * len(d.edges) > self.limits.artifact_bytes - total):
                _stop(KernelDebtReason.RESOURCE_BOUND, "artifact node preflight")
            row = [d.node, list(d.occurrence), d.operation_ordinal,
                   [d.storage[0], d.storage[1], d.storage[2], list(d.storage[3])],
                   d.byte_index, d.concrete, [list(edge) for edge in d.edges]]
            piece = json.dumps(row, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            total += len(piece) + (index > 0)
            if total > self.limits.artifact_bytes:
                _stop(KernelDebtReason.RESOURCE_BOUND, "artifact node budget")
            if index:
                parts.append(b",")
            parts.append(piece)
        parts.append(b"],[")
        total += 3
        for index, e in enumerate(self.events):
            if 256 + 11 * len(e.occurrence) > self.limits.artifact_bytes - total:
                _stop(KernelDebtReason.RESOURCE_BOUND, "artifact event preflight")
            row = [list(e.occurrence), e.operation_ordinal, e.kind, e.space_id,
                   e.start, e.size, e.address_kind, e.address_offset]
            piece = json.dumps(row, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            total += len(piece) + (index > 0)
            if total > self.limits.artifact_bytes:
                _stop(KernelDebtReason.RESOURCE_BOUND, "artifact event budget")
            if index:
                parts.append(b",")
            parts.append(piece)
        parts.append(b"]]")
        return b"".join(parts)
