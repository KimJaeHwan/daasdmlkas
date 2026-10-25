"""Opt-in, documentation-audited allocation lifecycle contracts.

These records are not external-effect models and are not installed by loading a
model file.  ``matches`` checks the exact original model identity and its
physical result/free ports; it does *not* select a call symbol, prove a size
port, close callbacks/private state, or make a lifecycle claim on its own.
In particular, one shipped CRT model entry covers both malloc and calloc.

``load_lifecycle_contracts`` reads only a caller-selected JSON file. The
shipped glibc-compatible profile is a documentation-relative binding, not a
runtime allocator certification: interposition/replacement and model
callback/private-state assumptions remain independent. ``owned_footprint``
describes the user's requested object-byte range only, never errno, allocator
metadata, locks, hidden writes, or the separately bounded call stack overlay.
An explicit release contract, not legacy ``ModelEntry.frees``, is the claimed
definite lifetime end. Format 2 may additionally assert preservation of the
old/new common byte prefix after a positive-size successful resize. That
content relation says nothing about equal addresses or allocation epochs.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .image_info import ImportedSymbol
from .summary_store import ModelEntry, ModelFile


_HEX_DIGEST = re.compile(r"[0-9a-fA-F]{64}\Z")
_KINDS = frozenset({"allocate", "release", "resize"})
_FAILURES = frozenset({"unknown", "retain"})
_ZERO_SIZE = frozenset({"unknown", "release"})
_INPLACE = frozenset({"unknown", "retain", "replace"})
_MOVED = frozenset({"unknown", "replace"})
_CONTENTS = frozenset({"unknown", "preserve-prefix"})
_PROFILE_FIELDS_V1 = frozenset({
    "contract_id", "version", "model_id", "model_digest", "kind",
    "result", "pointer", "size", "count", "nullable", "failure",
    "zero_size", "inplace", "moved", "owned_footprint", "references",
    "symbol_names",
})
_PROFILE_FIELDS_V2 = _PROFILE_FIELDS_V1 | {"contents"}


class LifecycleContractError(ValueError):
    """A selected lifecycle profile has malformed or conflicting evidence."""


def _port(value: tuple[int, int] | None, name: str) -> None:
    if value is None:
        return
    if type(value) is not tuple or len(value) != 2 or any(type(part) is not int for part in value):
        raise TypeError(f"{name} must be an exact (register offset, width) tuple or None")
    offset, width = value
    if offset < 0 or not 1 <= width <= 16 or offset + width > 1 << 64:
        raise ValueError(f"{name} must name 1..16 physical register bytes")


@dataclass(frozen=True, slots=True, kw_only=True)
class LifecycleContract:
    """An independent, opt-in lifecycle assertion relative to one model file.

    ``nullable=False`` is an explicit success guarantee, not a consequence of
    ``fresh``.  The contract's label must accompany every fact that uses it.
    Unknown outcome fields confer no transition; a consumer must keep them
    conservative.  ``references`` point to the audited documentation.

    ``contents='preserve-prefix'`` asserts only that a successful resize with
    positive old and new extents preserves the first ``min(old, new)`` object
    bytes. It neither equates old/new addresses or allocation epochs nor
    asserts a failed or zero-size resize copies bytes. The consumer must
    independently prove success, both extents, the live old base, the actual
    symbol/model binding, and every relevant memory interference.

    These kinds assert C-style NULL semantics as part of this versioned
    contract: release(NULL) is a no-op; resize(NULL, positive size) allocates.
    An arbitrary custom primitive without those semantics cannot be bound
    to these kinds merely because its effect model has a ``frees`` port.
    """

    contract_id: str
    version: int
    model_id: str
    model_digest: str
    kind: str
    result: tuple[int, int] | None
    pointer: tuple[int, int] | None
    size: tuple[int, int] | None
    count: tuple[int, int] | None
    nullable: bool
    failure: str
    zero_size: str
    inplace: str
    moved: str
    owned_footprint: bool
    references: tuple[str, ...]
    # Empty is inert. A consumer must check the actual ImportedSymbol in
    # addition to ``matches``; one ModelEntry may cover multiple C exports.
    symbol_names: tuple[str, ...] = ()
    # Format 1 omits contents from its historical canonical digest. A format-2
    # contract includes it even when the value is "unknown".
    contents: str = "unknown"
    format_version: int = 1

    def __post_init__(self) -> None:
        if type(self.contract_id) is not str or not self.contract_id or self.contract_id.strip() != self.contract_id:
            raise ValueError("contract_id must be a nonempty, unpadded string")
        if type(self.version) is not int or self.version <= 0:
            raise ValueError("version must be a positive exact int")
        if (type(self.model_id) is not str or "/" not in self.model_id
                or not all(self.model_id.split("/", 1))):
            raise ValueError("model_id must be '<file id>/<entry name>'")
        if type(self.model_digest) is not str or _HEX_DIGEST.fullmatch(self.model_digest) is None:
            raise ValueError("model_digest must be exactly 64 hexadecimal characters")
        if type(self.kind) is not str or self.kind not in _KINDS:
            raise ValueError("kind must be allocate, release, or resize")
        if type(self.format_version) is not int or self.format_version not in (1, 2):
            raise ValueError("format_version must be exact 1 or 2")
        if type(self.contents) is not str or self.contents not in _CONTENTS:
            raise ValueError("contents must be unknown or preserve-prefix")
        if self.format_version == 1 and self.contents != "unknown":
            raise ValueError("format-1 contracts cannot assert content preservation")
        for name in ("result", "pointer", "size", "count"):
            _port(getattr(self, name), name)
        if type(self.nullable) is not bool or type(self.owned_footprint) is not bool:
            raise TypeError("nullable and owned_footprint must be exact booleans")
        for name, allowed in (("failure", _FAILURES), ("zero_size", _ZERO_SIZE),
                              ("inplace", _INPLACE), ("moved", _MOVED)):
            value = getattr(self, name)
            if type(value) is not str or value not in allowed:
                raise ValueError(f"unsupported {name} lifecycle outcome")
        if self.count is not None and self.size is None:
            raise ValueError("a count port requires a size port")
        if self.owned_footprint and (self.size is None or self.kind == "release"):
            raise ValueError("an owned footprint requires an allocation/resize size port")
        if self.kind == "allocate":
            if self.result is None or self.pointer is not None:
                raise ValueError("allocate requires a result and no old pointer")
            if (self.failure, self.zero_size, self.inplace, self.moved) != (
                "unknown", "unknown", "unknown", "unknown"
            ):
                raise ValueError("allocate cannot assert old-object outcomes")
            if self.contents != "unknown":
                raise ValueError("allocate cannot assert copied contents")
        elif self.kind == "release":
            if self.pointer is None or self.result is not None:
                raise ValueError("release requires an old pointer and no result")
            if (self.failure, self.zero_size, self.inplace, self.moved) != (
                "unknown", "unknown", "unknown", "unknown"
            ):
                raise ValueError("release cannot assert result/resize outcomes")
            if self.nullable is False:
                raise ValueError("release has no result to guarantee non-NULL")
            if self.contents != "unknown":
                raise ValueError("release cannot assert copied contents")
        elif self.result is None or self.pointer is None:
            raise ValueError("resize requires both a result and an old pointer")
        if self.contents == "preserve-prefix" and (self.version < 2 or self.size is None):
            raise ValueError("preserve-prefix requires a version-2 resize with a size port")
        if type(self.references) is not tuple or not self.references:
            raise ValueError("references must be a nonempty tuple of documentation URLs")
        for reference in self.references:
            if type(reference) is not str:
                raise TypeError("references must contain exact strings")
            parsed = urlsplit(reference)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username is not None:
                raise ValueError("references must be absolute HTTP(S) documentation URLs")
        if len(set(self.references)) != len(self.references):
            raise ValueError("references must not contain duplicates")
        if type(self.symbol_names) is not tuple:
            raise TypeError("symbol_names must be an exact tuple")
        if any(type(name) is not str or not name or name.strip() != name for name in self.symbol_names):
            raise ValueError("symbol_names must contain nonempty, unpadded exact strings")
        if len(set(self.symbol_names)) != len(self.symbol_names):
            raise ValueError("symbol_names must not contain duplicates")

    @property
    def canonical_digest(self) -> str:
        """Full SHA-256; format-1 payload remains byte-for-byte historical."""
        payload = {
            "schema": 1,
            "contract_id": self.contract_id,
            "version": self.version,
            "model_id": self.model_id,
            "model_digest": self.model_digest.lower(),
            "kind": self.kind,
            "result": self.result,
            "pointer": self.pointer,
            "size": self.size,
            "count": self.count,
            "nullable": self.nullable,
            "failure": self.failure,
            "zero_size": self.zero_size,
            "inplace": self.inplace,
            "moved": self.moved,
            "owned_footprint": self.owned_footprint,
            "references": self.references,
            "symbol_names": self.symbol_names,
        }
        if self.format_version == 2:
            payload["schema"] = 2
            payload["contents"] = self.contents
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()

    @property
    def label(self) -> str:
        return f"lifecycle-contract:{self.contract_id}@v{self.version}#{self.canonical_digest}"

    def matches_symbol(self, symbol: ImportedSymbol) -> bool:
        """Exact actual import name, preferring a separate original name.

        This deliberately has no model-name or ABI fallback. For a C++ import,
        the original mangled name takes precedence over a short display name.
        """
        if type(symbol) is not ImportedSymbol or not self.symbol_names:
            return False
        actual = symbol.original_name if symbol.original_name is not None else symbol.name
        return type(actual) is str and actual in self.symbol_names

    def matches(self, model_file: ModelFile, entry: ModelEntry) -> bool:
        """Match one original model row, without selecting or validating a call.

        A true result is *not* enough to apply this contract: the consumer must
        verify the actual symbol, physical size/count inputs, original snapshot,
        callback/hidden-state closure, and outcome assumptions independently.
        """
        if type(model_file) is not ModelFile or type(entry) is not ModelEntry or not self.symbol_names:
            return False
        if (type(model_file.digest) is not str or _HEX_DIGEST.fullmatch(model_file.digest) is None
                or model_file.digest.lower() != self.model_digest.lower()
                or entry.model_id != self.model_id
                or entry.file_id != model_file.file_id
                or entry.version != model_file.version):
            return False
        if sum(original == entry for original in model_file.entries) != 1:
            return False
        # The whitelist must be a subset of names this same original model
        # could select. A contract cannot invent an unrelated import name.
        modeled_names = (set(entry.original_names) if model_file.libraries else
                         {name for alias in entry.names for name in (alias, "_" + alias)})
        if not set(self.symbol_names) <= modeled_names:
            return False
        writes = {write for write, _ in entry.registers}
        if self.kind == "allocate":
            return (self.result in writes and self.result in entry.fresh
                    and self.result not in {result for result, _ in entry.same_object}
                    and entry.frees == ())
        if entry.frees != (self.pointer,):
            return False
        if self.kind == "release":
            return True
        return (self.result in writes
                and (self.result, self.pointer) in entry.same_object
                and self.result not in entry.fresh)


def _unique_json_object(pairs):
    found = {}
    for name, value in pairs:
        if name in found:
            raise LifecycleContractError(f"duplicate lifecycle JSON key: {name}")
        found[name] = value
    return found


def _reject_json_constant(value):
    raise LifecycleContractError(f"non-JSON lifecycle value: {value}")


def _json_port(value, name):
    if value is None:
        return None
    if type(value) is not list or len(value) != 2:
        raise LifecycleContractError(f"{name} must be null or a two-element array")
    return tuple(value)


def load_lifecycle_contracts(path: str | Path) -> tuple[LifecycleContract, ...]:
    """Load one explicitly selected, strict format-1 or format-2 profile.

    This function does not install models, register defaults, select symbols,
    or certify a runtime allocator. Consumers still verify the original model
    digest, actual ImportedSymbol, physical ports, callback/private-state
    closure, and complete byte/stack interference at each demanded call.
    """
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"),
                         object_pairs_hook=_unique_json_object,
                         parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise LifecycleContractError(f"malformed lifecycle JSON: {error}") from error
    if type(raw) is not dict or set(raw) != {"format_version", "contracts"}:
        raise LifecycleContractError("lifecycle profile requires exactly format_version and contracts")
    if type(raw["format_version"]) is not int or raw["format_version"] not in (1, 2):
        raise LifecycleContractError("unsupported lifecycle profile format_version")
    format_version = raw["format_version"]
    fields = _PROFILE_FIELDS_V1 if format_version == 1 else _PROFILE_FIELDS_V2
    rows = raw["contracts"]
    if type(rows) is not list or not rows:
        raise LifecycleContractError("lifecycle contracts must be a nonempty array")
    contracts = []
    identities = set()
    bindings = set()
    for index, row in enumerate(rows):
        if type(row) is not dict or set(row) != fields:
            raise LifecycleContractError(
                f"lifecycle contract {index} must have exactly the format-{format_version} fields")
        payload = dict(row)
        payload["format_version"] = format_version
        for name in ("result", "pointer", "size", "count"):
            payload[name] = _json_port(payload[name], f"contract {index} {name}")
        for name in ("references", "symbol_names"):
            if type(payload[name]) is not list:
                raise LifecycleContractError(f"contract {index} {name} must be an array")
            payload[name] = tuple(payload[name])
        try:
            contract = LifecycleContract(**payload)
        except (TypeError, ValueError) as error:
            raise LifecycleContractError(f"invalid lifecycle contract {index}: {error}") from error
        if not contract.symbol_names:
            raise LifecycleContractError(f"contract {index} has no applicable symbol")
        identity = (contract.contract_id, contract.version)
        if identity in identities:
            raise LifecycleContractError(f"duplicate lifecycle contract identity: {identity}")
        identities.add(identity)
        for symbol in contract.symbol_names:
            binding = (contract.model_digest.lower(), contract.model_id, symbol)
            if binding in bindings:
                raise LifecycleContractError(f"duplicate lifecycle symbol profile: {binding}")
            bindings.add(binding)
        contracts.append(contract)
    return tuple(contracts)


__all__ = ("LifecycleContract", "LifecycleContractError", "load_lifecycle_contracts")
