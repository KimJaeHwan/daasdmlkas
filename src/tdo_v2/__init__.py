"""Low-PCode Data Origin V2 public API."""

from importlib import import_module
from typing import TYPE_CHECKING, Any

from .loader import LowPcodeLoader
from .model import (
    ByteSpan,
    NonStorage,
    ResolvedStorage,
    StorageObjectId,
    StorageObjectKind,
    StorageResolutionContext,
    StorageScopeId,
    StorageScopeKind,
    UnresolvedReason,
    UnresolvedStorage,
)

if TYPE_CHECKING:
    from .normalize import FunctionNormalizer, NormalizedFunction
    from .query import BackwardSliceQuery, SliceResult


_LAZY_EXPORTS = {
    "BaseGraphPolicy": (".base_graph", "BaseGraphPolicy"),
    "BaseGraphPublication": (".base_graph", "BaseGraphPublication"),
    "build_observed_graphs": (".base_graph", "build_observed_graphs"),
    "build_frozen_bundle_graphs": (".base_graph", "build_frozen_bundle_graphs"),
    "BackwardSliceQuery": (".query", "BackwardSliceQuery"),
    "FunctionNormalizer": (".normalize", "FunctionNormalizer"),
    "NormalizedFunction": (".normalize", "NormalizedFunction"),
    "SliceResult": (".query", "SliceResult"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = target
    value = getattr(import_module(module_name, __name__), attribute)
    globals()[name] = value
    return value

__all__ = [
    "BaseGraphPolicy",
    "BaseGraphPublication",
    "build_observed_graphs",
    "build_frozen_bundle_graphs",
    "BackwardSliceQuery",
    "ByteSpan",
    "FunctionNormalizer",
    "LowPcodeLoader",
    "NonStorage",
    "NormalizedFunction",
    "ResolvedStorage",
    "SliceResult",
    "StorageObjectId",
    "StorageObjectKind",
    "StorageResolutionContext",
    "StorageScopeId",
    "StorageScopeKind",
    "UnresolvedReason",
    "UnresolvedStorage",
]
