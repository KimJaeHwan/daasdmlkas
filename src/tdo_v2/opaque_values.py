"""Fail-closed evidence for deterministic opaque operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ._scope_contracts import ValidatedOperation


class OpaqueValueEvidenceProvider(Protocol):
    """Provide a stable identity only when determinism is certified."""

    def identity_token(
        self,
        translation_namespace: str,
        operation: ValidatedOperation,
    ) -> str | None: ...


@dataclass(frozen=True, slots=True)
class NullOpaqueValueEvidenceProvider:
    """Provide no opaque-value evidence."""

    def identity_token(
        self,
        translation_namespace: str,
        operation: ValidatedOperation,
    ) -> None:
        return None


@dataclass(frozen=True, slots=True)
class OpaqueValueEvidenceResolver:
    """Accept only exact, non-empty identity tokens from a provider."""

    provider: OpaqueValueEvidenceProvider

    def resolve(
        self,
        translation_namespace: str,
        operation: ValidatedOperation,
    ) -> str | None:
        if type(translation_namespace) is not str:
            raise TypeError("translation namespace must be exact text")
        if type(operation) is not ValidatedOperation:
            raise TypeError("opaque operation must be exact")

        token = self.provider.identity_token(translation_namespace, operation)
        if token is None:
            return None
        if type(token) is not str:
            raise TypeError("opaque-value identity token must be exact text")
        if not token:
            raise ValueError("opaque-value identity token must be non-empty")
        return token
