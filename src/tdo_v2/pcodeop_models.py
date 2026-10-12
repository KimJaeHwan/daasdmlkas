"""Declared semantics of CALLOTHER user ops (models/pcodeops/*.json).

A Bundle names a user op only by its CALLOTHER index; a model file maps
indices of given Ghidra language versions to names (verified with
``ghidra/GhidraV2ListUserOps.java``) and lists the ops with no data effect
(``no_effect``, e.g. x86 ``LOCK``/``UNLOCK``). Such a CALLOTHER (no output,
only its index operand) is normalized as a declared call effect that reads
and writes nothing -- not as an opaque call -- labelled
``pcodeop-model:<file id>/<name>@v<version>``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ._scope_contracts import VarnodeKindCode
from .assumed_call_effects import AssumedCallEffect
from .call_seeds import _operation_key


@dataclass(frozen=True, slots=True)
class PcodeOpModel:
    file_id: str
    version: int
    languages: frozenset   # (language id, major, minor)
    no_effect: dict        # CALLOTHER index -> name
    traps: dict = None     # CALLOTHER index -> operands that never return (software interrupts)


def load_pcodeop_models(paths) -> tuple[PcodeOpModel, ...]:
    models = []
    for path in paths:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if raw.get("format_version") != 1 or raw.get("kind") != "pcodeop-declared":
            raise ValueError(f"{path}: unsupported p-code op model")
        models.append(PcodeOpModel(
            raw["id"], raw["version"],
            frozenset((row["language_id"], row["major_version"], row["minor_version"]) for row in raw["languages"]),
            {int(index): name for index, name in raw["no_effect"].items()},
            {int(index): frozenset(operands) for index, operands in raw.get("traps", {}).items()},
        ))
    return tuple(models)


def no_effect_calls(unit, models) -> dict[str, AssumedCallEffect]:
    """CALLOTHER operation key -> a declared effect reading and writing nothing."""
    namespace = unit.scopes.program.evidence.translation_namespace
    language = (namespace.language_id, namespace.major_version, namespace.minor_version)
    applicable = [model for model in models if language in model.languages]
    found = {}
    if not applicable or unit.observation is None:
        return found
    for instruction in unit.observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            if operation.opcode != "CALLOTHER" or operation.output is not None or len(operation.inputs) != 1 \
                    or operation.inputs[0].kind is not VarnodeKindCode.CONSTANT:
                continue
            index = operation.inputs[0].coordinate.byte_offset
            for model in applicable:
                name = model.no_effect.get(index)
                if name is not None:
                    key = _operation_key(instruction.address, ordinal, operation.opcode)
                    found[key] = AssumedCallEffect(f"pcodeop-model:{model.file_id}/{name}@v{model.version}", ())
                    break
    return found


def trap_operations(unit, models) -> frozenset:
    """CALLOTHER keys of software traps (``traps``: e.g. x86 swi 3 / 0x29):
    for the named assumption debug-break-traps-do-not-return."""
    namespace = unit.scopes.program.evidence.translation_namespace
    language = (namespace.language_id, namespace.major_version, namespace.minor_version)
    applicable = [model for model in models if language in model.languages and model.traps]
    found = set()
    if not applicable or unit.observation is None:
        return frozenset()
    for instruction in unit.observation.instructions:
        for ordinal, operation in enumerate(instruction.operations):
            if operation.opcode != "CALLOTHER" or len(operation.inputs) != 2 \
                    or any(item.kind is not VarnodeKindCode.CONSTANT for item in operation.inputs):
                continue
            index, operand = (item.coordinate.byte_offset for item in operation.inputs)
            if any(operand in model.traps.get(index, ()) for model in applicable):
                found.add(_operation_key(instruction.address, ordinal, operation.opcode))
    return frozenset(found)


__all__ = ("PcodeOpModel", "load_pcodeop_models", "no_effect_calls", "trap_operations")
