"""Structural projection from observed effects to local memory actions."""

from .effects import EffectKind as _EffectKind
from .effects import ObservedEffectUnit as _ObservedEffectUnit
from .effects import UnresolvedMemoryAccess as _UnresolvedMemoryAccess
from .memory_contracts import LOCAL_MEMORY_CONTRACT_VERSION as _CONTRACT_VERSION
from .memory_contracts import LocalMemoryBlock as _LocalMemoryBlock
from .memory_contracts import LocalMemoryUnit as _LocalMemoryUnit
from .memory_contracts import LocalStorageAction as _LocalStorageAction
from .memory_contracts import MemoryWriteMode as _MemoryWriteMode
from .model import ResolvedStorage as _ResolvedStorage
from .model import StorageRef as _StorageRef


__all__ = ("decode_effect_unit",)


def decode_effect_unit(
    unit: _ObservedEffectUnit, /
) -> _LocalMemoryUnit:
    """Project one exact observed-effect unit without interpreting identities."""
    if type(unit) is not _ObservedEffectUnit:
        raise TypeError("unit must be an exact ObservedEffectUnit")

    blocks: list[_LocalMemoryBlock] = []
    for block in unit.blocks:
        actions: list[_LocalStorageAction] = []
        for effect in block.effects:
            reads = tuple(
                value.span
                for value in effect.reads
                if type(value) is _ResolvedStorage
            )
            writes = tuple(
                value.span
                for value in effect.writes
                if type(value) is _ResolvedStorage
            )

            raw_reads = tuple(
                _UnresolvedMemoryAccess(
                    address=value,
                    width=value.size,
                    raw_address=None,
                )
                for value in effect.reads
                if type(value) is _StorageRef
            )
            raw_writes = tuple(
                _UnresolvedMemoryAccess(
                    address=value,
                    width=value.size,
                    raw_address=None,
                )
                for value in effect.writes
                if type(value) is _StorageRef
            )
            memory_reads = (
                () if effect.memory_read is None else (effect.memory_read,)
            )
            memory_writes = (
                () if effect.memory_write is None else (effect.memory_write,)
            )

            write_mode = None
            if writes:
                write_mode = (
                    _MemoryWriteMode.KILL
                    if effect.kind is _EffectKind.KILL
                    else _MemoryWriteMode.DATA
                )

            actions.append(
                _LocalStorageAction(
                    operation_key=effect.operation_key,
                    reads=reads,
                    writes=writes,
                    unresolved_reads=(
                        effect.unresolved_reads + raw_reads + memory_reads
                    ),
                    unresolved_writes=(
                        effect.unresolved_writes + raw_writes + memory_writes
                    ),
                    write_mode=write_mode,
                )
            )
        blocks.append(
            _LocalMemoryBlock(
                key=block.key,
                predecessors=block.predecessors,
                actions=tuple(actions),
            )
        )

    return _LocalMemoryUnit(
        contract_version=_CONTRACT_VERSION,
        function_scope=unit.function_scope,
        entry_block_key=unit.entry_block_key,
        blocks=tuple(blocks),
        observed_terminal_block_keys=unit.observed_terminal_block_keys,
        effect_evidence_digest=unit.effect_evidence_digest,
    )
