"""Random ``LocalMemoryUnit`` inputs for memory SSA engine equivalence tests.

Covers what an alternative (sparse) engine can get wrong: partial overlaps
between reads and writes of different widths, several objects (register
file, unique, address space, function-relative), KILL writes, unresolved
accesses, back edges (including to the entry block and self loops), p-code
sub-block keys (``addr#n``), multiple terminal blocks, and long straight
chains.
"""

from __future__ import annotations

import random

from tdo_v2.effects import UnresolvedMemoryAccess
from tdo_v2.memory_contracts import (
    LOCAL_MEMORY_CONTRACT_VERSION,
    LocalMemoryBlock,
    LocalMemoryUnit,
    LocalStorageAction,
    MemoryWriteMode,
)
from tdo_v2.span_geometry import (
    ByteSpan, StorageObjectId, StorageObjectKind, StorageScopeId, StorageScopeKind,
)

FUNCTION_SCOPE = StorageScopeId(StorageScopeKind.FUNCTION, b"\x01" * 32)
PROGRAM_SCOPE = StorageScopeId(StorageScopeKind.PROGRAM, b"\x02" * 32)
OBJECTS = (
    StorageObjectId(StorageObjectKind.REGISTER_FILE, PROGRAM_SCOPE, 0),
    StorageObjectId(StorageObjectKind.FUNCTION_UNIQUE, FUNCTION_SCOPE, 0),
    StorageObjectId(StorageObjectKind.ADDRESS_SPACE, PROGRAM_SCOPE, 1),
    StorageObjectId(StorageObjectKind.FUNCTION_RELATIVE, FUNCTION_SCOPE, 7),
)


def _span(rng: random.Random) -> ByteSpan:
    obj = rng.choice(OBJECTS)
    size = rng.choice((1, 2, 4, 8))
    return ByteSpan(obj, rng.randrange(0, 40), size)


def _disjoint_writes(rng: random.Random, count: int) -> tuple[ByteSpan, ...]:
    writes: list[ByteSpan] = []
    for _ in range(count * 3):
        if len(writes) == count:
            break
        span = _span(rng)
        if not any(span.overlaps(item) for item in writes):
            writes.append(span)
    return tuple(writes)


def _action(rng: random.Random, key: str) -> LocalStorageAction:
    kind = rng.random()
    unresolved = (UnresolvedMemoryAccess(None, rng.choice((1, 4, 8))),)
    if kind < 0.12:  # kill write: no reads
        return LocalStorageAction(key, writes=_disjoint_writes(rng, rng.randint(1, 2)),
                                  write_mode=MemoryWriteMode.KILL)
    reads = tuple(_span(rng) for _ in range(rng.randint(0, 2)))
    writes = _disjoint_writes(rng, rng.choice((0, 0, 1, 1, 2)))
    return LocalStorageAction(
        key,
        reads=reads,
        writes=writes,
        unresolved_reads=unresolved if rng.random() < 0.08 else (),
        unresolved_writes=unresolved if rng.random() < 0.06 else (),
        write_mode=MemoryWriteMode.DATA if writes else None,
    )


def random_unit(seed: int, *, max_blocks: int = 14) -> LocalMemoryUnit:
    rng = random.Random(seed)
    count = rng.randint(1, max_blocks)
    keys = []
    address = 0x1000
    for index in range(count):
        if index and rng.random() < 0.15:  # a p-code sub-block of the previous instruction
            keys.append(f"1:{address:x}#{rng.randint(1, 9)}")
        else:
            address += rng.choice((1, 2, 4, 7))
            keys.append(f"1:{address:x}")
    keys = list(dict.fromkeys(keys))
    predecessors: dict[str, set[str]] = {key: set() for key in keys}
    for index, key in enumerate(keys[1:], start=1):
        predecessors[key].add(keys[index - 1])  # keeps every block reachable
    for _ in range(rng.randint(0, count)):
        source, target = rng.choice(keys), rng.choice(keys)  # forward, back, self, to entry
        predecessors[target].add(source)
    blocks = []
    serial = 0
    for key in keys:
        actions = []
        for _ in range(rng.randint(0, 4)):
            serial += 1
            actions.append(_action(rng, f"{key}:{serial}:OP"))
        blocks.append(LocalMemoryBlock(key, tuple(sorted(predecessors[key])), tuple(actions)))
    successors = {key: set() for key in keys}
    for key, sources in predecessors.items():
        for source in sources:
            successors[source].add(key)
    terminals = {key for key in keys if not successors[key]} | {keys[-1]}
    terminals |= {key for key in keys if rng.random() < 0.1}
    rng.shuffle(blocks)  # block order must not matter
    return LocalMemoryUnit(
        LOCAL_MEMORY_CONTRACT_VERSION,
        FUNCTION_SCOPE,
        keys[0],
        tuple(blocks),
        tuple(sorted(terminals)),
        effect_evidence_digest=b"\x03" * 32,
    )
