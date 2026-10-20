"""Label sets as Python int bitsets (docs 25.31 B2-0).

A ``LabelUniverse`` numbers a fixed collection of labels once (sorted --
by ``key`` when given -- so the numbering is deterministic); a set of them
is an int whose bit i stands for label i. Union is ``|``, a kill ``0``,
equality ``==`` -- exact, with no fingerprint -- and the empty set ``0``.
Only the indices are kept (``index_of``): a single-bit int ``1 << i`` costs
i / 8 bytes, so keeping one per label would be quadratic in the universe;
``bit`` makes one on demand. ``decode`` turns a set back into its labels:
the int is written out once in binary (C speed) and scanned for set bits,
so the Python-level work is the number of members, not the width.
"""

from __future__ import annotations


class LabelUniverse:
    __slots__ = ("labels", "index_of")

    def __init__(self, labels, key=None) -> None:
        self.labels: tuple = tuple(sorted(set(labels), key=key))
        self.index_of: dict = {label: index for index, label in enumerate(self.labels)}

    def bit(self, label) -> int:
        """The singleton set of ``label`` (which must be in the universe)."""
        return 1 << self.index_of[label]

    def mask(self, labels) -> int:
        """The set of the given labels (labels outside the universe ignored):
        built in a byte buffer, one pass, then one conversion."""
        index_of = self.index_of
        buffer = bytearray((len(self.labels) + 7) // 8)
        for label in labels:
            index = index_of.get(label)
            if index is not None:
                buffer[index >> 3] |= 1 << (index & 7)
        return int.from_bytes(buffer, "little")

    def decode(self, bits: int) -> list:
        """The labels of ``bits``, in universe order."""
        if not bits:
            return []
        text = format(bits, "b")[::-1]   # bit i at position i
        labels = self.labels
        found = []
        index = text.find("1")
        while index >= 0:
            found.append(labels[index])
            index = text.find("1", index + 1)
        return found


__all__ = ("LabelUniverse",)
