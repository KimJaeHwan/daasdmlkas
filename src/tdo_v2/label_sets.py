"""Label sets as Python int bitsets (docs 25.31 B2-0).

A ``LabelUniverse`` numbers a fixed collection of labels once (sorted, so
the numbering is deterministic); a set of them is an int whose bit i stands
for label i. Union is ``|``, a kill ``0``, equality ``==`` -- exact, with no
fingerprint -- and the empty set ``0``. ``decode`` turns a set back into its
labels: the int is written out once in binary (C speed) and scanned for set
bits, so the Python-level work is the number of members, not the width.
"""

from __future__ import annotations


class LabelUniverse:
    __slots__ = ("labels", "bit_of")

    def __init__(self, labels) -> None:
        self.labels: tuple = tuple(sorted(set(labels)))
        self.bit_of: dict = {label: 1 << index for index, label in enumerate(self.labels)}

    def mask(self, labels) -> int:
        """The set of the given labels (labels outside the universe ignored)."""
        found = 0
        bit_of = self.bit_of
        for label in labels:
            bit = bit_of.get(label)
            if bit is not None:
                found |= bit
        return found

    def decode(self, bits: int) -> list:
        """The labels of ``bits``, in universe (sorted) order."""
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
