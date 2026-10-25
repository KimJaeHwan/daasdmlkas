"""One bounded callee-entry address relation, not a general expression IR."""

from dataclasses import dataclass

from .span_geometry import ByteSpan


def _validate_offset(byte_size, extend, preoffset, scale) -> None:
    if type(byte_size) is not int:
        raise TypeError("index source width must be an exact int")
    if type(extend) is not str or (byte_size, extend) not in ((8, "identity"), (4, "sext"), (4, "zext")):
        raise ValueError("index must be identity8 or sext/zext4 to 8 bytes")
    if type(preoffset) is not int or type(scale) is not int:
        raise TypeError("index preoffset and scale must be exact ints")
    if not 0 <= preoffset < 1 << (8 * byte_size):
        raise ValueError("index preoffset must fit its unsigned source width")
    if not -(1 << 63) <= scale < 1 << 63 or scale == 0:
        raise ValueError("index scale must be a nonzero signed 64-bit integer")


@dataclass(frozen=True, slots=True)
class IndexedAnchor:
    """base + scale * extend(index + preoffset), with source-width addition.

    Both spans denote original function-entry values. The caller adds the
    relative object's ordinary displacement only after this relation.
    """

    base: ByteSpan
    index: ByteSpan
    space_id: int
    extend: str
    preoffset: int
    scale: int

    def __post_init__(self) -> None:
        if type(self.base) is not ByteSpan or type(self.index) is not ByteSpan:
            raise TypeError("indexed base and index must be exact ByteSpans")
        if self.base.size != 8:
            raise ValueError("indexed base must be 8 bytes")
        if type(self.space_id) is not int:
            raise TypeError("indexed memory space must be an exact int")
        if self.space_id < 0:
            raise ValueError("indexed memory space must be nonnegative")
        _validate_offset(self.index.size, self.extend, self.preoffset, self.scale)
