"""An exact, fixed-width scalar bit pattern, separate from pointer provenance."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ExactConstant:
    byte_size: int
    unsigned: int

    def __post_init__(self) -> None:
        if type(self.byte_size) is not int or type(self.unsigned) is not int:
            raise TypeError("constant width and value must be exact ints")
        if not 1 <= self.byte_size <= 16:
            raise ValueError("constant width must be between 1 and 16 bytes")
        if not 0 <= self.unsigned < 1 << (8 * self.byte_size):
            raise ValueError("constant value must fit its unsigned width")
