"""Composed value-projection behavior for a configured function view."""

from .configured_function_coordinate_values import _FunctionCoordinateValueMixin
from .configured_function_integer_values import _FunctionIntegerValueMixin
from .configured_function_pointer_values import _FunctionPointerValueMixin


class _FunctionValueProjectionMixin(
    _FunctionIntegerValueMixin,
    _FunctionPointerValueMixin,
    _FunctionCoordinateValueMixin,
):
    pass


__all__ = ["_FunctionValueProjectionMixin"]
