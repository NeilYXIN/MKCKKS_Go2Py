"""Traceable CKKS approximation measurements used by tests and examples."""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, overload

import numpy as np

if TYPE_CHECKING:
    from .api import Ciphertext, Parameters


class PrecisionClass(StrEnum):
    """Operation classes matching the pinned upstream test formulas."""

    BASIC = "basic"
    ROTATION = "rotation"
    MULTIPLICATION = "multiplication"


_SLACK_BITS = {
    PrecisionClass.BASIC: 8,
    PrecisionClass.ROTATION: 11,
    PrecisionClass.MULTIPLICATION: 12,
}


@overload
def precision_bound(source: Parameters, operation: PrecisionClass) -> float: ...


@overload
def precision_bound(source: Ciphertext, operation: PrecisionClass) -> float: ...


def precision_bound(source: Parameters | Ciphertext, operation: PrecisionClass) -> float:
    """Return the absolute per-component CKKS conformance bound.

    A :class:`Parameters` argument uses its configured initial scale. A
    :class:`Ciphertext` argument uses the ciphertext's actual current scale,
    which is the appropriate form after multiplication or explicit rescaling.
    """
    selected = PrecisionClass(operation)
    if hasattr(source, "context"):
        scale = float(source.scale)
        log_slots = int(source.context.parameters.log_slots)
    else:
        scale = float(source.scale)
        log_slots = int(source.log_slots)
    if not math.isfinite(scale) or scale <= 0:
        raise ValueError("scale must be finite and positive")
    return math.exp2(-math.log2(scale) + log_slots + _SLACK_BITS[selected])


@dataclass(frozen=True)
class PrecisionReport:
    """Error measurements with real and imaginary components kept separate."""

    maximum_real_error: float
    maximum_imaginary_error: float
    rms_error: float
    minimum_precision_bits: float
    sample_count: int

    @property
    def maximum_component_error(self) -> float:
        return max(self.maximum_real_error, self.maximum_imaginary_error)


def measure_precision(actual: Any, expected: Any) -> PrecisionReport:
    """Measure approximation error without rounding or hiding the imaginary component."""
    actual_array = np.asarray(actual, dtype=np.complex128)
    expected_array = np.asarray(expected, dtype=np.complex128)
    if actual_array.shape != expected_array.shape or actual_array.size == 0:
        raise ValueError("actual and expected must be non-empty arrays with identical shapes")
    error = actual_array - expected_array
    maximum_real = float(np.max(np.abs(error.real)))
    maximum_imaginary = float(np.max(np.abs(error.imag)))
    magnitude = np.abs(error)
    rms = float(np.sqrt(np.mean(magnitude * magnitude)))
    maximum = max(maximum_real, maximum_imaginary)
    bits = math.inf if maximum == 0 else -math.log2(maximum)
    return PrecisionReport(maximum_real, maximum_imaginary, rms, bits, actual_array.size)
