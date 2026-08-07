# SPDX-License-Identifier: MIT
"""Shared propagated CKKS error model for Python correctness tests."""

from __future__ import annotations

from typing import Any

import numpy as np

import mkckks


def local(
    source: mkckks.Parameters | mkckks.Ciphertext,
    operation: mkckks.PrecisionClass = mkckks.PrecisionClass.BASIC,
) -> float:
    return mkckks.precision_bound(source, operation)


def addition(result: mkckks.Ciphertext, *incoming: float) -> float:
    return sum(incoming) + local(result)


def transform(
    result: mkckks.Ciphertext,
    incoming: float,
    operation: mkckks.PrecisionClass = mkckks.PrecisionClass.BASIC,
) -> float:
    return incoming + local(result, operation)


def scalar(
    result: mkckks.Ciphertext,
    incoming: float,
    value: complex,
    *,
    fractional: bool,
) -> float:
    operation = mkckks.PrecisionClass.MULTIPLICATION if fractional else mkckks.PrecisionClass.BASIC
    return abs(value) * incoming + local(result, operation)


def product(
    result: mkckks.Ciphertext,
    left: Any,
    right: Any,
    left_error: float,
    right_error: float,
) -> float:
    left_magnitude = float(np.max(np.abs(np.asarray(left))))
    right_magnitude = float(np.max(np.abs(np.asarray(right))))
    return (
        right_magnitude * left_error
        + left_magnitude * right_error
        + left_error * right_error
        + local(result, mkckks.PrecisionClass.MULTIPLICATION)
    )


def assert_precision(actual: Any, expected: Any, bound: float) -> None:
    report = mkckks.measure_precision(actual, expected)
    assert report.maximum_real_error <= bound
    assert report.maximum_imaginary_error <= bound
