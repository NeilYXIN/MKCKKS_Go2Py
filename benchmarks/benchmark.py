"""Versioned C ABI versus public-Python add/multiply/rotate benchmark."""

from __future__ import annotations

import argparse
import ctypes
import json
import platform
import statistics
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import numpy as np
import psutil

import mkckks
from mkckks import _native


def timings(operation: Callable[[], None], warmup: int, repetitions: int) -> list[int]:
    for _ in range(warmup):
        operation()
    samples: list[int] = []
    for _ in range(repetitions):
        started = time.perf_counter_ns()
        operation()
        samples.append(time.perf_counter_ns() - started)
    return samples


def summary(samples: list[int]) -> dict[str, Any]:
    ordered = sorted(samples)
    low = ordered[max(0, round(0.025 * (len(ordered) - 1)))]
    high = ordered[min(len(ordered) - 1, round(0.975 * (len(ordered) - 1)))]
    return {
        "samples_ns": samples,
        "median_ns": statistics.median(samples),
        "mean_ns": statistics.fmean(samples),
        "sample_percentile_interval_95_ns": [low, high],
    }


def median_ratio_interval(
    numerator: list[int], denominator: list[int], resamples: int = 10_000
) -> list[float]:
    generator = np.random.default_rng(0)
    numerator_array = np.asarray(numerator)
    denominator_array = np.asarray(denominator)
    ratios = np.empty(resamples)
    for index in range(resamples):
        sampled_numerator = generator.choice(numerator_array, len(numerator_array), replace=True)
        sampled_denominator = generator.choice(
            denominator_array, len(denominator_array), replace=True
        )
        ratios[index] = np.median(sampled_numerator) / np.median(sampled_denominator)
    return [float(value) for value in np.quantile(ratios, [0.025, 0.975])]


def release_native(handle: int) -> None:
    error = ctypes.c_char_p()
    _native.check(_native.release_fn(handle, ctypes.byref(error)), error)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preset", default="PN14QP439")
    parser.add_argument("--size", type=int, default=1024)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--repetitions", type=int, default=30)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    context = mkckks.Context.create(mkckks.Parameters.preset(args.preset), args.workers)
    party = mkckks.Party.generate(context, "benchmark-party")
    values = np.linspace(-1, 1, args.size) + 1j * np.linspace(0.5, -0.5, args.size)
    left, right = party.encrypt(values), party.encrypt(values[::-1].copy())
    contribution = party.generate_evaluation_keys(relinearization=True, rotations=[1])
    keyset = mkckks.EvaluationKeySet.combine(context, [contribution])
    evaluator = mkckks.Evaluator(context, keyset)

    def python_add() -> None:
        result = evaluator.add(left, right)
        result.close()

    def abi_add() -> None:
        handle = _native.call_handle(_native.add_fn, left._native_handle, right._native_handle)
        release_native(handle)

    def python_multiply() -> None:
        result = evaluator.multiply(left, right)
        result.close()

    def abi_multiply() -> None:
        handle = _native.call_handle(
            _native.multiply_fn,
            keyset._native_handle,
            left._native_handle,
            right._native_handle,
            0,
        )
        release_native(handle)

    def python_rotate() -> None:
        result = evaluator.rotate_slots(left, 1)
        result.close()

    def abi_rotate() -> None:
        handle = _native.call_handle(
            _native.rotate_fn,
            keyset._native_handle,
            left._native_handle,
            1,
            0,
        )
        release_native(handle)

    process = psutil.Process()
    operations = {
        "add": (abi_add, python_add),
        "multiply": (abi_multiply, python_multiply),
        "rotate": (abi_rotate, python_rotate),
    }
    for abi_operation, python_operation in operations.values():
        for _ in range(args.warmup):
            abi_operation()
            python_operation()
    rss_before = process.memory_info().rss
    operation_reports: dict[str, Any] = {}
    for name, (abi_operation, python_operation) in operations.items():
        abi_samples = timings(abi_operation, 0, args.repetitions)
        python_samples = timings(python_operation, 0, args.repetitions)
        abi_median = float(statistics.median(abi_samples))
        python_median = float(statistics.median(python_samples))
        operation_reports[name] = {
            "c_abi": summary(abi_samples),
            "python": summary(python_samples),
            "python_to_c_abi_median_ratio": python_median / abi_median,
            "python_to_c_abi_median_ratio_confidence_interval_95": median_ratio_interval(
                python_samples, abi_samples
            ),
        }
    rss_after = process.memory_info().rss

    report = {
        "schema_version": 1,
        "operations": ["add", "multiply", "rotate"],
        "preset": args.preset,
        "party_count": 1,
        "logical_size": args.size,
        "chunk_count": left.chunks,
        "workers": args.workers,
        "warmup": args.warmup,
        "repetitions": args.repetitions,
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python": platform.python_version(),
            "numpy": np.__version__,
            "native": mkckks.BUILD_INFO,
            "go": subprocess.run(
                ["go", "version"], check=True, capture_output=True, text=True
            ).stdout.strip(),
        },
        "results": operation_reports,
        "rss_bytes": {"before": rss_before, "after": rss_after, "delta": rss_after - rss_before},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
