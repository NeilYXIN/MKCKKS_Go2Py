# SPDX-License-Identifier: MIT
"""Focused public-API benchmark for v0.2 release-relevant workflows."""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import time
from collections.abc import Callable
from contextlib import ExitStack
from pathlib import Path
from typing import Any

import numpy as np
import psutil

import mkckks


def sample(operation: Callable[[], None], warmup: int, repetitions: int) -> dict[str, Any]:
    for _ in range(warmup):
        operation()
    values: list[int] = []
    for _ in range(repetitions):
        started = time.perf_counter_ns()
        operation()
        values.append(time.perf_counter_ns() - started)
    ordered = sorted(values)
    return {
        "samples_ns": values,
        "median_ns": statistics.median(values),
        "sample_percentile_interval_95_ns": [ordered[0], ordered[-1]],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=2)
    arguments = parser.parse_args()
    parameters = mkckks.Parameters.preset("PN14QP439")
    process = psutil.Process()

    with ExitStack() as stack:
        context = stack.enter_context(mkckks.Context.create(parameters, workers=1))
        party = stack.enter_context(mkckks.Party.generate(context, "workflow-benchmark"))
        contribution = stack.enter_context(
            party.generate_evaluation_keys(rotations=[1], conjugation=True)
        )
        keyset = stack.enter_context(mkckks.EvaluationKeySet.combine(context, [contribution]))
        evaluator = mkckks.Evaluator(context, keyset)
        real_values = np.linspace(-1.0, 1.0, 1024)
        complex_values = real_values + 0.25j * real_values[::-1]
        real_ciphertext = stack.enter_context(party.encrypt(real_values))
        complex_ciphertext = stack.enter_context(party.encrypt(complex_values))

        def encrypt_real() -> None:
            party.encrypt(real_values).close()

        def encrypt_complex() -> None:
            party.encrypt(complex_values).close()

        def decrypt_complex() -> None:
            with party.partial_decrypt(complex_ciphertext) as share:
                context.collective_decrypt(complex_ciphertext, [share])

        def conjugate() -> None:
            evaluator.conjugate(complex_ciphertext).close()

        def serialize() -> None:
            assert complex_ciphertext.to_bytes()

        rss_before = process.memory_info().rss
        results = {
            "real_encrypt": sample(encrypt_real, arguments.warmup, arguments.repetitions),
            "complex_encrypt": sample(encrypt_complex, arguments.warmup, arguments.repetitions),
            "partial_and_collective_decrypt": sample(
                decrypt_complex, arguments.warmup, arguments.repetitions
            ),
            "conjugate": sample(conjugate, arguments.warmup, arguments.repetitions),
            "ciphertext_serialize": sample(serialize, arguments.warmup, arguments.repetitions),
        }
        assert real_ciphertext.shape == real_values.shape
        rss_after = process.memory_info().rss

    def create_context_and_keys() -> None:
        with ExitStack() as local_stack:
            local_context = local_stack.enter_context(mkckks.Context.create(parameters, workers=1))
            local_party = local_stack.enter_context(
                mkckks.Party.generate(local_context, "context-key-benchmark")
            )
            local_contribution = local_stack.enter_context(
                local_party.generate_evaluation_keys(rotations=[1], conjugation=True)
            )
            local_stack.enter_context(
                mkckks.EvaluationKeySet.combine(local_context, [local_contribution])
            )

    results["context_and_key_generation"] = sample(
        create_context_and_keys, 0, min(arguments.repetitions, 3)
    )
    report = {
        "schema_version": 1,
        "preset": "PN14QP439",
        "logical_size": 1024,
        "warmup": arguments.warmup,
        "repetitions": arguments.repetitions,
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "numpy": np.__version__,
            "native": mkckks.BUILD_INFO,
        },
        "results": results,
        "peak_rss_bytes": max(rss_before, rss_after),
        "rss_delta_bytes": rss_after - rss_before,
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
