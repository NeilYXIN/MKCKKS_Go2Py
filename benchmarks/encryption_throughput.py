"""Measure the bounded Go worker pool on an eight-or-more-chunk encryption workload."""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import time
from pathlib import Path

import numpy as np

import mkckks


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workers", type=int, required=True)
    parser.add_argument("--chunks", type=int, default=8)
    parser.add_argument("--warmup", type=int, default=3)
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    context = mkckks.Context.create(mkckks.Parameters.preset("PN14QP439"), args.workers)
    party = mkckks.Party.generate(context, f"throughput-{args.workers}")
    size = context.slots * args.chunks
    values = np.linspace(-1, 1, size) + 1j * np.linspace(0.5, -0.5, size)

    def encrypt_once() -> int:
        started = time.perf_counter_ns()
        ciphertext = party.encrypt(values)
        elapsed = time.perf_counter_ns() - started
        ciphertext.close()
        return elapsed

    for _ in range(args.warmup):
        encrypt_once()
    samples = [encrypt_once() for _ in range(args.repetitions)]
    median = float(statistics.median(samples))
    report = {
        "schema_version": 1,
        "operation": "complex_encryption",
        "preset": "PN14QP439",
        "logical_size": size,
        "chunk_count": args.chunks,
        "workers": args.workers,
        "warmup": args.warmup,
        "repetitions": args.repetitions,
        "samples_ns": samples,
        "median_ns": median,
        "throughput_values_per_second": size / (median / 1e9),
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "numpy": np.__version__,
            "native": mkckks.BUILD_INFO,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
