# SPDX-License-Identifier: MIT
"""Write the machine-readable v0.2 correctness-scope report after gates pass."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import mkckks


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    arguments = parser.parse_args()
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    report = {
        "schema_version": 1,
        "release": arguments.version,
        "commit": commit,
        "generated_at": datetime.now(UTC).isoformat(),
        "status": "passed",
        "upstream_commit": mkckks.BUILD_INFO["upstream_commit"],
        "presets": ["PN14QP439", "PN15QP880"],
        "direct_upstream_operations": [
            "encryption",
            "ciphertext_add",
            "ciphertext_subtract",
            "plaintext_add",
            "plaintext_subtract",
            "scalar_add",
            "scalar_subtract",
            "integer_scalar_multiply",
            "fractional_real_scalar_multiply",
            "complex_scalar_multiply",
            "plaintext_multiply",
            "ciphertext_multiply_normal_vs_operation_local_hoisting",
            "drop_level",
            "rescale",
            "rotation",
            "conjugation",
            "partial_and_collective_decryption",
            "level_exhaustion_circuit",
        ],
        "release_matrix": {
            "dtypes": ["float32", "float64", "complex64", "complex128", "mixed"],
            "dimensions": [1, 2, 3, 5],
            "sizes": [
                "1",
                "slots-1",
                "slots",
                "slots+1",
                "2*slots",
                "2*slots+3",
                "8*slots (PN14)",
            ],
            "party_counts": [1, 2, 4, 8],
            "rotations": [
                "0",
                "+/-1",
                "2",
                "3",
                "slots-1",
                "slots",
                "slots+1",
                "int32_min",
                "int32_max",
            ],
            "validated_maximum_component_magnitude": 2**20,
        },
        "precision_slack_bits": {"basic": 8, "rotation": 11, "multiplication": 12},
        "circuit_certification": {
            "generated_circuits": {"PN14QP439": 250, "PN15QP880": 150},
            "lengths": "3-10 operations, bounded by available levels",
            "ordered_operation_pairs_per_preset": 144,
            "intermediate_validation": True,
            "invalid_transition_fraction": 0.2,
            "range_margin_formula": (
                "sum(log2(Q[:level+1])) - log2(scale) - 1 - 3 - log2(magnitude + error)"
            ),
            "outside_range_behavior": "warn, proceed, and retain sticky status",
        },
        "correctness_statuses": [
            "WITHIN_TESTED_CONTRACT",
            "EXPERT_CONTEXT",
            "OUTSIDE_TRACKED_RANGE",
            "EXPERT_AND_OUTSIDE_RANGE",
        ],
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "native": mkckks.BUILD_INFO,
        },
        "limitations": [
            "cryptography is unaudited by this project",
            "conjugation is rejected below maximum level because pinned upstream panics",
            "validated input bounds do not guarantee cascaded intermediates remain in range",
            "outside-range descendants proceed without a project correctness claim",
            "subinterpreters and native Windows are unsupported",
        ],
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
