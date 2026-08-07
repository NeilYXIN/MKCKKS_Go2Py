# SPDX-License-Identifier: MIT
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_comprehensive_example(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [
            sys.executable,
            str(root / "examples" / "comprehensive.py"),
            "--workers",
            "2",
            "--skip-serialization",
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
        env={
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("COVERAGE_", "COV_CORE_"))
        },
    )
    assert completed.returncode == 0, completed.stderr
    assert "[three-party ciphertext addition]" in completed.stdout
    assert "[rotate each chunk left by one]" in completed.stdout
    assert "[concatenated circuit]" in completed.stdout
    assert "All comprehensive MKCKKS checks passed" in completed.stdout
