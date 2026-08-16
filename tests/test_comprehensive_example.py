# SPDX-License-Identifier: MIT
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _clean_subprocess_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("COVERAGE_", "COV_CORE_"))
    }


def test_check_script_validates_selected_stages() -> None:
    root = Path(__file__).resolve().parents[1]
    for invalid_stage in ("not-a-stage", ""):
        rejected = subprocess.run(
            ["bash", "scripts/check.sh", invalid_stage],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env=_clean_subprocess_environment(),
        )
        assert rejected.returncode == 2
        assert "Unknown check stage" in rejected.stderr

    selected = subprocess.run(
        ["bash", "scripts/check.sh", "upstream"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=_clean_subprocess_environment(),
    )
    assert selected.returncode == 0, selected.stderr
    assert "==> upstream" in selected.stdout
    assert "==> go" not in selected.stdout


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
        env=_clean_subprocess_environment(),
    )
    assert completed.returncode == 0, completed.stderr
    assert "[three-party ciphertext addition]" in completed.stdout
    assert "[rotate each chunk left by one]" in completed.stdout
    assert "[concatenated circuit]" in completed.stdout
    assert "All comprehensive MKCKKS checks passed" in completed.stdout


def test_original_notebook_verification(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run(
        [
            sys.executable,
            str(root / "examples" / "original_notebook_verification.py"),
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
        env=_clean_subprocess_environment(),
    )
    assert completed.returncode == 0, completed.stderr
    assert "ct4: weights1 + weights2" in completed.stdout
    assert "ct5: weights1 + weights2 + weights3" in completed.stdout
    assert "ct6: (weights1 + weights2 + weights3) * 2.5" in completed.stdout
    assert completed.stdout.count("Result: PASS") == 6
    assert "All computations from the original notebook passed" in completed.stdout
