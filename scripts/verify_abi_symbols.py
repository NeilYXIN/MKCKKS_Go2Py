"""Fail when the versioned native ABI symbol surface changes unexpectedly."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from mkckks import _native

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = set((ROOT / "abi" / "symbols-v1.txt").read_text().splitlines())
MANIFEST = ROOT / "abi" / "test-manifest-v1.json"


def main() -> None:
    library = _native._library_path()
    command = (
        ["nm", "-gU", str(library)]
        if sys.platform == "darwin"
        else [
            "nm",
            "-D",
            "--defined-only",
            str(library),
        ]
    )
    output = subprocess.run(command, check=True, capture_output=True, text=True).stdout
    actual: set[str] = set()
    for line in output.splitlines():
        symbol = line.rsplit(maxsplit=1)[-1]
        if symbol.startswith("_mkckks_v1_"):
            symbol = symbol[1:]
        if symbol.startswith("mkckks_v1_"):
            actual.add(symbol)
    if actual != EXPECTED:
        missing = sorted(EXPECTED - actual)
        added = sorted(actual - EXPECTED)
        raise SystemExit(f"ABI v1 symbol mismatch; missing={missing}, added={added}")
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    covered = set(manifest.get("symbols", {}))
    if covered != EXPECTED:
        missing = sorted(EXPECTED - covered)
        added = sorted(covered - EXPECTED)
        raise SystemExit(f"ABI test manifest mismatch; missing={missing}, added={added}")
    for symbol, evidence in manifest["symbols"].items():
        if not evidence.get("success") or "failure" not in evidence:
            raise SystemExit(f"ABI test manifest has incomplete evidence for {symbol}")
    print(f"ABI v1 symbol and test-evidence snapshots verified ({len(actual)} symbols)")


if __name__ == "__main__":
    main()
