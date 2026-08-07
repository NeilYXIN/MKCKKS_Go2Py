#!/usr/bin/env python3
"""Verify that the vendored MKHE-KKLSS snapshot is byte-for-byte unchanged."""

from __future__ import annotations

import hashlib
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "UPSTREAM.lock"


def digest_path(path: Path) -> tuple[int, str]:
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
    digest = hashlib.sha256()
    for file_path in files:
        relative = file_path.relative_to(ROOT).as_posix().encode()
        data = file_path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return len(files), digest.hexdigest()


def main() -> int:
    config = tomllib.loads(LOCK.read_text())
    failures: list[str] = []
    for name, expected in config["paths"].items():
        path = ROOT / name
        if not path.exists():
            failures.append(f"missing protected path: {name}")
            continue
        count, actual = digest_path(path)
        if count != expected["files"] or actual != expected["sha256"]:
            failures.append(
                f"{name}: expected {expected['files']} files/{expected['sha256']}, "
                f"found {count} files/{actual}"
            )
    manifest = config["files"]
    protected_files = {
        path.relative_to(ROOT).as_posix()
        for name in config["paths"]
        for path in ([ROOT / name] if (ROOT / name).is_file() else (ROOT / name).rglob("*"))
        if path.is_file()
    }
    if protected_files != set(manifest):
        missing = sorted(set(manifest) - protected_files)
        added = sorted(protected_files - set(manifest))
        failures.append(f"per-file manifest mismatch; missing={missing}, added={added}")
    for name, expected in manifest.items():
        path = ROOT / name
        if path.is_file():
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != expected:
                failures.append(f"{name}: expected SHA-256 {expected}, found {actual}")
    if failures:
        print("Upstream integrity check FAILED", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Upstream integrity verified at {config['commit']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
