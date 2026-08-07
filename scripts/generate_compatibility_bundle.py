# SPDX-License-Identifier: MIT
"""Generate the v0.2 serialization baseline bundle for future release tests."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import tarfile
import tempfile
import warnings
from contextlib import ExitStack
from pathlib import Path
from typing import Any

import numpy as np

import mkckks
from mkckks import _artifacts


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generate(output: Path, preset: str, version: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    archive_root = f"mkckks-compatibility-{version}"
    staging = Path(tempfile.mkdtemp(prefix=f".{archive_root}-", dir=output.parent))
    values = np.array([[0.125 + 0.25j, -0.5], [0.75 - 0.125j, 0.0]])

    with ExitStack() as stack:
        context = stack.enter_context(
            mkckks.Context.create(mkckks.Parameters.preset(preset), workers=1)
        )
        party = stack.enter_context(mkckks.Party.generate(context, "compatibility-party"))
        public_key = stack.enter_context(party.public_key)
        plaintext = stack.enter_context(context.encode(values))
        ciphertext = stack.enter_context(public_key.encrypt(values))
        contribution = stack.enter_context(party.generate_evaluation_keys())
        keyset = stack.enter_context(mkckks.EvaluationKeySet.combine(context, [contribution]))
        share = stack.enter_context(party.partial_decrypt(ciphertext))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            private_state = party.export_private_state()

        artifacts: dict[str, bytes] = {
            "context.mkckks": context.to_bytes(),
            "private-party.mkckks": private_state,
            "public-key.mkckks": public_key.to_bytes(),
            "plaintext.mkckks": plaintext.to_bytes(),
            "ciphertext.mkckks": ciphertext.to_bytes(),
            "evaluation-key-contribution.mkckks": contribution.to_bytes(),
            "evaluation-key-set.mkckks": keyset.to_bytes(),
            "decryption-share.mkckks": share.to_bytes(),
        }

    for name, data in artifacts.items():
        (staging / name).write_bytes(data)
    manifest: dict[str, Any] = {
        "release": version,
        "preset": preset,
        "python_envelope": {
            "major": _artifacts.FORMAT_MAJOR,
            "minor": _artifacts.FORMAT_MINOR,
        },
        "files": {
            path.name: {"bytes": path.stat().st_size, "sha256": digest(path)}
            for path in sorted(staging.glob("*.mkckks"))
        },
    }
    (staging / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (
        output.open("wb") as raw_output,
        gzip.GzipFile(filename="", mode="wb", fileobj=raw_output, mtime=0) as compressed,
        tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive,
    ):
        for path in sorted(staging.iterdir()):
            info = archive.gettarinfo(str(path), arcname=f"{archive_root}/{path.name}")
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            with path.open("rb") as stream:
                archive.addfile(info, stream)
    shutil.rmtree(staging)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--preset", default="PN14QP439")
    parser.add_argument("--version", required=True)
    arguments = parser.parse_args()
    generate(arguments.output, arguments.preset, arguments.version)


if __name__ == "__main__":
    main()
