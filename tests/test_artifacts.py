from __future__ import annotations

import hashlib
import json
import struct

import pytest

from mkckks import SerializationError
from mkckks import _artifacts as artifacts


def checked_body(body: bytes) -> bytes:
    return body + hashlib.sha256(body).digest()


def envelope(header: bytes, native: bytes = b"payload") -> bytes:
    body = (
        artifacts.MAGIC
        + struct.pack(
            ">HHIQ",
            artifacts.FORMAT_MAJOR,
            artifacts.FORMAT_MINOR,
            len(header),
            len(native),
        )
        + header
        + native
    )
    return checked_body(body)


def versioned_envelope(major: int, minor: int) -> bytes:
    native = b"payload"
    header = json.dumps(
        {
            "artifact_id": hashlib.sha256(native).hexdigest()[:32],
            "kind": "x",
            "metadata": {},
        }
    ).encode()
    body = artifacts.MAGIC + struct.pack(">HHIQ", major, minor, len(header), len(native))
    return checked_body(body + header + native)


def test_artifact_envelope_round_trip_and_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    packed = artifacts.pack("ciphertext", {"shape": [2, 3]}, b"native")
    assert artifacts.unpack(packed, "ciphertext") == ({"shape": [2, 3]}, b"native")
    assert packed == artifacts.pack("ciphertext", {"shape": [2, 3]}, b"native")

    monkeypatch.setattr(artifacts, "MAX_HEADER", 0)
    with pytest.raises(SerializationError, match="too large"):
        artifacts.pack("ciphertext", {}, b"")


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"short", "size"),
        (artifacts.pack("x", {}, b"x")[:-1] + b"!", "checksum"),
    ],
)
def test_artifact_rejects_basic_corruption(data: bytes, message: str) -> None:
    with pytest.raises(SerializationError, match=message):
        artifacts.unpack(data, "x")


def test_artifact_rejects_structural_corruption() -> None:
    valid_header = json.dumps({"kind": "x", "metadata": {}}).encode()

    wrong_magic = bytearray(envelope(valid_header))
    wrong_magic[0] ^= 1
    with pytest.raises(SerializationError, match="checksum"):
        artifacts.unpack(bytes(wrong_magic), "x")
    wrong_magic_body = b"BADMAGIC" + bytes(wrong_magic[len(artifacts.MAGIC) : -32])
    with pytest.raises(SerializationError, match="magic"):
        artifacts.unpack(checked_body(wrong_magic_body), "x")

    oversized = artifacts.MAGIC + struct.pack(
        ">HHIQ",
        artifacts.FORMAT_MAJOR,
        artifacts.FORMAT_MINOR,
        artifacts.MAX_HEADER + 1,
        0,
    )
    with pytest.raises(SerializationError, match="fields exceed"):
        artifacts.unpack(checked_body(oversized), "x")

    bad_length = (
        artifacts.MAGIC
        + struct.pack(
            ">HHIQ",
            artifacts.FORMAT_MAJOR,
            artifacts.FORMAT_MINOR,
            len(valid_header),
            100,
        )
        + valid_header
    )
    with pytest.raises(SerializationError, match="length"):
        artifacts.unpack(checked_body(bad_length), "x")

    with pytest.raises(SerializationError, match="metadata"):
        artifacts.unpack(envelope(b"not-json"), "x")
    with pytest.raises(SerializationError, match="expected"):
        artifacts.unpack(envelope(valid_header), "other")

    list_metadata = json.dumps({"kind": "x", "metadata": []}).encode()
    with pytest.raises(SerializationError, match="must be an object"):
        artifacts.unpack(envelope(list_metadata), "x")

    wrong_id_header = json.dumps({"artifact_id": "0" * 32, "kind": "x", "metadata": {}}).encode()
    with pytest.raises(SerializationError, match="artifact ID"):
        artifacts.unpack(envelope(wrong_id_header), "x")


def test_artifact_rejects_unsupported_explicit_versions() -> None:
    with pytest.raises(SerializationError, match="major version 2"):
        artifacts.unpack(versioned_envelope(2, 0), "x")
    with pytest.raises(SerializationError, match=r"minor version 1\.1"):
        artifacts.unpack(versioned_envelope(1, 1), "x")


def test_artifact_rejects_non_object_header() -> None:
    with pytest.raises(SerializationError, match="header must be an object"):
        artifacts.unpack(envelope(b"[]"), "x")
