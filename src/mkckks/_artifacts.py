"""Versioned Python metadata envelope around native binary artifacts."""

from __future__ import annotations

import hashlib
import json
import struct
from typing import Any

from .errors import SerializationError

MAGIC = b"MKPYG2\x00"
FORMAT_MAJOR = 1
FORMAT_MINOR = 0
_PREFIX = struct.Struct(">HHIQ")
MAX_HEADER = 1 << 20
MAX_ARTIFACT = 1 << 30


def pack(kind: str, metadata: dict[str, Any], native: bytes) -> bytes:
    artifact_id = hashlib.sha256(native).hexdigest()[:32]
    header = json.dumps(
        {"artifact_id": artifact_id, "kind": kind, "metadata": metadata},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    if len(header) > MAX_HEADER or len(native) > MAX_ARTIFACT:
        raise SerializationError("artifact is too large")
    body = (
        MAGIC + _PREFIX.pack(FORMAT_MAJOR, FORMAT_MINOR, len(header), len(native)) + header + native
    )
    return body + hashlib.sha256(body).digest()


def unpack(data: bytes, expected_kind: str) -> tuple[dict[str, Any], bytes]:
    if len(data) < len(MAGIC) + _PREFIX.size + 32 or len(data) > MAX_ARTIFACT:
        raise SerializationError("invalid artifact size")
    body, checksum = data[:-32], data[-32:]
    if hashlib.sha256(body).digest() != checksum:
        raise SerializationError(
            "artifact checksum mismatch; checksums detect corruption but do not authenticate data"
        )
    if not body.startswith(MAGIC):
        raise SerializationError("invalid Python artifact magic")
    major, minor, header_size, native_size = _PREFIX.unpack_from(body, len(MAGIC))
    if major != FORMAT_MAJOR:
        raise SerializationError(
            f"unsupported Python artifact major version {major}; expected {FORMAT_MAJOR}"
        )
    if minor > FORMAT_MINOR:
        raise SerializationError(
            f"unsupported Python artifact minor version {major}.{minor}; "
            f"maximum supported is {FORMAT_MAJOR}.{FORMAT_MINOR}"
        )
    if header_size > MAX_HEADER or native_size > MAX_ARTIFACT:
        raise SerializationError("artifact fields exceed configured limits")
    offset = len(MAGIC) + _PREFIX.size
    if offset + header_size + native_size != len(body):
        raise SerializationError("artifact length or trailing data is invalid")
    try:
        header = json.loads(body[offset : offset + header_size])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SerializationError("invalid artifact metadata") from exc
    if not isinstance(header, dict):
        raise SerializationError("artifact header must be an object")
    if header.get("kind") != expected_kind:
        raise SerializationError(
            f"expected {expected_kind!r} artifact, found {header.get('kind')!r}"
        )
    metadata = header.get("metadata")
    if not isinstance(metadata, dict):
        raise SerializationError("artifact metadata must be an object")
    native = body[offset + header_size :]
    artifact_id = header.get("artifact_id")
    if artifact_id != hashlib.sha256(native).hexdigest()[:32]:
        raise SerializationError("artifact ID does not match its native payload")
    return metadata, native
