"""Private ctypes bindings for the versioned cgo ABI."""

from __future__ import annotations

import ctypes
import json
import sys
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

from .errors import (
    ClosedHandleError,
    ContextMismatchError,
    InvalidParameterError,
    LevelError,
    MissingKeyError,
    MissingShareError,
    NativeError,
    SerializationError,
)

U8P = ctypes.POINTER(ctypes.c_uint8)
U64P = ctypes.POINTER(ctypes.c_uint64)
I32P = ctypes.POINTER(ctypes.c_int32)
DOUBLEP = ctypes.POINTER(ctypes.c_double)
ERRORP = ctypes.POINTER(ctypes.c_char_p)


def _library_path() -> Path:
    suffix = ".dylib" if sys.platform == "darwin" else ".so"
    path = Path(str(files("mkckks").joinpath("_native", f"libmkckks{suffix}")))
    if not path.exists():
        raise ImportError(
            f"MKCKKS native library is missing at {path}. Install a platform wheel or "
            "build from source with Go, cgo, and a C compiler."
        )
    return path


lib = ctypes.CDLL(str(_library_path()))


def _signature(name: str, args: list[Any], result: Any = ctypes.c_int32) -> Any:
    function = getattr(lib, name)
    function.argtypes = args
    function.restype = result
    return function


abi_version = _signature("mkckks_v1_abi_version", [], ctypes.c_uint32)
build_info_fn = _signature(
    "mkckks_v1_build_info", [ctypes.POINTER(U8P), ctypes.POINTER(ctypes.c_size_t), ERRORP]
)
buffer_free = _signature("mkckks_v1_buffer_free", [ctypes.c_void_p], None)
error_free = _signature("mkckks_v1_error_free", [ctypes.c_char_p], None)
release_fn = _signature("mkckks_v1_release", [ctypes.c_uint64, ERRORP])
live_handles = _signature("mkckks_v1_live_handles", [], ctypes.c_uint64)
context_create = _signature(
    "mkckks_v1_context_create", [U8P, ctypes.c_size_t, ctypes.c_int32, U64P, ERRORP]
)
context_info_fn = _signature(
    "mkckks_v1_context_info",
    [ctypes.c_uint64, ctypes.POINTER(U8P), ctypes.POINTER(ctypes.c_size_t), ERRORP],
)
party_generate = _signature(
    "mkckks_v1_party_generate", [ctypes.c_uint64, U8P, ctypes.c_size_t, U64P, ERRORP]
)
party_public_key = _signature("mkckks_v1_party_public_key", [ctypes.c_uint64, U64P, ERRORP])
encrypt_fn = _signature(
    "mkckks_v1_encrypt",
    [ctypes.c_uint64, DOUBLEP, DOUBLEP, ctypes.c_size_t, ctypes.c_uint8, U64P, ERRORP],
)
encode_plaintext_fn = _signature(
    "mkckks_v1_encode_plaintext",
    [ctypes.c_uint64, DOUBLEP, DOUBLEP, ctypes.c_size_t, ctypes.c_uint8, U64P, ERRORP],
)
add_fn = _signature("mkckks_v1_add", [ctypes.c_uint64, ctypes.c_uint64, U64P, ERRORP])
subtract_fn = _signature("mkckks_v1_subtract", [ctypes.c_uint64, ctypes.c_uint64, U64P, ERRORP])
add_scalar_fn = _signature(
    "mkckks_v1_add_scalar",
    [ctypes.c_uint64, ctypes.c_double, ctypes.c_double, ctypes.c_uint8, U64P, ERRORP],
)
add_plaintext_fn = _signature(
    "mkckks_v1_add_plaintext",
    [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint8, U64P, ERRORP],
)
multiply_scalar_fn = _signature(
    "mkckks_v1_multiply_scalar", [ctypes.c_uint64, ctypes.c_double, ctypes.c_double, U64P, ERRORP]
)
multiply_plaintext_fn = _signature(
    "mkckks_v1_multiply_plaintext", [ctypes.c_uint64, ctypes.c_uint64, U64P, ERRORP]
)
party_evaluation_keys = _signature(
    "mkckks_v1_party_evaluation_keys",
    [ctypes.c_uint64, ctypes.c_uint8, I32P, ctypes.c_size_t, ctypes.c_uint8, U64P, ERRORP],
)
evaluation_keys_combine = _signature(
    "mkckks_v1_evaluation_keys_combine", [U64P, ctypes.c_size_t, U64P, ERRORP]
)
multiply_fn = _signature(
    "mkckks_v1_multiply",
    [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint8, U64P, ERRORP],
)
drop_level_fn = _signature("mkckks_v1_drop_level", [ctypes.c_uint64, ctypes.c_int32, U64P, ERRORP])
rescale_fn = _signature("mkckks_v1_rescale", [ctypes.c_uint64, ctypes.c_double, U64P, ERRORP])
rotate_fn = _signature(
    "mkckks_v1_rotate",
    [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_int32, ctypes.c_uint8, U64P, ERRORP],
)
conjugate_fn = _signature("mkckks_v1_conjugate", [ctypes.c_uint64, ctypes.c_uint64, U64P, ERRORP])
partial_decrypt_fn = _signature(
    "mkckks_v1_partial_decrypt", [ctypes.c_uint64, ctypes.c_uint64, U64P, ERRORP]
)
collective_decrypt_fn = _signature(
    "mkckks_v1_collective_decrypt",
    [ctypes.c_uint64, U64P, ctypes.c_size_t, DOUBLEP, DOUBLEP, ctypes.c_size_t, ERRORP],
)
cipher_metadata_fn = _signature(
    "mkckks_v1_cipher_metadata",
    [ctypes.c_uint64, ctypes.POINTER(U8P), ctypes.POINTER(ctypes.c_size_t), ERRORP],
)
object_metadata_fn = _signature(
    "mkckks_v1_object_metadata",
    [ctypes.c_uint64, ctypes.POINTER(U8P), ctypes.POINTER(ctypes.c_size_t), ERRORP],
)
export_artifact_fn = _signature(
    "mkckks_v1_export_artifact",
    [ctypes.c_uint64, ctypes.POINTER(U8P), ctypes.POINTER(ctypes.c_size_t), ERRORP],
)
import_artifact_fn = _signature(
    "mkckks_v1_import_artifact",
    [ctypes.c_uint64, U8P, ctypes.c_size_t, U64P, ctypes.POINTER(ctypes.c_uint8), ERRORP],
)


_STATUS_ERRORS = {
    1: InvalidParameterError,
    2: ClosedHandleError,
    3: ContextMismatchError,
    4: MissingKeyError,
    5: LevelError,
    6: SerializationError,
    7: MissingShareError,
    255: NativeError,
}


def check(status: int, error: ctypes.c_char_p) -> None:
    if status == 0:
        return
    message = "unknown native error"
    if error.value:
        message = error.value.decode("utf-8", errors="replace")
        error_free(error)
    raise _STATUS_ERRORS.get(status, NativeError)(message)


def call_handle(function: Any, *args: Any) -> int:
    output = ctypes.c_uint64()
    error = ctypes.c_char_p()
    status = function(*args, ctypes.byref(output), ctypes.byref(error))
    check(status, error)
    return int(output.value)


def bytes_argument(data: bytes) -> tuple[Any, Any]:
    array = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
    return array, ctypes.cast(array, U8P)


def call_json(function: Any, *args: Any) -> dict[str, Any]:
    output = U8P()
    size = ctypes.c_size_t()
    error = ctypes.c_char_p()
    status = function(*args, ctypes.byref(output), ctypes.byref(size), ctypes.byref(error))
    check(status, error)
    try:
        raw = ctypes.string_at(output, size.value)
    finally:
        buffer_free(output)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise NativeError("native JSON response must be an object")
    return cast(dict[str, Any], value)


def export_artifact(handle: int) -> bytes:
    output = U8P()
    size = ctypes.c_size_t()
    error = ctypes.c_char_p()
    status = export_artifact_fn(
        handle, ctypes.byref(output), ctypes.byref(size), ctypes.byref(error)
    )
    check(status, error)
    try:
        return ctypes.string_at(output, size.value)
    finally:
        buffer_free(output)


def import_artifact(context_handle: int, data: bytes) -> tuple[int, int]:
    owner, pointer = bytes_argument(data)
    output = ctypes.c_uint64()
    kind = ctypes.c_uint8()
    error = ctypes.c_char_p()
    status = import_artifact_fn(
        context_handle,
        pointer,
        len(data),
        ctypes.byref(output),
        ctypes.byref(kind),
        ctypes.byref(error),
    )
    del owner
    check(status, error)
    return int(output.value), int(kind.value)


if abi_version() != 1:
    raise ImportError(f"Unsupported MKCKKS native ABI {abi_version()}; expected 1")


BUILD_INFO = call_json(build_info_fn)
