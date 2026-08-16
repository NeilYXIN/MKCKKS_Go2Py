"""NumPy-first public API for the MKCKKS native bridge."""

from __future__ import annotations

import ctypes
import json
import math
import operator
import os
import warnings
import weakref
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field, replace
from enum import StrEnum
from typing import Any, ClassVar, Self

import numpy as np
import numpy.typing as npt

from . import _native
from ._artifacts import pack as _pack_artifact
from ._artifacts import unpack as _unpack_artifact
from .errors import (
    ContextMismatchError,
    CorrectnessRangeWarning,
    ForkSafetyError,
    InvalidDTypeError,
    InvalidParameterError,
    SerializationError,
    ShapeMismatchError,
)

PN14QP439 = {
    "log_n": 14,
    "log_slots": 13,
    "q": [
        0x7FFFFFFFFE70001,
        0xFFFFFFFF00001,
        0xFFFFFFFE40001,
        0xFFFFFFFE20001,
        0xFFFFFFFBE0001,
        0xFFFFFFFA60001,
    ],
    "p": [0xFFFFFFFFFFC0001, 0xFFFFFFFFF840001],
    "scale": float(1 << 52),
    "sigma": 3.2,
}

PN15QP880 = {
    "log_n": 15,
    "log_slots": 14,
    "q": [
        0xFFFFFFFFF6A0001,
        0x3FFFFFFFD60001,
        0x3FFFFFFFCA0001,
        0x3FFFFFFF6D0001,
        0x3FFFFFFF5D0001,
        0x3FFFFFFF550001,
        0x3FFFFFFF390001,
        0x3FFFFFFF360001,
        0x3FFFFFFF2A0001,
        0x3FFFFFFF000001,
        0x3FFFFFFEFA0001,
        0x3FFFFFFEF40001,
        0x3FFFFFFED70001,
        0x3FFFFFFED30001,
    ],
    "p": [0x7FFFFFFFFE70001, 0x7FFFFFFFFE10001],
    "scale": float(1 << 54),
    "sigma": 3.2,
}

HARD_MAX_CHUNKS = 64
HARD_MAX_VALUES = 1 << 26
HARD_MAX_ARTIFACT_BYTES = 1 << 30
VALIDATED_COMPONENT_BOUND = float(1 << 20)


class InputPolicy(StrEnum):
    """Controls whether inputs must remain inside the tested preset envelope."""

    VALIDATED = "validated"
    EXPERT = "expert"


class CorrectnessStatus(StrEnum):
    """Whether an object remains inside the project's tested arithmetic contract."""

    WITHIN_TESTED_CONTRACT = "within_tested_contract"
    EXPERT_CONTEXT = "expert_context"
    OUTSIDE_TRACKED_RANGE = "outside_tracked_range"
    EXPERT_AND_OUTSIDE_RANGE = "expert_and_outside_range"


@dataclass(frozen=True)
class ResourceLimits:
    """Local denial-of-service limits applied before entering native code."""

    max_chunks: int = 64
    max_values: int = HARD_MAX_VALUES
    max_artifact_bytes: int = HARD_MAX_ARTIFACT_BYTES

    def __post_init__(self) -> None:
        """Reject limits that are not positive integers within the hard caps."""
        for name, value, maximum in (
            ("max_chunks", self.max_chunks, HARD_MAX_CHUNKS),
            ("max_values", self.max_values, HARD_MAX_VALUES),
            ("max_artifact_bytes", self.max_artifact_bytes, HARD_MAX_ARTIFACT_BYTES),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
                raise InvalidParameterError(f"{name} must be an integer between 1 and {maximum}")


@dataclass(frozen=True)
class Parameters:
    """An upstream-tested or expert-provided CKKS parameter literal."""

    log_n: int
    log_slots: int
    q: tuple[int, ...]
    p: tuple[int, ...]
    scale: float
    sigma: float
    _preset_name: str | None = field(default=None, repr=False, compare=False)

    _PRESETS: ClassVar[dict[str, dict[str, Any]]] = {
        "PN14QP439": PN14QP439,
        "PN15QP880": PN15QP880,
    }

    @classmethod
    def preset(cls, name: str) -> Parameters:
        """Return one of the parameter literals exercised by upstream tests."""
        if not isinstance(name, str):
            raise InvalidParameterError("preset name must be a string")
        normalized = name.upper()
        try:
            value = cls._PRESETS[normalized]
        except KeyError as exc:
            raise InvalidParameterError(
                f"unknown preset {name!r}; choose PN14QP439 or PN15QP880"
            ) from exc
        return replace(cls.from_literal(**value), _preset_name=normalized)

    @classmethod
    def from_literal(
        cls,
        *,
        log_n: int,
        log_slots: int,
        q: Sequence[int],
        p: Sequence[int],
        scale: float,
        sigma: float,
    ) -> Parameters:
        """Construct expert parameters; native Lattigo validation occurs at context creation."""
        if isinstance(log_n, bool) or isinstance(log_slots, bool):
            raise InvalidParameterError("log_n and log_slots must be integers")
        try:
            log_n = operator.index(log_n)
            log_slots = operator.index(log_slots)
        except TypeError as exc:
            raise InvalidParameterError("log_n and log_slots must be integers") from exc
        if not 1 <= log_slots < log_n <= 20:
            raise InvalidParameterError("require 1 <= log_slots < log_n <= 20")
        if not 1 <= len(q) <= 64 or not 2 <= len(p) <= 8 or len(p) % 2:
            raise InvalidParameterError("require 1-64 Q moduli and an even count of 2-8 P moduli")
        try:
            normalized_q = tuple(operator.index(value) for value in q)
            normalized_p = tuple(operator.index(value) for value in p)
        except TypeError as exc:
            raise InvalidParameterError("Q and P moduli must be unsigned 64-bit integers") from exc
        if any(isinstance(value, bool) for value in (*q, *p)) or any(
            not 0 < value < 2**64 for value in (*normalized_q, *normalized_p)
        ):
            raise InvalidParameterError("Q and P moduli must be unsigned 64-bit integers")
        if isinstance(scale, bool) or isinstance(sigma, bool):
            raise InvalidParameterError("scale and sigma must be finite and positive")
        try:
            normalized_scale = float(scale)
            normalized_sigma = float(sigma)
        except (TypeError, ValueError, OverflowError) as exc:
            raise InvalidParameterError("scale and sigma must be finite and positive") from exc
        if (
            not math.isfinite(normalized_scale)
            or normalized_scale <= 0
            or not math.isfinite(normalized_sigma)
            or normalized_sigma <= 0
        ):
            raise InvalidParameterError("scale and sigma must be finite and positive")
        return cls(
            log_n,
            log_slots,
            normalized_q,
            normalized_p,
            normalized_scale,
            normalized_sigma,
        )

    def _json(self) -> bytes:
        value = asdict(self)
        value.pop("_preset_name")
        value["q"] = list(self.q)
        value["p"] = list(self.p)
        return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _release_safely(handle: int, pid: int) -> None:
    try:
        if not handle or pid != os.getpid():
            return
        release = getattr(_native, "release_fn", None)
        if release is None:
            return
        error = ctypes.c_char_p()
        status = release(handle, ctypes.byref(error))
        if status and error.value:
            error_release = getattr(_native, "error_free", None)
            if error_release is not None:
                error_release(error)
    except Exception:
        # Interpreter shutdown can clear module state in arbitrary order.
        return


class _NativeObject:
    """Owner of one native handle, released by ``close()`` or garbage collection."""

    def __init__(self, handle: int) -> None:
        self._handle = handle
        self._pid = os.getpid()
        self._finalizer = weakref.finalize(self, _release_safely, handle, self._pid)

    @property
    def _native_handle(self) -> int:
        if self._pid != os.getpid():
            raise ForkSafetyError(
                "native handles cannot be inherited through fork; serialize and use spawn"
            )
        if not self._handle:
            from .errors import ClosedHandleError

            raise ClosedHandleError("native object is closed")
        return self._handle

    @property
    def closed(self) -> bool:
        """Whether the native handle has been released."""
        return self._handle == 0

    def _repr_fields(self) -> list[str]:
        """Return ``name=value`` fragments describing this object for ``repr()``."""
        return []

    def __repr__(self) -> str:
        name = type(self).__name__
        if self.closed:
            return f"{name}(closed=True)"
        try:
            fields = self._repr_fields()
        except Exception:
            # repr() is called by debuggers and logging, so it must never raise
            # even when the handle is unusable (for example after a fork).
            return f"{name}(<unavailable>)"
        return f"{name}({', '.join(fields)})"

    def close(self) -> None:
        """Release the native handle; repeated calls are harmless."""
        if self._handle:
            if self._pid != os.getpid():
                self._handle = 0
                self._finalizer.detach()
                return
            error = ctypes.c_char_p()
            status = _native.release_fn(self._handle, ctypes.byref(error))
            _native.check(status, error)
            self._handle = 0
            self._finalizer.detach()

    def __enter__(self) -> Self:
        _ = self._native_handle
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError(
            f"{type(self).__name__} is not pickleable; use its explicit serialization API"
        )


def _normalized_array(
    values: Any,
    context: Context,
) -> tuple[npt.NDArray[np.float64] | npt.NDArray[np.complex128], bool]:
    array = np.asarray(values)
    logical_shape = array.shape
    if array.size == 0:
        raise InvalidParameterError("empty arrays cannot be encrypted or encoded")
    if array.dtype.kind == "f":
        normalized = np.ascontiguousarray(array, dtype=np.float64)
        is_complex = False
    elif array.dtype.kind == "c":
        normalized = np.ascontiguousarray(array, dtype=np.complex128)
        is_complex = True
    else:
        raise InvalidDTypeError(
            f"dtype {array.dtype} is unsupported; explicitly cast to float32/64 or complex64/128"
        )
    if logical_shape == ():
        # np.ascontiguousarray promotes a zero-dimensional value to shape (1,).
        # Restore the documented logical scalar shape while retaining one native
        # value in the flattened ABI buffer.
        normalized = normalized.reshape(())
    if not np.all(np.isfinite(normalized)):
        raise InvalidParameterError("input contains NaN or infinity")
    maximum_values = min(context.limits.max_values, context.limits.max_chunks * context.slots)
    if normalized.size > maximum_values:
        raise InvalidParameterError(
            f"input has {normalized.size} values; this context permits at most {maximum_values}"
        )
    component_max = float(
        max(
            np.max(np.abs(normalized.real), initial=0.0),
            np.max(np.abs(normalized.imag), initial=0.0),
        )
    )
    _validate_magnitude(context, component_max)
    return normalized, is_complex


def _normalized_scalar(value: Any, context: Context) -> complex:
    if isinstance(value, (bool, int, np.integer)):
        raise InvalidDTypeError(
            "integer and bool scalars must be explicitly cast to float or complex"
        )
    try:
        normalized = complex(value)
    except (TypeError, ValueError) as exc:
        raise InvalidDTypeError("scalar must be a real or complex floating-point value") from exc
    if not math.isfinite(normalized.real) or not math.isfinite(normalized.imag):
        raise InvalidParameterError("scalar must be finite")
    _validate_magnitude(context, max(abs(normalized.real), abs(normalized.imag)))
    return normalized


def _validate_magnitude(context: Context, magnitude: float) -> None:
    if magnitude <= VALIDATED_COMPONENT_BOUND:
        return
    if context.input_policy is InputPolicy.VALIDATED:
        raise InvalidParameterError(
            f"component magnitude {magnitude:.6g} exceeds the validated bound "
            f"{VALIDATED_COMPONENT_BOUND:.6g}; use InputPolicy.EXPERT deliberately"
        )
    warnings.warn(
        "input lies outside the correctness-tested magnitude envelope",
        RuntimeWarning,
        stacklevel=3,
    )


def _validated_exact_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise InvalidParameterError(f"{name} must be an integer")
    try:
        result = operator.index(value)
    except TypeError as exc:
        raise InvalidParameterError(f"{name} must be an integer") from exc
    if not minimum <= result <= maximum:
        raise InvalidParameterError(f"{name} must be between {minimum} and {maximum}")
    return result


def _validate_party_id(party_id: str) -> bytes:
    if not isinstance(party_id, str):
        raise InvalidParameterError("party ID must be a string")
    try:
        raw = party_id.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise InvalidParameterError("party ID must be valid UTF-8") from exc
    if not raw or len(raw) > 128 or party_id == "0" or b"\x00" in raw:
        raise InvalidParameterError(
            "party ID must be 1-128 UTF-8 bytes, cannot contain NUL, and cannot be '0'"
        )
    return raw


def _validated_shape(value: Any) -> tuple[int, ...]:
    if not isinstance(value, (list, tuple)):
        raise SerializationError("artifact shape must be an array of dimensions")
    shape: list[int] = []
    size = 1
    for dimension in value:
        if isinstance(dimension, bool) or not isinstance(dimension, int) or dimension <= 0:
            raise SerializationError("artifact shape dimensions must be positive integers")
        size *= dimension
        if size > 1 << 26:
            raise SerializationError("artifact shape product exceeds the configured limit")
        shape.append(dimension)
    return tuple(shape)


def _parameters_from_metadata(metadata: dict[str, Any]) -> Parameters:
    value = metadata.get("parameters")
    if not isinstance(value, dict):
        raise SerializationError("context artifact parameters must be an object")
    try:
        parameters = Parameters.from_literal(**value)
    except (TypeError, ValueError) as exc:
        raise SerializationError("context artifact parameters are invalid") from exc
    for name in Parameters._PRESETS:
        preset = Parameters.preset(name)
        if parameters == preset:
            return replace(parameters, _preset_name=name)
    return parameters


def _party_id_from_metadata(metadata: dict[str, Any]) -> str:
    value = metadata.get("party_id")
    if not isinstance(value, str):
        raise SerializationError("artifact party_id must be a string")
    try:
        _validate_party_id(value)
    except InvalidParameterError as exc:
        raise SerializationError("artifact party_id is invalid") from exc
    return value


def _complex_flag_from_metadata(metadata: dict[str, Any]) -> bool:
    value = metadata.get("complex")
    if not isinstance(value, bool):
        raise SerializationError("artifact complex flag must be Boolean")
    return value


def _artifact_id_from_metadata(metadata: dict[str, Any]) -> str:
    value = metadata.get("artifact_id")
    if (
        not isinstance(value, str)
        or len(value) != 32
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SerializationError("artifact ciphertext ID must be 32 lowercase hexadecimal digits")
    return value


def _require_context(context: Context, *objects: Any) -> None:
    for value in objects:
        if value.context.fingerprint != context.fingerprint:
            raise ContextMismatchError("objects belong to different context/CRS instances")


def _native_object_metadata(handle: int, expected_kind: int, context: Context) -> dict[str, Any]:
    metadata = _native.call_json(_native.object_metadata_fn, handle)
    if metadata.get("kind") != expected_kind:
        raise SerializationError(
            f"native object kind is {metadata.get('kind')!r}; expected {expected_kind}"
        )
    if metadata.get("context_fingerprint") != context.fingerprint:
        raise SerializationError("native object context fingerprint is inconsistent")
    return metadata


def _array_pointers(array: npt.NDArray[Any], is_complex: bool) -> tuple[Any, Any, Any, Any]:
    flat = array.reshape(-1)
    if is_complex:
        real = np.ascontiguousarray(flat.real, dtype=np.float64)
        imag = np.ascontiguousarray(flat.imag, dtype=np.float64)
    else:
        real = np.ascontiguousarray(flat, dtype=np.float64)
        imag = np.empty(0, dtype=np.float64)
    real_pointer = real.ctypes.data_as(_native.DOUBLEP)
    imag_pointer = imag.ctypes.data_as(_native.DOUBLEP) if is_complex else _native.DOUBLEP()
    return real, imag, real_pointer, imag_pointer


def _pack_native(context: Context, kind: str, metadata: dict[str, Any], handle: int) -> bytes:
    result = _pack_artifact(kind, metadata, _native.export_artifact(handle))
    context._check_artifact_size(result)
    return result


def _unpack_native(context: Context, data: bytes, kind: str) -> tuple[dict[str, Any], bytes]:
    if len(data) > context.limits.max_artifact_bytes:
        raise SerializationError("artifact exceeds this context's resource limit")
    return _unpack_artifact(data, kind)


_TRACKING_FIELDS = (
    "tracked_magnitude_bound",
    "tracked_error_bound",
    "range_margin_bits",
    "range_exceeded",
)


def _validated_tracking(metadata: dict[str, Any]) -> dict[str, float | bool]:
    result: dict[str, float | bool] = {}
    for name in _TRACKING_FIELDS[:3]:
        value = metadata.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SerializationError(f"native {name} must be a finite number")
        normalized = float(value)
        if not math.isfinite(normalized) or (name != "range_margin_bits" and normalized < 0):
            raise SerializationError(f"native {name} is invalid")
        result[name] = normalized
    range_exceeded = metadata.get("range_exceeded")
    if not isinstance(range_exceeded, bool):
        raise SerializationError("native range_exceeded must be Boolean")
    result["range_exceeded"] = range_exceeded
    return result


def _tracking_envelope(value: Plaintext | Ciphertext) -> dict[str, float | bool]:
    return {name: value._tracking[name] for name in _TRACKING_FIELDS}


def _validate_tracking_envelope(serialized: dict[str, Any], value: Plaintext | Ciphertext) -> None:
    tracking = serialized.get("correctness")
    if not isinstance(tracking, dict):
        value.close()
        raise SerializationError("artifact correctness metadata must be an object")
    try:
        normalized = _validated_tracking(tracking)
    except SerializationError:
        value.close()
        raise
    if normalized != value._tracking:
        value.close()
        raise SerializationError("Python and native correctness metadata disagree")


def _correctness_status(context: Context, range_exceeded: bool) -> CorrectnessStatus:
    expert = context.input_policy is InputPolicy.EXPERT
    if expert and range_exceeded:
        return CorrectnessStatus.EXPERT_AND_OUTSIDE_RANGE
    if expert:
        return CorrectnessStatus.EXPERT_CONTEXT
    if range_exceeded:
        return CorrectnessStatus.OUTSIDE_TRACKED_RANGE
    return CorrectnessStatus.WITHIN_TESTED_CONTRACT


def _warn_on_range_transition(result: Ciphertext, inputs: Sequence[Plaintext | Ciphertext]) -> None:
    if result._range_exceeded and not any(value._range_exceeded for value in inputs):
        warnings.warn(
            "homomorphic result left the conservative modulus/scale range covered by "
            "the correctness tests; computation continues and the result is marked "
            "outside_tracked_range",
            CorrectnessRangeWarning,
            stacklevel=3,
        )


class Context(_NativeObject):
    """Shared CKKS parameters and common reference string for one computation.

    Every party, key, plaintext, ciphertext and decryption share belongs to
    exactly one context. Mixing objects from two contexts raises
    :class:`~mkckks.ContextMismatchError`, even when both were created from
    identical parameters, because the common reference string differs.

    Use :meth:`create` rather than constructing this class directly.
    """

    def __init__(
        self,
        handle: int,
        parameters: Parameters,
        input_policy: InputPolicy,
        limits: ResourceLimits,
    ) -> None:
        super().__init__(handle)
        self._parameters = parameters
        self._input_policy = input_policy
        self._limits = limits
        self._info = _native.call_json(_native.context_info_fn, self._native_handle)
        if self._info.get("parameters") != json.loads(parameters._json()):
            self.close()
            raise SerializationError("context parameter metadata does not match native context")

    @classmethod
    def create(
        cls,
        parameters: Parameters,
        workers: int | None = None,
        *,
        input_policy: InputPolicy = InputPolicy.VALIDATED,
        limits: ResourceLimits | None = None,
    ) -> Context:
        """Create a context and its common reference string.

        Args:
            parameters: A preset from :meth:`Parameters.preset`, or an expert
                literal, which requires ``input_policy=InputPolicy.EXPERT``.
            workers: Goroutines used for per-chunk evaluation. ``None`` lets the
                native layer choose based on available CPUs.
            input_policy: ``VALIDATED`` restricts inputs to the range covered by
                the project's correctness tests. ``EXPERT`` lifts that
                restriction and warns, because results are then untested.
            limits: Denial-of-service limits applied before entering native
                code. Defaults to :class:`ResourceLimits`.

        Raises:
            InvalidParameterError: The policy is unknown, or an expert literal
                was supplied under ``VALIDATED``.
        """
        try:
            policy = InputPolicy(input_policy)
        except (TypeError, ValueError) as exc:
            raise InvalidParameterError(
                "input_policy must be InputPolicy.VALIDATED or EXPERT"
            ) from exc
        if policy is InputPolicy.VALIDATED and parameters._preset_name is None:
            raise InvalidParameterError(
                "expert parameter literals require InputPolicy.EXPERT because they are not "
                "correctness-certified"
            )
        if policy is InputPolicy.EXPERT:
            warnings.warn(
                "InputPolicy.EXPERT is outside the project's correctness-certified domain",
                RuntimeWarning,
                stacklevel=2,
            )
        if workers is not None:
            workers = _validated_exact_int(workers, "workers", 1, 1024)
        raw = parameters._json()
        owner, pointer = _native.bytes_argument(raw)
        handle = _native.call_handle(
            _native.context_create, pointer, len(raw), 0 if workers is None else int(workers)
        )
        del owner
        return cls(handle, parameters, policy, limits or ResourceLimits())

    def _repr_fields(self) -> list[str]:
        preset = self.parameters._preset_name
        return [
            f"parameters={preset or 'expert'}",
            f"slots={self.slots}",
            f"max_level={self.max_level}",
            f"workers={self.workers}",
            f"policy={self.input_policy.value}",
        ]

    @property
    def parameters(self) -> Parameters:
        """The parameter literal this context was created from."""
        return self._parameters

    @property
    def input_policy(self) -> InputPolicy:
        """Whether inputs are restricted to the correctness-tested range."""
        return self._input_policy

    @property
    def limits(self) -> ResourceLimits:
        """Denial-of-service limits applied before entering native code."""
        return self._limits

    @property
    def fingerprint(self) -> str:
        """Hex digest binding objects to this context and its reference string."""
        return str(self._info["fingerprint"])

    @property
    def slots(self) -> int:
        """Plaintext slots per chunk; arrays longer than this span several chunks."""
        return int(self._info["slots"])

    @property
    def workers(self) -> int:
        """Goroutines the native layer uses to evaluate chunks in parallel."""
        return int(self._info["workers"])

    @property
    def max_level(self) -> int:
        """Multiplicative level of a freshly encrypted ciphertext."""
        return int(self._info["max_level"])

    def create_party(self, party_id: str) -> Party:
        """Generate a new party in this context; see :meth:`Party.generate`."""
        return Party.generate(self, party_id)

    def to_bytes(self) -> bytes:
        """Serialize the parameters and common reference string.

        Distribute the result to every participant so they share one reference
        string. The artifact is large, roughly 100 MiB for ``PN14QP439``.
        """
        result = _pack_artifact(
            "context",
            {
                "parameters": {
                    key: value
                    for key, value in asdict(self.parameters).items()
                    if key != "_preset_name"
                },
                "preset": self.parameters._preset_name,
            },
            _native.export_artifact(self._native_handle),
        )
        self._check_artifact_size(result)
        return result

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        *,
        input_policy: InputPolicy = InputPolicy.VALIDATED,
        limits: ResourceLimits | None = None,
    ) -> Context:
        """Restore a context produced by :meth:`to_bytes`.

        Raises:
            SerializationError: The artifact is malformed, is not a context, or
                exceeds ``limits.max_artifact_bytes``.
            InvalidParameterError: The literal is not a recognized preset and
                ``input_policy`` is ``VALIDATED``.
        """
        selected_limits = limits or ResourceLimits()
        if len(data) > selected_limits.max_artifact_bytes:
            raise SerializationError("context artifact exceeds local resource limits")
        metadata, native = _unpack_artifact(data, "context")
        parameters = _parameters_from_metadata(metadata)
        try:
            policy = InputPolicy(input_policy)
        except (TypeError, ValueError) as exc:
            raise InvalidParameterError("invalid input policy") from exc
        if policy is InputPolicy.EXPERT:
            warnings.warn(
                "InputPolicy.EXPERT is outside the project's correctness-certified domain",
                RuntimeWarning,
                stacklevel=2,
            )
        handle, kind = _native.import_artifact(0, native)
        if kind != 1:
            _release_safely(handle, os.getpid())
            raise SerializationError("native artifact is not a context")
        result = cls(handle, parameters, policy, selected_limits)
        if policy is InputPolicy.VALIDATED and parameters._preset_name is None:
            result.close()
            raise InvalidParameterError(
                "an unrecognized parameter literal requires InputPolicy.EXPERT"
            )
        return result

    def _check_artifact_size(self, data: bytes) -> None:
        if len(data) > self.limits.max_artifact_bytes:
            raise SerializationError("artifact exceeds this context's resource limit")

    def encode(self, values: Any) -> Plaintext:
        """Encode a NumPy array into an unencrypted plaintext.

        Accepts real or complex floating-point arrays of any shape. Integer and
        Boolean arrays must be cast explicitly, so that the loss of exactness is
        visible at the call site.
        """
        array, is_complex = _normalized_array(values, self)
        real, imag, real_pointer, imag_pointer = _array_pointers(array, is_complex)
        handle = _native.call_handle(
            _native.encode_plaintext_fn,
            self._native_handle,
            real_pointer,
            imag_pointer,
            array.size,
            int(is_complex),
        )
        del real, imag
        return Plaintext(handle, self, array.shape, is_complex)

    def collective_decrypt(
        self, ciphertext: Ciphertext, shares: Sequence[DecryptionShare]
    ) -> npt.NDArray[np.float64] | npt.NDArray[np.complex128]:
        """Combine one decryption share per participant to recover the plaintext.

        Exactly one share is required from every party in
        :attr:`Ciphertext.participants`; no party's secret key is ever revealed.
        The returned array has the ciphertext's shape, and its dtype is complex
        only if the ciphertext holds complex data.

        Raises:
            MissingShareError: A share is missing, duplicated, or bound to a
                different ciphertext.
        """
        _require_context(self, ciphertext, *shares)
        handles = (ctypes.c_uint64 * len(shares))(*(share._native_handle for share in shares))
        real = np.empty(ciphertext.size, dtype=np.float64)
        imag = np.empty(ciphertext.size, dtype=np.float64)
        error = ctypes.c_char_p()
        status = _native.collective_decrypt_fn(
            ciphertext._native_handle,
            handles,
            len(shares),
            real.ctypes.data_as(_native.DOUBLEP),
            imag.ctypes.data_as(_native.DOUBLEP),
            ciphertext.size,
            ctypes.byref(error),
        )
        _native.check(status, error)
        if ciphertext.is_complex:
            return (real + 1j * imag).reshape(ciphertext.shape)
        return real.reshape(ciphertext.shape)


class PublicKey(_NativeObject):
    """A party's encryption-only key, safe to publish.

    Obtained from :attr:`Party.public_key` or :meth:`from_bytes`. Holding it
    permits encryption under that party but not decryption.
    """

    def __init__(self, handle: int, context: Context) -> None:
        super().__init__(handle)
        self._context = context
        _native_object_metadata(handle, 3, context)

    @property
    def context(self) -> Context:
        """The context this key belongs to."""
        return self._context

    def encrypt(self, values: Any) -> Ciphertext:
        """Encrypt an array under this party alone."""
        return _encrypt(self, self.context, values)

    def to_bytes(self) -> bytes:
        """Serialize this public key for distribution."""
        return _pack_native(self.context, "public_key", {}, self._native_handle)

    @classmethod
    def from_bytes(cls, context: Context, data: bytes) -> PublicKey:
        """Restore a public key produced by :meth:`to_bytes`."""
        _, native = _unpack_native(context, data, "public_key")
        handle, kind = _native.import_artifact(context._native_handle, native)
        if kind != 3:
            _release_safely(handle, os.getpid())
            raise SerializationError("native artifact is not a public key")
        return cls(handle, context)


class Party(_NativeObject):
    """One participant's key pair, including its secret key.

    A party never leaves the process that generated it unless
    :meth:`export_private_state` is called explicitly. Parties contribute
    evaluation keys before computation and decryption shares afterwards; no
    single party can decrypt a multi-party ciphertext alone.
    """

    def __init__(self, handle: int, context: Context, party_id: str) -> None:
        super().__init__(handle)
        self._context = context
        metadata = _native_object_metadata(handle, 2, context)
        if metadata.get("party_id") != party_id:
            self.close()
            raise SerializationError("party ID metadata does not match native private state")
        self._party_id = party_id

    def _repr_fields(self) -> list[str]:
        return [f"party_id={self.party_id!r}"]

    @property
    def context(self) -> Context:
        """The context this party belongs to."""
        return self._context

    @property
    def party_id(self) -> str:
        """This party's identifier, used to label its ciphertext contributions."""
        return self._party_id

    @classmethod
    def generate(cls, context: Context, party_id: str) -> Party:
        """Generate a fresh key pair for ``party_id``.

        The identifier must be 1-128 bytes of UTF-8, must not contain NUL, must
        be unique within the context, and cannot be ``"0"``, which upstream
        reserves for the ciphertext constant component.

        Raises:
            InvalidParameterError: The identifier is malformed or already used.
        """
        raw = _validate_party_id(party_id)
        owner, pointer = _native.bytes_argument(raw)
        handle = _native.call_handle(
            _native.party_generate, context._native_handle, pointer, len(raw)
        )
        del owner
        return cls(handle, context, party_id)

    @property
    def public_key(self) -> PublicKey:
        """Derive this party's public key.

        Each access returns a new independently owned :class:`PublicKey`, so the
        caller is responsible for closing it. Reuse one object rather than
        reading this property in a loop.
        """
        handle = _native.call_handle(_native.party_public_key, self._native_handle)
        return PublicKey(handle, self.context)

    def encrypt(self, values: Any) -> Ciphertext:
        """Encrypt an array under this party alone."""
        return _encrypt(self, self.context, values)

    def generate_evaluation_keys(
        self,
        *,
        relinearization: bool = False,
        rotations: Sequence[int] = (),
        conjugation: bool = False,
    ) -> EvaluationKeyContribution:
        """Produce this party's contribution to the shared evaluation keys.

        Request only what the circuit needs, because each kind costs time and
        space: ``relinearization`` for :meth:`Evaluator.multiply`, ``rotations``
        for the rotation amounts used, and ``conjugation`` for
        :meth:`Evaluator.conjugate`. Every participant must contribute the same
        kinds, and the contributions are merged with
        :meth:`EvaluationKeySet.combine`.
        """
        if not isinstance(relinearization, bool) or not isinstance(conjugation, bool):
            raise InvalidParameterError("relinearization and conjugation must be Boolean")
        values = [
            _validated_exact_int(value, "rotation", -(1 << 31), (1 << 31) - 1)
            for value in rotations
        ]
        array = (ctypes.c_int32 * len(values))(*values) if values else None
        pointer = ctypes.cast(array, _native.I32P) if array is not None else _native.I32P()
        handle = _native.call_handle(
            _native.party_evaluation_keys,
            self._native_handle,
            int(relinearization),
            pointer,
            len(values),
            int(conjugation),
        )
        return EvaluationKeyContribution(handle, self.context, self.party_id)

    def partial_decrypt(self, ciphertext: Ciphertext) -> DecryptionShare:
        """Produce this party's decryption share for ``ciphertext``.

        The share is sensitive, unauthenticated protocol material intended for
        an authenticated combiner. It is combined with every other participant's
        share by :meth:`Context.collective_decrypt`; the wrapper makes no
        standalone confidentiality claim for an individual share.

        Raises:
            MissingShareError: This party is not among the ciphertext's
                participants.
        """
        handle = _native.call_handle(
            _native.partial_decrypt_fn, self._native_handle, ciphertext._native_handle
        )
        return DecryptionShare(handle, self.context, self.party_id, ciphertext.artifact_id)

    def export_private_state(self) -> bytes:
        """Serialize this party including its secret key, emitting a warning.

        The bytes are unencrypted and unauthenticated. Protect them as you would
        the secret key itself; prefer keeping a party inside one process.
        """
        warnings.warn(
            "Exporting raw, unencrypted private key material; "
            "authenticate and protect these bytes.",
            RuntimeWarning,
            stacklevel=2,
        )
        return _pack_native(
            self.context,
            "private_party",
            {"party_id": self.party_id},
            self._native_handle,
        )

    @classmethod
    def from_private_state(cls, context: Context, data: bytes) -> Party:
        """Restore a party from :meth:`export_private_state`, emitting a warning.

        The input is unauthenticated, so only load bytes from a trusted channel.
        """
        warnings.warn(
            "Importing raw, unencrypted private key material; authenticate and protect this data.",
            RuntimeWarning,
            stacklevel=2,
        )
        metadata, native = _unpack_native(context, data, "private_party")
        party_id = _party_id_from_metadata(metadata)
        handle, kind = _native.import_artifact(context._native_handle, native)
        if kind != 2:
            _release_safely(handle, os.getpid())
            raise SerializationError("native artifact is not private party state")
        return cls(handle, context, party_id)


def _encrypt(owner: _NativeObject, context: Context, values: Any) -> Ciphertext:
    array, is_complex = _normalized_array(values, context)
    real, imag, real_pointer, imag_pointer = _array_pointers(array, is_complex)
    handle = _native.call_handle(
        _native.encrypt_fn,
        owner._native_handle,
        real_pointer,
        imag_pointer,
        array.size,
        int(is_complex),
    )
    del real, imag
    result = Ciphertext(handle, context, array.shape)
    _warn_on_range_transition(result, ())
    return result


class EvaluationKeyContribution(_NativeObject):
    """One party's share of the joint evaluation keys.

    Produced by :meth:`Party.generate_evaluation_keys` and safe to publish.
    Contributions from all participants are merged by
    :meth:`EvaluationKeySet.combine`.
    """

    def __init__(self, handle: int, context: Context, party_id: str) -> None:
        super().__init__(handle)
        self._context = context
        metadata = _native_object_metadata(handle, 4, context)
        if metadata.get("party_id") != party_id:
            self.close()
            raise SerializationError("evaluation-key participant metadata mismatch")
        self._party_id = party_id

    def _repr_fields(self) -> list[str]:
        return [f"party_id={self.party_id!r}"]

    @property
    def context(self) -> Context:
        """The context this contribution belongs to."""
        return self._context

    @property
    def party_id(self) -> str:
        """Identifier of the party that produced this contribution."""
        return self._party_id

    def to_bytes(self) -> bytes:
        """Serialize this contribution for distribution."""
        return _pack_native(
            self.context,
            "evaluation_key_contribution",
            {"party_id": self.party_id},
            self._native_handle,
        )

    @classmethod
    def from_bytes(cls, context: Context, data: bytes) -> EvaluationKeyContribution:
        """Restore a contribution produced by :meth:`to_bytes`."""
        metadata, native = _unpack_native(context, data, "evaluation_key_contribution")
        party_id = _party_id_from_metadata(metadata)
        handle, kind = _native.import_artifact(context._native_handle, native)
        if kind != 4:
            _release_safely(handle, os.getpid())
            raise SerializationError("native artifact is not an evaluation-key contribution")
        return cls(handle, context, party_id)


class EvaluationKeySet(_NativeObject):
    """Merged evaluation keys enabling multiplication, rotation and conjugation.

    Pass this to :class:`Evaluator` to unlock the operations that need key
    material. The set must cover every participant of every ciphertext it is
    used on, otherwise :class:`~mkckks.MissingKeyError` is raised.
    """

    def __init__(self, handle: int, context: Context) -> None:
        super().__init__(handle)
        self._context = context
        _native_object_metadata(handle, 5, context)

    @property
    def context(self) -> Context:
        """The context these keys belong to."""
        return self._context

    @classmethod
    def combine(
        cls, context: Context, contributions: Sequence[EvaluationKeyContribution]
    ) -> EvaluationKeySet:
        """Merge one contribution per participant into a joint key set.

        Raises:
            InvalidParameterError: ``contributions`` is empty.
            MissingKeyError: Two contributions come from the same party.
        """
        if not contributions:
            raise InvalidParameterError("at least one evaluation-key contribution is required")
        _require_context(context, *contributions)
        handles = (ctypes.c_uint64 * len(contributions))(
            *(contribution._native_handle for contribution in contributions)
        )
        handle = _native.call_handle(_native.evaluation_keys_combine, handles, len(contributions))
        return cls(handle, context)

    def to_bytes(self) -> bytes:
        """Serialize the merged key set for distribution to evaluators."""
        return _pack_native(self.context, "evaluation_key_set", {}, self._native_handle)

    @classmethod
    def from_bytes(cls, context: Context, data: bytes) -> EvaluationKeySet:
        """Restore a key set produced by :meth:`to_bytes`."""
        _, native = _unpack_native(context, data, "evaluation_key_set")
        handle, kind = _native.import_artifact(context._native_handle, native)
        if kind != 5:
            _release_safely(handle, os.getpid())
            raise SerializationError("native artifact is not an evaluation-key set")
        return cls(handle, context)


class Plaintext(_NativeObject):
    """An encoded but unencrypted array, created by :meth:`Context.encode`.

    Plaintexts can be added to or multiplied with ciphertexts without any key
    material, which is cheaper than encrypting a constant operand.
    """

    def __init__(
        self, handle: int, context: Context, shape: tuple[int, ...], is_complex: bool
    ) -> None:
        super().__init__(handle)
        self._context = context
        self._shape = tuple(int(x) for x in shape)
        metadata = _native_object_metadata(handle, 6, context)
        if int(metadata.get("length", -1)) != int(np.prod(self._shape, dtype=np.int64)):
            self.close()
            raise SerializationError("plaintext shape does not match native logical length")
        if metadata.get("complex") is not is_complex:
            self.close()
            raise SerializationError("plaintext complex metadata does not match native data")
        self._is_complex: bool = is_complex
        self._tracking = _validated_tracking(metadata)

    def _repr_fields(self) -> list[str]:
        return [f"shape={self.shape}", f"dtype={'complex128' if self.is_complex else 'float64'}"]

    @property
    def correctness_status(self) -> CorrectnessStatus:
        """Whether this value is still inside the project's tested contract."""
        return _correctness_status(self.context, self._range_exceeded)

    @property
    def tracked_magnitude_bound(self) -> float:
        """Conservative upper bound on the largest encoded component."""
        return float(self._tracking["tracked_magnitude_bound"])

    @property
    def tracked_error_bound(self) -> float:
        """Conservative upper bound on the accumulated approximation error."""
        return float(self._tracking["tracked_error_bound"])

    @property
    def range_margin_bits(self) -> float:
        """Bits of headroom left before the tracked range is exceeded."""
        return float(self._tracking["range_margin_bits"])

    @property
    def _range_exceeded(self) -> bool:
        return bool(self._tracking["range_exceeded"])

    @property
    def context(self) -> Context:
        """The context this plaintext belongs to."""
        return self._context

    @property
    def shape(self) -> tuple[int, ...]:
        """Logical NumPy shape of the encoded array."""
        return self._shape

    @property
    def is_complex(self) -> bool:
        """Whether this plaintext holds complex rather than real data."""
        return self._is_complex

    def to_bytes(self) -> bytes:
        """Serialize this plaintext together with its correctness metadata."""
        return _pack_native(
            self.context,
            "plaintext",
            {
                "shape": self.shape,
                "complex": self.is_complex,
                "correctness": _tracking_envelope(self),
            },
            self._native_handle,
        )

    @classmethod
    def from_bytes(cls, context: Context, data: bytes) -> Plaintext:
        """Restore a plaintext produced by :meth:`to_bytes`.

        Raises:
            SerializationError: The artifact is malformed, or its recorded
                correctness metadata disagrees with the native payload.
        """
        metadata, native = _unpack_native(context, data, "plaintext")
        shape = _validated_shape(metadata.get("shape"))
        is_complex = _complex_flag_from_metadata(metadata)
        handle, kind = _native.import_artifact(context._native_handle, native)
        if kind != 6:
            _release_safely(handle, os.getpid())
            raise SerializationError("native artifact is not plaintext")
        result = cls(handle, context, shape, is_complex)
        _validate_tracking_envelope(metadata, result)
        return result


class Ciphertext(_NativeObject):
    """An encrypted array under one or more parties.

    Ciphertexts are immutable: every :class:`Evaluator` operation returns a new
    object rather than modifying its operands. Arrays longer than
    :attr:`Context.slots` are split across :attr:`chunks`, which affects
    rotation semantics; see :meth:`Evaluator.rotate_slots`.

    Decryption requires a share from every party in :attr:`participants`.
    """

    def __init__(
        self,
        handle: int,
        context: Context,
        shape: tuple[int, ...],
        *,
        validate: bool = True,
    ) -> None:
        super().__init__(handle)
        self._context = context
        self._shape = tuple(int(x) for x in shape)
        self._metadata: dict[str, Any] | None = None
        self._tracking_cache: dict[str, float | bool] | None = None
        if validate:
            self._validate_metadata()

    def _get_metadata(self) -> dict[str, Any]:
        if self._metadata is None:
            self._metadata = _native.call_json(_native.cipher_metadata_fn, self._native_handle)
        return self._metadata

    def _repr_fields(self) -> list[str]:
        return [
            f"shape={self.shape}",
            f"dtype={self.dtype.name}",
            f"level={self.level}",
            f"scale=2**{math.log2(self.scale):.1f}",
            f"participants={self.participants}",
        ]

    @property
    def context(self) -> Context:
        """The context this ciphertext belongs to."""
        return self._context

    @property
    def shape(self) -> tuple[int, ...]:
        """Logical NumPy shape of the encrypted array."""
        return self._shape

    def _validate_metadata(self) -> None:
        metadata = self._get_metadata()
        if metadata.get("kind") != 7:
            self.close()
            raise SerializationError("native object is not a ciphertext")
        if metadata.get("context_fingerprint") != self.context.fingerprint:
            self.close()
            raise SerializationError("ciphertext context metadata mismatch")
        if any(dimension <= 0 for dimension in self.shape) or self.size != int(metadata["length"]):
            self.close()
            raise SerializationError(
                "ciphertext shape metadata does not match its native logical length"
            )

    @property
    def size(self) -> int:
        """Total number of encrypted values, the product of :attr:`shape`."""
        return int(np.prod(self.shape, dtype=np.int64))

    @property
    def is_complex(self) -> bool:
        """Whether this ciphertext holds complex rather than real data."""
        return bool(self._get_metadata()["complex"])

    @property
    def dtype(self) -> np.dtype[Any]:
        """NumPy dtype that :meth:`Context.collective_decrypt` will return."""
        return np.dtype(np.complex128 if self.is_complex else np.float64)

    @property
    def chunks(self) -> int:
        """Number of native ciphertexts backing this array."""
        return int(self._get_metadata()["chunks"])

    @property
    def chunk_count(self) -> int:
        """Alias of :attr:`chunks`."""
        return self.chunks

    @property
    def slots(self) -> int:
        """Slots per chunk; alias of :attr:`Context.slots`."""
        return self.context.slots

    @property
    def context_fingerprint(self) -> str:
        """Fingerprint of the owning context, as recorded natively."""
        return str(self._get_metadata()["context_fingerprint"])

    @property
    def level(self) -> int:
        """Remaining multiplicative level available to rescale or discard."""
        return int(self._get_metadata()["level"])

    @property
    def scale(self) -> float:
        """Current CKKS scaling factor after any automatic rescaling."""
        return float(self._get_metadata()["scale"])

    @property
    def participants(self) -> tuple[str, ...]:
        """Sorted party identifiers whose shares are required to decrypt."""
        return tuple(str(value) for value in self._get_metadata()["participants"])

    @property
    def artifact_id(self) -> str:
        """Random identifier binding decryption shares to this exact ciphertext."""
        return str(self._get_metadata()["artifact_id"])

    @property
    def correctness_status(self) -> CorrectnessStatus:
        """Whether this value is still inside the project's tested contract."""
        return _correctness_status(self.context, self._range_exceeded)

    @property
    def tracked_magnitude_bound(self) -> float:
        """Conservative upper bound on the largest encrypted component."""
        return float(self._tracking["tracked_magnitude_bound"])

    @property
    def tracked_error_bound(self) -> float:
        """Conservative upper bound on the accumulated approximation error."""
        return float(self._tracking["tracked_error_bound"])

    @property
    def range_margin_bits(self) -> float:
        """Bits of headroom left before the tracked range is exceeded."""
        return float(self._tracking["range_margin_bits"])

    @property
    def _tracking(self) -> dict[str, float | bool]:
        # Ciphertexts are immutable, so the validated view is computed once.
        if self._tracking_cache is None:
            self._tracking_cache = _validated_tracking(self._get_metadata())
        return self._tracking_cache

    @property
    def _range_exceeded(self) -> bool:
        return bool(self._tracking["range_exceeded"])

    def to_bytes(self) -> bytes:
        """Serialize this ciphertext together with its correctness metadata."""
        return _pack_native(
            self.context,
            "ciphertext",
            {"shape": self.shape, "correctness": _tracking_envelope(self)},
            self._native_handle,
        )

    @classmethod
    def from_bytes(cls, context: Context, data: bytes) -> Ciphertext:
        """Restore a ciphertext produced by :meth:`to_bytes`.

        Raises:
            SerializationError: The artifact is malformed, or its recorded
                correctness metadata disagrees with the native payload.
        """
        metadata, native = _unpack_native(context, data, "ciphertext")
        shape = _validated_shape(metadata.get("shape"))
        handle, kind = _native.import_artifact(context._native_handle, native)
        if kind != 7:
            _release_safely(handle, os.getpid())
            raise SerializationError("native artifact is not ciphertext")
        result = cls(handle, context, shape)
        _validate_tracking_envelope(metadata, result)
        return result


class DecryptionShare(_NativeObject):
    """One party's contribution towards decrypting a specific ciphertext.

    Produced by :meth:`Party.partial_decrypt`. A share is bound to the exact
    ciphertext it was derived from via :attr:`artifact_id`, so it cannot be
    replayed against a different one. Shares remain sensitive, unauthenticated
    protocol material and must be transported over an authenticated channel.
    """

    def __init__(self, handle: int, context: Context, party_id: str, artifact_id: str) -> None:
        super().__init__(handle)
        self._context = context
        metadata = _native_object_metadata(handle, 8, context)
        if metadata.get("party_id") != party_id or metadata.get("artifact_id") != artifact_id:
            self.close()
            raise SerializationError("decryption-share binding metadata mismatch")
        self._party_id = party_id
        self._artifact_id = artifact_id

    def _repr_fields(self) -> list[str]:
        return [f"party_id={self.party_id!r}", f"artifact_id={self.artifact_id!r}"]

    @property
    def context(self) -> Context:
        """The context this share belongs to."""
        return self._context

    @property
    def party_id(self) -> str:
        """Identifier of the party that produced this share."""
        return self._party_id

    @property
    def artifact_id(self) -> str:
        """Identifier of the ciphertext this share may be combined with."""
        return self._artifact_id

    def to_bytes(self) -> bytes:
        """Serialize this share for transport to the combining party."""
        return _pack_native(
            self.context,
            "decryption_share",
            {"party_id": self.party_id, "artifact_id": self.artifact_id},
            self._native_handle,
        )

    @classmethod
    def from_bytes(cls, context: Context, data: bytes) -> DecryptionShare:
        """Restore a share produced by :meth:`to_bytes`."""
        metadata, native = _unpack_native(context, data, "decryption_share")
        party_id = _party_id_from_metadata(metadata)
        artifact_id = _artifact_id_from_metadata(metadata)
        handle, kind = _native.import_artifact(context._native_handle, native)
        if kind != 8:
            _release_safely(handle, os.getpid())
            raise SerializationError("native artifact is not a decryption share")
        return cls(handle, context, party_id, artifact_id)


class Evaluator:
    """Performs homomorphic operations on ciphertexts.

    Operations are grouped by whether they need key material. Addition,
    subtraction, scalar and plaintext multiplication, :meth:`drop_level` and
    :meth:`rescale` work with ``Evaluator(context)`` alone. Multiplication,
    non-zero rotation and conjugation additionally require an
    :class:`EvaluationKeySet`, and raise :class:`~mkckks.MissingKeyError`
    without one::

        evaluator = mkckks.Evaluator(context, evaluation_keys)

    The evaluator holds no native handle of its own and needs no closing.
    """

    def __init__(self, context: Context, evaluation_keys: EvaluationKeySet | None = None) -> None:
        """Bind an evaluator to ``context``, optionally with joint evaluation keys."""
        if evaluation_keys is not None:
            _require_context(context, evaluation_keys)
        self.context = context
        self.evaluation_keys = evaluation_keys

    def __repr__(self) -> str:
        return f"Evaluator(evaluation_keys={self.evaluation_keys is not None})"

    @staticmethod
    def _check_shape(left: Ciphertext, right: Ciphertext | Plaintext) -> None:
        if left.shape != right.shape:
            raise ShapeMismatchError(f"shape mismatch: {left.shape} != {right.shape}")

    def _cipher_result(
        self,
        function: Any,
        source: Ciphertext,
        *args: Any,
        tracking_inputs: Sequence[Plaintext | Ciphertext] | None = None,
    ) -> Ciphertext:
        _require_context(self.context, source)
        handle = _native.call_handle(function, *args)
        result = Ciphertext(handle, self.context, source.shape)
        _warn_on_range_transition(result, tracking_inputs or (source,))
        return result

    def _add_or_subtract(
        self,
        left: Ciphertext,
        right: Ciphertext | Plaintext | float | complex,
        *,
        subtract: bool,
    ) -> Ciphertext:
        if isinstance(right, Ciphertext):
            _require_context(self.context, right)
            self._check_shape(left, right)
            function = _native.subtract_fn if subtract else _native.add_fn
            return self._cipher_result(
                function,
                left,
                left._native_handle,
                right._native_handle,
                tracking_inputs=(left, right),
            )
        if isinstance(right, Plaintext):
            _require_context(self.context, right)
            self._check_shape(left, right)
            return self._cipher_result(
                _native.add_plaintext_fn,
                left,
                left._native_handle,
                right._native_handle,
                int(subtract),
                tracking_inputs=(left, right),
            )
        value = _normalized_scalar(right, self.context)
        return self._cipher_result(
            _native.add_scalar_fn,
            left,
            left._native_handle,
            value.real,
            value.imag,
            int(subtract),
        )

    def add(self, left: Ciphertext, right: Ciphertext | Plaintext | float | complex) -> Ciphertext:
        """Add a same-shaped ciphertext/plaintext or broadcast scalar."""
        return self._add_or_subtract(left, right, subtract=False)

    def subtract(
        self, left: Ciphertext, right: Ciphertext | Plaintext | float | complex
    ) -> Ciphertext:
        """Subtract a same-shaped ciphertext/plaintext or broadcast scalar."""
        return self._add_or_subtract(left, right, subtract=True)

    def multiply_scalar(self, ciphertext: Ciphertext, scalar: float | complex) -> Ciphertext:
        """Multiply every slot by one constant. Requires no evaluation keys."""
        value = _normalized_scalar(scalar, self.context)
        return self._cipher_result(
            _native.multiply_scalar_fn,
            ciphertext,
            ciphertext._native_handle,
            value.real,
            value.imag,
        )

    def multiply_plaintext(self, ciphertext: Ciphertext, plaintext: Plaintext) -> Ciphertext:
        """Multiply slot-wise by a same-shaped plaintext.

        Requires no evaluation keys, unlike :meth:`multiply`, and needs a
        positive :attr:`Ciphertext.level`. The pinned upstream operation
        rescales the product automatically and normally consumes one level.

        Raises:
            ShapeMismatchError: The operands have different shapes.
            LevelError: The ciphertext has no level left to consume.
        """
        _require_context(self.context, plaintext)
        self._check_shape(ciphertext, plaintext)
        return self._cipher_result(
            _native.multiply_plaintext_fn,
            ciphertext,
            ciphertext._native_handle,
            plaintext._native_handle,
            tracking_inputs=(ciphertext, plaintext),
        )

    def multiply(self, left: Ciphertext, right: Ciphertext) -> Ciphertext:
        """Multiply two ciphertexts and relinearize the product.

        The result's participant set is the union of both operands'. The pinned
        upstream operation rescales the product automatically, so a separate
        :meth:`rescale` call is usually an immutable no-op.

        Raises:
            MissingKeyError: The evaluator has no keys, or the keys lack a
                relinearization contribution for some participant.
            ShapeMismatchError: The operands have different shapes.
            LevelError: Either operand has no level left to consume.
        """
        _require_context(self.context, right)
        self._check_shape(left, right)
        if self.evaluation_keys is None:
            from .errors import MissingKeyError

            raise MissingKeyError("ciphertext multiplication requires evaluation keys")
        return self._cipher_result(
            _native.multiply_fn,
            left,
            self.evaluation_keys._native_handle,
            left._native_handle,
            right._native_handle,
            0,
            tracking_inputs=(left, right),
        )

    def drop_level(self, ciphertext: Ciphertext, levels: int = 1) -> Ciphertext:
        """Discard ``levels`` moduli without changing the scale or the values.

        Useful for aligning two ciphertexts before combining them.

        Raises:
            LevelError: ``levels`` exceeds the remaining level.
        """
        validated_levels = _validated_exact_int(levels, "levels", 0, (1 << 31) - 1)
        return self._cipher_result(
            _native.drop_level_fn, ciphertext, ciphertext._native_handle, validated_levels
        )

    def rescale(self, ciphertext: Ciphertext, minimum_scale: float | None = None) -> Ciphertext:
        """Divide out moduli to bring the scale back towards ``minimum_scale``.

        Defaults to the context's parameter scale. Depending on the current
        scale and threshold, this may consume zero, one, or several levels. A
        zero-consumption request returns an independent ciphertext copy.

        Raises:
            InvalidParameterError: ``minimum_scale`` is not finite and positive.
            LevelError: Rescaling would consume every remaining level or drop the
                scale below the supported minimum.
        """
        if minimum_scale is None:
            value = self.context.parameters.scale
        else:
            if isinstance(minimum_scale, (bool, np.bool_)):
                raise InvalidParameterError("minimum_scale must be finite and positive")
            try:
                value = float(minimum_scale)
            except (TypeError, ValueError, OverflowError) as exc:
                raise InvalidParameterError("minimum_scale must be finite and positive") from exc
        if not math.isfinite(value) or value <= 0:
            raise InvalidParameterError("minimum_scale must be finite and positive")
        return self._cipher_result(_native.rescale_fn, ciphertext, ciphertext._native_handle, value)

    def rotate_slots(self, ciphertext: Ciphertext, rotation: int) -> Ciphertext:
        """Rotate slots left by ``rotation``, refusing multi-chunk ciphertexts.

        Rotation acts within each chunk, never across chunk boundaries, so a
        whole-array rotation is only well defined for a single chunk. This method
        rejects anything larger rather than silently rotating per chunk; call
        :meth:`rotate_each_chunk` when the per-chunk behaviour is what you want.

        Raises:
            InvalidParameterError: The ciphertext spans more than one chunk.
            MissingKeyError: ``rotation`` is non-zero and no rotation key covers it.
        """
        if ciphertext.chunks != 1:
            raise InvalidParameterError(
                "rotate_slots requires one chunk; use rotate_each_chunk explicitly"
            )
        return self.rotate_each_chunk(ciphertext, rotation)

    def rotate_each_chunk(self, ciphertext: Ciphertext, rotation: int) -> Ciphertext:
        """Rotate the slots of every chunk left by ``rotation``, independently.

        Values do not move between chunks, so for a multi-chunk ciphertext this
        is not a rotation of the flattened array. A ``rotation`` of zero is a
        copy and needs no keys.

        Raises:
            MissingKeyError: ``rotation`` is non-zero and the evaluation keys do
                not cover the required rotation amounts for every participant.
        """
        validated_rotation = _validated_exact_int(rotation, "rotation", -(1 << 31), (1 << 31) - 1)
        normalized = validated_rotation % self.context.slots
        if normalized and self.evaluation_keys is None:
            from .errors import MissingKeyError

            raise MissingKeyError("rotation requires evaluation keys")
        return self._cipher_result(
            _native.rotate_fn,
            ciphertext,
            0 if self.evaluation_keys is None else self.evaluation_keys._native_handle,
            ciphertext._native_handle,
            validated_rotation,
            0,
        )

    def conjugate(self, ciphertext: Ciphertext) -> Ciphertext:
        """Conjugate every slot complex-wise.

        This binding only supports conjugation at the context's maximum level,
        because the pinned upstream revision indexes all moduli unconditionally.
        Conjugate before consuming any level.

        Raises:
            MissingKeyError: The evaluation keys lack a conjugation contribution.
            LevelError: The ciphertext is below the maximum level.
        """
        if self.evaluation_keys is None:
            from .errors import MissingKeyError

            raise MissingKeyError("conjugation requires evaluation keys")
        return self._cipher_result(
            _native.conjugate_fn,
            ciphertext,
            self.evaluation_keys._native_handle,
            ciphertext._native_handle,
        )
