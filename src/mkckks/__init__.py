"""MKCKKS Go2Py public API."""

from importlib.metadata import PackageNotFoundError, version

from ._native import BUILD_INFO
from .api import (
    Ciphertext,
    Context,
    CorrectnessStatus,
    DecryptionShare,
    EvaluationKeyContribution,
    EvaluationKeySet,
    Evaluator,
    InputPolicy,
    Parameters,
    Party,
    Plaintext,
    PublicKey,
    ResourceLimits,
)
from .errors import (
    ClosedHandleError,
    ContextMismatchError,
    CorrectnessRangeWarning,
    ForkSafetyError,
    InvalidDTypeError,
    InvalidParameterError,
    LevelError,
    MissingKeyError,
    MissingShareError,
    MKCKKSError,
    NativeError,
    SerializationError,
    ShapeMismatchError,
)
from .precision import PrecisionClass, PrecisionReport, measure_precision, precision_bound

__all__ = [
    "BUILD_INFO",
    "Ciphertext",
    "ClosedHandleError",
    "Context",
    "ContextMismatchError",
    "CorrectnessRangeWarning",
    "CorrectnessStatus",
    "DecryptionShare",
    "EvaluationKeyContribution",
    "EvaluationKeySet",
    "Evaluator",
    "ForkSafetyError",
    "InputPolicy",
    "InvalidDTypeError",
    "InvalidParameterError",
    "LevelError",
    "MKCKKSError",
    "MissingKeyError",
    "MissingShareError",
    "NativeError",
    "Parameters",
    "Party",
    "Plaintext",
    "PrecisionClass",
    "PrecisionReport",
    "PublicKey",
    "ResourceLimits",
    "SerializationError",
    "ShapeMismatchError",
    "measure_precision",
    "precision_bound",
]

try:
    __version__ = version("mkckks-go2py")
except PackageNotFoundError:  # Source tree without installed package metadata.
    __version__ = "0+unknown"
