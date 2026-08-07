"""Public exception hierarchy for MKCKKS Go2Py."""


class MKCKKSError(Exception):
    """Base class for wrapper and native errors."""


class InvalidParameterError(MKCKKSError, ValueError):
    """A parameter literal was structurally invalid."""


class InvalidDTypeError(MKCKKSError, TypeError):
    """An input array has an unsupported dtype."""


class ShapeMismatchError(MKCKKSError, ValueError):
    """Operands have incompatible logical shapes."""


class ContextMismatchError(MKCKKSError, ValueError):
    """Objects were created from different context/CRS instances."""


class MissingKeyError(MKCKKSError):
    """Required evaluation-key material is absent."""


class MissingShareError(MKCKKSError):
    """Collective decryption has missing or invalid shares."""


class LevelError(MKCKKSError):
    """An operation cannot be performed at the ciphertext's level."""


class ClosedHandleError(MKCKKSError):
    """A native object has already been closed."""


class ForkSafetyError(MKCKKSError):
    """A native handle was inherited across a process fork."""


class SerializationError(MKCKKSError):
    """An artifact could not be serialized or validated."""


class NativeError(MKCKKSError):
    """An unexpected native error or recovered panic occurred."""


class CorrectnessRangeWarning(RuntimeWarning):
    """A result left the conservative range covered by the correctness tests."""
