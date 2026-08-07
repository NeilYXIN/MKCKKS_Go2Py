# Architecture

The repository has a strict three-layer boundary:

1. `mkckks/`, `mkrlwe/`, `mkbfv/`, and `cnn/` are the byte-for-byte pinned
   upstream implementation. `scripts/verify_upstream.py` guards this boundary.
2. `bridge/` is a separately licensed cgo package. It stores Go objects in a
   typed registry and exposes only fixed-width values, byte buffers, and
   real/imaginary double arrays.
3. `src/mkckks/` owns validation, NumPy shapes and dtypes, lifecycle management,
   typed errors, and user-facing artifact metadata.

Native operations are immutable from Python. A handle is monotonically
allocated, typed, closed explicitly, and never reused. ABI calls take a shared
operation lease; release takes the exclusive lease, so close waits for in-flight
native work before secret cleanup. Python finalizers are a fallback only.
Native panics are recovered at the ABI boundary and are considered correctness
failures, not normal error handling.

Large arrays are split into CKKS-slot-sized chunks. Independent chunks use a
bounded Go worker pool; the unchanged upstream implementation remains
single-threaded within one ciphertext. Each chunk creates operation-local
encoder/evaluator scratch, including relinearization decompositions, so shared
evaluation-key sets remain read-only across workers and concurrent callers.

Collective decryption uses upstream `PartialDecrypt`, subtracts the original
`c0` to form a bound share delta, combines every delta once, and uses upstream
`Decrypt` for reduction and CKKS decoding. It does not reimplement secret-key
multiplication.

Python wrappers record their creating PID; inherited post-fork handles fail
before entering native code. Python subinterpreters are unsupported until a
dedicated isolation and shutdown matrix proves that the process-global Go
registry is safe for them.

Closing a Python context prevents new imports through that wrapper. Existing
child objects retain their native context reference and remain valid until they
are closed. Party release overwrites secret polynomial buffers after the final
in-flight ABI call, subject to the documented best-effort limits of Go and
Python memory management.
