# MKCKKS Go2Py 0.2.0

MKCKKS Go2Py 0.2.0 is a substantial hardening release for the NumPy-oriented
Python binding over the pinned MKHE-KKLSS multi-key CKKS research
implementation. It preserves the protected upstream algorithm byte-for-byte
while replacing the legacy coefficient-copying wrapper with a narrow,
versioned native ABI and opaque handles.

> [!IMPORTANT]
> This is an unaudited, noncommercial source-available research prerelease. New
> wrapper code is MIT licensed; the bundled protected MKHE-KKLSS implementation
> remains CC BY-NC 2.0. This engineering release is not a cryptographic security
> audit and is not intended for production systems handling sensitive data.

## Highlights

- NumPy `float32`, `float64`, `complex64`, and `complex128` input, including
  transparent slot-sized chunking and logical shape restoration.
- Addition, subtraction, plaintext and ciphertext multiplication, automatic
  upstream rescaling, level management, rotation, conjugation, and collective
  multi-party decryption.
- Opaque native handles, deterministic cleanup, context managers, typed errors,
  fork protection, resource ceilings, and panic containment.
- Versioned, checksummed serialization for contexts, parties, keys, plaintexts,
  ciphertexts, evaluation material, and decryption shares.
- Participant names bound to public-key fingerprints across ciphertexts,
  evaluation keys, shares, and serialized artifacts.
- Conservative magnitude, error, and range tracking with sticky warnings when
  a circuit leaves the tested numerical contract.
- One uniform runtime contract: standard GIL-enabled CPython 3.13. Unsupported
  versions, PyPy, and free-threaded builds are rejected rather than run outside
  the certified configuration.

## Performance

Opaque handles avoid copying ciphertext coefficients through Python after every
operation. Safe per-context pooling reuses ciphertext-only evaluators,
partial-decryptors, and explicitly scrubbed encoders; helpers that can retain
plaintext-derived buffers are deliberately not pooled.

In a controlled Apple M3 reference run using CPython 3.13.14 and PN14QP439,
Python median latency was within 9% of the C ABI for addition and within 1% for
multiplication and rotation. Four workers delivered 3.16x the one-worker
throughput for eight-chunk complex encryption. These are illustrative local
measurements, not universal performance promises. This release includes
environment-stamped native, Python, allocation, workflow, and throughput
reports so results can be evaluated in their actual runner context.

## Correctness and release evidence

The release-candidate program includes deterministic generated circuits for
both parameter presets, a direct protected-upstream differential oracle, all
ordered pairs of supported operation families, public and private encryption,
real and complex values, multi-party and multi-chunk workflows, serialization
continuation, malformed-input fuzzing, race detection, lifecycle stress, and a
standalone consumer exercising all 31 C ABI symbols.

Release assets include precision and correctness reports, benchmark reports, a
CycloneDX runtime SBOM, a compatibility bundle, a reproducible source
distribution and platform wheels, and `SHA256SUMS`. The tests provide strong
engineering evidence within the documented parameter and input envelope; they
are not formal verification.

## Supported runtime and platforms

- Standard GIL-enabled CPython 3.13 with NumPy 2.1 or newer.
- macOS 12 or later on arm64 and x86_64.
- manylinux_2_28 x86_64.
- Native Windows is unsupported; WSL2 with Ubuntu may be used for a source
  installation.

Install the wheel matching the target platform into a clean CPython 3.13
environment:

```console
python -m pip install /path/to/mkckks_go2py-0.2.0-*.whl
```

Review the repository's known limitations, security policy, license, and
attached evidence before using the software or redistributing it.
