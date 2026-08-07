# API reference

The supported public surface is exported from `mkckks`; modules beginning with
an underscore are private and may change during v0.x.

All native-backed objects belong to one `Context`, which fixes the parameters
and common reference string. Objects from different contexts are intentionally
incompatible. A `Party` represents one named key owner, and a ciphertext's
participant set records which parties must contribute to collective
decryption.

## Parameters and contexts

- `Parameters.preset(name)` returns `PN14QP439` or `PN15QP880`.
- `Parameters.from_literal(...)` accepts expert literals and performs wrapper
  bounds checks before Lattigo structural validation.
- `Context.create(parameters, workers=None, *, input_policy=InputPolicy.VALIDATED,
  limits=None)` creates a new CRS. Independent calls with the same literal
  intentionally create different fingerprints. `ResourceLimits` bounds chunks,
  logical values, and artifact bytes before allocation.
- `Context.encode(values)` creates a reusable plaintext.
- `Context.collective_decrypt(ciphertext, shares)` validates the context,
  ciphertext artifact ID, participant set, and exactly one share per party.

Contexts and every native-backed public object support `close()`, `closed`, and
the context-manager protocol. A closed or post-fork handle raises a typed error.

## Parties and keys

- `Party.generate(context, party_id)` creates private and public key material.
- `party.public_key` returns a public-only encryption handle.
- `party.generate_evaluation_keys(...)` creates an explicit contribution.
- `EvaluationKeySet.combine(context, contributions)` rejects missing,
  duplicate, or cross-context contributions.
- `party.partial_decrypt(ciphertext)` returns a share bound to one artifact ID.

`Party` is never implicitly pickleable. Private persistence requires the
deliberately named `export_private_state()` and `from_private_state()` methods.

## Evaluator

`Evaluator(context, evaluation_keys=None)` provides:

- `add` and `subtract` for same-shaped ciphertexts/plaintexts or a real/complex
  floating scalar;
- `multiply_scalar` and `multiply_plaintext`;
- `multiply` with relinearization keys (operation-local hoisting is an internal
  implementation detail);
- `drop_level` and `rescale`;
- `rotate_slots`, `rotate_each_chunk`, and `conjugate`.

Rotations accept exact, non-Boolean signed 32-bit integers and normalize modulo
the slot count. Rotation zero returns an independent ciphertext without a
rotation key. Hoisted multiplication is an internal implementation detail; the
public rotation methods use the normal compositional upstream path.
Conjugation currently requires a maximum-level ciphertext; lower levels raise
`LevelError` before entering the pinned upstream code.

All operations return new immutable wrapper objects. Integer and Boolean
scalars are rejected; cast explicitly to opt into approximate CKKS semantics.

`Plaintext` and `Ciphertext` expose read-only `correctness_status`,
`tracked_magnitude_bound`, `tracked_error_bound`, and `range_margin_bits`.
`CorrectnessStatus` distinguishes validated versus expert contexts and a sticky
outside-range state. The first transition outside the tracked range emits
`CorrectnessRangeWarning` while returning the result. See `precision.md`; this
metadata describes the tested numerical contract, not cryptographic security.

## Serialization

Contexts, public keys, evaluation contributions/sets, plaintexts, ciphertexts,
and shares use `to_bytes()` / `from_bytes(...)`. See `serialization.md` for the
format and compatibility contract. Checksums are not authentication.

## Exceptions

All public exceptions derive from `MKCKKSError`: `InvalidParameterError`,
`InvalidDTypeError`, `ShapeMismatchError`, `ContextMismatchError`,
`MissingKeyError`, `MissingShareError`, `LevelError`, `ClosedHandleError`,
`ForkSafetyError`, `SerializationError`, and `NativeError`.
Numerical range transitions use `CorrectnessRangeWarning`, a `RuntimeWarning`,
rather than an exception.
