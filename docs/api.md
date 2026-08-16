# API reference

The supported public surface is exported from `mkckks`; modules beginning with
an underscore are private and may change during v0.x.

Every class, method, and property below carries a docstring, so `help(mkckks)`,
`help(mkckks.Evaluator.multiply)`, and IDE tooltips are authoritative for
signatures. This page covers what those docstrings cannot: how the pieces fit
together, and which guarantees hold across the whole API.

All native-backed objects belong to one `Context`, which fixes the parameters
and common reference string. Objects from different contexts are intentionally
incompatible. A `Party` represents one named key owner, and a ciphertext's
participant set records which parties must contribute to collective
decryption.

## Exported surface

Everything in `mkckks.__all__`, grouped by role.

| Export | Kind | Purpose |
| --- | --- | --- |
| `Parameters` | dataclass | CKKS parameter literal; `preset()` or `from_literal()` |
| `Context` | native | Shared parameters and common reference string |
| `InputPolicy` | enum | `VALIDATED` (tested range) or `EXPERT` (unrestricted, warns) |
| `ResourceLimits` | dataclass | Pre-allocation caps: `max_chunks=64`, `max_values=2**26`, `max_artifact_bytes=2**30` |
| `Party` | native | One participant's key pair, including its secret key |
| `PublicKey` | native | Encryption-only key, safe to publish |
| `EvaluationKeyContribution` | native | One party's share of the joint evaluation keys |
| `EvaluationKeySet` | native | Merged keys enabling multiply, rotate, conjugate |
| `Plaintext` | native | Encoded but unencrypted array |
| `Ciphertext` | native | Encrypted array under one or more parties |
| `DecryptionShare` | native | One party's contribution to decrypting one ciphertext |
| `Evaluator` | plain | Homomorphic operations; holds no native handle |
| `CorrectnessStatus` | enum | `WITHIN_TESTED_CONTRACT`, `EXPERT_CONTEXT`, `OUTSIDE_TRACKED_RANGE`, `EXPERT_AND_OUTSIDE_RANGE` |
| `PrecisionClass` | enum | `BASIC`, `ROTATION`, `MULTIPLICATION` |
| `PrecisionReport` | dataclass | Measured error, with real and imaginary kept separate |
| `precision_bound` | function | Expected bound for a `Parameters` or `Ciphertext` and a class |
| `measure_precision` | function | Compare decrypted output against expected values |
| `BUILD_INFO` | dict | `abi_version`, `go_version`, `goos`, `goarch`, `upstream_commit` |
| `__version__` | str | Installed distribution version |

Exceptions are listed under [Exceptions](#exceptions).

Objects marked "native" own a native handle: they support `close()`, `closed`,
and the context-manager protocol, and they render their identifying state
through `repr()`. They are deliberately not pickleable.

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

`Evaluator(context, evaluation_keys=None)` splits into operations that need key
material and operations that do not. Constructing an evaluator without keys is
valid and sufficient for the first group.

Available with `Evaluator(context)`:

- `add` and `subtract` for same-shaped ciphertexts/plaintexts or a real/complex
  floating scalar;
- `multiply_scalar` and `multiply_plaintext`;
- `drop_level` and `rescale`;
- `rotate_slots` and `rotate_each_chunk` with a rotation of zero, which copies.

Requiring `Evaluator(context, evaluation_keys)`:

- `multiply`, which needs a relinearization contribution from every participant;
- `rotate_slots` and `rotate_each_chunk` with a non-zero rotation, which need
  rotation keys covering the requested amounts;
- `conjugate`, which needs a conjugation contribution.

Calling one of these without adequate keys raises `MissingKeyError` before any
native work happens. Request key kinds explicitly in
`party.generate_evaluation_keys(...)`, because each kind costs time and space,
and every participant must contribute the same kinds.

Rotations accept exact, non-Boolean signed 32-bit integers and normalize modulo
the slot count. Rotation acts within each chunk and never moves values across
chunk boundaries, so for a multi-chunk ciphertext it is not a rotation of the
flattened array: `rotate_slots` therefore rejects multi-chunk inputs with
`InvalidParameterError`, and `rotate_each_chunk` is the explicit opt-in to
per-chunk semantics. Hoisted multiplication is an internal implementation
detail; the public rotation methods use the normal compositional upstream path.
Conjugation currently requires a maximum-level ciphertext; lower levels raise
`LevelError` before entering the pinned upstream code.

Ciphertext/plaintext and ciphertext/ciphertext multiplication use the pinned
upstream operations, which rescale their products automatically. An explicit
`rescale` request can consume zero, one, or several levels; when no modulus
meets the threshold it returns an independent no-op copy. `Ciphertext.level`
reports what remains.

All operations return new immutable wrapper objects. Integer and Boolean
scalars are rejected; cast explicitly to opt into approximate CKKS semantics.

## Inspecting ciphertexts

`Ciphertext` reports its own state without decrypting. `shape`, `size`, `dtype`,
and `is_complex` describe the logical array; `chunks` (aliased `chunk_count`)
and `slots` describe how it is laid out natively; `level` and `scale` track
budget consumed by multiplication and rescaling; `participants` lists the
parties whose shares decryption needs; and `artifact_id` plus
`context_fingerprint` are the identifiers that bind shares and contexts
together. `Plaintext` exposes `shape` and `is_complex`.

Both types expose read-only `correctness_status`, `tracked_magnitude_bound`,
`tracked_error_bound`, and `range_margin_bits`. `CorrectnessStatus`
distinguishes validated versus expert contexts and a sticky outside-range state.
The first transition outside the tracked range emits `CorrectnessRangeWarning`
while returning the result. See [precision.md](precision.md); this metadata
describes the tested numerical contract, not cryptographic security.

## Serialization

Contexts, public keys, evaluation contributions/sets, plaintexts, ciphertexts,
and shares each provide `to_bytes()` and a matching `from_bytes(...)`.
`Context.to_bytes()` / `Context.from_bytes(data, *, input_policy=..., limits=...)`
stands alone because a context has no parent; every other type takes the context
first, as in `Ciphertext.from_bytes(context, data)`. `Party` uses the
deliberately distinct `export_private_state()` and `from_private_state()`.

Ciphertext and plaintext artifacts carry their correctness metadata, and
`from_bytes` rejects an artifact whose metadata disagrees with its native
payload. See [serialization.md](serialization.md) for the format and
compatibility contract. Checksums are not authentication.

## Exceptions

All library-defined operational exceptions derive from `MKCKKSError`:
`InvalidParameterError`,
`InvalidDTypeError`, `ShapeMismatchError`, `ContextMismatchError`,
`MissingKeyError`, `MissingShareError`, `LevelError`, `ClosedHandleError`,
`ForkSafetyError`, `SerializationError`, and `NativeError`.
Numerical range transitions use `CorrectnessRangeWarning`, a `RuntimeWarning`,
rather than an exception. Python's pickle protocol raises the standard
`TypeError` when asked to pickle a native-backed object; use its explicit
serialization API instead.
