# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) from
1.0 onwards.

The 0.x API and artifact formats may change before 1.0.

## [Unreleased]

These changes are intended for 0.2.0. The version heading, release date, and
compare links are added only when the release tag is created.

### Added

- Validated and expert input policies, hard resource ceilings, canonical native
  metadata checks, close/use leasing, and synchronous secret cleanup.
- Conservative magnitude, error, and range tracking on native objects and in
  serialized artifacts, with sticky correctness status and a one-time warning
  when a cascaded circuit leaves the tested numerical range.
- Direct-upstream differential tests for both presets, formula-based precision
  reports, complex property and metamorphic tests, structured fuzz targets,
  concurrent worker and race tests, and a full operational C ABI harness.
- 400 deterministic release circuits, full ordered-operation-pair coverage,
  multi-chunk differential chains, repeated-squaring range probes, oracle
  comparator self-tests, and per-operation C decryption checks.
- Frozen Python/native serialization envelope 1.0 and the first-release
  compatibility bundle generator.
- An executable reproduction of the original notebook's three-client
  encryption, addition, scalar multiplication, and collective-decryption flow,
  with explicit expected values and scale-aware precision checks.
- Docstrings across the entire exported public surface, so `help()` and IDE
  tooltips describe every class, method, and property, including which
  `Evaluator` operations require evaluation keys.
- `repr()` on native-backed types, showing shape, level, scale, and
  participants rather than an object address.
- The locked `auditwheel` release dependency used to inspect manylinux wheels.
- `scripts/check.sh`, one command that runs the core source gates shared with
  CI, reports all failing stages rather than only the first, and validates stage
  names for fast iteration.
- A `pip-audit` gate over the hash-pinned dependency closure, and a CycloneDX
  SBOM of the runtime closure among the release-candidate artifacts.
- Dependabot coverage for GitHub Actions and the `uv` lockfile. Go modules are
  deliberately excluded, because `go.mod` is byte-locked by `UPSTREAM.lock` and
  the pinned Lattigo version is part of the certified upstream snapshot.

### Changed

- Release-candidate versioning now derives directly from `pyproject.toml`.
- Every release-candidate artifact and report is pinned to one resolved commit,
  with checksums generated against the filenames published by GitHub Releases.
- Reworked large-artifact fuzz targets to use bounded structure-aware mutation
  instructions, preventing Go fuzz-worker shared-memory overflow without
  shortening fuzz duration or bypassing native payload decoders.
- Scoped the expensive generated-circuit counts to their intended Go and Python
  release steps and raised the uncached Go release-test timeout, avoiding
  duplicate heavy coverage execution without reducing the 400-circuit matrix.
- Raised observed Go bridge-core coverage above 95% with focused artifact
  validation and failure-atomicity tests; CI enforces a 93% maintenance floor.
- Corrected the preferred software citation to the MASER publication describing
  the Python wrapper, retaining the upstream KKLSS algorithm citation as a
  separate provenance reference.
- Corrected the direct-Go benchmark, separated release distributions from
  reports, and reduced GitHub automation to pull-request CI plus a manually
  dispatched draft-prerelease workflow.
- `parallelFor` stops dispatching chunk work after the first failure instead of
  evaluating every remaining chunk of a failed operation.
- `Ciphertext` computes its validated correctness-tracking view once instead of
  on every property access.
- A bare `pytest` now runs the fast tier, deselecting the `slow` and `release`
  markers; the two most expensive certification tests are marked `slow`, and
  `CONTRIBUTING.md` documents the command for each tier.
- The release-candidate workflow serializes all candidate runs, refuses to
  start when the target version tag points to another commit, and can complete a
  partially uploaded draft on re-dispatch.
- The Go bridge reuses ciphertext-only evaluators, partial-decryptors, and
  explicitly scrubbed encoders via per-context `sync.Pool`s, so cheap
  ciphertext operations no longer reconstruct a `KeySwitcher` on every chunk
  without retaining plaintext-derived buffers in long-lived pools.

### Removed

- The public Python `hoisted` Boolean; composite rotations now always use the
  safe compositional upstream path, and zero rotation is a keyless copy.
- Machine-specific benchmark output from source control and release artifacts;
  release-relevant reports are generated by the manual workflow.

### Fixed

- Bridge validation failures now carry explicit status codes, so a
  non-participant `partial_decrypt` raises `MissingShareError` rather than
  `ContextMismatchError`, and a multiply shape mismatch is no longer reported as
  a missing-key error.
- Public parameter, array, and scalar validation now raises `MKCKKSError`
  subclasses as documented, instead of bare `ValueError`. The types involved
  still subclass `ValueError`, so existing callers are unaffected.
- Scalar broadcasting keeps unused chunk padding zero under later rotations.
- Unsupported lower-level conjugation is a documented `LevelError` rather than
  an upstream panic.
- `__version__` is exported through `__all__`.

### Security

- Malformed native polynomial headers are rejected before entering the pinned
  upstream decoder, closing a fuzz-discovered panic path while keeping upstream
  source unchanged.
- Fractional and Boolean rotations, invalid ABI flags, non-finite native
  inputs, unsafe rescale thresholds, incompatible scales, and exhausted-level
  multiplication are rejected before entering upstream code.

## [0.1.0] - 2026-08-06

### Added

- NumPy real and complex arrays, chunking, full evaluator operations,
  collective decryption, explicit serialization, typed errors, and lifecycle
  safety.
- uv and scikit-build packaging, tests, documentation, licensing provenance,
  and project governance.

### Changed

- Replaced coefficient-copying ctypes structures with an opaque versioned ABI.
- Restored and integrity-locked the pinned upstream Go implementation.
