# Known limitations

- The bundled upstream implementation is CC BY-NC 2.0. The combined package is
  noncommercial source-available research software, not OSI open source.
- Neither the upstream cryptography nor these presets have been independently
  audited by this project. Engineering tests do not establish production
  security, malicious-party security, CCA security, threshold policy, or
  side-channel resistance.
- The protected upstream `cnn` test has a pre-existing compile failure at the
  pinned commit. It is recorded in the baseline and is not patched or shipped
  as part of the Python distribution.
- The protected upstream `mkbfv` package has pre-existing `go vet` diagnostics
  for unreachable code and unkeyed dependency struct literals. Its tests still
  pass unchanged; the Python wrapper does not use or ship `mkbfv`, and the
  release vet gate covers the bridge plus `mkckks` and `mkrlwe`.
- One CKKS ciphertext is evaluated single-threaded. Parallel speedup applies to
  independent chunks; small single-chunk inputs will not benefit from workers.
- Validated input components through `2**20` can still produce intermediates
  outside the representable centered-modulus range under cascaded
  multiplication. The wrapper warns and marks that ciphertext and every
  descendant outside the tracked range, but deliberately continues evaluation.
  Conservative tracking can warn before a particular computation visibly
  fails, and no claim is made for the numerical accuracy of outside-range
  descendants.
- Rotation of each chunk is blockwise and is not equivalent to `numpy.roll`
  across a multi-chunk logical array.
- Conjugation below the maximum level is rejected with `LevelError`. The pinned
  upstream implementation calls an all-moduli permutation after levels have
  been discarded, which would otherwise panic. The bridge does not reimplement
  that protected cryptographic operation.
- Context/CRS and evaluation-key artifacts can be very large. Byte-based import
  temporarily retains envelope and native payload copies; streaming APIs are
  deferred until profiling justifies them.
- Native Windows wheels, PyPy, free-threaded CPython, and Python subinterpreters
  are unsupported. v0.2 requires standard GIL-enabled CPython 3.13; unsupported
  interpreter builds fail at import. Windows users should use WSL2/Ubuntu source
  installation.
- Private-state exports and decryption shares are sensitive, unencrypted bytes.
  Callers must provide authenticated transport and secure storage.
- Go/Python cannot guarantee complete secret zeroization. Core dumps, swap,
  process inspection, allocator copies, and unmanaged serialized copies remain
  operational risks.
- The library provides local cryptographic computation, not an authenticated
  distributed protocol. It does not authenticate parties or prevent malformed
  or malicious protocol contributions.
