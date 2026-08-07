# Serialization compatibility

The current formats are Python envelope 1.0 and native envelope 1.0. Artifacts
have two checksummed layers. The Python envelope stores explicit 16-bit major
and minor fields (currently 1 and 0), rather than encoding version only in its
magic bytes, and preserves
logical shape and public object metadata alongside a native binary envelope holding
the cryptographic representation. Both include explicit major versions.

The native envelope includes artifact kind, pinned upstream commit,
context/CRS fingerprint, bounded lengths, and a SHA-256 corruption checksum.
Maps are serialized in sorted order. Imports reject mismatched contexts,
unsupported versions, corrupted data, excessive lengths, and trailing bytes.
Participant IDs are canonicalized and every Python-visible kind, context,
party ID, ciphertext ID, participant set, length, complexity flag, level, and
scale is cross-checked against native metadata before an object is returned.
Plaintext/ciphertext envelopes also store tracked magnitude, propagated error,
range margin, and sticky outside-range state. Import cross-checks those fields
against the native payload, so recomputing only the outer checksum cannot
relabel an outside-range circuit as within the tested contract.

This cross-check detects corruption and inconsistent envelope edits; it is not
authentication. An actor able to modify an artifact can also recompute its
checksums. Applications must authenticate the artifact and its transport before
relying on either its cryptographic payload or its correctness metadata.

Context exports include the actual random CRS and are large (the PN14 context
is roughly 100 MiB). Parties in separate processes must import the same context
artifact before importing related keys or ciphertexts.

No artifact is implicitly pickleable. Private party state uses the deliberately
named `export_private_state()` API and is not encrypted at rest.

Every Python envelope contains a stable 128-bit artifact identifier derived
from its native payload. It supports binding and tracing but, like the
checksum, is not an authenticator. Artifacts and logical arrays are rejected
above conservative 1 GiB and 2^26-value limits before allocation.

Minor-format additions must remain backward compatible. Unsupported minor and
future major versions are rejected and are never silently upgraded. v0.2 is the
first compatibility baseline, so its manual release workflow generates and
attaches a bundle containing every artifact kind. Future releases must import
that released bundle before a release candidate is published.
