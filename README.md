# MKCKKS Go2Py

[![CI](https://github.com/NeilYXIN/MKCKKS_Go2Py/actions/workflows/ci.yml/badge.svg)](https://github.com/NeilYXIN/MKCKKS_Go2Py/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.13-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT%20AND%20CC--BY--NC--2.0-lightgrey)](LICENSE)

A NumPy-first Python binding for the multi-key CKKS research implementation
[MKHE-KKLSS](https://github.com/SNUCP/MKHE-KKLSS), pinned to upstream commit
`13fed55fd28270fb4345dd532da24b323ebc5ce3`.

> [!IMPORTANT]
> This is an unaudited v0.x research preview. The combined distribution is
> available under MIT and CC BY-NC 2.0 and is therefore noncommercial
> source-available software, not currently OSI-approved open source.

## What this project does

CKKS is an approximate homomorphic-encryption scheme: it packs real or complex
values into encrypted slots and permits selected arithmetic without first
decrypting those values. MKHE-KKLSS extends that model to multiple key owners.
Each party can encrypt with its own key, evaluated ciphertexts retain the set of
participating party IDs, and every represented party supplies a decryption
share before the result can be recovered.

This project does not define a new cryptographic scheme. It provides a typed,
NumPy-oriented Python interface and a narrow native bridge over a pinned copy of
the original Go implementation. A `Context` owns the parameters and randomly
generated common reference string (CRS); parties, keys, plaintexts, and
ciphertexts from different contexts cannot be mixed. The intended audience is
researchers and developers evaluating multi-key CKKS locally, not production
systems handling sensitive data.

## Highlights

- `float32`/`float64` and `complex64`/`complex128` NumPy input, normalized to
  double precision.
- Packed, transparently chunked encryption for supported arrays within the
  configured resource limits.
- Addition, subtraction, real/complex constants, plaintext products,
  ciphertext multiplication/relinearization, rescaling, level management,
  rotation, conjugation, and collective decryption.
- Opaque native handles and pooled ciphertext-only helpers keep evaluation hot
  paths close to native latency without retaining plaintext-derived buffers.
- Bounded parallel execution accelerates independent ciphertext chunks.
- Versioned, checksummed serialization for contexts/CRS, keys, ciphertexts,
  plaintexts, and decryption shares.
- Conservative circuit-range and approximation-error tracking, with sticky
  warning metadata when an intermediate leaves the tested numerical contract.
- The upstream Go algorithm is byte-for-byte protected by `UPSTREAM.lock`.

In a controlled local reference run on an Apple M3 with CPython 3.13.14,
Python median latency was within 9% of the C ABI for addition and within 1% for
multiplication and rotation. Four workers delivered 3.16x the one-worker
throughput for eight-chunk complex encryption. These figures are illustrative,
not cross-machine guarantees; every release candidate attaches
environment-stamped timing, allocation, and throughput reports. See the
[performance methodology](docs/performance.md).

## Installation

v0.2 is distributed through
[GitHub Releases](https://github.com/NeilYXIN/MKCKKS_Go2Py/releases) rather than
PyPI. Download the wheel matching your platform and install it into a standard
GIL-enabled CPython 3.13 environment:

```console
python -m pip install /path/to/downloaded-wheel.whl
```

The release targets macOS 12 or later on arm64 and x86_64, and
manylinux_2_28 x86_64. A wheel installation does not require Go or a C
compiler. Native Windows is not supported; see the
[known limitations](docs/known-limitations.md) for WSL2 guidance.

GIL-enabled CPython 3.13 is the sole supported interpreter for v0.2. Source
tests, coverage, installed-wheel smoke tests, examples, and release
certification all use that same runtime. Unsupported implementations, versions,
and free-threaded builds fail at import rather than running outside the tested
contract. Another runtime will be added only when it can carry the same gates.

To build from a source checkout, install `uv`, Go 1.26.5 with cgo, and a C
compiler. On macOS, Homebrew can provide the tools:

```console
brew install uv go
uv sync --all-groups
```

`uv sync --all-groups` creates `.venv` under the repository. See the
[development guide](docs/development.md) for Linux setup and verification
commands.

## Quick start

```python
import numpy as np
import mkckks

context = mkckks.Context.create(
    mkckks.Parameters.preset("PN14QP439"),
    workers=4,
    input_policy=mkckks.InputPolicy.VALIDATED,
)
alice = mkckks.Party.generate(context, "alice")
bob = mkckks.Party.generate(context, "bob")

x = np.array([1.0, 2.0])
y = np.array([3.0 + 1.0j, 4.0 - 1.0j])

encrypted_x = alice.encrypt(x)
encrypted_y = bob.encrypt(y)
encrypted = mkckks.Evaluator(context).add(encrypted_x, encrypted_y)
shares = [alice.partial_decrypt(encrypted), bob.partial_decrypt(encrypted)]
result = context.collective_decrypt(encrypted, shares)
report = mkckks.measure_precision(result, x + y)
bound = sum(
    mkckks.precision_bound(value, mkckks.PrecisionClass.BASIC)
    for value in (encrypted_x, encrypted_y, encrypted)
)
assert report.maximum_component_error <= bound
```

The snippet is intentionally compact. Native-backed objects support context
managers and deterministic `close()`; long-running applications should close
objects explicitly rather than relying on interpreter finalization.

Ciphertext multiplication, rotation, and conjugation require contributions
from every participant:

```python
contributions = [
    party.generate_evaluation_keys(
        relinearization=True, rotations=[1], conjugation=True
    )
    for party in (alice, bob)
]
keys = mkckks.EvaluationKeySet.combine(context, contributions)
evaluator = mkckks.Evaluator(context, keys)
product = evaluator.multiply(encrypted, encrypted)
```

## Important semantics

- Integers, booleans, object arrays, empty arrays, NaN, and infinity are
  rejected. Cast integers explicitly only if approximate CKKS semantics are
  intended.
- Arrays are flattened in C order, encrypted in slot-sized chunks, and restored
  to their logical shape after decryption.
- Slot rotation operates on the zero-padded CKKS slot vector, not only the
  logical prefix. `rotate_slots` requires one chunk; `rotate_each_chunk` makes
  blockwise multi-chunk behavior explicit.
- Conjugation is supported at the maximum level. Lower-level conjugation is
  rejected with `LevelError` because the immutable pinned upstream path would
  otherwise index discarded moduli and panic.
- Private-state exports are raw and unencrypted. Protect and authenticate them.
- Serialization checksums detect corruption; they do not authenticate data.
- Existing handles cannot be reused after `fork`; serialize artifacts and use
  multiprocessing `spawn`.
- The default validated policy accepts finite real and imaginary input
  components through `2**20` for the two presets. This is an input bound, not a
  guarantee that cascaded multiplication remains representable. Every
  plaintext/ciphertext exposes tracked magnitude, error, range margin, and
  `correctness_status`; the first predicted circuit-range crossing emits
  `CorrectnessRangeWarning`, and the outside-range state remains sticky.
- Expert literals or wider finite inputs require `InputPolicy.EXPERT` and emit
  a warning. These metadata are engineering evidence, not a security
  certificate.
- Resource limits default to 64 chunks, `2**26` values, and 1 GiB per artifact;
  callers may lower but not raise the hard safety ceilings.

## Verification

The v0.2 release-candidate correctness program is configured to include:

- 250 deterministic PN14 and 150 deterministic PN15 generated circuits of
  length 3–10, with every intermediate decrypted and validated;
- a second 400-circuit Go oracle run comparing the bridge with a direct
  protected-upstream operation on the same source ciphertext and with the clear
  expression;
- all 144 ordered pairs of supported operation families for each preset;
- private/public encryption, real/complex and mixed operands, scalar through
  5D shapes, slot and multi-chunk boundaries, and 1, 2, 4, and 8 parties;
- repeated-squaring range crossings, modulus-boundary rescale tests,
  serialization/fresh-process continuation, malformed-input fuzzing, race and
  lifecycle tests, and a standalone consumer covering all 31 C ABI symbols;
- minimum coverage gates of 95% for the Python wrapper and 93% for new Go
  bridge code, excluding protected upstream code. The latest local bridge-core
  run measured 95.10% statement coverage.

See [the correctness methodology](docs/correctness.md) for the oracle design,
precision bounds, limitations, and release blockers. These tests provide strong
engineering evidence; they are not formal verification or an independent
cryptographic-security audit.

The generated reports describe one specific commit, toolchain, and execution
environment. They should be regenerated for the release commit rather than
treated as a permanent guarantee about later changes.

```console
bash scripts/check.sh
.venv/bin/pytest -m release
```

A bare `pytest` runs only the fast tier; see
[CONTRIBUTING.md](CONTRIBUTING.md) for the three test tiers.

The upstream `cnn` test currently has a pre-existing compile error at the
pinned commit; this is recorded in `baseline/environment.json` and is not
silently patched.

## Citation

If you use this Python wrapper, please cite the publication that describes its
use in the MASER privacy-preserving federated-learning system:

```bibtex
@inproceedings{AlOmar2025MASER,
  author    = {{Al Omar}, Abdullah and Yang, Xin and Choo, Euijin and Ardakanian, Omid},
  title     = {{MASER}: Efficient Privacy-Preserving Cross-Silo Federated Learning with Multi-Key Homomorphic Encryption},
  booktitle = {2025 IEEE International Conference on Big Data (BigData)},
  year      = {2025},
  pages     = {3472--3481},
  doi       = {10.1109/BIGDATA66926.2025.11401805}
}
```

The machine-readable citation is in [CITATION.cff](CITATION.cff). Work relying
on the underlying multi-key CKKS construction should also cite the original
[KKLSS paper](https://eprint.iacr.org/2022/347). The wrapper publication and
the upstream algorithm citation describe different contributions; neither
replaces the other.

## Improvements over the original wrapper

Compared with the legacy implementation at commit
[`7870ebb`](https://github.com/NeilYXIN/MKCKKS_Go2Py/tree/7870ebbb865522b9977171660ef4db26bb73b86f),
v0.2 adds:

- a narrow, versioned C ABI using opaque handles instead of exposing nested Go
  structures or repeatedly copying polynomial coefficients through Python;
- NumPy-first real and complex input with `float32`, `float64`, `complex64`,
  `complex128`, scalar through high-dimensional shape restoration, and
  transparent slot-sized chunking;
- public-key encryption, reusable plaintexts, the documented evaluator
  operations, explicit evaluation-key composition, and partial/collective
  decryption;
- bounded parallel processing of independent chunks, while leaving the
  protected single-ciphertext cryptographic implementation unchanged;
- deterministic handle cleanup, context managers, typed failures, stale-handle
  detection, panic containment, fork protection, and resource limits;
- versioned serialization for contexts/CRS, parties and keys, plaintexts,
  ciphertexts, evaluation material, and decryption shares;
- scale-aware precision measurement and conservative magnitude/error/range
  tracking across chained circuits, including sticky warning metadata when an
  intermediate leaves the tested numerical range;
- uv-based development setup, native wheels/source packaging, executable
  examples, API/security/architecture documentation, and focused CI/release
  workflows.

### Legacy implementation

Users who prefer the original, simpler, double-only wrapper and its narrowly
tested workflow can use commit
[`7870ebb`](https://github.com/NeilYXIN/MKCKKS_Go2Py/tree/7870ebbb865522b9977171660ef4db26bb73b86f).
That snapshot is easier to inspect and preserves the pre-refactor behavior, but
it does not have v0.2's complex support, opaque-handle ABI, serialization,
concurrency, range tracking, failure containment, packaging, or expanded
correctness matrix. “Tested within its original limited workflow” should not be
interpreted as universal correctness, production security, or coverage by the
new v0.2 release-candidate suite.

## Documentation

- [API reference](docs/api.md)
- [Architecture and native lifetime](docs/architecture.md)
- [Parameters, scale, levels, and precision](docs/precision.md)
- [Correctness methodology](docs/correctness.md)
- [Known limitations](docs/known-limitations.md)
- [Serialization and compatibility](docs/serialization.md)
- [API and artifact compatibility policy](docs/compatibility.md)
- [Security and threat model](docs/security.md)
- [Performance methodology](docs/performance.md)
- [Distributed-process example](examples/distributed.py)
- [Comprehensive executable tutorial](examples/comprehensive.py)
- [Original notebook verification](examples/original_notebook_verification.py)
- [Migration guide](docs/migration.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Contributor setup](docs/development.md)

## Project

- [v0.2.0 release notes](docs/release-notes-0.2.0.md) — release highlights,
  performance, runtime scope, and evidence
- [Changelog](CHANGELOG.md) — what changed in each release
- [Contributing](CONTRIBUTING.md) — how to build, test, and submit changes
- [Security policy](SECURITY.md) — how to report a vulnerability
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Citation](CITATION.cff) — how to cite this work

### Development provenance

The original Go-to-Python wrapper and project direction were created by the
repository author. The v0.2 architecture, bridge refactor, Python API, tests,
documentation, and release tooling were implemented extensively with OpenAI
Codex under the maintainer's direction. The protected upstream MKHE-KKLSS Go
implementation was not rewritten by AI: it remains pinned, hash-verified, and
byte-for-byte unchanged from upstream commit `13fed55`.

AI assistance is disclosed as development provenance, not as evidence of
correctness. Confidence comes from reproducible tests, independent comparison
with the protected upstream public API, reviewable source, and release gates.
Maintainers and contributors remain responsible for reviewing changes and
release decisions.

See [NOTICE](NOTICE) and [LICENSE](LICENSE) before redistribution.
