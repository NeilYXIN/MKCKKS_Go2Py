# Parameters, levels, and precision

`PN14QP439` and `PN15QP880` are upstream-tested parameter literals, not a new
security recommendation. Expert literals are structurally checked by Python
and Lattigo but are not automatically assigned a security level.

CKKS is approximate. Tests compare real and imaginary errors against direct
upstream behavior rather than rounding displayed values. Multiplication and
rescaling consume levels; operations fail explicitly when no valid level
remains.

Inputs normalize to `float64` or `complex128`. Integer and boolean arrays are
rejected because accepting them silently could imply exact arithmetic.

`InputPolicy.VALIDATED` is available only for the two named presets and accepts
finite real and imaginary input components up to `2**20`. That input-component
limit is not a safe bound for every intermediate expression. For example,
repeated squaring can exceed the centered CKKS modulus range before it exhausts
levels. `InputPolicy.EXPERT` is required for literal parameters and permits
wider finite values within resource limits while warning that they are outside
the tested correctness domain.

Plaintexts and ciphertexts expose four read-only numerical-contract fields:

- `tracked_magnitude_bound`: conservative maximum complex-component magnitude;
- `tracked_error_bound`: propagated maximum real/imaginary component error;
- `range_margin_bits`: estimated centered-modulus headroom after three safety
  bits;
- `correctness_status`: validated/expert context combined with whether the
  circuit has ever left the tracked range.

The margin is calculated in log space as
`sum(log2(Q[:level+1])) - log2(scale) - 1 - 3 - log2(magnitude + error)`.
Addition sums bounds; multiplication uses
`|y| ex + |x| ey + ex ey + local`; rotation, conjugation, dropping, and
rescaling retain magnitude and add their local error. Initial encoding also
includes a conservative floating-point FFT roundoff term, which matters near
the `2**20` input boundary.

When the margin first becomes negative, the operation succeeds but emits one
`CorrectnessRangeWarning`. The resulting ciphertext and all descendants remain
`OUTSIDE_TRACKED_RANGE`, even after multiplication by zero. A warning means the
project no longer claims its test-derived numerical bound for that descendant;
it does not prove that the particular value is wrong. Conversely, a within-
range status is not a cryptographic-security certificate.

The pinned upstream fractional complex-constant path is numerically unreliable.
The bridge therefore encodes complex constants as constant plaintexts and uses
the upstream plaintext multiplication path. This changes scale and may require
an explicit rescale in a longer circuit. The path is covered by the independent
upstream differential tests and does not modify upstream source.

The pinned upstream `RescaleNew` also allocates a zero output when its threshold
requires no modulus consumption. The bridge detects that no-level-change case
and returns an explicit ciphertext copy, so public rescaling has safe immutable
no-op semantics. A rescale is also rejected if its simulated result would fall
below half the configured context scale. This prevents upstream from accepting
a technically positive but unusably low scale outside the wrapper's precision
contract.

For a circuit, record the starting level and scale of every ciphertext. Addition
requires compatible scales; ciphertext multiplication increases scale and
normally requires rescaling; dropping a level without rescaling discards a
modulus but does not correct scale. A chain must never request more drops or
rescales than the current `ciphertext.level`. The wrapper raises `LevelError`
instead of allowing a native panic.

Measure precision against the unencrypted NumPy expression using both maximum
absolute error and RMS error, separately for real and imaginary components.
Use tolerances that grow with multiplication depth and input magnitude, and
record the applicable preset, scale, depth, and deterministic test inputs with
the result. Property-test failures also retain their reproducing example or
seed. Decimal display rounding and a BFV-style “noise budget” are not valid
CKKS error measurements.

The shared `precision_bound(parameters_or_ciphertext, operation)` helper
implements the test contract. Passing `Parameters` uses the initial configured
scale; passing `Ciphertext` uses its actual current scale and is required after
rescaling or multiplication. On normalized `[-1, 1]` vectors its absolute
component bounds are:

- basic encoding/encryption/add/subtract/drop/rescale: `2**(-log2(scale) +
  log2(slots) + 8)`;
- rotations and conjugation: the same formula with `+ 11`;
- ciphertext/plaintext multiplication and fractional constants: `+ 12`.

`measure_precision(actual, expected)` reports maximum real and imaginary error,
RMS error, minimum observed precision bits, and sample count. Concatenated
circuits must propagate the incoming approximation error through the clear
expression and add each primitive's local bound; a failing bound is investigated
instead of widened automatically.
