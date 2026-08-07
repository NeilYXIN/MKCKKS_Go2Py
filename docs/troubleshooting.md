# Troubleshooting

- **Native library missing:** install a platform wheel or build from source with
  Go, cgo, and Clang/GCC.
- **Context mismatch:** all parties must import the same serialized context/CRS,
  not create equivalent-looking parameter contexts independently.
- **Missing evaluation key:** collect a contribution from every participant in
  the ciphertext for multiplication, rotation, or conjugation.
- **Level error:** shorten the circuit or select an appropriate upstream-tested
  parameter profile; rescaling and multiplication consume levels. A tiny
  rescale threshold that would consume level zero, or would leave less than
  half the configured scale, is rejected before upstream.
- **Conjugation level error:** conjugate before the first multiplication,
  rescale, or explicit level drop. The pinned upstream implementation cannot
  safely conjugate a lower-level ciphertext, so the wrapper rejects it.
- **Scale incompatibility:** rescale operands to a compatible level/scale; the
  wrapper rejects inexact scale-ratio alignment instead of flooring a ratio.
- **Resource limit:** reduce the array/artifact, process fewer chunks, or lower
  application-level batch size. Hard ceilings cannot be raised.
- **Expert-policy warning:** use a named preset and keep components within
  `2**20` for the tested input domain, or explicitly accept behavior outside
  that domain with `InputPolicy.EXPERT`.
- **Fork safety error:** use multiprocessing `spawn` and explicit artifacts.
- **Integer dtype rejected:** cast deliberately to floating point only if
  approximate arithmetic is acceptable.
- **Windows:** native Windows wheels are unsupported. Use WSL2 with Ubuntu,
  install Go, a C compiler, and uv, then follow the source-build instructions.
