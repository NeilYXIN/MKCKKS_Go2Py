# Roadmap

- Complete controlled cross-platform performance reports and publish the first
  certified wheel set with checksums and correctness reports.
- Expand per-symbol C adversarial coverage across additional argument
  permutations, and evaluate targeted mutation testing where it provides
  useful evidence without disproportionate maintenance cost.
- Beginning with the release after v0.2, import the v0.2 compatibility bundle
  as a release gate.
- Complete the full preset/party/dtype/shape/chunk/depth cross-product and
  four-layer performance matrix on the release infrastructure; local pairwise
  and oracle tests do not substitute for those scheduled release results.
- Add exact integer support as a separate MKBFV namespace.
- Add Windows wheels and reviewed encrypted private-state storage.
- Seek independent review before making production-security claims.

The bundled distribution remains deliberately labeled noncommercial
source-available under the existing upstream terms. No release milestone
assumes that upstream relicensing will occur.
