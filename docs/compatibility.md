# Versioning and compatibility policy

The Python API follows SemVer after 1.0. During v0.x, breaking changes are
allowed only when documented in the changelog and migration guide. In 1.x, a
public API removal receives at least one minor release of deprecation warnings.

The native ABI major is encoded in every exported symbol (`mkckks_v1_...`). A
future incompatible ABI uses a new symbol prefix and may coexist during a
migration period; an installed Python package refuses an unexpected ABI.

Serialization has explicit major/minor versions at both native and Python
layers. Readers reject future major versions and do not silently upgrade or
rewrite input. Minor readers may accept an older compatible minor version, but
writers emit only their current version. Context fingerprints bind every
dependent artifact to the exact CRS, parameter literal, upstream commit, and
ABI.

No scheduled release assumes upstream relicensing. Unless the upstream terms
change independently, the bundled distribution remains noncommercial
source-available even when its wrapper API becomes stable.
