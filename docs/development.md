# Development and release guide

Use Python 3.12 for the primary development environment, `uv`, Go 1.26.5 with
cgo enabled, and a C compiler. Python 3.11–3.14 are installation targets, but
the complete local development matrix is pinned to 3.12. On macOS, Homebrew can
install `uv` and Go; on Linux, install `uv` and the exact Go toolchain from their
official distributions plus GCC or Clang. Then run `uv sync --all-groups`.
The project environment is `.venv` at the repository root.

Before opening a change, run:

```console
bash scripts/check.sh
```

That script is the shared definition of the local core gate, and CI invokes the
same stages. It runs, in order: the protected-upstream
verification, Go tests and vet, the race subset, the Go bridge-coverage gate,
`ruff format`/`ruff check`, `mypy`, `reuse lint`, `pytest -m "not release"`, the
standalone C ABI suite, the ABI symbol snapshot, and `pip-audit` over the locked
dependency closure. Pass stage names to run a subset, for example
`bash scripts/check.sh lint types`. Every stage except `audit` works offline.

CI also enables Python coverage reporting:

```console
uv run pytest -m "not release" --cov=src/mkckks --cov-branch --cov-report=term-missing
```

The workflow then executes the tutorial notebook and distributed example and
runs platform-specific wheel builds and smoke tests; those jobs are not part of
the portable local script.

The pinned upstream `cnn` test has a pre-existing compile failure recorded in
`baseline/environment.json`. The protected `mkbfv` package also has pre-existing
`go vet` diagnostics, so the vet gate covers the bridge and the
wrapper-relevant `mkckks`/`mkrlwe` packages. Do not patch protected Go to
conceal either condition.

Automation is intentionally limited to two workflows for v0.2. `CI` runs on
pull requests and pushes to `main`; it performs the correctness, race,
coverage, C ABI, documentation-example, wheel-smoke, and Python 3.11–3.14
checks. `Release candidate` is manual. It repeats CI, runs the focused release
matrix, fuzzing, 10,000-cycle soak, reproducible platform builds, benchmarks,
a CycloneDX SBOM of the runtime dependency closure, and compatibility-bundle
generation, then creates a draft GitHub prerelease. It refuses to start if the
target version tag resolves to another commit, and creating and uploading the
draft are separately idempotent, so a re-dispatch completes a partial upload.
The first job resolves the selected target to one commit SHA; every platform
artifact and the release tag use that same immutable commit. The workflow never
publishes to PyPI and requires no project publishing credential.

Python wrapper branch coverage is gated at 95%. The latest local Go bridge-core
run measured 95.08% statement coverage, with a 93% gate for maintenance
headroom. It is reported separately from the cgo export shim. The operational
ABI and its failure boundary are additionally exercised by the standalone C
consumer.
There are no scheduled jobs in v0.2. High-cost release tests run only when the
maintainer deliberately dispatches the release-candidate workflow.

Dependabot covers GitHub Actions and the `uv` lockfile. It deliberately does not
cover Go modules: `go.mod` is byte-locked by `UPSTREAM.lock`, and the pinned
Lattigo version is part of the certified upstream snapshot, so bumping it is an
upstream re-certification decision rather than a routine dependency update.

After the implementation branch is pushed, the maintainer enables Actions in
**Settings → Actions → General**, opens a pull request, and merges only after CI
is green. Then run **Actions → Release candidate → Run workflow** with target
`main`; the version is read from `pyproject.toml`. If it succeeds, inspect the draft under **Releases**,
confirm the prerelease and noncommercial/unaudited wording, and publish it
manually. The workflows do not require a local GitHub CLI installation, PyPI
account, long-lived token, or self-hosted runner. Availability and billing of
GitHub-hosted runners remain subject to the repository's GitHub plan and
settings.
