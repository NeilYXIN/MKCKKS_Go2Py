# Development and release guide

Use Python 3.12 for the primary development environment, `uv`, Go 1.26.5 with
cgo enabled, and a C compiler. Python 3.11–3.14 are installation targets, but
the complete local development matrix is pinned to 3.12. On macOS, Homebrew can
install `uv` and Go; on Linux, install `uv` and the exact Go toolchain from their
official distributions plus GCC or Clang. Then run `uv sync --all-groups`.
The project environment is `.venv` at the repository root.

Before opening a change, run:

```console
uv run python scripts/verify_upstream.py
go test ./mkckks ./mkrlwe ./mkbfv ./bridge
go vet ./bridge ./mkckks ./mkrlwe
go test -race -run 'Test(WorkerAndConcurrentOperationMatrix|ConcurrentEvaluationKeyUse|RegistryRejectsStaleHandles)$' ./bridge
bash scripts/check_go_coverage.sh
uv run ruff format --check src tests scripts examples benchmarks
uv run ruff check src tests scripts examples benchmarks
uv run mypy src/mkckks examples/comprehensive.py
uv run pytest -m "not release" --cov=src/mkckks --cov-branch --cov-report=term-missing
uv run reuse lint
bash scripts/test_c_abi.sh
uv run python scripts/verify_abi_symbols.py
```

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
and compatibility-bundle generation, then creates a draft GitHub prerelease.
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

After the implementation branch is pushed, the maintainer enables Actions in
**Settings → Actions → General**, opens a pull request, and merges only after CI
is green. Then run **Actions → Release candidate → Run workflow** with target
`main`; the version is read from `pyproject.toml`. If it succeeds, inspect the draft under **Releases**,
confirm the prerelease and noncommercial/unaudited wording, and publish it
manually. The workflows do not require a local GitHub CLI installation, PyPI
account, long-lived token, or self-hosted runner. Availability and billing of
GitHub-hosted runners remain subject to the repository's GitHub plan and
settings.
