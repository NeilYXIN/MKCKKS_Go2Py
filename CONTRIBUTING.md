# Contributing

Install `uv` and a tested Go toolchain, run `uv sync --all-groups`, and execute:

```console
.venv/bin/python scripts/verify_upstream.py
GOCACHE=/tmp/mkckks-go-cache go test ./mkckks ./mkrlwe ./mkbfv ./bridge
GOCACHE=/tmp/mkckks-go-cache go vet ./bridge ./mkckks ./mkrlwe
bash scripts/check_go_coverage.sh
.venv/bin/ruff format --check src tests scripts examples benchmarks
.venv/bin/ruff check src tests scripts examples benchmarks
.venv/bin/mypy src/mkckks examples/comprehensive.py scripts/generate_compatibility_bundle.py
.venv/bin/pytest -m "not release"
.venv/bin/reuse lint
bash scripts/test_c_abi.sh
.venv/bin/python scripts/verify_abi_symbols.py
```

Do not modify protected upstream paths. Propose bridge or Python changes with
tests, documentation, and benchmark evidence where performance is affected.
Commits contributed to the project must include a Developer Certificate of
Origin `Signed-off-by` line.
