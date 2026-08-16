# Contributing

Install `uv` and a tested Go toolchain, then:

```console
uv sync --all-groups
bash scripts/check.sh
```

`scripts/check.sh` runs the core source checks shared with CI, in the order that
fails fastest, and reports every failing stage rather than stopping at the
first. CI invokes the same stages directly. CI additionally executes the
notebook and distributed example, enables Python coverage reporting, and builds
and smoke-tests platform wheels.

While iterating, run only the stages you need:

```console
bash scripts/check.sh lint types      # fast feedback
bash scripts/check.sh pytest          # Python tests only
```

Stages are `upstream`, `go`, `race`, `coverage`, `lint`, `types`, `licence`,
`pytest`, `cabi`, `abi`, and `audit`. Only `audit` needs network access: it
resolves the locked dependency closure against the PyPI advisory database.

## Test tiers

Python tests are tiered by cost, so the default command is the one you can
afford to run on every change:

| Command | Scope | Approximate time |
| --- | --- | --- |
| `pytest` | Fast tier; the default, which deselects `slow` and `release` | ~15s |
| `pytest -m "not release"` | Adds the `slow` tier; what CI runs, so match it before pushing | ~75s |
| `pytest -m release` | The full release correctness matrix | Several minutes |

The default lives in `addopts` in `pyproject.toml`. Passing `-m` on the command
line replaces it, which is how the two fuller tiers are selected.

Mark a new test `slow` if it takes more than a couple of seconds, and `release`
if it belongs to the high-cost release correctness matrix.

## Ground rules

Do not modify protected upstream paths. Propose bridge or Python changes with
tests, documentation, and benchmark evidence where performance is affected.
Commits contributed to the project must include a Developer Certificate of
Origin `Signed-off-by` line.
