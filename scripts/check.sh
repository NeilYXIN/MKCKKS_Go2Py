#!/usr/bin/env bash
# Run the shared core source checks used by CI, in the order that fails fastest.
#
#   bash scripts/check.sh          # everything
#   bash scripts/check.sh lint     # only the named stages
#
# Stages: upstream, go, race, coverage, lint, types, licence, pytest, cabi, abi, audit
#
# The audit stage queries the PyPI advisory database, so it needs network access.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -x .venv/bin/python ]]; then
  run() { .venv/bin/"$@"; }
  python_bin=.venv/bin/python
else
  echo "note: .venv not found, falling back to 'uv run'. Create it with: uv sync --all-groups" >&2
  run() { uv run "$@"; }
  python_bin="uv run python"
fi

# Locally, keep tool caches in a portable temporary location so a full run does
# not depend on ambient home-directory permissions. CI manages its own caches.
if [[ -z "${GITHUB_ACTIONS:-}" ]]; then
  export GOCACHE="${GOCACHE:-/tmp/mkckks-go-cache}"
  export UV_CACHE_DIR="${UV_CACHE_DIR:-/tmp/mkckks-uv-cache}"
fi

requested=("$@")
requested_count=$#
supported=(upstream go race coverage lint types licence pytest cabi abi audit)
if ((requested_count > 0)); then
  for requested_stage in "${requested[@]}"; do
    valid=false
    for supported_stage in "${supported[@]}"; do
      if [[ "$requested_stage" == "$supported_stage" ]]; then
        valid=true
        break
      fi
    done
    if [[ "$valid" != true ]]; then
      printf 'Unknown check stage %q. Choose one of: %s\n' \
        "$requested_stage" "${supported[*]}" >&2
      exit 2
    fi
  done
fi

wanted() {
  ((requested_count == 0)) && return 0
  local stage
  for stage in "${requested[@]}"; do
    [[ "$stage" == "$1" ]] && return 0
  done
  return 1
}

# Audit the locked closure instead of the live interpreter: a uv-managed .venv
# has no pip for pip-audit to introspect.
audit_locked_dependencies() {
  local requirements="${TMPDIR:-/tmp}/mkckks-locked-requirements.txt"
  local status=0
  uv export --frozen --all-groups --no-emit-project --format requirements-txt \
    -o "$requirements" >/dev/null &&
    run pip-audit --strict --require-hashes --progress-spinner off -r "$requirements" || status=$?
  rm -f "$requirements"
  return "$status"
}

failures=()
failure_count=0
stage() {
  local name="$1"
  shift
  wanted "$name" || return 0
  echo "==> $name"
  if ! "$@"; then
    failures+=("$name")
    failure_count=$((failure_count + 1))
    echo "!!! $name failed" >&2
  fi
}

stage upstream $python_bin scripts/verify_upstream.py
stage go go test ./mkckks ./mkrlwe ./mkbfv ./bridge
stage go go vet ./bridge ./mkckks ./mkrlwe
stage race go test -race \
  -run 'Test(WorkerAndConcurrentOperationMatrix|ConcurrentEvaluationKeyUse|RegistryRejectsStaleHandles)$' \
  ./bridge
stage coverage bash scripts/check_go_coverage.sh
stage lint run ruff format --check src tests scripts examples benchmarks
stage lint run ruff check src tests scripts examples benchmarks
stage types run mypy src/mkckks examples/comprehensive.py \
  examples/original_notebook_verification.py scripts/generate_compatibility_bundle.py
stage licence run reuse lint
# CI runs the slow tier too; -m matches .github/workflows/ci.yml.
stage pytest run pytest -m "not release"
stage cabi bash scripts/test_c_abi.sh
stage abi $python_bin scripts/verify_abi_symbols.py
stage audit audit_locked_dependencies

if ((failure_count > 0)); then
  printf 'FAILED: %s\n' "${failures[*]}" >&2
  exit 1
fi
echo "All checks passed."
