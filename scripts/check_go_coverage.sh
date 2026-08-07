#!/usr/bin/env bash
set -euo pipefail

coverage_dir="$(mktemp -d)"
profile="$coverage_dir/bridge.cover"
core_profile="$coverage_dir/bridge-core.cover"
GOCACHE="$coverage_dir/go-cache" go test -coverprofile="$profile" ./bridge

# bridge.go is the thin cgo export surface. It is exercised by the standalone C
# smoke test and Python integration suite because Go does not instrument calls
# entering a c-shared library during `go test`. The threshold below covers all
# native model, artifact parser, and registry code.
grep -v 'bridge/bridge.go' "$profile" > "$core_profile"
total="$(awk 'NR > 1 { statements += $2; if ($3 > 0) covered += $2 } END { printf "%.2f", 100 * covered / statements }' "$core_profile")"
awk -v total="$total" 'BEGIN { if (total + 0 < 93) exit 1 }'
echo "Go bridge core coverage: $total% (required: 93%)"
