#!/usr/bin/env bash
set -euo pipefail

abi_build_dir="$(mktemp -d)"
if [[ "$(uname -s)" == "Darwin" ]]; then
  abi_library="$abi_build_dir/libmkckks.dylib"
else
  abi_library="$abi_build_dir/libmkckks.so"
fi

GOCACHE="$abi_build_dir/go-cache" go build -trimpath -buildvcs=false \
  -buildmode=c-shared -o "$abi_library" ./bridge
cc -Wall -Wextra -Werror -I"$abi_build_dir" tests/c_smoke.c \
  -L"$abi_build_dir" -lmkckks -o "$abi_build_dir/c-smoke"
if [[ "$(uname -s)" == "Darwin" ]]; then
  DYLD_LIBRARY_PATH="$abi_build_dir" "$abi_build_dir/c-smoke"
else
  LD_LIBRARY_PATH="$abi_build_dir" "$abi_build_dir/c-smoke"
fi

