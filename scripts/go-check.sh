#!/usr/bin/env bash
# Static and unit gates for the Go KeePass module (go/).
set -euo pipefail
cd "$(dirname "$0")/../go"
export GOFLAGS="${GOFLAGS:--mod=mod}"
# Use the pinned (Nix) toolchain; go.mod's toolchain line names the newest tested.
export GOTOOLCHAIN=local

unformatted="$(gofmt -l .)"
if [[ -n "$unformatted" ]]; then
  printf 'gofmt: unformatted files:\n%s\n' "$unformatted" >&2
  exit 1
fi
for tags in "" nasblackbox; do
  go vet -tags "$tags" ./...
  staticcheck -tags "$tags" ./...
  gosec -quiet -tags "$tags" ./...
done
exhaustive ./...
go test -count=1 ./...
