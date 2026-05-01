#!/usr/bin/env bash
#
# Build pcc2k-agent for one or both targets via Docker. No system Go
# required. Output is byte-reproducible per HIPAA-READY.md §4
# (-trimpath -buildvcs=false plus the static, pinned go.mod).
#
# Usage:
#   ./scripts/build.sh             # both targets
#   ./scripts/build.sh linux       # linux/amd64 only
#   ./scripts/build.sh windows     # windows/amd64 only

set -euo pipefail

cd "$(dirname "$0")/.."

target="${1:-both}"
image="golang:1.22-alpine"
ldflags="-s -w"
flags="-trimpath -buildvcs=false"

build_linux() {
  echo "==> linux/amd64"
  docker run --rm -v "$PWD:/src" -w /src "$image" sh -c "
    go mod tidy && \
    CGO_ENABLED=0 go build $flags -ldflags='$ldflags' -o pcc2k-agent ./cmd/agent"
  ls -l pcc2k-agent
  sha256sum pcc2k-agent
}

build_windows() {
  echo "==> windows/amd64"
  docker run --rm -v "$PWD:/src" -w /src \
    -e GOOS=windows -e GOARCH=amd64 -e CGO_ENABLED=0 \
    "$image" sh -c "
    go build $flags -ldflags='$ldflags' -o pcc2k-agent.exe ./cmd/agent"
  ls -l pcc2k-agent.exe
  sha256sum pcc2k-agent.exe
}

case "$target" in
  linux)   build_linux ;;
  windows) build_windows ;;
  both)    build_linux; build_windows ;;
  *) echo "usage: $0 [linux|windows|both]" >&2; exit 2 ;;
esac
