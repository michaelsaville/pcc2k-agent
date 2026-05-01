#!/usr/bin/env bash
#
# Build the Windows MSI installer via wixl (from msitools), running in
# a Fedora Docker container so no system .NET / msitools install is
# required on the host.
#
# Why wixl, not WiX 5: WiX 5 is officially Windows-only, and while it
# starts on Linux, it has path-handling bugs in StandardDirectory that
# make Linux builds unreliable. wixl is a pragmatic WiX 3 reimplementation
# in C — purpose-built for cross-platform native builds.
#
# Prereqs:
#   - pcc2k-agent.exe must exist (built via scripts/build.sh windows;
#     this script chains that automatically)
#
# Usage:
#   ./scripts/build-msi.sh                 # version=0.0.0.0 (dev)
#   ./scripts/build-msi.sh 0.3.0.0         # explicit version
#
# The MSI is unsigned. Authenticode signing happens in a separate
# post-build step once the EV cert lands. Don't ship to clinical
# clients before signing.

set -euo pipefail

cd "$(dirname "$0")/.."

version="${1:-0.0.0.0}"
out="pcc2k-agent-${version}.msi"

if [[ ! -f "pcc2k-agent.exe" ]]; then
  echo "==> pcc2k-agent.exe not found; building first"
  ./scripts/build.sh windows
fi

echo "==> wixl (containerized) — building $out (version $version)"

docker run --rm -v "$PWD:/work" -w /work fedora:39 sh -c "
  set -e
  dnf install -y --setopt=install_weak_deps=False msitools >/dev/null 2>&1
  wixl --define Version=$version \
       -I /work \
       -o $out \
       installer/pcc2k-agent.wxs
"

ls -l "$out"
sha256sum "$out"
