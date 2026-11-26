#!/usr/bin/env bash
set -euo pipefail
tag="${1:?usage: release-local.sh <tag> [notes]}"
notes="${2:-Rocksoul $tag}"
cd "$(dirname "$0")/.."
rm -rf dist && mkdir dist
for target in windows/amd64/.exe linux/amd64/ linux/arm64/ darwin/arm64/; do
  IFS=/ read -r os arch ext <<<"$target"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags '-s -w' -o "dist/rocksoul-$os-$arch$ext" ./cmd/rocksoul
done
(cd dist && if command -v sha256sum >/dev/null; then sha256sum rocksoul-* > checksums.txt; else shasum -a 256 rocksoul-* > checksums.txt; fi)
gh release create "$tag" dist/* --title "$tag" --notes "$notes"