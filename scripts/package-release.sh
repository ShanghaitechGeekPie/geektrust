#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <version> [output-dir]" >&2
  exit 2
fi

version=$1
output_dir=${2:-dist}

case "$version" in
  ""|*[!A-Za-z0-9._-]*)
    echo "version may contain only letters, digits, dots, underscores, and hyphens" >&2
    exit 2
    ;;
esac

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

mkdir -p "$output_dir"
if [[ -n $(find "$output_dir" -mindepth 1 -print -quit) ]]; then
  echo "output directory must be empty: $output_dir" >&2
  exit 1
fi
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)

package_tmp=$(mktemp -d)
trap 'rm -rf "$package_tmp"' EXIT

npm --prefix web ci
npm --prefix web run build

targets=(
  linux/amd64
  linux/arm64
  darwin/amd64
  darwin/arm64
  windows/amd64
  windows/arm64
)

for target in "${targets[@]}"; do
  goos=${target%/*}
  goarch=${target#*/}
  package_name="geektrust_${version}_${goos}_${goarch}"
  package_dir="$package_tmp/$package_name"
  binary=geektrust
  archive="$output_dir/$package_name.tar.gz"

  if [[ "$goos" == windows ]]; then
    binary=geektrust.exe
    archive="$output_dir/$package_name.zip"
  fi

  mkdir -p "$package_dir"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -buildvcs=true -ldflags="-s -w -X main.version=$version" \
    -o "$package_dir/$binary" ./cmd/geektrust
  cp README.md config.example.toml "$package_dir/"

  if [[ "$goos" == windows ]]; then
    go run ./tools/zipdir "$package_dir" "$archive"
  else
    tar -C "$package_tmp" -czf "$archive" "$package_name"
  fi
done

if command -v sha256sum >/dev/null 2>&1; then
  (
    cd "$output_dir"
    sha256sum ./*.tar.gz ./*.zip > SHA256SUMS
  )
else
  (
    cd "$output_dir"
    shasum -a 256 ./*.tar.gz ./*.zip > SHA256SUMS
  )
fi

echo "release packages written to $output_dir"
