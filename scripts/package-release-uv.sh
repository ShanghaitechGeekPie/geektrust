#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <version> [output-dir]" >&2
  exit 2
fi

version=$1
output_dir=${2:-dist}
uv_version=${UV_VERSION:-0.11.33}

case "$version" in
  ""|*[!A-Za-z0-9._-]*)
    echo "version may contain only letters, digits, dots, underscores, and hyphens" >&2
    exit 2
    ;;
esac
case "$uv_version" in
  ""|*[!0-9.]*)
    echo "UV_VERSION must contain only digits and dots" >&2
    exit 2
    ;;
esac
if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required to download the pinned uv release" >&2
  exit 1
fi

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
base_output="$package_tmp/base"
downloads="$package_tmp/downloads"
mkdir -p "$base_output" "$downloads"

# Build the base packages first so Go build flags stay in package-release.sh.
# Keep the target list below in sync with that script.
bash scripts/package-release.sh "$version" "$base_output"

uv_release_url="https://releases.astral.sh/github/uv/releases/download/$uv_version"
curl_args=(
  --fail
  --location
  --silent
  --show-error
  --connect-timeout 20
  --retry 5
  --retry-delay 2
  --retry-all-errors
)

download_uv() {
  local asset=$1
  if [[ ! -f "$downloads/$asset" ]]; then
    curl "${curl_args[@]}" --output "$downloads/$asset" "$uv_release_url/$asset"
    curl "${curl_args[@]}" --output "$downloads/$asset.sha256" "$uv_release_url/$asset.sha256"
    (
      cd "$downloads"
      if command -v sha256sum >/dev/null 2>&1; then
        sha256sum --check "$asset.sha256"
      else
        shasum -a 256 --check "$asset.sha256"
      fi
    )
  fi
}

license_dir="$package_tmp/uv-licenses"
mkdir -p "$license_dir"
curl "${curl_args[@]}" --output "$license_dir/LICENSE-MIT" \
  "https://raw.githubusercontent.com/astral-sh/uv/$uv_version/LICENSE-MIT"
curl "${curl_args[@]}" --output "$license_dir/LICENSE-APACHE" \
  "https://raw.githubusercontent.com/astral-sh/uv/$uv_version/LICENSE-APACHE"

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
  base_name="geektrust_${version}_${goos}_${goarch}"
  package_name="${base_name}_with-uv"
  work_dir="$package_tmp/work-${goos}-${goarch}"
  uv_dir="$package_tmp/uv-${goos}-${goarch}"
  mkdir -p "$work_dir" "$uv_dir"

  case "$target" in
    linux/amd64) uv_target=x86_64-unknown-linux-gnu ;;
    linux/arm64) uv_target=aarch64-unknown-linux-gnu ;;
    darwin/amd64) uv_target=x86_64-apple-darwin ;;
    darwin/arm64) uv_target=aarch64-apple-darwin ;;
    windows/amd64) uv_target=x86_64-pc-windows-msvc ;;
    windows/arm64) uv_target=aarch64-pc-windows-msvc ;;
    *) echo "unsupported target: $target" >&2; exit 1 ;;
  esac

  if [[ "$goos" == windows ]]; then
    base_archive="$base_output/$base_name.zip"
    uv_asset="uv-$uv_target.zip"
    go run ./tools/zipdir --extract "$base_archive" "$work_dir"
  else
    base_archive="$base_output/$base_name.tar.gz"
    uv_asset="uv-$uv_target.tar.gz"
    tar -C "$work_dir" -xzf "$base_archive"
  fi

  mv "$work_dir/$base_name" "$work_dir/$package_name"
  package_dir="$work_dir/$package_name"
  download_uv "$uv_asset"

  if [[ "$goos" == windows ]]; then
    go run ./tools/zipdir --extract "$downloads/$uv_asset" "$uv_dir"
    cp "$uv_dir/uv.exe" "$uv_dir/uvx.exe" "$package_dir/"
  else
    tar -C "$uv_dir" -xzf "$downloads/$uv_asset"
    cp "$uv_dir/uv-$uv_target/uv" "$uv_dir/uv-$uv_target/uvx" "$package_dir/"
  fi
  mkdir -p "$package_dir/third-party/uv"
  cp "$license_dir/LICENSE-MIT" "$license_dir/LICENSE-APACHE" "$package_dir/third-party/uv/"

  if [[ "$goos" == windows ]]; then
    go run ./tools/zipdir "$package_dir" "$output_dir/$package_name.zip"
  else
    tar -C "$work_dir" -czf "$output_dir/$package_name.tar.gz" "$package_name"
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

echo "release packages with uv $uv_version written to $output_dir"
