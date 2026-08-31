#!/usr/bin/env bash
set -euo pipefail

supported_platform_target() {
    case "$1:$2" in
        linux-amd64:x86_64-unknown-linux-musl | \
            linux-arm64:aarch64-unknown-linux-musl | \
            macos-amd64:x86_64-apple-darwin | \
            macos-arm64:aarch64-apple-darwin) return 0 ;;
        *) return 1 ;;
    esac
}

if [[ "${1:-}" == "--self-test" ]]; then
    if [[ $# -ne 1 ]]; then
        echo "usage: $0 --self-test" >&2
        exit 2
    fi

    valid_pairs=(
        "linux-amd64:x86_64-unknown-linux-musl"
        "linux-arm64:aarch64-unknown-linux-musl"
        "macos-amd64:x86_64-apple-darwin"
        "macos-arm64:aarch64-apple-darwin"
    )
    invalid_pairs=(
        "macos-amd64:aarch64-apple-darwin"
        "linux-arm64:x86_64-unknown-linux-musl"
        "windows-amd64:x86_64-pc-windows-msvc"
    )

    for pair in "${valid_pairs[@]}"; do
        platform="${pair%%:*}"
        target="${pair#*:}"
        supported_platform_target "$platform" "$target"
    done
    for pair in "${invalid_pairs[@]}"; do
        platform="${pair%%:*}"
        target="${pair#*:}"
        if supported_platform_target "$platform" "$target"; then
            echo "invalid platform/target pair was accepted: $platform / $target" >&2
            exit 1
        fi
    done
    echo "h00ligan-platforms: OK (4 native release targets; mismatch canaries rejected)"
    exit 0
fi

if [[ $# -ne 8 ]]; then
    echo "usage: $0 VERSION PLATFORM TARGET BINARY IDENTITY_FILE SBOM NOTICES OUTPUT_DIR" >&2
    exit 2
fi

version="$1"
platform="$2"
target="$3"
binary="$4"
identity_file="$5"
sbom="$6"
notices="$7"
output_dir="${8:-}"

# The argument count above deliberately catches a missing output directory,
# but shellcheck cannot infer the eighth argument after that guard.
if [[ -z "$output_dir" ]]; then
    echo "output directory is required" >&2
    exit 2
fi

if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "release version must be plain SemVer: $version" >&2
    exit 2
fi

if ! supported_platform_target "$platform" "$target"; then
    echo "unsupported platform/target pair: $platform / $target" >&2
    exit 2
fi

for required in "$binary" "$identity_file" "$sbom" "$notices"; do
    if [[ ! -f "$required" ]]; then
        echo "required release input is missing: $required" >&2
        exit 2
    fi
done

repo_root="$(git rev-parse --show-toplevel)"
commit="$(git rev-parse HEAD)"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
build_date="$(date --utc --date="@$source_date_epoch" +%Y-%m-%dT%H:%M:%SZ)"
identity="$(tr -d '\r\n' < "$identity_file")"
bundle_name="h00ligan-${version}-${platform}"
archive="$output_dir/${bundle_name}.tar.gz"

if [[ "$identity" != "h00ligan ${version}+"* ]]; then
    echo "binary identity does not match release version: $identity" >&2
    exit 1
fi
if [[ -e "$archive" ]]; then
    echo "refusing to overwrite existing archive: $archive" >&2
    exit 1
fi

mkdir -p "$output_dir"
stage_parent="$(mktemp -d)"
trap 'rm -rf -- "$stage_parent"' EXIT
stage="$stage_parent/$bundle_name"
mkdir -p "$stage"

install -m 0755 "$binary" "$stage/h00ligan"
install -m 0644 "$repo_root/crates/h00ligan/README.md" "$stage/README.md"
install -m 0644 "$repo_root/crates/h00ligan/CHANGELOG.md" "$stage/CHANGELOG.md"
install -m 0644 "$repo_root/LICENSE-MIT" "$stage/LICENSE-MIT"
install -m 0644 "$repo_root/LICENSE-APACHE" "$stage/LICENSE-APACHE"
install -m 0644 "$repo_root/LICENSE-BSL" "$stage/LICENSE-BSL"
install -m 0644 "$sbom" "$stage/h00ligan.cdx.json"
install -m 0644 "$notices" "$stage/THIRD-PARTY-LICENSES.html"

{
    echo "component=h00ligan"
    echo "version=$version"
    echo "build_identity=$identity"
    echo "git_commit=$commit"
    echo "target=$target"
    echo "source_date_epoch=$source_date_epoch"
    echo "source_date_utc=$build_date"
    echo "rustc=$(rustc --version)"
    echo "cargo=$(cargo --version)"
} > "$stage/BUILD-METADATA.txt"

find "$stage" -exec touch --date="@$source_date_epoch" {} +
tar --sort=name \
    --mtime="@$source_date_epoch" \
    --owner=0 --group=0 --numeric-owner \
    --mode='u+rwX,go+rX,go-w' \
    -C "$stage_parent" -cf - "$bundle_name" | gzip -n -9 > "$archive"

echo "$archive"
