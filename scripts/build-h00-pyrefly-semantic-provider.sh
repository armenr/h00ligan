#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${H00_PYREFLY_BUILDER_INVOCATION_ROOT:-}" ]]; then
    live_script="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${BASH_SOURCE[0]}")"
    live_script_dir="$(cd -- "$(dirname "$live_script")" && pwd)"
    live_repo_root="$(cd -- "$live_script_dir/.." && pwd)"
    if [[ -z "${DEVBOX_PACKAGES_DIR:-}" ]]; then
        command -v devbox >/dev/null 2>&1 || {
            echo "Pyrefly semantic-provider builds require the repository's pinned Devbox" >&2
            exit 1
        }
        exec devbox run -- "$live_script" "$@"
    fi
    live_cache_publisher="$live_repo_root/scripts/publish-h00ligan-cache-directory.py"
    [[ -f "$live_cache_publisher" && ! -L "$live_cache_publisher" ]] || {
        echo "Pyrefly cache publisher must be a regular non-symlink" >&2
        exit 1
    }
    live_cache_root="$live_repo_root/target/portable-cache/python-provider"
    invocation_parent="$live_repo_root/target/portable-cache/python-provider/invocations"
    [[ ! -L "$live_repo_root/target" && ! -L "$live_repo_root/target/portable-cache" ]] || {
        echo "Pyrefly provider cache roots must not be symlinks" >&2
        exit 1
    }
    mkdir -p "$live_cache_root" "$invocation_parent"
    [[ -d "$live_cache_root" && ! -L "$live_cache_root" ]] || {
        echo "Pyrefly provider cache root is invalid: $live_cache_root" >&2
        exit 1
    }
    if [[ -z "${H00LIGAN_CACHE_LOCK_FD:-}" ]]; then
        exec python3 "$live_cache_publisher" locked-exec \
            --owner-root "$live_cache_root" \
            --lock-file "$live_cache_root/compiler.lock" \
            -- "$live_script" "$@"
    fi
    python3 "$live_cache_publisher" verify-lock \
        --owner-root "$live_cache_root" \
        --lock-file "$live_cache_root/compiler.lock" \
        --descriptor "$H00LIGAN_CACHE_LOCK_FD"
    prune_interrupted_invocation_roots() {
        local interrupted
        local interrupted_invocations=()
        shopt -s nullglob
        interrupted_invocations=("$invocation_parent"/invocation.*)
        shopt -u nullglob
        for interrupted in "${interrupted_invocations[@]}"; do
            [[ -d "$interrupted" && ! -L "$interrupted" ]] || {
                echo "Pyrefly interrupted invocation entry is unsafe: $interrupted" >&2
                return 1
            }
            rm -rf -- "$interrupted"
        done
    }
    prune_interrupted_invocation_roots
    invocation_root="$(mktemp -d "$invocation_parent/invocation.XXXXXX")"
    trap 'rm -rf -- "$invocation_root"' EXIT HUP INT TERM
    install -m 0500 "$live_script" "$invocation_root/build-provider.sh"
    export H00_PYREFLY_BUILDER_INVOCATION_ROOT="$invocation_root"
    export H00_PYREFLY_BUILDER_LIVE_SCRIPT="$live_script"
    export H00_PYREFLY_BUILDER_REPO_ROOT="$live_repo_root"
    exec "$invocation_root/build-provider.sh" "$@"
fi

invocation_root="$H00_PYREFLY_BUILDER_INVOCATION_ROOT"
repo_root="$H00_PYREFLY_BUILDER_REPO_ROOT"
builder_live="$H00_PYREFLY_BUILDER_LIVE_SCRIPT"
builder="$invocation_root/build-provider.sh"
[[ -d "$invocation_root" && ! -L "$invocation_root" ]] || {
    echo "Pyrefly builder invocation root is invalid" >&2
    exit 1
}

usage() {
    cat >&2 <<'USAGE'
Usage: scripts/build-h00-pyrefly-semantic-provider.sh [OPTIONS]

Prepare or build h00ligan's private Pyrefly 1.2.0 semantic provider from the exact
official source archive. The final h00ligan product links this provider behind
a hidden same-executable mode; it is never installed as a second product.

Options:
  --target TARGET   Rust target triple (defaults to portable musl on Linux and
                    the pinned compiler host on Darwin)
  --prepare-only    Verify and prepare the exact patched source, then stop
  --machine         Print stable KEY=VALUE receipt fields
  -h, --help        Show this help

H00_PYREFLY_SOURCE_ARCHIVE may name a pre-fetched official archive. Its bytes
must match the checked-in SHA-256; otherwise the builder downloads the pinned
archive into the ignored repository-local cache.
USAGE
}

requested_target=""
prepare_only=0
machine=0
while (($#)); do
    case "$1" in
        --target)
            (($# >= 2)) || { usage; exit 2; }
            requested_target="$2"
            shift 2
            ;;
        --prepare-only)
            prepare_only=1
            shift
            ;;
        --machine)
            machine=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage
            exit 2
            ;;
    esac
done

pyrefly_version="1.2.0"
pyrefly_commit="1933169ad8ee9e4d4114112eb56ef0811fb0a094"
archive_url="https://codeload.github.com/facebook/pyrefly/tar.gz/refs/tags/1.2.0"
archive_name="pyrefly-1.2.0.tar.gz"
archive_prefix="pyrefly-1.2.0"
archive_sha256="39c3d391da0aa85eb7d0149fc57e860495f50e431f4911547f21906a35ab33bd"
rust_version="1.97.1"

patch_live="$repo_root/providers/python/pyrefly/pyrefly-1.2.0.patch"
semantic_live="$repo_root/providers/python/pyrefly/h00_semantic.rs"
manifest_live="$repo_root/providers/python/pyrefly/provider.Cargo.toml.in"
lockfile_live="$repo_root/providers/python/pyrefly/provider.Cargo.lock"
provider_live="$repo_root/providers/python/pyrefly/h00_pyrefly_semantic_provider.rs"
provider_main_live="$repo_root/providers/python/pyrefly/h00_pyrefly_semantic_provider_main.rs"
protocol_manifest_live="$repo_root/crates/h00ligan-provider-protocol/Cargo.toml"
protocol_source_live="$repo_root/crates/h00ligan-provider-protocol/src/lib.rs"
cache_publisher_live="$repo_root/scripts/publish-h00ligan-cache-directory.py"
live_inputs=(
    "$builder_live"
    "$patch_live"
    "$semantic_live"
    "$manifest_live"
    "$lockfile_live"
    "$provider_live"
    "$provider_main_live"
    "$protocol_manifest_live"
    "$protocol_source_live"
    "$cache_publisher_live"
)
for input in "${live_inputs[@]}"; do
    [[ -f "$input" && ! -L "$input" ]] || {
        echo "Pyrefly provider build input must be a regular non-symlink: $input" >&2
        exit 1
    }
done

input_root="$invocation_root/inputs"
mkdir -p "$input_root"
patch="$input_root/pyrefly-1.2.0.patch"
semantic="$input_root/h00_semantic.rs"
manifest="$input_root/provider.Cargo.toml.in"
lockfile="$input_root/provider.Cargo.lock"
provider="$input_root/h00_pyrefly_semantic_provider.rs"
provider_main="$input_root/h00_pyrefly_semantic_provider_main.rs"
protocol_manifest="$input_root/protocol.Cargo.toml"
protocol_source="$input_root/protocol-lib.rs"
cache_publisher="$input_root/publish-h00ligan-cache-directory.py"
install -m 0644 "$patch_live" "$patch"
install -m 0644 "$semantic_live" "$semantic"
install -m 0644 "$manifest_live" "$manifest"
install -m 0644 "$lockfile_live" "$lockfile"
install -m 0644 "$provider_live" "$provider"
install -m 0644 "$provider_main_live" "$provider_main"
install -m 0644 "$protocol_manifest_live" "$protocol_manifest"
install -m 0644 "$protocol_source_live" "$protocol_source"
install -m 0500 "$cache_publisher_live" "$cache_publisher"

verify_live_inputs() {
    python3 - \
        "$builder_live" "$builder" \
        "$patch_live" "$patch" \
        "$semantic_live" "$semantic" \
        "$manifest_live" "$manifest" \
        "$lockfile_live" "$lockfile" \
        "$provider_live" "$provider" \
        "$provider_main_live" "$provider_main" \
        "$protocol_manifest_live" "$protocol_manifest" \
        "$protocol_source_live" "$protocol_source" \
        "$cache_publisher_live" "$cache_publisher" <<'PY'
from pathlib import Path
import sys

paths = [Path(value) for value in sys.argv[1:]]
for live, snapshot in zip(paths[::2], paths[1::2], strict=True):
    if live.is_symlink() or not live.is_file() or live.read_bytes() != snapshot.read_bytes():
        raise SystemExit(f"Pyrefly provider build input changed after snapshot: {live}")
PY
}
verify_live_inputs

patch_sha256="$(sha256sum "$patch" | awk '{print $1}')"
builder_sha256="$(sha256sum "$builder" | awk '{print $1}')"
source_key="$(python3 - "$pyrefly_commit" "$archive_sha256" \
    "$builder" "$patch" "$semantic" "$manifest" "$lockfile" \
    "$provider" "$provider_main" "$protocol_manifest" "$protocol_source" <<'PY'
import hashlib
from pathlib import Path
import struct
import sys

commit, archive_sha256, *raw_paths = sys.argv[1:]
hasher = hashlib.sha256()
for value in (b"h00/pyrefly-semantic-provider-source/v1", commit.encode(), archive_sha256.encode()):
    hasher.update(struct.pack(">Q", len(value)))
    hasher.update(value)
for raw_path in raw_paths:
    value = Path(raw_path).read_bytes()
    hasher.update(struct.pack(">Q", len(value)))
    hasher.update(value)
print(hasher.hexdigest())
PY
)"

cache_root="$repo_root/target/portable-cache/python-provider"
archive_root="$cache_root/archives"
# Keep patched analyzer source beside the existing semantic-provider cache,
# separate from target-specific artifacts and temporary adapter workspaces.
source_parent="$repo_root/target/semantic-provider/python/source"
candidate_parent="$cache_root/candidates"
compilation_parent="$cache_root/compilation"
artifact_parent="$cache_root/artifacts"
mkdir -p "$archive_root" "$source_parent" "$candidate_parent" "$compilation_parent" "$artifact_parent"
for path in \
    "$cache_root" \
    "$archive_root" \
    "$repo_root/target/semantic-provider" \
    "$repo_root/target/semantic-provider/python" \
    "$source_parent" \
    "$candidate_parent" \
    "$compilation_parent" \
    "$artifact_parent"; do
    [[ -d "$path" && ! -L "$path" ]] || {
        echo "Pyrefly provider cache path is invalid: $path" >&2
        exit 1
    }
done

candidate=""
download=""
adapter_root=""
compilation_root=""
artifact_candidate=""
cleanup() {
    [[ -z "$candidate" || ! -d "$candidate" ]] || rm -rf -- "$candidate"
    [[ -z "$download" || ! -f "$download" ]] || rm -f -- "$download"
    [[ -z "$adapter_root" || ! -d "$adapter_root" ]] || rm -rf -- "$adapter_root"
    [[ -z "$compilation_root" || ! -d "$compilation_root" ]] || rm -rf -- "$compilation_root"
    [[ -z "$artifact_candidate" || ! -d "$artifact_candidate" ]] || rm -rf -- "$artifact_candidate"
    [[ ! -d "$invocation_root" ]] || rm -rf -- "$invocation_root"
}
trap cleanup EXIT HUP INT TERM

python3 "$cache_publisher" verify-lock \
    --owner-root "$cache_root" \
    --lock-file "$cache_root/compiler.lock" \
    --descriptor "$H00LIGAN_CACHE_LOCK_FD"
unset H00LIGAN_CACHE_LOCK_FD

prune_interrupted_cache_roots() {
    local entry
    local entries=()
    local target_directory
    shopt -s nullglob
    entries=(
        "$candidate_parent"/source.*
        "$candidate_parent"/adapter.*
        "$compilation_parent"/build.*
    )
    for target_directory in "$artifact_parent"/*; do
        [[ -d "$target_directory" && ! -L "$target_directory" ]] || {
            echo "Pyrefly artifact target cache is unsafe: $target_directory" >&2
            return 1
        }
        entries+=("$target_directory"/artifact.*)
    done
    shopt -u nullglob
    for entry in "${entries[@]}"; do
        [[ -d "$entry" && ! -L "$entry" ]] || {
            echo "Pyrefly interrupted cache entry is unsafe: $entry" >&2
            return 1
        }
        rm -rf -- "$entry"
    done
    shopt -s nullglob
    entries=("$archive_root"/*.download.*)
    shopt -u nullglob
    for entry in "${entries[@]}"; do
        [[ -f "$entry" && ! -L "$entry" ]] || {
            echo "Pyrefly interrupted archive entry is unsafe: $entry" >&2
            return 1
        }
        rm -f -- "$entry"
    done
}
prune_interrupted_cache_roots

archive="$archive_root/$archive_name"
if [[ ! -e "$archive" ]]; then
    download="$(mktemp "$archive_root/$archive_name.download.XXXXXX")"
    if [[ -n "${H00_PYREFLY_SOURCE_ARCHIVE:-}" ]]; then
        [[ -f "$H00_PYREFLY_SOURCE_ARCHIVE" && ! -L "$H00_PYREFLY_SOURCE_ARCHIVE" ]] || {
            echo "H00_PYREFLY_SOURCE_ARCHIVE is not a regular archive" >&2
            exit 1
        }
        install -m 0644 "$H00_PYREFLY_SOURCE_ARCHIVE" "$download"
    else
        command -v curl >/dev/null 2>&1 || { echo "curl is required to acquire Pyrefly" >&2; exit 1; }
        curl --fail --location --proto '=https' --tlsv1.2 "$archive_url" --output "$download"
    fi
    [[ "$(sha256sum "$download" | awk '{print $1}')" == "$archive_sha256" ]] || {
        echo "official Pyrefly source archive checksum mismatch" >&2
        exit 1
    }
    if [[ ! -e "$archive" ]]; then
        mv "$download" "$archive"
    fi
    download=""
fi
[[ -f "$archive" && ! -L "$archive" \
    && "$(sha256sum "$archive" | awk '{print $1}')" == "$archive_sha256" ]] || {
    echo "cached Pyrefly source archive failed integrity verification" >&2
    exit 1
}

verify_source_cache() {
    python3 - "$1" "$source_key" "$builder_sha256" "$archive_sha256" "$pyrefly_commit" "$2" <<'PY'
import hashlib
import json
from pathlib import Path
import stat
import struct
import sys

root = Path(sys.argv[1])
source_key, builder_sha256, archive_sha256, commit, operation = sys.argv[2:]
receipt = root / ".h00-pyrefly-source.json"
if root.is_symlink() or not root.is_dir():
    raise SystemExit("Pyrefly source cache must be a real directory")

def field(hasher, value):
    hasher.update(struct.pack(">Q", len(value)))
    hasher.update(value)

hasher = hashlib.sha256()
field(hasher, b"h00/pyrefly-semantic-provider-source-tree/v1")
file_count = 0
total_bytes = 0
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    if path == receipt:
        continue
    if path.is_symlink() or (not path.is_dir() and not path.is_file()):
        raise SystemExit(f"unsupported Pyrefly source-cache entry: {path}")
    if path.is_dir():
        continue
    relative = path.relative_to(root).as_posix().encode()
    contents = path.read_bytes()
    mode = stat.S_IMODE(path.stat().st_mode).to_bytes(4, "big")
    for value in (relative, mode, contents):
        field(hasher, value)
    file_count += 1
    total_bytes += len(contents)

observed = {
    "schema": "h00/pyrefly-semantic-provider-source-cache/v1",
    "source_key": source_key,
    "builder_sha256": builder_sha256,
    "archive_sha256": archive_sha256,
    "upstream_commit": commit,
    "tree_sha256": hasher.hexdigest(),
    "file_count": file_count,
    "total_bytes": total_bytes,
}
if operation == "create":
    if receipt.exists():
        raise SystemExit("Pyrefly source receipt already exists during creation")
    receipt.write_text(json.dumps(observed, sort_keys=True, separators=(",", ":")) + "\n")
elif operation == "verify":
    if receipt.is_symlink() or not receipt.is_file() or json.loads(receipt.read_text()) != observed:
        raise SystemExit("Pyrefly source cache failed integrity verification")
else:
    raise SystemExit(f"unknown source-cache operation: {operation}")
PY
}

source_root="$source_parent/$source_key"
if [[ ! -e "$source_root" ]]; then
    command -v patch >/dev/null 2>&1 || { echo "patch is required" >&2; exit 1; }
    candidate="$(mktemp -d "$candidate_parent/source.XXXXXX")"
    python3 - "$archive" "$candidate" "$archive_prefix" <<'PY'
from pathlib import Path, PurePosixPath
import posixpath
import sys
import tarfile

archive, destination, expected_prefix = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
with tarfile.open(archive, "r:gz") as source:
    members = source.getmembers()
    if not members:
        raise SystemExit("Pyrefly source archive is empty")
    by_name = {member.name: member for member in members}
    links = []
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != expected_prefix:
            raise SystemExit(f"unsafe Pyrefly archive path: {member.name}")
        if member.issym():
            target = PurePosixPath(posixpath.normpath(str(path.parent / member.linkname)))
            target_member = by_name.get(target.as_posix())
            if (
                target.is_absolute()
                or ".." in target.parts
                or not target.parts
                or target.parts[0] != expected_prefix
                or target_member is None
                or not target_member.isfile()
            ):
                raise SystemExit(f"unsafe Pyrefly archive symlink: {member.name} -> {member.linkname}")
            links.append((path, target))
        elif not (member.isfile() or member.isdir()):
            raise SystemExit(f"unsupported Pyrefly archive entry: {member.name}")
    source.extractall(destination, filter="data")
    for link, target in links:
        link_path = destination / link
        target_path = destination / target
        contents = target_path.read_bytes()
        link_path.unlink()
        link_path.write_bytes(contents)
PY
    extracted="$candidate/$archive_prefix"
    [[ -d "$extracted" && ! -L "$extracted" ]] || {
        echo "Pyrefly archive produced no source root" >&2
        exit 1
    }
    find "$extracted" -type l -print -quit | grep -q . && {
        echo "Pyrefly source archive contains an unsupported symlink" >&2
        exit 1
    }
    patch --dry-run --batch -p1 -d "$extracted" -i "$patch" >/dev/null
    patch --batch -p1 -d "$extracted" -i "$patch" >/dev/null
    install -m 0644 "$semantic" "$extracted/pyrefly/lib/h00_semantic.rs"
    verify_live_inputs
    verify_source_cache "$extracted" create
    mv "$extracted" "$source_root"
    rm -rf -- "$candidate"
    candidate=""
elif [[ ! -d "$source_root" || -L "$source_root" ]]; then
    echo "Pyrefly source-cache path is invalid: $source_root" >&2
    exit 1
fi
verify_source_cache "$source_root" verify
verify_live_inputs
source_tree_sha256="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tree_sha256"])' \
    "$source_root/.h00-pyrefly-source.json")"
cache_publisher_sha256="$(sha256sum "$cache_publisher" | awk '{print $1}')"

emit_prepared_receipt() {
    if ((machine)); then
        printf 'H00_PYREFLY_SOURCE_ROOT=%s\n' "$source_root"
        printf 'H00_PYREFLY_PATCH_SHA256=%s\n' "$patch_sha256"
        printf 'H00_PYREFLY_SOURCE_KEY=%s\n' "$source_key"
        printf 'H00_PYREFLY_BUILDER_SHA256=%s\n' "$builder_sha256"
        printf 'H00_PYREFLY_ARCHIVE_SHA256=%s\n' "$archive_sha256"
        printf 'H00_PYREFLY_SOURCE_TREE_SHA256=%s\n' "$source_tree_sha256"
        printf 'H00_PYREFLY_CACHE_PUBLISHER_SHA256=%s\n' "$cache_publisher_sha256"
    else
        printf '%s\n' "$source_root"
    fi
}
if ((prepare_only)); then
    emit_prepared_receipt
    exit 0
fi

command -v rustup >/dev/null 2>&1 || { echo "rustup is required" >&2; exit 1; }
command -v cc >/dev/null 2>&1 || { echo "a C compiler is required" >&2; exit 1; }
rustc_version="$(rustup run "$rust_version" rustc --version)"
rustc_identity="$(rustup run "$rust_version" rustc -vV)"
[[ "$rustc_version" == "rustc 1.97.1 (8bab26f4f 2026-07-14)" ]] || {
    echo "unexpected compiler identity: $rustc_version" >&2
    exit 1
}
host_target="$(printf '%s\n' "$rustc_identity" | sed -n 's/^host: //p')"
case "$host_target" in
    x86_64-unknown-linux-gnu)
        default_target="x86_64-unknown-linux-musl"
        ;;
    aarch64-unknown-linux-gnu)
        default_target="aarch64-unknown-linux-musl"
        ;;
    x86_64-apple-darwin | aarch64-apple-darwin)
        default_target="$host_target"
        ;;
    *)
        echo "unsupported Pyrefly provider host: $host_target" >&2
        exit 1
        ;;
esac
target="${requested_target:-$default_target}"
rustup target list --toolchain "$rust_version" --installed | grep -Fxq "$target" || {
    echo "Rust $rust_version target is not installed: $target" >&2
    exit 1
}

host_os="$(uname -s)"
portable_linux=0
case "$target" in
    x86_64-unknown-linux-musl | aarch64-unknown-linux-musl)
        [[ "$host_os" == Linux ]] || { echo "Linux target requires a Linux host" >&2; exit 1; }
        portable_linux=1
        ;;
    x86_64-apple-darwin | aarch64-apple-darwin)
        [[ "$host_os" == Darwin ]] || { echo "Darwin target requires a Darwin host" >&2; exit 1; }
        ;;
    *)
        echo "unsupported Pyrefly provider target: $target" >&2
        exit 1
        ;;
esac

cargo_home="${CARGO_HOME:-${HOME}/.cargo}"
rust_sysroot="$(rustup run "$rust_version" rustc --print sysroot)"
portable_rustflags="--remap-path-prefix=$HOME=build-home --remap-path-prefix=$repo_root=h00-source --remap-path-prefix=$cargo_home=cargo-registry --remap-path-prefix=$rust_sysroot=rust-toolchain --remap-path-prefix=$source_root=pyrefly-source"
native_remap_flags="-ffile-prefix-map=$HOME=build-home -ffile-prefix-map=$repo_root=h00-source -ffile-prefix-map=$cargo_home=cargo-registry -ffile-prefix-map=$rust_sysroot=rust-toolchain -ffile-prefix-map=$source_root=pyrefly-source"
linker_identity="native $(cc --version | head -n 1)"
if ((portable_linux)); then
    command -v cargo-zigbuild >/dev/null 2>&1 || { echo "cargo-zigbuild is required" >&2; exit 1; }
    command -v zig >/dev/null 2>&1 || { echo "zig is required" >&2; exit 1; }
    [[ "$(cargo-zigbuild --version)" == "cargo-zigbuild 0.23.0" ]] || {
        echo "expected cargo-zigbuild 0.23.0" >&2
        exit 1
    }
    [[ "$(zig version)" == "0.16.0" ]] || { echo "expected Zig 0.16.0" >&2; exit 1; }
    command -v readelf >/dev/null 2>&1 || { echo "readelf is required" >&2; exit 1; }
    linker_identity="$(cargo-zigbuild --version); zig $(zig version)"
fi
case "$target" in
    x86_64-apple-darwin)
        export MACOSX_DEPLOYMENT_TARGET=10.12
        ;;
    aarch64-apple-darwin)
        export MACOSX_DEPLOYMENT_TARGET=11.0
        ;;
esac

build_key="$(python3 - "$target" "$source_key" "$source_tree_sha256" \
    "$patch_sha256" "$archive_sha256" "$builder_sha256" \
    "$cache_publisher_sha256" "$rustc_identity" "$linker_identity" \
    "$portable_rustflags" "$native_remap_flags" <<'PY'
import hashlib
import struct
import sys

hasher = hashlib.sha256()
for value in (
    b"h00/pyrefly-semantic-provider-artifact-key/v2",
    *(value.encode() for value in sys.argv[1:]),
):
    hasher.update(struct.pack(">Q", len(value)))
    hasher.update(value)
print(hasher.hexdigest())
PY
)"
artifact_root="$artifact_parent/$target/$build_key"
binary="$artifact_root/h00-pyrefly-semantic-provider"
receipt="$artifact_root/h00-pyrefly-semantic-provider.build.json"
mkdir -p "$artifact_parent/$target"
[[ ! -L "$artifact_parent/$target" && ! -L "$artifact_root" ]] || {
    echo "Pyrefly provider artifact cache path must not be a symlink" >&2
    exit 1
}

validate_provider_binary() {
    local candidate="$1"
    [[ -x "$candidate" && -f "$candidate" && ! -L "$candidate" ]] || {
        echo "Pyrefly provider binary is missing or unsafe" >&2
        return 1
    }
    python3 - "$candidate" "$repo_root" "$HOME" "${DEVBOX_PACKAGES_DIR:-}" <<'PY'
from pathlib import Path
import re
import sys

payload = Path(sys.argv[1]).read_bytes().lower()
for label, value in (
    ("Nix store", "/nix/store"),
    ("repository root", sys.argv[2]),
    ("home root", sys.argv[3]),
    ("Devbox package root", sys.argv[4]),
):
    if value and value.encode().lower() in payload:
        detail = ""
        if label == "Nix store":
            packages = sorted(
                match.decode("utf-8", errors="replace")
                for match in re.findall(
                    rb"/nix/store/[0-9a-z]{32}-([^/\x00\s]+)", payload
                )
            )
            if packages:
                detail = f": {', '.join(packages)}"
        raise SystemExit(
            f"Pyrefly provider embeds a forbidden host/build path ({label}{detail})"
        )
for token in (b"devbox_packages_dir", b"devbox run"):
    if token in payload:
        raise SystemExit("Pyrefly provider embeds a build-environment command")
PY
    if ((portable_linux)); then
        file "$candidate" | grep -Eq 'static-pie linked|statically linked' || {
            echo "Pyrefly provider is not a static Linux executable" >&2
            return 1
        }
        if readelf -l "$candidate" | grep -q 'INTERP'; then
            echo "Pyrefly provider retains a dynamic interpreter" >&2
            return 1
        fi
        if readelf -d "$candidate" 2>/dev/null | grep -q '(NEEDED)'; then
            echo "Pyrefly provider retains a dynamic library dependency" >&2
            return 1
        fi
    fi
}

if [[ ! -e "$artifact_root" ]]; then
    adapter_root="$(mktemp -d "$candidate_parent/adapter.XXXXXX")"
    compilation_root="$(mktemp -d "$compilation_parent/build.XXXXXX")"
    mkdir -p "$adapter_root/src" "$adapter_root/protocol/src"
    install -m 0644 "$provider" "$adapter_root/src/lib.rs"
    install -m 0644 "$provider_main" "$adapter_root/src/main.rs"
    install -m 0644 "$protocol_manifest" "$adapter_root/protocol/Cargo.toml"
    install -m 0644 "$protocol_source" "$adapter_root/protocol/src/lib.rs"
    install -m 0644 "$lockfile" "$adapter_root/Cargo.lock"
    python3 - "$manifest" "$adapter_root/Cargo.toml" "$source_root/pyrefly" <<'PY'
from pathlib import Path
import sys

template, destination, pyrefly = map(Path, sys.argv[1:])
rendered = template.read_text()
rendered = rendered.replace("@H00_PROTOCOL_PATH@", "protocol")
rendered = rendered.replace("@H00_PYREFLY_PATH@", str(pyrefly))
if "@H00_" in rendered:
    raise SystemExit("unresolved Pyrefly provider manifest placeholder")
destination.write_text(rendered + "\n[workspace]\n")
PY

    export H00_PYREFLY_PATCH_SHA256="$patch_sha256"
    export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
    export CARGO_PROFILE_RELEASE_LTO=thin
    export CARGO_PROFILE_RELEASE_PANIC=abort
    export CARGO_PROFILE_RELEASE_STRIP=symbols
    export RUSTFLAGS="$portable_rustflags"
    export CFLAGS="$native_remap_flags"
    export CXXFLAGS="$native_remap_flags"
    unset CARGO_ENCODED_RUSTFLAGS LD_LIBRARY_PATH LIBRARY_PATH NIX_LDFLAGS
    unset DYLD_LIBRARY_PATH DYLD_FALLBACK_LIBRARY_PATH
    unset CC CXX AR LDFLAGS

    CARGO_TARGET_DIR="$compilation_root" cargo "+$rust_version" test \
        --manifest-path "$adapter_root/Cargo.toml" \
        --locked --offline --lib -- --test-threads=1

    if ((portable_linux)); then
        export CARGO_ZIGBUILD_CACHE_DIR="$cache_root/cargo-zigbuild"
        export ZIG_GLOBAL_CACHE_DIR="$cache_root/zig-global"
        export ZIG_LOCAL_CACHE_DIR="$cache_root/zig-local/$target"
        CARGO_TARGET_DIR="$compilation_root" cargo "+$rust_version" zigbuild \
            --manifest-path "$adapter_root/Cargo.toml" \
            --locked --offline --release --target "$target" \
            --bin h00-pyrefly-semantic-provider
    else
        CARGO_TARGET_DIR="$compilation_root" cargo "+$rust_version" build \
            --manifest-path "$adapter_root/Cargo.toml" \
            --locked --offline --release --target "$target" \
            --bin h00-pyrefly-semantic-provider
    fi
    built="$compilation_root/$target/release/h00-pyrefly-semantic-provider"
    validate_provider_binary "$built"
    verify_source_cache "$source_root" verify
    verify_live_inputs

    artifact_candidate="$(mktemp -d "$artifact_parent/$target/artifact.XXXXXX")"
    install -m 0755 "$built" "$artifact_candidate/h00-pyrefly-semantic-provider"
    binary_sha256="$(sha256sum "$artifact_candidate/h00-pyrefly-semantic-provider" | awk '{print $1}')"
    binary_size="$(python3 -c 'import os,sys; print(os.path.getsize(sys.argv[1]))' \
        "$artifact_candidate/h00-pyrefly-semantic-provider")"
    python3 - "$artifact_candidate/h00-pyrefly-semantic-provider.build.json" \
        "$build_key" "$target" "$rustc_version" "$linker_identity" \
        "$pyrefly_version" "$pyrefly_commit" "$archive_sha256" \
        "$patch_sha256" "$builder_sha256" "$cache_publisher_sha256" \
        "$source_key" "$source_tree_sha256" "$binary_sha256" "$binary_size" <<'PY'
import json
from pathlib import Path
import sys

(
    receipt, build_key, target, rustc, linker, version, commit, archive,
    patch, builder, cache_publisher, source_key, source_tree, binary_sha256,
    binary_size,
) = sys.argv[1:]
payload = {
    "schema": "h00/pyrefly-semantic-provider-build/v2",
    "protocol": "h00/semantic-provider/v15",
    "provider_id": "h00-pyrefly-scip",
    "language": "python",
    "build_key": build_key,
    "target": target,
    "rustc": rustc,
    "linker": linker,
    "upstream_version": version,
    "upstream_commit": commit,
    "archive_sha256": archive,
    "patch_sha256": patch,
    "builder_sha256": builder,
    "cache_publisher_sha256": cache_publisher,
    "source_key": source_key,
    "source_tree_sha256": source_tree,
    "binary_sha256": binary_sha256,
    "binary_size": int(binary_size),
}
Path(receipt).write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
PY
    python3 "$cache_publisher" publish \
        --owner-root "$cache_root" \
        --candidate "$artifact_candidate" \
        --destination "$artifact_root" >/dev/null
    artifact_candidate=""
    rm -rf -- "$compilation_root"
    compilation_root=""
elif [[ ! -d "$artifact_root" || -L "$artifact_root" ]]; then
    echo "Pyrefly provider artifact cache entry is invalid" >&2
    exit 1
fi

validate_provider_binary "$binary"
binary_sha256="$(sha256sum "$binary" | awk '{print $1}')"
binary_size="$(python3 -c 'import os,sys; print(os.path.getsize(sys.argv[1]))' "$binary")"
python3 - "$receipt" "$build_key" "$target" "$rustc_version" "$linker_identity" \
    "$pyrefly_version" "$pyrefly_commit" "$archive_sha256" "$patch_sha256" \
    "$builder_sha256" "$cache_publisher_sha256" "$source_key" \
    "$source_tree_sha256" "$binary_sha256" "$binary_size" <<'PY'
import json
from pathlib import Path
import sys

(
    receipt, build_key, target, rustc, linker, version, commit, archive,
    patch, builder, cache_publisher, source_key, source_tree, binary_sha256,
    binary_size,
) = sys.argv[1:]
payload = json.loads(Path(receipt).read_text(encoding="utf-8"))
expected = {
    "schema": "h00/pyrefly-semantic-provider-build/v2",
    "protocol": "h00/semantic-provider/v15",
    "provider_id": "h00-pyrefly-scip",
    "language": "python",
    "build_key": build_key,
    "target": target,
    "rustc": rustc,
    "linker": linker,
    "upstream_version": version,
    "upstream_commit": commit,
    "archive_sha256": archive,
    "patch_sha256": patch,
    "builder_sha256": builder,
    "cache_publisher_sha256": cache_publisher,
    "source_key": source_key,
    "source_tree_sha256": source_tree,
    "binary_sha256": binary_sha256,
    "binary_size": int(binary_size),
}
if payload != expected:
    raise SystemExit("Pyrefly provider artifact failed exact receipt verification")
PY
verify_source_cache "$source_root" verify
verify_live_inputs

if ((machine)); then
    emit_prepared_receipt
    printf 'H00_PYREFLY_PROVIDER_BINARY=%s\n' "$binary"
    printf 'H00_PYREFLY_PROVIDER_RECEIPT=%s\n' "$receipt"
    printf 'H00_PYREFLY_PROVIDER_BINARY_SHA256=%s\n' "$binary_sha256"
else
    printf '%s\n' "$binary"
fi
