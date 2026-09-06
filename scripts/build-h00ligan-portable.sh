#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${H00LIGAN_BUILDER_INVOCATION_ROOT:-}" ]]; then
    [[ -z "${H00LIGAN_BUILDER_INVOCATION_TOKEN:-}${H00LIGAN_BUILDER_LIVE_SCRIPT:-}${H00LIGAN_BUILDER_REPO_ROOT:-}" ]] || {
        echo "portable h00ligan internal handoff is partial or ambient" >&2
        exit 1
    }
    live_script="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${BASH_SOURCE[0]}")"
    live_script_dir="$(cd -- "$(dirname "$live_script")" && pwd)"
    live_repo_root="$(cd -- "$live_script_dir/.." && pwd)"
    invocation_parent="$live_repo_root/target/portable-cache/invocations"
    [[ ! -L "$live_repo_root/target" \
        && ! -L "$live_repo_root/target/portable-cache" \
        && ! -L "$live_repo_root/target/portable-workspaces" ]] || {
        echo "portable h00ligan cache roots must not be symlinks" >&2
        exit 1
    }
    mkdir -p "$invocation_parent"
    invocation_root="$(mktemp -d "$invocation_parent/invocation.XXXXXX")"
    chmod 0700 "$invocation_root"
    cleanup_parent_invocation() {
        rm -rf -- "$invocation_root"
    }
    trap cleanup_parent_invocation EXIT HUP INT TERM
    install -m 0755 "$live_script" "$invocation_root/build-h00ligan.sh"
    invocation_token="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    printf '%s\n' "$invocation_token" > "$invocation_root/.h00-invocation-token"
    chmod 0600 "$invocation_root/.h00-invocation-token"
    export H00LIGAN_BUILDER_INVOCATION_ROOT="$invocation_root"
    export H00LIGAN_BUILDER_INVOCATION_TOKEN="$invocation_token"
    export H00LIGAN_BUILDER_LIVE_SCRIPT="$live_script"
    export H00LIGAN_BUILDER_REPO_ROOT="$live_repo_root"
    if [[ -z "${DEVBOX_PACKAGES_DIR:-}" ]]; then
        command -v devbox >/dev/null 2>&1 || {
            echo "portable h00ligan builds require the repository's pinned Devbox" >&2
            exit 1
        }
        exec devbox run -- "$invocation_root/build-h00ligan.sh" "$@"
    fi
    exec "$invocation_root/build-h00ligan.sh" "$@"
fi

invocation_root="$H00LIGAN_BUILDER_INVOCATION_ROOT"
invocation_token="${H00LIGAN_BUILDER_INVOCATION_TOKEN:-}"
repo_root="$H00LIGAN_BUILDER_REPO_ROOT"
product_builder_live="$H00LIGAN_BUILDER_LIVE_SCRIPT"
product_builder="$invocation_root/build-h00ligan.sh"
[[ ! -L "$invocation_root" && -d "$invocation_root" ]] || {
    echo "portable h00ligan builder invocation root is invalid" >&2
    exit 1
}
invocation_marker="$invocation_root/.h00-invocation-token"
[[ "$invocation_token" =~ ^[0-9a-f]{64}$ \
    && -f "$invocation_marker" \
    && ! -L "$invocation_marker" \
    && "$(<"$invocation_marker")" == "$invocation_token" ]] || {
    echo "portable h00ligan builder lacks a valid private handoff" >&2
    exit 1
}
cleanup_verified_invocation() {
    rm -rf -- "$invocation_root"
}
trap cleanup_verified_invocation EXIT HUP INT TERM
[[ "$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${BASH_SOURCE[0]}")" == "$product_builder" ]] || {
    echo "portable h00ligan builder is not executing its private snapshot" >&2
    exit 1
}
if ! [[ -f "$product_builder_live" && ! -L "$product_builder_live" \
    && "$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$product_builder_live")" == "$repo_root/scripts/build-h00ligan-portable.sh" \
    && "$(dirname "$invocation_root")" == "$repo_root/target/portable-cache/invocations" ]]; then
    echo "portable h00ligan builder private handoff does not bind the live entrypoint" >&2
    exit 1
fi
if ! cmp -s "$product_builder_live" "$product_builder"; then
    echo "portable h00ligan builder private handoff does not bind the live entrypoint" >&2
    exit 1
fi

if [[ -z "${DEVBOX_PACKAGES_DIR:-}" ]]; then
    echo "portable h00ligan builder snapshot did not enter the pinned Devbox" >&2
    exit 1
fi

usage() {
    cat >&2 <<'USAGE'
Usage: scripts/build-h00ligan-portable.sh [--target TARGET] [--rust-source PATH] [--prepare-only] [--install] [--destination PATH]

Build the single-file h00ligan product for the native platform. The exact Rust
semantic provider is linked into a hidden self-spawn mode; it is not installed
or distributed as a companion executable. Linux executables are fully static
musl artifacts; macOS executables are thin native binaries with only system
dynamic dependencies.
USAGE
}

requested_target=""
rust_source="${H00_RUST_SOURCE_DIR:-}"
install_binary=0
machine_output=0
prepare_only=0
destination="${H00LIGAN_INSTALL_PATH:-${HOME}/.local/bin/h00ligan}"
while (($#)); do
    case "$1" in
        --target)
            (($# >= 2)) || { usage; exit 2; }
            requested_target="$2"
            shift 2
            ;;
        --install)
            install_binary=1
            shift
            ;;
        --rust-source)
            (($# >= 2)) || { usage; exit 2; }
            rust_source="$2"
            shift 2
            ;;
        --destination)
            (($# >= 2)) || { usage; exit 2; }
            destination="$2"
            shift 2
            ;;
        --machine)
            machine_output=1
            shift
            ;;
        --prepare-only)
            prepare_only=1
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

if ((prepare_only && install_binary)); then
    echo "--prepare-only and --install are mutually exclusive" >&2
    exit 2
fi

host_os="$(uname -s)"
host_arch="$(uname -m)"
case "$host_os:$host_arch" in
    Linux:x86_64)
        host_target="x86_64-unknown-linux-musl"
        ;;
    Linux:aarch64 | Linux:arm64)
        host_target="aarch64-unknown-linux-musl"
        ;;
    Darwin:x86_64)
        host_target="x86_64-apple-darwin"
        ;;
    Darwin:arm64 | Darwin:aarch64)
        host_target="aarch64-apple-darwin"
        ;;
    *)
        echo "unsupported h00ligan build host: $host_os $host_arch" >&2
        exit 1
        ;;
esac

target="${requested_target:-$host_target}"
case "$target" in
    x86_64-unknown-linux-musl | aarch64-unknown-linux-musl)
        target_os="Linux"
        ;;
    x86_64-apple-darwin | aarch64-apple-darwin)
        target_os="Darwin"
        ;;
    *)
        echo "unsupported h00ligan distribution target: $target" >&2
        exit 1
        ;;
esac
if [[ "$target_os" != "$host_os" ]]; then
    echo "cross-OS local builds are unsupported: host $host_os, target $target" >&2
    exit 1
fi
if ((install_binary)) && [[ "$target" != "$host_target" ]]; then
    echo "refusing to install non-native target $target on $host_target" >&2
    exit 1
fi

toolchain="1.97.1"
if [[ -n "${RUSTFLAGS:-}" ]]; then
    echo "refusing inherited RUSTFLAGS in the portable h00ligan lane" >&2
    exit 1
fi
if [[ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]]; then
    echo "refusing inherited CARGO_ENCODED_RUSTFLAGS in the portable h00ligan lane" >&2
    exit 1
fi
command -v rustup >/dev/null 2>&1 || { echo "rustup is required" >&2; exit 1; }
command -v file >/dev/null 2>&1 || { echo "file is required" >&2; exit 1; }

if ! rustup target list --toolchain "$toolchain" --installed | grep -Fxq "$target"; then
    echo "Installing pinned Rust $toolchain target $target ..." >&2
    rustup target add --toolchain "$toolchain" "$target" >&2
fi

authority_test="${H00LIGAN_BUILD_AUTHORITY_TEST:-0}"
[[ "$authority_test" == 0 || "$authority_test" == 1 ]] || {
    echo "H00LIGAN_BUILD_AUTHORITY_TEST must be 0 or 1" >&2
    exit 1
}
if [[ "$authority_test" == 1 && "$install_binary" == 1 ]]; then
    echo "authority-test artifacts are non-distributable and cannot be installed" >&2
    exit 2
fi
if [[ "$authority_test" == 1 ]]; then
    authority_test_barrier_timeout_seconds="${H00LIGAN_BUILD_TEST_BARRIER_TIMEOUT_SECONDS:-180}"
    if [[ ! "$authority_test_barrier_timeout_seconds" =~ ^[1-9][0-9]*$ ]] \
        || ((authority_test_barrier_timeout_seconds > 3600)); then
        echo "H00LIGAN_BUILD_TEST_BARRIER_TIMEOUT_SECONDS must be an integer from 1 to 3600" >&2
        exit 1
    fi
    test_root="${H00LIGAN_BUILD_TEST_ROOT:-}"
    [[ -n "$test_root" && -d "$test_root" && ! -L "$test_root" ]] || {
        echo "build-authority test root must be an existing real directory" >&2
        exit 1
    }
    test_root="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$test_root")"
    test_input="${H00LIGAN_BUILD_TEST_INPUT:-}"
    test_binary="${H00LIGAN_BUILD_TEST_BINARY:-}"
    [[ "$test_input" == "$test_root"/* && -f "$test_input" && ! -L "$test_input" ]] || {
        echo "build-authority test input must be a regular file inside the test root" >&2
        exit 1
    }
    [[ -x "$test_binary" && -f "$test_binary" && ! -L "$test_binary" ]] || {
        echo "build-authority test binary must be a regular executable" >&2
        exit 1
    }
    portable_target_dir="$test_root/portable-target"
    portable_cache_root="$test_root/portable-cache"
    portable_workspace_parent="$test_root/portable-workspaces"
else
    [[ -z "${H00LIGAN_BUILD_TEST_ROOT:-}${H00LIGAN_BUILD_TEST_INPUT:-}${H00LIGAN_BUILD_TEST_BINARY:-}${H00LIGAN_BUILD_TEST_BARRIER:-}${H00LIGAN_BUILD_TEST_CAPTURE_BARRIER:-}${H00LIGAN_BUILD_TEST_BARRIER_TIMEOUT_SECONDS:-}" ]] || {
        echo "portable build test controls require H00LIGAN_BUILD_AUTHORITY_TEST=1" >&2
        exit 1
    }
    portable_target_dir="$repo_root/target/portable"
    portable_cache_root="$repo_root/target/portable-cache"
    portable_workspace_parent="$repo_root/target/portable-workspaces"
fi

authority_test_barrier() {
    local barrier="$1"
    [[ -n "$barrier" ]] || return 0
    [[ "$authority_test" == 1 ]] || {
        echo "build-authority barrier used outside the test lane" >&2
        return 1
    }
    [[ "$barrier" == "$test_root"/* && -d "$(dirname "$barrier")" && ! -L "$(dirname "$barrier")" ]] || {
        echo "build-authority barrier must be inside a real test-root directory" >&2
        return 1
    }
    (umask 077; printf '%s\n' "$BASHPID" > "$barrier.ready")
    # The outer adversarial harness owns the shorter observation deadline and
    # terminates the whole process group. This inner bound exists only to keep
    # a directly invoked test builder finite; it must not release authority
    # first during a cold source capture.
    local deadline=$((SECONDS + authority_test_barrier_timeout_seconds))
    while [[ ! -f "$barrier.continue" ]]; do
        if ((SECONDS >= deadline)); then
            echo "timed out at build-authority barrier: $barrier" >&2
            return 1
        fi
        sleep 0.05
    done
    [[ ! -L "$barrier.continue" ]] || {
        echo "build-authority barrier release must not be a symlink" >&2
        return 1
    }
}
mkdir -p \
    "$portable_target_dir" \
    "$portable_cache_root/cargo-zigbuild" \
    "$portable_cache_root/zig-global" \
    "$portable_cache_root/zig-local/$target" \
    "$portable_workspace_parent"
[[ ! -L "$portable_workspace_parent" && -d "$portable_workspace_parent" ]] || {
    echo "portable build-workspace parent must be a real directory" >&2
    exit 1
}

cargo_home="${CARGO_HOME:-${HOME}/.cargo}"
rust_sysroot="$(rustup run "$toolchain" rustc --print sysroot)"
[[ -d "$rust_sysroot" ]] || {
    echo "pinned Rust toolchain reported no usable sysroot: $rust_sysroot" >&2
    exit 1
}
# rustc applies the last matching remap. Keep broad host paths first and
# increasingly specific build inputs last so no personal/repository prefix can
# survive under a misleading relative spelling.
portable_rustflags="--remap-path-prefix=$HOME=build-home --remap-path-prefix=$repo_root=h00-live-source --remap-path-prefix=$cargo_home=cargo-registry --remap-path-prefix=$rust_sysroot=rust-toolchain"
native_remap_flags="-ffile-prefix-map=$HOME=build-home -ffile-prefix-map=$repo_root=h00-live-source -ffile-prefix-map=$cargo_home=cargo-registry -ffile-prefix-map=$rust_sysroot=rust-toolchain"

export CARGO_TARGET_DIR="$portable_target_dir"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_LTO=thin
export CARGO_PROFILE_RELEASE_PANIC=abort
export CARGO_PROFILE_RELEASE_STRIP=symbols
export CFLAGS="$native_remap_flags"
export CXXFLAGS="$native_remap_flags"
unset NIX_LDFLAGS LIBRARY_PATH LD_LIBRARY_PATH
unset DYLD_LIBRARY_PATH DYLD_FALLBACK_LIBRARY_PATH
unset CC CXX AR LDFLAGS
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
export RUSTFLAGS="$portable_rustflags"

cd -- "$repo_root"

provider_args=(--prepare-only --machine)
if [[ -n "$rust_source" ]]; then
    provider_args+=(--rust-source "$rust_source")
fi
provider_details="$(
    unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
    "$repo_root/scripts/build-h00-rust-semantic-provider.sh" "${provider_args[@]}"
)"
provider_source_root="$(printf '%s\n' "$provider_details" | sed -n 's/^H00_RA_SOURCE_ROOT=//p')"
provider_patch_sha256="$(printf '%s\n' "$provider_details" | sed -n 's/^H00_RA_PATCH_SHA256=//p')"
provider_source_key="$(printf '%s\n' "$provider_details" | sed -n 's/^H00_RA_SOURCE_KEY=//p')"
provider_builder_sha256="$(printf '%s\n' "$provider_details" | sed -n 's/^H00_RA_BUILDER_SHA256=//p')"
[[ -d "$provider_source_root" ]] || {
    echo "semantic-provider source root was not prepared: $provider_source_root" >&2
    exit 1
}
[[ "$provider_patch_sha256" =~ ^[0-9a-f]{64}$ ]] || {
    echo "semantic-provider patch identity is invalid" >&2
    exit 1
}
[[ "$provider_source_key" =~ ^[0-9a-f]{64}$ ]] || {
    echo "semantic-provider source identity is invalid" >&2
    exit 1
}
[[ "$provider_builder_sha256" =~ ^[0-9a-f]{64}$ ]] || {
    echo "semantic-provider builder identity is invalid" >&2
    exit 1
}

verify_provider_source() {
    local current_details current_source_root current_patch_sha256
    local current_source_key current_builder_sha256
    current_details="$(
        unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
        "$repo_root/scripts/build-h00-rust-semantic-provider.sh" "${provider_args[@]}"
    )"
    current_source_root="$(printf '%s\n' "$current_details" | sed -n 's/^H00_RA_SOURCE_ROOT=//p')"
    current_patch_sha256="$(printf '%s\n' "$current_details" | sed -n 's/^H00_RA_PATCH_SHA256=//p')"
    current_source_key="$(printf '%s\n' "$current_details" | sed -n 's/^H00_RA_SOURCE_KEY=//p')"
    current_builder_sha256="$(printf '%s\n' "$current_details" | sed -n 's/^H00_RA_BUILDER_SHA256=//p')"
    [[ "$current_source_root" == "$provider_source_root" ]] || {
        echo "semantic-provider source root changed after product snapshot" >&2
        return 1
    }
    [[ "$current_patch_sha256" == "$provider_patch_sha256" ]] || {
        echo "semantic-provider patch changed after product snapshot" >&2
        return 1
    }
    [[ "$current_source_key" == "$provider_source_key" ]] || {
        echo "semantic-provider source identity changed after product snapshot" >&2
        return 1
    }
    [[ "$current_builder_sha256" == "$provider_builder_sha256" ]] || {
        echo "semantic-provider builder changed after product snapshot" >&2
        return 1
    }
}

python_provider_prepare_args=(--prepare-only --machine)
python_provider_details="$(
    unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
    "$repo_root/scripts/build-h00-pyrefly-semantic-provider.sh" --target "$target" --machine
)"
python_provider_binary="$(printf '%s\n' "$python_provider_details" | sed -n 's/^H00_PYREFLY_PROVIDER_BINARY=//p')"
python_provider_receipt="$(printf '%s\n' "$python_provider_details" | sed -n 's/^H00_PYREFLY_PROVIDER_RECEIPT=//p')"
python_provider_binary_sha256="$(printf '%s\n' "$python_provider_details" | sed -n 's/^H00_PYREFLY_PROVIDER_BINARY_SHA256=//p')"
python_provider_source_root="$(printf '%s\n' "$python_provider_details" | sed -n 's/^H00_PYREFLY_SOURCE_ROOT=//p')"
python_provider_patch_sha256="$(printf '%s\n' "$python_provider_details" | sed -n 's/^H00_PYREFLY_PATCH_SHA256=//p')"
python_provider_source_key="$(printf '%s\n' "$python_provider_details" | sed -n 's/^H00_PYREFLY_SOURCE_KEY=//p')"
python_provider_builder_sha256="$(printf '%s\n' "$python_provider_details" | sed -n 's/^H00_PYREFLY_BUILDER_SHA256=//p')"
python_provider_archive_sha256="$(printf '%s\n' "$python_provider_details" | sed -n 's/^H00_PYREFLY_ARCHIVE_SHA256=//p')"
python_provider_source_tree_sha256="$(printf '%s\n' "$python_provider_details" | sed -n 's/^H00_PYREFLY_SOURCE_TREE_SHA256=//p')"
python_provider_cache_publisher_sha256="$(printf '%s\n' "$python_provider_details" | sed -n 's/^H00_PYREFLY_CACHE_PUBLISHER_SHA256=//p')"
[[ -x "$python_provider_binary" && -f "$python_provider_receipt" \
    && ! -L "$python_provider_binary" && ! -L "$python_provider_receipt" \
    && -d "$python_provider_source_root" && ! -L "$python_provider_source_root" \
    && -f "$python_provider_source_root/pyrefly/Cargo.toml" \
    && ! -L "$python_provider_source_root/pyrefly/Cargo.toml" ]] || {
    echo "embedded Pyrefly semantic-provider artifact is incomplete" >&2
    exit 1
}
for digest in \
    "$python_provider_binary_sha256" \
    "$python_provider_patch_sha256" \
    "$python_provider_source_key" \
    "$python_provider_builder_sha256" \
    "$python_provider_archive_sha256" \
    "$python_provider_source_tree_sha256" \
    "$python_provider_cache_publisher_sha256"; do
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
        echo "embedded Pyrefly semantic-provider identity is invalid" >&2
        exit 1
    }
done

verify_python_provider_source() {
    local current_details current_source_root current_patch_sha256
    local current_source_key current_builder_sha256 current_archive_sha256
    current_details="$(
        unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
        "$repo_root/scripts/build-h00-pyrefly-semantic-provider.sh" "${python_provider_prepare_args[@]}"
    )"
    current_source_root="$(printf '%s\n' "$current_details" | sed -n 's/^H00_PYREFLY_SOURCE_ROOT=//p')"
    current_patch_sha256="$(printf '%s\n' "$current_details" | sed -n 's/^H00_PYREFLY_PATCH_SHA256=//p')"
    current_source_key="$(printf '%s\n' "$current_details" | sed -n 's/^H00_PYREFLY_SOURCE_KEY=//p')"
    current_builder_sha256="$(printf '%s\n' "$current_details" | sed -n 's/^H00_PYREFLY_BUILDER_SHA256=//p')"
    current_archive_sha256="$(printf '%s\n' "$current_details" | sed -n 's/^H00_PYREFLY_ARCHIVE_SHA256=//p')"
    [[ "$current_source_root" == "$python_provider_source_root" ]] || {
        echo "Pyrefly semantic-provider source root changed after product snapshot" >&2
        return 1
    }
    [[ "$current_patch_sha256" == "$python_provider_patch_sha256" ]] || {
        echo "Pyrefly semantic-provider patch changed after product snapshot" >&2
        return 1
    }
    [[ "$current_source_key" == "$python_provider_source_key" ]] || {
        echo "Pyrefly semantic-provider source identity changed after product snapshot" >&2
        return 1
    }
    [[ "$current_builder_sha256" == "$python_provider_builder_sha256" ]] || {
        echo "Pyrefly semantic-provider builder changed after product snapshot" >&2
        return 1
    }
    [[ "$current_archive_sha256" == "$python_provider_archive_sha256" ]] || {
        echo "Pyrefly semantic-provider archive changed after product snapshot" >&2
        return 1
    }
}

python3 - "$python_provider_binary" "$python_provider_receipt" "$target" \
    "$python_provider_binary_sha256" "$python_provider_source_key" \
    "$python_provider_patch_sha256" "$python_provider_builder_sha256" \
    "$python_provider_archive_sha256" "$python_provider_source_tree_sha256" \
    "$python_provider_cache_publisher_sha256" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

binary = Path(sys.argv[1])
receipt = Path(sys.argv[2])
target, binary_sha256, source_key, patch, builder, archive, source_tree, cache_publisher = sys.argv[3:]
payload = json.loads(receipt.read_text(encoding="utf-8"))
expected = {
    "schema": "h00/pyrefly-semantic-provider-build/v2",
    "target": target,
    "binary_sha256": binary_sha256,
    "source_key": source_key,
    "patch_sha256": patch,
    "builder_sha256": builder,
    "archive_sha256": archive,
    "source_tree_sha256": source_tree,
    "cache_publisher_sha256": cache_publisher,
}
for field, value in expected.items():
    if payload.get(field) != value:
        raise SystemExit(
            f"Pyrefly provider receipt field {field!r} is {payload.get(field)!r}, expected {value!r}"
        )
contents = binary.read_bytes()
if hashlib.sha256(contents).hexdigest() != binary_sha256:
    raise SystemExit("Pyrefly provider binary differs from its receipt")
if payload.get("binary_size") != len(contents):
    raise SystemExit("Pyrefly provider size differs from its receipt")
PY

go_provider_details="$(
    "$repo_root/scripts/build-h00-go-semantic-provider.sh" --target "$target" --machine
)"
go_provider_binary="$(printf '%s\n' "$go_provider_details" | sed -n 's/^H00_GO_PROVIDER_BINARY=//p')"
go_provider_receipt="$(printf '%s\n' "$go_provider_details" | sed -n 's/^H00_GO_PROVIDER_RECEIPT=//p')"
go_provider_binary_sha256="$(printf '%s\n' "$go_provider_details" | sed -n 's/^H00_GO_PROVIDER_BINARY_SHA256=//p')"
go_provider_patch_sha256="$(printf '%s\n' "$go_provider_details" | sed -n 's/^H00_GO_PROVIDER_PATCH_SHA256=//p')"
go_provider_source_tree_sha256="$(printf '%s\n' "$go_provider_details" | sed -n 's/^H00_GO_PROVIDER_SOURCE_TREE_SHA256=//p')"
go_provider_builder_sha256="$(printf '%s\n' "$go_provider_details" | sed -n 's/^H00_GO_PROVIDER_BUILDER_SHA256=//p')"
go_provider_cache_publisher_sha256="$(printf '%s\n' "$go_provider_details" | sed -n 's/^H00_GO_PROVIDER_CACHE_PUBLISHER_SHA256=//p')"
go_provider_go_sdk_resolver_sha256="$(printf '%s\n' "$go_provider_details" | sed -n 's/^H00_GO_SDK_RESOLVER_SHA256=//p')"
go_provider_go_sdk_receipt_sha256="$(printf '%s\n' "$go_provider_details" | sed -n 's/^H00_GO_SDK_RECEIPT_SHA256=//p')"
[[ -x "$go_provider_binary" && -f "$go_provider_receipt" && ! -L "$go_provider_binary" && ! -L "$go_provider_receipt" ]] || {
    echo "embedded Go semantic-provider artifact is incomplete" >&2
    exit 1
}
for digest in \
    "$go_provider_binary_sha256" \
    "$go_provider_patch_sha256" \
    "$go_provider_source_tree_sha256" \
    "$go_provider_builder_sha256" \
    "$go_provider_cache_publisher_sha256" \
    "$go_provider_go_sdk_resolver_sha256" \
    "$go_provider_go_sdk_receipt_sha256"; do
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
        echo "embedded Go semantic-provider identity is invalid" >&2
        exit 1
    }
done

typescript_provider_details="$(
    "$repo_root/scripts/build-h00-typescript-semantic-provider.sh" --target "$target" --machine
)"
typescript_provider_binary="$(printf '%s\n' "$typescript_provider_details" | sed -n 's/^H00_TYPESCRIPT_PROVIDER_BINARY=//p')"
typescript_provider_receipt="$(printf '%s\n' "$typescript_provider_details" | sed -n 's/^H00_TYPESCRIPT_PROVIDER_RECEIPT=//p')"
typescript_provider_binary_sha256="$(printf '%s\n' "$typescript_provider_details" | sed -n 's/^H00_TYPESCRIPT_PROVIDER_BINARY_SHA256=//p')"
typescript_provider_patch_sha256="$(printf '%s\n' "$typescript_provider_details" | sed -n 's/^H00_TYPESCRIPT_PROVIDER_PATCH_SHA256=//p')"
typescript_provider_test_sha256="$(printf '%s\n' "$typescript_provider_details" | sed -n 's/^H00_TYPESCRIPT_PROVIDER_TEST_SHA256=//p')"
typescript_provider_source_tree_sha256="$(printf '%s\n' "$typescript_provider_details" | sed -n 's/^H00_TYPESCRIPT_PROVIDER_SOURCE_TREE_SHA256=//p')"
typescript_provider_builder_sha256="$(printf '%s\n' "$typescript_provider_details" | sed -n 's/^H00_TYPESCRIPT_PROVIDER_BUILDER_SHA256=//p')"
typescript_provider_cache_publisher_sha256="$(printf '%s\n' "$typescript_provider_details" | sed -n 's/^H00_TYPESCRIPT_PROVIDER_CACHE_PUBLISHER_SHA256=//p')"
typescript_provider_go_sdk_resolver_sha256="$(printf '%s\n' "$typescript_provider_details" | sed -n 's/^H00_GO_SDK_RESOLVER_SHA256=//p')"
typescript_provider_go_sdk_receipt_sha256="$(printf '%s\n' "$typescript_provider_details" | sed -n 's/^H00_GO_SDK_RECEIPT_SHA256=//p')"
[[ -x "$typescript_provider_binary" && -f "$typescript_provider_receipt" \
    && ! -L "$typescript_provider_binary" && ! -L "$typescript_provider_receipt" ]] || {
    echo "embedded TypeScript semantic-provider artifact is incomplete" >&2
    exit 1
}
for digest in \
    "$typescript_provider_binary_sha256" \
    "$typescript_provider_patch_sha256" \
    "$typescript_provider_test_sha256" \
    "$typescript_provider_source_tree_sha256" \
    "$typescript_provider_builder_sha256" \
    "$typescript_provider_cache_publisher_sha256" \
    "$typescript_provider_go_sdk_resolver_sha256" \
    "$typescript_provider_go_sdk_receipt_sha256"; do
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
        echo "embedded TypeScript semantic-provider identity is invalid" >&2
        exit 1
    }
done
[[ "$go_provider_go_sdk_resolver_sha256" == "$typescript_provider_go_sdk_resolver_sha256" \
    && "$go_provider_go_sdk_receipt_sha256" == "$typescript_provider_go_sdk_receipt_sha256" ]] || {
    echo "embedded Go and TypeScript providers did not resolve one exact official Go SDK" >&2
    exit 1
}
[[ "$python_provider_cache_publisher_sha256" == "$go_provider_cache_publisher_sha256" \
    && "$python_provider_cache_publisher_sha256" == "$typescript_provider_cache_publisher_sha256" ]] || {
    echo "embedded providers did not use one exact cache publisher" >&2
    exit 1
}

product_template_live="$repo_root/providers/rust-analyzer/h00ligan-product.Cargo.toml.in"
provider_adapter_template_live="$repo_root/providers/rust-analyzer/h00ligan-provider-adapter.Cargo.toml.in"
product_main_live="$repo_root/providers/rust-analyzer/h00ligan_embedded_main.rs"
product_lockfile_live="$repo_root/providers/rust-analyzer/h00ligan-product.Cargo.lock"
provider_source_lib="$provider_source_root/crates/h00ligan-ra-provider/src/lib.rs"
go_provider_builder_live="$repo_root/scripts/build-h00-go-semantic-provider.sh"
typescript_provider_builder_live="$repo_root/scripts/build-h00-typescript-semantic-provider.sh"
python_provider_builder_live="$repo_root/scripts/build-h00-pyrefly-semantic-provider.sh"
go_sdk_resolver_live="$repo_root/scripts/resolve-h00-official-go-sdk.sh"
go_cache_publisher_live="$repo_root/scripts/publish-h00ligan-cache-directory.py"
binary_checker_live="$repo_root/scripts/check-h00ligan-binary.py"
cargo_generation_manager_live="$repo_root/scripts/manage-h00ligan-cargo-generation.py"
go_provider_source_inputs=(
    "$repo_root/providers/go/gopls/h00_provider_main.go"
    "$repo_root/providers/go/gopls/h00_provider_protocol.go"
    "$repo_root/providers/go/gopls/h00_semantic_provider.go"
    "$repo_root/providers/go/gopls/h00_scip.go"
    "$repo_root/providers/go/scip-go/h00scip/export.go"
)
typescript_provider_source_inputs=(
    "$repo_root/providers/go/shared/h00provider/protocol.go"
    "$repo_root/providers/typescript/h00_provider_main.go"
    "$repo_root/providers/typescript/h00_provider_protocol.go"
    "$repo_root/providers/typescript/h00_semantic_provider.go"
    "$repo_root/providers/typescript/h00_typescript_engine.go"
    "$repo_root/providers/typescript/h00_typescript_scip.go"
    "$repo_root/providers/typescript/h00_typescript_engine_test.go"
    "$repo_root/providers/typescript/h00_typescript_provider_process_test.go"
)
python_provider_source_inputs=(
    "$repo_root/providers/python/pyrefly/provider.Cargo.toml.in"
    "$repo_root/providers/python/pyrefly/provider.Cargo.lock"
    "$repo_root/providers/python/pyrefly/h00_pyrefly_semantic_provider.rs"
    "$repo_root/providers/python/pyrefly/h00_pyrefly_semantic_provider_main.rs"
    "$repo_root/providers/python/pyrefly/h00_semantic.rs"
    "$repo_root/providers/python/pyrefly/pyrefly-1.2.0.patch"
)
product_source_inputs=(
    "crates/h00ligan-engine/Cargo.toml"
    "crates/h00ligan-engine/build.rs"
    "crates/h00ligan-engine/build_support"
    "crates/h00ligan-engine/examples"
    "crates/h00ligan-engine/src"
    "crates/h00ligan-interface/Cargo.toml"
    "crates/h00ligan-interface/src"
    "crates/h00ligan-provider-protocol/Cargo.toml"
    "crates/h00ligan-provider-protocol/src"
    "crates/h00ligan/Cargo.toml"
    "crates/h00ligan/README.md"
    "crates/h00ligan/src"
)
for required in \
    "$product_builder_live" \
    "$product_template_live" \
    "$provider_adapter_template_live" \
    "$product_main_live" \
    "$product_lockfile_live" \
    "$provider_source_lib" \
    "$go_provider_builder_live" \
    "$typescript_provider_builder_live" \
    "$python_provider_builder_live" \
    "$go_sdk_resolver_live" \
    "$go_cache_publisher_live" \
    "$binary_checker_live" \
    "$cargo_generation_manager_live" \
    "${go_provider_source_inputs[@]}" \
    "${typescript_provider_source_inputs[@]}" \
    "${python_provider_source_inputs[@]}"; do
    [[ -f "$required" ]] || { echo "missing portable product build input: $required" >&2; exit 1; }
    [[ ! -L "$required" ]] || { echo "portable product build input must not be a symlink: $required" >&2; exit 1; }
done
for relative in "${product_source_inputs[@]}"; do
    required="$repo_root/$relative"
    [[ -e "$required" && ! -L "$required" ]] || {
        echo "missing or unsafe h00ligan product source input: $relative" >&2
        exit 1
    }
    if [[ -d "$required" && -n "$(find "$required" -type l -print -quit)" ]]; then
        echo "h00ligan product source input contains a symlink: $relative" >&2
        exit 1
    fi
done

measure_live_source_state() {
    local git_root=""
    git_root="$(git -C "$repo_root" rev-parse --show-toplevel 2>/dev/null || true)"
    if [[ -n "$git_root" \
        && "$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$git_root")" == "$repo_root" ]]; then
        local commit
        commit="$(git -C "$repo_root" rev-parse HEAD)"
        [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || {
            echo "h00ligan Git source revision is invalid: $commit" >&2
            return 1
        }
        local dirty=0
        if [[ -n "$(git -C "$repo_root" status --porcelain)" ]]; then
            dirty=1
        fi
        printf 'git:%s\n%s\n' "$commit" "$dirty"
        return
    fi

    local tree_sha256
    tree_sha256="$(python3 - "$repo_root" "${product_source_inputs[@]}" <<'PY'
import hashlib
from pathlib import Path
import stat
import struct
import sys

root = Path(sys.argv[1])
inputs = [Path(value) for value in sys.argv[2:]]
hasher = hashlib.sha256()

def field(value: bytes) -> None:
    hasher.update(struct.pack(">Q", len(value)))
    hasher.update(value)

field(b"h00ligan/live-product-source/v1")
population = []
for relative in inputs:
    source = root / relative
    if source.is_symlink():
        raise SystemExit(f"product source input must not be a symlink: {relative}")
    if source.is_file():
        population.append((relative.as_posix(), source))
    elif source.is_dir():
        for path in source.rglob("*"):
            if path.is_symlink():
                raise SystemExit(f"product source input must not contain a symlink: {path}")
            if path.is_file():
                population.append((path.relative_to(root).as_posix(), path))
    else:
        raise SystemExit(f"product source input is missing: {relative}")

for relative, path in sorted(population):
    field(relative.encode())
    field(stat.S_IMODE(path.stat().st_mode).to_bytes(4, "big"))
    field(path.read_bytes())
print(hasher.hexdigest())
PY
)"
    [[ "$tree_sha256" =~ ^[0-9a-f]{64}$ ]] || {
        echo "h00ligan source-tree revision is invalid: $tree_sha256" >&2
        return 1
    }
    printf 'tree:%s\n0\n' "$tree_sha256"
}

source_state="$(measure_live_source_state)"
source_revision="$(printf '%s\n' "$source_state" | sed -n '1p')"
source_dirty="$(printf '%s\n' "$source_state" | sed -n '2p')"
[[ "$source_revision" =~ ^(git:[0-9a-f]{40}|tree:[0-9a-f]{64})$ \
    && "$source_dirty" =~ ^[01]$ \
    && ( "$source_revision" == git:* || "$source_dirty" == 0 ) ]] || {
    echo "h00ligan source state is invalid: revision=$source_revision dirty=$source_dirty" >&2
    exit 1
}

product_source_key=""
product_root=""
product_candidate="$(mktemp -d "$portable_cache_root/product.XXXXXX")"
product_lock=""
install_temp=""
artifact_candidate=""
build_lock=""
product_build_candidate=""
cleanup() {
    local owned_product_lock="$product_lock"
    local owned_build_lock="$build_lock"
    product_lock=""
    build_lock=""
    if [[ -n "$install_temp" && -f "$install_temp" ]]; then
        rm -f -- "$install_temp"
    fi
    if [[ -n "$product_candidate" && -d "$product_candidate" ]]; then
        rm -rf -- "$product_candidate"
    fi
    if [[ -n "$owned_product_lock" && -d "$owned_product_lock" ]]; then
        rmdir -- "$owned_product_lock" 2>/dev/null || true
    fi
    if [[ -n "$artifact_candidate" && -d "$artifact_candidate" ]]; then
        rm -rf -- "$artifact_candidate"
    fi
    if [[ -n "$owned_build_lock" && -d "$owned_build_lock" ]]; then
        rmdir -- "$owned_build_lock" 2>/dev/null || true
    fi
    if [[ -n "$product_build_candidate" && -d "$product_build_candidate" ]]; then
        rm -rf -- "$product_build_candidate"
    fi
    if [[ -n "${invocation_root:-}" && -d "$invocation_root" ]]; then
        rm -rf -- "$invocation_root"
    fi
}
trap cleanup EXIT HUP INT TERM

verify_product_workspace() {
    python3 - "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys

root = Path(sys.argv[1])
source_key = sys.argv[2]
operation = sys.argv[3]
provider_source_key = sys.argv[4]
provider_patch_sha256 = sys.argv[5]
provider_builder_sha256 = sys.argv[6]
product_builder_sha256 = sys.argv[7]
source_revision = sys.argv[8]
source_dirty = sys.argv[9]
authority_test = sys.argv[10]
receipt = root / ".h00-h00ligan-product-source.json"

if root.is_symlink() or not root.is_dir():
    raise SystemExit("product-source root must be a real directory")
if not (
    (source_revision.startswith("git:") and len(source_revision) == 44)
    or (source_revision.startswith("tree:") and len(source_revision) == 69)
):
    raise SystemExit("product-source revision has no typed exact identity")
if source_dirty not in {"0", "1"} or (
    source_revision.startswith("tree:") and source_dirty != "0"
):
    raise SystemExit("product-source dirty state is incompatible with its revision kind")

def field(hasher, value):
    hasher.update(struct.pack(">Q", len(value)))
    hasher.update(value)

hasher = hashlib.sha256()
field(hasher, b"h00/h00ligan-product-source-tree/v1")
file_count = 0
total_bytes = 0
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    if path == receipt:
        continue
    relative = path.relative_to(root).as_posix().encode()
    mode = stat.S_IMODE(path.lstat().st_mode).to_bytes(4, "big")
    if path.is_symlink():
        kind = b"symlink"
        contents = os.readlink(path).encode()
    elif path.is_dir():
        continue
    elif path.is_file():
        kind = b"file"
        contents = path.read_bytes()
    else:
        raise SystemExit(f"unsupported product-source entry: {path}")
    for value in (relative, kind, mode, contents):
        field(hasher, value)
    file_count += 1
    total_bytes += len(contents)

tree_sha256 = hasher.hexdigest()
key_hasher = hashlib.sha256()
for value in (
    b"h00/h00ligan-product-source/v6",
    provider_source_key.encode(),
    provider_patch_sha256.encode(),
    provider_builder_sha256.encode(),
    product_builder_sha256.encode(),
    source_revision.encode(),
    source_dirty.encode(),
    tree_sha256.encode(),
):
    field(key_hasher, value)
expected_source_key = key_hasher.hexdigest()
product_lock = root / "product/Cargo.lock"
if not product_lock.is_file() or product_lock.is_symlink():
    raise SystemExit("product-source snapshot has no regular product lockfile")

observed = {
    "schema": "h00/h00ligan-product-source-cache/v6",
    "source_key": expected_source_key,
    "provider_source_key": provider_source_key,
    "provider_patch_sha256": provider_patch_sha256,
    "provider_builder_sha256": provider_builder_sha256,
    "product_builder_sha256": product_builder_sha256,
    "source_revision": source_revision,
    "source_dirty": source_dirty == "1",
    "product_lock_sha256": hashlib.sha256(product_lock.read_bytes()).hexdigest(),
    "tree_sha256": tree_sha256,
    "file_count": file_count,
    "total_bytes": total_bytes,
}
if authority_test == "1":
    observed["authority_test"] = True
if operation == "measure":
    print(json.dumps(observed, sort_keys=True, separators=(",", ":")))
elif operation == "create":
    if source_key != expected_source_key:
        raise SystemExit("product-source key does not describe the staged tree")
    if receipt.exists():
        raise SystemExit("product-source receipt already exists during creation")
    receipt.write_text(json.dumps(observed, sort_keys=True, separators=(",", ":")) + "\n")
elif operation == "verify":
    if source_key != expected_source_key:
        raise SystemExit("product-source key does not describe the cached tree")
    if not receipt.is_file():
        raise SystemExit("product-source receipt is missing")
    if json.loads(receipt.read_text()) != observed:
        raise SystemExit("h00ligan product-source cache failed integrity verification")
else:
    raise SystemExit(f"unknown product-source operation: {operation}")
PY
}

build_inputs="$product_candidate/.h00-build-inputs"
mkdir -p "$build_inputs"
install -m 0755 "$product_builder" "$build_inputs/build-h00ligan-portable.sh"
install -m 0644 "$product_template_live" "$build_inputs/h00ligan-product.Cargo.toml.in"
install -m 0644 "$provider_adapter_template_live" "$build_inputs/h00ligan-provider-adapter.Cargo.toml.in"
install -m 0644 "$product_main_live" "$build_inputs/h00ligan_embedded_main.rs"
install -m 0644 "$product_lockfile_live" "$build_inputs/h00ligan-product.Cargo.lock"
install -m 0755 "$go_provider_builder_live" "$build_inputs/build-h00-go-semantic-provider.sh"
install -m 0755 "$typescript_provider_builder_live" "$build_inputs/build-h00-typescript-semantic-provider.sh"
install -m 0755 "$python_provider_builder_live" "$build_inputs/build-h00-pyrefly-semantic-provider.sh"
install -m 0755 "$go_sdk_resolver_live" "$build_inputs/resolve-h00-official-go-sdk.sh"
install -m 0644 "$go_cache_publisher_live" "$build_inputs/publish-h00ligan-cache-directory.py"
staged_go_sdk_resolver_sha256="$(sha256sum "$build_inputs/resolve-h00-official-go-sdk.sh" | awk '{print $1}')"
[[ "$staged_go_sdk_resolver_sha256" == "$go_provider_go_sdk_resolver_sha256" \
    && "$staged_go_sdk_resolver_sha256" == "$typescript_provider_go_sdk_resolver_sha256" ]] || {
    echo "official Go SDK resolver changed after provider publication" >&2
    exit 1
}
staged_cache_publisher_sha256="$(sha256sum "$build_inputs/publish-h00ligan-cache-directory.py" | awk '{print $1}')"
[[ "$staged_cache_publisher_sha256" == "$go_provider_cache_publisher_sha256" \
    && "$staged_cache_publisher_sha256" == "$typescript_provider_cache_publisher_sha256" ]] || {
    echo "semantic-provider cache publisher changed after provider publication" >&2
    exit 1
}
install -m 0755 "$binary_checker_live" "$build_inputs/check-h00ligan-binary.py"
install -m 0644 "$cargo_generation_manager_live" "$build_inputs/manage-h00ligan-cargo-generation.py"
printf '%s\n' "${product_source_inputs[@]}" > "$build_inputs/h00ligan-product-source-inputs"
mkdir -p "$build_inputs/go-provider/gopls" "$build_inputs/go-provider/scip-go/h00scip"
install -m 0644 "${go_provider_source_inputs[0]}" "$build_inputs/go-provider/gopls/h00_provider_main.go"
install -m 0644 "${go_provider_source_inputs[1]}" "$build_inputs/go-provider/gopls/h00_provider_protocol.go"
install -m 0644 "${go_provider_source_inputs[2]}" "$build_inputs/go-provider/gopls/h00_semantic_provider.go"
install -m 0644 "${go_provider_source_inputs[3]}" "$build_inputs/go-provider/gopls/h00_scip.go"
install -m 0644 "${go_provider_source_inputs[4]}" "$build_inputs/go-provider/scip-go/h00scip/export.go"
mkdir -p \
    "$build_inputs/typescript-provider/shared/h00provider" \
    "$build_inputs/typescript-provider/typescript"
install -m 0644 "${typescript_provider_source_inputs[0]}" "$build_inputs/typescript-provider/shared/h00provider/protocol.go"
install -m 0644 "${typescript_provider_source_inputs[1]}" "$build_inputs/typescript-provider/typescript/h00_provider_main.go"
install -m 0644 "${typescript_provider_source_inputs[2]}" "$build_inputs/typescript-provider/typescript/h00_provider_protocol.go"
install -m 0644 "${typescript_provider_source_inputs[3]}" "$build_inputs/typescript-provider/typescript/h00_semantic_provider.go"
install -m 0644 "${typescript_provider_source_inputs[4]}" "$build_inputs/typescript-provider/typescript/h00_typescript_engine.go"
install -m 0644 "${typescript_provider_source_inputs[5]}" "$build_inputs/typescript-provider/typescript/h00_typescript_scip.go"
install -m 0644 "${typescript_provider_source_inputs[6]}" "$build_inputs/typescript-provider/typescript/h00_typescript_engine_test.go"
install -m 0644 "${typescript_provider_source_inputs[7]}" "$build_inputs/typescript-provider/typescript/h00_typescript_provider_process_test.go"
mkdir -p "$build_inputs/python-provider"
install -m 0644 "${python_provider_source_inputs[0]}" "$build_inputs/python-provider/provider.Cargo.toml.in"
install -m 0644 "${python_provider_source_inputs[1]}" "$build_inputs/python-provider/provider.Cargo.lock"
install -m 0644 "${python_provider_source_inputs[2]}" "$build_inputs/python-provider/lib.rs"
install -m 0644 "${python_provider_source_inputs[3]}" "$build_inputs/python-provider/main.rs"
install -m 0644 "${python_provider_source_inputs[4]}" "$build_inputs/python-provider/h00_semantic.rs"
install -m 0644 "${python_provider_source_inputs[5]}" "$build_inputs/python-provider/pyrefly-1.2.0.patch"
if [[ "$authority_test" == 1 ]]; then
    install -m 0644 "$test_input" "$build_inputs/authority-test-input"
fi
product_builder_sha256="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$build_inputs/build-h00ligan-portable.sh")"

source_workspace_root="$product_candidate/source"
mkdir -p "$source_workspace_root/crates"
install -m 0644 "$repo_root/Cargo.toml" "$source_workspace_root/Cargo.toml"
install -m 0644 "$repo_root/rust-toolchain.toml" "$source_workspace_root/rust-toolchain.toml"
install -m 0644 "$build_inputs/h00ligan-product.Cargo.lock" "$source_workspace_root/Cargo.lock"
for relative in "${product_source_inputs[@]}"; do
    source_input="$repo_root/$relative"
    staged_input="$source_workspace_root/$relative"
    mkdir -p "$(dirname "$staged_input")"
    cp -a "$source_input" "$staged_input"
done
product_crate_root="$product_candidate/product"
mkdir -p "$product_crate_root/src"
install -m 0644 "$build_inputs/h00ligan-product.Cargo.lock" "$product_crate_root/Cargo.lock"
install -m 0644 "$build_inputs/h00ligan_embedded_main.rs" "$product_crate_root/src/main.rs"
if [[ "$authority_test" == 1 ]]; then
    # Make the existing authority input a real Cargo source input as well as a
    # source-receipt input. Its caller-controlled historical mtime lets the
    # harness exercise stable-workspace freshness without touching live source.
    python3 - "$test_input" "$product_crate_root/src/main.rs" <<'PY'
import os
from pathlib import Path
import sys

source = Path(sys.argv[1])
output = Path(sys.argv[2])
marker = source.read_bytes().hex().encode()
with output.open("ab") as stream:
    stream.write(
        b"\n#[used]\nstatic H00_BUILD_AUTHORITY_TEST_MARKER: [u8; "
        + str(len(marker)).encode()
        + b"] = *b\""
        + marker
        + b"\";\n"
    )
source_stat = source.stat()
os.utime(output, ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns))
PY
fi
provider_adapter_root="$product_candidate/rust-provider"
mkdir -p "$provider_adapter_root/src"
install -m 0644 "$provider_source_lib" "$provider_adapter_root/src/lib.rs"
provider_source_relative="$(python3 -c 'import os,sys; print(os.path.relpath(sys.argv[1], sys.argv[2]))' "$provider_source_root" "$provider_adapter_root")"
python3 - "$build_inputs/h00ligan-product.Cargo.toml.in" "$product_crate_root/Cargo.toml" \
    "$build_inputs/h00ligan-provider-adapter.Cargo.toml.in" \
    "$provider_adapter_root/Cargo.toml" \
    "$source_workspace_root/crates/h00ligan/Cargo.toml" \
    "$provider_source_relative" <<'PY'
from pathlib import Path
import sys
import tomllib

(
    template,
    output,
    adapter_template,
    adapter_output,
    ligan_manifest,
    provider_source_relative,
) = sys.argv[1:]
template = Path(template)
output = Path(output)
adapter_template = Path(adapter_template)
adapter_output = Path(adapter_output)
ligan_manifest = Path(ligan_manifest)
manifest = template.read_text(encoding="utf-8")
manifest = manifest.replace("@H00_LIGAN_PATH@", "../source/crates/h00ligan")
manifest = manifest.replace("@H00_RA_PROVIDER_PATH@", "../rust-provider")
with ligan_manifest.open("rb") as handle:
    product_version = tomllib.load(handle)["package"]["version"]
manifest = manifest.replace("@H00LIGAN_VERSION@", product_version)
if "@H00_" in manifest:
    raise SystemExit("unresolved h00ligan product-manifest placeholder")
output.write_text(manifest, encoding="utf-8")

adapter = adapter_template.read_text(encoding="utf-8")
adapter = adapter.replace("@H00_RA_SOURCE_PATH@", provider_source_relative)
if "@H00_" in adapter:
    raise SystemExit("unresolved h00ligan provider-adapter placeholder")
adapter_output.write_text(adapter, encoding="utf-8")
PY

verify_live_product_inputs() {
    local snapshot_root="$1"
    python3 - "$repo_root" "$product_builder_live" "$snapshot_root" \
        "$provider_source_lib" "$cargo_generation_manager_live" "${test_input:-}" <<'PY'
import hashlib
from pathlib import Path
import stat
import sys

repo = Path(sys.argv[1])
live_builder = Path(sys.argv[2])
snapshot = Path(sys.argv[3])
provider_source_lib = Path(sys.argv[4])
cargo_generation_manager = Path(sys.argv[5])
test_input = Path(sys.argv[6]) if sys.argv[6] else None
inputs = snapshot / ".h00-build-inputs"

def regular_equal(live, staged):
    if live.is_symlink() or staged.is_symlink() or not live.is_file() or not staged.is_file():
        return False
    return live.read_bytes() == staged.read_bytes()

fixed = (
    (live_builder, inputs / "build-h00ligan-portable.sh"),
    (repo / "providers/rust-analyzer/h00ligan-product.Cargo.toml.in", inputs / "h00ligan-product.Cargo.toml.in"),
    (repo / "providers/rust-analyzer/h00ligan-provider-adapter.Cargo.toml.in", inputs / "h00ligan-provider-adapter.Cargo.toml.in"),
    (repo / "providers/rust-analyzer/h00ligan_embedded_main.rs", inputs / "h00ligan_embedded_main.rs"),
    (repo / "providers/rust-analyzer/h00ligan-product.Cargo.lock", inputs / "h00ligan-product.Cargo.lock"),
    (provider_source_lib, snapshot / "rust-provider/src/lib.rs"),
    (repo / "scripts/build-h00-go-semantic-provider.sh", inputs / "build-h00-go-semantic-provider.sh"),
    (repo / "scripts/build-h00-typescript-semantic-provider.sh", inputs / "build-h00-typescript-semantic-provider.sh"),
    (repo / "scripts/build-h00-pyrefly-semantic-provider.sh", inputs / "build-h00-pyrefly-semantic-provider.sh"),
    (repo / "scripts/resolve-h00-official-go-sdk.sh", inputs / "resolve-h00-official-go-sdk.sh"),
    (repo / "scripts/publish-h00ligan-cache-directory.py", inputs / "publish-h00ligan-cache-directory.py"),
    (repo / "scripts/check-h00ligan-binary.py", inputs / "check-h00ligan-binary.py"),
    (cargo_generation_manager, inputs / "manage-h00ligan-cargo-generation.py"),
    (repo / "providers/go/gopls/h00_provider_main.go", inputs / "go-provider/gopls/h00_provider_main.go"),
    (repo / "providers/go/gopls/h00_provider_protocol.go", inputs / "go-provider/gopls/h00_provider_protocol.go"),
    (repo / "providers/go/gopls/h00_semantic_provider.go", inputs / "go-provider/gopls/h00_semantic_provider.go"),
    (repo / "providers/go/gopls/h00_scip.go", inputs / "go-provider/gopls/h00_scip.go"),
    (repo / "providers/go/scip-go/h00scip/export.go", inputs / "go-provider/scip-go/h00scip/export.go"),
    (repo / "providers/go/shared/h00provider/protocol.go", inputs / "typescript-provider/shared/h00provider/protocol.go"),
    (repo / "providers/typescript/h00_provider_main.go", inputs / "typescript-provider/typescript/h00_provider_main.go"),
    (repo / "providers/typescript/h00_provider_protocol.go", inputs / "typescript-provider/typescript/h00_provider_protocol.go"),
    (repo / "providers/typescript/h00_semantic_provider.go", inputs / "typescript-provider/typescript/h00_semantic_provider.go"),
    (repo / "providers/typescript/h00_typescript_engine.go", inputs / "typescript-provider/typescript/h00_typescript_engine.go"),
    (repo / "providers/typescript/h00_typescript_scip.go", inputs / "typescript-provider/typescript/h00_typescript_scip.go"),
    (repo / "providers/typescript/h00_typescript_engine_test.go", inputs / "typescript-provider/typescript/h00_typescript_engine_test.go"),
    (repo / "providers/typescript/h00_typescript_provider_process_test.go", inputs / "typescript-provider/typescript/h00_typescript_provider_process_test.go"),
    (repo / "providers/python/pyrefly/provider.Cargo.toml.in", inputs / "python-provider/provider.Cargo.toml.in"),
    (repo / "providers/python/pyrefly/provider.Cargo.lock", inputs / "python-provider/provider.Cargo.lock"),
    (repo / "providers/python/pyrefly/h00_pyrefly_semantic_provider.rs", inputs / "python-provider/lib.rs"),
    (repo / "providers/python/pyrefly/h00_pyrefly_semantic_provider_main.rs", inputs / "python-provider/main.rs"),
    (repo / "providers/python/pyrefly/h00_semantic.rs", inputs / "python-provider/h00_semantic.rs"),
    (repo / "providers/python/pyrefly/pyrefly-1.2.0.patch", inputs / "python-provider/pyrefly-1.2.0.patch"),
    (repo / "Cargo.toml", snapshot / "source/Cargo.toml"),
    (repo / "rust-toolchain.toml", snapshot / "source/rust-toolchain.toml"),
)
for live, staged in fixed:
    if not regular_equal(live, staged):
        raise SystemExit(f"portable product build input changed after snapshot: {live}")
if test_input is not None and not regular_equal(
    test_input, inputs / "authority-test-input"
):
    raise SystemExit("portable product build input changed after snapshot: authority-test-input")

def tree_digest(root):
    if root.is_symlink() or not root.is_dir():
        raise SystemExit(f"product source root is not a real directory: {root}")
    hasher = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode()
        mode = stat.S_IMODE(path.lstat().st_mode).to_bytes(4, "big")
        if path.is_symlink():
            raise SystemExit(f"product source input must not be a symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise SystemExit(f"unsupported product source input: {path}")
        contents = path.read_bytes()
        for value in (relative, mode, contents):
            hasher.update(len(value).to_bytes(8, "big"))
            hasher.update(value)
    return hasher.digest()

source_manifest = inputs / "h00ligan-product-source-inputs"
if source_manifest.is_symlink() or not source_manifest.is_file():
    raise SystemExit("portable product source-input manifest is missing or unsafe")
source_inputs = source_manifest.read_text(encoding="utf-8").splitlines()
if not source_inputs or source_inputs != sorted(set(source_inputs)):
    raise SystemExit("portable product source-input manifest is empty, duplicated, or unsorted")
for relative in source_inputs:
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise SystemExit(f"unsafe portable product source-input path: {relative}")
    live = repo / relative_path
    staged = snapshot / "source" / relative_path
    if live.is_dir() and staged.is_dir():
        equal = tree_digest(live) == tree_digest(staged)
    else:
        equal = regular_equal(live, staged)
    if not equal:
        raise SystemExit(f"portable product source input changed after snapshot: {relative}")
PY
    local current_state current_revision current_dirty
    current_state="$(measure_live_source_state)"
    current_revision="$(printf '%s\n' "$current_state" | sed -n '1p')"
    current_dirty="$(printf '%s\n' "$current_state" | sed -n '2p')"
    [[ "$current_revision" == "$source_revision" && "$current_dirty" == "$source_dirty" ]] || {
        echo "h00ligan source state changed after snapshot" >&2
        return 1
    }
}

product_workspace_authority=(
    "$provider_source_key"
    "$provider_patch_sha256"
    "$provider_builder_sha256"
    "$product_builder_sha256"
    "$source_revision"
    "$source_dirty"
    "$authority_test"
)

authority_test_barrier "${H00LIGAN_BUILD_TEST_BARRIER:-}"
verify_provider_source
verify_python_provider_source
verify_live_product_inputs "$product_candidate"
product_measurement="$(verify_product_workspace "$product_candidate" "" measure \
    "${product_workspace_authority[@]}")"
product_source_key="$(printf '%s\n' "$product_measurement" | python3 -c 'import json,sys; print(json.load(sys.stdin)["source_key"])')"
[[ "$product_source_key" =~ ^[0-9a-f]{64}$ ]] || {
    echo "h00ligan product-source identity is invalid" >&2
    exit 1
}
product_root="$portable_cache_root/product-source-$product_source_key"
[[ ! -L "$product_root" ]] || {
    echo "h00ligan product-source cache path must not be a symlink: $product_root" >&2
    exit 1
}

if [[ ! -e "$product_root" ]]; then
    if ! mkdir "$product_root.lock"; then
        echo "h00ligan product-source preparation is already active: $product_root.lock" >&2
        exit 1
    fi
    product_lock="$product_root.lock"
    verify_live_product_inputs "$product_candidate"
    verify_product_workspace "$product_candidate" "$product_source_key" create \
        "${product_workspace_authority[@]}"
    mv "$product_candidate" "$product_root"
    product_candidate=""
    lock_to_release="$product_lock"
    product_lock=""
    rmdir "$lock_to_release"
elif [[ ! -d "$product_root" ]]; then
    echo "h00ligan product-source cache path is not a directory: $product_root" >&2
    exit 1
else
    rm -rf -- "$product_candidate"
    product_candidate=""
fi

verify_product_workspace "$product_root" "$product_source_key" verify \
    "${product_workspace_authority[@]}"
product_crate_root="$product_root/product"
product_manifest="$product_crate_root/Cargo.toml"
binary_checker="$product_root/.h00-build-inputs/check-h00ligan-binary.py"
provider_adapter_root="$product_root/rust-provider"
resolved_provider_source="$(python3 -c 'import os,sys; print(os.path.realpath(os.path.join(sys.argv[1], sys.argv[2])))' "$provider_adapter_root" "$provider_source_relative")"
[[ "$resolved_provider_source" == "$provider_source_root" ]] || {
    echo "product provider adapter does not resolve to its receipted source" >&2
    exit 1
}
if ((prepare_only)); then
    if ((machine_output)); then
        printf 'H00LIGAN_PRODUCT_ROOT=%s\n' "$product_root"
        printf 'H00LIGAN_PRODUCT_MANIFEST=%s\n' "$product_manifest"
        printf 'H00LIGAN_PRODUCT_LOCKFILE=%s\n' "$product_crate_root/Cargo.lock"
        printf 'H00LIGAN_PRODUCT_SOURCE_RECEIPT=%s\n' "$product_root/.h00-h00ligan-product-source.json"
        printf 'H00LIGAN_PRODUCT_SOURCE_KEY=%s\n' "$product_source_key"
        printf 'H00LIGAN_PRODUCT_BUILDER_SHA256=%s\n' "$product_builder_sha256"
        printf 'H00_RA_SOURCE_ROOT=%s\n' "$provider_source_root"
        printf 'H00_RA_SOURCE_KEY=%s\n' "$provider_source_key"
        printf 'H00_RA_PATCH_SHA256=%s\n' "$provider_patch_sha256"
        printf 'H00_RA_BUILDER_SHA256=%s\n' "$provider_builder_sha256"
        printf 'H00_PYREFLY_SOURCE_ROOT=%s\n' "$python_provider_source_root"
        printf 'H00_PYREFLY_SOURCE_KEY=%s\n' "$python_provider_source_key"
        printf 'H00_PYREFLY_PATCH_SHA256=%s\n' "$python_provider_patch_sha256"
        printf 'H00_PYREFLY_BUILDER_SHA256=%s\n' "$python_provider_builder_sha256"
        printf 'H00_PYREFLY_ARCHIVE_SHA256=%s\n' "$python_provider_archive_sha256"
        printf 'H00_PYREFLY_SOURCE_TREE_SHA256=%s\n' "$python_provider_source_tree_sha256"
        printf 'H00_PYREFLY_CACHE_PUBLISHER_SHA256=%s\n' "$python_provider_cache_publisher_sha256"
        printf 'H00_PYREFLY_PROVIDER_BINARY=%s\n' "$python_provider_binary"
        printf 'H00_PYREFLY_PROVIDER_RECEIPT=%s\n' "$python_provider_receipt"
        printf 'H00_PYREFLY_PROVIDER_BINARY_SHA256=%s\n' "$python_provider_binary_sha256"
        printf 'H00_GO_PROVIDER_BINARY=%s\n' "$go_provider_binary"
        printf 'H00_GO_PROVIDER_RECEIPT=%s\n' "$go_provider_receipt"
        printf 'H00_GO_PROVIDER_BINARY_SHA256=%s\n' "$go_provider_binary_sha256"
        printf 'H00_GO_PROVIDER_PATCH_SHA256=%s\n' "$go_provider_patch_sha256"
        printf 'H00_GO_PROVIDER_SOURCE_TREE_SHA256=%s\n' "$go_provider_source_tree_sha256"
        printf 'H00_GO_PROVIDER_BUILDER_SHA256=%s\n' "$go_provider_builder_sha256"
        printf 'H00_GO_PROVIDER_CACHE_PUBLISHER_SHA256=%s\n' "$go_provider_cache_publisher_sha256"
        printf 'H00_TYPESCRIPT_PROVIDER_BINARY=%s\n' "$typescript_provider_binary"
        printf 'H00_TYPESCRIPT_PROVIDER_RECEIPT=%s\n' "$typescript_provider_receipt"
        printf 'H00_TYPESCRIPT_PROVIDER_BINARY_SHA256=%s\n' "$typescript_provider_binary_sha256"
        printf 'H00_TYPESCRIPT_PROVIDER_PATCH_SHA256=%s\n' "$typescript_provider_patch_sha256"
        printf 'H00_TYPESCRIPT_PROVIDER_TEST_SHA256=%s\n' "$typescript_provider_test_sha256"
        printf 'H00_TYPESCRIPT_PROVIDER_SOURCE_TREE_SHA256=%s\n' "$typescript_provider_source_tree_sha256"
        printf 'H00_TYPESCRIPT_PROVIDER_BUILDER_SHA256=%s\n' "$typescript_provider_builder_sha256"
        printf 'H00_TYPESCRIPT_PROVIDER_CACHE_PUBLISHER_SHA256=%s\n' "$typescript_provider_cache_publisher_sha256"
    else
        printf '%s\n' "$product_manifest"
    fi
    exit 0
fi
export H00_RA_PATCH_SHA256="$provider_patch_sha256"
export H00_PYREFLY_PATCH_SHA256="$python_provider_patch_sha256"
export H00_PYREFLY_PROVIDER_BINARY="$python_provider_binary"
export H00_PYREFLY_PROVIDER_BINARY_SHA256="$python_provider_binary_sha256"
export H00_GO_PROVIDER_BINARY="$go_provider_binary"
export H00_GO_PROVIDER_BINARY_SHA256="$go_provider_binary_sha256"
export H00_GO_PROVIDER_PATCH_SHA256="$go_provider_patch_sha256"
export H00_TYPESCRIPT_PROVIDER_BINARY="$typescript_provider_binary"
export H00_TYPESCRIPT_PROVIDER_BINARY_SHA256="$typescript_provider_binary_sha256"
export H00_TYPESCRIPT_PROVIDER_PATCH_SHA256="$typescript_provider_patch_sha256"
export H00_BUILD_SOURCE_REVISION="$source_revision"
export H00_BUILD_SOURCE_DIRTY="$source_dirty"
export RUSTFLAGS="$portable_rustflags --remap-path-prefix=$portable_cache_root=portable-product-cache --remap-path-prefix=$provider_source_root=rust-provider-source"

rustc_identity="$(rustup run "$toolchain" rustc -vV)"
cargo_identity="$(rustup run "$toolchain" cargo --version --verbose)"
linker_identity=""
case "$target_os" in
    Linux)
        command -v cargo-zigbuild >/dev/null 2>&1 || {
            echo "cargo-zigbuild is required for static Linux artifacts" >&2
            exit 1
        }
        command -v zig >/dev/null 2>&1 || { echo "zig is required" >&2; exit 1; }
        [[ "$(cargo-zigbuild --version)" == "cargo-zigbuild 0.23.0" ]] || {
            echo "expected cargo-zigbuild 0.23.0" >&2
            exit 1
        }
        [[ "$(zig version)" == "0.16.0" ]] || {
            echo "expected Zig 0.16.0" >&2
            exit 1
        }
        command -v readelf >/dev/null 2>&1 || { echo "readelf is required" >&2; exit 1; }
        linker_identity="$(cargo-zigbuild --version); zig $(zig version)"
        export CARGO_ZIGBUILD_CACHE_DIR="$portable_cache_root/cargo-zigbuild"
        export ZIG_GLOBAL_CACHE_DIR="$portable_cache_root/zig-global"
        export ZIG_LOCAL_CACHE_DIR="$portable_cache_root/zig-local/$target"
        ;;
    Darwin)
        case "$target" in
            x86_64-apple-darwin)
                export MACOSX_DEPLOYMENT_TARGET=10.12
                ;;
            aarch64-apple-darwin)
                export MACOSX_DEPLOYMENT_TARGET=11.0
                ;;
        esac
        export CFLAGS="$CFLAGS -mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
        export CXXFLAGS="$CXXFLAGS -mmacosx-version-min=$MACOSX_DEPLOYMENT_TARGET"
        command -v xcrun >/dev/null 2>&1 || { echo "xcrun is required for native macOS artifacts" >&2; exit 1; }
        linker_identity="$(cc --version | head -n 1); macOS SDK $(xcrun --show-sdk-version)"
        ;;
esac

product_source_receipt="$product_root/.h00-h00ligan-product-source.json"
product_source_receipt_sha256="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$product_source_receipt")"
product_source_tree_sha256="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["tree_sha256"])' "$product_source_receipt")"
product_lock_sha256="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["product_lock_sha256"])' "$product_source_receipt")"
python_provider_receipt_sha256="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$python_provider_receipt")"
go_provider_receipt_sha256="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$go_provider_receipt")"
typescript_provider_receipt_sha256="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$typescript_provider_receipt")"
artifact_build_key="$(python3 - \
    "$target" "$product_source_key" "$product_source_tree_sha256" \
    "$product_source_receipt_sha256" "$product_lock_sha256" \
    "$provider_source_key" "$provider_patch_sha256" "$provider_builder_sha256" \
    "$python_provider_binary_sha256" "$python_provider_patch_sha256" \
    "$python_provider_source_key" "$python_provider_source_tree_sha256" \
    "$python_provider_builder_sha256" "$python_provider_archive_sha256" \
    "$python_provider_cache_publisher_sha256" "$python_provider_receipt_sha256" \
    "$go_provider_binary_sha256" "$go_provider_patch_sha256" \
    "$go_provider_source_tree_sha256" "$go_provider_builder_sha256" \
    "$go_provider_receipt_sha256" \
    "$typescript_provider_binary_sha256" "$typescript_provider_patch_sha256" \
    "$typescript_provider_test_sha256" "$typescript_provider_source_tree_sha256" \
    "$typescript_provider_builder_sha256" "$typescript_provider_receipt_sha256" \
    "$product_builder_sha256" "$rustc_identity" "$cargo_identity" "$linker_identity" \
    "$RUSTFLAGS" "$CFLAGS" "$CXXFLAGS" <<'PY'
import hashlib
import struct
import sys

hasher = hashlib.sha256()
for value in (b"h00/h00ligan-portable-artifact-key/v3", *(value.encode() for value in sys.argv[1:])):
    hasher.update(struct.pack(">Q", len(value)))
    hasher.update(value)
print(hasher.hexdigest())
PY
)"
[[ "$artifact_build_key" =~ ^[0-9a-f]{64}$ ]] || {
    echo "portable artifact build identity is invalid" >&2
    exit 1
}
artifact_parent="$portable_cache_root/artifacts/$target"
artifact_root="$artifact_parent/$artifact_build_key"
artifact_binary="$artifact_root/h00ligan"
artifact_receipt="$artifact_root/h00ligan.build.json"
cargo_generation_manager="$product_root/.h00-build-inputs/manage-h00ligan-cargo-generation.py"
cargo_generation_receipt="$portable_workspace_parent/$target.cargo-generation.json"
mkdir -p "$artifact_parent" "$portable_cache_root/build-locks"
[[ ! -L "$artifact_parent" && ! -L "$artifact_root" ]] || {
    echo "portable artifact cache path must not be a symlink" >&2
    exit 1
}

acquire_target_build_lock() {
    local candidate_lock="$portable_cache_root/build-locks/$target.lock"
    local deadline=$((SECONDS + ${H00LIGAN_BUILD_LOCK_TIMEOUT_SECONDS:-900}))
    local contention_reported=0
    while ! mkdir "$candidate_lock" 2>/dev/null; do
        # One lstat distinguishes an invalid entry from a legitimate release
        # between failed acquisition and inspection. A waiter owns no cleanup.
        if ! python3 - "$candidate_lock" <<'PY'
import os
import stat
import sys

try:
    mode = os.lstat(sys.argv[1]).st_mode
except FileNotFoundError:
    pass
else:
    if not stat.S_ISDIR(mode):
        raise SystemExit("portable target-build lock is invalid: " + sys.argv[1])
PY
        then
            return 1
        fi
        if [[ "$authority_test" == 1 && "$contention_reported" == 0 && -n "${H00LIGAN_BUILD_TEST_CAPTURE_BARRIER:-}" ]]; then
            local contention_path="$H00LIGAN_BUILD_TEST_CAPTURE_BARRIER"
            [[ "$contention_path" == "$test_root"/* && -d "$(dirname "$contention_path")" && ! -L "$(dirname "$contention_path")" ]] || {
                echo "build-authority contention receipt must be inside the test root" >&2
                return 1
            }
            (umask 077; printf '%s\n' "$BASHPID" > "$contention_path.contended")
            contention_reported=1
        fi
        if ((SECONDS >= deadline)); then
            echo "timed out waiting for portable target-build lock: $candidate_lock" >&2
            return 1
        fi
        sleep 0.1
    done
    build_lock="$candidate_lock"
}

forbidden_path_args=(--forbid-path "$repo_root" --forbid-path "$HOME")
case "$repo_root" in
    "$HOME"/*)
        # Catch a broad-prefix remap that merely drops HOME while retaining the
        # machine-specific repository suffix (the defect this guard was added
        # for).
        forbidden_path_args+=(--forbid-path "${repo_root#"$HOME"/}")
        ;;
esac
receipt_test_args=()
if [[ "$authority_test" == 1 ]]; then
    receipt_test_args+=(--allow-authority-test-receipt)
fi
if [[ -n "${DEVBOX_PACKAGES_DIR:-}" ]]; then
    forbidden_path_args+=(--forbid-path "$DEVBOX_PACKAGES_DIR")
fi

providers_verified_after_build=0
if [[ ! -e "$artifact_root" ]]; then
    acquire_target_build_lock
    if [[ ! -e "$artifact_root" ]]; then
        product_build_root="$portable_workspace_parent/$target"
        built_binary="$portable_target_dir/$target/release/h00ligan"
        [[ ! -L "$product_build_root" ]] || {
            echo "portable build workspace must not be a symlink: $product_build_root" >&2
            exit 1
        }
        [[ ! -L "$cargo_generation_receipt" ]] || {
            echo "Cargo generation receipt must not be a symlink: $cargo_generation_receipt" >&2
            exit 1
        }
        product_build_candidate="$(mktemp -d "$portable_workspace_parent/.${target}.XXXXXX")"
        cp -a -- "$product_root/." "$product_build_candidate/"
        if [[ -e "$product_build_root" ]]; then
            [[ -d "$product_build_root" && ! -L "$product_build_root" ]] || {
                echo "portable build workspace is not an owned real directory: $product_build_root" >&2
                exit 1
            }
        fi
        python3 "$cargo_generation_manager" prepare \
            --candidate "$product_build_candidate" \
            --previous "$product_build_root" \
            --receipt "$cargo_generation_receipt" \
            --target "$target" \
            --build-key "$artifact_build_key" \
            --source-key "$product_source_key" \
            --mutable-binary "$built_binary" \
            --freshness-root "$portable_target_dir/release" \
            --freshness-root "$portable_target_dir/$target/release"
        verify_product_workspace "$product_build_candidate" "$product_source_key" verify \
            "${product_workspace_authority[@]}"
        if [[ -e "$product_build_root" ]]; then
            rm -rf -- "$product_build_root"
        fi
        mv -- "$product_build_candidate" "$product_build_root"
        product_build_candidate=""
        product_build_manifest="$product_build_root/product/Cargo.toml"
        [[ -f "$product_build_manifest" && ! -L "$product_build_manifest" ]] || {
            echo "portable build workspace has no regular product manifest" >&2
            exit 1
        }
        resolved_build_provider_source="$(python3 -c 'import os,sys; print(os.path.realpath(os.path.join(sys.argv[1], sys.argv[2])))' "$product_build_root/rust-provider" "$provider_source_relative")"
        [[ "$resolved_build_provider_source" == "$provider_source_root" ]] || {
            echo "stable product workspace does not resolve to its receipted provider source" >&2
            exit 1
        }
        mkdir -p "$(dirname "$built_binary")"
        if [[ "$authority_test" == 1 ]]; then
            install -m 0755 "$test_binary" "$built_binary"
        else
            case "$target_os" in
                Linux)
                    echo "Building static h00ligan for $target ..." >&2
                    cargo "+$toolchain" zigbuild \
                        --locked --offline --release \
                        --manifest-path "$product_build_manifest" --bin h00ligan \
                        --target "$target" >&2
                    ;;
                Darwin)
                    echo "Building native h00ligan for $target ..." >&2
                    cargo "+$toolchain" build \
                        --locked --offline --release \
                        --manifest-path "$product_build_manifest" --bin h00ligan \
                        --target "$target" >&2
                    ;;
            esac
        fi
        authority_test_barrier "${H00LIGAN_BUILD_TEST_CAPTURE_BARRIER:-}"

        # Cargo may write only to the external target/cache directories. The
        # source and live inputs must still equal the snapshot before bytes are
        # admitted into the immutable artifact cache.
        verify_provider_source
        verify_python_provider_source
        providers_verified_after_build=1
        verify_product_workspace "$product_build_root" "$product_source_key" verify \
            "${product_workspace_authority[@]}"
        verify_product_workspace "$product_root" "$product_source_key" verify \
            "${product_workspace_authority[@]}"
        verify_live_product_inputs "$product_root"

        [[ -x "$built_binary" ]] || { echo "portable h00ligan binary was not produced" >&2; exit 1; }
        for forbidden_companion in \
            "$portable_target_dir/$target/release/h00ligan-ra-provider" \
            "$portable_target_dir/$target/release/h00ligan-ra-provider.build.json" \
            "$portable_target_dir/$target/release/h00-pyrefly-semantic-provider" \
            "$portable_target_dir/$target/release/h00-pyrefly-semantic-provider.build.json"; do
            if [[ -L "$forbidden_companion" || ( -e "$forbidden_companion" && ! -f "$forbidden_companion" ) ]]; then
                echo "refusing to remove unexpected companion product path: $forbidden_companion" >&2
                exit 1
            fi
            rm -f -- "$forbidden_companion"
        done

        artifact_candidate="$(mktemp -d "$artifact_parent/artifact.XXXXXX")"
        install -m 0755 "$built_binary" "$artifact_candidate/h00ligan"
        python3 - \
            "$artifact_candidate/h00ligan" "$artifact_candidate/h00ligan.build.json" \
            "$artifact_build_key" "$target" "$product_source_key" \
            "$product_source_tree_sha256" "$product_source_receipt_sha256" \
            "$product_lock_sha256" "$provider_source_key" "$provider_patch_sha256" \
            "$provider_builder_sha256" "$python_provider_binary_sha256" \
            "$python_provider_patch_sha256" "$python_provider_source_key" \
            "$python_provider_source_tree_sha256" "$python_provider_builder_sha256" \
            "$python_provider_archive_sha256" "$python_provider_cache_publisher_sha256" \
            "$python_provider_receipt_sha256" "$go_provider_binary_sha256" \
            "$go_provider_patch_sha256" "$go_provider_source_tree_sha256" \
            "$go_provider_builder_sha256" "$go_provider_receipt_sha256" \
            "$typescript_provider_binary_sha256" "$typescript_provider_patch_sha256" \
            "$typescript_provider_test_sha256" "$typescript_provider_source_tree_sha256" \
            "$typescript_provider_builder_sha256" "$typescript_provider_receipt_sha256" \
            "$product_builder_sha256" "$rustc_identity" \
            "$cargo_identity" "$linker_identity" "$RUSTFLAGS" "$CFLAGS" "$CXXFLAGS" \
            "$authority_test" <<'PY'
import hashlib
import json
import os
import sys

(
    binary, receipt, build_key, target, product_source_key,
    product_source_tree_sha256, product_source_receipt_sha256,
    product_lock_sha256, provider_source_key, provider_patch_sha256,
    provider_builder_sha256, python_provider_binary_sha256,
    python_provider_patch_sha256, python_provider_source_key,
    python_provider_source_tree_sha256, python_provider_builder_sha256,
    python_provider_archive_sha256, python_provider_cache_publisher_sha256,
    python_provider_receipt_sha256, go_provider_binary_sha256,
    go_provider_patch_sha256, go_provider_source_tree_sha256,
    go_provider_builder_sha256, go_provider_receipt_sha256,
    typescript_provider_binary_sha256, typescript_provider_patch_sha256,
    typescript_provider_test_sha256, typescript_provider_source_tree_sha256,
    typescript_provider_builder_sha256, typescript_provider_receipt_sha256,
    product_builder_sha256, rustc, cargo, linker,
    rustflags, cflags, cxxflags, authority_test,
) = sys.argv[1:]
with open(binary, "rb") as handle:
    binary_sha256 = hashlib.sha256(handle.read()).hexdigest()
payload = {
    "schema": "h00/h00ligan-portable-artifact/v3",
    "build_key": build_key,
    "target": target,
    "product_source_key": product_source_key,
    "product_source_tree_sha256": product_source_tree_sha256,
    "product_source_receipt_sha256": product_source_receipt_sha256,
    "product_lock_sha256": product_lock_sha256,
    "provider_source_key": provider_source_key,
    "provider_patch_sha256": provider_patch_sha256,
    "provider_builder_sha256": provider_builder_sha256,
    "python_provider_binary_sha256": python_provider_binary_sha256,
    "python_provider_patch_sha256": python_provider_patch_sha256,
    "python_provider_source_key": python_provider_source_key,
    "python_provider_source_tree_sha256": python_provider_source_tree_sha256,
    "python_provider_builder_sha256": python_provider_builder_sha256,
    "python_provider_archive_sha256": python_provider_archive_sha256,
    "python_provider_cache_publisher_sha256": python_provider_cache_publisher_sha256,
    "python_provider_receipt_sha256": python_provider_receipt_sha256,
    "go_provider_binary_sha256": go_provider_binary_sha256,
    "go_provider_patch_sha256": go_provider_patch_sha256,
    "go_provider_source_tree_sha256": go_provider_source_tree_sha256,
    "go_provider_builder_sha256": go_provider_builder_sha256,
    "go_provider_receipt_sha256": go_provider_receipt_sha256,
    "typescript_provider_binary_sha256": typescript_provider_binary_sha256,
    "typescript_provider_patch_sha256": typescript_provider_patch_sha256,
    "typescript_provider_test_sha256": typescript_provider_test_sha256,
    "typescript_provider_source_tree_sha256": typescript_provider_source_tree_sha256,
    "typescript_provider_builder_sha256": typescript_provider_builder_sha256,
    "typescript_provider_receipt_sha256": typescript_provider_receipt_sha256,
    "product_builder_sha256": product_builder_sha256,
    "rustc": rustc,
    "cargo": cargo,
    "linker": linker,
    "rustflags": rustflags,
    "cflags": cflags,
    "cxxflags": cxxflags,
    "binary_sha256": binary_sha256,
    "binary_size": os.path.getsize(binary),
}
if authority_test == "1":
    payload["authority_test"] = True
with open(receipt, "x", encoding="utf-8") as output:
    json.dump(payload, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
PY
        python3 "$binary_checker" \
            --binary "$artifact_candidate/h00ligan" \
            --target "$target" \
            --receipt "$artifact_candidate/h00ligan.build.json" \
            --source-receipt "$product_source_receipt" \
            "${forbidden_path_args[@]}" \
            "${receipt_test_args[@]}" \
            --quiet
        mv "$artifact_candidate" "$artifact_root"
        artifact_candidate=""
        python3 "$cargo_generation_manager" record \
            --receipt "$cargo_generation_receipt" \
            --target "$target" \
            --build-key "$artifact_build_key" \
            --source-key "$product_source_key" \
            --binary "$artifact_binary"
    fi
    lock_to_release="$build_lock"
    build_lock=""
    rmdir "$lock_to_release"
elif [[ ! -d "$artifact_root" ]]; then
    echo "portable artifact cache path is not a directory: $artifact_root" >&2
    exit 1
fi

if ((providers_verified_after_build == 0)); then
    verify_provider_source
    verify_python_provider_source
fi
python3 "$binary_checker" \
    --binary "$artifact_binary" \
    --target "$target" \
    --receipt "$artifact_receipt" \
    --source-receipt "$product_source_receipt" \
    "${forbidden_path_args[@]}" \
    "${receipt_test_args[@]}" \
    --quiet

binary="$artifact_binary"
receipt="$artifact_receipt"
output="$binary"
if ((install_binary)); then
    destination="$(python3 -c 'import os, sys; print(os.path.abspath(os.path.expanduser(sys.argv[1])))' "$destination")"
    mkdir -p "$(dirname "$destination")"
    install_temp="$(mktemp "${destination}.tmp.XXXXXX")"
    install -m 0755 "$binary" "$install_temp"
    mv -f "$install_temp" "$destination"
    install_temp=""
    python3 "$binary_checker" \
        --binary "$destination" \
        --target "$target" \
        --receipt "$receipt" \
        --source-receipt "$product_source_receipt" \
        "${forbidden_path_args[@]}" \
        "${receipt_test_args[@]}" \
        --quiet
    cmp -s "$binary" "$destination"
    "$destination" --version >&2
    echo "Installed portable h00ligan at $destination" >&2
    output="$destination"
fi

if ((machine_output)); then
    printf 'H00LIGAN_BINARY=%s\n' "$output"
    printf 'H00LIGAN_RECEIPT=%s\n' "$receipt"
    printf 'H00LIGAN_PRODUCT_SOURCE_RECEIPT=%s\n' "$product_source_receipt"
    printf 'H00LIGAN_PRODUCT_SOURCE_KEY=%s\n' "$product_source_key"
    printf 'H00LIGAN_ARTIFACT_BUILD_KEY=%s\n' "$artifact_build_key"
    printf 'H00LIGAN_TARGET=%s\n' "$target"
    printf 'H00_RA_SOURCE_ROOT=%s\n' "$provider_source_root"
    printf 'H00_RA_SOURCE_KEY=%s\n' "$provider_source_key"
    printf 'H00_RA_PATCH_SHA256=%s\n' "$provider_patch_sha256"
    printf 'H00_RA_BUILDER_SHA256=%s\n' "$provider_builder_sha256"
    printf 'H00_PYREFLY_PROVIDER_BINARY=%s\n' "$python_provider_binary"
    printf 'H00_PYREFLY_PROVIDER_RECEIPT=%s\n' "$python_provider_receipt"
    printf 'H00_PYREFLY_PROVIDER_BINARY_SHA256=%s\n' "$python_provider_binary_sha256"
    printf 'H00_PYREFLY_SOURCE_ROOT=%s\n' "$python_provider_source_root"
    printf 'H00_PYREFLY_SOURCE_KEY=%s\n' "$python_provider_source_key"
    printf 'H00_PYREFLY_PATCH_SHA256=%s\n' "$python_provider_patch_sha256"
    printf 'H00_PYREFLY_BUILDER_SHA256=%s\n' "$python_provider_builder_sha256"
    printf 'H00_PYREFLY_ARCHIVE_SHA256=%s\n' "$python_provider_archive_sha256"
    printf 'H00_PYREFLY_SOURCE_TREE_SHA256=%s\n' "$python_provider_source_tree_sha256"
    printf 'H00_PYREFLY_CACHE_PUBLISHER_SHA256=%s\n' "$python_provider_cache_publisher_sha256"
    printf 'H00_GO_PROVIDER_BINARY_SHA256=%s\n' "$go_provider_binary_sha256"
    printf 'H00_GO_PROVIDER_PATCH_SHA256=%s\n' "$go_provider_patch_sha256"
    printf 'H00_TYPESCRIPT_PROVIDER_BINARY_SHA256=%s\n' "$typescript_provider_binary_sha256"
    printf 'H00_TYPESCRIPT_PROVIDER_PATCH_SHA256=%s\n' "$typescript_provider_patch_sha256"
else
    printf '%s\n' "$output"
fi
