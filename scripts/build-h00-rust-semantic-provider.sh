#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${H00_RA_BUILDER_INVOCATION_ROOT:-}" ]]; then
    live_script="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${BASH_SOURCE[0]}")"
    live_script_dir="$(cd -- "$(dirname "$live_script")" && pwd)"
    live_repo_root="$(cd -- "$live_script_dir/.." && pwd)"
    invocation_parent="$live_repo_root/target/semantic-provider/invocations"
    [[ ! -L "$live_repo_root/target" && ! -L "$live_repo_root/target/semantic-provider" ]] || {
        echo "semantic-provider build cache roots must not be symlinks" >&2
        exit 1
    }
    mkdir -p "$invocation_parent"
    invocation_root="$(mktemp -d "$invocation_parent/invocation.XXXXXX")"
    install -m 0755 "$live_script" "$invocation_root/build-provider.sh"
    export H00_RA_BUILDER_INVOCATION_ROOT="$invocation_root"
    export H00_RA_BUILDER_LIVE_SCRIPT="$live_script"
    export H00_RA_BUILDER_REPO_ROOT="$live_repo_root"
    exec "$invocation_root/build-provider.sh" "$@"
fi

invocation_root="$H00_RA_BUILDER_INVOCATION_ROOT"
repo_root="$H00_RA_BUILDER_REPO_ROOT"
provider_builder_live="$H00_RA_BUILDER_LIVE_SCRIPT"
provider_builder="$invocation_root/build-provider.sh"
[[ ! -L "$invocation_root" && -d "$invocation_root" ]] || {
    echo "semantic-provider builder invocation root is invalid" >&2
    exit 1
}
[[ "$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${BASH_SOURCE[0]}")" == "$provider_builder" ]] || {
    echo "semantic-provider builder is not executing its private snapshot" >&2
    exit 1
}

rust_version="1.97.1"
rust_commit="8bab26f4f68e0e26f0bb7960be334d5b520ea452"
rust_source="${H00_RUST_SOURCE_DIR:-}"
rust_source_from_cli=0
prepared_source_cache=""
requested_target=""
requested_output=""
machine_output=0
prepare_only=0

usage() {
    cat >&2 <<'USAGE'
Usage: scripts/build-h00-rust-semantic-provider.sh [SOURCE] [OPTIONS]

Build h00ligan's process-isolated rust-analyzer semantic provider from the exact
Rust 1.97.1 source commit without mutating the supplied checkout.

Options:
  --rust-source PATH           Git repository containing the exact Rust source commit
  --prepared-source-cache PATH Receipt-verified prepared source-cache root
  --target TARGET     Rust target triple (defaults to the pinned compiler host)
  --output PATH       Final binary path under target/ by default
  --prepare-only      Verify or prepare the exact patched source, then stop
  --machine           Print stable KEY=VALUE receipt paths
  -h, --help          Show this help

H00_RUST_SOURCE_DIR may supply --rust-source. A source checkout is required
only when the exact verified source cache does not already exist. Dependency
resolution is always locked and offline.
USAGE
}

while (($#)); do
    case "$1" in
        --rust-source)
            (($# >= 2)) || { usage; exit 2; }
            rust_source="$2"
            rust_source_from_cli=1
            shift 2
            ;;
        --prepared-source-cache)
            (($# >= 2)) || { usage; exit 2; }
            prepared_source_cache="$2"
            shift 2
            ;;
        --target)
            (($# >= 2)) || { usage; exit 2; }
            requested_target="$2"
            shift 2
            ;;
        --output)
            (($# >= 2)) || { usage; exit 2; }
            requested_output="$2"
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

if [[ -n "$prepared_source_cache" ]]; then
    [[ "$rust_source_from_cli" == 0 ]] || {
        echo "--rust-source and --prepared-source-cache are mutually exclusive" >&2
        exit 2
    }
    rust_source=""
    [[ -d "$prepared_source_cache" && ! -L "$prepared_source_cache" ]] || {
        echo "prepared semantic-provider source cache must be a real directory" >&2
        exit 1
    }
    prepared_source_cache="$(cd -- "$prepared_source_cache" && pwd)"
fi

command -v rustup >/dev/null 2>&1 || { echo "rustup is required" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

authority_test="${H00_RA_BUILD_AUTHORITY_TEST:-0}"
[[ "$authority_test" == 0 || "$authority_test" == 1 ]] || {
    echo "H00_RA_BUILD_AUTHORITY_TEST must be 0 or 1" >&2
    exit 1
}
if [[ "$authority_test" == 1 ]]; then
    authority_test_root="${H00_RA_BUILD_TEST_ROOT:-}"
    [[ -n "$authority_test_root" && -d "$authority_test_root" && ! -L "$authority_test_root" ]] || {
        echo "provider build-authority tests require a real caller-selected temporary root" >&2
        exit 1
    }
    authority_test_root="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$authority_test_root")"
    [[ "$repo_root" == "$authority_test_root"/* && -d "$repo_root" && ! -L "$repo_root" ]] || {
        echo "provider build-authority copied repository escapes its temporary root" >&2
        exit 1
    }
    authority_test_input="${H00_RA_BUILD_TEST_INPUT:-}"
    authority_test_barrier="${H00_RA_BUILD_TEST_BARRIER:-}"
    [[ "$authority_test_input" == "$repo_root"/* && -f "$authority_test_input" && ! -L "$authority_test_input" ]] || {
        echo "provider build-authority test input must be a regular file in the copied repository" >&2
        exit 1
    }
    [[ "$authority_test_barrier" == "$repo_root"/* && -d "$(dirname "$authority_test_barrier")" && ! -L "$(dirname "$authority_test_barrier")" ]] || {
        echo "provider build-authority barrier must be inside the copied repository" >&2
        exit 1
    }
else
    [[ -z "${H00_RA_BUILD_TEST_ROOT:-}${H00_RA_BUILD_TEST_INPUT:-}${H00_RA_BUILD_TEST_BARRIER:-}" ]] || {
        echo "provider build test controls require H00_RA_BUILD_AUTHORITY_TEST=1" >&2
        exit 1
    }
fi

if [[ -n "${RUSTFLAGS:-}" || -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]]; then
    echo "refusing inherited Rust flags in the semantic-provider build" >&2
    exit 1
fi

rustc_version="$(rustup run "$rust_version" rustc --version)"
[[ "$rustc_version" == "rustc 1.97.1 (8bab26f4f 2026-07-14)" ]] || {
    echo "unexpected compiler identity: $rustc_version" >&2
    exit 1
}
host_target="$(rustup run "$rust_version" rustc -vV | sed -n 's/^host: //p')"
target="${requested_target:-$host_target}"
rustup target list --toolchain "$rust_version" --installed | grep -Fxq "$target" || {
    echo "Rust $rust_version target is not installed: $target" >&2
    exit 1
}

patch_live="$repo_root/providers/rust-analyzer/rust-analyzer-1.97.1.patch"
protocol_manifest_live="$repo_root/providers/rust-analyzer/protocol-provider.Cargo.toml"
sidecar_manifest_live="$repo_root/providers/rust-analyzer/sidecar.Cargo.toml"
protocol_source_live="$repo_root/crates/h00ligan-provider-protocol/src/lib.rs"
sidecar_source_live="$repo_root/providers/rust-analyzer/h00ligan_ra_provider.rs"
sidecar_main_live="$repo_root/providers/rust-analyzer/h00ligan_ra_provider_main.rs"
for required in "$provider_builder_live" "$patch_live" "$protocol_manifest_live" "$sidecar_manifest_live" "$protocol_source_live" "$sidecar_source_live" "$sidecar_main_live"; do
    [[ -f "$required" ]] || { echo "missing provider build input: $required" >&2; exit 1; }
    [[ ! -L "$required" ]] || { echo "provider build input must not be a symlink: $required" >&2; exit 1; }
done

input_root="$invocation_root/inputs"
mkdir -p "$input_root"
patch="$input_root/rust-analyzer-1.97.1.patch"
protocol_manifest="$input_root/protocol-provider.Cargo.toml"
sidecar_manifest="$input_root/sidecar.Cargo.toml"
protocol_source="$input_root/protocol-lib.rs"
sidecar_source="$input_root/h00ligan_ra_provider.rs"
sidecar_main="$input_root/h00ligan_ra_provider_main.rs"
install -m 0644 "$patch_live" "$patch"
install -m 0644 "$protocol_manifest_live" "$protocol_manifest"
install -m 0644 "$sidecar_manifest_live" "$sidecar_manifest"
install -m 0644 "$protocol_source_live" "$protocol_source"
install -m 0644 "$sidecar_source_live" "$sidecar_source"
install -m 0644 "$sidecar_main_live" "$sidecar_main"
if [[ "$authority_test" == 1 ]]; then
    install -m 0644 "$authority_test_input" "$input_root/authority-test-input"
fi

verify_live_inputs() {
    local input_pairs=( \
        "$provider_builder_live" "$provider_builder" \
        "$patch_live" "$patch" \
        "$protocol_manifest_live" "$protocol_manifest" \
        "$sidecar_manifest_live" "$sidecar_manifest" \
        "$protocol_source_live" "$protocol_source" \
        "$sidecar_source_live" "$sidecar_source" \
        "$sidecar_main_live" "$sidecar_main" \
    )
    if [[ "$authority_test" == 1 ]]; then
        input_pairs+=("$authority_test_input" "$input_root/authority-test-input")
    fi
    python3 - "${input_pairs[@]}" <<'PY'
from pathlib import Path
import sys

arguments = [Path(value) for value in sys.argv[1:]]
for live, staged in zip(arguments[::2], arguments[1::2], strict=True):
    if live.is_symlink() or not live.is_file():
        raise SystemExit(f"provider build input is no longer a regular file: {live}")
    if live.read_bytes() != staged.read_bytes():
        raise SystemExit(f"provider build input changed after snapshot: {live}")
PY
}

patch_sha256="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$patch")"
builder_sha256="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$provider_builder")"
source_key_inputs=("$patch" "$provider_builder" "$protocol_manifest" "$sidecar_manifest" "$protocol_source" "$sidecar_source" "$sidecar_main")
if [[ "$authority_test" == 1 ]]; then
    source_key_inputs+=("$input_root/authority-test-input")
fi
source_key="$(python3 - "$rust_commit" "${source_key_inputs[@]}" <<'PY'
import hashlib
import struct
import sys

upstream_commit, *paths = sys.argv[1:]
hasher = hashlib.sha256()
for value in [b"h00/rust-semantic-provider-source/v2", upstream_commit.encode()]:
    hasher.update(struct.pack(">Q", len(value)))
    hasher.update(value)
for path in paths:
    with open(path, "rb") as handle:
        value = handle.read()
    hasher.update(struct.pack(">Q", len(value)))
    hasher.update(value)
print(hasher.hexdigest())
PY
)"
if [[ "$authority_test" == 1 ]]; then
    (umask 077; printf '%s\n' "$BASHPID" > "$authority_test_barrier.ready")
    authority_deadline=$((SECONDS + 60))
    while [[ ! -f "$authority_test_barrier.continue" ]]; do
        if ((SECONDS >= authority_deadline)); then
            echo "timed out at provider build-authority barrier: $authority_test_barrier" >&2
            exit 1
        fi
        sleep 0.05
    done
    [[ ! -L "$authority_test_barrier.continue" ]] || {
        echo "provider build-authority release must not be a symlink" >&2
        exit 1
    }
fi
verify_live_inputs

target_root="$repo_root/target/semantic-provider"
build_parent="$target_root/build"
cargo_target="$target_root/cargo"
output="${requested_output:-$target_root/$target/h00ligan-ra-provider}"
receipt="$output.build.json"
mkdir -p "$build_parent" "$cargo_target" "$(dirname "$output")"
build_root="$build_parent/rust-$source_key"
candidate=""
source_lock=""
output_temp=""
cleanup() {
    if [[ -n "$candidate" && -d "$candidate" ]]; then
        rm -rf -- "$candidate"
    fi
    if [[ -n "$output_temp" && -f "$output_temp" ]]; then
        rm -f -- "$output_temp"
    fi
    if [[ -n "$source_lock" && -d "$source_lock" ]]; then
        rmdir -- "$source_lock" 2>/dev/null || true
    fi
    if [[ -n "${invocation_root:-}" && -d "$invocation_root" ]]; then
        rm -rf -- "$invocation_root"
    fi
}
trap cleanup EXIT HUP INT TERM

verify_source_cache() {
    python3 - "$1" "$2" "$3" "$4" "$5" <<'PY'
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
builder_sha256 = sys.argv[4]
expected_authority_test = sys.argv[5]
if expected_authority_test not in {"0", "1"}:
    raise SystemExit("invalid semantic-provider source-cache authority expectation")
receipt = root / ".h00-semantic-provider-source.json"

if root.is_symlink() or not root.is_dir():
    raise SystemExit("semantic-provider source-cache root must be a real directory")

def field(hasher, value):
    hasher.update(struct.pack(">Q", len(value)))
    hasher.update(value)

hasher = hashlib.sha256()
field(hasher, b"h00/rust-semantic-provider-source-tree/v1")
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
        raise SystemExit(f"unsupported source-cache entry: {path}")
    for value in (relative, kind, mode, contents):
        field(hasher, value)
    file_count += 1
    total_bytes += len(contents)

observed = {
    "schema": "h00/rust-semantic-provider-source-cache/v2",
    "source_key": source_key,
    "builder_sha256": builder_sha256,
    "tree_sha256": hasher.hexdigest(),
    "file_count": file_count,
    "total_bytes": total_bytes,
}
if expected_authority_test == "1":
    observed["authority_test"] = True
if operation == "create":
    if receipt.exists():
        raise SystemExit("source-cache receipt already exists during creation")
    receipt.write_text(json.dumps(observed, sort_keys=True, separators=(",", ":")) + "\n")
elif operation == "verify":
    if not receipt.is_file():
        raise SystemExit("source-cache receipt is missing")
    recorded = json.loads(receipt.read_text())
    if recorded != observed:
        raise SystemExit("semantic-provider source cache failed integrity verification")
else:
    raise SystemExit(f"unknown source-cache operation: {operation}")
PY
}

if [[ ! -e "$build_root" ]]; then
    source_lock="$build_root.lock"
    if ! mkdir "$source_lock"; then
        echo "semantic-provider source preparation is already active: $source_lock" >&2
        exit 1
    fi
    candidate="$(mktemp -d "$build_parent/source.XXXXXX")"
    reusable_root="$(python3 - "$build_parent" "$prepared_source_cache" "$rust_commit" "$patch" "$provider_builder" <<'PY'
import hashlib
import json
from pathlib import Path
import struct
import sys

build_parent = Path(sys.argv[1])
prepared_source_cache = Path(sys.argv[2]) if sys.argv[2] else None
upstream_commit = sys.argv[3]
patch = Path(sys.argv[4])
builder = Path(sys.argv[5])
overlay_paths = [
    "src/tools/rust-analyzer/crates/h00ligan-provider-protocol/Cargo.toml",
    "src/tools/rust-analyzer/crates/h00ligan-ra-provider/Cargo.toml",
    "src/tools/rust-analyzer/crates/h00ligan-provider-protocol/src/lib.rs",
    "src/tools/rust-analyzer/crates/h00ligan-ra-provider/src/lib.rs",
    "src/tools/rust-analyzer/crates/h00ligan-ra-provider/src/main.rs",
]

def field(hasher, value):
    hasher.update(struct.pack(">Q", len(value)))
    hasher.update(value)

roots = [prepared_source_cache] if prepared_source_cache is not None else sorted(
    build_parent.glob("rust-*")
)
for root in roots:
    receipt_path = root / ".h00-semantic-provider-source.json"
    if root.is_symlink() or not root.is_dir() or receipt_path.is_symlink() or not receipt_path.is_file():
        continue
    try:
        receipt = json.loads(receipt_path.read_text())
        hasher = hashlib.sha256()
        for value in [b"h00/rust-semantic-provider-source/v2", upstream_commit.encode()]:
            field(hasher, value)
        field(hasher, patch.read_bytes())
        field(hasher, builder.read_bytes())
        for relative in overlay_paths:
            field(hasher, (root / relative).read_bytes())
    except (OSError, ValueError, KeyError):
        continue
    if receipt.get("source_key") == hasher.hexdigest():
        print(root)
        break
PY
)"
    if [[ -n "$prepared_source_cache" && -z "$reusable_root" ]]; then
        echo "prepared semantic-provider source cache is incompatible with current inputs" >&2
        exit 1
    fi
    if [[ -n "$reusable_root" ]]; then
        reusable_key="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_key"])' "$reusable_root/.h00-semantic-provider-source.json")"
        verify_source_cache "$reusable_root" "$reusable_key" verify "$builder_sha256" 0
        cp -a "$reusable_root/." "$candidate"
        rm -f -- "$candidate/.h00-semantic-provider-source.json"
    else
        [[ -n "$rust_source" ]] || {
            echo "--rust-source is required because no compatible verified provider source cache exists" >&2
            exit 2
        }
        rust_source="$(cd -- "$rust_source" && pwd)"
        command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 1; }
        command -v patch >/dev/null 2>&1 || { echo "patch is required" >&2; exit 1; }
        command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 1; }
        resolved_commit="$(git -C "$rust_source" rev-parse "$rust_commit^{commit}")"
        [[ "$resolved_commit" == "$rust_commit" ]] || {
            echo "Rust source does not contain the required commit $rust_commit" >&2
            exit 1
        }
        git -C "$rust_source" archive --format=tar "$rust_commit" | tar -xf - -C "$candidate"
        patch --dry-run --batch -p1 -d "$candidate" -i "$patch" >/dev/null
        patch --batch -p1 -d "$candidate" -i "$patch" >/dev/null
    fi

    candidate_ra_root="$candidate/src/tools/rust-analyzer"
    mkdir -p \
        "$candidate_ra_root/crates/h00ligan-provider-protocol/src" \
        "$candidate_ra_root/crates/h00ligan-ra-provider/src"
    install -m 0644 "$protocol_manifest" "$candidate_ra_root/crates/h00ligan-provider-protocol/Cargo.toml"
    install -m 0644 "$protocol_source" "$candidate_ra_root/crates/h00ligan-provider-protocol/src/lib.rs"
    install -m 0644 "$sidecar_manifest" "$candidate_ra_root/crates/h00ligan-ra-provider/Cargo.toml"
    install -m 0644 "$sidecar_source" "$candidate_ra_root/crates/h00ligan-ra-provider/src/lib.rs"
    install -m 0644 "$sidecar_main" "$candidate_ra_root/crates/h00ligan-ra-provider/src/main.rs"
    verify_live_inputs
    verify_source_cache "$candidate" "$source_key" create "$builder_sha256" "$authority_test"
    mv "$candidate" "$build_root"
    candidate=""
    rmdir "$source_lock"
    source_lock=""
elif [[ ! -d "$build_root" ]]; then
    echo "semantic-provider source cache path is not a directory: $build_root" >&2
    exit 1
fi

verify_source_cache "$build_root" "$source_key" verify "$builder_sha256" "$authority_test"
verify_live_inputs

ra_root="$build_root/src/tools/rust-analyzer"

if ((prepare_only)); then
    if ((machine_output)); then
        printf 'H00_RA_SOURCE_CACHE_ROOT=%s\n' "$build_root"
        printf 'H00_RA_SOURCE_ROOT=%s\n' "$ra_root"
        printf 'H00_RA_PATCH_SHA256=%s\n' "$patch_sha256"
        printf 'H00_RA_SOURCE_KEY=%s\n' "$source_key"
        printf 'H00_RA_BUILDER_SHA256=%s\n' "$builder_sha256"
    else
        printf '%s\n' "$ra_root"
    fi
    exit 0
fi

export CARGO_TARGET_DIR="$cargo_target"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_LTO=thin
export CARGO_PROFILE_RELEASE_STRIP=symbols
export H00_RA_PATCH_SHA256="$patch_sha256"
export RUSTFLAGS="--remap-path-prefix=$build_root=rust-source --remap-path-prefix=$repo_root=h00-source"
unset CARGO_ENCODED_RUSTFLAGS LD_LIBRARY_PATH LIBRARY_PATH NIX_LDFLAGS
unset DYLD_LIBRARY_PATH DYLD_FALLBACK_LIBRARY_PATH

rustup run "$rust_version" cargo build \
    --manifest-path "$ra_root/Cargo.toml" \
    --locked --offline --release \
    -p h00ligan-ra-provider \
    --target "$target"
verify_source_cache "$build_root" "$source_key" verify "$builder_sha256" "$authority_test"
verify_live_inputs

built_binary="$cargo_target/$target/release/h00ligan-ra-provider"
[[ -x "$built_binary" ]] || { echo "provider binary was not produced" >&2; exit 1; }
output_temp="$(mktemp "${output}.tmp.XXXXXX")"
install -m 0755 "$built_binary" "$output_temp"
mv -f "$output_temp" "$output"
output_temp=""

python3 - "$output" "$receipt" "$target" "$rust_version" "$rust_commit" "$patch_sha256" \
    "$builder_sha256" "$source_key" "$rustc_version" "$provider_builder" "$protocol_manifest" "$sidecar_manifest" "$protocol_source" "$sidecar_source" "$sidecar_main" <<'PY'
import hashlib
import json
import os
import re
import sys

(
    binary,
    receipt,
    target,
    upstream_version,
    upstream_commit,
    patch_sha,
    builder_sha256,
    source_key,
    rustc_version,
    provider_builder,
    protocol_manifest,
    sidecar_manifest,
    protocol_source,
    sidecar_source,
    sidecar_main,
) = sys.argv[1:]

def digest(path):
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()

protocol_source_text = open(protocol_source, encoding="utf-8").read()
protocol_matches = re.findall(
    r'^pub const SEMANTIC_PROVIDER_PROTOCOL: &str = "([^"]+)";$',
    protocol_source_text,
    flags=re.MULTILINE,
)
if len(protocol_matches) != 1:
    raise SystemExit("semantic-provider protocol constant is missing or ambiguous")

payload = {
    "schema": "h00/rust-semantic-provider-build/v2",
    "protocol": protocol_matches[0],
    "provider_id": "h00-rust-analyzer-scip",
    "language": "rust",
    "target": target,
    "rustc": rustc_version,
    "upstream_version": upstream_version,
    "upstream_commit": upstream_commit,
    "patch_sha256": patch_sha,
    "builder_sha256": builder_sha256,
    "source_key": source_key,
    "binary_sha256": digest(binary),
    "binary_size": os.path.getsize(binary),
    "input_sha256": {
        "provider_builder": digest(provider_builder),
        "protocol_manifest": digest(protocol_manifest),
        "sidecar_manifest": digest(sidecar_manifest),
        "protocol_source": digest(protocol_source),
        "sidecar_source": digest(sidecar_source),
        "sidecar_main": digest(sidecar_main),
    },
}
temporary = f"{receipt}.tmp.{os.getpid()}"
with open(temporary, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
os.replace(temporary, receipt)
PY

if ((machine_output)); then
    printf 'H00_RA_SEMANTIC_PROVIDER_BINARY=%s\n' "$output"
    printf 'H00_RA_SEMANTIC_PROVIDER_RECEIPT=%s\n' "$receipt"
    printf 'H00_RA_SOURCE_CACHE_ROOT=%s\n' "$build_root"
    printf 'H00_RA_SOURCE_ROOT=%s\n' "$ra_root"
    printf 'H00_RA_BUILDER_SHA256=%s\n' "$builder_sha256"
else
    printf '%s\n' "$output"
fi
