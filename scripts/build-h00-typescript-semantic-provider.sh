#!/usr/bin/env bash
set -euo pipefail

script_path="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${BASH_SOURCE[0]}")"
script_dir="$(cd -- "$(dirname "$script_path")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
cache_publisher_live="$repo_root/scripts/publish-h00ligan-cache-directory.py"
go_sdk_resolver_live="$repo_root/scripts/resolve-h00-official-go-sdk.sh"

if [[ -z "${DEVBOX_PACKAGES_DIR:-}" ]]; then
    command -v devbox >/dev/null 2>&1 || {
        echo "TypeScript semantic-provider builds require the repository's pinned Devbox" >&2
        exit 1
    }
    exec devbox run -- "$script_path" "$@"
fi

usage() {
    cat >&2 <<'USAGE'
Usage: scripts/build-h00-typescript-semantic-provider.sh [--target TARGET] [--machine]

Build the private CGO-free TypeScript-native provider embedded by h00ligan. The
output is a build input, never a separately installed product executable.
USAGE
}

target=""
machine=0
while (($#)); do
    case "$1" in
        --target)
            (($# >= 2)) || { usage; exit 2; }
            target="$2"
            shift 2
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

if [[ -z "$target" ]]; then
    case "$(uname -s):$(uname -m)" in
        Linux:x86_64) target="x86_64-unknown-linux-musl" ;;
        Linux:aarch64 | Linux:arm64) target="aarch64-unknown-linux-musl" ;;
        Darwin:x86_64) target="x86_64-apple-darwin" ;;
        Darwin:arm64 | Darwin:aarch64) target="aarch64-apple-darwin" ;;
        *) echo "unsupported TypeScript-provider host" >&2; exit 1 ;;
    esac
fi
case "$target" in
    x86_64-unknown-linux-musl) goos=linux; goarch=amd64 ;;
    aarch64-unknown-linux-musl) goos=linux; goarch=arm64 ;;
    x86_64-apple-darwin) goos=darwin; goarch=amd64 ;;
    aarch64-apple-darwin) goos=darwin; goarch=arm64 ;;
    *) echo "unsupported TypeScript-provider target: $target" >&2; exit 1 ;;
esac

# Primary upstreams checked 2026-08-26. TypeScript-Go's latest stable release
# was typescript/v7.0.2; SCIP's Go bindings latest stable release was v0.9.0.
# Every mutable label below is paired with immutable source-distribution bytes.
go_sdk_version="go1.27.0"
go_build_tags="timetzdata"
typescript_version="7.0.2"
typescript_tag="typescript/v7.0.2"
typescript_commit="2bd066d87f5bafd315be9f40889d0a60b9e58e0b"
typescript_tree="ed2c2c12c401b84bd5888d0b889737495aa93a20"
typescript_archive_url="https://codeload.github.com/microsoft/typescript-go/tar.gz/refs/tags/typescript/v7.0.2"
typescript_archive_name="typescript-go-typescript-v7.0.2.tar.gz"
typescript_archive_sha256="25cca8ec9d89e4ceec5181a677ded2c6d690fa18b81e1277846303973eb71fcf"
typescript_archive_prefix="typescript-go-typescript-v7.0.2"
scip_module="github.com/scip-code/scip/bindings/go/scip"
scip_version="v0.9.0"
scip_sum="h1:C0LVhTl9Gw+2UC4d7RZdvB0iWUkaOyRA1fQW1CrhsMA="
scip_go_mod_sum="h1:QhuSgP19HyWJIU/bvfBGn/RmkL/BX2IPoZWTNQ9M5wY="
scip_commit="e8ee0ae6038f8298e2195812eea9d7b1196748ae"

runtime_inputs=(
    "$repo_root/providers/go/shared/h00provider/protocol.go"
    "$repo_root/providers/typescript/h00_provider_main.go"
    "$repo_root/providers/typescript/h00_provider_protocol.go"
    "$repo_root/providers/typescript/h00_semantic_provider.go"
    "$repo_root/providers/typescript/h00_typescript_engine.go"
    "$repo_root/providers/typescript/h00_typescript_scip.go"
)
test_inputs=(
    "$repo_root/providers/typescript/h00_typescript_engine_test.go"
    "$repo_root/providers/typescript/h00_typescript_provider_process_test.go"
)
for input in "${runtime_inputs[@]}" "${test_inputs[@]}" \
    "$script_path" "$cache_publisher_live" "$go_sdk_resolver_live" \
    "$repo_root/devbox.json" "$repo_root/devbox.lock"; do
    [[ -f "$input" && ! -L "$input" ]] || {
        echo "TypeScript provider build input must be a regular non-symlink: $input" >&2
        exit 1
    }
done

cache_root="$repo_root/target/portable-cache/typescript-provider"
mkdir -p \
    "$cache_root/artifacts/$target" \
    "$cache_root/build-cache/$target" \
    "$cache_root/build-cache/host-tests" \
    "$cache_root/candidates" \
    "$cache_root/module-cache" \
    "$cache_root/source" \
    "$cache_root/tmp"
for path in "$cache_root" "$cache_root/artifacts/$target" "$cache_root/module-cache" \
    "$cache_root/source" "$cache_root/tmp"; do
    [[ -d "$path" && ! -L "$path" ]] || {
        echo "TypeScript provider cache root must be a real directory: $path" >&2
        exit 1
    }
done

candidate=""
artifact_candidate=""
archive_download=""
go_tmp_root=""
cleanup() {
    [[ -z "$candidate" || ! -d "$candidate" ]] || rm -rf -- "$candidate"
    [[ -z "$artifact_candidate" || ! -d "$artifact_candidate" ]] || rm -rf -- "$artifact_candidate"
    [[ -z "$archive_download" || ! -f "$archive_download" ]] || rm -f -- "$archive_download"
    [[ -z "$go_tmp_root" || ! -d "$go_tmp_root" ]] || rm -rf -- "$go_tmp_root"
}
trap cleanup EXIT HUP INT TERM

go_tmp_root="$(mktemp -d "$cache_root/tmp/invocation.XXXXXX")"
export GOTMPDIR="$go_tmp_root"
export GOCACHE="$cache_root/build-cache/$target"
export GOMODCACHE="$cache_root/module-cache"
export GOENV=off
export GOTOOLCHAIN=local
export GOWORK=off

cache_publisher="$go_tmp_root/publish-h00ligan-cache-directory.py"
install -m 0500 "$cache_publisher_live" "$cache_publisher"
cache_publisher_sha256="$(sha256sum "$cache_publisher" | awk '{print $1}')"
verify_cache_publisher() {
    local live_sha256
    local snapshot_sha256
    live_sha256="$(sha256sum "$cache_publisher_live" | awk '{print $1}')"
    snapshot_sha256="$(sha256sum "$cache_publisher" | awk '{print $1}')"
    [[ "$live_sha256" == "$cache_publisher_sha256" \
        && "$snapshot_sha256" == "$cache_publisher_sha256" ]] || {
        echo "TypeScript provider cache-publisher input changed during the build" >&2
        exit 1
    }
}
verify_cache_publisher

go_sdk_details="$("$go_sdk_resolver_live")"
go_tool="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_TOOL=//p')"
resolved_go_sdk_version="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_VERSION=//p')"
go_sdk_filename="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_FILENAME=//p')"
go_sdk_archive_sha256="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_ARCHIVE_SHA256=//p')"
go_sdk_tree_sha256="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_TREE_SHA256=//p')"
go_sdk_binary_sha256="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_BINARY_SHA256=//p')"
go_identity="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_IDENTITY=//p')"
go_sdk_receipt_sha256="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_RECEIPT_SHA256=//p')"
go_sdk_resolver_sha256="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_RESOLVER_SHA256=//p')"
go_sdk_cache_publisher_sha256="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_CACHE_PUBLISHER_SHA256=//p')"
[[ -x "$go_tool" && ! -L "$go_tool" && "$resolved_go_sdk_version" == "$go_sdk_version" \
    && "$go_identity" == go\ version\ "$go_sdk_version"* ]] || {
    echo "official Go SDK resolver returned invalid TypeScript toolchain coordinates" >&2
    exit 1
}
for digest in "$go_sdk_archive_sha256" "$go_sdk_tree_sha256" \
    "$go_sdk_binary_sha256" "$go_sdk_receipt_sha256" \
    "$go_sdk_resolver_sha256" "$go_sdk_cache_publisher_sha256"; do
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
        echo "official Go SDK resolver returned an invalid TypeScript toolchain digest" >&2
        exit 1
    }
done
[[ "$go_sdk_cache_publisher_sha256" == "$cache_publisher_sha256" ]] || {
    echo "official Go SDK and TypeScript builders resolved different cache publishers" >&2
    exit 1
}
verify_go_sdk_resolver() {
    [[ "$(sha256sum "$go_sdk_resolver_live" | awk '{print $1}')" == "$go_sdk_resolver_sha256" ]] || {
        echo "official Go SDK resolver changed during the TypeScript provider build" >&2
        exit 1
    }
}
verify_go_sdk_resolver

archive="$cache_root/source/$typescript_archive_name"
if [[ ! -e "$archive" ]]; then
    command -v curl >/dev/null 2>&1 || {
        echo "curl is required to acquire the pinned TypeScript-Go source" >&2
        exit 1
    }
    archive_download="$(mktemp "$cache_root/source/$typescript_archive_name.download.XXXXXX")"
    curl --fail --location --proto '=https' --tlsv1.2 \
        "$typescript_archive_url" --output "$archive_download"
    [[ "$(sha256sum "$archive_download" | awk '{print $1}')" == "$typescript_archive_sha256" ]] || {
        echo "official TypeScript-Go source archive checksum mismatch" >&2
        exit 1
    }
    if [[ ! -e "$archive" ]]; then
        mv "$archive_download" "$archive"
    fi
    archive_download=""
fi
[[ -f "$archive" && ! -L "$archive" ]] || {
    echo "cached TypeScript-Go source archive is invalid" >&2
    exit 1
}
[[ "$(sha256sum "$archive" | awk '{print $1}')" == "$typescript_archive_sha256" ]] || {
    echo "cached TypeScript-Go source archive checksum mismatch" >&2
    exit 1
}

candidate="$(mktemp -d "$cache_root/candidates/source.XXXXXX")"
python3 - "$archive" "$candidate" "$typescript_archive_prefix" <<'PY'
from pathlib import Path, PurePosixPath
import sys
import tarfile

archive, destination, expected_prefix = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
with tarfile.open(archive, "r:gz") as source:
    members = source.getmembers()
    if not members:
        raise SystemExit("TypeScript-Go source archive is empty")
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != expected_prefix:
            raise SystemExit(f"unsafe TypeScript-Go archive path: {member.name}")
        if not (member.isfile() or member.isdir()):
            raise SystemExit(f"unsupported TypeScript-Go archive entry: {member.name}")
    source.extractall(destination, filter="data")
PY
typescript_root="$candidate/$typescript_archive_prefix"
[[ -d "$typescript_root" && ! -L "$typescript_root" ]] || {
    echo "TypeScript-Go archive produced no source root" >&2
    exit 1
}
find "$typescript_root" -type l -print -quit | grep -q . && {
    echo "TypeScript-Go source contains an unsupported symlink" >&2
    exit 1
}

mkdir -p "$typescript_root/internal/h00provider" "$typescript_root/cmd/h00-typescript-provider"
install -m 0644 "${runtime_inputs[0]}" "$typescript_root/internal/h00provider/protocol.go"
install -m 0644 "${runtime_inputs[1]}" "$typescript_root/cmd/h00-typescript-provider/h00_provider_main.go"
install -m 0644 "${runtime_inputs[2]}" "$typescript_root/cmd/h00-typescript-provider/h00_provider_protocol.go"
install -m 0644 "${runtime_inputs[3]}" "$typescript_root/cmd/h00-typescript-provider/h00_semantic_provider.go"
install -m 0644 "${runtime_inputs[4]}" "$typescript_root/cmd/h00-typescript-provider/h00_typescript_engine.go"
install -m 0644 "${runtime_inputs[5]}" "$typescript_root/cmd/h00-typescript-provider/h00_typescript_scip.go"
install -m 0644 "${test_inputs[0]}" "$typescript_root/cmd/h00-typescript-provider/h00_typescript_engine_test.go"
install -m 0644 "${test_inputs[1]}" "$typescript_root/cmd/h00-typescript-provider/h00_typescript_provider_process_test.go"

digest_inputs() {
    python3 - "$@" <<'PY'
import hashlib
from pathlib import Path
import struct
import sys

arguments = sys.argv[1:]
if len(arguments) % 2:
    raise SystemExit("digest inputs require logical/path pairs")
hasher = hashlib.sha256()
for logical, raw in zip(arguments[::2], arguments[1::2]):
    for field in (logical.encode(), Path(raw).read_bytes()):
        hasher.update(struct.pack(">Q", len(field)))
        hasher.update(field)
print(hasher.hexdigest())
PY
}

patch_sha256="$(digest_inputs \
    internal/h00provider/protocol.go "${runtime_inputs[0]}" \
    cmd/h00-typescript-provider/h00_provider_main.go "${runtime_inputs[1]}" \
    cmd/h00-typescript-provider/h00_provider_protocol.go "${runtime_inputs[2]}" \
    cmd/h00-typescript-provider/h00_semantic_provider.go "${runtime_inputs[3]}" \
    cmd/h00-typescript-provider/h00_typescript_engine.go "${runtime_inputs[4]}" \
    cmd/h00-typescript-provider/h00_typescript_scip.go "${runtime_inputs[5]}")"
test_sha256="$(digest_inputs \
    cmd/h00-typescript-provider/h00_typescript_engine_test.go "${test_inputs[0]}" \
    cmd/h00-typescript-provider/h00_typescript_provider_process_test.go "${test_inputs[1]}")"
[[ "$patch_sha256" =~ ^[0-9a-f]{64}$ && "$test_sha256" =~ ^[0-9a-f]{64}$ ]] || {
    echo "invalid TypeScript provider source identity" >&2
    exit 1
}

scip_resolution="$("$go_tool" mod download -json "$scip_module@$scip_version")"
python3 - "$scip_module" "$scip_version" "$scip_sum" "$scip_go_mod_sum" "$scip_commit" "$scip_resolution" <<'PY'
import json
import sys

module, version, expected_sum, expected_mod_sum, expected_commit, raw = sys.argv[1:]
payload = json.loads(raw)
if payload.get("Error"):
    raise SystemExit(f"download {module}@{version}: {payload['Error']}")
if payload.get("Path") != module or payload.get("Version") != version:
    raise SystemExit("SCIP module resolver returned the wrong coordinate")
if payload.get("Sum") != expected_sum or payload.get("GoModSum") != expected_mod_sum:
    raise SystemExit("SCIP module resolver returned the wrong immutable sums")
if payload.get("Origin", {}).get("Hash") != expected_commit:
    raise SystemExit("SCIP module resolver returned the wrong source revision")
PY

(
    cd -- "$typescript_root"
    "$go_tool" mod edit -require="$scip_module@$scip_version"
    "$go_tool" mod tidy
    GOCACHE="$cache_root/build-cache/host-tests" GOFLAGS=-mod=readonly \
        "$go_tool" test -trimpath ./cmd/h00-typescript-provider -count=1
)

tree_sha256() {
    python3 - "$1" <<'PY'
import hashlib
from pathlib import Path
import struct
import sys

root = Path(sys.argv[1])
hasher = hashlib.sha256()
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    if path.is_symlink():
        raise SystemExit(f"unexpected symlink in TypeScript provider source: {path}")
    if path.is_dir():
        continue
    if not path.is_file():
        raise SystemExit(f"unsupported TypeScript provider source entry: {path}")
    for field in (path.relative_to(root).as_posix().encode(), path.read_bytes()):
        hasher.update(struct.pack(">Q", len(field)))
        hasher.update(field)
print(hasher.hexdigest())
PY
}

source_tree_sha256="$(tree_sha256 "$typescript_root")"
builder_sha256="$(sha256sum "$script_path" | awk '{print $1}')"
devbox_json_sha256="$(sha256sum "$repo_root/devbox.json" | awk '{print $1}')"
devbox_lock_sha256="$(sha256sum "$repo_root/devbox.lock" | awk '{print $1}')"
verify_cache_publisher
build_key="$(python3 - \
    "$target" "$source_tree_sha256" "$patch_sha256" "$test_sha256" "$builder_sha256" \
    "$cache_publisher_sha256" "$devbox_json_sha256" "$devbox_lock_sha256" \
    "$go_sdk_version" "$go_sdk_filename" "$go_sdk_archive_sha256" \
    "$go_sdk_tree_sha256" "$go_sdk_binary_sha256" "$go_identity" \
    "$go_sdk_receipt_sha256" "$go_sdk_resolver_sha256" \
    "$go_sdk_cache_publisher_sha256" "$go_build_tags" \
    "$typescript_version" "$typescript_tag" "$typescript_commit" "$typescript_tree" \
    "$typescript_archive_url" "$typescript_archive_sha256" \
    "$scip_version" "$scip_sum" "$scip_go_mod_sum" "$scip_commit" <<'PY'
import hashlib
import struct
import sys

hasher = hashlib.sha256()
for field in (b"h00/typescript-semantic-provider-artifact/v2", *(value.encode() for value in sys.argv[1:])):
    hasher.update(struct.pack(">Q", len(field)))
    hasher.update(field)
print(hasher.hexdigest())
PY
)"

artifact_root="$cache_root/artifacts/$target/$build_key"
binary="$artifact_root/h00-typescript-semantic-provider"
receipt="$artifact_root/h00-typescript-semantic-provider.build.json"
if [[ ! -e "$artifact_root" ]]; then
    artifact_candidate="$(mktemp -d "$cache_root/artifacts/$target/artifact.XXXXXX")"
    output="$artifact_candidate/h00-typescript-semantic-provider"
    (
        cd -- "$typescript_root"
        CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOFLAGS=-mod=readonly \
            "$go_tool" build -trimpath -buildvcs=false -tags "$go_build_tags" \
                -ldflags "-s -w -buildid= -X main.h00ProviderPatchSHA256=$patch_sha256" \
                -o "$output" ./cmd/h00-typescript-provider
    )
    [[ -x "$output" && -f "$output" && ! -L "$output" ]] || {
        echo "TypeScript semantic-provider build produced no executable" >&2
        exit 1
    }
    [[ "$(tree_sha256 "$typescript_root")" == "$source_tree_sha256" ]] || {
        echo "TypeScript provider source changed during compilation" >&2
        exit 1
    }
    verify_go_sdk_resolver
    binary_sha256="$(sha256sum "$output" | awk '{print $1}')"
    python3 - "$artifact_candidate/h00-typescript-semantic-provider.build.json" \
        "$build_key" "$target" "$goos" "$goarch" \
        "$go_sdk_version" "$go_sdk_filename" "$go_sdk_archive_sha256" \
        "$go_sdk_tree_sha256" "$go_sdk_binary_sha256" "$go_identity" \
        "$go_sdk_receipt_sha256" "$go_sdk_resolver_sha256" \
        "$go_sdk_cache_publisher_sha256" "$go_build_tags" \
        "$typescript_version" "$typescript_tag" "$typescript_commit" "$typescript_tree" \
        "$typescript_archive_url" "$typescript_archive_sha256" \
        "$scip_version" "$scip_sum" "$scip_go_mod_sum" "$scip_commit" \
        "$patch_sha256" "$test_sha256" "$source_tree_sha256" "$builder_sha256" \
        "$cache_publisher_sha256" "$devbox_json_sha256" "$devbox_lock_sha256" \
        "$binary_sha256" <<'PY'
import json
from pathlib import Path
import sys

(
    receipt, build_key, target, goos, goarch,
    go_sdk_version, go_sdk_filename, go_sdk_archive_sha256,
    go_sdk_tree_sha256, go_sdk_binary_sha256, go_identity,
    go_sdk_receipt_sha256, go_sdk_resolver_sha256,
    go_sdk_cache_publisher_sha256, go_build_tags,
    typescript_version, typescript_tag, typescript_commit, typescript_tree,
    typescript_archive_url, typescript_archive_sha256,
    scip_version, scip_sum, scip_go_mod_sum, scip_commit,
    patch_sha256, test_sha256, source_tree_sha256, builder_sha256,
    cache_publisher_sha256, devbox_json_sha256, devbox_lock_sha256,
    binary_sha256,
) = sys.argv[1:]
payload = {
    "schema": "h00/typescript-semantic-provider-artifact/v2",
    "build_key": build_key,
    "target": target,
    "goos": goos,
    "goarch": goarch,
    "go_sdk_version": go_sdk_version,
    "go_sdk_filename": go_sdk_filename,
    "go_sdk_archive_sha256": go_sdk_archive_sha256,
    "go_sdk_tree_sha256": go_sdk_tree_sha256,
    "go_sdk_binary_sha256": go_sdk_binary_sha256,
    "go_identity": go_identity,
    "go_sdk_receipt_sha256": go_sdk_receipt_sha256,
    "go_sdk_resolver_sha256": go_sdk_resolver_sha256,
    "go_sdk_cache_publisher_sha256": go_sdk_cache_publisher_sha256,
    "go_build_tags": go_build_tags,
    "typescript_version": typescript_version,
    "typescript_tag": typescript_tag,
    "typescript_commit": typescript_commit,
    "typescript_tree": typescript_tree,
    "typescript_archive_url": typescript_archive_url,
    "typescript_archive_sha256": typescript_archive_sha256,
    "scip_bindings_version": scip_version,
    "scip_bindings_sum": scip_sum,
    "scip_bindings_go_mod_sum": scip_go_mod_sum,
    "scip_bindings_commit": scip_commit,
    "patch_sha256": patch_sha256,
    "test_sha256": test_sha256,
    "source_tree_sha256": source_tree_sha256,
    "builder_sha256": builder_sha256,
    "cache_publisher_sha256": cache_publisher_sha256,
    "devbox_json_sha256": devbox_json_sha256,
    "devbox_lock_sha256": devbox_lock_sha256,
    "binary_sha256": binary_sha256,
}
Path(receipt).write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
PY
    python3 "$cache_publisher" publish \
        --owner-root "$cache_root" \
        --candidate "$artifact_candidate" \
        --destination "$artifact_root" >/dev/null
    verify_cache_publisher
    artifact_candidate=""
elif [[ ! -d "$artifact_root" || -L "$artifact_root" ]]; then
    echo "TypeScript provider artifact cache entry is invalid" >&2
    exit 1
fi

[[ -x "$binary" && -f "$receipt" && ! -L "$binary" && ! -L "$receipt" ]] || {
    echo "TypeScript provider cached artifact is incomplete" >&2
    exit 1
}
binary_sha256="$(sha256sum "$binary" | awk '{print $1}')"
path_probe="$go_tmp_root/forbidden-path-positive"
printf '/nix/store/positive-control\n' > "$path_probe"
LC_ALL=C grep -aFq '/nix/store/' "$path_probe" || {
    echo "TypeScript provider forbidden-path probe is vacuous" >&2
    exit 1
}
if LC_ALL=C grep -aFq '/nix/store/' "$binary"; then
    echo "TypeScript provider embeds a forbidden Nix store path" >&2
    exit 1
fi
python3 - "$receipt" "$build_key" "$target" "$goos" "$goarch" "$go_identity" \
    "$go_sdk_version" "$go_sdk_filename" "$go_sdk_archive_sha256" \
    "$go_sdk_tree_sha256" "$go_sdk_binary_sha256" "$go_sdk_receipt_sha256" \
    "$go_sdk_resolver_sha256" "$go_sdk_cache_publisher_sha256" "$go_build_tags" \
    "$typescript_version" "$typescript_tag" "$typescript_commit" "$typescript_tree" \
    "$typescript_archive_url" "$typescript_archive_sha256" \
    "$scip_version" "$scip_sum" "$scip_go_mod_sum" "$scip_commit" \
    "$binary_sha256" "$patch_sha256" "$test_sha256" "$source_tree_sha256" \
    "$builder_sha256" "$cache_publisher_sha256" "$devbox_json_sha256" \
    "$devbox_lock_sha256" <<'PY'
import json
import sys

(
    receipt, build_key, target, goos, goarch, go_identity,
    go_sdk_version, go_sdk_filename, go_sdk_archive_sha256,
    go_sdk_tree_sha256, go_sdk_binary_sha256, go_sdk_receipt_sha256,
    go_sdk_resolver_sha256, go_sdk_cache_publisher_sha256, go_build_tags,
    typescript_version, typescript_tag, typescript_commit, typescript_tree,
    typescript_archive_url, typescript_archive_sha256,
    scip_version, scip_sum, scip_go_mod_sum, scip_commit,
    binary_sha256, patch_sha256, test_sha256, source_tree_sha256,
    builder_sha256, cache_publisher_sha256, devbox_json_sha256, devbox_lock_sha256,
) = sys.argv[1:]
payload = json.load(open(receipt, encoding="utf-8"))
expected = {
    "schema": "h00/typescript-semantic-provider-artifact/v2",
    "build_key": build_key,
    "target": target,
    "goos": goos,
    "goarch": goarch,
    "go_sdk_version": go_sdk_version,
    "go_sdk_filename": go_sdk_filename,
    "go_sdk_archive_sha256": go_sdk_archive_sha256,
    "go_sdk_tree_sha256": go_sdk_tree_sha256,
    "go_sdk_binary_sha256": go_sdk_binary_sha256,
    "go_identity": go_identity,
    "go_sdk_receipt_sha256": go_sdk_receipt_sha256,
    "go_sdk_resolver_sha256": go_sdk_resolver_sha256,
    "go_sdk_cache_publisher_sha256": go_sdk_cache_publisher_sha256,
    "go_build_tags": go_build_tags,
    "typescript_version": typescript_version,
    "typescript_tag": typescript_tag,
    "typescript_commit": typescript_commit,
    "typescript_tree": typescript_tree,
    "typescript_archive_url": typescript_archive_url,
    "typescript_archive_sha256": typescript_archive_sha256,
    "scip_bindings_version": scip_version,
    "scip_bindings_sum": scip_sum,
    "scip_bindings_go_mod_sum": scip_go_mod_sum,
    "scip_bindings_commit": scip_commit,
    "binary_sha256": binary_sha256,
    "patch_sha256": patch_sha256,
    "test_sha256": test_sha256,
    "source_tree_sha256": source_tree_sha256,
    "builder_sha256": builder_sha256,
    "cache_publisher_sha256": cache_publisher_sha256,
    "devbox_json_sha256": devbox_json_sha256,
    "devbox_lock_sha256": devbox_lock_sha256,
}
for field, value in expected.items():
    if payload.get(field) != value:
        raise SystemExit(f"TypeScript provider receipt mismatch: {field}")
PY
verify_cache_publisher
verify_go_sdk_resolver

if ((machine)); then
    printf 'H00_TYPESCRIPT_PROVIDER_BINARY=%s\n' "$binary"
    printf 'H00_TYPESCRIPT_PROVIDER_RECEIPT=%s\n' "$receipt"
    printf 'H00_TYPESCRIPT_PROVIDER_BINARY_SHA256=%s\n' "$binary_sha256"
    printf 'H00_TYPESCRIPT_PROVIDER_PATCH_SHA256=%s\n' "$patch_sha256"
    printf 'H00_TYPESCRIPT_PROVIDER_TEST_SHA256=%s\n' "$test_sha256"
    printf 'H00_TYPESCRIPT_PROVIDER_SOURCE_TREE_SHA256=%s\n' "$source_tree_sha256"
    printf 'H00_TYPESCRIPT_PROVIDER_BUILDER_SHA256=%s\n' "$builder_sha256"
    printf 'H00_TYPESCRIPT_PROVIDER_CACHE_PUBLISHER_SHA256=%s\n' "$cache_publisher_sha256"
    printf 'H00_GO_SDK_RESOLVER_SHA256=%s\n' "$go_sdk_resolver_sha256"
    printf 'H00_GO_SDK_RECEIPT_SHA256=%s\n' "$go_sdk_receipt_sha256"
else
    printf '%s\n' "$binary"
fi
