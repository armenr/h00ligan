#!/usr/bin/env bash
set -euo pipefail

script_path="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${BASH_SOURCE[0]}")"
script_dir="$(cd -- "$(dirname "$script_path")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
cache_publisher_live="$repo_root/scripts/publish-h00ligan-cache-directory.py"
go_sdk_resolver_live="$repo_root/scripts/resolve-h00-official-go-sdk.sh"

if [[ -z "${DEVBOX_PACKAGES_DIR:-}" ]]; then
    command -v devbox >/dev/null 2>&1 || {
        echo "Go semantic-provider builds require the repository's pinned Devbox" >&2
        exit 1
    }
    exec devbox run -- "$script_path" "$@"
fi

usage() {
    cat >&2 <<'USAGE'
Usage: scripts/build-h00-go-semantic-provider.sh [--target TARGET] [--machine]

Build the private CGO-free persistent Go provider embedded by h00ligan. The
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
        *) echo "unsupported Go provider host" >&2; exit 1 ;;
    esac
fi
case "$target" in
    x86_64-unknown-linux-musl) goos=linux; goarch=amd64 ;;
    aarch64-unknown-linux-musl) goos=linux; goarch=arm64 ;;
    x86_64-apple-darwin) goos=darwin; goarch=amd64 ;;
    aarch64-apple-darwin) goos=darwin; goarch=arm64 ;;
    *) echo "unsupported Go provider target: $target" >&2; exit 1 ;;
esac

# Primary upstreams checked 2026-08-23. These were the latest stable releases
# on that date; module sums are Go's immutable source-distribution identities.
go_sdk_version="go1.27.0"
gopls_module="golang.org/x/tools/gopls"
gopls_version="v0.23.0"
gopls_sum="h1:Dn6mf9WXu9iLnTftDDMb9wV0c6Se7PjzEMqP0LEe08Y="
gopls_commit="014f87ff5c01915bc90f4f11a6bb8aea3e0edbd7"
scip_module="github.com/scip-code/scip-go"
scip_version="v0.2.7"
scip_sum="h1:gcHFnhoMCdp3C/0xvCn9QFuTsF/W3JSR5cLVf7uG+Us="
scip_commit="2e9ff3c2603a85daabe125c9f20075ec52df0731"

inputs=(
    "$repo_root/providers/go/gopls/h00_provider_main.go"
    "$repo_root/providers/go/shared/h00provider/protocol.go"
    "$repo_root/providers/go/gopls/h00_provider_protocol.go"
    "$repo_root/providers/go/gopls/h00_semantic_provider.go"
    "$repo_root/providers/go/gopls/h00_scip.go"
    "$repo_root/providers/go/scip-go/h00scip/export.go"
)
for input in "${inputs[@]}" "$script_path" "$cache_publisher_live" "$go_sdk_resolver_live"; do
    [[ -f "$input" && ! -L "$input" ]] || {
        echo "Go provider build input must be a regular non-symlink: $input" >&2
        exit 1
    }
done

cache_root="$repo_root/target/portable-cache/go-provider"
mkdir -p \
    "$cache_root/candidates" \
    "$cache_root/artifacts/$target" \
    "$cache_root/build-cache/$target" \
    "$cache_root/tmp"
[[ ! -L "$cache_root" \
    && ! -L "$cache_root/artifacts/$target" \
    && ! -L "$cache_root/tmp" \
    && -d "$cache_root/tmp" ]] || {
    echo "Go provider cache roots must not be symlinks" >&2
    exit 1
}
candidate=""
artifact_candidate=""
go_tmp_root=""
cleanup() {
    [[ -z "$candidate" || ! -d "$candidate" ]] || rm -rf -- "$candidate"
    [[ -z "$artifact_candidate" || ! -d "$artifact_candidate" ]] || rm -rf -- "$artifact_candidate"
    [[ -z "$go_tmp_root" || ! -d "$go_tmp_root" ]] || rm -rf -- "$go_tmp_root"
}
trap cleanup EXIT HUP INT TERM
go_tmp_root="$(mktemp -d "$cache_root/tmp/invocation.XXXXXX")"
export GOTMPDIR="$go_tmp_root"
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
        echo "Go provider cache-publisher input changed during the build" >&2
        exit 1
    }
}
verify_cache_publisher

go_sdk_details="$("$go_sdk_resolver_live")"
go_tool="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_TOOL=//p')"
resolved_go_sdk_version="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_VERSION=//p')"
sdk_filename="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_FILENAME=//p')"
sdk_sha256="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_ARCHIVE_SHA256=//p')"
sdk_tree_sha256="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_TREE_SHA256=//p')"
go_sdk_binary_sha256="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_BINARY_SHA256=//p')"
go_identity="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_IDENTITY=//p')"
go_sdk_receipt_sha256="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_RECEIPT_SHA256=//p')"
go_sdk_resolver_sha256="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_RESOLVER_SHA256=//p')"
go_sdk_cache_publisher_sha256="$(printf '%s\n' "$go_sdk_details" | sed -n 's/^H00_GO_SDK_CACHE_PUBLISHER_SHA256=//p')"
[[ -x "$go_tool" && ! -L "$go_tool" && "$resolved_go_sdk_version" == "$go_sdk_version" \
    && "$go_identity" == go\ version\ "$go_sdk_version"* ]] || {
    echo "official Go SDK resolver returned invalid toolchain coordinates" >&2
    exit 1
}
for digest in "$sdk_sha256" "$sdk_tree_sha256" "$go_sdk_binary_sha256" \
    "$go_sdk_receipt_sha256" "$go_sdk_resolver_sha256" \
    "$go_sdk_cache_publisher_sha256"; do
    [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || {
        echo "official Go SDK resolver returned an invalid digest" >&2
        exit 1
    }
done
[[ "$(sha256sum "$go_sdk_resolver_live" | awk '{print $1}')" == "$go_sdk_resolver_sha256" ]] || {
    echo "official Go SDK resolver changed after toolchain resolution" >&2
    exit 1
}
[[ "$go_sdk_cache_publisher_sha256" == "$cache_publisher_sha256" ]] || {
    echo "official Go SDK and provider builders resolved different cache publishers" >&2
    exit 1
}
verify_go_sdk_resolver() {
    [[ "$(sha256sum "$go_sdk_resolver_live" | awk '{print $1}')" == "$go_sdk_resolver_sha256" ]] || {
        echo "official Go SDK resolver changed during the provider build" >&2
        exit 1
    }
}
verify_go_sdk_resolver

candidate="$(mktemp -d "$cache_root/candidates/source.XXXXXX")"

download_module() {
    local module="$1"
    local version="$2"
    local expected_sum="$3"
    local expected_commit="$4"
    local result
    if ! result="$(GOWORK=off GOENV=off GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off "$go_tool" mod download -json "$module@$version" 2>/dev/null)"; then
        result="$(GOWORK=off GOENV=off GOTOOLCHAIN=local "$go_tool" mod download -json "$module@$version")"
    fi
    python3 - "$module" "$version" "$expected_sum" "$expected_commit" "$result" <<'PY'
import json
import sys

module, version, expected, expected_commit, raw = sys.argv[1:]
payload = json.loads(raw)
if payload.get("Error"):
    raise SystemExit(f"download {module}@{version}: {payload['Error']}")
if payload.get("Path") != module or payload.get("Version") != version:
    raise SystemExit("Go module resolver returned the wrong source coordinate")
if payload.get("Sum") != expected:
    raise SystemExit(
        f"Go module sum mismatch for {module}@{version}: "
        f"expected {expected}, observed {payload.get('Sum')}"
    )
if payload.get("Origin", {}).get("Hash") != expected_commit:
    raise SystemExit(
        f"Go module commit mismatch for {module}@{version}: "
        f"expected {expected_commit}, observed {payload.get('Origin', {}).get('Hash')}"
    )
directory = payload.get("Dir")
if not directory:
    raise SystemExit("Go module resolver returned no extracted source directory")
print(directory)
PY
}

gopls_source="$(download_module "$gopls_module" "$gopls_version" "$gopls_sum" "$gopls_commit")"
scip_source="$(download_module "$scip_module" "$scip_version" "$scip_sum" "$scip_commit")"
[[ -d "$gopls_source" && ! -L "$gopls_source" && -d "$scip_source" && ! -L "$scip_source" ]] || {
    echo "resolved Go module source is not a real directory" >&2
    exit 1
}

gopls_root="$candidate/gopls"
scip_root="$candidate/scip-go"
mkdir -p "$gopls_root" "$scip_root"
cp -a "$gopls_source/." "$gopls_root"
cp -a "$scip_source/." "$scip_root"
chmod -R u+w "$gopls_root" "$scip_root"
find "$gopls_root" "$scip_root" -type l -print -quit | grep -q . && {
    echo "upstream Go provider sources contain an unsupported symlink" >&2
    exit 1
}

install -m 0644 "${inputs[0]}" "$gopls_root/main.go"
mkdir -p "$gopls_root/internal/h00provider"
install -m 0644 "${inputs[1]}" "$gopls_root/internal/h00provider/protocol.go"
install -m 0644 "${inputs[2]}" "$gopls_root/internal/cmd/h00_provider_protocol.go"
install -m 0644 "${inputs[3]}" "$gopls_root/internal/cmd/h00_semantic_provider.go"
install -m 0644 "${inputs[4]}" "$gopls_root/internal/server/h00_scip.go"
mkdir -p "$scip_root/h00scip"
install -m 0644 "${inputs[5]}" "$scip_root/h00scip/export.go"

patch_sha256="$(python3 - "${inputs[@]}" <<'PY'
import hashlib
import struct
import sys
from pathlib import Path

logical = (
    "gopls/main.go",
    "gopls/internal/h00provider/protocol.go",
    "gopls/internal/cmd/h00_provider_protocol.go",
    "gopls/internal/cmd/h00_semantic_provider.go",
    "gopls/internal/server/h00_scip.go",
    "scip-go/h00scip/export.go",
)
hasher = hashlib.sha256()
for name, raw in zip(logical, sys.argv[1:]):
    for field in (name.encode(), Path(raw).read_bytes()):
        hasher.update(struct.pack(">Q", len(field)))
        hasher.update(field)
print(hasher.hexdigest())
PY
)"
[[ "$patch_sha256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid Go provider patch identity" >&2; exit 1; }

(
    cd -- "$gopls_root"
    GOWORK=off GOENV=off GOTOOLCHAIN=local "$go_tool" mod edit \
        -require="$scip_module@$scip_version" \
        -replace="$scip_module=../scip-go"
    if ! GOWORK=off GOENV=off GOTOOLCHAIN=local GOPROXY=off \
        GOCACHE="$cache_root/build-cache/$target" "$go_tool" mod tidy; then
        GOWORK=off GOENV=off GOTOOLCHAIN=local \
            GOCACHE="$cache_root/build-cache/$target" "$go_tool" mod tidy
    fi
)

tree_sha256() {
    python3 - "$1" <<'PY'
import hashlib
import os
from pathlib import Path
import stat
import struct
import sys

root = Path(sys.argv[1])
hasher = hashlib.sha256()
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    if path.is_symlink():
        raise SystemExit(f"unexpected symlink in Go provider source: {path}")
    if path.is_dir():
        continue
    if not path.is_file():
        raise SystemExit(f"unsupported Go provider source entry: {path}")
    for field in (path.relative_to(root).as_posix().encode(), path.read_bytes()):
        hasher.update(struct.pack(">Q", len(field)))
        hasher.update(field)
print(hasher.hexdigest())
PY
}

source_tree_sha256="$(tree_sha256 "$candidate")"
builder_sha256="$(sha256sum "$script_path" | awk '{print $1}')"
verify_cache_publisher
build_key="$(python3 - \
    "$target" "$source_tree_sha256" "$patch_sha256" "$builder_sha256" \
    "$cache_publisher_sha256" "$go_sdk_version" "$sdk_filename" "$sdk_sha256" \
    "$sdk_tree_sha256" "$go_sdk_binary_sha256" "$go_identity" \
    "$go_sdk_receipt_sha256" "$go_sdk_resolver_sha256" \
    "$go_sdk_cache_publisher_sha256" <<'PY'
import hashlib
import struct
import sys

hasher = hashlib.sha256()
for field in (b"h00/go-semantic-provider-artifact/v2", *(value.encode() for value in sys.argv[1:])):
    hasher.update(struct.pack(">Q", len(field)))
    hasher.update(field)
print(hasher.hexdigest())
PY
)"
artifact_root="$cache_root/artifacts/$target/$build_key"
binary="$artifact_root/h00-go-semantic-provider"
receipt="$artifact_root/h00-go-semantic-provider.build.json"

if [[ ! -e "$artifact_root" ]]; then
    artifact_candidate="$(mktemp -d "$cache_root/artifacts/$target/artifact.XXXXXX")"
    output="$artifact_candidate/h00-go-semantic-provider"
    (
        cd -- "$gopls_root"
        CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        GOWORK=off GOENV=off GOTOOLCHAIN=local GOFLAGS=-mod=readonly \
        GOCACHE="$cache_root/build-cache/$target" \
        "$go_tool" build -trimpath -buildvcs=false \
            -ldflags "-s -w -buildid= -X golang.org/x/tools/gopls/internal/cmd.h00ProviderPatchSHA256=$patch_sha256" \
            -o "$output" .
    )
    [[ -x "$output" && -f "$output" && ! -L "$output" ]] || {
        echo "Go semantic-provider build produced no executable" >&2
        exit 1
    }
    [[ "$(tree_sha256 "$candidate")" == "$source_tree_sha256" ]] || {
        echo "Go provider source changed during compilation" >&2
        exit 1
    }
    verify_go_sdk_resolver
    binary_sha256="$(sha256sum "$output" | awk '{print $1}')"
    python3 - "$artifact_candidate/h00-go-semantic-provider.build.json" \
        "$build_key" "$target" "$goos" "$goarch" \
        "$go_sdk_version" "$sdk_filename" "$sdk_sha256" "$sdk_tree_sha256" \
        "$go_sdk_binary_sha256" "$go_identity" "$go_sdk_receipt_sha256" \
        "$go_sdk_resolver_sha256" "$go_sdk_cache_publisher_sha256" \
        "$gopls_version" "$gopls_sum" "$gopls_commit" \
        "$scip_version" "$scip_sum" "$scip_commit" \
        "$patch_sha256" "$source_tree_sha256" "$builder_sha256" \
        "$cache_publisher_sha256" "$binary_sha256" <<'PY'
import json
from pathlib import Path
import sys

(
    receipt, build_key, target, goos, goarch,
    go_sdk_version, go_sdk_filename, go_sdk_archive_sha256, go_sdk_tree_sha256,
    go_sdk_binary_sha256, go_identity, go_sdk_receipt_sha256,
    go_sdk_resolver_sha256, go_sdk_cache_publisher_sha256,
    gopls_version, gopls_sum, gopls_commit,
    scip_version, scip_sum, scip_commit,
    patch_sha256, source_tree_sha256, builder_sha256,
    cache_publisher_sha256, binary_sha256,
) = sys.argv[1:]
payload = {
    "schema": "h00/go-semantic-provider-artifact/v2",
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
    "gopls_version": gopls_version,
    "gopls_sum": gopls_sum,
    "gopls_commit": gopls_commit,
    "scip_go_version": scip_version,
    "scip_go_sum": scip_sum,
    "scip_go_commit": scip_commit,
    "patch_sha256": patch_sha256,
    "source_tree_sha256": source_tree_sha256,
    "builder_sha256": builder_sha256,
    "cache_publisher_sha256": cache_publisher_sha256,
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
    echo "Go provider artifact cache entry is invalid" >&2
    exit 1
fi

[[ -x "$binary" && -f "$receipt" && ! -L "$binary" && ! -L "$receipt" ]] || {
    echo "Go provider cached artifact is incomplete" >&2
    exit 1
}
binary_sha256="$(sha256sum "$binary" | awk '{print $1}')"
python3 - "$receipt" "$build_key" "$binary_sha256" "$patch_sha256" \
    "$go_sdk_version" "$sdk_filename" "$sdk_sha256" "$sdk_tree_sha256" \
    "$go_sdk_binary_sha256" "$go_identity" "$go_sdk_receipt_sha256" \
    "$go_sdk_resolver_sha256" "$go_sdk_cache_publisher_sha256" \
    "$cache_publisher_sha256" <<'PY'
import json
import sys

(
    receipt, build_key, binary_sha256, patch_sha256,
    go_sdk_version, go_sdk_filename, go_sdk_archive_sha256, go_sdk_tree_sha256,
    go_sdk_binary_sha256, go_identity, go_sdk_receipt_sha256,
    go_sdk_resolver_sha256, go_sdk_cache_publisher_sha256,
    cache_publisher_sha256,
) = sys.argv[1:]
payload = json.load(open(receipt, encoding="utf-8"))
if payload.get("schema") != "h00/go-semantic-provider-artifact/v2":
    raise SystemExit("Go provider receipt schema mismatch")
if payload.get("build_key") != build_key:
    raise SystemExit("Go provider build-key mismatch")
if payload.get("binary_sha256") != binary_sha256:
    raise SystemExit("Go provider binary digest mismatch")
if payload.get("patch_sha256") != patch_sha256:
    raise SystemExit("Go provider patch digest mismatch")
if payload.get("go_sdk_version") != go_sdk_version:
    raise SystemExit("Go provider SDK version mismatch")
if payload.get("go_sdk_filename") != go_sdk_filename:
    raise SystemExit("Go provider SDK filename mismatch")
if payload.get("go_sdk_archive_sha256") != go_sdk_archive_sha256:
    raise SystemExit("Go provider SDK archive digest mismatch")
if payload.get("go_sdk_tree_sha256") != go_sdk_tree_sha256:
    raise SystemExit("Go provider SDK tree digest mismatch")
if payload.get("go_sdk_binary_sha256") != go_sdk_binary_sha256:
    raise SystemExit("Go provider SDK executable digest mismatch")
if payload.get("go_identity") != go_identity:
    raise SystemExit("Go provider SDK identity mismatch")
if payload.get("go_sdk_receipt_sha256") != go_sdk_receipt_sha256:
    raise SystemExit("Go provider SDK receipt digest mismatch")
if payload.get("go_sdk_resolver_sha256") != go_sdk_resolver_sha256:
    raise SystemExit("Go provider SDK resolver digest mismatch")
if payload.get("go_sdk_cache_publisher_sha256") != go_sdk_cache_publisher_sha256:
    raise SystemExit("Go provider SDK cache-publisher digest mismatch")
if payload.get("cache_publisher_sha256") != cache_publisher_sha256:
    raise SystemExit("Go provider cache publisher digest mismatch")
PY
verify_cache_publisher
verify_go_sdk_resolver

if ((machine)); then
    printf 'H00_GO_PROVIDER_BINARY=%s\n' "$binary"
    printf 'H00_GO_PROVIDER_RECEIPT=%s\n' "$receipt"
    printf 'H00_GO_PROVIDER_BINARY_SHA256=%s\n' "$binary_sha256"
    printf 'H00_GO_PROVIDER_PATCH_SHA256=%s\n' "$patch_sha256"
    printf 'H00_GO_PROVIDER_SOURCE_TREE_SHA256=%s\n' "$source_tree_sha256"
    printf 'H00_GO_PROVIDER_BUILDER_SHA256=%s\n' "$builder_sha256"
    printf 'H00_GO_PROVIDER_CACHE_PUBLISHER_SHA256=%s\n' "$cache_publisher_sha256"
    printf 'H00_GO_SDK_RESOLVER_SHA256=%s\n' "$go_sdk_resolver_sha256"
    printf 'H00_GO_SDK_RECEIPT_SHA256=%s\n' "$go_sdk_receipt_sha256"
else
    printf '%s\n' "$binary"
fi
