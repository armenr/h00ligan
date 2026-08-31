#!/usr/bin/env bash
set -euo pipefail

script_path="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "${BASH_SOURCE[0]}")"
script_dir="$(cd -- "$(dirname "$script_path")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
cache_publisher_live="$repo_root/scripts/publish-h00ligan-cache-directory.py"

if [[ -z "${DEVBOX_PACKAGES_DIR:-}" ]]; then
    command -v devbox >/dev/null 2>&1 || {
        echo "official Go SDK resolution requires the repository's pinned Devbox" >&2
        exit 1
    }
    exec devbox run -- "$script_path" "$@"
fi

if (($# != 0)); then
    echo "Usage: scripts/resolve-h00-official-go-sdk.sh" >&2
    exit 2
fi

# Latest stable Go release and official distribution checksums were verified
# against go.dev/dl on 2026-08-23. Provider builders consume these exact
# upstream SDK bytes instead of a distribution-patched host compiler.
go_sdk_version="go1.27.0"
case "$(uname -s):$(uname -m)" in
    Linux:x86_64)
        sdk_filename="$go_sdk_version.linux-amd64.tar.gz"
        sdk_sha256="675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685"
        ;;
    Linux:aarch64 | Linux:arm64)
        sdk_filename="$go_sdk_version.linux-arm64.tar.gz"
        sdk_sha256="51798d2c42d0e1c6ed7fd9f48728b4193abac9e8aad6dbac2fe96a81f5909bda"
        ;;
    Darwin:x86_64)
        sdk_filename="$go_sdk_version.darwin-amd64.tar.gz"
        sdk_sha256="d3314e25496e4381d71a5c51d2907e7af655d199f6780b549f015bd85fef4986"
        ;;
    Darwin:arm64 | Darwin:aarch64)
        sdk_filename="$go_sdk_version.darwin-arm64.tar.gz"
        sdk_sha256="90493b3bbd5e10f91d12153198bf1994fd756399b4fec93b49b0c6e2acdeeb3e"
        ;;
    *)
        echo "unsupported host for the official Go SDK" >&2
        exit 1
        ;;
esac

sdk_url="https://go.dev/dl/$sdk_filename"
cache_root="$repo_root/target/portable-cache/go-sdk"
archive_root="$cache_root/archives"
artifact_parent="$cache_root/artifacts"
candidate_root="$cache_root/candidates"
tmp_root="$cache_root/tmp"
mkdir -p "$archive_root" "$artifact_parent" "$candidate_root" "$tmp_root"
for path in "$cache_root" "$archive_root" "$artifact_parent" "$candidate_root" "$tmp_root"; do
    [[ -d "$path" && ! -L "$path" ]] || {
        echo "official Go SDK cache path must be a real directory: $path" >&2
        exit 1
    }
done

candidate=""
download=""
invocation_root=""
cleanup() {
    [[ -z "$candidate" || ! -d "$candidate" ]] || rm -rf -- "$candidate"
    [[ -z "$download" || ! -f "$download" ]] || rm -f -- "$download"
    [[ -z "$invocation_root" || ! -d "$invocation_root" ]] || rm -rf -- "$invocation_root"
}
trap cleanup EXIT HUP INT TERM

invocation_root="$(mktemp -d "$tmp_root/invocation.XXXXXX")"
cache_publisher="$invocation_root/publish-h00ligan-cache-directory.py"
install -m 0500 "$cache_publisher_live" "$cache_publisher"
cache_publisher_sha256="$(sha256sum "$cache_publisher" | awk '{print $1}')"
resolver_sha256="$(sha256sum "$script_path" | awk '{print $1}')"

verify_live_inputs() {
    [[ "$(sha256sum "$script_path" | awk '{print $1}')" == "$resolver_sha256" \
        && "$(sha256sum "$cache_publisher_live" | awk '{print $1}')" == "$cache_publisher_sha256" \
        && "$(sha256sum "$cache_publisher" | awk '{print $1}')" == "$cache_publisher_sha256" ]] || {
        echo "official Go SDK resolver inputs changed during resolution" >&2
        exit 1
    }
}
verify_live_inputs

archive="$archive_root/$sdk_filename"
if [[ ! -e "$archive" ]]; then
    command -v curl >/dev/null 2>&1 || {
        echo "curl is required to acquire the pinned official Go SDK" >&2
        exit 1
    }
    download="$(mktemp "$archive_root/$sdk_filename.download.XXXXXX")"
    curl --fail --location --proto '=https' --tlsv1.2 "$sdk_url" --output "$download"
    [[ "$(sha256sum "$download" | awk '{print $1}')" == "$sdk_sha256" ]] || {
        echo "official Go SDK checksum mismatch: $sdk_filename" >&2
        exit 1
    }
    if [[ ! -e "$archive" ]]; then
        mv "$download" "$archive"
    fi
    download=""
fi
[[ -f "$archive" && ! -L "$archive" ]] || {
    echo "official Go SDK archive cache entry is invalid" >&2
    exit 1
}
[[ "$(sha256sum "$archive" | awk '{print $1}')" == "$sdk_sha256" ]] || {
    echo "cached official Go SDK checksum mismatch: $sdk_filename" >&2
    exit 1
}

artifact_root="$artifact_parent/$sdk_sha256"
receipt_name=".h00-official-go-sdk.json"
tree_sha256() {
    python3 - "$1" "$receipt_name" <<'PY'
import hashlib
from pathlib import Path
import stat
import struct
import sys

root, receipt_name = Path(sys.argv[1]), sys.argv[2]
hasher = hashlib.sha256()
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    relative = path.relative_to(root).as_posix()
    if relative == receipt_name:
        continue
    if path.is_symlink():
        raise SystemExit(f"official Go SDK contains a symlink: {relative}")
    if path.is_dir():
        continue
    if not path.is_file():
        raise SystemExit(f"official Go SDK contains an unsupported entry: {relative}")
    fields = (
        relative.encode(),
        stat.S_IMODE(path.stat().st_mode).to_bytes(4, "big"),
        path.read_bytes(),
    )
    for field in fields:
        hasher.update(struct.pack(">Q", len(field)))
        hasher.update(field)
print(hasher.hexdigest())
PY
}

if [[ ! -e "$artifact_root" ]]; then
    candidate="$(mktemp -d "$candidate_root/sdk.XXXXXX")"
    python3 - "$archive" "$candidate" <<'PY'
from pathlib import Path, PurePosixPath
import sys
import tarfile

archive, destination = Path(sys.argv[1]), Path(sys.argv[2])
with tarfile.open(archive, "r:gz") as source:
    members = source.getmembers()
    if not members:
        raise SystemExit("official Go SDK archive is empty")
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "go":
            raise SystemExit(f"unsafe official Go SDK archive path: {member.name}")
        if not (member.isfile() or member.isdir()):
            raise SystemExit(f"unsupported official Go SDK archive entry: {member.name}")
    source.extractall(destination, filter="data")
PY
    sdk_candidate="$candidate/go"
    go_candidate="$sdk_candidate/bin/go"
    [[ -x "$go_candidate" && -f "$go_candidate" && ! -L "$go_candidate" ]] || {
        echo "official Go SDK archive has no real go executable" >&2
        exit 1
    }
    go_identity="$("$go_candidate" version)"
    [[ "$go_identity" == go\ version\ "$go_sdk_version"* ]] || {
        echo "official Go SDK version mismatch: $go_identity" >&2
        exit 1
    }
    sdk_tree_sha256="$(tree_sha256 "$sdk_candidate")"
    go_binary_sha256="$(sha256sum "$go_candidate" | awk '{print $1}')"
    python3 - "$sdk_candidate/$receipt_name" "$go_sdk_version" "$sdk_filename" \
        "$sdk_url" "$sdk_sha256" "$sdk_tree_sha256" "$go_binary_sha256" \
        "$go_identity" <<'PY'
import json
from pathlib import Path
import sys

(
    receipt, version, filename, url, archive_sha256, tree_sha256,
    go_binary_sha256, go_identity,
) = sys.argv[1:]
payload = {
    "schema": "h00/official-go-sdk/v1",
    "version": version,
    "filename": filename,
    "url": url,
    "archive_sha256": archive_sha256,
    "tree_sha256": tree_sha256,
    "go_binary_sha256": go_binary_sha256,
    "go_identity": go_identity,
}
Path(receipt).write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
PY
    python3 "$cache_publisher" publish \
        --owner-root "$cache_root" \
        --candidate "$sdk_candidate" \
        --destination "$artifact_root" >/dev/null
    rmdir "$candidate"
    candidate=""
elif [[ ! -d "$artifact_root" || -L "$artifact_root" ]]; then
    echo "official Go SDK artifact cache entry is invalid" >&2
    exit 1
fi

go_tool="$artifact_root/bin/go"
receipt="$artifact_root/$receipt_name"
[[ -x "$go_tool" && -f "$receipt" && ! -L "$go_tool" && ! -L "$receipt" ]] || {
    echo "official Go SDK artifact is incomplete" >&2
    exit 1
}
go_identity="$("$go_tool" version)"
sdk_tree_sha256="$(tree_sha256 "$artifact_root")"
go_binary_sha256="$(sha256sum "$go_tool" | awk '{print $1}')"
python3 - "$receipt" "$go_sdk_version" "$sdk_filename" "$sdk_url" \
    "$sdk_sha256" "$sdk_tree_sha256" "$go_binary_sha256" "$go_identity" <<'PY'
import json
import sys

(
    receipt, version, filename, url, archive_sha256, tree_sha256,
    go_binary_sha256, go_identity,
) = sys.argv[1:]
payload = json.load(open(receipt, encoding="utf-8"))
expected = {
    "schema": "h00/official-go-sdk/v1",
    "version": version,
    "filename": filename,
    "url": url,
    "archive_sha256": archive_sha256,
    "tree_sha256": tree_sha256,
    "go_binary_sha256": go_binary_sha256,
    "go_identity": go_identity,
}
if payload != expected:
    raise SystemExit("official Go SDK receipt does not describe the cached tree")
PY
verify_live_inputs
receipt_sha256="$(sha256sum "$receipt" | awk '{print $1}')"

printf 'H00_GO_SDK_TOOL=%s\n' "$go_tool"
printf 'H00_GO_SDK_VERSION=%s\n' "$go_sdk_version"
printf 'H00_GO_SDK_FILENAME=%s\n' "$sdk_filename"
printf 'H00_GO_SDK_ARCHIVE_SHA256=%s\n' "$sdk_sha256"
printf 'H00_GO_SDK_TREE_SHA256=%s\n' "$sdk_tree_sha256"
printf 'H00_GO_SDK_BINARY_SHA256=%s\n' "$go_binary_sha256"
printf 'H00_GO_SDK_IDENTITY=%s\n' "$go_identity"
printf 'H00_GO_SDK_RECEIPT=%s\n' "$receipt"
printf 'H00_GO_SDK_RECEIPT_SHA256=%s\n' "$receipt_sha256"
printf 'H00_GO_SDK_RESOLVER_SHA256=%s\n' "$resolver_sha256"
printf 'H00_GO_SDK_CACHE_PUBLISHER_SHA256=%s\n' "$cache_publisher_sha256"
