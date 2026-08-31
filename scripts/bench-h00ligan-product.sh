#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"

if [[ -z "${DEVBOX_PACKAGES_DIR:-}" ]]; then
    command -v devbox >/dev/null 2>&1 || {
        echo "h00ligan performance requires the repository's pinned Devbox" >&2
        exit 1
    }
    exec devbox run -- "$0" "$@"
fi

mode="${1:-smoke}"
case "$mode" in
    smoke | full) ;;
    *)
        echo "usage: $0 [smoke|full] [bench-h00ligan.py arguments...]" >&2
        exit 2
        ;;
esac
shift || true

build_details="$("$repo_root/scripts/build-h00ligan-portable.sh" --machine)"
binary="$(printf '%s\n' "$build_details" | sed -n 's/^H00LIGAN_BINARY=//p')"
receipt="$(printf '%s\n' "$build_details" | sed -n 's/^H00LIGAN_RECEIPT=//p')"
source_receipt="$(printf '%s\n' "$build_details" | sed -n 's/^H00LIGAN_PRODUCT_SOURCE_RECEIPT=//p')"

[[ -n "$binary" && -n "$receipt" && -n "$source_receipt" ]] || {
    echo "portable builder did not return the complete artifact receipt population" >&2
    exit 1
}
target="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["target"])' "$receipt")"
python3 "$repo_root/scripts/check-h00ligan-binary.py" \
    --binary "$binary" \
    --target "$target" \
    --receipt "$receipt" \
    --source-receipt "$source_receipt" \
    --forbid-path "$repo_root" \
    --forbid-path "$HOME" \
    --quiet

bench_arguments=(--summary)
output_selected=false
for argument in "$@"; do
    if [[ "$argument" == "--output" || "$argument" == --output=* ]]; then
        output_selected=true
        break
    fi
done
if [[ "$output_selected" == false ]]; then
    bench_arguments+=(
        --output "$repo_root/.h00ligan/performance/h00ligan-${mode}-latest.json"
    )
fi

exec env PYTHONDONTWRITEBYTECODE=1 python3 "$repo_root/scripts/bench-h00ligan.py" \
    --binary "$binary" \
    --receipt "$receipt" \
    --source-receipt "$source_receipt" \
    --mode "$mode" \
    "${bench_arguments[@]}" \
    "$@"
