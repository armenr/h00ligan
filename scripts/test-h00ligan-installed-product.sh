#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

script_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"

if [[ -z "${DEVBOX_PACKAGES_DIR:-}" ]]; then
    command -v devbox >/dev/null 2>&1 || {
        echo "installed h00ligan acceptance requires the repository's pinned Devbox" >&2
        exit 1
    }
    exec devbox run -- "$0" "$@"
fi

mkdir -p "$repo_root/target"
[[ -d "$repo_root/target" && ! -L "$repo_root/target" ]] || {
    echo "installed h00ligan test target root must be a real directory" >&2
    exit 1
}
test_tmp_parent="$repo_root/target/h00ligan-test-tmp"
mkdir -p "$test_tmp_parent"
[[ -d "$test_tmp_parent" && ! -L "$test_tmp_parent" ]] || {
    echo "installed h00ligan test temporary parent must be a real directory" >&2
    exit 1
}
owned_tmp_root="$(mktemp -d "$test_tmp_parent/installed-product.XXXXXX")"
export TMPDIR="$owned_tmp_root"
scratch_root="$owned_tmp_root/acceptance"
mkdir "$scratch_root"
process_baseline=""
process_reconciled=0
cleanup() {
    local status=$?
    if [[ "$process_reconciled" == 0 && -n "$process_baseline" && -f "$process_baseline" && -n "${binary:-}" ]]; then
        local cleanup_processes="$scratch_root/product-process-cleanup.json"
        if ! capture_product_processes "$cleanup_processes" || \
            ! process_population_comparator "$process_baseline" "$cleanup_processes"; then
            status=1
        fi
    fi
    [[ -n "${owned_tmp_root:-}" && -d "$owned_tmp_root" ]] && rm -rf -- "$owned_tmp_root"
    rmdir -- "$test_tmp_parent" 2>/dev/null || true
    trap - EXIT HUP INT TERM
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

binary="${H00_TEST_H00LIGAN_BINARY:-}"
receipt="${H00_TEST_H00LIGAN_RECEIPT:-}"
source_receipt="${H00_TEST_H00LIGAN_PRODUCT_SOURCE_RECEIPT:-}"
provider_details=""
binary_overridden=0
if [[ -z "$binary" ]]; then
    build_details="$("$repo_root/scripts/build-h00ligan-portable.sh" --machine)"
    provider_details="$build_details"
    binary="$(printf '%s\n' "$build_details" | sed -n 's/^H00LIGAN_BINARY=//p')"
    receipt="$(printf '%s\n' "$build_details" | sed -n 's/^H00LIGAN_RECEIPT=//p')"
    source_receipt="$(printf '%s\n' "$build_details" | sed -n 's/^H00LIGAN_PRODUCT_SOURCE_RECEIPT=//p')"
else
    binary_overridden=1
    [[ -n "$receipt" && -n "$source_receipt" ]] || {
        echo "H00_TEST_H00LIGAN_BINARY requires its artifact and product-source receipts" >&2
        exit 1
    }
fi
binary="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$binary")"
receipt="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$receipt")"
source_receipt="$(python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$source_receipt")"
[[ -x "$binary" ]] || {
    echo "installed h00ligan test binary is not executable: $binary" >&2
    exit 1
}
target="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["target"])' "$receipt")"
if ((binary_overridden)); then
    current_details="$("$repo_root/scripts/build-h00ligan-portable.sh" --prepare-only --machine)"
    provider_details="$current_details"
    current_source_key="$(printf '%s\n' "$current_details" | sed -n 's/^H00LIGAN_PRODUCT_SOURCE_KEY=//p')"
    receipt_source_key="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_key"])' "$source_receipt")"
    [[ -n "$current_source_key" && "$receipt_source_key" == "$current_source_key" ]] || {
        echo "installed h00ligan override does not match the current product-source snapshot" >&2
        exit 1
    }
fi
python_provider_binary="$(printf '%s\n' "$provider_details" | sed -n 's/^H00_PYREFLY_PROVIDER_BINARY=//p')"
python_provider_receipt="$(printf '%s\n' "$provider_details" | sed -n 's/^H00_PYREFLY_PROVIDER_RECEIPT=//p')"
[[ -x "$python_provider_binary" && -f "$python_provider_receipt" ]] || {
    echo "installed h00ligan gate lacks the exact embedded Pyrefly provider artifact" >&2
    exit 1
}
python3 "$repo_root/scripts/check-h00ligan-binary.py" \
    --binary "$binary" \
    --target "$target" \
    --receipt "$receipt" \
    --source-receipt "$source_receipt" \
    --forbid-path "$repo_root" \
    --forbid-path "$HOME" \
    --quiet

capture_product_processes() {
    local output_path="$1"
    python3 - "$binary" "$output_path" <<'PY'
import json
import os
import subprocess
import sys

binary = sys.argv[1]
output_path = sys.argv[2]
current = os.getpid()
population = []
for line in subprocess.run(
    ["ps", "-ww", "-axo", "pid=,ppid=,pgid=,lstart=,args="],
    check=True,
    capture_output=True,
    text=True,
).stdout.splitlines():
    fields = line.strip().split(maxsplit=8)
    if len(fields) != 9:
        continue
    pid = int(fields[0])
    parent_pid = int(fields[1])
    process_group = int(fields[2])
    started = " ".join(fields[3:8])
    command = fields[8]
    try:
        executable = __import__("shlex").split(command)[0]
    except (ValueError, IndexError):
        continue
    if int(pid) != current and os.path.realpath(executable) == binary:
        population.append(
            {
                "pid": pid,
                "parent_pid": parent_pid,
                "process_group": process_group,
                "started": started,
                "command": command,
            }
        )
population.sort(key=lambda process: (
    process["pid"], process["parent_pid"], process["process_group"],
    process["started"], process["command"]
))
with open(output_path, "w", encoding="utf-8") as output:
    json.dump(population, output, sort_keys=True)
    output.write("\n")
PY
}

process_population_comparator() {
    python3 - "$@" <<'PY'
import json
import sys


def identity(process):
    return (
        process["pid"], process["parent_pid"], process["process_group"],
        process["started"], process["command"],
    )


def new_identities(baseline, current):
    known = {identity(process) for process in baseline}
    return sorted(
        (process for process in current if identity(process) not in known),
        key=identity,
    )


if sys.argv[1:] == ["--self-test"]:
    first = {"pid": 101, "parent_pid": 90, "process_group": 101, "started": "Sat Aug 22 10:00:00 2026", "command": "h00ligan mcp-serve"}
    second = {"pid": 102, "parent_pid": 90, "process_group": 102, "started": "Sat Aug 22 10:00:01 2026", "command": "h00ligan watch"}
    if new_identities([first], [first]):
        raise SystemExit("identical process-population control failed")
    if new_identities([first, second], [first]):
        raise SystemExit("exited baseline-process control failed")
    if new_identities([first], [first, second]) != [second]:
        raise SystemExit("new-process sabotage did not fire exactly")
    raise SystemExit(0)

if len(sys.argv) != 3:
    raise SystemExit("usage: process_population_comparator BASELINE CURRENT")
with open(sys.argv[1], encoding="utf-8") as source:
    baseline = json.load(source)
with open(sys.argv[2], encoding="utf-8") as source:
    current = json.load(source)
if leaked := new_identities(baseline, current):
    raise SystemExit(f"installed h00ligan left new process residue: {leaked!r}")
PY
}

process_baseline="$scratch_root/product-process-baseline.json"
process_population_comparator --self-test
capture_product_processes "$process_baseline"
patch_sha256="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$repo_root/providers/rust-analyzer/rust-analyzer-1.97.1.patch")"

python3 "$repo_root/scripts/test-h00-rust-semantic-provider.py" \
    --binary "$binary" \
    --binary-arg __h00-internal-rust-provider \
    --patch-sha256 "$patch_sha256" \
    --scratch-root "$scratch_root/provider"

python3 "$repo_root/scripts/test-h00-pyrefly-semantic-provider.py" \
    --binary "$python_provider_binary" \
    --receipt "$python_provider_receipt" \
    --scratch-root "$scratch_root/python-provider"

directory_logical_bytes() {
    python3 - "$1" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
if root.is_symlink() or not root.is_dir():
    raise SystemExit(f"cache population is not a real directory: {root}")
total = 0
for path in root.rglob("*"):
    if path.is_symlink():
        raise SystemExit(f"cache population contains a symlink: {path}")
    if path.is_file():
        total += path.stat().st_size
print(total)
PY
}

cache_counter_probe="$scratch_root/cache-counter-positive"
mkdir "$cache_counter_probe"
cache_counter_before="$(directory_logical_bytes "$cache_counter_probe")"
printf 'cache-counter-positive\n' > "$cache_counter_probe/payload"
cache_counter_after="$(directory_logical_bytes "$cache_counter_probe")"
((cache_counter_after > cache_counter_before)) || {
    echo "TypeScript provider cache-growth counter positive control did not fire" >&2
    exit 1
}

python_compilation_cache="$repo_root/target/portable-cache/python-provider/compilation"
python_compilation_before="$(directory_logical_bytes "$python_compilation_cache")"
((python_compilation_before == 0)) || {
    echo "Pyrefly provider retained compiler cache residue before replay: $python_compilation_before bytes" >&2
    exit 1
}
python_repeat_details="$(
    "$repo_root/scripts/build-h00-pyrefly-semantic-provider.sh" \
        --target "$target" --machine
)"
python_compilation_after="$(directory_logical_bytes "$python_compilation_cache")"
((python_compilation_after == 0)) || {
    echo "Pyrefly provider retained compiler cache residue after replay: $python_compilation_after bytes" >&2
    exit 1
}
python_expected_sha256="$(printf '%s\n' "$provider_details" | sed -n 's/^H00_PYREFLY_PROVIDER_BINARY_SHA256=//p')"
python_repeated_sha256="$(printf '%s\n' "$python_repeat_details" | sed -n 's/^H00_PYREFLY_PROVIDER_BINARY_SHA256=//p')"
[[ "$python_expected_sha256" =~ ^[0-9a-f]{64}$ \
    && "$python_repeated_sha256" == "$python_expected_sha256" ]] || {
    echo "repeated Pyrefly provider build did not retain the exact artifact identity" >&2
    exit 1
}

typescript_host_test_cache="$repo_root/target/portable-cache/typescript-provider/build-cache/host-tests"
typescript_cache_before="$(directory_logical_bytes "$typescript_host_test_cache")"
typescript_repeat_details="$(
    "$repo_root/scripts/build-h00-typescript-semantic-provider.sh" \
        --target "$target" --machine
)"
typescript_cache_after="$(directory_logical_bytes "$typescript_host_test_cache")"
typescript_cache_delta=$((typescript_cache_after - typescript_cache_before))
typescript_cache_growth_limit=$((8 * 1024 * 1024))
((typescript_cache_delta >= 0 && typescript_cache_delta <= typescript_cache_growth_limit)) || {
    echo "repeated TypeScript provider build grew the host-test cache by $typescript_cache_delta bytes" >&2
    exit 1
}
typescript_expected_sha256="$(printf '%s\n' "$provider_details" | sed -n 's/^H00_TYPESCRIPT_PROVIDER_BINARY_SHA256=//p')"
typescript_repeated_sha256="$(printf '%s\n' "$typescript_repeat_details" | sed -n 's/^H00_TYPESCRIPT_PROVIDER_BINARY_SHA256=//p')"
[[ "$typescript_expected_sha256" =~ ^[0-9a-f]{64}$ \
    && "$typescript_repeated_sha256" == "$typescript_expected_sha256" ]] || {
    echo "repeated TypeScript provider build did not retain the exact artifact identity" >&2
    exit 1
}

build_authority_args=(--seed-binary "$binary" --target "$target")
rust_source_root="$(printf '%s\n' "$provider_details" | sed -n 's/^H00_RA_SOURCE_ROOT=//p')"
[[ -n "$rust_source_root" && -d "$rust_source_root" && ! -L "$rust_source_root" ]] || {
    echo "installed h00ligan gate lacks the builder's exact resolved Rust source root" >&2
    exit 1
}
rust_source_cache="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).parents[2])' "$rust_source_root")"
[[ -d "$rust_source_cache" && ! -L "$rust_source_cache" \
    && -f "$rust_source_cache/.h00-semantic-provider-source.json" \
    && ! -L "$rust_source_cache/.h00-semantic-provider-source.json" \
    && "$rust_source_root" == "$rust_source_cache/src/tools/rust-analyzer" ]] || {
    echo "installed h00ligan gate could not bind the resolved Rust source to its prepared cache" >&2
    exit 1
}
build_authority_args+=(--rust-source-cache "$rust_source_cache")
PYTHONDONTWRITEBYTECODE=1 python3 "$repo_root/scripts/test-h00ligan-build-authority.py" \
    "${build_authority_args[@]}"

export H00_TEST_H00LIGAN_BINARY="$binary"
cargo test --locked --offline -p h00ligan \
    --test installed_one_file_mcp \
    installed_go_callable_liveness_distinguishes_callback_dispatch_from_unreached_code -- \
    --exact --ignored --nocapture --test-threads=1

cargo test --locked --offline -p h00ligan \
    --test installed_one_file_mcp \
    installed_go_callable_liveness_normalizes_build_exclusions -- \
    --exact --ignored --nocapture --test-threads=1

cargo test --locked --offline -p h00ligan \
    --test installed_one_file_mcp \
    installed_one_file_cli_and_mcp_share_exact_semantic_authority -- \
    --exact --ignored --nocapture --test-threads=1

cargo test --locked --offline -p h00ligan \
    --test installed_one_file_mcp \
    installed_typescript_cli_and_mcp_need_no_ambient_toolchain -- \
    --exact --ignored --nocapture --test-threads=1

cargo test --locked --offline -p h00ligan \
    --test installed_one_file_mcp \
    installed_python_cli_and_mcp_need_no_ambient_toolchain -- \
    --exact --ignored --nocapture --test-threads=1

cargo test --locked --offline -p h00ligan \
    --test installed_one_file_mcp \
    installed_javascript_jsx_and_pnpm_share_exact_semantic_authority -- \
    --exact --ignored --nocapture --test-threads=1

cargo test --locked --offline -p h00ligan \
    --test multimodule_root_contract \
    installed_multiroot_go_index_overlaps_independent_provider_processes -- \
    --exact --ignored --nocapture --test-threads=1

watch_tests=(
    installed_typescript_watch_source_and_configuration_lifecycle_matches_full_baselines
    installed_python_watch_source_and_configuration_lifecycle_matches_full_baselines
    installed_mixed_watch_does_not_rerun_go_for_a_rust_only_edit
    installed_go_watch_body_edit_reuses_one_session_with_full_baseline_parity
    installed_go_watch_import_change_succeeds_in_first_reconciliation
    installed_go_build_variant_is_explicitly_qualified
    installed_go_workspace_watch_does_not_rerun_an_unchanged_module
    installed_go_workspace_watch_recovers_exact_basis_after_process_restart
    installed_independent_go_project_input_change_reuses_only_affected_root
    installed_nested_go_workspace_inputs_reconfigure_warm
    installed_one_file_watch_recertifies_hidden_cargo_configuration
    installed_one_file_watch_reloads_changed_build_script_semantics
    installed_one_file_watch_reloads_changed_build_input_semantics
    installed_one_file_watch_reloads_hidden_declared_build_input_semantics
    installed_one_file_status_detects_persisted_build_input_drift
    installed_one_file_refuses_weaker_rust_fallback_after_health_failure
)
for test_name in "${watch_tests[@]}"; do
    cargo test --locked --offline -p h00ligan \
        --test watch_lifecycle "$test_name" -- \
        --exact --ignored --nocapture --test-threads=1
done

process_after="$scratch_root/product-process-after.json"
capture_product_processes "$process_after"
process_population_comparator "$process_baseline" "$process_after"
process_reconciled=1
printf 'installed-h00ligan-product: OK (receipted build authority, hidden provider, MCP, provider concurrency, %d WATCH lifecycles; zero new process residue)\n' "${#watch_tests[@]}"
