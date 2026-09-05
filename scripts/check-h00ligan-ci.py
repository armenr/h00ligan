#!/usr/bin/env python3
"""Keep the fast h00ligan gate narrow, complete, and non-vacuous."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path


CLIPPY_COMMANDS = (
    "cargo clippy --locked --offline --workspace --all-targets --all-features "
    "-- -D warnings",
)

TEST_COMMANDS = (
    "cargo test --locked --offline --workspace --all-targets --all-features "
    "-- --test-threads=1",
)

CI_DEPENDENCIES = (
    "ci-contract",
    "portability-check",
    "fmt-check",
    "check",
    "lint",
    "test",
    "deps-check",
    "release-check",
)
CI_PRODUCT_DEPENDENCIES = (
    "ci-product-preflight",
    "ci",
    "test-installed",
    "perf-smoke",
)
CI_PREFLIGHT_COMMAND = (
    "PYTHONDONTWRITEBYTECODE=1 python3 "
    "scripts/emit-h00ligan-ci-product-receipt.py --begin "
    "--source-preflight .h00ligan/gates/ci-product-source-preflight.json"
)
CI_RECEIPT_SELF_TEST_COMMAND = (
    "PYTHONDONTWRITEBYTECODE=1 python3 "
    "scripts/emit-h00ligan-ci-product-receipt.py --self-test"
)
CI_COMPLETION_COMMAND = (
    "PYTHONDONTWRITEBYTECODE=1 python3 "
    "scripts/emit-h00ligan-ci-product-receipt.py "
    "--benchmark-report .h00ligan/performance/h00ligan-smoke-latest.json "
    "--source-preflight .h00ligan/gates/ci-product-source-preflight.json"
)

ACTIONLINT_VERSION_COMMAND = (
    'test "$(actionlint -version | sed -n \'1p\')" = \'1.7.12\''
)
SHELLCHECK_VERSION_COMMAND = (
    "shellcheck --version | grep -Fx 'version: 0.11.0'"
)
ACTIONLINT_COMMAND = "actionlint -color"

LINUX_LINT_STEP = "- name: Strict lint"
LINUX_CLEAN_STEP = "- name: Reclaim compiler artifacts before test linking"
LINUX_CLEAN_COMMAND = "run: devbox run -- cargo clean --profile dev"
LINUX_TEST_STEP = "- name: Serial source and real-process tests"

RELEASE_REQUIRED_COMMANDS = (
    ACTIONLINT_VERSION_COMMAND,
    SHELLCHECK_VERSION_COMMAND,
    ACTIONLINT_COMMAND,
    "PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-conventional-commits.py --self-test",
    "PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-action-pins.py --self-test",
    "PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-action-pins.py",
    "PYTHONDONTWRITEBYTECODE=1 python3 scripts/normalize-h00ligan-sbom.py --self-test",
    "PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-h00ligan-sbom.py --self-test",
    "PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-h00ligan-release.py",
    "scripts/package-h00ligan-release.sh --self-test",
    "shellcheck .githooks/commit-msg scripts/bench-h00ligan-product.sh "
    "scripts/build-h00-go-semantic-provider.sh scripts/build-h00-pyrefly-semantic-provider.sh "
    "scripts/build-h00-rust-semantic-provider.sh "
    "scripts/build-h00-typescript-semantic-provider.sh scripts/build-h00ligan-portable.sh "
    "scripts/package-h00ligan-release.sh scripts/resolve-h00-official-go-sdk.sh "
    "scripts/test-h00ligan-installed-product.sh",
)

PERFORMANCE_HARNESS_REQUIRED_FRAGMENTS = (
    'SCHEMA_VERSION = "h00/h00ligan-performance/v4"',
    'GO_PROVIDER_ID = "h00-gopls-scip"',
    'PYTHON_PROVIDER_ID = "h00-pyrefly-scip"',
    'TYPESCRIPT_PROVIDER_ID = "h00-typescript-native-scip"',
    'DEFAULT_ABSOLUTE_TOLERANCE_MS = 5.0',
    'benchmark_process_startup(',
    '"metrics.process_startup"',
    '"--require-complete-calls"',
    '"--profile"',
    "validate_complete_status(status)",
    "validate_calls(baseline_rust, language=\"rust\")",
    "validate_calls(baseline_go, language=\"go\")",
    "validate_calls(baseline_python, language=\"python\")",
    "validate_calls(baseline_typescript, language=\"typescript\")",
    "McpSession(binary, root, data_dir, environment)",
    "process_population(executables)",
    "direct_provider_identity(",
    "wait_for_no_new_processes(",
    'raise HarnessError("benchmark fixture was not restored byte-exactly")',
    'f"performance battery left process residue: {leaked!r}"',
    'parser.add_argument("--baseline", type=Path)',
)
PERFORMANCE_HARNESS_FORBIDDEN_FRAGMENTS = (
    'shutil.which("scip-go")',
    '"go_provider": "scip-go"',
)

PERFORMANCE_WRAPPER_REQUIRED_FRAGMENTS = (
    'exec devbox run -- "$0" "$@"',
    'build-h00ligan-portable.sh" --machine',
    'check-h00ligan-binary.py"',
    '--forbid-path "$repo_root"',
    '--forbid-path "$HOME"',
    'bench-h00ligan.py"',
)

PORTABLE_BUILDER_REQUIRED_FRAGMENTS = (
    "H00LIGAN_BUILDER_INVOCATION_ROOT",
    "H00LIGAN_BUILDER_INVOCATION_TOKEN",
    '"$invocation_root/.h00-invocation-token"',
    "portable h00ligan builder lacks a valid private handoff",
    'install -m 0755 "$live_script" "$invocation_root/build-h00ligan.sh"',
    "H00_RA_SOURCE_KEY=",
    "H00_RA_BUILDER_SHA256=",
    "H00_PYREFLY_SOURCE_KEY=",
    "H00_PYREFLY_BUILDER_SHA256=",
    "H00_PYREFLY_ARCHIVE_SHA256=",
    'product_lockfile_live="$repo_root/providers/rust-analyzer/h00ligan-product.Cargo.lock"',
    'b"h00/h00ligan-product-source/v6"',
    'provider_adapter_template_live="$repo_root/providers/rust-analyzer/h00ligan-provider-adapter.Cargo.toml.in"',
    'provider_adapter_root="$product_candidate/rust-provider"',
    'binary_checker="$product_root/.h00-build-inputs/check-h00ligan-binary.py"',
    'cargo_generation_manager="$product_root/.h00-build-inputs/manage-h00ligan-cargo-generation.py"',
    'cargo_generation_receipt="$portable_workspace_parent/$target.cargo-generation.json"',
    'go_cache_publisher_live="$repo_root/scripts/publish-h00ligan-cache-directory.py"',
    'go_provider_cache_publisher_sha256=',
    'install -m 0644 "$go_cache_publisher_live" "$build_inputs/publish-h00ligan-cache-directory.py"',
    'semantic-provider cache publisher changed after provider publication',
    'verify_provider_source',
    'verify_python_provider_source',
    'H00_PYREFLY_PROVIDER_BINARY=',
    'H00_PYREFLY_PROVIDER_BINARY_SHA256=',
    'H00_PYREFLY_SOURCE_TREE_SHA256=',
    'H00_PYREFLY_CACHE_PUBLISHER_SHA256=',
    'python_provider_receipt_sha256=',
    '--remap-path-prefix=$portable_cache_root=portable-product-cache',
    'install -m 0644 "$product_lockfile_live" "$build_inputs/h00ligan-product.Cargo.lock"',
    'product_source_inputs=(',
    '"$build_inputs/h00ligan-product-source-inputs"',
    'source_manifest = inputs / "h00ligan-product-source-inputs"',
    'verify_live_product_inputs "$product_candidate"',
    'product_root="$portable_cache_root/product-source-$product_source_key"',
    'install -m 0644 "$build_inputs/h00ligan-product.Cargo.lock" "$product_crate_root/Cargo.lock"',
    'verify_product_workspace "$product_root" "$product_source_key" verify',
    'mv "$product_candidate" "$product_root"',
    'artifact_root="$artifact_parent/$artifact_build_key"',
    '"schema": "h00/h00ligan-portable-artifact/v3"',
    'acquire_target_build_lock',
    'python3 "$cargo_generation_manager" prepare',
    'install -m 0755 "$built_binary" "$artifact_candidate/h00ligan"',
    'mv "$artifact_candidate" "$artifact_root"',
    'python3 "$cargo_generation_manager" record',
    '--receipt "$artifact_receipt"',
    "H00LIGAN_PRODUCT_MANIFEST=",
    "H00LIGAN_PRODUCT_LOCKFILE=",
    "H00LIGAN_PRODUCT_SOURCE_RECEIPT=",
    "H00LIGAN_ARTIFACT_BUILD_KEY=",
    '"../source/crates/h00ligan"',
    'export H00_BUILD_SOURCE_REVISION="$source_revision"',
    'export H00_GO_PROVIDER_BINARY_SHA256="$go_provider_binary_sha256"',
    'export H00_PYREFLY_PATCH_SHA256="$python_provider_patch_sha256"',
    '[[ -n "$test_root" && -d "$test_root" && ! -L "$test_root" ]]',
    "authority-test artifacts are non-distributable and cannot be installed",
)

PORTABLE_BUILDER_FORBIDDEN_FRAGMENTS = (
    'mktemp -d "${TMPDIR:-/tmp}/h00ligan-product.',
    '"$test_root" == /tmp/*',
    "generate-lockfile",
    "str(repo).encode()",
    '\nbinary="$portable_target_dir/$target/release/h00ligan"',
    'b"h00/h00ligan-product-source/v3"',
    'b"h00/h00ligan-product-source/v4"',
    'b"h00/h00ligan-product-source/v5"',
    'cp -a "$repo_root/crates/$product_crate"',
    'cp -a "$provider_source_root/."',
    '--remap-path-prefix=$product_root=embedded-provider-source',
    'python3 "$repo_root/scripts/check-h00ligan-binary.py"',
)

PORTABLE_PRODUCT_LOCK = Path(
    "providers/rust-analyzer/h00ligan-product.Cargo.lock"
)
PORTABLE_LOCK_REQUIRED_PACKAGES = (
    "h00ligan",
    "h00ligan-product",
    "h00ligan-ra-provider",
    "h00ligan-provider-protocol",
)
PORTABLE_LOCK_DIRECT_DEPENDENCIES = (
    "h00ligan",
    "h00ligan-provider-protocol",
    "h00ligan-ra-provider",
)

PROVIDER_BUILDER_REQUIRED_FRAGMENTS = (
    "H00_RA_BUILDER_INVOCATION_ROOT",
    'install -m 0755 "$live_script" "$invocation_root/build-provider.sh"',
    'input_root="$invocation_root/inputs"',
    'b"h00/rust-semantic-provider-source/v2"',
    "verify_live_inputs",
    "semantic-provider source-cache root must be a real directory",
    '"builder_sha256": builder_sha256',
    "H00_RA_BUILDER_SHA256=",
    'authority_test_root="${H00_RA_BUILD_TEST_ROOT:-}"',
    "--prepared-source-cache",
    "rust_source_from_cli",
    "expected_authority_test",
    "prepared semantic-provider source cache is incompatible with current inputs",
)

PROVIDER_BUILDER_FORBIDDEN_FRAGMENTS = (
    'b"h00/rust-semantic-provider-source/v1"',
    '"schema": "h00/rust-semantic-provider-source-cache/v1"',
    '"schema": "h00/rust-semantic-provider-build/v1"',
)

PYREFLY_BUILDER_REQUIRED_FRAGMENTS = (
    'default_target="x86_64-unknown-linux-musl"',
    'default_target="aarch64-unknown-linux-musl"',
    'target="${requested_target:-$default_target}"',
    'compilation_parent="$cache_root/compilation"',
    'compilation_root="$(mktemp -d "$compilation_parent/build.XXXXXX")"',
    'CARGO_TARGET_DIR="$compilation_root" cargo "+$rust_version" test',
    'CARGO_TARGET_DIR="$compilation_root" cargo "+$rust_version" zigbuild',
    'CARGO_TARGET_DIR="$compilation_root" cargo "+$rust_version" build',
    'rm -rf -- "$compilation_root"',
    'compilation_root=""',
    'H00LIGAN_CACHE_LOCK_FD',
    'locked-exec',
    'verify-lock',
    'prune_interrupted_cache_roots',
    'prune_interrupted_invocation',
)

PYREFLY_BUILDER_FORBIDDEN_FRAGMENTS = (
    'CARGO_TARGET_DIR="$cache_root/tests/$source_key"',
    'build_target="$build_target/$target/$build_key"',
    'source_lock="$source_root.lock"',
    "Pyrefly stale source lock",
)

INSTALLED_GATE_REQUIRED_FRAGMENTS = (
    "export PYTHONDONTWRITEBYTECODE=1",
    "cleanup() {",
    "trap cleanup EXIT",
    'owned_tmp_root="$(mktemp -d "$test_tmp_parent/installed-product.XXXXXX")"',
    'scripts/build-h00ligan-portable.sh" --machine',
    "--binary-arg __h00-internal-rust-provider",
    "H00_PYREFLY_PROVIDER_BINARY=",
    "H00_PYREFLY_PROVIDER_RECEIPT=",
    "scripts/test-h00-pyrefly-semantic-provider.py",
    "H00_TEST_H00LIGAN_BINARY=",
    "installed_go_callable_liveness_distinguishes_callback_dispatch_from_unreached_code",
    "installed_go_callable_liveness_normalizes_build_exclusions",
    "installed_go_build_tags_select_test_documents_and_bind_generation_reuse",
    "installed_one_file_cli_and_mcp_share_exact_semantic_authority",
    "installed_rust_linked_worktree_refuses_nonreciprocal_git_authority",
    "installed_python_cli_and_mcp_need_no_ambient_toolchain",
    "installed_one_file",
    '"ps", "-ww", "-axo", "pid=,ppid=,pgid=,lstart=,args="',
    "process_population_comparator --self-test",
    'product-process-baseline.json',
    'process_population_comparator "$process_baseline" "$process_after"',
    'H00_TEST_H00LIGAN_RECEIPT',
    'H00_TEST_H00LIGAN_PRODUCT_SOURCE_RECEIPT',
    'scripts/check-h00ligan-binary.py',
    'scripts/test-h00ligan-build-authority.py',
    '--rust-source-cache "$rust_source_cache"',
    "could not bind the resolved Rust source to its prepared cache",
    'python_compilation_cache="$repo_root/target/portable-cache/python-provider/compilation"',
    "Pyrefly provider retained compiler cache residue",
    "Pyrefly provider accepted a forged inherited compiler lock",
    "Pyrefly interrupted-cache residue positive control did not fire",
    "Pyrefly provider retained interrupted cache residue after replay",
    "repeated Pyrefly provider build did not retain the exact artifact identity",
    'watch_test_source="$repo_root/crates/h00ligan/tests/watch_lifecycle.rs"',
    'declared_watch_population="$(',
    'discovered_watch_population="$(',
    "-- --list --ignored",
    '[[ -n "$declared_watch_population" ]]',
    '[[ "$declared_watch_population" == "$discovered_watch_population" ]]',
    "installed WATCH declaration/discovery mismatch",
    "while IFS= read -r test_name; do",
    '--test watch_lifecycle "$test_name"',
    "watch_test_count=$((watch_test_count + 1))",
)

INSTALLED_WATCH_REQUIRED_TESTS = (
    "installed_typescript_watch_source_and_configuration_lifecycle_matches_full_baselines",
    "installed_python_watch_source_and_configuration_lifecycle_matches_full_baselines",
    "installed_staged_python_watch_reuses_rust_and_owns_both_publications",
    "installed_mixed_watch_does_not_rerun_go_for_a_rust_only_edit",
    "installed_go_watch_body_edit_reuses_one_session_with_full_baseline_parity",
    "installed_go_watch_import_change_succeeds_in_first_reconciliation",
    "installed_go_build_variant_is_explicitly_qualified",
    "installed_go_workspace_watch_does_not_rerun_an_unchanged_module",
    "installed_go_workspace_watch_recovers_exact_basis_after_process_restart",
    "installed_independent_go_project_input_change_reuses_only_affected_root",
    "installed_nested_go_workspace_inputs_reconfigure_warm",
    "installed_one_file_watch_recertifies_hidden_cargo_configuration",
    "installed_one_file_watch_reloads_changed_build_script_semantics",
    "installed_one_file_watch_reloads_changed_build_input_semantics",
    "installed_one_file_watch_reloads_hidden_declared_build_input_semantics",
    "installed_one_file_status_detects_persisted_build_input_drift",
    "installed_one_file_refuses_weaker_rust_fallback_after_health_failure",
)

PYREFLY_PROVIDER_TEST_REQUIRED_FRAGMENTS = (
    'caller_before.replace(b"targetA()\\n", b"targetB()\\n")',
    "Pyrefly affected refresh retained stale targetA call evidence",
    "Pyrefly affected refresh omitted fresh targetB call",
    '"persistent_epoch_replaced_call_target": True',
    '"foreign_session_failed_closed": True',
    '"replay_failed_closed": True',
    '"source_bytes_unchanged": True',
    '"stale_authority_failed_closed": True',
)

BUILD_AUTHORITY_REQUIRED_FRAGMENTS = (
    'dir=os.environ.get("TMPDIR")',
    "prove_cargo_mtime_hazard_is_live(scratch)",
    'rebound_workspace / "product/src/main.rs"',
    "stable workspace preserved historical mtime for changed Cargo input",
    "authority-test product was installable instead of non-distributable",
    "ambient private-handoff forgery did not fail for the intended reason",
    "unverified invocation root was destructively cleaned",
    '"H00_RA_BUILD_TEST_ROOT": str(repo.parent)',
    "provider post-snapshot drift did not fail for the intended reason",
    "post-snapshot drift did not fail for the intended reason",
    'with_suffix(".contended")',
    "second build reached mutable output while first held the lock",
    "distinct source identities shared one artifact path",
    "test artifact was accepted as a distributable artifact",
    "identical build identity did not reuse its immutable artifact",
    "non-product test populations entered the portable product source key",
    "portable builder left new invocation residue",
    "validate_prepared_source_cache(rust_source_cache)",
    '"--prepared-source-cache"',
    "prepared Rust source cache receipt is not production authority",
    "truncated prepared source cache did not fail integrity",
    "normal builder accepted authority-test source cache",
)

DISTRIBUTION_DISK_REQUIRED_FRAGMENTS = (
    "Establish the Linux release disk budget",
    "/usr/local/lib/android",
    "/usr/share/dotnet",
    "/usr/local/.ghcup",
    "/usr/share/swift",
    'before_kib="$(df -Pk / | awk \'NR == 2 {print $4}\')"',
    'available_kib="$(df -Pk / | awk \'NR == 2 {print $4}\')"',
    "minimum_available_kib=$((20 * 1024 * 1024))",
    'if [[ -L "$path" ]]; then',
    '[[ -d "$path" ]] || {',
    'sudo rm -rf -- "$path"',
)

DISTRIBUTION_REQUIRED_FRAGMENTS = (
    *DISTRIBUTION_DISK_REQUIRED_FRAGMENTS,
    "timeout-minutes: ${{ matrix.platform == 'macos-amd64' && 150 || 90 }}",
    "Prepare native macOS product environment",
    "actions-rust-lang/setup-rust-toolchain@"
    "166cdcfd11aee3cb47222f9ddb555ce30ddb9659 "
    "# v1.17.0 (checked 2026-08-16)\n"
    "        if: startsWith(matrix.platform, 'macos-')",
    "Install the pinned Rust toolchain inside Devbox",
    'devbox run -- rustup toolchain install 1.97.1 \\\n'
    '            --profile minimal \\\n'
    '            --target "${{ matrix.target }}" \\\n'
    "            --no-self-update",
    "Install the pinned Rust inventory toolchain inside Devbox",
    'devbox run -- rustup toolchain install 1.97.1 \\\n'
    '            --profile minimal \\\n'
    "            --target x86_64-unknown-linux-musl \\\n"
    "            --no-self-update",
    'exec shasum -a 256 "$@"',
    'echo "DEVBOX_PACKAGES_DIR=$native_root/packages" >> "$GITHUB_ENV"',
    "run_product python3",
    "details=\"$(run_product scripts/build-h00ligan-portable.sh",
    "run_product scripts/test-h00ligan-installed-product.sh",
    "Check out the exact distribution tooling",
    "ref: ${{ github.workflow_sha }}",
    "path: target/release-tooling",
    '"$GITHUB_WORKSPACE/target/release-tooling/scripts/fetch-h00ligan-release-cargo.py"',
    '--source-root "$GITHUB_WORKSPACE"',
    '--rust-source "$H00_RUST_SOURCE_DIR"',
    "scripts/build-h00ligan-portable.sh",
    "scripts/test-h00ligan-installed-product.sh",
    "target/upstream-rust-1.97.1",
    "H00LIGAN_PRODUCT_MANIFEST",
    "H00_TEST_H00LIGAN_RECEIPT",
    "H00_TEST_H00LIGAN_PRODUCT_SOURCE_RECEIPT",
    "--describe crate",
    "h00ligan-product.cdx.json",
    '--source-root "rust-analyzer=$provider_source_root"',
    '--receipt "${{ steps.product.outputs.receipt }}"',
    '--source-receipt "${{ steps.product.outputs.source_receipt }}"',
    "cargo fetch --locked",
)

DISTRIBUTION_REQUIRED_FRAGMENT_COUNTS = (
    ("run_product()", 3),
    ('if [[ "$PLATFORM" == macos-* ]]; then', 3),
    ("if: startsWith(matrix.platform, 'linux-')", 3),
    ("if: startsWith(matrix.platform, 'macos-')", 2),
    ("PLATFORM: ${{ matrix.platform }}", 4),
    ("toolchain: 1.97.1", 2),
)

DISTRIBUTION_FORBIDDEN_FRAGMENTS = (
    "cachix/install-nix-action@",
    "-p h00ligan --bin h00ligan",
    "h00ligan-product_bin.cdx.json",
    "--describe binaries",
)

REPOSITORY_LOCAL_IGNORE_PATTERNS = (
    ".codex-home/",
    "__pycache__/",
    "*.pyc",
)


@dataclass(frozen=True)
class Recipe:
    dependencies: tuple[str, ...]
    commands: tuple[str, ...]
    failure_suppressed_commands: tuple[str, ...]


def normalize_command(command: str) -> str:
    return " ".join(command.split())


def parse_recipes(justfile: str) -> dict[str, Recipe]:
    lines = justfile.splitlines()
    recipes: dict[str, Recipe] = {}
    index = 0
    while index < len(lines):
        line = lines[index]
        if not line or line[0].isspace() or line.startswith("#") or ":" not in line:
            index += 1
            continue

        header, dependency_text = line.split(":", 1)
        name = header.split(maxsplit=1)[0]
        dependencies = tuple(dependency_text.split())
        commands: list[str] = []
        failure_suppressed_commands: list[str] = []
        index += 1
        while index < len(lines):
            body_line = lines[index]
            if body_line and not body_line[0].isspace():
                break
            stripped = body_line.strip()
            if stripped and not stripped.startswith("#"):
                command = stripped.lstrip("@")
                if command.startswith("-"):
                    failure_suppressed_commands.append(
                        normalize_command(command[1:].lstrip("@"))
                    )
                commands.append(normalize_command(command.lstrip("-").lstrip("@")))
            index += 1
        recipes[name] = Recipe(
            dependencies,
            tuple(commands),
            tuple(failure_suppressed_commands),
        )
    return recipes


def validate_justfile(justfile: str) -> list[str]:
    failures: list[str] = []
    recipes = parse_recipes(justfile)

    required_recipes = (
        "build",
        "build-portable",
        "install",
        "install-hooks",
        "check",
        "fmt",
        "ci-product-preflight",
        "fmt-check",
        "lint",
        "test",
        "ci-contract",
        "portability-check",
        "deps-check",
        "release-check",
        "test-installed",
        "perf-contract",
        "perf-smoke",
        "perf",
        "ci",
        "ci-product",
    )
    for name in required_recipes:
        if name not in recipes:
            failures.append(f"missing required recipe {name!r}")
        elif recipes[name].failure_suppressed_commands:
            failures.append(
                f"{name} contains failure-suppressed command(s): "
                f"{recipes[name].failure_suppressed_commands!r}"
            )

    if "ci" in recipes:
        actual = recipes["ci"].dependencies
        if actual != CI_DEPENDENCIES:
            failures.append(
                "ci dependency closure is "
                f"{actual!r}, expected {CI_DEPENDENCIES!r}"
            )
        expected_body = ('echo "All standalone source gates passed"',)
        if recipes["ci"].commands != expected_body:
            failures.append(
                "ci completion receipt is missing or changed: "
                f"{recipes['ci'].commands!r}"
            )

    expected_exact = {
        "build": (
            "cargo build --locked --offline --workspace --all-targets --all-features",
        ),
        "build-portable": ("scripts/build-h00ligan-portable.sh",),
        "install": ("scripts/build-h00ligan-portable.sh --install",),
        "install-hooks": (
            'test "$(git rev-parse --show-toplevel)" = "$(pwd -P)"',
            "git config --local core.hooksPath .githooks",
        ),
        "check": (
            "cargo check --locked --offline --workspace --all-targets --all-features",
        ),
        "fmt": ("cargo fmt --all",),
        "fmt-check": ("cargo fmt --all -- --check",),
        "lint": CLIPPY_COMMANDS,
        "test": TEST_COMMANDS,
        "ci-product-preflight": (CI_PREFLIGHT_COMMAND,),
        "ci-contract": (
            "PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-h00ligan-ci.py --self-test",
            CI_RECEIPT_SELF_TEST_COMMAND,
        ),
        "portability-check": (
            "PYTHONDONTWRITEBYTECODE=1 python3 scripts/check-h00ligan-binary.py --self-test",
            "PYTHONDONTWRITEBYTECODE=1 python3 scripts/publish-h00ligan-cache-directory.py --self-test",
        ),
        "test-installed": ("scripts/test-h00ligan-installed-product.sh",),
        "perf-contract": (
            "PYTHONDONTWRITEBYTECODE=1 python3 scripts/bench-h00ligan.py --self-test",
        ),
        "perf-smoke": ("scripts/bench-h00ligan-product.sh smoke",),
        "perf": ("scripts/bench-h00ligan-product.sh full",),
    }
    for name, expected_commands in expected_exact.items():
        recipe = recipes.get(name)
        if recipe is not None and recipe.commands != expected_commands:
            failures.append(
                f"{name} command population is {recipe.commands!r}, "
                f"expected {expected_commands!r}"
            )

    expected_dependencies = {
        "ci-contract": ("perf-contract",),
        "perf-smoke": ("perf-contract",),
        "perf": ("perf-contract",),
        "ci-product": CI_PRODUCT_DEPENDENCIES,
    }
    for name, dependencies in expected_dependencies.items():
        recipe = recipes.get(name)
        if recipe is not None and recipe.dependencies != dependencies:
            failures.append(
                f"{name} dependency closure is {recipe.dependencies!r}, "
                f"expected {dependencies!r}"
            )

    product_recipe = recipes.get("ci-product")
    if product_recipe is not None:
        expected_body = (CI_COMPLETION_COMMAND,)
        if product_recipe.commands != expected_body:
            failures.append(
                "ci-product completion receipt is missing or changed: "
                f"{product_recipe.commands!r}"
            )

    deps_recipe = recipes.get("deps-check")
    if deps_recipe is not None:
        expected_commands = (
            'test "$(cargo-deny --version)" = \'cargo-deny 0.20.2\'',
            "cargo-deny --offline --locked --exclude-dev -L error check",
        )
        if deps_recipe.commands != expected_commands:
            failures.append(
                "deps-check command population is "
                f"{deps_recipe.commands!r}, expected {expected_commands!r}"
            )

    release_recipe = recipes.get("release-check")
    if release_recipe is not None:
        if release_recipe.dependencies:
            failures.append(
                "release-check is static and must not hide build dependencies, got "
                f"{release_recipe.dependencies!r}"
            )
        for command in RELEASE_REQUIRED_COMMANDS:
            if command not in release_recipe.commands:
                failures.append(
                    f"release-check is missing required command {command!r}"
                )

    legacy = sorted(
        {
            "ci-ligan",
            "ci-ligan-preflight",
            "ci-ligan-contract",
            "build-ligan-portable",
            "install-ligan",
            "lint-ligan",
            "test-ligan",
            "test-ligan-installed",
            "deps-check-ligan",
            "perf-ligan-contract",
            "perf-ligan-smoke",
            "perf-ligan",
        }
        & recipes.keys()
    )
    if legacy:
        failures.append(
            "standalone Justfile retains superseded parent-workspace aliases: "
            + ", ".join(legacy)
        )

    return failures


def validate_repository_hygiene(gitignore: str | None) -> list[str]:
    """Keep local agent state and Python execution residue outside Git."""
    if gitignore is None:
        return ["repository .gitignore is missing"]

    active_patterns = {
        line.lstrip("/")
        for raw_line in gitignore.splitlines()
        if (line := raw_line.strip()) and not line.startswith("#")
    }
    return [
        "repository .gitignore is missing local-only pattern " + repr(pattern)
        for pattern in REPOSITORY_LOCAL_IGNORE_PATTERNS
        if pattern not in active_patterns
    ]


def validate_portable_builder(builder: str) -> list[str]:
    """Require a verified stable product workspace so Cargo can reuse work."""
    failures: list[str] = []
    for fragment in PORTABLE_BUILDER_REQUIRED_FRAGMENTS:
        if fragment not in builder:
            failures.append(
                f"portable builder is missing stable-workspace contract {fragment!r}"
            )
    for fragment in PORTABLE_BUILDER_FORBIDDEN_FRAGMENTS:
        if fragment in builder:
            failures.append(
                f"portable builder retains random product-workspace churn {fragment!r}"
            )
    return failures


def validate_provider_builder(builder: str) -> list[str]:
    """Bind cached generated provider source to the transforming builder."""
    failures: list[str] = []
    for fragment in PROVIDER_BUILDER_REQUIRED_FRAGMENTS:
        if fragment not in builder:
            failures.append(
                f"provider builder is missing cache-authority input {fragment!r}"
            )
    for fragment in PROVIDER_BUILDER_FORBIDDEN_FRAGMENTS:
        if fragment in builder:
            failures.append(
                f"provider builder retains obsolete cache authority {fragment!r}"
            )
    return failures


def validate_pyrefly_builder(builder: str | None) -> list[str]:
    """Require Pyrefly compiler state to be invocation-scoped and disposable."""
    if builder is None:
        return ["missing Pyrefly provider builder"]
    failures = [
        f"Pyrefly provider builder is missing bounded compilation contract {fragment!r}"
        for fragment in PYREFLY_BUILDER_REQUIRED_FRAGMENTS
        if fragment not in builder
    ]
    failures.extend(
        f"Pyrefly provider builder retains unbounded compiler cache {fragment!r}"
        for fragment in PYREFLY_BUILDER_FORBIDDEN_FRAGMENTS
        if fragment in builder
    )
    return failures


def validate_installed_gate(
    gate: str | None, watch_test_source: str | None
) -> list[str]:
    """Require the exact installed product to exercise provider, MCP, and WATCH."""
    if gate is None:
        return ["missing installed one-file product gate"]
    executable_gate = "\n".join(
        line for line in gate.splitlines() if not line.lstrip().startswith("#")
    )
    failures = [
        f"installed product gate is missing boundary {fragment!r}"
        for fragment in INSTALLED_GATE_REQUIRED_FRAGMENTS
        if fragment not in executable_gate
    ]
    cleanup_definition = executable_gate.find("cleanup() {")
    cleanup_trap = executable_gate.find("trap cleanup EXIT")
    owned_root_creation = executable_gate.find(
        'owned_tmp_root="$(mktemp -d "$test_tmp_parent/installed-product.XXXXXX")"'
    )
    if (
        min(cleanup_definition, cleanup_trap, owned_root_creation) >= 0
        and not cleanup_definition < cleanup_trap < owned_root_creation
    ):
        failures.append(
            "installed product gate must arm cleanup before allocating its owned "
            "temporary root"
        )
    if watch_test_source is None:
        failures.append("missing installed WATCH lifecycle test source")
    else:
        declared = {
            line.removeprefix("fn ").removesuffix("() {")
            for line in watch_test_source.splitlines()
            if line.startswith("fn installed_") and line.endswith("() {")
        }
        missing = [
            test_name
            for test_name in INSTALLED_WATCH_REQUIRED_TESTS
            if test_name not in declared
        ]
        if missing:
            failures.append(
                "installed WATCH source is missing required lifecycle tests "
                f"{missing!r}"
            )
        if not declared:
            failures.append("installed WATCH source declares no installed lifecycle tests")
    return failures


def prove_installed_gate_early_failure_cleanup(gate: str) -> None:
    """Fail after owned-root allocation and require the armed trap to remove it."""
    bash = shutil.which("bash")
    real_mkdir = shutil.which("mkdir")
    if bash is None or real_mkdir is None:
        raise AssertionError("installed cleanup self-test requires bash and mkdir")

    with tempfile.TemporaryDirectory(prefix="h00ligan-installed-cleanup.") as raw_root:
        probe_root = Path(raw_root)
        repo = probe_root / "repo"
        scripts = repo / "scripts"
        scripts.mkdir(parents=True)
        gate_path = scripts / "test-h00ligan-installed-product.sh"
        gate_path.write_text(gate, encoding="utf-8")
        gate_path.chmod(0o755)

        fake_bin = probe_root / "bin"
        fake_bin.mkdir()
        failure_marker = probe_root / "injected-mkdir-failure"
        fake_mkdir = fake_bin / "mkdir"
        fake_mkdir.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
for candidate in "$@"; do
    case "$candidate" in
        */installed-product.*/acceptance)
            printf '%s\\n' "$candidate" > "$H00_TEST_FAILED_PATH"
            exit 73
            ;;
    esac
done
exec "$H00_TEST_REAL_MKDIR" "$@"
""",
            encoding="utf-8",
        )
        fake_mkdir.chmod(0o755)

        environment = os.environ.copy()
        environment.update(
            {
                "DEVBOX_PACKAGES_DIR": "ci-contract-self-test",
                "H00_TEST_FAILED_PATH": str(failure_marker),
                "H00_TEST_REAL_MKDIR": real_mkdir,
                "PATH": f"{fake_bin}{os.pathsep}{environment.get('PATH', '')}",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        completed = subprocess.run(
            [bash, str(gate_path)],
            cwd=repo,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        if completed.returncode != 73 or not failure_marker.is_file():
            raise AssertionError(
                "installed cleanup probe did not reach the injected owned-root "
                f"failure: exit={completed.returncode}, "
                f"stderr={completed.stderr.decode(errors='replace')[-500:]!r}"
            )
        temp_parent = repo / "target/h00ligan-test-tmp"
        residue = sorted(temp_parent.glob("installed-product.*"))
        if residue:
            raise AssertionError(
                "installed gate left its owned temporary root after an early "
                f"failure: {[path.name for path in residue]!r}"
            )


def prove_installed_gate_go_environment(gate: str) -> None:
    """Run the real entrypoint through SDK selection, stopping before any build."""
    with tempfile.TemporaryDirectory(prefix="h00ligan-installed-go.") as raw_root:
        root = Path(raw_root)
        repo = root / "repo with spaces"
        scripts = repo / "scripts"
        scripts.mkdir(parents=True)
        gate_path = scripts / "test-h00ligan-installed-product.sh"
        gate_path.write_text(gate, encoding="utf-8")
        gate_path.chmod(0o755)
        bin_dir = root / "bin"
        bin_dir.mkdir()
        # Deliberately exclude ambient Go, Cargo and Devbox. The fixture must
        # reach the selected SDK and the build boundary without any of them.
        for name in ("bash", "dirname", "mkdir", "mktemp", "rm", "rmdir", "sed"):
            tool = shutil.which(name)
            if tool is None:
                raise AssertionError(f"installed Go environment probe requires {name}")
            (bin_dir / name).symlink_to(tool)
        sdk_bin = root / "pinned sdk/bin"
        sdk_bin.mkdir(parents=True)
        go_tool = sdk_bin / "go"
        go_tool.write_text(
            '#!/usr/bin/env bash\nprintf "pinned-go-positive\\n"\n',
            encoding="utf-8",
        )
        go_tool.chmod(0o755)
        resolver = scripts / "resolve-h00-official-go-sdk.sh"
        resolver.write_text(
            '#!/usr/bin/env bash\nset -euo pipefail\n'
            '[[ "$H00_TEST_RESOLVER_MODE" != failed ]] || exit 71\n'
            'printf "H00_GO_SDK_TOOL=%s\\n" "$H00_TEST_GO_TOOL"\n',
            encoding="utf-8",
        )
        resolver.chmod(0o755)
        builder = scripts / "build-h00ligan-portable.sh"
        builder.write_text(
            '#!/usr/bin/env bash\nset -euo pipefail\n'
            'echo builder-reached >&2\n'
            'go version >&2\n'
            '[[ "$(command -v go)" == "$H00_TEST_GO_TOOL" ]]\n'
            '[[ "${GOROOT:-}" == "$H00_TEST_GO_ROOT" ]]\n'
            '[[ "${GOENV:-}" == off && "${GOTOOLCHAIN:-}" == local ]]\n'
            'exit 73\n',
            encoding="utf-8",
        )
        builder.chmod(0o755)
        environment = {
            "PATH": str(bin_dir),
            "DEVBOX_PACKAGES_DIR": "ci-contract-self-test",
            "H00_TEST_GO_TOOL": str(go_tool),
            "H00_TEST_GO_ROOT": str(sdk_bin.parent),
            "H00_TEST_RESOLVER_MODE": "ready",
            "GOROOT": str(root / "wrong ambient SDK"),
            "GOENV": str(root / "wrong ambient Go configuration"),
            "GOTOOLCHAIN": "auto",
        }
        for mode in ("no-ambient-go", "wrong-ambient-go", "failed", "missing-tool"):
            trial = environment.copy()
            if mode == "wrong-ambient-go":
                ambient_go = bin_dir / "go"
                ambient_go.write_text(
                    '#!/usr/bin/env bash\necho wrong-ambient-go >&2\nexit 72\n',
                    encoding="utf-8",
                )
                ambient_go.chmod(0o755)
            elif mode == "failed":
                trial["H00_TEST_RESOLVER_MODE"] = "failed"
            elif mode == "missing-tool":
                trial["H00_TEST_GO_TOOL"] = str(root / "missing/bin/go")
            completed = subprocess.run(
                [str(bin_dir / "bash"), str(gate_path)], cwd=repo, env=trial,
                capture_output=True, text=True, check=False, timeout=10,
            )
            if mode in ("no-ambient-go", "wrong-ambient-go"):
                if completed.returncode != 73 or "pinned-go-positive" not in completed.stderr:
                    raise AssertionError(
                        f"installed entrypoint did not select the pinned SDK with {mode}: "
                        f"exit={completed.returncode}, stderr={completed.stderr[-500:]!r}"
                    )
            elif mode == "failed":
                if completed.returncode != 71 or "builder-reached" in completed.stderr:
                    raise AssertionError("failed SDK resolution did not stop before the build")
            elif completed.returncode != 1 or "builder-reached" in completed.stderr:
                raise AssertionError("absent SDK executable did not stop before the build")
            if list((repo / "target/h00ligan-test-tmp").glob("installed-product.*")):
                raise AssertionError(f"installed Go environment probe left residue for {mode}")
    print("installed-go-environment: OK (2 positive and 2 early-failure controls)")


def validate_pyrefly_provider_test(test: str | None) -> list[str]:
    """Require the retained provider epoch to replace, not accumulate, call truth."""
    if test is None:
        return ["missing installed Pyrefly provider lifecycle test"]
    return [
        f"Pyrefly provider lifecycle test is missing control {fragment!r}"
        for fragment in PYREFLY_PROVIDER_TEST_REQUIRED_FRAGMENTS
        if fragment not in test
    ]


def validate_build_authority_gate(gate: str | None) -> list[str]:
    """Require non-vacuous drift, capture-race, receipt, and residue controls."""
    if gate is None:
        return ["missing portable build-authority gate"]
    return [
        f"portable build-authority gate is missing control {fragment!r}"
        for fragment in BUILD_AUTHORITY_REQUIRED_FRAGMENTS
        if fragment not in gate
    ]


def prove_build_lock_handoff(builder: str) -> None:
    """Execute the live lock/cleanup code across controlled filesystem races."""
    def section(pattern: str) -> str:
        found = re.search(pattern, builder, flags=re.MULTILINE | re.DOTALL)
        if found is None:
            raise AssertionError(f"build-lock control lost its production section: {pattern}")
        return found.group()

    acquire = section(r"^acquire_target_build_lock\(\) \{\n.*?^\}")
    cleanup = section(r"^cleanup\(\) \{\n.*?^\}")
    source_admission = section(r'^if \[\[ ! -e "\$product_root" \]\]; then\n.*?^fi$')
    with tempfile.TemporaryDirectory(prefix="h00ligan-build-lock.") as raw:
        root = Path(raw)
        for mode in ("free", "release", "timeout", "file", "symlink", "fifo", "source"):
            case = root / mode
            case.mkdir()
            locks = case / "build-locks"
            locks.mkdir()
            lock = case / "product.lock" if mode == "source" else locks / "test.lock"
            marker = case / "release-once"
            sentinel = case / "foreign"
            sentinel.mkdir()
            (sentinel / "keep").write_text("foreign owner\n", encoding="utf-8")
            if mode in ("release", "timeout", "source"):
                lock.mkdir()
            elif mode == "file":
                lock.write_text("not a lock directory\n", encoding="utf-8")
            elif mode == "symlink":
                lock.symlink_to(sentinel, target_is_directory=True)
            elif mode == "fifo":
                os.mkfifo(lock)
            if mode == "release":
                marker.touch()
            body = r'''
set -euo pipefail
portable_cache_root="$1"
target=test
authority_test=0
build_lock=""
product_lock=""
install_temp=""
product_candidate=""
artifact_candidate=""
product_build_candidate=""
invocation_root=""
product_root="$1/product"
H00LIGAN_BUILD_LOCK_TIMEOUT_SECONDS="$2"
mkdir() {
    if [[ "$1" == "$portable_cache_root/build-locks/test.lock" && -f "$portable_cache_root/release-once" ]]; then
        # The owner releases after mkdir reports contention, before the waiter
        # inspects the path. This is a legitimate handoff, not invalid state.
        command rm "$portable_cache_root/release-once"
        command rmdir "$1"
        return 1
    fi
    command mkdir "$@"
}
'''
            body += cleanup + "\ntrap cleanup EXIT\n"
            body += source_admission if mode == "source" else acquire + "\nacquire_target_build_lock\n"
            completed = subprocess.run(
                ["bash", "-c", body, "lock-control", str(case), "0" if mode == "timeout" else "2"],
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                text=True, capture_output=True, check=False, timeout=10,
            )
            if mode in ("free", "release"):
                if completed.returncode != 0 or lock.exists() or marker.exists():
                    raise AssertionError(
                        f"build lock {mode} handoff failed: exit={completed.returncode}, "
                        f"stderr={completed.stderr!r}"
                    )
            else:
                expected = (
                    "already active" if mode == "source" else
                    "timed out" if mode == "timeout" else "lock is invalid"
                )
                if completed.returncode == 0 or expected not in completed.stderr:
                    raise AssertionError(f"build lock {mode} refused for the wrong reason: {completed}")
                if not os.path.lexists(lock):
                    raise AssertionError(f"unadmitted {mode} waiter deleted another owner's lock")
            if (sentinel / "keep").read_text(encoding="utf-8") != "foreign owner\n":
                raise AssertionError(f"build lock {mode} touched foreign content")
    print("build-lock-handoff: OK (free/released positives; timeout/type/source ownership controls)")


def prove_build_authority_failure_diagnostics() -> None:
    """A bounded failed wait must retain the child's actual diagnostic evidence."""
    gate = runpy.run_path(str(Path(__file__).with_name("test-h00ligan-build-authority.py")))
    with tempfile.TemporaryDirectory(prefix="h00-build-wait-controls.") as raw:
        root = Path(raw)
        for mode in ("ready", "barrier-timeout", "terminal-timeout", "early-exit"):
            case = root / mode
            case.mkdir()
            ready = case / "ready"
            child = (
                "import pathlib, sys, time\n"
                "print('x' * 32768 + 'stdout-tail-control', flush=True)\n"
                "print('y' * 32768 + 'stderr-tail-control', file=sys.stderr, flush=True)\n"
                "pathlib.Path(sys.argv[1]).touch()\n"
                + ("sys.exit(7)\n" if mode == "early-exit" else "time.sleep(30)\n")
            )
            run = gate["BuilderRun"]([sys.executable, "-c", child, str(ready)], os.environ.copy(), case)
            try:
                gate["wait_for"](ready, run, "populated diagnostic control", timeout=10)
                if mode == "ready":
                    if run.process.poll() is not None:
                        raise AssertionError("live barrier positive control did not fire")
                    continue
                try:
                    if mode == "terminal-timeout":
                        run.finish(timeout=0.1)
                    else:
                        gate["wait_for"](
                            case / "never-ready", run, "controlled missing barrier",
                            timeout=10 if mode == "early-exit" else 0.1,
                        )
                except AssertionError as error:
                    message = str(error)
                    expected = "builder exited 7" if mode == "early-exit" else "timed out"
                    if expected not in message:
                        raise AssertionError(f"{mode} failed for the wrong reason: {message!r}") from error
                    if "stdout-tail-control" not in message or "stderr-tail-control" not in message:
                        raise AssertionError(f"{mode} discarded the child's populated diagnostics") from error
                    if len(message.encode()) > 18000:
                        raise AssertionError(f"{mode} returned unbounded child diagnostics") from error
                else:
                    raise AssertionError(f"{mode} incorrectly succeeded")
            finally:
                run.terminate()
                if run.process.poll() is None:
                    raise AssertionError(f"{mode} left its child running")
    print("build-authority-diagnostics: OK (live barrier plus 3 bounded failure controls)")


def validate_performance_battery(
    harness: str | None, wrapper: str | None
) -> list[str]:
    """Require installed-product timing to remain coupled to truth and cleanup."""
    failures: list[str] = []
    if harness is None:
        failures.append("missing h00ligan performance harness")
    else:
        failures.extend(
            f"performance harness is missing control {fragment!r}"
            for fragment in PERFORMANCE_HARNESS_REQUIRED_FRAGMENTS
            if fragment not in harness
        )
        failures.extend(
            f"performance harness retains external-provider dependency {fragment!r}"
            for fragment in PERFORMANCE_HARNESS_FORBIDDEN_FRAGMENTS
            if fragment in harness
        )
    if wrapper is None:
        failures.append("missing h00ligan installed performance wrapper")
    else:
        failures.extend(
            f"performance wrapper is missing boundary {fragment!r}"
            for fragment in PERFORMANCE_WRAPPER_REQUIRED_FRAGMENTS
            if fragment not in wrapper
        )
    return failures


def validate_distribution_workflow(workflow: str) -> list[str]:
    """Forbid publishing a provider-less binary under the product name."""
    failures = [
        f"distribution workflow is missing exact-product boundary {fragment!r}"
        for fragment in DISTRIBUTION_REQUIRED_FRAGMENTS
        if fragment not in workflow
    ]
    failures.extend(
        f"distribution workflow has {workflow.count(fragment)} of required {count} "
        f"exact-product boundaries {fragment!r}"
        for fragment, count in DISTRIBUTION_REQUIRED_FRAGMENT_COUNTS
        if workflow.count(fragment) != count
    )
    failures.extend(
        f"distribution workflow retains obsolete product boundary {fragment!r}"
        for fragment in DISTRIBUTION_FORBIDDEN_FRAGMENTS
        if fragment in workflow
    )
    # Both jobs prepare the native providers. A build-job-only capacity check
    # cannot protect the fresh runner used to assemble the dependency inventory.
    for job in ("build", "package"):
        section = re.search(
            rf"^  {job}:\n(.*?)(?=^  \S|\Z)", workflow, re.MULTILINE | re.DOTALL
        )
        if section is None:
            failures.append(f"distribution workflow is missing {job} job")
            continue
        body = section.group(1)
        failures.extend(
            f"distribution {job} job is missing Linux disk boundary {fragment!r}"
            for fragment in DISTRIBUTION_DISK_REQUIRED_FRAGMENTS
            if body.count(fragment) != 1
        )
        disk_boundary = body.find("Establish the Linux release disk budget")
        environment_boundary = body.find("Install the pinned product build environment")
        if environment_boundary < 0 or disk_boundary > environment_boundary:
            failures.append(
                f"distribution {job} job must establish Linux disk capacity before "
                "installing the pinned product build environment"
            )
    return failures


def validate_integration_workflow(workflow: str | None) -> list[str]:
    """Keep the hosted Linux gate below its bounded compiler-artifact budget."""
    if workflow is None:
        return ["missing integration workflow"]
    active_lines = [
        line.strip()
        for line in workflow.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    required = (
        LINUX_LINT_STEP,
        LINUX_CLEAN_STEP,
        LINUX_CLEAN_COMMAND,
        LINUX_TEST_STEP,
    )
    failures = [
        f"integration workflow is missing Linux artifact boundary {line!r}"
        for line in required
        if active_lines.count(line) != 1
    ]
    if not failures:
        positions = [active_lines.index(line) for line in required]
        if positions != sorted(positions):
            failures.append(
                "Linux compiler-artifact cleanup must run after strict lint and "
                "before serial tests"
            )
    return failures


def validate_test_profile(manifest: str | None) -> list[str]:
    """Forbid throwaway incremental state in the complete test population."""
    if manifest is None:
        return ["missing workspace manifest"]
    try:
        parsed = tomllib.loads(manifest)
    except tomllib.TOMLDecodeError as error:
        return [f"workspace manifest is invalid TOML: {error}"]

    test_profile = parsed.get("profile", {}).get("test", {})
    failures = []
    if test_profile.get("debug") != 0:
        failures.append(
            "workspace test profile must set debug = 0 so linked test artifacts "
            "fit the hosted-runner disk budget"
        )
    if test_profile.get("incremental") is not False:
        failures.append(
            "workspace test profile must set incremental = false so a clean "
            "gate does not retain disposable compiler state"
        )
    return failures


def validate_portable_lockfile(lockfile: str | None) -> list[str]:
    """Require one tracked Cargo lock for the exact embedded product graph."""
    if lockfile is None:
        return [f"missing tracked portable product lock {PORTABLE_PRODUCT_LOCK}"]

    try:
        parsed = tomllib.loads(lockfile)
    except tomllib.TOMLDecodeError as error:
        return [f"portable product lock is invalid TOML: {error}"]

    failures: list[str] = []
    if parsed.get("version") != 4:
        failures.append(
            f"portable product lock version is {parsed.get('version')!r}, expected 4"
        )

    packages = parsed.get("package")
    if not isinstance(packages, list) or not packages:
        return failures + ["portable product lock has no package population"]

    by_name: dict[str, list[dict[str, object]]] = {}
    for package in packages:
        if isinstance(package, dict) and isinstance(package.get("name"), str):
            by_name.setdefault(package["name"], []).append(package)
    for name in PORTABLE_LOCK_REQUIRED_PACKAGES:
        count = len(by_name.get(name, []))
        if count != 1:
            failures.append(
                f"portable product lock package {name!r} population is {count}, expected 1"
            )

    product = by_name.get("h00ligan-product", [])
    if len(product) == 1:
        dependencies = product[0].get("dependencies")
        expected = list(PORTABLE_LOCK_DIRECT_DEPENDENCIES)
        if dependencies != expected:
            failures.append(
                "portable product lock direct dependencies are "
                f"{dependencies!r}, expected {expected!r}"
            )
    return failures


def prove_distribution_inventory_copy() -> None:
    """Execute the live copy boundary with a real relative path dependency."""
    workflow_path = Path(__file__).resolve().parents[1] / ".github/workflows/h00ligan-dist.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    start_marker = "          inventory_root="
    end_marker = "          cargo metadata "
    if workflow.count(start_marker) != 1 or workflow.count(end_marker) != 1:
        raise AssertionError("distribution must have one executable inventory copy boundary")
    start = workflow.index(start_marker)
    end = workflow.index(end_marker, start)
    body = "\n".join(line[10:] for line in workflow[start:end].splitlines())
    probe = """
import json
import sys
import tomllib
from pathlib import Path
inventory_root, manifest, expected_provider = map(Path, sys.argv[1:])
assert manifest.is_file(), "inventory manifest was not copied"
relative = tomllib.loads(manifest.read_text())["dependencies"]["hir"]["path"]
provider = (manifest.parent / relative / "Cargo.toml").resolve()
assert provider == expected_provider and provider.is_file(), "inventory moved the relative provider dependency"
manifest.write_text(manifest.read_text() + "\\n# disposable inventory proof\\n")
print(json.dumps({"inventory_root": str(inventory_root)}))
"""

    def exercise(copy_body: str) -> str | None:
        with tempfile.TemporaryDirectory(prefix="h00ligan inventory copy ") as temporary:
            root = Path(temporary).resolve()
            product_root = root / "target/portable-cache/product-source-fixture"
            manifest = product_root / "product/Cargo.toml"
            provider = root / "target/semantic-provider/crates/hir/Cargo.toml"
            files = {
                manifest: (
                    '[package]\nname = "product"\nversion = "0.1.0"\n'
                    '[dependencies]\nhir = { path = "../../../semantic-provider/crates/hir" }\n'
                ),
                manifest.parent / "src/lib.rs": "pub fn product() {}\n",
                provider: '[package]\nname = "hir"\nversion = "0.1.0"\n',
                provider.parent / "src/lib.rs": "pub fn provider() {}\n",
            }
            for path, contents in files.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            before = {path: path.read_bytes() for path in files}
            relative = tomllib.loads(manifest.read_text())["dependencies"]["hir"]["path"]
            if (manifest.parent / relative / "Cargo.toml").resolve() != provider:
                raise AssertionError("populated original relative-dependency control failed")
            environment = os.environ | {
                "product_root": str(product_root),
                "product_manifest": str(manifest),
                "RUNNER_TEMP": str(root),
                "inventory_test_python": sys.executable,
                "inventory_test_probe": probe,
                "inventory_test_provider": str(provider),
            }
            command = (
                "set -euo pipefail\n" + copy_body
                + '\n"$inventory_test_python" -c "$inventory_test_probe" '
                '"$inventory_root" "$inventory_manifest" "$inventory_test_provider"\n'
            )
            completed = subprocess.run(
                ["bash", "-c", command], env=environment,
                capture_output=True, text=True, timeout=20, check=False,
            )
            if any(
                not path.is_file() or path.read_bytes() != contents
                for path, contents in before.items()
            ):
                return "inventory changed protected source inputs"
            if completed.returncode != 0:
                return completed.stderr[-2048:]
            output = json.loads(completed.stdout)
            if Path(output["inventory_root"]).exists():
                return "inventory copy survived terminal cleanup"
            return None

    if failure := exercise(body):
        raise AssertionError(f"live distribution inventory copy failed: {failure}")
    mutants = {
        "displaced relative dependency": (
            re.sub(
                r"^inventory_root=.*$",
                'inventory_root="$RUNNER_TEMP/displaced"\nmkdir "$inventory_root"',
                body, count=1, flags=re.MULTILINE,
            ),
            "inventory moved the relative provider dependency",
        ),
        "omitted source copy": (
            re.sub(r"^cp -a.*$", ":", body, count=1, flags=re.MULTILINE),
            "inventory manifest was not copied",
        ),
        "omitted terminal cleanup": (
            body.replace('trap \'rm -rf -- "$inventory_root"\' EXIT', ":", 1),
            "inventory copy survived terminal cleanup",
        ),
    }
    for name, (mutant, expected) in mutants.items():
        if mutant == body:
            raise AssertionError(f"inventory copy mutant did not change {name}")
        failure = exercise(mutant)
        if failure is None or expected not in failure:
            raise AssertionError(
                f"inventory copy {name} did not fail for its exact reason: {failure}"
            )
    print(
        "distribution-inventory-copy: OK "
        "(4 protected files; relative dependency; isolated writes; "
        "3 sabotages; zero copy residue)"
    )


def fixture() -> str:
    def recipe(
        name: str,
        commands: tuple[str, ...],
        dependencies: tuple[str, ...] = (),
    ) -> str:
        header = f"{name}:"
        if dependencies:
            header += " " + " ".join(dependencies)
        body = "\n".join(f"    {command}" for command in commands)
        return f"{header}\n{body}\n"

    sections = [
        recipe(
            "build",
            (
                "cargo build --locked --offline --workspace --all-targets "
                "--all-features",
            ),
        ),
        recipe("build-portable", ("scripts/build-h00ligan-portable.sh",)),
        recipe("install", ("scripts/build-h00ligan-portable.sh --install",)),
        recipe("ci-product-preflight", (CI_PREFLIGHT_COMMAND,)),
        recipe(
            "install-hooks",
            (
                'test "$(git rev-parse --show-toplevel)" = "$(pwd -P)"',
                "git config --local core.hooksPath .githooks",
            ),
        ),
        recipe(
            "check",
            (
                "cargo check --locked --offline --workspace --all-targets "
                "--all-features",
            ),
        ),
        recipe("fmt", ("cargo fmt --all",)),
        recipe("fmt-check", ("cargo fmt --all -- --check",)),
        recipe("lint", CLIPPY_COMMANDS),
        recipe("test", TEST_COMMANDS),
        recipe(
            "ci-contract",
            (
                "PYTHONDONTWRITEBYTECODE=1 python3 "
                "scripts/check-h00ligan-ci.py --self-test",
                CI_RECEIPT_SELF_TEST_COMMAND,
            ),
            ("perf-contract",),
        ),
        recipe(
            "perf-contract",
            (
                "PYTHONDONTWRITEBYTECODE=1 python3 "
                "scripts/bench-h00ligan.py --self-test",
            ),
        ),
        recipe(
            "perf-smoke",
            ("scripts/bench-h00ligan-product.sh smoke",),
            ("perf-contract",),
        ),
        recipe(
            "perf",
            ("scripts/bench-h00ligan-product.sh full",),
            ("perf-contract",),
        ),
        recipe(
            "portability-check",
            (
                "PYTHONDONTWRITEBYTECODE=1 python3 "
                "scripts/check-h00ligan-binary.py --self-test",
                "PYTHONDONTWRITEBYTECODE=1 python3 "
                "scripts/publish-h00ligan-cache-directory.py --self-test",
            ),
        ),
        recipe(
            "test-installed",
            ("scripts/test-h00ligan-installed-product.sh",),
        ),
        recipe(
            "deps-check",
            (
                "@test \"$(cargo-deny --version)\" = 'cargo-deny 0.20.2'",
                "cargo-deny --offline --locked --exclude-dev -L error check",
            ),
        ),
        recipe("release-check", RELEASE_REQUIRED_COMMANDS),
        recipe(
            "ci",
            ('@echo "All standalone source gates passed"',),
            CI_DEPENDENCIES,
        ),
        recipe(
            "ci-product",
            (CI_COMPLETION_COMMAND,),
            CI_PRODUCT_DEPENDENCIES,
        ),
    ]
    return "\n".join(sections)


def self_test() -> int:
    valid = fixture()
    accepted = validate_justfile(valid)
    if accepted:
        raise AssertionError(f"valid h00ligan CI fixture rejected: {accepted!r}")

    sabotages = {
        "source preflight capture": valid.replace(
            f"    {CI_PREFLIGHT_COMMAND}\n",
            "",
            1,
        ),
        "dependency closure": valid.replace(
            " ".join(CI_DEPENDENCIES),
            " ".join(
                dependency
                for dependency in CI_DEPENDENCIES
                if dependency != "test"
            ),
            1,
        ),
        "installed dependency closure": valid.replace(
            "ci-product: ci-product-preflight ci test-installed perf-smoke",
            "ci-product: ci-product-preflight ci perf-smoke",
            1,
        ),
        "lint population": valid.replace(
            f"    {CLIPPY_COMMANDS[0]}\n", "", 1
        ),
        "test population": valid.replace(f"    {TEST_COMMANDS[0]}\n", "", 1),
        "serial process tests": valid.replace("-- --test-threads=1", "", 1),
        "release static authority": valid.replace(
            f"    {RELEASE_REQUIRED_COMMANDS[5]}\n",
            "",
            1,
        ),
        "actionlint version": valid.replace(
            f"    {ACTIONLINT_VERSION_COMMAND}\n",
            "",
            1,
        ),
        "shellcheck version": valid.replace(
            f"    {SHELLCHECK_VERSION_COMMAND}\n",
            "",
            1,
        ),
        "workflow lint": valid.replace(
            f"    {ACTIONLINT_COMMAND}\n",
            "",
            1,
        ),
        "portable install": valid.replace(
            "    scripts/build-h00ligan-portable.sh --install\n",
            "    cargo build --release -p h00ligan --bin h00ligan\n",
            1,
        ),
        "local hook installation": valid.replace(
            "    git config --local core.hooksPath .githooks\n",
            "",
            1,
        ),
        "installed product boundary": valid.replace(
            "    scripts/test-h00ligan-installed-product.sh\n", "", 1
        ),
        "performance contract": valid.replace(
            "    PYTHONDONTWRITEBYTECODE=1 python3 "
            "scripts/bench-h00ligan.py --self-test\n",
            "",
            1,
        ),
        "performance installed boundary": valid.replace(
            "    scripts/bench-h00ligan-product.sh smoke\n",
            "    python3 scripts/bench-h00ligan.py --mode smoke\n",
            1,
        ),
        "performance dependency closure": valid.replace(
            "perf: perf-contract",
            "perf:",
            1,
        ),
        "dependency root": valid.replace(
            "cargo-deny --offline --locked --exclude-dev -L error check",
            "cargo-deny --manifest-path crates/h00ligan/Cargo.toml "
            "--exclude-dev -L error check",
            1,
        ),
        "legacy alias": valid + "\nci-ligan:\n    true\n",
        "typed completion receipt": valid.replace(
            CI_COMPLETION_COMMAND,
            'echo "All standalone installed-product gates passed"',
            1,
        ),
        "receipt self-test": valid.replace(
            f"    {CI_RECEIPT_SELF_TEST_COMMAND}\n",
            "",
            1,
        ),
        "dependency executable dispatch": valid.replace(
            "cargo-deny --version",
            "cargo deny --version",
            1,
        ),
        "failure-suppressed dependency executable": valid.replace(
            "    cargo-deny --offline --locked --exclude-dev -L error check\n",
            "    -cargo-deny --offline --locked --exclude-dev -L error check\n",
            1,
        ),
    }
    expected_fragments = {
        "source preflight capture": "ci-product-preflight command population",
        "dependency closure": "ci dependency closure",
        "installed dependency closure": "ci-product dependency closure",
        "lint population": "lint command population",
        "test population": "test command population",
        "serial process tests": "test command population",
        "release static authority": "release-check is missing required command",
        "actionlint version": "release-check is missing required command",
        "shellcheck version": "release-check is missing required command",
        "workflow lint": "release-check is missing required command",
        "portable install": "install command population",
        "local hook installation": "install-hooks command population",
        "installed product boundary": "test-installed command population",
        "performance contract": "perf-contract command population",
        "performance installed boundary": "perf-smoke command population",
        "performance dependency closure": "perf dependency closure",
        "dependency root": "deps-check command population",
        "legacy alias": "superseded parent-workspace aliases",
        "typed completion receipt": "ci-product completion receipt",
        "receipt self-test": "ci-contract command population",
        "dependency executable dispatch": "deps-check command population",
        "failure-suppressed dependency executable": "failure-suppressed command",
    }
    for name, sabotaged in sabotages.items():
        rejected = validate_justfile(sabotaged)
        fragment = expected_fragments[name]
        if not any(fragment in failure for failure in rejected):
            raise AssertionError(
                f"{name} sabotage did not fire {fragment!r}: {rejected!r}"
            )

    # Prove validation has no stateful dependence on the first run.
    accepted_again = validate_justfile(copy.copy(valid))
    if accepted_again:
        raise AssertionError(f"repeat validation drifted: {accepted_again!r}")

    valid_gitignore = "\n".join(REPOSITORY_LOCAL_IGNORE_PATTERNS) + "\n"
    if failures := validate_repository_hygiene(valid_gitignore):
        raise AssertionError(f"valid repository ignore fixture rejected: {failures!r}")
    for pattern in REPOSITORY_LOCAL_IGNORE_PATTERNS:
        sabotaged = valid_gitignore.replace(f"{pattern}\n", "", 1)
        failures = validate_repository_hygiene(sabotaged)
        if not any(pattern in failure for failure in failures):
            raise AssertionError(
                f"repository ignore omission did not fire for {pattern!r}: "
                f"{failures!r}"
            )

    valid_builder = "\n".join(PORTABLE_BUILDER_REQUIRED_FRAGMENTS)
    accepted_builder = validate_portable_builder(valid_builder)
    if accepted_builder:
        raise AssertionError(
            f"valid portable-builder fixture rejected: {accepted_builder!r}"
        )
    for fragment in PORTABLE_BUILDER_REQUIRED_FRAGMENTS:
        sabotaged = valid_builder.replace(fragment, "", 1)
        rejected = validate_portable_builder(sabotaged)
        if not any("missing stable-workspace contract" in failure for failure in rejected):
            raise AssertionError(
                f"portable-builder omission did not fire for {fragment!r}: {rejected!r}"
            )
    random_builder = (
        valid_builder + "\n" + PORTABLE_BUILDER_FORBIDDEN_FRAGMENTS[0]
    )
    rejected = validate_portable_builder(random_builder)
    if not any("random product-workspace churn" in failure for failure in rejected):
        raise AssertionError(
            f"portable-builder random-root sabotage did not fire: {rejected!r}"
        )

    generated_builder = valid_builder + "\ncargo generate-lockfile\n"
    rejected = validate_portable_builder(generated_builder)
    if not any("generate-lockfile" in failure for failure in rejected):
        raise AssertionError(
            f"portable-builder generated-lock sabotage did not fire: {rejected!r}"
        )

    valid_provider_builder = "\n".join(PROVIDER_BUILDER_REQUIRED_FRAGMENTS)
    if failures := validate_provider_builder(valid_provider_builder):
        raise AssertionError(f"valid provider builder rejected: {failures!r}")
    for fragment in PROVIDER_BUILDER_REQUIRED_FRAGMENTS:
        sabotaged = valid_provider_builder.replace(fragment, "", 1)
        failures = validate_provider_builder(sabotaged)
        if not any("missing cache-authority input" in failure for failure in failures):
            raise AssertionError(
                f"provider-builder omission did not fire for {fragment!r}: "
                f"{failures!r}"
            )
    stale_provider_builder = (
        valid_provider_builder + "\n" + PROVIDER_BUILDER_FORBIDDEN_FRAGMENTS[0]
    )
    if not validate_provider_builder(stale_provider_builder):
        raise AssertionError("provider-builder stale-schema sabotage did not fire")

    valid_pyrefly_builder = "\n".join(PYREFLY_BUILDER_REQUIRED_FRAGMENTS)
    if failures := validate_pyrefly_builder(valid_pyrefly_builder):
        raise AssertionError(f"valid Pyrefly builder rejected: {failures!r}")
    for fragment in PYREFLY_BUILDER_REQUIRED_FRAGMENTS:
        sabotaged = valid_pyrefly_builder.replace(fragment, "", 1)
        failures = validate_pyrefly_builder(sabotaged)
        if not any("missing bounded compilation contract" in failure for failure in failures):
            raise AssertionError(
                f"Pyrefly builder omission did not fire for {fragment!r}: {failures!r}"
            )
    for fragment in PYREFLY_BUILDER_FORBIDDEN_FRAGMENTS:
        failures = validate_pyrefly_builder(valid_pyrefly_builder + "\n" + fragment)
        if not any("retains unbounded compiler cache" in failure for failure in failures):
            raise AssertionError(
                f"Pyrefly builder retained-cache sabotage did not fire for {fragment!r}"
            )

    valid_installed_gate = "\n".join(INSTALLED_GATE_REQUIRED_FRAGMENTS)
    valid_watch_test_source = "\n".join(
        f"fn {test_name}() {{\n}}" for test_name in INSTALLED_WATCH_REQUIRED_TESTS
    )
    if failures := validate_installed_gate(valid_installed_gate, valid_watch_test_source):
        raise AssertionError(f"valid installed product gate rejected: {failures!r}")
    for fragment in INSTALLED_GATE_REQUIRED_FRAGMENTS:
        sabotaged = valid_installed_gate.replace(fragment, "", 1)
        if not validate_installed_gate(sabotaged, valid_watch_test_source):
            raise AssertionError(
                f"installed product omission did not fire for {fragment!r}"
            )
    discovery_fragment = 'discovered_watch_population="$('
    comment_only_discovery = valid_installed_gate.replace(
        discovery_fragment,
        f"# {discovery_fragment}",
        1,
    )
    if not validate_installed_gate(comment_only_discovery, valid_watch_test_source):
        raise AssertionError(
            "comment-only installed WATCH discovery still satisfied executable wiring"
        )
    cleanup_trap = "trap cleanup EXIT"
    owned_root_creation = (
        'owned_tmp_root="$(mktemp -d "$test_tmp_parent/installed-product.XXXXXX")"'
    )
    late_cleanup = valid_installed_gate.replace(
        f"{cleanup_trap}\n{owned_root_creation}",
        f"{owned_root_creation}\n{cleanup_trap}",
        1,
    )
    late_cleanup_failures = validate_installed_gate(
        late_cleanup, valid_watch_test_source
    )
    if not any("arm cleanup before allocating" in failure for failure in late_cleanup_failures):
        raise AssertionError(
            "late installed-product cleanup trap satisfied the ownership ordering"
        )
    missing_required_watch = valid_watch_test_source.replace(
        f"fn {INSTALLED_WATCH_REQUIRED_TESTS[0]}() {{\n}}", "", 1
    )
    if not validate_installed_gate(valid_installed_gate, missing_required_watch):
        raise AssertionError("missing required installed WATCH source test was accepted")
    live_installed_gate = Path(__file__).resolve().with_name(
        "test-h00ligan-installed-product.sh"
    )
    prove_installed_gate_early_failure_cleanup(
        live_installed_gate.read_text(encoding="utf-8")
    )
    prove_installed_gate_go_environment(live_installed_gate.read_text(encoding="utf-8"))

    valid_pyrefly_test = "\n".join(PYREFLY_PROVIDER_TEST_REQUIRED_FRAGMENTS)
    if failures := validate_pyrefly_provider_test(valid_pyrefly_test):
        raise AssertionError(f"valid Pyrefly provider test rejected: {failures!r}")
    for fragment in PYREFLY_PROVIDER_TEST_REQUIRED_FRAGMENTS:
        sabotaged = valid_pyrefly_test.replace(fragment, "", 1)
        if not validate_pyrefly_provider_test(sabotaged):
            raise AssertionError(
                f"Pyrefly provider-test omission did not fire for {fragment!r}"
            )

    valid_build_authority_gate = "\n".join(BUILD_AUTHORITY_REQUIRED_FRAGMENTS)
    if failures := validate_build_authority_gate(valid_build_authority_gate):
        raise AssertionError(f"valid build-authority gate rejected: {failures!r}")
    for fragment in BUILD_AUTHORITY_REQUIRED_FRAGMENTS:
        sabotaged = valid_build_authority_gate.replace(fragment, "", 1)
        if not validate_build_authority_gate(sabotaged):
            raise AssertionError(
                f"build-authority omission did not fire for {fragment!r}"
            )
    prove_build_lock_handoff(
        Path(__file__).with_name("build-h00ligan-portable.sh").read_text(encoding="utf-8")
    )
    prove_build_authority_failure_diagnostics()

    valid_performance_harness = "\n".join(PERFORMANCE_HARNESS_REQUIRED_FRAGMENTS)
    valid_performance_wrapper = "\n".join(PERFORMANCE_WRAPPER_REQUIRED_FRAGMENTS)
    if failures := validate_performance_battery(
        valid_performance_harness, valid_performance_wrapper
    ):
        raise AssertionError(f"valid performance battery rejected: {failures!r}")
    for fragment in PERFORMANCE_HARNESS_REQUIRED_FRAGMENTS:
        sabotaged = valid_performance_harness.replace(fragment, "", 1)
        if not validate_performance_battery(sabotaged, valid_performance_wrapper):
            raise AssertionError(
                f"performance-harness omission did not fire for {fragment!r}"
            )
    for fragment in PERFORMANCE_HARNESS_FORBIDDEN_FRAGMENTS:
        sabotaged = valid_performance_harness + "\n" + fragment
        if not validate_performance_battery(sabotaged, valid_performance_wrapper):
            raise AssertionError(
                f"performance-harness forbidden dependency did not fire for {fragment!r}"
            )
    for fragment in PERFORMANCE_WRAPPER_REQUIRED_FRAGMENTS:
        sabotaged = valid_performance_wrapper.replace(fragment, "", 1)
        if not validate_performance_battery(valid_performance_harness, sabotaged):
            raise AssertionError(
                f"performance-wrapper omission did not fire for {fragment!r}"
            )

    disk_boundary = "Establish the Linux release disk budget"
    environment_boundary = "Install the pinned product build environment"
    valid_distribution = "\n".join(
        fragment
        for fragment in DISTRIBUTION_REQUIRED_FRAGMENTS
        if fragment not in DISTRIBUTION_DISK_REQUIRED_FRAGMENTS
    )
    for job in ("build", "package"):
        valid_distribution += f"\n  {job}:\n" + "\n".join(
            "    " + fragment
            for fragment in (*DISTRIBUTION_DISK_REQUIRED_FRAGMENTS, environment_boundary)
        ) + "\n"
    for fragment, count in DISTRIBUTION_REQUIRED_FRAGMENT_COUNTS:
        missing = count - valid_distribution.count(fragment)
        if missing < 0:
            raise AssertionError(
                f"distribution fixture already exceeds {count} copies of {fragment!r}"
            )
        if missing:
            valid_distribution += "\n" + "\n".join(fragment for _ in range(missing))
    if failures := validate_distribution_workflow(valid_distribution):
        raise AssertionError(f"valid distribution workflow rejected: {failures!r}")
    for job in ("build", "package"):
        prefix, body = valid_distribution.split(f"  {job}:\n", 1)
        reordered = prefix + f"  {job}:\n" + body.replace(
            disk_boundary, "__DISK_BOUNDARY__", 1
        ).replace(environment_boundary, disk_boundary, 1).replace(
            "__DISK_BOUNDARY__", environment_boundary, 1
        )
        expected = (
            f"distribution {job} job must establish Linux disk capacity before "
            "installing the pinned product build environment"
        )
        if validate_distribution_workflow(reordered) != [expected]:
            raise AssertionError(f"distribution {job} disk-boundary reorder did not fire exactly")
        omitted = prefix + f"  {job}:\n" + body.replace(disk_boundary, "", 1)
        expected = f"distribution {job} job is missing Linux disk boundary {disk_boundary!r}"
        if validate_distribution_workflow(omitted) != [expected]:
            raise AssertionError(f"distribution {job} disk-boundary omission did not fire exactly")
    for fragment in DISTRIBUTION_REQUIRED_FRAGMENTS:
        sabotaged = valid_distribution.replace(fragment, "", 1)
        if not validate_distribution_workflow(sabotaged):
            raise AssertionError(
                f"distribution omission did not fire for {fragment!r}"
            )
    for fragment, _count in DISTRIBUTION_REQUIRED_FRAGMENT_COUNTS:
        sabotaged = valid_distribution.replace(fragment, "", 1)
        if not validate_distribution_workflow(sabotaged):
            raise AssertionError(
                f"distribution population omission did not fire for {fragment!r}"
            )
    for fragment in DISTRIBUTION_FORBIDDEN_FRAGMENTS:
        invalid_distribution = valid_distribution + "\n" + fragment
        if not validate_distribution_workflow(invalid_distribution):
            raise AssertionError(
                f"forbidden distribution fragment did not fire: {fragment!r}"
            )
    prove_distribution_inventory_copy()

    valid_integration = "\n".join(
        (
            LINUX_LINT_STEP,
            "run: devbox run -- cargo clippy --locked --offline --workspace",
            LINUX_CLEAN_STEP,
            LINUX_CLEAN_COMMAND,
            LINUX_TEST_STEP,
            "run: devbox run -- cargo test --locked --offline --workspace",
        )
    )
    if failures := validate_integration_workflow(valid_integration):
        raise AssertionError(f"valid integration workflow rejected: {failures!r}")
    integration_sabotages = {
        "cleanup omission": valid_integration.replace(
            f"{LINUX_CLEAN_COMMAND}\n", "", 1
        ),
        "cleanup misordering": "\n".join(
            (
                LINUX_CLEAN_STEP,
                LINUX_CLEAN_COMMAND,
                LINUX_LINT_STEP,
                LINUX_TEST_STEP,
            )
        ),
    }
    for name, sabotaged in integration_sabotages.items():
        if not validate_integration_workflow(sabotaged):
            raise AssertionError(f"integration {name} did not fire")

    valid_manifest = """\
[workspace]
members = []

[profile.test]
debug = 0
incremental = false
"""
    if failures := validate_test_profile(valid_manifest):
        raise AssertionError(f"valid test profile rejected: {failures!r}")
    test_profile_sabotages = {
        "debug omission": valid_manifest.replace("debug = 0\n", "", 1),
        "debug enablement": valid_manifest.replace("debug = 0", "debug = 1", 1),
        "incremental omission": valid_manifest.replace("incremental = false\n", "", 1),
        "incremental enablement": valid_manifest.replace(
            "incremental = false", "incremental = true", 1
        ),
    }
    for name, sabotaged in test_profile_sabotages.items():
        if not validate_test_profile(sabotaged):
            raise AssertionError(f"test profile {name} sabotage did not fire")

    valid_lock = """\
version = 4

[[package]]
name = "h00ligan"
version = "0.2.0"

[[package]]
name = "h00ligan-ra-provider"
version = "0.1.0"

[[package]]
name = "h00ligan-provider-protocol"
version = "0.1.0"

[[package]]
name = "h00ligan-product"
version = "0.2.0"
dependencies = [
 "h00ligan",
 "h00ligan-provider-protocol",
 "h00ligan-ra-provider",
]
"""
    if failures := validate_portable_lockfile(valid_lock):
        raise AssertionError(f"valid portable product lock rejected: {failures!r}")
    lock_sabotages = {
        "missing": None,
        "schema": valid_lock.replace("version = 4", "version = 3", 1),
        "package population": valid_lock.replace(
            'name = "h00ligan-provider-protocol"',
            'name = "wrong-protocol"',
            1,
        ),
        "provider direct dependency": valid_lock.replace(
            ' "h00ligan-ra-provider",\n', "", 1
        ),
        "protocol direct dependency": valid_lock.replace(
            ' "h00ligan-provider-protocol",\n', "", 1
        ),
    }
    for name, sabotaged in lock_sabotages.items():
        if not validate_portable_lockfile(sabotaged):
            raise AssertionError(f"portable product lock {name} sabotage did not fire")

    return (
        len(sabotages)
        + len(PORTABLE_BUILDER_REQUIRED_FRAGMENTS)
        + 2
        + len(PROVIDER_BUILDER_REQUIRED_FRAGMENTS)
        + 1
        + len(PYREFLY_BUILDER_REQUIRED_FRAGMENTS)
        + len(PYREFLY_BUILDER_FORBIDDEN_FRAGMENTS)
        + len(INSTALLED_GATE_REQUIRED_FRAGMENTS)
        + 4
        + 2  # installed Go SDK resolution/executable failures before any build
        + len(PYREFLY_PROVIDER_TEST_REQUIRED_FRAGMENTS)
        + len(BUILD_AUTHORITY_REQUIRED_FRAGMENTS)
        + 5  # target timeout/type and source-cache ownership controls
        + 3  # barrier timeout, terminal timeout, and early-exit diagnostic controls
        + len(PERFORMANCE_HARNESS_REQUIRED_FRAGMENTS)
        + len(PERFORMANCE_HARNESS_FORBIDDEN_FRAGMENTS)
        + len(PERFORMANCE_WRAPPER_REQUIRED_FRAGMENTS)
        + len(DISTRIBUTION_REQUIRED_FRAGMENTS)
        + len(DISTRIBUTION_REQUIRED_FRAGMENT_COUNTS)
        + len(DISTRIBUTION_FORBIDDEN_FRAGMENTS)
        + 4  # build/package disk-step omission and ordering controls
        + 3  # relative dependency, copy omission, and terminal cleanup controls
        + len(integration_sabotages)
        + len(test_profile_sabotages)
        + len(lock_sabotages)
        + len(REPOSITORY_LOCAL_IGNORE_PATTERNS)
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        sabotage_count = self_test()
        print(
            "h00ligan-ci-contract: self-test OK "
            f"({sabotage_count} sabotage controls fired)"
        )

    root = args.root.resolve()
    gitignore_path = root / ".gitignore"
    gitignore = (
        gitignore_path.read_text(encoding="utf-8")
        if gitignore_path.is_file()
        else None
    )
    failures = validate_repository_hygiene(gitignore)
    justfile_path = root / "Justfile"
    failures.extend(validate_justfile(justfile_path.read_text(encoding="utf-8")))
    builder_path = root / "scripts/build-h00ligan-portable.sh"
    failures.extend(validate_portable_builder(builder_path.read_text(encoding="utf-8")))
    provider_builder_path = (
        root / "scripts/build-h00-rust-semantic-provider.sh"
    )
    failures.extend(
        validate_provider_builder(provider_builder_path.read_text(encoding="utf-8"))
    )
    pyrefly_builder_path = (
        root / "scripts/build-h00-pyrefly-semantic-provider.sh"
    )
    pyrefly_builder = (
        pyrefly_builder_path.read_text(encoding="utf-8")
        if pyrefly_builder_path.is_file()
        else None
    )
    failures.extend(validate_pyrefly_builder(pyrefly_builder))
    installed_gate_path = (
        root / "scripts/test-h00ligan-installed-product.sh"
    )
    installed_gate = (
        installed_gate_path.read_text(encoding="utf-8")
        if installed_gate_path.is_file()
        else None
    )
    watch_test_source_path = root / "crates/h00ligan/tests/watch_lifecycle.rs"
    watch_test_source = (
        watch_test_source_path.read_text(encoding="utf-8")
        if watch_test_source_path.is_file()
        else None
    )
    failures.extend(validate_installed_gate(installed_gate, watch_test_source))
    pyrefly_provider_test_path = (
        root / "scripts/test-h00-pyrefly-semantic-provider.py"
    )
    pyrefly_provider_test = (
        pyrefly_provider_test_path.read_text(encoding="utf-8")
        if pyrefly_provider_test_path.is_file()
        else None
    )
    failures.extend(validate_pyrefly_provider_test(pyrefly_provider_test))
    build_authority_gate_path = (
        root / "scripts/test-h00ligan-build-authority.py"
    )
    build_authority_gate = (
        build_authority_gate_path.read_text(encoding="utf-8")
        if build_authority_gate_path.is_file()
        else None
    )
    failures.extend(validate_build_authority_gate(build_authority_gate))
    performance_harness_path = (
        root / "scripts/bench-h00ligan.py"
    )
    performance_wrapper_path = (
        root / "scripts/bench-h00ligan-product.sh"
    )
    performance_harness = (
        performance_harness_path.read_text(encoding="utf-8")
        if performance_harness_path.is_file()
        else None
    )
    performance_wrapper = (
        performance_wrapper_path.read_text(encoding="utf-8")
        if performance_wrapper_path.is_file()
        else None
    )
    failures.extend(
        validate_performance_battery(performance_harness, performance_wrapper)
    )
    distribution_path = root / ".github/workflows/h00ligan-dist.yml"
    failures.extend(
        validate_distribution_workflow(distribution_path.read_text(encoding="utf-8"))
    )
    integration_path = root / ".github/workflows/integration-tests.yml"
    integration_text = (
        integration_path.read_text(encoding="utf-8")
        if integration_path.is_file()
        else None
    )
    failures.extend(validate_integration_workflow(integration_text))
    manifest_path = root / "Cargo.toml"
    manifest_text = (
        manifest_path.read_text(encoding="utf-8")
        if manifest_path.is_file()
        else None
    )
    failures.extend(validate_test_profile(manifest_text))
    lock_path = root / PORTABLE_PRODUCT_LOCK
    lock_text = lock_path.read_text(encoding="utf-8") if lock_path.is_file() else None
    failures.extend(validate_portable_lockfile(lock_text))
    if failures:
        print("h00ligan-ci-contract: FAIL", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print(
        "h00ligan-ci-contract: OK "
        "(complete standalone workspace lint/test populations; snapshot-derived "
        "receipted portable artifacts; portability, dependency, MCP, performance, "
        "release, packaging, local-state ignore, and diff controls)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
