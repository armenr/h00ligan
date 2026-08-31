#!/usr/bin/env python3
"""Prove that an h00ligan artifact is distribution-shaped for its target."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path


LINUX_TARGETS = {
    "x86_64-unknown-linux-musl": "x86-64",
    "aarch64-unknown-linux-musl": "ARM aarch64",
}
MACOS_TARGETS = {
    "x86_64-apple-darwin": ("x86_64", "10.12"),
    "aarch64-apple-darwin": ("arm64", "11.0"),
}
INTERNAL_RUST_PROVIDER_ARGUMENT = "__h00-internal-rust-provider"
PROVIDER_PARENT_PID_ENV = "H00_PROVIDER_PARENT_PID"
RESOLVED_TOOLCHAIN_SHA256 = hashlib.sha256(b"binary-check-toolchain").hexdigest()
RUST_SEMANTIC_PROFILE = json.dumps(
    {
        "schema_version": "h00/rust-semantic-profile/v1",
        "cargo_features": "workspace_default",
        "target": None,
    },
    separators=(",", ":"),
)
FORBIDDEN_COMPANION_NAMES = (
    "h00ligan-ra-provider",
    "h00ligan-ra-provider.build.json",
    "h00-pyrefly-semantic-provider",
    "h00-pyrefly-semantic-provider.build.json",
)
FORBIDDEN_RUNTIME_TOOLING_TOKENS = (
    b"devbox_packages_dir",
    b"devbox run",
)
ARTIFACT_SCHEMA = "h00/h00ligan-portable-artifact/v3"
SOURCE_SCHEMA = "h00/h00ligan-product-source-cache/v6"
ARTIFACT_KEY_SCHEMA = b"h00/h00ligan-portable-artifact-key/v3"
ARTIFACT_KEY_FIELDS = (
    "target",
    "product_source_key",
    "product_source_tree_sha256",
    "product_source_receipt_sha256",
    "product_lock_sha256",
    "provider_source_key",
    "provider_patch_sha256",
    "provider_builder_sha256",
    "python_provider_binary_sha256",
    "python_provider_patch_sha256",
    "python_provider_source_key",
    "python_provider_source_tree_sha256",
    "python_provider_builder_sha256",
    "python_provider_archive_sha256",
    "python_provider_cache_publisher_sha256",
    "python_provider_receipt_sha256",
    "go_provider_binary_sha256",
    "go_provider_patch_sha256",
    "go_provider_source_tree_sha256",
    "go_provider_builder_sha256",
    "go_provider_receipt_sha256",
    "typescript_provider_binary_sha256",
    "typescript_provider_patch_sha256",
    "typescript_provider_test_sha256",
    "typescript_provider_source_tree_sha256",
    "typescript_provider_builder_sha256",
    "typescript_provider_receipt_sha256",
    "product_builder_sha256",
    "rustc",
    "cargo",
    "linker",
    "rustflags",
    "cflags",
    "cxxflags",
)


def artifact_build_key(payload: dict[str, object]) -> str:
    hasher = hashlib.sha256()
    for value in (ARTIFACT_KEY_SCHEMA, *(
        str(payload.get(field, "")).encode() for field in ARTIFACT_KEY_FIELDS
    )):
        hasher.update(struct.pack(">Q", len(value)))
        hasher.update(value)
    return hasher.hexdigest()


def validate_artifact_payload(
    *,
    payload: dict[str, object],
    binary_sha256: str,
    binary_size: int,
    target: str,
    source_payload: dict[str, object],
    source_receipt_sha256: str,
    allow_authority_test_receipt: bool = False,
) -> list[str]:
    failures: list[str] = []
    if payload.get("schema") != ARTIFACT_SCHEMA:
        failures.append("portable artifact receipt schema is invalid")
    if source_payload.get("schema") != SOURCE_SCHEMA:
        failures.append("portable product-source receipt schema is invalid")
    artifact_authority_test = payload.get("authority_test", False)
    source_authority_test = source_payload.get("authority_test", False)
    if not isinstance(artifact_authority_test, bool) or not isinstance(
        source_authority_test, bool
    ):
        failures.append("portable artifact test-authority marker is invalid")
    elif artifact_authority_test != source_authority_test:
        failures.append("portable artifact and source test-authority markers differ")
    elif artifact_authority_test and not allow_authority_test_receipt:
        failures.append("portable artifact is a non-distributable build-authority fixture")
    if payload.get("target") != target:
        failures.append(
            f"portable artifact target is {payload.get('target')!r}, expected {target!r}"
        )
    expected_from_source = {
        "product_source_key": source_payload.get("source_key"),
        "product_source_tree_sha256": source_payload.get("tree_sha256"),
        "product_source_receipt_sha256": source_receipt_sha256,
        "product_lock_sha256": source_payload.get("product_lock_sha256"),
        "provider_source_key": source_payload.get("provider_source_key"),
        "provider_patch_sha256": source_payload.get("provider_patch_sha256"),
        "provider_builder_sha256": source_payload.get("provider_builder_sha256"),
        "product_builder_sha256": source_payload.get("product_builder_sha256"),
    }
    for field, expected in expected_from_source.items():
        if payload.get(field) != expected:
            failures.append(
                f"portable artifact {field} is {payload.get(field)!r}, expected {expected!r}"
            )
    if payload.get("binary_sha256") != binary_sha256:
        failures.append("portable artifact binary digest differs from its receipt")
    if payload.get("binary_size") != binary_size:
        failures.append("portable artifact binary size differs from its receipt")
    expected_build_key = artifact_build_key(payload)
    if payload.get("build_key") != expected_build_key:
        failures.append("portable artifact build key does not describe its coordinates")
    for field in (*ARTIFACT_KEY_FIELDS, "binary_sha256"):
        value = payload.get(field)
        if not isinstance(value, str) or not value:
            failures.append(f"portable artifact receipt field {field!r} is empty")
    return failures


def validate_artifact_receipt(
    binary: Path,
    receipt: Path,
    source_receipt: Path,
    target: str,
    *,
    allow_authority_test_receipt: bool = False,
) -> list[str]:
    try:
        if receipt.is_symlink() or not receipt.is_file():
            return [f"portable artifact receipt is not a regular file: {receipt}"]
        if source_receipt.is_symlink() or not source_receipt.is_file():
            return [f"portable product-source receipt is not a regular file: {source_receipt}"]
        receipt_bytes = receipt.read_bytes()
        source_bytes = source_receipt.read_bytes()
        payload = json.loads(receipt_bytes)
        source_payload = json.loads(source_bytes)
    except (OSError, json.JSONDecodeError) as error:
        return [f"portable artifact receipt could not be read: {error}"]
    return validate_artifact_payload(
        payload=payload,
        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        binary_size=binary.stat().st_size,
        target=target,
        source_payload=source_payload,
        source_receipt_sha256=hashlib.sha256(source_bytes).hexdigest(),
        allow_authority_test_receipt=allow_authority_test_receipt,
    )


def validate_linux(
    *,
    target: str,
    file_output: str,
    program_headers: str,
    dynamic_section: str,
    section_headers: str,
) -> list[str]:
    failures: list[str] = []
    expected_arch = LINUX_TARGETS[target]
    if "ELF" not in file_output or expected_arch not in file_output:
        failures.append(
            f"Linux artifact is not the expected {expected_arch} ELF: {file_output!r}"
        )
    if not re.search(r"(?:statically linked|static-pie linked)", file_output):
        failures.append(f"Linux artifact is not statically linked: {file_output!r}")
    if "dynamically linked" in file_output:
        failures.append(f"Linux artifact is dynamically linked: {file_output!r}")
    if "stripped" not in file_output or "not stripped" in file_output:
        failures.append(f"Linux artifact is not stripped: {file_output!r}")
    if re.search(r"\bINTERP\b", program_headers):
        failures.append("Linux artifact contains a runtime program interpreter")
    if "(NEEDED)" in dynamic_section:
        failures.append("Linux artifact contains dynamic NEEDED dependencies")
    if re.search(r"\.(?:symtab|debug_[A-Za-z0-9_.-]+)\b", section_headers):
        failures.append("Linux artifact retains symbol or debug sections")
    return failures


def parse_macos_minimum(vtool_output: str) -> str | None:
    lines = [line.strip().split() for line in vtool_output.splitlines()]
    for fields in lines:
        if len(fields) >= 2 and fields[0] == "minos":
            return fields[1]
    for index, fields in enumerate(lines):
        if fields[:2] == ["cmd", "LC_VERSION_MIN_MACOSX"]:
            for candidate in lines[index + 1 :]:
                if len(candidate) >= 2 and candidate[0] == "version":
                    return candidate[1]
    return None


def parse_macos_dependencies(otool_output: str) -> list[str]:
    lines = otool_output.splitlines()
    return [line.strip().split()[0] for line in lines[1:] if line.strip()]


def validate_macos(
    *,
    target: str,
    architectures: str,
    vtool_output: str,
    otool_output: str,
) -> list[str]:
    failures: list[str] = []
    expected_arch, expected_minimum = MACOS_TARGETS[target]
    if architectures.strip() != expected_arch:
        failures.append(
            f"macOS artifact architectures are {architectures.strip()!r}, "
            f"expected exactly {expected_arch!r}"
        )
    actual_minimum = parse_macos_minimum(vtool_output)
    if actual_minimum != expected_minimum:
        failures.append(
            f"macOS deployment target is {actual_minimum!r}, "
            f"expected {expected_minimum!r}"
        )
    dependencies = parse_macos_dependencies(otool_output)
    if not dependencies:
        failures.append("macOS artifact exposes no inspectable dynamic dependencies")
    for dependency in dependencies:
        if not dependency.startswith(("/usr/lib/", "/System/Library/")):
            failures.append(
                f"macOS artifact contains a non-system dependency: {dependency}"
            )
    return failures


def validate_embedded_paths(payload: bytes, forbidden_paths: list[str]) -> list[str]:
    failures: list[str] = []
    normalized = ["/nix/store", *forbidden_paths]
    for path in normalized:
        if not path:
            continue
        marker = path.rstrip("/").encode() + b"/"
        if marker in payload:
            failures.append(
                f"artifact embeds forbidden machine-local path prefix {path.rstrip('/')!r}"
            )
    return failures


def validate_embedded_runtime_tooling(payload: bytes) -> list[str]:
    """Reject repository build-environment coupling in the shipped product."""
    lowered = payload.lower()
    return [
        f"artifact embeds forbidden build-environment token {token.decode()!r}"
        for token in FORBIDDEN_RUNTIME_TOOLING_TOKENS
        if token in lowered
    ]


def native_target() -> str | None:
    system = platform.system()
    machine = platform.machine().lower()
    if system == "Linux" and machine in {"x86_64", "amd64"}:
        return "x86_64-unknown-linux-musl"
    if system == "Linux" and machine in {"aarch64", "arm64"}:
        return "aarch64-unknown-linux-musl"
    if system == "Darwin" and machine in {"x86_64", "amd64"}:
        return "x86_64-apple-darwin"
    if system == "Darwin" and machine in {"aarch64", "arm64"}:
        return "aarch64-apple-darwin"
    return None


def validate_private_provider_dispatch(
    *,
    label: str,
    argument: str,
    help_output: str,
    returncode: int,
    stdout: str,
    stderr: str,
) -> list[str]:
    failures: list[str] = []
    if argument in help_output:
        failures.append(f"private {label}-provider dispatch leaked into public CLI help")
    if returncode == 0:
        failures.append(f"private {label}-provider dispatch accepted an incomplete frame")
    if stdout:
        failures.append(f"private {label}-provider dispatch wrote protocol noise to stdout")
    if not all(
        marker in stderr
        for marker in (
            "Internal semantic provider failed:",
            "provider transport I/O failed:",
        )
    ):
        failures.append(
            f"private {label}-provider dispatch did not reach the linked framed provider"
        )
    return failures


def validate_unowned_provider_refusal(
    *, returncode: int, stdout: str, stderr: str
) -> list[str]:
    failures: list[str] = []
    if returncode == 0:
        failures.append("private Rust-provider dispatch accepted an absent owning parent")
    if stdout:
        failures.append("unowned private Rust-provider dispatch wrote protocol noise to stdout")
    if not all(
        marker in stderr
        for marker in ("Internal semantic provider failed:", PROVIDER_PARENT_PID_ENV)
    ):
        failures.append("private Rust-provider dispatch did not enforce exact parent identity")
    return failures


def validate_product_runtime(
    *,
    version_returncode: int,
    version_stdout: str,
    help_returncode: int,
    help_output: str,
    rust_provider_returncode: int,
    rust_provider_stdout: str,
    rust_provider_stderr: str,
) -> list[str]:
    failures: list[str] = []
    if version_returncode != 0 or not version_stdout.strip().startswith("h00ligan "):
        failures.append("artifact does not expose the h00ligan version boundary")
    if help_returncode != 0 or "Usage: h00ligan" not in help_output:
        failures.append("artifact does not expose the h00ligan CLI boundary")
    failures.extend(
        validate_private_provider_dispatch(
            label="Rust",
            argument=INTERNAL_RUST_PROVIDER_ARGUMENT,
            help_output=help_output,
            returncode=rust_provider_returncode,
            stdout=rust_provider_stdout,
            stderr=rust_provider_stderr,
        )
    )
    return failures


def probe_product_runtime(binary: Path) -> list[str]:
    rustc = shutil.which(os.environ.get("RUSTC", "rustc"))
    cargo = shutil.which(os.environ.get("CARGO", "cargo"))
    if rustc is None or cargo is None:
        return ["artifact provider runtime probe requires installed rustc and cargo"]
    # Preserve rustup proxy basenames; resolving the symlink to `rustup` would
    # change the executable's dispatch identity.
    rustc_path = Path(rustc).absolute()
    cargo_path = Path(cargo).absolute()
    try:
        version = subprocess.run(
            [str(binary), "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        help_result = subprocess.run(
            [str(binary), "--help"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        provider_environment = {
            **os.environ,
            "H00_RESOLVED_TOOLCHAIN_SHA256": RESOLVED_TOOLCHAIN_SHA256,
            "H00_RUST_SEMANTIC_PROFILE": RUST_SEMANTIC_PROFILE,
            "RUSTC": str(rustc_path),
            "CARGO": str(cargo_path),
            "H00_RESOLVED_RUSTC_SHA256": hashlib.sha256(
                rustc_path.read_bytes()
            ).hexdigest(),
            "H00_RESOLVED_CARGO_SHA256": hashlib.sha256(
                cargo_path.read_bytes()
            ).hexdigest(),
        }
        rust_provider = subprocess.run(
            [str(binary), INTERNAL_RUST_PROVIDER_ARGUMENT],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            start_new_session=True,
            env={
                **provider_environment,
                PROVIDER_PARENT_PID_ENV: str(os.getpid()),
            },
        )
        unowned_rust_provider = subprocess.run(
            [str(binary), INTERNAL_RUST_PROVIDER_ARGUMENT],
            check=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=10,
            start_new_session=True,
            env=provider_environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return [f"artifact runtime boundary could not be exercised: {error}"]
    failures = validate_product_runtime(
        version_returncode=version.returncode,
        version_stdout=version.stdout,
        help_returncode=help_result.returncode,
        help_output=help_result.stdout + help_result.stderr,
        rust_provider_returncode=rust_provider.returncode,
        rust_provider_stdout=rust_provider.stdout,
        rust_provider_stderr=rust_provider.stderr,
    )
    failures.extend(
        validate_unowned_provider_refusal(
            returncode=unowned_rust_provider.returncode,
            stdout=unowned_rust_provider.stdout,
            stderr=unowned_rust_provider.stderr,
        )
    )
    return failures


def run(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise RuntimeError(f"could not execute {command[0]!r}: {error}") from error
    if result.returncode != 0:
        detail = " ".join((result.stderr or result.stdout).strip().split())
        raise RuntimeError(
            f"{' '.join(command)!r} exited {result.returncode}: {detail or 'no output'}"
        )
    return result.stdout


def check_binary(binary: Path, target: str, forbidden_paths: list[str]) -> list[str]:
    failures: list[str] = []
    if not binary.is_file():
        return [f"artifact is not a regular file: {binary}"]
    if not os.access(binary, os.X_OK):
        failures.append(f"artifact is not executable: {binary}")

    payload = binary.read_bytes()
    failures.extend(validate_embedded_paths(payload, forbidden_paths))
    failures.extend(validate_embedded_runtime_tooling(payload))
    for companion_name in FORBIDDEN_COMPANION_NAMES:
        if (binary.parent / companion_name).exists():
            failures.append(
                f"single-file product directory retains companion product {companion_name!r}"
            )
    if target == native_target():
        failures.extend(probe_product_runtime(binary))
    try:
        if target in LINUX_TARGETS:
            failures.extend(
                validate_linux(
                    target=target,
                    file_output=run(["file", str(binary)]),
                    program_headers=run(["readelf", "--program-headers", str(binary)]),
                    dynamic_section=run(["readelf", "--dynamic", str(binary)]),
                    section_headers=run(["readelf", "--section-headers", str(binary)]),
                )
            )
        elif target in MACOS_TARGETS:
            failures.extend(
                validate_macos(
                    target=target,
                    architectures=run(["lipo", "-archs", str(binary)]),
                    vtool_output=run(["xcrun", "vtool", "-show-build", str(binary)]),
                    otool_output=run(["otool", "-L", str(binary)]),
                )
            )
        else:
            failures.append(f"unsupported h00ligan distribution target: {target}")
    except RuntimeError as error:
        failures.append(str(error))
    return failures


def self_test() -> None:
    linux_file = (
        "h00ligan: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), "
        "static-pie linked, stripped"
    )
    accepted_linux = validate_linux(
        target="x86_64-unknown-linux-musl",
        file_output=linux_file,
        program_headers="LOAD 0x0000000000000000",
        dynamic_section="There is no dynamic section in this file.",
        section_headers="[ 1] .text PROGBITS",
    )
    accepted_linux += validate_embedded_paths(b"portable-h00ligan", [])
    if accepted_linux:
        raise AssertionError(f"valid static Linux fixture rejected: {accepted_linux!r}")

    accepted_macos = validate_macos(
        target="aarch64-apple-darwin",
        architectures="arm64\n",
        vtool_output="cmd LC_BUILD_VERSION\nminos 11.0\nsdk 26.0\n",
        otool_output=(
            "h00ligan:\n"
            "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0)\n"
            "\t/System/Library/Frameworks/Security.framework/Versions/A/Security "
            "(compatibility version 1.0.0)\n"
        ),
    )
    if accepted_macos:
        raise AssertionError(f"valid macOS fixture rejected: {accepted_macos!r}")

    accepted_runtime = validate_product_runtime(
        version_returncode=0,
        version_stdout="h00ligan 0.2.0\n",
        help_returncode=0,
        help_output="Usage: h00ligan [OPTIONS] <COMMAND>\n",
        rust_provider_returncode=1,
        rust_provider_stdout="",
        rust_provider_stderr=(
            "Internal semantic provider failed: read semantic-provider request: "
            "provider transport I/O failed: failed to fill whole buffer\n"
        ),
    )
    if accepted_runtime:
        raise AssertionError(
            f"valid single-file product runtime rejected: {accepted_runtime!r}"
        )
    accepted_owner_refusal = validate_unowned_provider_refusal(
        returncode=1,
        stdout="",
        stderr=(
            "Internal semantic provider failed: read required "
            f"{PROVIDER_PARENT_PID_ENV}: environment variable not found\n"
        ),
    )
    if accepted_owner_refusal:
        raise AssertionError(
            "valid unowned-provider refusal rejected: "
            f"{accepted_owner_refusal!r}"
        )

    binary_sha256 = hashlib.sha256(b"qualified portable product").hexdigest()
    source_receipt_sha256 = hashlib.sha256(b"qualified source receipt\n").hexdigest()
    source_payload = {
        "schema": SOURCE_SCHEMA,
        "source_key": "1" * 64,
        "tree_sha256": "2" * 64,
        "product_lock_sha256": "3" * 64,
        "provider_source_key": "4" * 64,
        "provider_patch_sha256": "5" * 64,
        "provider_builder_sha256": "6" * 64,
        "product_builder_sha256": "7" * 64,
    }
    artifact_payload = {
        "schema": ARTIFACT_SCHEMA,
        "target": "x86_64-unknown-linux-musl",
        "product_source_key": source_payload["source_key"],
        "product_source_tree_sha256": source_payload["tree_sha256"],
        "product_source_receipt_sha256": source_receipt_sha256,
        "product_lock_sha256": source_payload["product_lock_sha256"],
        "provider_source_key": source_payload["provider_source_key"],
        "provider_patch_sha256": source_payload["provider_patch_sha256"],
        "provider_builder_sha256": source_payload["provider_builder_sha256"],
        "python_provider_binary_sha256": "8" * 64,
        "python_provider_patch_sha256": "9" * 64,
        "python_provider_source_key": "a" * 64,
        "python_provider_source_tree_sha256": "b" * 64,
        "python_provider_builder_sha256": "c" * 64,
        "python_provider_archive_sha256": "d" * 64,
        "python_provider_cache_publisher_sha256": "e" * 64,
        "python_provider_receipt_sha256": "f" * 64,
        "go_provider_binary_sha256": "8" * 64,
        "go_provider_patch_sha256": "9" * 64,
        "go_provider_source_tree_sha256": "a" * 64,
        "go_provider_builder_sha256": "b" * 64,
        "go_provider_receipt_sha256": "c" * 64,
        "typescript_provider_binary_sha256": "d" * 64,
        "typescript_provider_patch_sha256": "e" * 64,
        "typescript_provider_test_sha256": "f" * 64,
        "typescript_provider_source_tree_sha256": "0" * 64,
        "typescript_provider_builder_sha256": "1" * 64,
        "typescript_provider_receipt_sha256": "2" * 64,
        "product_builder_sha256": source_payload["product_builder_sha256"],
        "rustc": "rustc 1.97.1 fixture",
        "cargo": "cargo 1.97.1 fixture",
        "linker": "zig 0.16.0 fixture",
        "rustflags": "--remap-path-prefix=fixture",
        "cflags": "-ffile-prefix-map=fixture",
        "cxxflags": "-ffile-prefix-map=fixture",
        "binary_sha256": binary_sha256,
        "binary_size": len(b"qualified portable product"),
    }
    artifact_payload["build_key"] = artifact_build_key(artifact_payload)
    if failures := validate_artifact_payload(
        payload=artifact_payload,
        binary_sha256=binary_sha256,
        binary_size=len(b"qualified portable product"),
        target="x86_64-unknown-linux-musl",
        source_payload=source_payload,
        source_receipt_sha256=source_receipt_sha256,
    ):
        raise AssertionError(f"valid portable artifact receipt rejected: {failures!r}")
    authority_source = {**source_payload, "authority_test": True}
    authority_artifact = {**artifact_payload, "authority_test": True}
    if failures := validate_artifact_payload(
        payload=authority_artifact,
        binary_sha256=binary_sha256,
        binary_size=len(b"qualified portable product"),
        target="x86_64-unknown-linux-musl",
        source_payload=authority_source,
        source_receipt_sha256=source_receipt_sha256,
        allow_authority_test_receipt=True,
    ):
        raise AssertionError(f"explicit test fixture receipt rejected: {failures!r}")
    authority_failures = validate_artifact_payload(
        payload=authority_artifact,
        binary_sha256=binary_sha256,
        binary_size=len(b"qualified portable product"),
        target="x86_64-unknown-linux-musl",
        source_payload=authority_source,
        source_receipt_sha256=source_receipt_sha256,
    )
    if not any("non-distributable" in failure for failure in authority_failures):
        raise AssertionError("test-fixture receipt was accepted as distributable")
    receipt_sabotages = {
        "wrong binary": (artifact_payload, "8" * 64, source_payload),
        "wrong source": (
            artifact_payload,
            binary_sha256,
            {**source_payload, "source_key": "9" * 64},
        ),
        "wrong build key": (
            {**artifact_payload, "build_key": "d" * 64},
            binary_sha256,
            source_payload,
        ),
        "wrong Go provider identity": (
            {**artifact_payload, "go_provider_binary_sha256": "e" * 64},
            binary_sha256,
            source_payload,
        ),
        "wrong Python provider identity": (
            {**artifact_payload, "python_provider_source_key": "b" * 64},
            binary_sha256,
            source_payload,
        ),
        "wrong TypeScript provider identity": (
            {**artifact_payload, "typescript_provider_binary_sha256": "3" * 64},
            binary_sha256,
            source_payload,
        ),
        "wrong target": (artifact_payload, binary_sha256, source_payload),
    }
    for name, (candidate, candidate_binary_sha, candidate_source) in receipt_sabotages.items():
        candidate_target = (
            "aarch64-unknown-linux-musl"
            if name == "wrong target"
            else "x86_64-unknown-linux-musl"
        )
        if not validate_artifact_payload(
            payload=candidate,
            binary_sha256=candidate_binary_sha,
            binary_size=len(b"qualified portable product"),
            target=candidate_target,
            source_payload=candidate_source,
            source_receipt_sha256=source_receipt_sha256,
        ):
            raise AssertionError(f"portable receipt {name} sabotage was accepted")

    sabotages = {
        "dynamic Linux": validate_linux(
            target="x86_64-unknown-linux-musl",
            file_output=(
                "h00ligan: ELF 64-bit LSB pie executable, x86-64, dynamically linked"
            ),
            program_headers="INTERP 0x0000000000000318",
            dynamic_section="0x0000000000000001 (NEEDED) Shared library: [libc.so.6]",
            section_headers="[ 1] .text PROGBITS",
        ),
        "unstripped Linux": validate_linux(
            target="x86_64-unknown-linux-musl",
            file_output=(
                "h00ligan: ELF 64-bit LSB pie executable, x86-64, "
                "static-pie linked, not stripped"
            ),
            program_headers="LOAD 0x0000000000000000",
            dynamic_section="There is no dynamic section in this file.",
            section_headers="[27] .symtab SYMTAB",
        ),
        "wrong Linux architecture": validate_linux(
            target="aarch64-unknown-linux-musl",
            file_output=linux_file,
            program_headers="LOAD 0x0000000000000000",
            dynamic_section="There is no dynamic section in this file.",
            section_headers="[ 1] .text PROGBITS",
        ),
        "Nix path": validate_embedded_paths(
            b"loader=/nix/store/abc-glibc/lib/ld-linux-x86-64.so.2", []
        ),
        "Devbox runtime coupling": validate_embedded_runtime_tooling(
            b"exec devbox run -- h00ligan"
        ),
        "wrong macOS architecture": validate_macos(
            target="aarch64-apple-darwin",
            architectures="x86_64\n",
            vtool_output="minos 11.0\n",
            otool_output="h00ligan:\n\t/usr/lib/libSystem.B.dylib (compatibility 1.0.0)\n",
        ),
        "wrong macOS deployment": validate_macos(
            target="x86_64-apple-darwin",
            architectures="x86_64\n",
            vtool_output="minos 14.0\n",
            otool_output="h00ligan:\n\t/usr/lib/libSystem.B.dylib (compatibility 1.0.0)\n",
        ),
        "foreign macOS dependency": validate_macos(
            target="aarch64-apple-darwin",
            architectures="arm64\n",
            vtool_output="minos 11.0\n",
            otool_output=(
                "h00ligan:\n\t/opt/homebrew/lib/libssl.3.dylib (compatibility 3.0.0)\n"
            ),
        ),
        "public hidden Rust provider": validate_product_runtime(
            version_returncode=0,
            version_stdout="h00ligan 0.2.0\n",
            help_returncode=0,
            help_output=f"Usage: h00ligan\n{INTERNAL_RUST_PROVIDER_ARGUMENT}\n",
            rust_provider_returncode=1,
            rust_provider_stdout="",
            rust_provider_stderr=(
                "Internal semantic provider failed: provider transport I/O failed:\n"
            ),
        ),
        "missing linked Rust provider": validate_product_runtime(
            version_returncode=0,
            version_stdout="h00ligan 0.2.0\n",
            help_returncode=0,
            help_output="Usage: h00ligan\n",
            rust_provider_returncode=2,
            rust_provider_stdout="",
            rust_provider_stderr="error: unrecognized subcommand\n",
        ),
        "unowned Rust provider accepted": validate_unowned_provider_refusal(
            returncode=0,
            stdout="",
            stderr="",
        ),
    }
    for name, failures in sabotages.items():
        if not failures:
            raise AssertionError(f"{name} sabotage was accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--target", choices=sorted([*LINUX_TARGETS, *MACOS_TARGETS]))
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--source-receipt", type=Path)
    parser.add_argument("--forbid-path", action="append", default=[])
    parser.add_argument("--allow-authority-test-receipt", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        if not args.quiet:
            print(
                "h00ligan-binary: self-test OK "
                "(5 positives; 16 sabotages fired)"
            )

    if (args.binary is None) != (args.target is None):
        parser.error("--binary and --target must be supplied together")
    if args.binary is None:
        if not args.self_test:
            parser.error("provide --binary and --target, or --self-test")
        return 0

    binary = args.binary.resolve()
    failures = check_binary(binary, args.target, args.forbid_path)
    if (args.receipt is None) != (args.source_receipt is None):
        parser.error("--receipt and --source-receipt must be supplied together")
    if args.receipt is not None and binary.is_file():
        failures.extend(
            validate_artifact_receipt(
                binary,
                args.receipt.resolve(),
                args.source_receipt.resolve(),
                args.target,
                allow_authority_test_receipt=args.allow_authority_test_receipt,
            )
        )
    if failures:
        print("h00ligan-binary: FAIL", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"h00ligan-binary: OK ({args.target}; {binary})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
