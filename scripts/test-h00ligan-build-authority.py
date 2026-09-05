#!/usr/bin/env python3
"""Adversarial installed-boundary proof for portable build identity and capture."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
import time


EXPECTED_PRODUCT_SOURCE_INPUTS = (
    "crates/h00ligan-engine/Cargo.toml",
    "crates/h00ligan-engine/build.rs",
    "crates/h00ligan-engine/build_support",
    "crates/h00ligan-engine/examples",
    "crates/h00ligan-engine/src",
    "crates/h00ligan-interface/Cargo.toml",
    "crates/h00ligan-interface/src",
    "crates/h00ligan-provider-protocol/Cargo.toml",
    "crates/h00ligan-provider-protocol/src",
    "crates/h00ligan/Cargo.toml",
    "crates/h00ligan/README.md",
    "crates/h00ligan/src",
)

PREPARED_SOURCE_OVERLAY_PATHS = (
    "src/tools/rust-analyzer/crates/h00ligan-provider-protocol/Cargo.toml",
    "src/tools/rust-analyzer/crates/h00ligan-ra-provider/Cargo.toml",
    "src/tools/rust-analyzer/crates/h00ligan-provider-protocol/src/lib.rs",
    "src/tools/rust-analyzer/crates/h00ligan-ra-provider/src/lib.rs",
    "src/tools/rust-analyzer/crates/h00ligan-ra-provider/src/main.rs",
)

# The harness owns barrier liveness. Builder-side barriers outlive this bound
# so a cold source capture cannot release authority before the harness has
# either observed the intended state or terminated the process group.
HARNESS_WAIT_TIMEOUT_SECONDS = 120.0
BUILDER_BARRIER_TIMEOUT_SECONDS = 180


def native_target() -> str:
    system = platform.system()
    machine = platform.machine().lower()
    targets = {
        ("Linux", "x86_64"): "x86_64-unknown-linux-musl",
        ("Linux", "aarch64"): "aarch64-unknown-linux-musl",
        ("Linux", "arm64"): "aarch64-unknown-linux-musl",
        ("Darwin", "x86_64"): "x86_64-apple-darwin",
        ("Darwin", "arm64"): "aarch64-apple-darwin",
        ("Darwin", "aarch64"): "aarch64-apple-darwin",
    }
    try:
        return targets[(system, machine)]
    except KeyError as error:
        raise SystemExit(f"unsupported build-authority host: {system} {machine}") from error


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class BuilderRun:
    def __init__(self, command: list[str], environment: dict[str, str], log_root: Path):
        log_root.mkdir(parents=True, exist_ok=True)
        self.stdout_path = log_root / "stdout"
        self.stderr_path = log_root / "stderr"
        self.stdout_file = self.stdout_path.open("wb")
        self.stderr_file = self.stderr_path.open("wb")
        self.process = subprocess.Popen(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=self.stdout_file,
            stderr=self.stderr_file,
            start_new_session=True,
        )

    def diagnostics(self) -> str:
        def tail(path: Path) -> str:
            with path.open("rb") as stream:
                size = stream.seek(0, os.SEEK_END)
                stream.seek(max(0, size - 4096))
                contents = stream.read(4096).decode("utf-8", errors="replace")
            return ("[tail] " if size > 4096 else "") + contents

        return f"stdout={tail(self.stdout_path)!r} stderr={tail(self.stderr_path)!r}"

    def finish(self, timeout: float = 180.0) -> tuple[int, str, str]:
        try:
            returncode = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.terminate()
            raise AssertionError(
                f"portable builder timed out before terminal exit: {self.diagnostics()}"
            ) from None
        finally:
            self.stdout_file.close()
            self.stderr_file.close()
        return (
            returncode,
            self.stdout_path.read_text(encoding="utf-8", errors="replace"),
            self.stderr_path.read_text(encoding="utf-8", errors="replace"),
        )

    def terminate(self) -> None:
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGTERM)
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)
        if not self.stdout_file.closed:
            self.stdout_file.close()
        if not self.stderr_file.closed:
            self.stderr_file.close()


def wait_for(
    path: Path,
    run: BuilderRun,
    description: str,
    timeout: float = HARNESS_WAIT_TIMEOUT_SECONDS,
) -> None:
    started = time.monotonic()
    deadline = started + timeout
    print(f"build-authority: waiting for {description} (bound {timeout:g}s)", file=sys.stderr, flush=True)
    while time.monotonic() < deadline:
        if path.is_file() and not path.is_symlink():
            print(
                f"build-authority: reached {description} in {time.monotonic() - started:.3f}s",
                file=sys.stderr, flush=True,
            )
            return
        if run.process.poll() is not None:
            run.terminate()
            raise AssertionError(
                f"builder exited {run.process.returncode} before {description}: {run.diagnostics()}"
            )
        time.sleep(0.05)
    run.terminate()
    raise AssertionError(
        f"timed out waiting for {description}: {path}; {run.diagnostics()}"
    )


def parse_machine_output(stdout: str) -> dict[str, Path | str]:
    fields: dict[str, str] = {}
    for line in stdout.splitlines():
        name, separator, value = line.partition("=")
        if separator:
            fields[name] = value
    required = (
        "H00LIGAN_BINARY",
        "H00LIGAN_RECEIPT",
        "H00LIGAN_PRODUCT_SOURCE_RECEIPT",
        "H00LIGAN_PRODUCT_SOURCE_KEY",
        "H00LIGAN_ARTIFACT_BUILD_KEY",
        "H00LIGAN_TARGET",
    )
    missing = [name for name in required if not fields.get(name)]
    if missing:
        raise AssertionError(f"builder machine output omitted {missing!r}: {stdout!r}")
    return {
        **fields,
        "binary": Path(fields["H00LIGAN_BINARY"]),
        "receipt": Path(fields["H00LIGAN_RECEIPT"]),
        "source_receipt": Path(fields["H00LIGAN_PRODUCT_SOURCE_RECEIPT"]),
    }


def assert_receipted_fixture(result: dict[str, Path | str], expected_binary: Path) -> None:
    binary = result["binary"]
    receipt = result["receipt"]
    source_receipt = result["source_receipt"]
    assert isinstance(binary, Path)
    assert isinstance(receipt, Path)
    assert isinstance(source_receipt, Path)
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    source = json.loads(source_receipt.read_text(encoding="utf-8"))
    source_root = source_receipt.parent
    source_manifest = source_root / ".h00-build-inputs/h00ligan-product-source-inputs"
    source_inputs = tuple(source_manifest.read_text(encoding="utf-8").splitlines())
    if source_inputs != EXPECTED_PRODUCT_SOURCE_INPUTS:
        raise AssertionError(
            "portable product source projection is incomplete or reordered: "
            f"{source_inputs!r}"
        )
    missing_positive = [
        relative
        for relative in EXPECTED_PRODUCT_SOURCE_INPUTS
        if not (source_root / "source" / relative).exists()
    ]
    if missing_positive:
        raise AssertionError(
            f"portable product source positives are missing: {missing_positive!r}"
        )
    excluded = [
        source_root / "source/crates" / crate / directory
        for crate in (
            "h00ligan-interface",
            "h00ligan-engine",
            "h00ligan",
            "h00ligan-provider-protocol",
        )
        for directory in ("tests", "testdata")
        if (source_root / "source/crates" / crate / directory).exists()
    ]
    if excluded:
        raise AssertionError(
            "non-product test populations entered the portable product source key: "
            f"{excluded!r}"
        )
    if not isinstance(source.get("file_count"), int) or source["file_count"] <= len(
        EXPECTED_PRODUCT_SOURCE_INPUTS
    ):
        raise AssertionError("portable product source population is vacuous")
    if payload.get("authority_test") is not True or source.get("authority_test") is not True:
        raise AssertionError("build-authority fixture receipts are not visibly non-distributable")
    if payload.get("binary_sha256") != sha256(binary):
        raise AssertionError("artifact receipt does not bind the captured binary bytes")
    if payload.get("binary_size") != binary.stat().st_size:
        raise AssertionError("artifact receipt does not bind the captured binary size")
    if sha256(binary) != sha256(expected_binary):
        raise AssertionError("immutable artifact did not capture its invocation's output bytes")
    if payload.get("product_source_key") != source.get("source_key"):
        raise AssertionError("artifact receipt does not bind its product-source receipt")
    if payload.get("build_key") != result["H00LIGAN_ARTIFACT_BUILD_KEY"]:
        raise AssertionError("machine output and artifact receipt disagree on build identity")
    if binary.parent.name != payload.get("build_key"):
        raise AssertionError("artifact path is not content-addressed by its build identity")


def inspect_stable_build_workspace(root: Path, target: str) -> tuple[Path, str]:
    parent = root / "portable-workspaces"
    workspace = parent / target
    if parent.is_symlink() or workspace.is_symlink() or not workspace.is_dir():
        raise AssertionError(
            "portable builds must materialize one real target-owned stable workspace"
        )
    population = sorted(
        path.name for path in parent.iterdir() if path.is_dir() and not path.is_symlink()
    )
    if population != [target]:
        raise AssertionError(
            "portable build-workspace population is not bounded by target: "
            f"{population!r}"
        )
    receipt = workspace / ".h00-h00ligan-product-source.json"
    if receipt.is_symlink() or not receipt.is_file():
        raise AssertionError("stable build workspace has no exact source receipt")
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    source_key = payload.get("source_key")
    if not isinstance(source_key, str) or len(source_key) != 64:
        raise AssertionError("stable build workspace has no valid source identity")
    return workspace, source_key


def builder_environment(
    *, root: Path, input_path: Path, binary: Path, barrier: Path | None = None
) -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "H00LIGAN_BUILDER_INVOCATION_ROOT",
        "H00LIGAN_BUILDER_INVOCATION_TOKEN",
        "H00LIGAN_BUILDER_LIVE_SCRIPT",
        "H00LIGAN_BUILDER_REPO_ROOT",
        "H00LIGAN_BUILD_TEST_BARRIER",
        "H00LIGAN_BUILD_TEST_CAPTURE_BARRIER",
        "H00LIGAN_BUILD_TEST_BARRIER_TIMEOUT_SECONDS",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "H00LIGAN_BUILD_AUTHORITY_TEST": "1",
            "H00LIGAN_BUILD_TEST_ROOT": str(root),
            "H00LIGAN_BUILD_TEST_INPUT": str(input_path),
            "H00LIGAN_BUILD_TEST_BINARY": str(binary),
            "H00LIGAN_BUILD_LOCK_TIMEOUT_SECONDS": "120",
            "H00LIGAN_BUILD_TEST_BARRIER_TIMEOUT_SECONDS": str(
                BUILDER_BARRIER_TIMEOUT_SECONDS
            ),
        }
    )
    if barrier is not None:
        environment["H00LIGAN_BUILD_TEST_CAPTURE_BARRIER"] = str(barrier)
    return environment


def make_command(builder: Path, target: str) -> list[str]:
    return [str(builder), "--target", target, "--machine"]


def validate_prepared_source_cache(root: Path) -> None:
    receipt = root / ".h00-semantic-provider-source.json"
    if root.is_symlink() or not root.is_dir():
        raise AssertionError(f"prepared Rust source cache is not a real directory: {root}")
    if receipt.is_symlink() or not receipt.is_file():
        raise AssertionError("prepared Rust source cache lacks a regular receipt")
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    source_key = payload.get("source_key")
    if (
        payload.get("schema") != "h00/rust-semantic-provider-source-cache/v2"
        or not isinstance(source_key, str)
        or len(source_key) != 64
        or payload.get("authority_test") is not None
        or root.name != f"rust-{source_key}"
        or not (root / "src/tools/rust-analyzer").is_dir()
    ):
        raise AssertionError("prepared Rust source cache receipt is not production authority")


def make_truncated_source_cache(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True)
    shutil.copy2(
        source / ".h00-semantic-provider-source.json",
        destination / ".h00-semantic-provider-source.json",
    )
    for relative in PREPARED_SOURCE_OVERLAY_PATHS:
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, output)


def make_seed(source: Path, output: Path, marker: bytes) -> None:
    output.write_bytes(source.read_bytes() + marker)
    output.chmod(0o755)


def prove_cargo_mtime_hazard_is_live(root: Path) -> None:
    """Positive control: current Cargo can reuse changed same-path bytes by old mtime."""
    fixture = root / "cargo-mtime-positive-control"
    source = fixture / "src/main.rs"
    target = fixture / "target"
    source.parent.mkdir(parents=True)
    (fixture / "Cargo.toml").write_text(
        '[package]\nname = "h00-mtime-positive-control"\nversion = "0.0.0"\n'
        'edition = "2024"\n\n[workspace]\n',
        encoding="utf-8",
    )
    source_a = b'fn main() { print!("source-a"); }\n'
    source_b = b'fn main() { print!("source-b"); }\n'
    if len(source_a) != len(source_b):
        raise AssertionError("Cargo mtime control sources must have equal byte lengths")
    historical_ns = 946_684_800_000_000_000
    source.write_bytes(source_a)
    os.utime(source, ns=(historical_ns, historical_ns))
    command = [
        "cargo",
        "build",
        "--offline",
        "--quiet",
        "--manifest-path",
        str(fixture / "Cargo.toml"),
        "--target-dir",
        str(target),
    ]
    environment = {**os.environ, "CARGO_INCREMENTAL": "0"}
    subprocess.run(command, check=True, env=environment)
    binary = target / "debug/h00-mtime-positive-control"
    if subprocess.run([str(binary)], check=True, capture_output=True).stdout != b"source-a":
        raise AssertionError("Cargo mtime control did not build source A")

    time.sleep(0.02)
    source.write_bytes(source_b)
    subprocess.run(command, check=True, env=environment)
    if subprocess.run([str(binary)], check=True, capture_output=True).stdout != b"source-b":
        raise AssertionError("Cargo mtime control did not build source B")

    source.write_bytes(source_a)
    os.utime(source, ns=(historical_ns, historical_ns))
    subprocess.run(command, check=True, env=environment)
    if subprocess.run([str(binary)], check=True, capture_output=True).stdout != b"source-b":
        raise AssertionError(
            "Cargo mtime hazard positive control did not retain the newer binary"
        )


def provider_environment(repo: Path, input_path: Path, barrier: Path) -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "H00_RA_BUILDER_INVOCATION_ROOT",
        "H00_RA_BUILDER_LIVE_SCRIPT",
        "H00_RA_BUILDER_REPO_ROOT",
        "H00_RA_BUILD_TEST_ROOT",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "H00_RA_BUILD_AUTHORITY_TEST": "1",
            "H00_RA_BUILD_TEST_ROOT": str(repo.parent),
            "H00_RA_BUILD_TEST_INPUT": str(input_path),
            "H00_RA_BUILD_TEST_BARRIER": str(barrier),
        }
    )
    return environment


def normal_provider_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "H00_RA_BUILDER_INVOCATION_ROOT",
        "H00_RA_BUILDER_LIVE_SCRIPT",
        "H00_RA_BUILDER_REPO_ROOT",
        "H00_RA_BUILD_AUTHORITY_TEST",
        "H00_RA_BUILD_TEST_ROOT",
        "H00_RA_BUILD_TEST_INPUT",
        "H00_RA_BUILD_TEST_BARRIER",
        "H00_RUST_SOURCE_DIR",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
    ):
        environment.pop(name, None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def copy_provider_fixture(repo: Path, fixture: Path) -> Path:
    relative_inputs = (
        "scripts/build-h00-rust-semantic-provider.sh",
        "providers/rust-analyzer/rust-analyzer-1.97.1.patch",
        "providers/rust-analyzer/protocol-provider.Cargo.toml",
        "providers/rust-analyzer/sidecar.Cargo.toml",
        "providers/rust-analyzer/h00ligan_ra_provider.rs",
        "providers/rust-analyzer/h00ligan_ra_provider_main.rs",
        "crates/h00ligan-provider-protocol/src/lib.rs",
    )
    for relative in relative_inputs:
        destination = fixture / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo / relative, destination)
    builder = fixture / "scripts/build-h00-rust-semantic-provider.sh"
    builder.chmod(0o755)
    return builder


def run_test(args: argparse.Namespace) -> None:
    repo = Path(__file__).resolve().parent.parent
    builder = repo / "scripts/build-h00ligan-portable.sh"
    checker = repo / "scripts/check-h00ligan-binary.py"
    seed = args.seed_binary.resolve()
    if seed.is_symlink() or not seed.is_file() or not os.access(seed, os.X_OK):
        raise AssertionError(f"seed binary is not a real executable: {seed}")
    rust_source_cache = args.rust_source_cache.resolve()
    validate_prepared_source_cache(rust_source_cache)
    invocation_parent = repo / "target/portable-cache/invocations"
    invocation_before = (
        {path.name for path in invocation_parent.iterdir()} if invocation_parent.is_dir() else set()
    )
    active: list[BuilderRun] = []

    with tempfile.TemporaryDirectory(
        prefix="h00ligan-build-authority.", dir=os.environ.get("TMPDIR")
    ) as raw:
        scratch = Path(raw)
        prove_cargo_mtime_hazard_is_live(scratch)
        seed_a = scratch / "seed-a-h00ligan"
        seed_b = scratch / "seed-b-h00ligan"
        make_seed(seed, seed_a, b"\nH00_BUILD_AUTHORITY_VARIANT_A\n")
        make_seed(seed, seed_b, b"\nH00_BUILD_AUTHORITY_VARIANT_B\n")
        if sha256(seed_a) == sha256(seed_b):
            raise AssertionError("distinct-output positive control did not fire")

        command = make_command(builder, args.target)
        try:
            # Ambient internal variables are not lifecycle authority. A copied
            # snapshot with a caller-selected root but no parent-created token
            # must fail before arming cleanup, and the foreign root must remain
            # untouched. Later successful builder runs are the known-positive
            # private-handoff controls.
            forged_root = scratch / "forged-invocation"
            forged_root.mkdir()
            forged_builder = forged_root / "build-h00ligan.sh"
            shutil.copy2(builder, forged_builder)
            forged_builder.chmod(0o755)
            forged_environment = os.environ.copy()
            forged_environment.update(
                {
                    "H00LIGAN_BUILDER_INVOCATION_ROOT": str(forged_root),
                    "H00LIGAN_BUILDER_INVOCATION_TOKEN": "0" * 64,
                    "H00LIGAN_BUILDER_LIVE_SCRIPT": str(builder),
                    "H00LIGAN_BUILDER_REPO_ROOT": str(repo),
                }
            )
            forged = subprocess.run(
                [str(forged_builder), "--target", args.target],
                check=False,
                capture_output=True,
                text=True,
                env=forged_environment,
            )
            if forged.returncode == 0 or "lacks a valid private handoff" not in forged.stderr:
                raise AssertionError(
                    "ambient private-handoff forgery did not fail for the intended reason: "
                    f"returncode={forged.returncode} stderr={forged.stderr!r}"
                )
            if not forged_root.is_dir() or not forged_builder.is_file():
                raise AssertionError("unverified invocation root was destructively cleaned")

            # The provider preparer has the same stage-then-key obligation. Run
            # an exact copied entrypoint under the caller-selected temporary
            # root so the test can mutate its own live input without ever
            # touching the operator's repository.
            provider_repo = scratch / "provider-repo"
            provider_builder = copy_provider_fixture(repo, provider_repo)
            truncated_source_cache = scratch / "truncated-source-cache"
            make_truncated_source_cache(rust_source_cache, truncated_source_cache)
            truncated_repo = scratch / "truncated-provider-repo"
            truncated_builder = copy_provider_fixture(repo, truncated_repo)
            truncated = subprocess.run(
                [
                    str(truncated_builder),
                    "--prepare-only",
                    "--machine",
                    "--prepared-source-cache",
                    str(truncated_source_cache),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=normal_provider_environment(),
                timeout=HARNESS_WAIT_TIMEOUT_SECONDS,
            )
            if (
                truncated.returncode == 0
                or "semantic-provider source cache failed integrity verification"
                not in truncated.stderr
            ):
                raise AssertionError(
                    "truncated prepared source cache did not fail integrity: "
                    f"returncode={truncated.returncode} stderr={truncated.stderr!r}"
                )
            truncated_build = truncated_repo / "target/semantic-provider/build"
            if truncated_build.exists() and list(truncated_build.glob("rust-*")):
                raise AssertionError("truncated prepared source cache was published")
            provider_barriers = provider_repo / "barriers"
            provider_barriers.mkdir()
            provider_input = provider_repo / "authority-input"
            provider_input.write_text("provider-original\n", encoding="utf-8")
            provider_barrier = provider_barriers / "staged"
            provider_entrypoint = [str(provider_builder)]
            if os.environ.get("H00_RA_BUILD_AUTHORITY_TRACE") == "1":
                provider_entrypoint = ["bash", "-x", str(provider_builder)]
            provider_command = [
                *provider_entrypoint,
                "--prepare-only",
                "--machine",
                "--prepared-source-cache",
                str(rust_source_cache),
            ]
            provider_drift = BuilderRun(
                provider_command,
                provider_environment(provider_repo, provider_input, provider_barrier),
                provider_repo / "logs-drift",
            )
            active.append(provider_drift)
            wait_for(
                provider_barrier.with_suffix(".ready"),
                provider_drift,
                "provider staged-input barrier",
            )
            provider_input.write_text("provider-changed\n", encoding="utf-8")
            provider_barrier.with_suffix(".continue").touch()
            code, _, stderr = provider_drift.finish()
            active.remove(provider_drift)
            if code == 0 or "changed after snapshot" not in stderr:
                raise AssertionError(
                    f"provider post-snapshot drift did not fail for the intended reason: {stderr!r}"
                )
            provider_build = provider_repo / "target/semantic-provider/build"
            if provider_build.exists() and list(provider_build.glob("rust-*")):
                raise AssertionError("failed provider drift probe published source authority")

            provider_input.write_text("provider-aba\n", encoding="utf-8")
            provider_barrier.with_suffix(".ready").unlink(missing_ok=True)
            provider_barrier.with_suffix(".continue").unlink(missing_ok=True)
            provider_aba = BuilderRun(
                provider_command,
                provider_environment(provider_repo, provider_input, provider_barrier),
                provider_repo / "logs-aba",
            )
            active.append(provider_aba)
            wait_for(
                provider_barrier.with_suffix(".ready"),
                provider_aba,
                "provider ABA staged-input barrier",
            )
            provider_input.write_text("provider-transient\n", encoding="utf-8")
            provider_input.write_text("provider-aba\n", encoding="utf-8")
            provider_barrier.with_suffix(".continue").touch()
            code, stdout, stderr = provider_aba.finish()
            active.remove(provider_aba)
            if code != 0:
                raise AssertionError(
                    "provider snapshot-safe ABA control failed: "
                    f"returncode={code} stdout={stdout!r} stderr={stderr!r}"
                )
            provider_fields = {
                name: value
                for line in stdout.splitlines()
                for name, separator, value in [line.partition("=")]
                if separator
            }
            provider_source = Path(provider_fields["H00_RA_SOURCE_ROOT"])
            provider_receipt = provider_source.parents[2] / ".h00-semantic-provider-source.json"
            provider_payload = json.loads(provider_receipt.read_text(encoding="utf-8"))
            if provider_payload.get("authority_test") is not True:
                raise AssertionError("provider test cache is not visibly non-authoritative")
            if provider_source.parents[2].name != f"rust-{provider_fields['H00_RA_SOURCE_KEY']}":
                raise AssertionError("provider source path does not match its staged source key")

            normal_reuse_repo = scratch / "normal-reuse-provider-repo"
            normal_reuse_builder = copy_provider_fixture(repo, normal_reuse_repo)
            normal_reuse = subprocess.run(
                [
                    str(normal_reuse_builder),
                    "--prepare-only",
                    "--machine",
                    "--prepared-source-cache",
                    str(provider_source.parents[2]),
                ],
                check=False,
                capture_output=True,
                text=True,
                env=normal_provider_environment(),
                timeout=HARNESS_WAIT_TIMEOUT_SECONDS,
            )
            if (
                normal_reuse.returncode == 0
                or "prepared semantic-provider source cache is incompatible"
                not in normal_reuse.stderr
            ):
                raise AssertionError(
                    "normal builder accepted authority-test source cache: "
                    f"returncode={normal_reuse.returncode} stderr={normal_reuse.stderr!r}"
                )
            normal_reuse_build = normal_reuse_repo / "target/semantic-provider/build"
            if normal_reuse_build.exists() and list(normal_reuse_build.glob("rust-*")):
                raise AssertionError("normal builder published authority-test source cache")

            # Right-reason RED: once the private snapshot exists, changed live
            # input must fail before any source or artifact publication.
            drift_root = scratch / "drift"
            drift_barriers = drift_root / "barriers"
            drift_barriers.mkdir(parents=True)
            drift_input = drift_root / "live-input"
            drift_input.write_text("drift-original\n", encoding="utf-8")
            drift_barrier = drift_barriers / "staged"
            drift_env = builder_environment(
                root=drift_root, input_path=drift_input, binary=seed_a
            )
            drift_env["H00LIGAN_BUILD_TEST_BARRIER"] = str(drift_barrier)
            drift = BuilderRun(command, drift_env, drift_root / "logs")
            active.append(drift)
            wait_for(drift_barrier.with_suffix(".ready"), drift, "staged-input barrier")
            drift_input.write_text("drift-changed\n", encoding="utf-8")
            drift_barrier.with_suffix(".continue").touch()
            code, _, stderr = drift.finish()
            active.remove(drift)
            if code == 0 or "authority-test-input" not in stderr:
                raise AssertionError(
                    f"post-snapshot drift did not fail for the intended reason: {stderr!r}"
                )
            cache = drift_root / "portable-cache"
            if list(cache.glob("product-source-*")) or list(cache.glob("artifacts/*/*")):
                raise AssertionError("failed drift probe published source or artifact authority")

            # ABA is safe because Cargo consumes the immutable snapshot: the
            # temporary live mutation is restored before admission, while the
            # captured bytes remain those staged at invocation start.
            aba_root = scratch / "aba"
            aba_barriers = aba_root / "barriers"
            aba_barriers.mkdir(parents=True)
            aba_input = aba_root / "live-input"
            original = b"aba-original\n"
            aba_input.write_bytes(original)
            aba_barrier = aba_barriers / "staged"
            aba_env = builder_environment(root=aba_root, input_path=aba_input, binary=seed_a)
            aba_env["H00LIGAN_BUILD_TEST_BARRIER"] = str(aba_barrier)
            aba = BuilderRun(command, aba_env, aba_root / "logs")
            active.append(aba)
            wait_for(aba_barrier.with_suffix(".ready"), aba, "ABA staged-input barrier")
            aba_input.write_bytes(b"aba-transient\n")
            aba_input.write_bytes(original)
            aba_barrier.with_suffix(".continue").touch()
            code, stdout, stderr = aba.finish()
            active.remove(aba)
            if code != 0:
                raise AssertionError(
                    "snapshot-safe ABA control failed: "
                    f"returncode={code} stdout={stdout!r} stderr={stderr!r}"
                )
            aba_result = parse_machine_output(stdout)
            assert_receipted_fixture(aba_result, seed_a)

            # Test-only substituted artifacts are unmistakably barred from the
            # distribution checker unless its explicit internal flag is used.
            refusal = subprocess.run(
                [
                    "python3",
                    str(checker),
                    "--binary",
                    str(aba_result["binary"]),
                    "--target",
                    args.target,
                    "--receipt",
                    str(aba_result["receipt"]),
                    "--source-receipt",
                    str(aba_result["source_receipt"]),
                    "--quiet",
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            if refusal.returncode == 0 or "non-distributable" not in refusal.stderr:
                raise AssertionError("test artifact was accepted as a distributable artifact")

            # Two different source identities race through one mutable Cargo
            # output. B must observe A's target lock and cannot capture until A
            # has atomically published its own immutable artifact.
            race_root = scratch / "race"
            barriers = race_root / "barriers"
            barriers.mkdir(parents=True)
            input_a = race_root / "input-a"
            input_b = race_root / "input-b"
            input_a.write_text("race-source-a\n", encoding="utf-8")
            input_b.write_text("race-source-b\n", encoding="utf-8")
            historical_a_ns = 946_684_800_000_000_000
            historical_b_ns = historical_a_ns + 1_000_000_000
            os.utime(input_a, ns=(historical_a_ns, historical_a_ns))
            os.utime(input_b, ns=(historical_b_ns, historical_b_ns))
            barrier_a = barriers / "capture-a"
            barrier_b = barriers / "capture-b"
            run_a = BuilderRun(
                command,
                builder_environment(
                    root=race_root, input_path=input_a, binary=seed_a, barrier=barrier_a
                ),
                race_root / "logs-a",
            )
            active.append(run_a)
            wait_for(barrier_a.with_suffix(".ready"), run_a, "first capture barrier")
            run_b = BuilderRun(
                command,
                builder_environment(
                    root=race_root, input_path=input_b, binary=seed_b, barrier=barrier_b
                ),
                race_root / "logs-b",
            )
            active.append(run_b)
            wait_for(barrier_b.with_suffix(".contended"), run_b, "target-lock contention")
            if barrier_b.with_suffix(".ready").exists():
                raise AssertionError("second build reached mutable output while first held the lock")

            workspace_a, workspace_key_a = inspect_stable_build_workspace(
                race_root, args.target
            )

            barrier_a.with_suffix(".continue").touch()
            code_a, stdout_a, stderr_a = run_a.finish()
            active.remove(run_a)
            if code_a != 0:
                raise AssertionError(f"first raced build failed: {stderr_a!r}")
            result_a = parse_machine_output(stdout_a)
            assert_receipted_fixture(result_a, seed_a)
            if workspace_key_a != result_a["H00LIGAN_PRODUCT_SOURCE_KEY"]:
                raise AssertionError("first stable workspace did not bind its immutable source")
            digest_a = sha256(result_a["binary"])

            wait_for(barrier_b.with_suffix(".ready"), run_b, "second capture barrier")
            if sha256(result_a["binary"]) != digest_a:
                raise AssertionError("second build changed the first immutable artifact")
            workspace_b, workspace_key_b = inspect_stable_build_workspace(
                race_root, args.target
            )
            if workspace_b != workspace_a:
                raise AssertionError("distinct source identities selected distinct Cargo roots")
            barrier_b.with_suffix(".continue").touch()
            code_b, stdout_b, stderr_b = run_b.finish()
            active.remove(run_b)
            if code_b != 0:
                raise AssertionError(f"second raced build failed: {stderr_b!r}")
            result_b = parse_machine_output(stdout_b)
            assert_receipted_fixture(result_b, seed_b)
            if workspace_key_b != result_b["H00LIGAN_PRODUCT_SOURCE_KEY"]:
                raise AssertionError("second stable workspace did not bind its immutable source")

            if result_a["binary"] == result_b["binary"]:
                raise AssertionError("distinct source identities shared one artifact path")
            if result_a["H00LIGAN_PRODUCT_SOURCE_KEY"] == result_b["H00LIGAN_PRODUCT_SOURCE_KEY"]:
                raise AssertionError("distinct staged inputs shared one source key")
            if sha256(result_a["binary"]) != digest_a:
                raise AssertionError("completed second build changed the first artifact")

            # Right-reason RED for the target-stable Cargo boundary. Force an
            # A -> B -> A workspace rebind after discarding only A's scratch
            # artifact. The A snapshot deliberately carries a historical
            # mtime. Changed compiled bytes must be made newer than B's prior
            # mutable Cargo output before Cargo is invoked again.
            mutable_binary = (
                race_root / "portable-target" / args.target / "release/h00ligan"
            )
            prior_output_mtime_ns = mutable_binary.stat().st_mtime_ns
            artifact_a = result_a["binary"].parent
            assert isinstance(artifact_a, Path)
            shutil.rmtree(artifact_a)
            time.sleep(0.02)
            rebound = BuilderRun(
                command,
                builder_environment(root=race_root, input_path=input_a, binary=seed_a),
                race_root / "logs-rebound-a",
            )
            active.append(rebound)
            rebound_code, rebound_stdout, rebound_stderr = rebound.finish()
            active.remove(rebound)
            if rebound_code != 0:
                raise AssertionError(f"A-after-B workspace rebind failed: {rebound_stderr!r}")
            rebound_result = parse_machine_output(rebound_stdout)
            assert_receipted_fixture(rebound_result, seed_a)
            rebound_workspace, rebound_key = inspect_stable_build_workspace(
                race_root, args.target
            )
            if rebound_key != result_a["H00LIGAN_PRODUCT_SOURCE_KEY"]:
                raise AssertionError("A-after-B workspace did not restore source A identity")
            compiled_input = rebound_workspace / "product/src/main.rs"
            if compiled_input.stat().st_mtime_ns <= prior_output_mtime_ns:
                raise AssertionError(
                    "stable workspace preserved historical mtime for changed Cargo input"
                )

            # An identical replay returns the same immutable path without
            # recapturing or changing its bytes.
            replay = BuilderRun(
                command,
                builder_environment(root=race_root, input_path=input_a, binary=seed_a),
                race_root / "logs-replay",
            )
            active.append(replay)
            replay_code, replay_stdout, replay_stderr = replay.finish()
            active.remove(replay)
            if replay_code != 0:
                raise AssertionError(f"identical artifact replay failed: {replay_stderr!r}")
            replay_result = parse_machine_output(replay_stdout)
            if replay_result["binary"] != result_a["binary"]:
                raise AssertionError("identical build identity did not reuse its immutable artifact")
            if sha256(replay_result["binary"]) != digest_a:
                raise AssertionError("identical artifact replay changed published bytes")

            # A substituted authority-test artifact is intentionally useful to
            # this harness but must never enter even an explicit install path.
            # The caller already has same-user execution authority; this is a
            # product-provenance boundary, not a privilege boundary.
            forbidden_destination = race_root / "forbidden-installed-h00ligan"
            install_command = [
                str(builder),
                "--target",
                args.target,
                "--install",
                "--destination",
                str(forbidden_destination),
            ]
            forbidden_install = BuilderRun(
                install_command,
                builder_environment(root=race_root, input_path=input_a, binary=seed_a),
                race_root / "logs-forbidden-install",
            )
            active.append(forbidden_install)
            install_code, _, install_stderr = forbidden_install.finish()
            active.remove(forbidden_install)
            if (
                install_code == 0
                or forbidden_destination.exists()
                or "non-distributable and cannot be installed" not in install_stderr
            ):
                raise AssertionError(
                    "authority-test product was installable instead of non-distributable: "
                    f"{install_stderr!r}"
                )
        finally:
            for run in active:
                run.terminate()

    invocation_after = (
        {path.name for path in invocation_parent.iterdir()} if invocation_parent.is_dir() else set()
    )
    leaked_invocations = invocation_after - invocation_before
    if leaked_invocations:
        raise AssertionError(
            "portable builder left new invocation residue: "
            f"leaked={leaked_invocations!r} before={invocation_before!r} "
            f"after={invocation_after!r}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed-binary", type=Path, required=True)
    parser.add_argument("--target", default=native_target())
    parser.add_argument("--rust-source-cache", type=Path, required=True)
    args = parser.parse_args()
    run_test(args)
    print(
        "h00ligan-build-authority: OK "
        "(provider/product drift refused; provider/product ABA snapshot safe; "
        "Cargo mtime hazard fired; target generation invalidated; "
        "target capture serialized; distinct immutable receipts; replay stable; "
        "zero invocation residue)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
