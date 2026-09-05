#!/usr/bin/env python3
"""Warm every locked Cargo graph needed by an exact h00ligan release build."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib


Invoke = Callable[[Sequence[str], Path, bool], subprocess.CompletedProcess[str]]


def invoke(command: Sequence[str], cwd: Path, capture: bool) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE if capture else None,
        text=True,
    )


def require_regular(path: Path, description: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{description} must be a regular non-symlink: {path}")
    return path


def require_directory(path: Path, description: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise RuntimeError(f"{description} must be a real directory: {path}")
    return path


def require_descendant(path: Path, parent: Path, description: str) -> Path:
    resolved = path.resolve(strict=True)
    authority = parent.resolve(strict=True)
    try:
        resolved.relative_to(authority)
    except ValueError as error:
        raise RuntimeError(f"{description} escapes its release authority: {path}") from error
    return resolved


def machine_field(output: str, name: str) -> str:
    prefix = f"{name}="
    values = [line[len(prefix) :] for line in output.splitlines() if line.startswith(prefix)]
    if len(values) != 1 or not values[0]:
        raise RuntimeError(f"release preparer returned {len(values)} values for {name}")
    return values[0]


def materialize_pyrefly_adapter(
    source_root: Path, pyrefly_source_root: Path, destination: Path
) -> Path:
    require_directory(destination, "owned Pyrefly dependency workspace")
    if any(destination.iterdir()):
        raise RuntimeError("owned Pyrefly dependency workspace must start empty")

    template = require_regular(
        source_root / "providers/python/pyrefly/provider.Cargo.toml.in",
        "Pyrefly provider manifest template",
    )
    lockfile = require_regular(
        source_root / "providers/python/pyrefly/provider.Cargo.lock",
        "Pyrefly provider lockfile",
    )
    provider = require_regular(
        source_root / "providers/python/pyrefly/h00_pyrefly_semantic_provider.rs",
        "Pyrefly provider source",
    )
    provider_main = require_regular(
        source_root / "providers/python/pyrefly/h00_pyrefly_semantic_provider_main.rs",
        "Pyrefly provider entrypoint",
    )
    protocol_manifest = require_regular(
        source_root / "crates/h00ligan-provider-protocol/Cargo.toml",
        "provider protocol manifest",
    )
    protocol_source = require_regular(
        source_root / "crates/h00ligan-provider-protocol/src/lib.rs",
        "provider protocol source",
    )
    require_directory(pyrefly_source_root / "pyrefly", "prepared Pyrefly package")

    (destination / "src").mkdir()
    (destination / "protocol/src").mkdir(parents=True)
    shutil.copyfile(provider, destination / "src/lib.rs")
    shutil.copyfile(provider_main, destination / "src/main.rs")
    shutil.copyfile(protocol_manifest, destination / "protocol/Cargo.toml")
    shutil.copyfile(protocol_source, destination / "protocol/src/lib.rs")
    shutil.copyfile(lockfile, destination / "Cargo.lock")

    rendered = template.read_text(encoding="utf-8")
    rendered = rendered.replace("@H00_PROTOCOL_PATH@", "protocol")
    rendered = rendered.replace(
        "@H00_PYREFLY_PATH@", str(pyrefly_source_root / "pyrefly")
    )
    if "@H00_" in rendered:
        raise RuntimeError("Pyrefly dependency manifest retains an unresolved placeholder")
    manifest = destination / "Cargo.toml"
    manifest.write_text(rendered + "\n[workspace]\n", encoding="utf-8")
    return manifest


def rust_toolchain(source_root: Path) -> str:
    toolchain_file = require_regular(
        source_root / "rust-toolchain.toml", "release Rust toolchain authority"
    )
    payload = tomllib.loads(toolchain_file.read_text(encoding="utf-8"))
    channel = payload.get("toolchain", {}).get("channel")
    if not isinstance(channel, str) or not channel or any(c.isspace() for c in channel):
        raise RuntimeError("release Rust toolchain channel is invalid")
    return channel


def fetch_release_cargo(
    source_root: Path,
    rust_source: str,
    *,
    runner: Invoke = invoke,
    scratch_parent: Path | None = None,
) -> tuple[str, ...]:
    source_root = require_directory(source_root, "release source root").resolve(strict=True)
    provider_builder = require_regular(
        source_root / "scripts/build-h00-pyrefly-semantic-provider.sh",
        "Pyrefly source preparer",
    )
    product_builder = require_regular(
        source_root / "scripts/build-h00ligan-portable.sh", "portable product preparer"
    )
    toolchain = rust_toolchain(source_root)

    prepared = runner(
        (str(provider_builder), "--prepare-only", "--machine"), source_root, True
    )
    pyrefly_root = require_descendant(
        Path(machine_field(prepared.stdout, "H00_PYREFLY_SOURCE_ROOT")),
        source_root / "target/semantic-provider/python/source",
        "prepared Pyrefly source",
    )

    events: list[str] = []
    with tempfile.TemporaryDirectory(
        prefix="h00ligan-release-cargo.",
        dir=str(scratch_parent) if scratch_parent is not None else None,
    ) as temporary:
        adapter_manifest = materialize_pyrefly_adapter(
            source_root, pyrefly_root, Path(temporary)
        )
        runner(
            (
                "cargo",
                f"+{toolchain}",
                "fetch",
                "--locked",
                "--manifest-path",
                str(adapter_manifest),
            ),
            source_root,
            False,
        )
        events.append("pyrefly")

    product_command = [str(product_builder), "--prepare-only"]
    if rust_source:
        product_command.extend(("--rust-source", rust_source))
    product_command.append("--machine")
    product = runner(tuple(product_command), source_root, True)
    product_manifest = require_descendant(
        Path(machine_field(product.stdout, "H00LIGAN_PRODUCT_MANIFEST")),
        source_root / "target/portable-cache",
        "prepared product manifest",
    )
    require_regular(product_manifest, "prepared product manifest")
    runner(
        (
            "cargo",
            f"+{toolchain}",
            "fetch",
            "--locked",
            "--manifest-path",
            str(product_manifest),
        ),
        source_root,
        False,
    )
    events.append("product")

    workspace_manifest = require_regular(
        source_root / "Cargo.toml", "release workspace manifest"
    )
    runner(
        (
            "cargo",
            f"+{toolchain}",
            "fetch",
            "--locked",
            "--manifest-path",
            str(workspace_manifest),
        ),
        source_root,
        False,
    )
    events.append("workspace")
    return tuple(events)


def write_fixture(root: Path) -> tuple[Path, Path]:
    paths = (
        "scripts",
        "providers/python/pyrefly",
        "crates/h00ligan-provider-protocol/src",
        "target/semantic-provider/python/source/source-key/pyrefly",
        "target/portable-cache/product/product",
    )
    for relative in paths:
        (root / relative).mkdir(parents=True, exist_ok=True)
    files = {
        "rust-toolchain.toml": '[toolchain]\nchannel = "1.97.1"\n',
        "Cargo.toml": "[workspace]\nmembers = []\n",
        "scripts/build-h00-pyrefly-semantic-provider.sh": "provider-preparer\n",
        "scripts/build-h00ligan-portable.sh": "product-preparer\n",
        "providers/python/pyrefly/provider.Cargo.toml.in": (
            "[package]\nname = \"fixture\"\nversion = \"0.0.0\"\n"
            "[lib]\npath = \"src/lib.rs\"\n"
            "[[bin]]\nname = \"fixture\"\npath = \"src/main.rs\"\n"
            "[dependencies]\nprotocol = { path = \"@H00_PROTOCOL_PATH@\" }\n"
            "pyrefly = { path = \"@H00_PYREFLY_PATH@\" }\n"
        ),
        "providers/python/pyrefly/provider.Cargo.lock": "version = 4\n",
        "providers/python/pyrefly/h00_pyrefly_semantic_provider.rs": "pub fn provider() {}\n",
        "providers/python/pyrefly/h00_pyrefly_semantic_provider_main.rs": "fn main() {}\n",
        "crates/h00ligan-provider-protocol/Cargo.toml": (
            "[package]\nname = \"protocol\"\nversion = \"0.0.0\"\n"
        ),
        "crates/h00ligan-provider-protocol/src/lib.rs": "pub struct Frame;\n",
        "target/semantic-provider/python/source/source-key/pyrefly/Cargo.toml": (
            "[package]\nname = \"pyrefly\"\nversion = \"0.0.0\"\n"
        ),
        "target/portable-cache/product/product/Cargo.toml": (
            "[package]\nname = \"product\"\nversion = \"0.0.0\"\n"
        ),
    }
    for relative, contents in files.items():
        (root / relative).write_text(contents, encoding="utf-8")
    return (
        root / "target/semantic-provider/python/source/source-key",
        root / "target/portable-cache/product/product/Cargo.toml",
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="h00ligan-release-cargo-self-test.") as raw:
        root = Path(raw) / "repo"
        root.mkdir()
        pyrefly_root, product_manifest = write_fixture(root)
        observed: list[str] = []
        adapter_root: Path | None = None

        def fake_runner(
            command: Sequence[str], cwd: Path, capture: bool
        ) -> subprocess.CompletedProcess[str]:
            nonlocal adapter_root
            assert cwd == root
            if command[0].endswith("build-h00-pyrefly-semantic-provider.sh"):
                assert tuple(command[1:]) == ("--prepare-only", "--machine")
                return subprocess.CompletedProcess(
                    command, 0, f"H00_PYREFLY_SOURCE_ROOT={pyrefly_root}\n", ""
                )
            if command[0] == "cargo":
                manifest = Path(command[-1])
                if "h00ligan-release-cargo." in manifest.parent.name:
                    rendered = manifest.read_text(encoding="utf-8")
                    assert "@H00_" not in rendered
                    assert rendered.endswith("\n[workspace]\n")
                    assert (manifest.parent / "Cargo.lock").read_text() == "version = 4\n"
                    assert (manifest.parent / "src/lib.rs").is_file()
                    assert (manifest.parent / "protocol/src/lib.rs").is_file()
                    adapter_root = manifest.parent
                    observed.append("fetch:pyrefly")
                elif manifest == product_manifest:
                    observed.append("fetch:product")
                elif manifest == root / "Cargo.toml":
                    observed.append("fetch:workspace")
                else:
                    raise AssertionError(f"unexpected Cargo manifest: {manifest}")
                return subprocess.CompletedProcess(command, 0, "", "")
            if command[0].endswith("build-h00ligan-portable.sh"):
                if observed != ["fetch:pyrefly"]:
                    raise AssertionError(
                        "portable preparation ran before the Pyrefly lock was fetched"
                    )
                assert "--prepare-only" in command and "--machine" in command
                observed.append("prepare:product")
                return subprocess.CompletedProcess(
                    command, 0, f"H00LIGAN_PRODUCT_MANIFEST={product_manifest}\n", ""
                )
            raise AssertionError(f"unexpected command: {command!r}")

        result = fetch_release_cargo(
            root, "target/upstream-rust", runner=fake_runner, scratch_parent=Path(raw)
        )
        expected = (
            "fetch:pyrefly",
            "prepare:product",
            "fetch:product",
            "fetch:workspace",
        )
        if tuple(observed) != expected or result != ("pyrefly", "product", "workspace"):
            raise AssertionError(f"release dependency order drifted: {observed!r} {result!r}")
        if adapter_root is None or adapter_root.exists():
            raise AssertionError("temporary Pyrefly dependency workspace was not reclaimed")

        outside = Path(raw) / "foreign-source"
        (outside / "pyrefly").mkdir(parents=True)

        def foreign_runner(
            command: Sequence[str], cwd: Path, capture: bool
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                command, 0, f"H00_PYREFLY_SOURCE_ROOT={outside}\n", ""
            )

        try:
            fetch_release_cargo(root, "", runner=foreign_runner, scratch_parent=Path(raw))
        except RuntimeError as error:
            if "escapes its release authority" not in str(error):
                raise
        else:
            raise AssertionError("foreign Pyrefly source received dependency authority")

        duplicate = f"H00_PYREFLY_SOURCE_ROOT={pyrefly_root}\n" * 2
        try:
            machine_field(duplicate, "H00_PYREFLY_SOURCE_ROOT")
        except RuntimeError as error:
            if "returned 2 values" not in str(error):
                raise
        else:
            raise AssertionError("duplicate machine fields were accepted")

    print("h00ligan-release-cargo: self-test OK (3 fetch stages, 2 sabotages)")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--rust-source", default="")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.source_root is None:
        parser.error("--source-root is required unless --self-test is used")
    events = fetch_release_cargo(args.source_root, args.rust_source)
    print(f"h00ligan-release-cargo: fetched {','.join(events)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
