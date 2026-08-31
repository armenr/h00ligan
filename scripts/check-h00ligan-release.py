#!/usr/bin/env python3
"""Check that h00ligan's release authorities agree before automation runs."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path


SEMVER = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)")
CHANGELOG_VERSION_HEADING = re.compile(
    rf"^## (?:v?{SEMVER.pattern}|\[v?{SEMVER.pattern}\])(?:\s|\(|$)",
    re.MULTILINE,
)
EMBEDDED_PRODUCT_DIRECT_DEPENDENCIES = [
    "h00ligan",
    "h00ligan-provider-protocol",
    "h00ligan-ra-provider",
]


def check_workspace_publication(root: Path, failures: list[str]) -> None:
    """Keep every source package private until registry release is designed."""
    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    members = workspace.get("workspace", {}).get("members", [])
    if not isinstance(members, list) or not members:
        failures.append("standalone workspace must declare a non-empty member population")
        return
    for member in members:
        if not isinstance(member, str):
            failures.append(f"workspace member must be a literal path: {member!r}")
            continue
        manifest_path = root / member / "Cargo.toml"
        if not manifest_path.is_file():
            failures.append(f"workspace member manifest is missing: {member}/Cargo.toml")
            continue
        package = tomllib.loads(manifest_path.read_text(encoding="utf-8")).get(
            "package", {}
        )
        if package.get("publish") is not False:
            failures.append(
                f"workspace package {package.get('name', member)!r} must set "
                "publish = false until registry release is explicitly authorized"
            )


def check_product_lock(root: Path, version: str, failures: list[str]) -> None:
    """Validate the tracked lock for the exact one-file product authority."""
    template = tomllib.loads(
        (root / "providers/rust-analyzer/h00ligan-product.Cargo.toml.in").read_text(
            encoding="utf-8"
        )
    )
    if template.get("package", {}).get("name") != "h00ligan-product":
        failures.append(
            "embedded product manifest must name the one-file h00ligan product"
        )
    if template.get("package", {}).get("version") != "@H00LIGAN_VERSION@":
        failures.append("embedded product manifest must derive the h00ligan version")
    if template.get("package", {}).get("license") != "MIT OR Apache-2.0":
        failures.append("embedded product manifest must declare its source license")

    about_path = root / "release/about.toml"
    if about_path.is_file():
        about = tomllib.loads(about_path.read_text(encoding="utf-8"))
        if "Apache-2.0 WITH LLVM-exception" not in about.get("accepted", []):
            failures.append(
                "release license policy must admit rust-analyzer's LLVM exception"
            )

    product_lock = tomllib.loads(
        (root / "providers/rust-analyzer/h00ligan-product.Cargo.lock").read_text(
            encoding="utf-8"
        )
    )
    packages = product_lock.get("package", [])
    by_name = {
        package.get("name"): package
        for package in packages
        if isinstance(package, dict) and isinstance(package.get("name"), str)
    }
    required = {
        "h00ligan",
        "h00ligan-product",
        "h00ligan-ra-provider",
        "h00ligan-provider-protocol",
        "redb",
    }
    if missing := sorted(required - by_name.keys()):
        failures.append("embedded product lock misses: " + ", ".join(missing))
    for package_name in ("h00ligan", "h00ligan-product"):
        package_version = by_name.get(package_name, {}).get("version")
        if package_version != version:
            failures.append(
                f"embedded product lock {package_name} version is "
                f"{package_version!r}, expected {version!r}"
            )
    product_dependencies = by_name.get("h00ligan-product", {}).get("dependencies")
    if product_dependencies != EMBEDDED_PRODUCT_DIRECT_DEPENDENCIES:
        failures.append(
            "embedded product direct dependencies are "
            f"{product_dependencies!r}, expected "
            f"{EMBEDDED_PRODUCT_DIRECT_DEPENDENCIES!r}"
        )
    forbidden = {
        "h00-core",
        "h00-sdl",
        "lancedb",
        "tarpc",
        "tarpc-plugins",
        "tiktoken-rs",
    }
    if leaked := sorted(forbidden & by_name.keys()):
        failures.append("embedded product lock contains substrate crates: " + ", ".join(leaked))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    root = args.root.resolve()

    cargo = tomllib.loads((root / "crates/h00ligan/Cargo.toml").read_text(encoding="utf-8"))
    cargo_lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    manifest = json.loads((root / ".release-please-manifest.json").read_text(encoding="utf-8"))
    config = json.loads((root / "release-please-config.json").read_text(encoding="utf-8"))
    package = config.get("packages", {}).get("crates/h00ligan", {})

    version = cargo.get("package", {}).get("version")
    failures: list[str] = []
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        failures.append(f"Cargo version is not plain SemVer: {version!r}")
    if manifest.get("crates/h00ligan") != version:
        failures.append("Cargo.toml and .release-please-manifest.json versions differ")
    lock_versions = [
        package.get("version")
        for package in cargo_lock.get("package", [])
        if package.get("name") == "h00ligan"
    ]
    if lock_versions != [version]:
        failures.append(f"Cargo.lock h00ligan population is {lock_versions!r}, expected [{version!r}]")
    if cargo.get("package", {}).get("publish") is not False:
        failures.append("h00ligan must retain publish = false until crates.io is explicitly authorized")
    check_workspace_publication(root, failures)
    if config.get("release-type") != "rust":
        failures.append("release-type must be rust")
    if package.get("component") != "h00ligan":
        failures.append("component must be h00ligan")
    if package.get("include-component-in-tag") is not True:
        failures.append("tags must include the h00ligan component")
    if package.get("include-v-in-tag") is not True:
        failures.append("tags must include the v prefix")
    if package.get("draft") is not True:
        failures.append("Release Please must create a draft until distribution assets succeed")
    if package.get("force-tag-creation") is not True:
        failures.append("draft releases must materialize their tag before distribution verifies it")
    if config.get("plugins"):
        failures.append("workspace plugins would widen a component-only version bump")
    lock_updaters = package.get("extra-files")
    expected_lock_updaters = [
        {
            "type": "toml",
            "path": "/Cargo.lock",
            "jsonpath": "$.package[?(@.name.value == 'h00ligan')].version",
        },
        {
            "type": "toml",
            "path": "/providers/rust-analyzer/h00ligan-product.Cargo.lock",
            "jsonpath": "$.package[?(@.name.value == 'h00ligan')].version",
        },
        {
            "type": "toml",
            "path": "/providers/rust-analyzer/h00ligan-product.Cargo.lock",
            "jsonpath": "$.package[?(@.name.value == 'h00ligan-product')].version",
        },
    ]
    if lock_updaters != expected_lock_updaters:
        failures.append("Release Please must update the root and embedded product locks")
    if "bootstrap-sha" in config:
        failures.append(
            "standalone release history must not inherit a foreign bootstrap SHA"
        )

    required = [
        root / "crates/h00ligan/CHANGELOG.md",
        root / "crates/h00ligan/README.md",
        root / "release/about.toml",
        root / "release/about.hbs",
        root / "docs/releasing-h00ligan.md",
        root / "scripts/build-h00ligan-portable.sh",
        root / "scripts/test-h00ligan-installed-product.sh",
        root / "scripts/check-h00ligan-binary.py",
        root / "scripts/smoke-h00ligan-mcp.py",
    ]
    missing = [str(path.relative_to(root)) for path in required if not path.is_file()]
    if missing:
        failures.append("missing release inputs: " + ", ".join(missing))

    distribution_path = root / ".github/workflows/h00ligan-dist.yml"
    if distribution_path.is_file():
        distribution = distribution_path.read_text(encoding="utf-8")
        if "python3 scripts/smoke-h00ligan-mcp.py" not in distribution:
            failures.append(
                "distribution must smoke-test MCP through each native release binary"
            )
        if "scripts/build-h00ligan-portable.sh" not in distribution:
            failures.append("distribution must build the exact one-file product")
        if "scripts/test-h00ligan-installed-product.sh" not in distribution:
            failures.append(
                "distribution must run installed provider/MCP/WATCH acceptance"
            )
        if "-p h00ligan --bin h00ligan" in distribution:
            failures.append(
                "distribution must not publish the provider-less development binary"
            )
        if not re.search(
            r"python3 scripts/check-h00ligan-binary\.py \\\n"
            r"\s+--binary \"\$binary\" \\\n"
            r"\s+--target \"\$TARGET\"",
            distribution,
        ):
            failures.append(
                "distribution must invoke the shared binary-shape verifier with its "
                "matrix target and built artifact"
            )
    check_product_lock(root, version, failures)

    changelog_path = root / "crates/h00ligan/CHANGELOG.md"
    if changelog_path.is_file():
        changelog = changelog_path.read_text(encoding="utf-8")
        top_level_headings = re.findall(r"^# .+$", changelog, re.MULTILINE)
        if top_level_headings != ["# Changelog"] or re.search(
            r"^#{2,} Changelog$", changelog, re.MULTILINE
        ):
            failures.append("CHANGELOG must have one canonical top-level heading")
        if not CHANGELOG_VERSION_HEADING.search(changelog):
            failures.append(
                "CHANGELOG must retain a version-shaped H2 baseline for Release Please"
            )

    if failures:
        print("h00ligan-release: FAIL", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(f"h00ligan-release: OK (version {version}, tag h00ligan-v{version}, crates.io disabled)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
