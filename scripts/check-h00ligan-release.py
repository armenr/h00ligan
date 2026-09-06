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
ROOT_RELEASE_PATH = "."
PRODUCT_VERSION_FILE = "version.txt"
PRODUCT_CHANGELOG_PATH = "crates/h00ligan/CHANGELOG.md"
PRODUCT_VERSION_UPDATERS = [
    {
        "type": "toml",
        "path": "crates/h00ligan/Cargo.toml",
        "jsonpath": "$.package.version",
    },
    {
        "type": "toml",
        "path": "Cargo.lock",
        "jsonpath": "$.package[?(@.name.value == 'h00ligan')].version",
    },
    {
        "type": "toml",
        "path": "providers/rust-analyzer/h00ligan-product.Cargo.lock",
        "jsonpath": "$.package[?(@.name.value == 'h00ligan')].version",
    },
    {
        "type": "toml",
        "path": "providers/rust-analyzer/h00ligan-product.Cargo.lock",
        "jsonpath": "$.package[?(@.name.value == 'h00ligan-product')].version",
    },
]


def check_release_credentials(workflow: str) -> list[str]:
    """Check the release steps' credential wiring; actionlint owns YAML semantics."""
    failures: list[str] = []
    steps = re.split(r"(?m)^      - ", workflow)[1:]

    def step_with_id(step_id: str) -> str:
        matches = [
            step for step in steps
            if re.search(rf"(?m)^        id: {re.escape(step_id)}$", step)
        ]
        return matches[0] if len(matches) == 1 else ""

    token = step_with_id("release-token")
    if not re.search(
        r"(?m)^        uses: actions/create-github-app-token@[0-9a-f]{40}(?: #.*)?$",
        token,
    ):
        failures.append("release maintenance must mint one pinned GitHub App token")
    if "        if: steps.gate.outputs.current == 'true'\n" not in token:
        failures.append("release App token must follow current-green-main admission")
    inputs = re.findall(r"(?m)^          ([\w-]+): ([^\n]+)$", token)
    expected = {
        "client-id": "${{ vars.RELEASE_APP_CLIENT_ID }}",
        "private-key": "${{ secrets.RELEASE_APP_PRIVATE_KEY }}",
        "owner": "${{ github.repository_owner }}",
        "repositories": "${{ github.event.repository.name }}",
        "permission-contents": "write",
        "permission-pull-requests": "write",
        "skip-token-revoke": "false",
    }
    if len(inputs) != len(expected) or dict(inputs) != expected:
        failures.append(
            "release App token must be repository-scoped, least-privilege and revoked"
        )
    release = step_with_id("release")
    if not re.search(
        r"(?m)^          token: \$\{\{ steps\.release-token\.outputs\.token \}\}$",
        release,
    ):
        failures.append(
            "Release Please must use the App token so its PR checks run unattended"
        )
    if token and release and workflow.index(token) > workflow.index(release):
        failures.append("release App token must be minted before Release Please")
    return failures


def check_release_credentials_canaries() -> list[str]:
    good = """jobs:
  release-please:
    steps:
      - name: Mint release credentials
        if: steps.gate.outputs.current == 'true'
        id: release-token
        uses: actions/create-github-app-token@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        with:
          client-id: ${{ vars.RELEASE_APP_CLIENT_ID }}
          private-key: ${{ secrets.RELEASE_APP_PRIVATE_KEY }}
          owner: ${{ github.repository_owner }}
          repositories: ${{ github.event.repository.name }}
          permission-contents: write
          permission-pull-requests: write
          skip-token-revoke: false
      - name: Maintain release
        id: release
        with:
          token: ${{ steps.release-token.outputs.token }}
"""
    failures = check_release_credentials(good)
    if failures:
        return [f"release credential known-positive failed: {failures!r}"]
    prefix, token_and_release = good.split("      - name: Mint release credentials", 1)
    token_step, release_step = token_and_release.split("      - name: Maintain release", 1)
    mutants = {
        "built-in token": good.replace(
            "token: ${{ steps.release-token.outputs.token }}",
            "token: ${{ secrets.GITHUB_TOKEN }}",
        ),
        "mutable action": good.replace("a" * 40, "v3"),
        "wrong repository": good.replace("github.event.repository.name", "vars.OTHER_REPO"),
        "whole installation": good.replace(
            "          repositories: ${{ github.event.repository.name }}\n", ""
        ),
        "unrestricted permissions": good.replace(
            "          permission-contents: write\n", ""
        ),
        "extra permissions": good.replace(
            "          permission-contents: write\n",
            "          permission-contents: write\n          permission-administration: write\n",
        ),
        "unrevoked token": good.replace("skip-token-revoke: false", "skip-token-revoke: true"),
        "missing freshness gate": good.replace(
            "        if: steps.gate.outputs.current == 'true'\n", ""
        ),
        "duplicate input": good.replace(
            "          owner: ${{ github.repository_owner }}\n",
            "          owner: ${{ github.repository_owner }}\n" * 2,
        ),
        "reordered token": (
            prefix + "      - name: Maintain release" + release_step
            + "      - name: Mint release credentials" + token_step
        ),
    }
    for name, mutant in mutants.items():
        if mutant == good or not check_release_credentials(mutant):
            failures.append(f"release credential mutant escaped: {name}")
    return failures


def check_product_release_scope(
    config: dict[object, object],
    manifest: dict[object, object],
    workflow: str,
    version_file: str | None,
    version: object,
    failures: list[str],
) -> None:
    """Keep the one shipped product release-scoped to the whole repository."""
    packages = config.get("packages")
    if not isinstance(packages, dict) or set(packages) != {ROOT_RELEASE_PATH}:
        failures.append(
            "Release Please must define exactly one repository-wide root product "
            "component"
        )
        package: dict[object, object] = {}
    else:
        configured_package = packages.get(ROOT_RELEASE_PATH)
        package = configured_package if isinstance(configured_package, dict) else {}

    if manifest != {ROOT_RELEASE_PATH: version}:
        failures.append(
            "release manifest must bind the repository-wide product version"
        )
    if version_file is None or version_file.strip() != version:
        failures.append("version.txt and Cargo.toml product versions differ")
    if config.get("release-type") != "simple":
        failures.append(
            "release-type must be simple so one repository-wide product version "
            "does not rewrite private workspace crate versions"
        )
    if package.get("version-file") != PRODUCT_VERSION_FILE:
        failures.append("root product component must own version.txt")
    if package.get("changelog-path") != PRODUCT_CHANGELOG_PATH:
        failures.append(
            "root product component must write the shipped h00ligan changelog"
        )
    if package.get("package-name") != "h00ligan":
        failures.append("root product package name must be h00ligan")
    if package.get("extra-files") != PRODUCT_VERSION_UPDATERS:
        failures.append(
            "Release Please must update the executable manifest and both product locks"
        )
    if package.get("exclude-paths"):
        failures.append(
            "repository-wide product commits must not be hidden by release path exclusions"
        )

    expected_outputs = [
        "release-created: ${{ steps.release.outputs.release_created }}",
        "sha: ${{ steps.release.outputs.sha }}",
        "version: ${{ steps.release.outputs.version }}",
        "tag: ${{ steps.release.outputs.tag_name }}",
    ]
    for expected in expected_outputs:
        if expected not in workflow:
            failures.append(
                f"release workflow must consume the root product output {expected!r}"
            )
    if "crates/h00ligan--" in workflow:
        failures.append("release workflow retains crate-local Release Please outputs")


def check_product_release_scope_canaries() -> list[str]:
    """Prove the release-scope check catches the production defect and output drift."""
    config = {
        "release-type": "simple",
        "packages": {
            ROOT_RELEASE_PATH: {
                "component": "h00ligan",
                "package-name": "h00ligan",
                "version-file": PRODUCT_VERSION_FILE,
                "changelog-path": PRODUCT_CHANGELOG_PATH,
                "extra-files": PRODUCT_VERSION_UPDATERS,
            }
        },
    }
    manifest = {ROOT_RELEASE_PATH: "0.2.0"}
    workflow = "\n".join(
        [
            "release-created: ${{ steps.release.outputs.release_created }}",
            "sha: ${{ steps.release.outputs.sha }}",
            "version: ${{ steps.release.outputs.version }}",
            "tag: ${{ steps.release.outputs.tag_name }}",
        ]
    )
    failures: list[str] = []
    check_product_release_scope(
        config, manifest, workflow, "0.2.0\n", "0.2.0", failures
    )
    if failures:
        return [f"release-scope known-positive failed: {failures!r}"]

    mutants = {
        "crate-local component": (
            {
                **config,
                "packages": {
                    "crates/h00ligan": config["packages"][ROOT_RELEASE_PATH]
                },
            },
            manifest,
            workflow,
            "0.2.0\n",
            "exactly one repository-wide root product component",
        ),
        "crate-local manifest": (
            config,
            {"crates/h00ligan": "0.2.0"},
            workflow,
            "0.2.0\n",
            "release manifest must bind the repository-wide product version",
        ),
        "crate-local workflow outputs": (
            config,
            manifest,
            workflow.replace(
                "steps.release.outputs.",
                "steps.release.outputs.crates/h00ligan--",
            ),
            "0.2.0\n",
            "release workflow retains crate-local Release Please outputs",
        ),
        "missing product version ledger": (
            config,
            manifest,
            workflow,
            None,
            "version.txt and Cargo.toml product versions differ",
        ),
    }
    canary_failures: list[str] = []
    for name, (
        mutant_config,
        mutant_manifest,
        mutant_workflow,
        mutant_version,
        expected_failure,
    ) in mutants.items():
        mutant_failures: list[str] = []
        check_product_release_scope(
            mutant_config,
            mutant_manifest,
            mutant_workflow,
            mutant_version,
            "0.2.0",
            mutant_failures,
        )
        if not any(expected_failure in failure for failure in mutant_failures):
            canary_failures.append(
                f"release-scope mutant escaped its owning check: {name}"
            )
    return canary_failures


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
    packages = config.get("packages", {})
    package = packages.get(ROOT_RELEASE_PATH, {}) if isinstance(packages, dict) else {}
    version_path = root / PRODUCT_VERSION_FILE
    version_file = (
        version_path.read_text(encoding="utf-8") if version_path.is_file() else None
    )
    release_workflow_path = root / ".github/workflows/release-h00ligan.yml"
    release_workflow = (
        release_workflow_path.read_text(encoding="utf-8")
        if release_workflow_path.is_file()
        else ""
    )

    version = cargo.get("package", {}).get("version")
    failures = check_product_release_scope_canaries()
    failures.extend(check_release_credentials_canaries())
    failures.extend(check_release_credentials(release_workflow))
    if not isinstance(version, str) or not SEMVER.fullmatch(version):
        failures.append(f"Cargo version is not plain SemVer: {version!r}")
    check_product_release_scope(
        config,
        manifest,
        release_workflow,
        version_file,
        version,
        failures,
    )
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
