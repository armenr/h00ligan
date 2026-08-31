#!/usr/bin/env python3
"""Validate the release SBOM describes h00ligan for the promised target."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


Package = tuple[str, str]
DependencyEdge = tuple[Package, Package]


def iter_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from iter_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from iter_strings(item)


def cargo_dependency_graph(
    manifest: Path, target: str
) -> tuple[Package, set[Package], set[DependencyEdge]]:
    command = [
        "cargo",
        "metadata",
        "--locked",
        "--offline",
        "--manifest-path",
        str(manifest),
        "--format-version",
        "1",
        "--filter-platform",
        target,
        "--no-default-features",
    ]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    metadata = json.loads(result.stdout)
    packages_by_id = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    roots = [
        package_id
        for package_id, package in packages_by_id.items()
        if package.get("name") == "h00ligan-product"
    ]
    if len(roots) != 1:
        raise ValueError(
            f"h00ligan-product Cargo root population is {len(roots)}, expected 1"
        )
    root_id = roots[0]

    def admitted(dependency: dict[str, Any]) -> bool:
        return any(
            kind.get("kind") in (None, "normal", "build")
            for kind in dependency.get("dep_kinds", [])
        )

    reachable = {root_id}
    pending = [root_id]
    while pending:
        package_id = pending.pop()
        for dependency in nodes[package_id].get("deps", []):
            dependency_id = dependency["pkg"]
            if admitted(dependency) and dependency_id not in reachable:
                reachable.add(dependency_id)
                pending.append(dependency_id)

    def coordinate(package_id: str) -> Package:
        package = packages_by_id[package_id]
        return package["name"], package["version"]

    coordinates = [coordinate(package_id) for package_id in reachable]
    if len(coordinates) != len(set(coordinates)):
        raise ValueError("Cargo graph contains ambiguous duplicate name/version coordinates")
    root = coordinate(root_id)
    packages = set(coordinates)
    packages.remove(root)
    edges = {
        (coordinate(package_id), coordinate(dependency["pkg"]))
        for package_id in reachable
        for dependency in nodes[package_id].get("deps", [])
        if dependency["pkg"] in reachable and admitted(dependency)
    }
    return root, packages, edges


def sbom_dependency_graph(
    document: dict[str, Any],
) -> tuple[Package, set[Package], set[DependencyEdge], list[str]]:
    failures: list[str] = []
    root_component = document.get("metadata", {}).get("component", {})
    components = [root_component, *document.get("components", [])]
    references: dict[str, Package] = {}
    coordinates: list[Package] = []
    for component in components:
        if not isinstance(component, dict):
            failures.append("SBOM component population contains a non-object")
            continue
        reference = component.get("bom-ref")
        name = component.get("name")
        version = component.get("version")
        if not all(isinstance(value, str) and value for value in (reference, name, version)):
            failures.append("SBOM component lacks a complete ref/name/version coordinate")
            continue
        coordinate = (name, version)
        if reference in references:
            failures.append(f"SBOM repeats component reference {reference!r}")
            continue
        references[reference] = coordinate
        coordinates.append(coordinate)
    if len(coordinates) != len(set(coordinates)):
        failures.append("SBOM contains ambiguous duplicate name/version coordinates")

    root = (root_component.get("name"), root_component.get("version"))
    packages = set(coordinates)
    packages.discard(root)
    dependency_refs: set[str] = set()
    edges: set[DependencyEdge] = set()
    for dependency in document.get("dependencies", []):
        if not isinstance(dependency, dict) or not isinstance(dependency.get("ref"), str):
            failures.append("SBOM dependency population contains an invalid entry")
            continue
        parent_ref = dependency["ref"]
        if parent_ref in dependency_refs:
            failures.append(f"SBOM repeats dependency node {parent_ref!r}")
        dependency_refs.add(parent_ref)
        parent = references.get(parent_ref)
        if parent is None:
            failures.append(f"SBOM dependency parent is unknown: {parent_ref!r}")
            continue
        for child_ref in dependency.get("dependsOn", []):
            child = references.get(child_ref)
            if child is None:
                failures.append(f"SBOM dependency child is unknown: {child_ref!r}")
            else:
                edges.add((parent, child))
    if dependency_refs != set(references):
        failures.append("SBOM dependency-node population does not equal component population")
    return root, packages, edges, failures


def validate_exact_graph(
    *,
    expected_root: Package,
    expected_packages: set[Package],
    expected_edges: set[DependencyEdge],
    actual_root: Package,
    actual_packages: set[Package],
    actual_edges: set[DependencyEdge],
) -> list[str]:
    failures: list[str] = []
    if actual_root != expected_root:
        failures.append(f"SBOM root is {actual_root!r}, expected {expected_root!r}")
    if omitted := sorted(expected_packages - actual_packages):
        failures.append(f"SBOM omits Cargo dependencies: {omitted!r}")
    if extras := sorted(actual_packages - expected_packages):
        failures.append(f"SBOM contains target-inapplicable dependencies: {extras!r}")
    if omitted_edges := sorted(expected_edges - actual_edges):
        failures.append(f"SBOM omits Cargo dependency edges: {omitted_edges!r}")
    if extra_edges := sorted(actual_edges - expected_edges):
        failures.append(f"SBOM contains target-inapplicable dependency edges: {extra_edges!r}")
    return failures


def self_test() -> None:
    root = ("h00ligan-product", "0.2.0")
    packages = {("core", "1.0.0"), ("platform", "2.0.0")}
    edges = {(root, ("core", "1.0.0")), (("core", "1.0.0"), ("platform", "2.0.0"))}
    if validate_exact_graph(
        expected_root=root,
        expected_packages=packages,
        expected_edges=edges,
        actual_root=root,
        actual_packages=packages,
        actual_edges=edges,
    ):
        raise AssertionError("exact SBOM graph positive was rejected")
    sabotages = {
        "omitted package": (packages - {("platform", "2.0.0")}, edges),
        "extra package": (packages | {("fsevent-sys", "4.0.0")}, edges),
        "omitted edge": (packages, edges - {(root, ("core", "1.0.0"))}),
        "extra edge": (packages, edges | {(root, ("platform", "2.0.0"))}),
    }
    for name, (actual_packages, actual_edges) in sabotages.items():
        if not validate_exact_graph(
            expected_root=root,
            expected_packages=packages,
            expected_edges=edges,
            actual_root=root,
            actual_packages=actual_packages,
            actual_edges=actual_edges,
        ):
            raise AssertionError(f"{name} sabotage did not fire")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--target")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("h00ligan-sbom: self-test OK (1 exact graph; 4 sabotages fired)")
    if args.sbom is None and args.target is None and args.manifest is None:
        return 0 if args.self_test else parser.error("provide SBOM, target, and manifest")
    if args.sbom is None or args.target is None or args.manifest is None:
        parser.error("--sbom, --target, and --manifest must be supplied together")

    document = json.loads(args.sbom.read_text(encoding="utf-8"))
    metadata = document.get("metadata", {})
    component = metadata.get("component", {})
    properties = {
        item.get("name"): item.get("value")
        for item in metadata.get("properties", [])
        if isinstance(item, dict)
    }
    failures: list[str] = []
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.5":
        failures.append("SBOM must be CycloneDX 1.5")
    if (
        component.get("name") != "h00ligan-product"
        or component.get("type") != "application"
    ):
        failures.append(
            "metadata component must be the exact one-file h00ligan product"
        )
    actual_target = properties.get("cdx:rustc:sbom:target:triple")
    if actual_target != args.target:
        failures.append(f"target property is {actual_target!r}, expected {args.target!r}")
    if not document.get("components") or not document.get("dependencies"):
        failures.append("dependency population is empty")
    absolute_file_uris = [
        value for value in iter_strings(document) if "file:///" in value
    ]
    if absolute_file_uris:
        failures.append(
            f"SBOM contains {len(absolute_file_uris)} machine-local absolute file URI value(s)"
        )
    sbom_root, sbom_packages, sbom_edges, graph_failures = sbom_dependency_graph(document)
    failures.extend(graph_failures)
    component_names = {name for name, _version in sbom_packages if isinstance(name, str)}
    required = {
        "h00ligan",
        "h00ligan-engine",
        "h00ligan-interface",
        "h00ligan-provider-protocol",
        "h00ligan-ra-provider",
        "hir",
        "ide",
        "load-cargo",
        "project-model",
        "redb",
        "rust-analyzer",
        "scip",
        "tree-sitter",
        "tree-sitter-go",
        "tree-sitter-python",
        "tree-sitter-rust",
        "tree-sitter-typescript",
        "vfs",
    }
    if missing := sorted(required - component_names):
        failures.append(
            "lean h00ligan SBOM is missing known production dependencies: "
            + ", ".join(missing)
        )
    forbidden_exact = {
        "cudarc",
        "fastembed",
        "h00-agent",
        "h00-core",
        "h00-sdl",
        "lancedb",
        "ort",
        "tarpc",
        "tarpc-plugins",
        "tiktoken-rs",
    }
    forbidden_prefixes = ("arrow-", "candle-", "lancedb-", "ort-")
    leaked = sorted(
        name
        for name in component_names
        if name in forbidden_exact or name == "arrow" or name.startswith(forbidden_prefixes)
    )
    if leaked:
        failures.append(
            "lean h00ligan SBOM contains feature-unified heavy dependencies: "
            + ", ".join(leaked)
        )

    try:
        product_root, product_packages, product_edges = cargo_dependency_graph(
            args.manifest, args.target
        )
    except (json.JSONDecodeError, subprocess.CalledProcessError, ValueError) as error:
        failures.append(f"could not derive exact Cargo dependency graph: {error}")
    else:
        if not product_packages or not product_edges:
            failures.append("exact embedded product Cargo dependency graph is empty")
        failures.extend(
            validate_exact_graph(
                expected_root=product_root,
                expected_packages=product_packages,
                expected_edges=product_edges,
                actual_root=sbom_root,
                actual_packages=sbom_packages,
                actual_edges=sbom_edges,
            )
        )

    if failures:
        print("h00ligan-sbom: FAIL", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print(
        f"h00ligan-sbom: OK ({args.target}, "
        f"{len(document['components'])} component(s), exact package and edge graph)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
